package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const globalTimeout = 30 * time.Second

var caKeyRef = flag.String("ca", "", "ca private key (1p secret reference)")
var userKeyRef = flag.String("u", "", "user public key (1p secret reference)")
var certValidityPeriod = flag.Duration("d", time.Hour*24, "cert validity period")
var principals = flag.String("p", "bob", "cert principals (comma-separated list)")
var logTag = flag.String("t", "1pca", "syslog record tag")

func main() {
	flag.Parse()
	stderr := log.New(os.Stderr, "", 0)
	stdout := log.New(os.Stdout, "", 0)
	sysl, err := syslog.New(syslog.LOG_NOTICE|syslog.LOG_USER, *logTag)
	if err != nil {
		stderr.Println(err)
		return
	}
	defer sysl.Close()
	ctx, cancel := context.WithTimeout(context.Background(), globalTimeout)
	defer cancel()
	caKey, err := parsePrivKey(ctx, *caKeyRef)
	if err != nil {
		stderr.Println(err)
		return
	}
	stderr.Println("CA key parsed")
	userKey, err := parsePubKey(ctx, *userKeyRef)
	if err != nil {
		stderr.Println(err)
		return
	}
	stderr.Println("User key parsed")
	hostname, err := os.Hostname()
	if err != nil {
		stderr.Println(err)
		return
	}
	now := time.Now()
	serial := uint64(now.Unix())
	cert := &ssh.Certificate{
		CertType:        ssh.UserCert,
		Key:             userKey,
		KeyId:           hostname,
		ValidPrincipals: strings.Split(*principals, ","),
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(*certValidityPeriod).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
			},
		},
		Serial: serial,
	}
	if err := cert.SignCert(rand.Reader, caKey); err != nil {
		stderr.Println(err)
		return
	}
	msg := fmt.Sprintf("Issuing cert %d for key %s valid %v",
		serial,
		ssh.FingerprintSHA256(userKey),
		*certValidityPeriod,
	)
	sysl.Info(msg)
	stderr.Println(msg)
	stdout.Printf("%s", ssh.MarshalAuthorizedKey(cert))
}

// pullItem pulls an item from 1p
func pullItem(ctx context.Context, ref string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "op", "read", ref)
	var stderr bytes.Buffer
	var stdout bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &stdout
	err := cmd.Run()
	if err != nil {
		// timeout
		if ctx.Err() == context.DeadlineExceeded {
			err = errors.Join(err, ctx.Err())
			return nil, err
		}
		err = fmt.Errorf("%w: %s", err, stderr.Bytes())
		return nil, err
	}
	return stdout.Bytes(), nil
}

func parsePrivKey(ctx context.Context, ref string) (ssh.Signer, error) {
	b, err := pullItem(ctx, ref)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(b)
}

func parsePubKey(ctx context.Context, ref string) (ssh.PublicKey, error) {
	b, err := pullItem(ctx, ref)
	if err != nil {
		return nil, err
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(b)
	return pubKey, err
}
