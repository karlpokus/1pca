# 1pca
Private certificate authority stored in 1password. Easy to rotate: just update the key and `TrustedUserCAKeys` on the host(s).

Requires keys stored in 1password and the cli option enabled.

# Usage

````sh
$ go run main.go -h
````

Note! `ssh-keygen` does not allow passing keys on stdin nor as strings but go does.

# TODOs
- [ ] Ansible playbook
- [ ] AWS KMS support
