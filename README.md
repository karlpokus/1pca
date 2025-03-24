# 1pca
Private certificate authority stored in 1password. Easy to rotate: just update the key and `TrustedUserCAKeys` on the host(s).

Requires keys stored in 1password and the cli option enabled.

# Usage

````sh
# The cli dumps the cert to stdout by default. Use `-h` for help.
#
# Optionally pass a config file to `-config` with the args as keys. 
$ go run main.go
````

Note! `ssh-keygen` does not allow passing keys on stdin nor as strings but go does.

# TODOs
- [ ] Ansible playbook
- [ ] AWS KMS support
