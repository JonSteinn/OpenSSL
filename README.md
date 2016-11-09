# OpenSSL
A chat server that uses OpenSSL

## Questions and implemented features

### 1 Key management
Following the [OpenSSL coobook](https://www.feistyduck.com/library/openssl-cookbook/online/	), we generated the following:
* RSA private key called fd.key with the command
```bash
$ openssl genrsa -aes128 -out fd.key 2048
```
* RSA public key called fd-public.key with the command
```bash
$ openssl rsa -in fd.key -pubout -out fd-public.key
```
* Certificate signing request called fd.csr with the command 
```bash
openssl req -new -key fd.key -out fd.csr
```
* Self signed certificate called fd.crt with the command
```bash
openssl x509 -req -days 365 -in fd.csr -signkey fd.key -out fd.crt
```
The pass phrase is 'tussuduft'.

### 2 OpenSSL initialisation

### 3 Secure client server connection

### 4 List of connected users

### 5 Chat room

### 6 Authentication

### 7 Private messages

### 8 Idle timeouts

### 9 Dice
