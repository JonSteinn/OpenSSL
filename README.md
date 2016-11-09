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
Using the SSL libary, we initialize OpenSSL and the self signed certificate in the following function
```c
void init_SSL()
{
	// Internal SSL init functions
	SSL_library_init();
	SSL_load_error_strings();

	// Authentication
	if ((ctx = SSL_CTX_new(TLSv1_method())) == NULL) exit_error("SSL CTX");
	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0) exit_error("certificate");
	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) exit_error("privatekey");
	if (SSL_CTX_check_private_key(ctx) != 1) exit_error("match");

	// Message to user
	fprintf(stdout, "Access granted\n");
	fflush(stdout);
}
```


### 3 Secure client server connection

### 4 List of connected users

### 5 Chat room

### 6 Authentication

### 7 Private messages

### 8 Idle timeouts

### 9 Dice
