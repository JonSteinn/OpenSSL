# OpenSSL
A chat server that uses OpenSSL


## Compile and run
In the root folder, run the following command to compile.
```bash
make -C src/
```
To run the server, enter
```bash
./src/chatd 8000
```
which will open the server on port 8000. Any non-system port can be chosen. To run the client, enter
```bash
./src/chat 8000
```
A server must be running locally on the same port in order to run the client. The localhost in hardcoded in the server but that is easy to change.


## List of client commands
Command | Action
--- | --- | ---
`/bye` | exit
`/quit` | exit
`/game <user>` | prompt a user to play a game
`/join <chat room>` | join a chat room
`/list` | get a list of all chat rooms
`/roll` | roll in a game
`/say <user>` | send a private message
`/user <name>` | identify as a user
`/who` | get a list of all users
`/yes` | accept a game prompt
`/no` |  decline a game prompt
`<message>` | send 'string' to current chat room



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
If the user does not enter 'tussuduft', he will not be granted access to run up the server.


### 3 Secure client server connection
To connect to the client we must use the standard socket c library and make a SSL connection using the OpenSSL libary. This is accomplished with the following function calling in main.
```c
// Connect to server
server_fd = init_server_connection(server_port);

// Initialize OpenSSL connection
init_ssl();
```
On the server side, all connection activity (connected, disconnected, timeout, etc) are logged to a file called chat.log with the function 
```c
void client_logger(struct client_data *client, int status)
```


### 4 List of connected users



### 5 Chat room

### 6 Authentication
#### 6.1
#### 6.2


### 7 Private messages
#### 7.1
#### 7.2


### 8 Idle timeouts
#### 8.1
#### 8.2


### 9 Dice
#### 9.1
#### 9.2