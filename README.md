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


## Video demo
[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/o2lv3EBrp68/maxresdefault.jpg)](https://www.youtube.com/watch?v=o2lv3EBrp68)


## List of client commands
Command | Action
| --- | --- |
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
On the server side, all connection activity (connected, disconnected, timeout, etc) are logged to a file called `chat.log` with the function 
```c
void client_logger(struct client_data *client, int status)
```


### 4 List of connected users
To suppoert multiple connection, we use `select()` wrapped in the following function.
```c
int SELECT(fd_set *rfds, int server_fd)
{
	// Restart pool
	FD_ZERO(rfds);

	// Add file descriptors to pool
	FD_SET(server_fd, rfds);
	int max_fd = server_fd;

	// Find the largests file descriptor
	g_tree_foreach(client_collection, get_max_fd, &max_fd);

	// Add all existing clients to the pool
	g_tree_foreach(client_collection, fd_set_all, rfds);

	// Set inactive time
	struct timeval tv;
	tv.tv_sec = TIME_OUT_CHECK_INTERVAL;
	tv.tv_usec = 0;

	return select(max_fd + 1, rfds, NULL, NULL, &tv);
}
```
After this function we check if a new client wants to connect with `FD_ISSET(server_fd, &rfds)` and if so, we add him to the list of clients.

The clients are kept in a tree map, that maps the pair of ip address and ports to the following struct.
```c 
struct client_data
{
	int fd;
	SSL *ssl;
	struct sockaddr_in addr;
	char *name;
	char *room;
	time_t timer;
};
```

In every iteration of our server loop, we check if a clients has something to say and if one does and has given the who-command, we respond by sending a buffer that has every client appended to it via foreach iteration of the client tree. Foreach client, we will list the following information:
* name
* chatroom
* ip
* port


### 5 Chat room
Chat rooms are kept in a tree that maps their name to another tree of users. The subtree holds the users currently in that channel. Although, a different tree from the client one, it uses the same memory. That is, suppose some client belongs to the tree of clients and a some subtree for a specific channel, then the memory allocated for him in the client tree is the same in the chat room's subtree. This means that memory is never freed in that tree, we only remove its entries. 

If the client sends a `/list` request, we iterate through the tree of chat rooms and append their name to a buffer which is sent to the appropriate client. No information, other than its name, are kept for the chat rooms but the subtree keeps track of its count of course, so we have easy access to the client count in each channel.

Initally there is a channel called lobby and all new clients are directed to it. If a client asks to join a channel that does not exist, we create it, and then make him join it. Otherwise we just add him to it directly. If the client leaves (or disconnects) we check his previous channel and if empty, we remove it and clean up its resources. Upon swapping chat rooms, we remove client from the old chat room's subtree and add them to the new one's tree. 

### 6 Authentication
#### 6.1 
The authentication process is split into multiple steps and are split up both on the client and the Server

The Clients prompts the server to let him know that hes trying to log in with the command:  `/user 'username'`, then the user is asked to enter the password, the password is not displayed on the console so no one can see it.

##### The Client #####
Hashes the password before sending it to the Server so not even the server knows the password so it is as secure as possible. Then the Client sends the username and the hashed password to the server.

##### The Server #####
Checks to see if there is a user already logged in with the given username, if so you can't login, since there can't be two  with the same username.

If no one is logged in with that username the server checks in its `password.ini` file if the user already exists, if it does, the server matches its stored hashed version of the password with the password it recived from the Client, if they are a match you are logged in to the system, if not you get 2 more tries to give the correct password, failing in doing so will terminate the connection to the server and close the client.

If no user is found with that username in the `password.ini` file the server then saves the user and the password in the file for later use and the user is then logged in.

There are no session tokes passed from the server to the client so upon closing the client you have to log into the server again with username and password.

#### 6.2 
The passwords are stored in a file on the server, in the `passwd` folder in the root. There is a file called `passwd.ini` that stores usernames and their `Sha256` hased passwords to match with what users send in.
There is a hardcoded string that is appended to the user password before we hash it with Sha256. This is done to prevent the use of Rainbow tables and other ways to check the hash string against known common passwords.

We send the passwords hashed from the client to the server since there is no reason for the server to get it in plain text from the client, even tho no one can read them while they are passed through the SSL connection, its a good security mesure for almost no extra time.

No one should be able to read the password in transit due to the nature of the SSL connection, all communications between the server and clients are encrypted by the connection.

The main security implication is how the usernames and passwords are stored, since this is just in a regulare text-file on the server, its easy to just go to the file and replace a hashed password with a hash string that you know the actual password to and then login with that password


### 7 Private messages
#### 7.1 
To handle the private messages, we start by splitting the string sent by the client in two: `char *receiver` and `char *message`.
We then append the two strings into `GList *list` and search the `client_collection` for the receiver of the message. If the message is found, we send the message to the receiver.

#### 7.2 
We do not log any private messages as that can not be stored safely. They could contain private information that people would not want to share with anyone. Since we do not store any of this data, users can not see their history and the chat can not store any information for them, if needed later. 


### 8 Idle timeouts
#### 8.1 
To handle timeouts we kept track of the time for every client with a `time_t` struct. When a new client is added, the current time is set. Whenever select returns 0 (which is set very low), the server checks every client and compares there time to the current time. If it has passed the maximum we disconnect them and log it as a timeout. Whenever a command or message is received from a client, we reset his time to the current.

#### 8.2 
If we do not close the connection and the client does not terminate it either, anyone who can access the computer can access the chat as the other person. This is the main reason that the banks timeout there clients in their online serivces for example. To make sure timeouts happen, we run a check on every client.

### 9 Dice
#### 9.1 
To start the game we send a request to the client by writing `/game client_name`. We start by searching for the client. If the client exists, we send a message to that client asking if he wants to start a game. The receiver of the request can then do a `/roll` to generate a random number. 
This is how we generate the seed which is used by both clients.
```c
time_t t;
srand((unsigned) time(&t));
```
Then, when either user rolls the dice, we use `rand() % 5 + 1` to generate a random number from 1 to 6. Both numbers are then checked and we check who the winner is, or if there was a draw.
The server waits until both players have rolled to calculate the outcome.
#### 9.2
The only way to cheat in such a game like this, is to learn the pattern of the pseudo random numbers, returned by `drand48()`. We prevent that by seeding the function with the current time for any game played.
