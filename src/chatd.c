/***********************************************
   __________     ____
  / __/ __/ /    / __/__ _____  _____ ____
 _\ \_\ \/ /__  _\ \/ -_) __/ |/ / -_) __/
/___/___/____/ /___/\__/_/  |___/\__/_/

************************************************
JON STEINN ELIASSON   - JONSTEINN@GMAIL.COM
DADI GUDVARDARSON     - DADIG4@GMAIL:COM
DANIEL ORN STEFANSSON - DANIEL@STEFNA.IS
************************************************/

/* Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <glib.h>
#include <math.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <ctype.h>





/* Defines */

/* Used to fool compiler with unused parameters */
#define UNUSED(x) (void)(x)

/* Paths to file. These are relative to the root of the project.
 * By adding '../' in front, one can run from '/src'. */
#define CERTIFICATE "encryption/fd.crt"
#define PRIVATE_KEY "encryption/fd.key"
#define PASSWORD_FILE "passwd/passwd.ini"

/* Flags for logger */
#define LOG_DISCONNECTED 0
#define LOG_CONNECTED 1
#define LOG_TIMED_OUT 2
#define LOG_AUTH_FAIL 3
#define LOG_AUTH_SUCC 4

/* Metrics for clients */
#define MAX_QUEUED 5

/* Timers */
#define TIME_OUT_CHECK_INTERVAL 1
#define CLIENT_TIMEOUT 30

/* Initial namings */
#define INIT_CHANNEL "Lobby"
#define INIT_USER "Anonymous"

/* Commands */
#define BYE "/bye"
#define QUIT "/quit"
#define GAME "/game"
#define JOIN "/join"
#define LIST "/list"
#define ROLL "/roll"
#define SAY "/say"
#define USER "/user"
#define WHO "/who"
#define YES "/yes"
#define NO "/no"

/* Messages */
#define GREET "WELCOME"

/* Buffer sizes */
#define MESSAGE_SIZE 512
#define TIME_SIZE 25





/* Data structure for clients. It includes the following fields:
 *   (identifier, type, description)
 *   1: fd, int, file descriptor
 *   2: ssl, SSL, SSL connection
 *   3: addr, struct sockaddr_in, port&ip info
 *   4: name, char *, name of user
 *   5: room, char *, current channel
 * Each new member will receive one and initially, all will be set
 * to the inital channel. */
struct client_data
{
	int fd;
	SSL *ssl;
	struct sockaddr_in addr;
	char *name;
	char *room;
	time_t timer;
};





/* Global variables */
static GTree *client_collection;
static GTree *room_collection;
static SSL_CTX *ctx;
int running = TRUE;





/* Initializers */
void init_SSL();
int init_server(int port);
void init_chat_rooms();

/* Comparators */
int sockaddr_in_cmp(const void *addr1, const void *addr2);
int chat_cmp(const void *name1, const void *name2);
int find_chat_room(const void *name1, const void *name2);

/* Add to */
void add_room(char *name);
void add_client(int server_fd, SSL_CTX *ctx);

/* Request handlers */
void handle_who(SSL *ssl);
void handle_list(SSL *ssl);
void handle_say(char *sender, char *buffer);
void handle_join(struct client_data *client, char *buffer);
void handle_user(struct client_data *client, char *buffer);
void handle_game(struct client_data *client, char *buffer);

/* Memory clean up */
void free_client(struct client_data *client, int flag);
void clean_all();

/* Misc */
void server_loop(int server_fd);
int SELECT(fd_set *rfds, int server_fd);
void client_logger(struct client_data *client, int status);
void exit_error(char *msg);
int has_timed_out(time_t client_time);

/* Tree iterations */
gboolean get_max_fd(gpointer key, gpointer val, gpointer data);
gboolean fd_set_all(gpointer key, gpointer val, gpointer data);
gboolean responde_to_client(gpointer key, gpointer value, gpointer data);
gboolean append_client_list(gpointer key, gpointer val, gpointer data);
gboolean append_chat_rooms(gpointer key, gpointer val, gpointer data);
gboolean send_to_room(gpointer key, gpointer val, gpointer data);
gboolean find_user_by_name(gpointer key, gpointer val, gpointer data);
gboolean delete_empty_room(gpointer key, gpointer val, gpointer data);
gboolean clean_all_rooms(gpointer key, gpointer val, gpointer data);
gboolean clean_all_clients(gpointer key, gpointer val, gpointer data);
gboolean timeout_checker(gpointer key, gpointer val, gpointer data);
gboolean find_user_and_respond_to_game(gpointer key, gpointer val, gpointer data);
gboolean check_availability(gpointer key, gpointer val, gpointer data);





/* Starting point */
int main(int argc, char **argv)
{
	// If sufficient arguments are not provided
	if (argc < 2) exit_error("argument");

	// Convert port to int
	const int server_port = strtol(argv[1], NULL, 0);

	// Message to user
	fprintf(stdout, "Starting server on port %d\n", server_port);
	fflush(stdout);

	// Initialize OpenSSL connection
	init_SSL();

	// Socket setup
	int server_fd = init_server(server_port);

	// Initialize collection for clients where (port, ip) pairs are keys
	client_collection = g_tree_new(sockaddr_in_cmp);

	// Initialize chat rooms
	init_chat_rooms();

	// Runs until interrupted
	server_loop(server_fd);

	// Empty all trees and their resources
	clean_all();

	exit(EXIT_SUCCESS);
}





/* Prints msg to standard error and exits with error code EXIT_FAILURE */
void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}





/* Sets up SSL and check if key matches. All error results in termination. */
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





/* Removes everything from all data structures and frees their emory */
void clean_all()
{
	// Clean rooms 
	g_tree_foreach(room_collection, clean_all_rooms, NULL);
	g_tree_destroy(room_collection);

	// Clean clients
	g_tree_foreach(client_collection, clean_all_clients, NULL);
	g_tree_destroy(client_collection);
}





/* Sets up socket and error checks while doing so. We allocate the
 * sockaddr_in struct's resources after this functions since we do
 * not need it elsewhere. Returns file descriptor of server */
int init_server(int port)
{
	// Setup socket
	int socket_fd;
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit_error("socket");

	// Init server struct
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);

	// Bind to port and listen
	if (bind(socket_fd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) < 0) exit_error("bind");
	if (listen(socket_fd, MAX_QUEUED) < 0) exit_error("listen");

	// Message to user
	fprintf(stdout, "Server setup complete\n");
	fflush(stdout);

	return socket_fd;
}





/* Creates data structure for chats and creates the first
 * channel that everyone will enter initially. */
void init_chat_rooms()
{
	// Create new tree collection for chats with name comparatores.
	room_collection = g_tree_new(chat_cmp);

	// Add lobby to structure
	add_room(INIT_CHANNEL);

	// We can add more channels if we want more predefined.
	//add_room("chat room 1");
	//add_room("chat room 2");
	//add_room("chat room 3");
}





/* Add room to tree */
void add_room(char *name)
{
	// Add to tree
	g_tree_insert(room_collection, g_strdup(name), g_tree_new(sockaddr_in_cmp));
}





/* Comparator for sockaddr to keep tree balanced. Uses
 * dictionary ordering on (addr, port) pairs. Returns
 *    0 if equal
 *    1 if addr1 > addr2
 *   -1 if addr1 < addr2 */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;

	// If IP 1 < IP 2
	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) return -1;
	// if IP 1 > IP 2
	if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) return 1;
	// If port 1 < port 2
	if (_addr1->sin_port < _addr2->sin_port) return -1;
	// if port 2 < port 1
	if (_addr1->sin_port > _addr2->sin_port) return 1;
	// equals
	return 0;
}





/* Compare function for chat tree. Returns
 *    0 if equal,
 *    1 if name1 > name2,
 *    -1 if nam1 < name2. */
int chat_cmp(const void *name1, const void *name2)
{
	return g_strcmp0((char *)name1, (char *)name2);
}





/* Free client completely from server. Frees memory in all
 * collections and closes connection*/
void free_client(struct client_data *client, int flag)
{
	// Log client' departure
	client_logger(client, flag);

	// Close connection and free connection resoures
	close(client->fd);
	SSL_shutdown(client->ssl);
	SSL_free(client->ssl);

	// Remove user from channel's list of users without freeing memory
	char *channel = client->room;
	g_tree_remove(g_tree_search(room_collection, find_chat_room, channel), &client->addr);

	// Free memory
	g_free(client->name);
	g_free(channel);
	g_tree_remove(client_collection, &client->addr);
	g_free(client);
}





/* Main loop of server */
void server_loop(int server_fd)
{
	// Loop indefinitely
	while (running)
	{
		// Wait for request
		fd_set rfds;
		int r = SELECT(&rfds, server_fd);

		if (r < 0)
		{
			// If select returns an error, we close the client
			// unless EINTR error, then we skip the iteration
			if (errno == EINTR) continue;
			perror("select()");
			break;
		}

		// Check for timeouts                                                 
		if (r == 0) g_tree_foreach(client_collection, timeout_checker, NULL);

		// If new client awaits
		if (FD_ISSET(server_fd, &rfds)) add_client(server_fd, ctx);

		// Handle all existing client's requests
		g_tree_foreach(client_collection, responde_to_client, &rfds);

		// Remove empty channels (other than lobby)
		g_tree_foreach(room_collection, delete_empty_room, NULL);
	}
}






/* A wrapped version select, that handles attinional logic.
 * Returns the return value of select() */
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





/* Add client to server. */
void add_client(int server_fd, SSL_CTX *ctx)
{
	// Allocate memory for tree entry
	struct client_data *client = g_new0(struct client_data, 1);
	socklen_t scklen = (socklen_t)sizeof(client->addr);

	// Create connection
	if ((client->fd = accept(server_fd, (struct sockaddr *)&client->addr, &scklen)) < 0)
	{
		perror("accept()");
		g_free(client);
		return;
	}
	if ((client->ssl = SSL_new(ctx)) == NULL)
	{
		perror("SSL");
		g_free(client);
		return;
	}
	if (SSL_set_fd(client->ssl, client->fd) == 0)
	{
		perror("SSL fd");
		g_free(client);
		return;
	}
	if (SSL_accept(client->ssl) < 0)
	{
		perror("SSL accept()");
		g_free(client);
		return;
	}

	// Message to user
	fprintf(stdout, "New client! FD = %d\n", client->fd);
	fflush(stdout);

	// Set room and name with allocated memory
	client->room = g_strdup(INIT_CHANNEL);
	client->name = g_strdup(INIT_USER);

	// Set timeout to 0
	client->timer = time(&client->timer);

	// Add client to client collection
	g_tree_insert(client_collection, &client->addr, client);

	// Add client to Lobby tree. Notice that we are using the same memory for both trees!
	// That will result in us only freeing the one from the client collection when he
	// leaves and for the others, we just need to remove from tree so they do not have an
	// address to random memory. The same goes when switching channels.
	g_tree_insert(g_tree_search(room_collection, find_chat_room, INIT_CHANNEL), &client->addr, client);

	// Greeting message sent to client
	if (SSL_write(client->ssl, GREET, strlen(GREET)) < 0) perror("SSL write");

	// Log users connection
	client_logger(client, LOG_CONNECTED);

}





/* Opposite comparator for chat rooms */
int find_chat_room(const void *name1, const void *name2)
{
	// Store reference
	const char *first = name1;
	const char *second = name2;

	// Compare strings, return opposite if non-equal
	int x = g_strcmp0(first, second);
	if (x > 0) return -1;
	if (x < 0) return 1;
	return 0;
}





/* Returns true iff timer of client has passed CLIENT_TIMEOUT */
int has_timed_out(time_t client_time)
{
	time_t current;
	time(&current);
	return (difftime(current, client_time) >= CLIENT_TIMEOUT) ? 1 : 0;
}





/* Time stamp on client action, in local file system. */
void client_logger(struct client_data *client, int status)
{
	// Convert ip to string
	char *ip = inet_ntoa(client->addr.sin_addr);

	// Convert port to short
	uint16_t port = client->addr.sin_port;

	// Set ISO time
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char timestamp[TIME_SIZE];
	memset(timestamp, 0, sizeof(timestamp));
	strftime(timestamp, 80, "%a, %d %b %Y %X GMT", timeinfo);

	// Open filestream and append to chat.log
	FILE *tof;
	if((tof = fopen("chat.log", "a")) == NULL)
	{
	        perror("Log");
	        return;
	}

	// Formatting
	fwrite("<", 1, 1, tof);
	fwrite(timestamp, 1, strlen(timestamp), tof);
	fwrite("> : <", 1, 5, tof);
	fwrite(ip, 1, strlen(ip), tof);
	fwrite("> : <", 1, 5, tof);
	fprintf(tof, "%d",port );
	fwrite(">", 1, 2, tof);

	// Set status
	if (status == LOG_CONNECTED) fwrite(" : <CONNECTED>\n", 1, 15, tof);
	else if (status == LOG_DISCONNECTED) fwrite(" : <DISCONNECTED>\n", 1, 18, tof);
	else if (status == LOG_TIMED_OUT)  fwrite(" : <TIMED OUT>\n", 1, 18, tof);
	else if (status == LOG_AUTH_FAIL)  fwrite(" : <AUTHENTICATION ERROR>\n", 1, 26, tof);
	else if (status == LOG_AUTH_SUCC)  fwrite(" : <AUTHENTICATED>\n", 1, 19, tof);

	// Release resources
	fflush(tof);
	fclose(tof);
}





/* Create response for /who request */
void handle_who(SSL *ssl)
{
	// Create an empty string that handles memory allocation during appending.
	GString *buffer = g_string_new(NULL);

	// Set the header of the message
	buffer = g_string_append(buffer, "\nList of clients:\n");
	// Pass string to foreach method that appends users to it
	g_tree_foreach(client_collection, append_client_list, buffer);

	// Send list of clients (including self) to requesting client
	if (SSL_write(ssl, buffer->str, buffer->len) < 0) perror("SSL write");

	// Release string resources
	g_string_free(buffer, TRUE);
}





/* Responds to clients requesting a private message to another user.
 * If the user does not exist(or has no nickname), the client will
 * be notified.  */
void handle_say(char *sender, char *buff)
{
	// Initialize data types
	char *receiver;
	char *message;

	/* Parse through the buffer and find the receiver
	 * of the message and the message to send */
	int i = 4;
	while (buff[i] != '\0' && isspace(buff[i])) {i++;}
	int j = i+1;
	while (buff[j] != '\0' && isgraph(buff[j])) {j++;}

	receiver = strndup(&(buff[i]), j - i);

	// No message allowed to anonymous
	if (g_strcmp0(receiver, INIT_USER) == 0)
	{
		g_free(receiver);
		return;
	}

	message = g_strchomp(&buff[i + strlen(receiver) + 1]);

	// Create a list and insert the receiver, sender and the message
	GList *list = NULL;
	list = g_list_append(list, receiver);
	list = g_list_append(list, sender);
	list = g_list_append(list, message);

	// Find the user by name and send the private message
	g_tree_foreach(client_collection, find_user_by_name, list);

	// Free string resources
	g_free(receiver);
}





/* Create response for /list request */
void handle_list(SSL *ssl)
{
	// Buffer to send.
	GString *buffer = g_string_new("\n\nList of chat rooms:");

	// A string for foreach-method appending
	g_tree_foreach(room_collection, append_chat_rooms, buffer);
	buffer = g_string_append(buffer, "\n");

	// Send list of channels (including his current) to requesting client
	if (SSL_write(ssl, buffer->str, buffer->len) < 0) perror("SSL write");

	// Release string resources
	g_string_free(buffer, TRUE);
}





/* Responds to clients request of joining a channel. If the channel does
 * not exist, we create it but.  */
void handle_join(struct client_data *client, char *buffer)
{
	// Remove client from old channel, clean up memory used for old channel's name.
	g_tree_remove(g_tree_search(room_collection, find_chat_room, client->room), &client->addr);
	g_free(client->room);

	// Remove trailing whitespace
	char *room_name = g_strchomp(&buffer[6]);

	// If room does not exist, we create a new one. In the end, tree will point to the 
	// room with the given name, regardless if it did exist before or not.
	GTree *tree;
	if ((tree = g_tree_search(room_collection, find_chat_room, room_name)) == NULL)
	{
		add_room(room_name);
		tree = g_tree_search(room_collection, find_chat_room, room_name);
	}

	// Allocate memory for client's new chat room name.
	client->room = strdup(room_name);

	// Add client to channel's tree
	g_tree_insert(tree, &client->addr, client);
}





/* Sets the user name of the client */
void handle_user(struct client_data *client, char *buffer)
{
	// Get the new name from buffer
	char *name = g_strchomp(&buffer[6]);
	char pass[65];

	int is_available = 1;

	GList *lst = NULL;
	lst = g_list_append(lst, name);
	lst = g_list_append(lst, (gpointer)&is_available);

	g_tree_foreach(client_collection, check_availability, lst);
	
        SSL_read(client->ssl, pass, sizeof(pass) - 1);

	if (is_available)
	{
		//new KeyFile Object
		GKeyFile *keyfile = g_key_file_new();
		//Get from the current KeyFile
		g_key_file_load_from_file(keyfile, PASSWORD_FILE, G_KEY_FILE_NONE, NULL);
		if (g_key_file_has_key(keyfile, "passwords", name, NULL)) {
			//User was found
			//Request Password
			char *md = g_key_file_get_value(keyfile, "passwords", name, NULL);
			if (strcmp(md, pass) == 0) {
				//its a Match!
				memset(pass, 0, sizeof(pass));
				g_free(client->name);
				client->name = strdup(name);
				SSL_write(client->ssl, "--accepted", 10);
				client_logger(client, LOG_AUTH_SUCC);
			} else {
				client_logger(client, LOG_AUTH_FAIL);
				memset(pass, 0, sizeof(pass));
				//Incorrect passWord
				for (int i = 0; i < 2; i++) { //Allow 2 more attempts
					if (SSL_write(client->ssl, "--wrongPass", strlen("--wrongPass")) < 0) perror("ssl_write");
					SSL_read(client->ssl, pass, sizeof(pass) - 1);
					
					if (strcmp(md, pass) == 0) {
						g_free(client->name);
						client->name = strdup(name);
						client_logger(client, LOG_AUTH_SUCC);
						SSL_write(client->ssl, "--accepted", 10);
						memset(pass, 0, sizeof(pass));
						break;
					}
					memset(pass, 0, sizeof(pass));
					client_logger(client, LOG_AUTH_FAIL);
				}
			}
		} else {
			if (SSL_write(client->ssl, "--newUser", 9) < 0) perror("ssl_write");
			//User Not found so we make new one
			g_key_file_set_string(keyfile, "passwords", name, pass);
			// Save the file
			memset(pass, 0, sizeof(pass));
			g_key_file_save_to_file (keyfile, PASSWORD_FILE, NULL);
			g_free(client->name);
			client->name = strdup(name);
			client_logger(client, LOG_AUTH_SUCC);

		}	
	} else {
		//not Avalible
		 if (SSL_write(client->ssl, "--notAvalible", 13) < 0) perror("ssl_write");
	}
	memset(pass, 0, sizeof(pass));
}





/* Initializes game playing request */
void handle_game(struct client_data *client, char *buffer)
{
	// Remove trailing whitespace
	char *receiver = g_strchomp(&buffer[6]);

	// No games allowed with unamed users
	if (g_strcmp0(receiver, INIT_USER) == 0) return;

	// Create a list and insert the receiver and the sender
	GList *list = NULL;
	list = g_list_append(list, receiver);
	list = g_list_append(list, client);

	// Find the user by name and send the game request
	g_tree_foreach(client_collection, find_user_and_respond_to_game, list);
}





/* Iteration-bound. Runs through the tree of clients, and for those
 * who "have something to say", we process the request. Return value
 * is irrelivant. */
gboolean responde_to_client(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Each client
	struct client_data *client = (struct client_data *)val;

	// If client has something to say
	if (FD_ISSET(client->fd, (fd_set *)data))
	{
		// Clean buffer
		char buff[MESSAGE_SIZE];
		memset(buff,0, sizeof(buff));

		// If read is successfull
		if (SSL_read(client->ssl, buff, sizeof(buff) - 1) > 0)
		{
			// Timer is restart since client has proven to be active
			client->timer = time(&client->timer);

			// Cases of different requests. Else case serves for standard messages.
			if (strncmp(buff, "/who", 4) == 0) handle_who(client->ssl);
			else if (strncmp(buff, "/bye", 4) == 0) free_client(client, LOG_DISCONNECTED);
			else if (strncmp(buff, "/list", 5) == 0) handle_list(client->ssl);
			else if (strncmp(buff, "/join", 5) == 0) handle_join(client, buff);
			else if (strncmp(buff, "/say", 4) == 0) handle_say(client->name, buff);
			else if (strncmp(buff, "/user", 5) == 0) handle_user(client, buff);
			else if (strncmp(buff, "/game", 5) == 0) handle_game(client, buff);
			else g_tree_foreach(g_tree_search(room_collection, find_chat_room, client->room), send_to_room, buff);
		}
		else free_client(client, LOG_DISCONNECTED); // Assumed dead
	}

	return FALSE;
}





/* Iteration-bound. Runs through the tree of clients, finding
 * the largest file descriptor and passing it back through data.
 * Return value is irrelivant. */
gboolean get_max_fd(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// If current max is less than this fd, we replace max
	int this_fd = ((struct client_data *)val)->fd;
	if (this_fd > *((int *)data)) *((int *)data) = this_fd;

	return FALSE;
}





/* Iteration-bound. Adds every current client's file descriptor
 * to the pool of fd's that are checked for requests. Return
 * value is irrelivant. */
gboolean fd_set_all(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Adds current client (in a iteration) to ppol
	FD_SET(((struct client_data *)val)->fd, (fd_set *)data);

	return FALSE;
}





/* Iteration-bound. Adds each chat room name to a string.
 * Return value is irrelivant. */
gboolean append_chat_rooms(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(val);

	// Append user to string
	GString *buffer = (GString *)data;
	buffer = g_string_append(buffer, "\n");
	buffer = g_string_append(buffer, (char *)key);

	return FALSE;
}





/* Iteration-bound. Adds each client name to a string.
 * Return value is irrelivant. */
gboolean append_client_list(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Store parameter pointers on correct format locally.
	struct client_data *client = (struct client_data *)val;
	GString *buffer = (GString *)data;

	// Convert (ip, port) data.
	char *ip = inet_ntoa(client->addr.sin_addr);
	gchar *port = g_strdup_printf(":%i ", client->addr.sin_port);

	// Add name to buffer
	buffer = g_string_append(buffer, "\nName: ");
	if (client->name != NULL) buffer = g_string_append(buffer, client->name);

	// Add chat to buffer
	buffer = g_string_append(buffer, "\nChat room: ");
	if (client->room == NULL) buffer = g_string_append(buffer, "No Room");
	else buffer = g_string_append(buffer, client->room);

	// Formatting
	buffer = g_string_append(buffer, "\nIP: ");
	buffer = g_string_append(buffer, ip);
	buffer = g_string_append(buffer, "\nPort: ");
	buffer = g_string_append(buffer, port);
	buffer = g_string_append(buffer, "\n");

	// Free memory
	g_free(port);

	return FALSE;
}





/* Iteration-bound. Sends message to everyone in a specific
 * channel. Return value is irrelivant. */
gboolean send_to_room(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Send message to current client (in a iteration).
	if (SSL_write(((struct client_data *)val)->ssl, data, strlen(data)) < 0) perror("SSL write");

	return FALSE;
}





/* Iterates through a a collection of users. If the name of the user
 * is found, a private message it sent to that user. */
gboolean find_user_by_name(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Initialize data types
	struct client_data *client = val;
	GList *list = data;

	// Get the name of the user supposed to receive the message
	char *receiver = g_list_nth_data(list, 0);

	// If the receiver is found in the collection
	if (strcmp(client->name, receiver) == 0)
	{
		/* Get the  data from the list and make a private
		 * message prompt */
		char *sender = g_list_nth_data(list, 1);
		char *message = g_list_nth_data(list, 2);
		char *private = "<private> : ";

		// A string to hold the message
		GString *string = g_string_new(sender);

		// Append all information to the string
		g_string_append(string, " ");
		g_string_append(string, private);
		g_string_append(string, message);

		// Send a privat message in the format sender <private> message
		SSL_write(client->ssl, string->str, string->len);

		// Release resources
		g_string_free(string, TRUE);
	}

	return FALSE;
}





/* On iteration, removes channel if empty. It does not free value
 * since we are using it in the client tree but name is freed.  */
gboolean delete_empty_room(gpointer key, gpointer val, gpointer data)
{
	// Fool compiler
	UNUSED(data);

	// If string is not INIT_CHANNEL
	if (g_strcmp0((char *)key, INIT_CHANNEL))
	{
		// NULL case is without desroy
		if (val == NULL)
		{
			g_tree_remove(room_collection, (char *)key);
			g_free((char *)key);
		}
		else if (g_tree_nnodes((GTree *)val) == 0)
		{
			g_tree_remove(room_collection, (char *)key);
			g_free((char *)key);
			g_tree_destroy((GTree *)val);
		}
	}
	return FALSE;
}




/* On iteration, cleans all rooms */
gboolean clean_all_rooms(gpointer key, gpointer val, gpointer data)
{
	// Fool compiler
	UNUSED(data);

	// Free string memory
	g_free((char *)key);

	// We only remove the tree, the deep memory will
	// be free when client_collection is destroyed.
	g_tree_destroy((GTree *)val);

	return FALSE;
}




/* On iteration, cleans all clients */
gboolean clean_all_clients(gpointer key, gpointer val, gpointer data)
{
	// Fool compiler
	UNUSED(key);
	UNUSED(data);

	// Store reference
	struct client_data *client = (struct client_data *)val;

	// Close connection and free connection resoures
	close(client->fd);
	SSL_shutdown(client->ssl);
	SSL_free(client->ssl);

	// Free memory
	g_free(client->name);
	g_free(client->room);
	g_free(client);

	return FALSE;
}





/* On iteration, checks if clients have timed out and if
 * so, he requests that the connection will be terminated. */
gboolean timeout_checker(gpointer key, gpointer val, gpointer data)
{
	// Fool compiler
	UNUSED(key);
	UNUSED(data);

	// If time has past idle limit, we terminate connection.
	if (has_timed_out(((struct client_data *)val)->timer)) free_client((struct client_data *)val, LOG_TIMED_OUT);

	return FALSE;
}





/* On iteration, checks if the user that has been requested
 * to play a game exists. If so, they will play a game of dice.
*  If he does not exist, nothing happens. */
gboolean find_user_and_respond_to_game(gpointer key, gpointer val, gpointer data)
{
	// Avoid compiler warnings
	UNUSED(key);

	// Initialize data types
	struct client_data *receiver = val;
	GList *list = data;

	// Get the name of the user supposed to receive the message
	char *receiver_name = g_list_nth_data(list, 0);

	// If the receiver is found in the collection
	if (strcmp (receiver->name, receiver_name) == 0)
	{
		/* Get the  data from the list and make a private
		 * message prompt */
		struct client_data *sender = g_list_nth_data(list, 1);
		char *sender_name = sender->name;

		// Build string to hold the message
		GString *string = g_string_new("Would you like to play a game with ");
		string = g_string_append(string, sender_name);
		string = g_string_append(string, " /yes | /no");

		// Send a game request
		if (SSL_write(receiver->ssl, string->str, string->len) < 0) perror("SSL_write");

		// Buffer to hold the answer to the game request
		char buff[MESSAGE_SIZE];
		memset(buff,0, sizeof(buff));

		// Check if the recipient wants to play or not
		if (SSL_read(receiver->ssl, buff, sizeof(buff) - 1) > 0)
		{
			// Build a string to send to the sender
			GString *msg = g_string_new(receiver->name);
			msg = g_string_append(msg, " accepted your request!");

			// Send a response to the sender requesting the game, that the game has been accepted
			if (SSL_write(sender->ssl, msg->str, msg->len) < 0) perror("SSL_write");

			g_string_free(msg, TRUE);

			// Initialize numbers to roll
			int rand_num_first = 0;
			int rand_num_second = 0;
			char *person1 = NULL;
			char *person2 = NULL;

			// Check if the user accepted the /game request
			if ((strncmp(YES, buff, 4)) == 0)
			{
				// Seed for random generator
				time_t t;
				srand((unsigned) time(&t));

				// Buffer for receiving /roll command from sender
				char buff_first[MESSAGE_SIZE];
				memset(buff_first,0, sizeof(buff_first));

				// Read roll number from sender
				if (SSL_read(sender->ssl, buff_first, sizeof(buff_first) - 1) > 0)
				{
					// Check of the sender has rolled
					if (strncmp(buff_first, "/roll", 5) == 0)
					{
						// Generate a random number from 1 to 6
						rand_num_first = rand() % 5 +1;

						// Copy and convert the number from int to char pointer
						person1 = g_strdup_printf(":%d ", rand_num_first);
					}
				}

				// Buffer for receiving /roll command from receiver
				char buff_second[MESSAGE_SIZE];
				memset(buff_second,0, sizeof(buff_second));

				// Read roll from receiver
				if (SSL_read(receiver->ssl, buff_second, sizeof(buff_second) - 1) > 0)
				{
					// Check of the receiver has rolled
					if (strncmp(buff_second, "/roll", 5) == 0)
					{
						// Generate a random number from 1 to 6
						rand_num_second = rand() % 5 +1;
						// Copy and convert the number from int to char pointer
						person2 = g_strdup_printf(":%d ", rand_num_second);
					}
				}

				/* Make a string to announce the winner.
				 * Compare the rolls and build a string
				 * according who won */

				GString *win_msg = g_string_new(NULL);

				if(rand_num_first > rand_num_second)
				{
					win_msg = g_string_append(win_msg, "The winner is [");
					win_msg = g_string_append(win_msg, sender->name);
					win_msg = g_string_append(win_msg, "]\n\t");
					win_msg = g_string_append(win_msg, sender->name);
					win_msg = g_string_append(win_msg," Rolled ");
					win_msg = g_string_append(win_msg, person1);
					win_msg = g_string_append(win_msg, "\n\t");
					win_msg = g_string_append(win_msg, receiver->name);
					win_msg = g_string_append(win_msg, " Rolled ");
					win_msg = g_string_append(win_msg, person2);
				}
				else if(rand_num_first < rand_num_second)
				{
					win_msg = g_string_append(win_msg, "The winner is [");
					win_msg = g_string_append(win_msg, receiver->name);
					win_msg = g_string_append(win_msg, "]\n\t");
					win_msg = g_string_append(win_msg, sender->name);
					win_msg = g_string_append(win_msg," Rolled ");
					win_msg = g_string_append(win_msg, person1);
					win_msg = g_string_append(win_msg, "\n\t");
					win_msg = g_string_append(win_msg, receiver->name);
					win_msg = g_string_append(win_msg, " Rolled ");
					win_msg = g_string_append(win_msg, person2);
				}
				else // If there is a draw in the game
				{
					win_msg = g_string_append(win_msg, "\n\tDRAW");
				}

				// Write the result of the game to both users
				SSL_write(receiver->ssl, win_msg->str, win_msg->len);
				SSL_write(sender->ssl, win_msg->str, win_msg->len);

				// Free resources
				g_string_free(win_msg, TRUE);
				g_free(person1);
				g_free(person2);
			}
			else if ((strncmp(NO, buff, 3)) == 0) // Tell the sender that his request was denied
			{
				if (SSL_write(sender->ssl, "Game declined", strlen("Game declined")) < 0) perror("SSL_write");
			}
		}
	}

	return FALSE;
}





/* Check if user name is available. If username is found, a entry 
 * that is initially 1, in the data is set as 0. */
gboolean check_availability(gpointer key, gpointer val, gpointer data)
{
	UNUSED(key);

	// If found
	if (g_strcmp0(((struct client_data *)val)->name, (char *)g_list_nth_data((GList *)data, 0)) == 0) *((int *)g_list_nth_data((GList *)data, 1)) = 0;

	return FALSE;
}
