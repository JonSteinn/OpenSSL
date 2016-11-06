/***********************************************************************************************************
 _______  _______  _          _______  _______  _______           _______  _______ 
(  ____ \(  ____ \( \        (  ____ \(  ____ \(  ____ )|\     /|(  ____ \(  ____ )
| (    \/| (    \/| (        | (    \/| (    \/| (    )|| )   ( || (    \/| (    )|
| (_____ | (_____ | |        | (_____ | (__    | (____)|| |   | || (__    | (____)|
(_____  )(_____  )| |        (_____  )|  __)   |     __)( (   ) )|  __)   |     __)
      ) |      ) || |              ) || (      | (\ (    \ \_/ / | (      | (\ (   
/\____) |/\____) || (____/\  /\____) || (____/\| ) \ \__  \   /  | (____/\| ) \ \__
\_______)\_______)(_______/  \_______)(_______/|/   \__/   \_/   (_______/|/   \__/

************************************************************************************************************
JON STEINN ELIASSON   - JONSTEINN@GMAIL.COM
DADI GUDVARDARSON     - DADIG4@GMAIL:COM
DANIEL ORN STEFANSSON - DANIEL@STEFNA.IS
************************************************************************************************************/

/* Libraries */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <glib.h>
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

/* Flags for logger */
#define LOG_DISCONNECTED 0
#define LOG_CONNECTED 1

/* Metrics for clients */
#define MAX_QUEUED 5

/* Name of initial channel */
#define INIT_CHANNEL "LOBBY"





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
};

/* Data structure for chat rooms. It includes the following fields:
 *   (identifier, type, description)
 *   1: name, char *, name of channel
 *   2: members, GTree *, collection of clients
 * Each chat room has a tree of the user it contains. Initially, one 
 * one channel exists. */
struct room_data
{
	char *name;
	GTree *members;
};

/* Global variables */
static GTree *client_collection;
static GTree *room_collection;
static SSL_CTX *ctx;

void exit_error(char *msg);

/* Initializers */
void init_SSL();
int init_server(int port);
void init_chat_rooms();

/* COMPARISON */
int sockaddr_in_cmp(const void *addr1, const void *addr2);
int chat_cmp(const void *name1, const void *name2);

/* ADDING */
void add_room(char *name);
void add_client(int server_fd, SSL_CTX *ctx);

/* MISC */
void free_client(struct client_data *client);
void server_loop(int server_fd);
int SELECT(fd_set *rfds, int server_fd);
void client_logger(struct client_data *client, int status);

/* ITERATION */
gboolean get_max_fd(gpointer key, gpointer val, gpointer data);
gboolean fd_set_all(gpointer key, gpointer val, gpointer data);
gboolean responde_to_client(gpointer key, gpointer value, gpointer data);
gboolean send_client_list(gpointer key, gpointer val, gpointer data);
gboolean send_chat_rooms(gpointer key, gpointer val, gpointer data);
gboolean send_to_room(gpointer key, gpointer val, gpointer data);
int find_chat_room();

/* HANDLERS */
void handle_who(SSL *ssl);
void handle_list(SSL *ssl);
void handle_join(struct client_data *client, char *buffer);

int main(int argc, char **argv)
{
	// TODO: COMMENT STEPS

	if (argc < 2) exit_error("argument");
	const int server_port = strtol(argv[1], NULL, 0);
	fprintf(stdout, "Starting server on port %d\n", server_port);
	fflush(stdout);
	init_SSL();
	int server_fd = init_server(server_port);
	client_collection = g_tree_new(sockaddr_in_cmp);
	init_chat_rooms();
	server_loop(server_fd);
	exit(EXIT_SUCCESS);
}

/* Prints msg to standard error and exits with error code EXIT_FAILURE */
void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

/* Sets up SSL and check if key matches.
 * All error results in termination.
 *
 * Parameters: SSL certificate */
void init_SSL()
{
	//TODO: Comment steps

	SSL_library_init();
	SSL_load_error_strings();
	if ((ctx = SSL_CTX_new(TLSv1_method())) == NULL) exit_error("SSL CTX");
	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0) exit_error("certificate");
	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) exit_error("privatekey");
	if (SSL_CTX_check_private_key(ctx) != 1) exit_error("match");
	fprintf(stdout, "Access granted\n");
	fflush(stdout);
}


/* Sets up socket and error checks while doing so. We allocate the
 * sockaddr_in struct's resources after this functions since we do
 * not need it elsewhere.
 *
 * Paramaters: port number of server
 * Return value: file descriptor of server */
int init_server(int port)
{
	// TODO: Comment steps

	int socket_fd;
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit_error("socket");
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = htonl(INADDR_ANY);
	server.sin_port = htons(port);
	if (bind(socket_fd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) < 0) exit_error("bind");
	if (listen(socket_fd, MAX_QUEUED) < 0) exit_error("listen");
	fprintf(stdout, "Server setup complete\n");
	fflush(stdout);
	return socket_fd;
}

//TODO:comment
void init_chat_rooms()
{
	room_collection = g_tree_new(chat_cmp);
	add_room(INIT_CHANNEL);
	add_room("Gamers");
	add_room("Study");
}

void add_room(char *name)
{
	struct room_data *newChat = g_new0(struct room_data, 1);
	newChat->name = g_strdup(name);
	newChat->members = g_tree_new(sockaddr_in_cmp);
	g_tree_insert (room_collection, newChat->name, newChat->members);
}

/* Comparator for sockaddr to keep tree balanced */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	// TODO: comment steps

	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;
	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) return -1;
	if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) return 1;
	if (_addr1->sin_port < _addr2->sin_port) return -1;
	if (_addr1->sin_port > _addr2->sin_port) return 1;
	return 0;
}

// Compare function for chat tree (since for some reason
// it did not accept g_strcmp0 as an argument)
int chat_cmp(const void *name1, const void *name2)
{
	return g_strcmp0(name1, name2);
}

// TODO: Comment
void free_client(struct client_data *client)
{
	// TODO: comment steps

	client_logger(client, LOG_DISCONNECTED);
	close(client->fd);
	SSL_shutdown(client->ssl);
	SSL_free(client->ssl);
	g_tree_remove(client_collection, &client->addr);
	g_free(client);
}

/* Main loop of server */
void server_loop(int server_fd)
{
	// TODO: comment steps

	while (1)
	{
		fd_set rfds;
		int r = SELECT(&rfds, server_fd);
		if (r < 0)
		{
			if (errno == EINTR) continue;
			perror("select()");
			break;
		}
		if (r == 0)
		{
			fprintf(stdout, "nothing for 30s\n");
			fflush(stdout);
		}

		if (FD_ISSET(server_fd, &rfds)) add_client(server_fd, ctx);
		g_tree_foreach(client_collection, responde_to_client, &rfds);
	}
}

/* A wrapped version select, that handles attinional logic. */
int SELECT(fd_set *rfds, int server_fd)
{
	// TODO: comment steps

	FD_ZERO(rfds);
	FD_SET(server_fd, rfds);
	int max_fd = server_fd;
	g_tree_foreach(client_collection, get_max_fd, &max_fd);
	g_tree_foreach(client_collection, fd_set_all, rfds);
	struct timeval tv;
	tv.tv_sec = 30;
	tv.tv_usec = 0;
	return select(max_fd + 1, rfds, NULL, NULL, &tv);

}

/* Iterates through the tree of clients, finding the largest
 * file descriptor and passing it back through data. */
gboolean get_max_fd(gpointer key, gpointer val, gpointer data)
{
	UNUSED(key);
	int this_fd = ((struct client_data *)val)->fd;
	if (this_fd > *((int *)data)) *((int *)data) = this_fd;
	return FALSE;
}

/* Adds every current client's file descriptor to the
 * pool of fd's that are checked for requests */
gboolean fd_set_all(gpointer key, gpointer val, gpointer data)
{
	UNUSED(key);
	FD_SET(((struct client_data *)val)->fd, (fd_set *)data);
	return FALSE;
}

/* Add client to server. Will be added to the tree and greeted
 * with a message.  */
void add_client(int server_fd, SSL_CTX *ctx)
{
	// TODO: comment steps
	struct client_data *client = g_new0(struct client_data, 1);
	socklen_t scklen = (socklen_t)sizeof(client->addr);

	if ((client->fd = accept(server_fd, (struct sockaddr *)&client->addr, &scklen)) < 0)
	{
		perror("accept");
		return;
	}
	if ((client->ssl = SSL_new(ctx)) == NULL)
	{
		perror("SSL");
		return;
	}
	if (SSL_set_fd(client->ssl, client->fd) == 0)
	{
		perror("SSL fd");
		return;
	}
	if (SSL_accept(client->ssl) < 0)
	{
		perror("SSL accept");
		return;
	}

	fprintf(stdout, "New client! FD = %d\n", client->fd);
	fflush(stdout);

	client->room = g_strdup(INIT_CHANNEL);
	g_tree_insert(client_collection, &client->addr, client);
	GTree *tree = g_tree_search(room_collection, find_chat_room, "LOBBY");
	g_tree_insert(tree, &client->addr, client);
	//client->room = "LOBBY";
	if (SSL_write(client->ssl, "WELCOME", strlen("WELCOME")) < 0) perror("SSL write");
	client_logger(client, LOG_CONNECTED);

}

/* Time stamp on client action, in local file system */
void client_logger(struct client_data *client, int status)
{
	// TODO: Comment steps

	char *ip = inet_ntoa(client->addr.sin_addr);
	uint16_t port = client->addr.sin_port;

	// Set ISO time
	time_t rawtime;
	struct tm *timeinfo;
	time(&rawtime);
	timeinfo = localtime(&rawtime);
	char timestamp[25];
	memset(timestamp, 0, sizeof(timestamp));
	strftime(timestamp, 80, "%a, %d %b %Y %X GMT", timeinfo);

	// Open filestream and append to chat.log
	FILE *tof;
	if((tof = fopen("chat.log", "a")) == NULL)
	{
	        fprintf(stdout, "%s\n","Log error");
	        return;
	}
	fwrite("<", 1, 1, tof);
	fwrite(timestamp, 1, strlen(timestamp), tof);
	fwrite("> : <", 1, 5, tof);
	fwrite(ip, 1, strlen(ip), tof);
	fwrite("> : <", 1, 5, tof);
	fprintf(tof, "%d",port );
	fwrite(">", 1, 2, tof);
	if (status == LOG_CONNECTED) fwrite(" : <CONNECTED>\n", 1, 15, tof);
	else if (status == LOG_DISCONNECTED) fwrite(" : <DISCONNECTED>\n", 1, 18, tof);
	fflush(tof);
	fclose(tof);
}

// TODO: COMMENT
gboolean responde_to_client(gpointer key, gpointer val, gpointer data)
{
	// TODO: COMMENT steps

	UNUSED(key);
	struct client_data *client = val;
	char buff[512];
	memset(buff,0, sizeof(buff));
	if (FD_ISSET(client->fd, (fd_set *)data))
	{
		if (SSL_read(client->ssl, buff, sizeof(buff) - 1) > 0)
		{
			if (strncmp(buff, "/who", 4) == 0) handle_who(client->ssl);
			else if (strncmp(buff, "/bye", 4) == 0) free_client(client);
			else if (strncmp(buff, "/list", 5) == 0) handle_list(client->ssl);
			else if (strncmp(buff, "/join", 5) == 0) handle_join(client, buff);
			// TODO: ADD more handling else-if-s and corresponding methods
			else g_tree_foreach(g_tree_search(room_collection, find_chat_room, client->room), send_to_room, buff);
		}
		else free_client(client);
	}
	return FALSE;
}

// TODO: COMMENT
void handle_who(SSL *ssl)
{
	if(SSL_write(ssl, "\nList of clients:\n", strlen("\nList of clients:\n")) < 0) perror("SSL write");
	GString * buffer = g_string_new(NULL);
	g_tree_foreach(client_collection, send_client_list, buffer);
	if(SSL_write(ssl, buffer->str, buffer->len) < 0) perror("SSL write");
	g_string_free(buffer, TRUE);
}

// TODO: COMMENT:
void handle_list(SSL *ssl)
{
	GString *buffer = g_string_new(NULL);
	GString *message = g_string_new("\n\nList of chatrooms:");
	fprintf(stdout, "%d\n", g_tree_nnodes(room_collection));
	g_tree_foreach(room_collection, send_chat_rooms, buffer);
	message = g_string_append (message, buffer->str);
	message = g_string_append (message, "\n");
	if(SSL_write(ssl, message->str, message->len) < 0) perror("SSL write");
	g_string_free(buffer, TRUE);
	g_string_free(message, TRUE);
}

// TODO Comment
gboolean send_chat_rooms(gpointer key, gpointer val, gpointer data)
{
	UNUSED(val);
	GString *buffer = data;
	buffer = g_string_append(buffer, "\n");
	buffer = g_string_append(buffer, (char *)key);

	return FALSE;
}

// TODO: COMMENT
void handle_join(struct client_data *client, char *buffer)
{
	char *room_name = g_strchomp(&buffer[6]);
	GTree *tree;

	if((tree = g_tree_search(room_collection, find_chat_room, room_name)) == NULL)
	{
		add_room(room_name);
	}
		tree = g_tree_search(room_collection, find_chat_room, client->room);

		if(tree != NULL)
		{
			fprintf(stdout, "%s\n","Tree ready");
			fflush(stdout);
		}

		if(g_tree_remove(tree, &client->addr) == FALSE)
		{
			fprintf(stdout, "%s\n", "ERROR REMOVING FROM ROOM");
		}

		tree = g_tree_search(room_collection, find_chat_room, room_name);
		g_tree_insert (tree, &client->addr, client);
		client->room = strdup(room_name);
}

//TODO: COMMENT
int find_chat_room(const void *name1, const void *name2)
{
		const char *first = name1;
		const char *second = name2;
		int x = g_strcmp0(first, second);
		if (x > 0) return -1;
		if (x < 0) return 1;
		return 0;
}

// TODO: COMMENT
gboolean send_client_list(gpointer key, gpointer val, gpointer data)
{
	// TODO: comment steps
	UNUSED(key);
	struct client_data *client = val;
	GString * buffer = data;
	char *ip = inet_ntoa(client->addr.sin_addr);
	gchar * port = g_strdup_printf(":%i ", client->addr.sin_port);

	buffer = g_string_append(buffer, "\nName: ");
	if(client->name == NULL){}
	else
	{
		buffer = g_string_append(buffer, client->name);
	}

	buffer = g_string_append(buffer, "\nChatroom: ");

	if(client->room == NULL){
		buffer = g_string_append(buffer, "No Room");
	}
	else
	{
		buffer = g_string_append(buffer, client->room);
	}
	buffer = g_string_append(buffer, "\nIP: ");
	buffer = g_string_append(buffer, ip);
	buffer = g_string_append(buffer, "\nPort: ");
	buffer = g_string_append(buffer, port);
	buffer = g_string_append(buffer, "\n");

	g_free(port);
	return FALSE;
}

gboolean send_to_room(gpointer key, gpointer val, gpointer data)
{
	UNUSED(key);
	struct client_data * client = val;
	if(SSL_write(client->ssl, data, strlen(data)) < 0) perror("SSL write");
	return FALSE;
}
