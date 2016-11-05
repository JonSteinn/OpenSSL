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

#define UNUSED(x) (void)(x)

#define CERTIFICATE "../encryption/fd.crt"
#define PRIVATE_KEY "../encryption/fd.key"

#define LOG_DISCONNECTED 0
#define LOG_CONNECTED 1

#define MAX_QUEUED 5

#define INIT_CHANNEL "LOBBY"

/*
 * Data structure for clients.
 * 1 fd = File descriptor
 * 2 ssl = ssl descriptor
 * 3 addr = socket info
 * 4 ... // TODO UPDATE
 * 5 ...
 * 6 ...
 * 7 ...
 * 8 ...
 * */
struct client_data
{
	int fd;
	SSL *ssl;
	struct sockaddr_in addr;
	char *name;
	char *room;
};

// TODO: Comment
struct room_data
{
	char *name;
	GTree *members;
};

static GTree *client_collection;
static GTree *room_collection;
static SSL_CTX *ctx;

void exit_error(char *msg);
void init_SSL();
int init_server(int port);
void init_chat_rooms();
int sockaddr_in_cmp(const void *addr1, const void *addr2);
int chat_cmp(const void *name1, const void *name2);
void add_room(char *nane);
void free_client(struct client_data *client);
void server_loop(int server_fd);
int SELECT(fd_set *rfds, int server_fd);
gboolean get_max_fd(gpointer key, gpointer val, gpointer data);
gboolean fd_set_all(gpointer key, gpointer val, gpointer data);
void add_client(int server_fd, SSL_CTX *ctx);
void client_logger(struct client_data *client, int status);
gboolean responde_to_client(gpointer key, gpointer value, gpointer data);
void handle_who(SSL *ssl);
void handle_list(SSL *ssl);
gboolean send_client_list(gpointer key, gpointer val, gpointer data);

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
}

void add_room(char *name)
{
	struct room_data *newChat = g_new0(struct room_data, 1);
	newChat->name = g_strdup(name);
	newChat->members = g_tree_new(sockaddr_in_cmp);
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
	if (FD_ISSET(client->fd, (fd_set *)data))
	{
		if (SSL_read(client->ssl, buff, sizeof(buff) - 1) > 0)
		{
			if (strncmp(buff, "/who", 4) == 0) handle_who(client->ssl);
			else if (strncmp(buff, "/bye", 4) == 0) free_client(client);
			else if (strncmp(buff, "/list", 5) == 0) handle_list(client->ssl);
			// TODO: ADD more handling else-if-s and corresponding methods
		}
		else
		{
			free_client(client);
		}
	}
	return FALSE;
}

// TODO: Comment
void handle_who(SSL *ssl)
{
	SSL_write(ssl, "List of clients:\n", strlen("List of client:\n"));
	GString * buffer = g_string_new(NULL);
	g_tree_foreach(client_collection, send_client_list, buffer);
	if(SSL_write(ssl, buffer->str, buffer->len) < 0) perror("SSL write");
	g_string_free(buffer, TRUE);
}

// TODO: COMMENT:
void handle_list(SSL *ssl)
{
	UNUSED(ssl);
	// TODO iterate through chat room tree and send info to user
	
}

// TODO COMMENT, UPDATE
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
