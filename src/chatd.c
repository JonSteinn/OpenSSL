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

#define CERTIFICATE "encryption/fd.crt"
#define PRIVATE_KEY "encryption/fd.key"

#define LOG_DISCONNECTED 0
#define LOG_CONNECTED 1

#define MAX_QUEUED 5

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
static SSL_CTX *ctx;

void exit_error(char *msg);
void init_SSL();
int init_server(int port);
int sockaddr_in_cmp(const void *addr1, const void *addr2);
void free_client(struct client_data *client);
void server_loop(int server_fd);
int SELECT(fd_set *rfds, int server_fd);
gboolean get_max_fd(gpointer key, gpointer val, gpointer data);
gboolean fd_set_all(gpointer key, gpointer val, gpointer data);
void add_client(int server_fd, SSL_CTX *ctx);
void client_logger(struct client_data *client, int status);
gboolean responde_to_client(gpointer key, gpointer value, gpointer data);
void handle_who(SSL *ssl);

int main(int argc, char **argv)
{
	if (argc < 2) exit_error("argument");
	const int server_port = strtol(argv[1], NULL, 0);
	fprintf(stdout, "Starting server on port %d\n", server_port);
	fflush(stdout);	
	init_SSL();
	int server_fd = init_server(server_port);
	client_collection = g_tree_new(sockaddr_in_cmp);
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

/* Comparator for sockaddr to keep tree balanced */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;
	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) return -1;
	if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) return 1;
	if (_addr1->sin_port < _addr2->sin_port) return -1;
	if (_addr1->sin_port > _addr2->sin_port) return 1;
	return 0;
}

// TODO: Comment
void free_client(struct client_data *client)
{
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
	struct client_data client;
	size_t client_size = sizeof(client);
	memset(&client, 0, client_size);
	socklen_t scklen = (socklen_t)sizeof(client.addr);

	if ((client.fd = accept(server_fd, (struct sockaddr *)&client.addr, &scklen)) < 0)
	{
		perror("accept");
		return;
	}
	if ((client.ssl = SSL_new(ctx)) == NULL)
	{
		perror("SSL");
		return;
	}
	if (SSL_set_fd(client.ssl, client.fd) == 0)
	{
		perror("SSL fd");
		return;
	}
	if (SSL_accept(client.ssl) < 0)
	{
		perror("SSL accept");
		return;
	}
	
	fprintf(stdout, "New client! FD = %d\n", client.fd);
	fflush(stdout);

	struct client_data *cpy = (struct client_data *)malloc(client_size);
	memcpy(cpy, &client, client_size);
	g_tree_insert(client_collection, &cpy->addr, cpy);
	if (SSL_write(client.ssl, "WELCOME", strlen("WELCOME")) < 0) perror("SSL write");
	client_logger(&client, LOG_CONNECTED);
}

/* Time stamp on client action, in local file system */
void client_logger(struct client_data *client, int status)
{
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
	UNUSED(key);
	struct client_data *client = val;
	char buff[512];
	if (FD_ISSET(client->fd, (fd_set *)data))
	{
		if (SSL_read(client->ssl, buff, sizeof(buff) - 1) > 0)
		{
			if (strncmp(buff, "/who", 4) == 0) handle_who(client->ssl);
			else if (strncmp(buff, "/bye", 4) == 0) free_client(client);
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
	// TODO: Replace by actual list of clients
	// Needs to be done with a foreach loop through tree
	SSL_write(ssl, "List of clients:", strlen("List of client:"));
}

// TODO COMMENT:
gboolean send_client_list(gpointer key, gpointer val, gpointer data)
{
	//TODO: remove those you use from unused
	UNUSED(key);
	UNUSED(val);
	UNUSED(data);
	//char buffer[100];
	//char *ip = inet_ntoa(client->addr.sin_addr);
	//uint16_t port = client->addr.sin_port;
	//TODO -----> /* SSL_write(ssl, */ 
	// FORMAT IDEA:
	//	
	//	Name: john 
	//	Chatroom: tsam
	//	IP: 1.1.1.1
	//  port: 2000
	//
	// (leave name and chatroom empty for now)
	return FALSE;
}
