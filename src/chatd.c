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

#define CERTIFICATE "../encryption/fd.crt"
#define PRIVATE_KEY "../encryption/fd.key"

#define MAX_QUEUED 2

/*
 * Data structure for clients.
 * */
struct client_data
{
	int fd;
	SSL *ssl;
	struct sockaddr_in addr;
};

void exit_error(char *msg);
int init_server(int port);
void client_logger(uint16_t port, char *ip, int status);
int sockaddr_in_cmp(const void *addr1, const void *addr2);

int main(int argc, char **argv)
{
	if (argc < 2) exit_error("argument");
	const int server_port = strtol(argv[1], NULL, 0);

	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ctx;
	if ((ctx = SSL_CTX_new(TLSv1_method())) == NULL) exit_error("SSL CTX");
	if (SSL_CTX_use_certificate_file(ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0) exit_error("certificate");
	if (SSL_CTX_use_PrivateKey_file(ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) exit_error("privatekey");
	if (SSL_CTX_check_private_key(ctx) != 1) exit_error("match");

	int server_fd = init_server(server_port);

	// TODO: Data structures for rooms and clients
	GTree* client_collection = g_tree_new(sockaddr_in_cmp);
	

	int client_fd;
	struct sockaddr_in client;
	while (1)
	{
		memset(&client, 0, sizeof(client));
		socklen_t scklen = (socklen_t)sizeof(client);
		if ((client_fd = accept(server_fd, (struct sockaddr *)&client, &scklen)) < 0) exit_error("accept");

		char *client_ip = inet_ntoa(client.sin_addr);
		uint16_t client_port = client.sin_port;
		client_logger(client_port, client_ip, 1);

		SSL *ssl;
		if ((ssl = SSL_new(ctx)) == NULL) exit_error("SSL"); //TODO, dont exit
		if (SSL_set_fd(ssl, client_fd) == 0) exit_error("SSL fd"); // TODO, don't exit
		if (SSL_accept(ssl) < 0) exit_error("SSL accept"); //TODO, don't exit
		if (SSL_write(ssl, "WELCOME", strlen("WELCOME")) < 0) exit_error("SSL write"); // TODO, don't exit

		
		close(client_fd);
	}

	exit(EXIT_SUCCESS);
}

/* Prints msg to standard error and exits with error code EXIT_FAILURE */
void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
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

	return socket_fd;
}

int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;
	g_assert(_addr1 == NULL || _addr2 == NULL || _addr1->sin_family != _addr2->sin_family);
	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) return -1;
	if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) return 1;
	if (_addr1->sin_port < _addr2->sin_port) return -1;
	if (_addr1->sin_port > _addr2->sin_port) return 1;
	return 0;
}

void client_logger(uint16_t port, char *ip, int status)
{
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
		if(status == 1)
		{
			fwrite(" : <CONNECTED>\n", 1, 15, tof);
		}
		else
		{
			fwrite(" : <DISCONNECTED>\n", 1, 18, tof);
		}

		fflush(tof);
		fclose(tof);
}
