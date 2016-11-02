/* A TCP echo server with timeouts.
*
* Note that you will not need to use select and the timeout for a
* tftp server. However, select is also useful if you want to receive
* from multiple sockets at the same time. Read the documentation for
* select on how to do this (Hint: Iterate with FD_ISSET()).
*/

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

#define CERTIFICATE "encryption/fd.crt"
#define PRIVATE_KEY "encryption/fd.key"

#define MAX_QUEUED 2

void exit_error(char *msg)
int init_server(int port)

int main(int argc, char **argv)
{
	if (argc < 2) exit_error("argument");
	const int server_port = strtol(argv[1], NULL, 0);

	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX *ssl;
	if ((ssl = SSL_CTX_new(TLSv1_method())) == NULL) exit_error("SSL CTX");
	if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0) exit_error("certificate");
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) exit_error("privatekey");
	if (SSL_CTX_check_private_key(ssl_ctx) != 1) exit_error("match");

	int server_fd = init_server(server_port);

	// TODO: Data structures for rooms and clients

	int client_fd;
	struct sockaddr_in client;
	while (1)
	{
		memset(&client, 0, sizeof(client));
		socklen_t scklen = (socklen_t)sizeof(client);
		if ((client_fd = accept(server_fd, (struct sockaddr *)&client, &scklen)) < 0) exit_error("accept");
		char buf[512];
		memset(&buf, 0, 512);
		recv(client_fd, buf, 512, 0);
		fprintf(stdout, "%s\n", buf);
		fflush(stdout);
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