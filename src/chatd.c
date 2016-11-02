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

#define UNUSED(x) (void)(x)

static GTree* chat_room_tree;
static GTree* client_tree;

SSL_CTX *ssl_ctx;

void sigint_handler(int sig)
{
	UNUSED(sig);
	g_tree_destroy(chat_room_tree);
	g_tree_destroy(client_tree);
	SSL_CTX_free(ssl_ctx);
	RAND_cleanup();
	ENGINE_cleanup();
	CONF_modules_unload(1);
	CONF_modules_free();
	EVP_cleanup();
	ERR_free_strings();
	ERR_remove_state(0);
	CRYPTO_cleanup_all_ex_data();
	exit(0);
}

void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

/* This can be used to build instances of GTree that index on the address of a connection. */
int sockaddr_in_cmp(const void *addr1, const void *addr2)
{
	const struct sockaddr_in *_addr1 = addr1;
	const struct sockaddr_in *_addr2 = addr2;

	/* If either of the pointers is NULL or the addresses belong to different families, we abort. */
	g_assert((_addr1 == NULL) || (_addr2 == NULL) || (_addr1->sin_family != _addr2->sin_family));
	if (_addr1->sin_addr.s_addr < _addr2->sin_addr.s_addr) return -1;
	else if (_addr1->sin_addr.s_addr > _addr2->sin_addr.s_addr) return 1;
	else if (_addr1->sin_port < _addr2->sin_port) return -1;
	else if (_addr1->sin_port > _addr2->sin_port) return 1;
	return 0;
}


/* This can be used to build instances of GTree that index on
   the file descriptor of a connection. */
gint fd_cmp(gconstpointer fd1,  gconstpointer fd2, gpointer G_GNUC_UNUSED data)
{
	return GPOINTER_TO_INT(fd1) - GPOINTER_TO_INT(fd2);
}


int main(int argc, char **argv)
{
	// Install the sigint handler for key interupt
	signal(SIGINT, sigint_handler);
	SSL_library_init();
	SSL_load_error_strings();
	ssl_ctx = SSL_CTX_new(TLSv1_method());
	
	if (!ssl_ctx) exit_error("ssl_ctx");
	if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE, SSL_FILETYPE_PEM) <= 0) exit_error("certificate");
	if (SSL_CTX_use_PrivateKey_file(ssl_ctx, PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0) exit_error("privatekey");
	if ( !SSL_CTX_check_private_key(ssl_ctx) ) exit_error("match");

	/* Receive and handle messages. */

	exit(EXIT_SUCCESS);
}
