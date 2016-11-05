#include <assert.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <glib.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <readline/readline.h>
#include <readline/history.h>

#define UNUSED(x) (void)(x)

static int server_fd;
static SSL *server_ssl;
static SSL_CTX *ssl_ctx;
static char *prompt;
static int running = 1;

void signal_handler(int signum);
void exit_error(char *msg);
int init_server_connection(int port);
void init_ssl();
void close_connection();
void client_loop();
void readline_callback(char *line);
void request_quit();
void request_game();
void request_join(char *line);
void request_list();
void request_roll();
void request_say();
void request_user();
void request_who();
void getpasswd(const char *prompt, char *passwd, size_t size);

int main(int argc, char **argv)
{
	signal(SIGINT, signal_handler);
	if (argc < 2) exit_error("args");
	const int server_port = strtol(argv[1], NULL, 0);
	server_fd = init_server_connection(server_port);
	init_ssl();
	prompt = strdup("Lobby> ");
	rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
	client_loop();
	close_connection();
	return 0;
}

void signal_handler(int signum)
{
	UNUSED(signum);
	running = 0;
	write(STDOUT_FILENO, "Terminated.\n", 12);
	fsync(STDOUT_FILENO);
}

/* Prints error message and erminates process */
void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

/* Initialization of sockets. All error leads to termination.
 * Return value: file descriptor (int) */
int init_server_connection(int port)
{
	int socket_fd;
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit_error("socket");
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1"); // TODO: Add to arguements/define ?
	server.sin_port = htons(port);
	if (connect(socket_fd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) < 0) exit_error("connect");
	return socket_fd;
}

/* SSL initialization and assigns value to ssl_ctx
 * and server_ssl, both static. All errors lead to
 * termination of program. */
void init_ssl()
{
	SSL_library_init();
	SSL_load_error_strings();
	if ((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) exit_error("ssl ctx");
	server_ssl = SSL_new(ssl_ctx);
	SSL_set_fd(server_ssl, server_fd);
	if (SSL_connect(server_ssl) < 0) exit_error("SSL connect");
}

/* Clean socket and ssl resources */
void close_connection()
{
	if(SSL_write(server_ssl, "/bye", strlen("/bye")) == -1) perror("/bye");
	SSL_shutdown(server_ssl);
	SSL_free(server_ssl);
	SSL_CTX_free(ssl_ctx);
	close(server_fd);
}

void client_loop()
{
	while (running)
	{
		fd_set rfds;
		struct timeval timeout;
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(server_fd, &rfds);
		timeout.tv_sec = 45;
		timeout.tv_usec = 0;
		int r = select(server_fd + 1, &rfds, NULL, NULL, &timeout);
		if (r < 0)
		{
			if (errno == EINTR) continue;
			perror("select()");
			break;
		}
		if (r == 0)
		{
			write(STDOUT_FILENO, "No message?\n", 12);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			write (STDOUT_FILENO, prompt, strlen(prompt));
			continue;
		}
		// If standard input is ready to talk
		if (FD_ISSET(STDIN_FILENO, &rfds)) rl_callback_read_char();
		// If server is ready to talk
		if (FD_ISSET(server_fd, &rfds))
		{
			char buffer[1024];
			int size;
			if ((size = SSL_read(server_ssl, buffer, 1024)) < 0)
			{
				perror("Error receiving message\n");
				break;
			}
			else if (size == 0) continue; // <--------- double check later
			else
			{
				buffer[size] = '\0';
				fprintf(stdout, "%s\n", buffer);
				fflush(stdout);
				write (STDOUT_FILENO, prompt, strlen(prompt));
				fsync(STDOUT_FILENO);
			}
		}
	}
}


/* Handles the input from the client. The client can
 * send up to 7 commands to the server. The available
 * commands are:
 * > /game: to play a mini-game
 * > /join: to join a chatroom
 * > /list: to list all available chatrooms
 * > /roll: roll a dice in the mini-game
 * > /say: 	sends a private message to a user
 * > /user:	set a username
 * > /who:	list all users in chatroom
 *
 * All commands are written to a buffer and sent securely
 * to the server via SSL_write().
 *
 * Paramaters: user input */
void readline_callback(char *line)
{
	char buffer[256];
	if (NULL == line)
	{
		rl_callback_handler_remove();
		return;
	}
	if (strlen(line) > 0) add_history(line);

	if ((strncmp("/bye", line, 4) == 0) || (strncmp("/quit", line, 5) == 0)) request_quit();
	else if (strncmp("/game", line, 5) == 0) request_game();
	else if (strncmp("/join", line, 5) == 0) request_join(line);
	else if (strncmp("/list", line, 5) == 0) request_list();
	else if (strncmp("/roll", line, 5) == 0) request_roll();
	else if (strncmp("/say", line, 4) == 0) request_say();
	else if (strncmp("/user", line, 5) == 0) request_user();
	else if (strncmp("/who", line, 4) == 0) request_who();
	else
	{
		snprintf(buffer, 255, "\nMessage: %s", line);
		write(STDOUT_FILENO, buffer, strlen(buffer));
		fsync(STDOUT_FILENO);
		GString * message = g_string_new(NULL);
		message = g_string_append(message, buffer);
		if(SSL_write(server_ssl, message->str, message->len) == -1) perror("SSL_write");
	}
}

void request_quit()
{
	rl_callback_handler_remove();
	running = 0;
}
void request_game()
{
	// TODO
}
void request_join(char *line)
{
	int i = 5;
	while(line[i] != '\0' && isspace(line[i])) {i++;}
	if(line[i] == '\0')
	{
		write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
		fsync(STDOUT_FILENO);
		rl_redisplay();
	}
	char *chatroom = strdup(&(line[i]));
	if(SSL_write(server_ssl, line, strlen(line)) == -1) perror("/join");
	free(prompt);
	strcat(chatroom, "> ");
	prompt = strdup(chatroom);
	rl_set_prompt(prompt);
}
void request_list()
{
	if(SSL_write(server_ssl, "/list", strlen("/list")) == -1) perror("/list");
}
void request_roll()
{
	// TODO
}
void request_say()
{
	// TODO
}
void request_user()
{
	// TODO
}
/* Write /who to the buffer and send it to the server */
void request_who()
{
	if(SSL_write(server_ssl, "/who", strlen("/who")) == -1) perror("/who");
}

/* For typing password without showing it on stdout */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
	struct termios old_flags, new_flags;
	memset(passwd, 0, size);
	tcgetattr(fileno(stdin), &old_flags);
	memcpy(&new_flags, &old_flags, sizeof(old_flags));
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;
	if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) exit_error("tcsetattr");
	write (STDOUT_FILENO, prompt, strlen(prompt));
	fsync(STDOUT_FILENO);
	fgets(passwd, size, stdin);
	if (passwd[strlen(passwd) -1] == '\n') passwd[strlen(passwd)-1] = '\0';
	if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) exit_error("tcsetattr");
}
