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
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <readline/readline.h>
#include <readline/history.h>

static int server_fd;
static SSL *server_ssl;
static SSL_CTX *ssl_ctx;
static char *prompt;
static int running = 1;

void exit_error(char *msg);
int init_server_connection(int port);
void init_ssl();
void getpasswd(const char *prompt, char *passwd, size_t size);
void close_connection();
void readline_callback(char *line);


int main(int argc, char **argv)
{
	if (argc < 2) exit_error("args");
	const int server_port = strtol(argv[1], NULL, 0);
	server_fd = init_server_connection(server_port);
	init_ssl();	
	prompt = strdup("> ");
	rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);
	char buffer[512];
	while (running)
	{
		fd_set rfds;
		struct timeval timeout;
		FD_ZERO(&rfds);
		FD_SET(STDIN_FILENO, &rfds);
		FD_SET(server_fd, &rfds);
		timeout.tv_sec = 5;
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
			continue;
		}
		if (FD_ISSET(STDIN_FILENO, &rfds)) rl_callback_read_char();
		if (FD_ISSET(server_fd, &rfds))
		{
			int size;
			if ((size = SSL_read(server_ssl, buffer, 512)) < 0)
			{
				perror("Error receiving message\n");
				continue;
			}
			else if (size == 0) continue; // <-------- check later
			else 
			{
				buffer[size] = '\0';
				fprintf(stdout, "%s\n", buffer);
				fflush(stdout);
			}
		}
	}
	void close_connection();
}

void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int init_server_connection(int port)
{
	int socket_fd;
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit_error("socket");
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr("127.0.0.1");
	server.sin_port = htons(port);
	if (connect(socket_fd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) < 0) exit_error("connect");
	return socket_fd;
}

void init_ssl()
{
	SSL_library_init();
	SSL_load_error_strings();
	if ((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) exit_error("ssl ctx");
	server_ssl = SSL_new(ssl_ctx);
	SSL_set_fd(server_ssl, server_fd);
	if (SSL_connect(server_ssl) < 0) exit_error("SSL connect");
}

void readline_callback(char *line) 
{
	char buffer[256];
	if (NULL == line) 
	{
		rl_callback_handler_remove();
		return;
	}

	if (strlen(line) > 0) add_history(line);
	if ((strncmp("/bye", line, 4) == 0) || (strncmp("/quit", line, 5) == 0)) 
	{
		rl_callback_handler_remove();
		running = 0;
		return;
	}
	if (strncmp("/game", line, 5) == 0) 
	{
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) i++;
		if (line[i] == '\0') 
		{
			write(STDOUT_FILENO, "Usage: /game username\n", 29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		// TODO: Start game
		return;
	}
	if (strncmp("/join", line, 5) == 0) 
	{
		int i = 5;
		while (line[i] != '\0' && isspace(line[i])) i++;
		if (line[i] == '\0') 
		{
			write(STDOUT_FILENO, "Usage: /join chatroom\n", 22);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		// char *chatroom = strdup(&(line[i]));
		// TODO:
		// Process and send this information to the server.
		// Maybe update the prompt.
		free(prompt);
		prompt = NULL; // What should the new prompt look like?
		rl_set_prompt(prompt);
		return;
	}
	if (strncmp("/list", line, 5) == 0) 
	{
		// TODO: Query all available chat rooms
		return;
	}
	if (strncmp("/roll", line, 5) == 0) 
	{
		// TODO: roll dice and declare winner.
		return;
	}
	if (strncmp("/say", line, 4) == 0)
	{
		int i = 4;
		while (line[i] != '\0' && isspace(line[i])) i++;
		if (line[i] == '\0') 
		{
			write(STDOUT_FILENO, "Usage: /say username message\n", 29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		int j = i + 1;
		while (line[j] != '\0' && isgraph(line[j])) j++;
		if (line[j] == '\0') 
		{
			write(STDOUT_FILENO, "Usage: /say username message\n", 29);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		//char *receiver = strndup(&(line[i]), j - i - 1);
		//char *message = strndup(&(line[j]), j - i - 1);

		// TODO: Send private message to receiver.
		return;
	}
	if (strncmp("/user", line, 5) == 0) 
	{
		int i = 5;
		while (line[i] != '\0' && isspace(line[i])) i++;
		if (line[i] == '\0') 
		{
			write(STDOUT_FILENO, "Usage: /user username\n", 22);
			fsync(STDOUT_FILENO);
			rl_redisplay();
			return;
		}
		//char *new_user = strdup(&(line[i]));
		char passwd[48];
		getpasswd("Password: ", passwd, 48);

		// TODO Process and send this information to the server.

		// Maybe update the prompt
		free(prompt);
		prompt = NULL; // What should the new prompt look like?
		rl_set_prompt(prompt);
		return;
	}
	if (strncmp("/who", line, 4) == 0) 
	{
		// TODO Query all available users
		return;
	}
	snprintf(buffer, 255, "Message: %s\n", line);
	write(STDOUT_FILENO, buffer, strlen(buffer));
	fsync(STDOUT_FILENO);
}

void close_connection()
{
	SSL_shutdown(server_ssl);
	SSL_free(server_ssl);
	SSL_CTX_free(ssl_ctx);
	close(server_fd);
}

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
