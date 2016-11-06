/***********************************************************************************************************
 _______  _______  _          _______  _       _________ _______  _       _________
(  ____ \(  ____ \( \        (  ____ \( \      \__   __/(  ____ \( (    /|\__   __/
| (    \/| (    \/| (        | (    \/| (         ) (   | (    \/|  \  ( |   ) (   
| (_____ | (_____ | |        | |      | |         | |   | (__    |   \ | |   | |   
(_____  )(_____  )| |        | |      | |         | |   |  __)   | (\ \) |   | |   
      ) |      ) || |        | |      | |         | |   | (      | | \   |   | |   
/\____) |/\____) || (____/\  | (____/\| (____/\___) (___| (____/\| )  \  |   | |   
\_______)\_______)(_______/  (_______/(_______/\_______/(_______/|/    )_)   )_(   

************************************************************************************************************
JON STEINN ELIASSON   - JONSTEINN@GMAIL.COM
DADI GUDVARDARSON     - DADIG4@GMAIL:COM
DANIEL ORN STEFANSSON - DANIEL@STEFNA.IS
************************************************************************************************************/





/* Libraries */
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





/* Defines */

/* Used to fool compiler with unused parameters */
#define UNUSED(x) (void)(x)

/* IP address of server */
#define HOST "127.0.0.1"

/* Timer for select */
#define NO_ACTION_TIME 60

/* Buffer sizes */
#define BUFFER_SIZE 1024
#define LINE_BUFFER 256
#define PROMPT_BUFFER 128

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





/* Global variables */
static int server_fd;
static SSL *server_ssl;   
static SSL_CTX *ssl_ctx;
static char *prompt;
static int running = TRUE;





/* Initializers */
int init_server_connection(int port);
void init_ssl();

/* Request handler */
void request_game();
void request_join(char *line);
void request_list();
void request_roll();
void request_say();
void request_user();
void request_who();

/* Misc */
void signal_handler(int signum);
void exit_error(char *msg);
void close_connection();
void client_loop();
void readline_callback(char *line);
void getpasswd(const char *prompt, char *passwd, size_t size);
int SELECT(fd_set *rfds, int server_fd);





/* Starting point */
int main(int argc, char **argv)
{
	// Terminate if port is not passed with arguments
	if (argc < 2) exit_error("args");

	// Setup handler for interupt signal (ctrl+c).
	signal(SIGINT, signal_handler);

	// Convert port argument to int.
	const int server_port = strtol(argv[1], NULL, 0);

	// Connect to server
	server_fd = init_server_connection(server_port);

	// Initialize OpenSSL connection
	init_ssl();

	// Initialize prompt
	prompt = strdup("Lobby> ");
	rl_callback_handler_install(prompt, (rl_vcpfunc_t*) &readline_callback);

	// Runs until interrupted
	client_loop();

	// Clean up when done
	close_connection();
	
	return 0;
}





void signal_handler(int signum)
{
	UNUSED(signum);

	// Stops client loop
	running = FALSE;

	// Message
	if (write(STDOUT_FILENO, "Connection closed\n", 12) < 0) perror("write");
	fsync(STDOUT_FILENO);
}





/* Prints error message and erminates process */
void exit_error(char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}





/* Initialization of sockets and connection to server. All error 
 * leads to termination. Returns file descriptor (int) */
int init_server_connection(int port)
{
	// Setup socket
	int socket_fd;
	if ((socket_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) exit_error("socket");

	// Init server struct
	struct sockaddr_in server;
	memset(&server, 0, sizeof(server));
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = inet_addr(HOST);
	server.sin_port = htons(port);

	// Connect to server 
	if (connect(socket_fd, (struct sockaddr *)&server, (socklen_t)sizeof(server)) < 0) exit_error("connect");

	return socket_fd;
}





/* SSL initialization and assigns value to ssl_ctx
 * and server_ssl, both static. All errors lead to
 * termination of program. */
void init_ssl()
{
	// Internal SSL init functions
	SSL_library_init();
	SSL_load_error_strings();

	// Exit on error
	if ((ssl_ctx = SSL_CTX_new(TLSv1_client_method())) == NULL) exit_error("ssl ctx");
	
	// Set ssl (connection) for server
	server_ssl = SSL_new(ssl_ctx);
	SSL_set_fd(server_ssl, server_fd);

	// Connect to server, exit on error.
	if (SSL_connect(server_ssl) < 0) exit_error("SSL connect");
}





/* Clean socket and ssl resources */
void close_connection()
{
	rl_callback_handler_remove();

	// Notify server
	if (SSL_write(server_ssl, "/bye", strlen("/bye")) == -1) perror("/bye");

	// Close connection
	SSL_shutdown(server_ssl);
	SSL_free(server_ssl);
	SSL_CTX_free(ssl_ctx);
	close(server_fd);

	// Free resources
	free(prompt);
}





void client_loop()
{
	// Loop indefinitely
	while (running)
	{
		// Wait for requests
		fd_set rfds;
		int r = SELECT(&rfds, server_fd);
		
		// If select returns an error, we close the client
		// unless EINTR error, then we skip the iteration
		if (r < 0)
		{
			if (errno == EINTR) continue;
			perror("select()");
			break;
		}

		// If nothing has happened for 'NO_ACTIION_TIME' then 
		// we prompt the user and let him no that he is inactive
		// The rest of the iteration will be skipped.
		if (r == 0)
		{
			if (write(STDOUT_FILENO, "No message?\n", 12) < 0) perror("write");
			fsync(STDOUT_FILENO);
			rl_redisplay();
			if (write (STDOUT_FILENO, prompt, strlen(prompt)) < 0) perror("write");
			continue;
		}

		// If standard input is ready to talk
		if (FD_ISSET(STDIN_FILENO, &rfds)) rl_callback_read_char();
		
		// If server is ready to talk
		if (FD_ISSET(server_fd, &rfds))
		{
			char buffer[BUFFER_SIZE];
			int size;
			if ((size = SSL_read(server_ssl, buffer, BUFFER_SIZE)) < 0)
			{
				perror("Receiving from server failed\n");
				continue;
			}
			else if (size == 0) continue; // TODO: CHANGE TO return; AND TEST. THAT IS THE CORRECT WAY!!!!
			else
			{
				// Print message from server
				buffer[size] = '\0';
				fprintf(stdout, "%s\n", buffer);
				fflush(stdout);
				if (write (STDOUT_FILENO, prompt, strlen(prompt)) < 0) perror("write");	
				fsync(STDOUT_FILENO);
			}
		}
	}
}





/* A wrapped version select, that handles attinional logic. 
 * Returns the return value of select() */
int SELECT(fd_set *rfds, int server_fd)
{
	// Restart pool
	FD_ZERO(rfds);

	// Add file descriptors to ppol
	FD_SET(server_fd, rfds);
	FD_SET(STDIN_FILENO, rfds);

	// Set inactive time
	struct timeval tv;
	tv.tv_sec = NO_ACTION_TIME;
	tv.tv_usec = 0;

	// Returns value of select for fd+1 where fd = max(STDIN_FILENO, server_fd)
	return select(server_fd > STDIN_FILENO ? server_fd + 1 : STDIN_FILENO + 1, rfds, NULL, NULL, &tv);
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
	// If nothing is entered.
	if (line == NULL)
	{
		rl_callback_handler_remove();
		return;
	}

	// Log line entered.
	if (strlen(line) > 0) add_history(line);

	// Command handlers:
	if ((strncmp(BYE, line, 4) == 0) || (strncmp(QUIT, line, 5) == 0)) running = FALSE;
	else if (strncmp(GAME, line, 5) == 0) request_game();
	else if (strncmp(JOIN, line, 5) == 0) request_join(line);
	else if (strncmp(LIST, line, 5) == 0) request_list();
	else if (strncmp(ROLL, line, 5) == 0) request_roll();
	else if (strncmp(SAY, line, 4) == 0) request_say();
	else if (strncmp(USER, line, 5) == 0) request_user();
	else if (strncmp(WHO, line, 4) == 0) request_who();
	else
	{
		// Place message in buffer
		char buffer[LINE_BUFFER];
		snprintf(buffer, 255, "\nMessage: %s", line);

		// Send messager to server.
		if (SSL_write(server_ssl, buffer, strlen(buffer)) == -1) perror("SSL_write");
	}
}





void request_game()
{
	// TODO
}





/* Write /join to the server */
void request_join(char *line)
{
	// Skip whitespace
	int i = 5; 
	while (line[i] != '\0' && isspace(line[i])) {i++;}

	// Handle missing channel name
	if (line[i] == '\0')
	{
		if (write(STDOUT_FILENO, "Usage: /join chatroom\n", 22) < 0) perror("write");
		fsync(STDOUT_FILENO);
		rl_redisplay();
	}

	// On error, we won't change channel
	if (SSL_write(server_ssl, line, strlen(line)) == -1)
	{
		perror(JOIN);
		return;
	}

	// TODO: Can this overflow the buffer? Is there a leak here?
	// Replace prompt
	free(prompt);
	char *chatroom = strdup(&(line[i]));
	strcat(chatroom, "> ");
	prompt = strdup(chatroom);
	free(chatroom);
	rl_set_prompt(prompt);
}





/* Write /list to the server, asking it to provide
 * us a list of all available channels */
void request_list()
{
	if (SSL_write(server_ssl, LIST, strlen(LIST)) == -1) perror(LIST);
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





/* Write /who to the server, asking it to provide
 * us a list of all available users */
void request_who()
{
	if (SSL_write(server_ssl, WHO, strlen(WHO)) == -1) perror(WHO);
}





/* To read a password without echoing it to the console.
 *
 * We assume that stdin is not redirected to a pipe and we won't
 * access tty directly. It does not make much sense for this program
 * to redirect input and output.
 *
 * This function is not safe to terminate. If the program crashes
 * during getpasswd or gets terminated, then echoing may remain
 * disabled for the shell (that depends on shell, operating system and
 * C library). To restore echoing, type 'reset' into the sell and
 * press enter.
 */
void getpasswd(const char *prompt, char *passwd, size_t size)
{
	struct termios old_flags, new_flags;

	// Clear out the buffer content.
	memset(passwd, 0, size);

	// Disable echo.
	tcgetattr(fileno(stdin), &old_flags);
	memcpy(&new_flags, &old_flags, sizeof(old_flags));
	new_flags.c_lflag &= ~ECHO;
	new_flags.c_lflag |= ECHONL;
	if (tcsetattr(fileno(stdin), TCSANOW, &new_flags) != 0) exit_error("tcsetattr");

	// Write the prompt.
	if (write (STDOUT_FILENO, prompt, strlen(prompt)) < 0) perror("write");
	fsync(STDOUT_FILENO);
	(void)(fgets(passwd, size, stdin) + 1);

	// The result in passwd is '\0' terminated and may contain 
	// a final '\n'. If it exists, we remove it.
	if (passwd[strlen(passwd) -1] == '\n') passwd[strlen(passwd)-1] = '\0';

	// Restore the terminal.
	if (tcsetattr(fileno(stdin), TCSANOW, &old_flags) != 0) exit_error("tcsetattr");
}