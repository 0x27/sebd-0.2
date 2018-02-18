/* mkpasswd.c - gets and encrypts you password with desired salt */

#define _XOPEN_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "mkpasswd.h"

int _getpass()
{
    struct termios old, new;
    char salt_command[20];
    char pass_command[29];
    char password1[256];
    char password2[256];
    char encrypted[14];
    char salt[5];
    
    tcgetattr(0, &old);
    new = old;
    new.c_lflag &= ~(ICANON | ECHO | ISIG);
    new.c_iflag &= ~(IXON | IXOFF);
    
    while(1) {	
	tcsetattr(0, TCSAFLUSH, &new);
	fprintf(stderr, "Enter password: ");
	fflush(stderr);
	fgets(password1, 256, stdin);
	fprintf(stderr, "\nRe-enter password: ");
	fflush(stderr);
	fgets(password2, 256, stdin);
	tcsetattr(0, TCSAFLUSH, &old);
	if (!*password1 || !*password2 || *password1 == '\n' || *password2 == '\n') {
	    fprintf(stderr, "\nAborted.\n");
	    return 1;
	}
	if (!strcmp(password1, password2)) {
	    fprintf(stderr, "\n");
	    break;
	} 
	else {
	    fprintf(stderr, "\nThey don't match; try again.\n");
	}
    }

    printf("Enter salt: ");
    scanf("%s",salt);
    snprintf(encrypted, 14, crypt(password1, salt));
    snprintf(salt_command, 20, "echo %s > config", salt);
    system(salt_command);
    snprintf(pass_command, 29, "echo %s >> config", encrypted);
    system(pass_command);
        
    return 0;																		
}
    
int main()
{
    _getpass();

    return 0;
}

