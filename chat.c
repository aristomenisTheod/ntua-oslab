/*
 * socket-client.c
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include "socket-common.h"

/* Insist until all of the data has been written */
ssize_t insist_write(int fd, const void *buf, size_t cnt)
{
	ssize_t ret;
	size_t orig_cnt = cnt;
	
	while (cnt > 0) {
	        ret = write(fd, buf, cnt);
	        if (ret < 0)
	                return ret;
	        buf += ret;
	        cnt -= ret;
	}

	return orig_cnt;
}

int main(int argc, char *argv[])
{
	int sd, port, fd=0,rfd,sret,ppfd[2];
	fd_set readfd;
	ssize_t n;
	pid_t pd;
	char buf[100];

	if (argc != 4 && argc!=2) {
		fprintf(stderr, "Usage: %s client hostname port\n %s server", argv[0]);
		exit(1);
	}
	ppfd=pipe();
	pd=fork();
	if(pd<0){
		perror("error:fork");
		exit(1);
	}
	else if(pd==0){
		close(ppf[0]);
		if(strcmp(argv[1],"client")=0){
			execve("chat-client.exe",{argv[2],argv[3],ppfd[1]},NULL);
			return 1;
		}
		else{
			execve("chat-server.exe", {ppfd[0]}, NULL);
			return 1;
		}
	}
 
	// hostname = argv[1];
	// port = atoi(argv[2]); /* Needs better error checking */

	// /* Create TCP/IP socket, used as main chat channel */
	// if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
	// 	perror("socket");
	// 	exit(1);
	// }
	// fprintf(stderr, "Created TCP socket\n");
	
	// /* Look up remote hostname on DNS */
	// if ( !(hp = gethostbyname(hostname))) {
	// 	printf("DNS lookup failed for host %s\n", hostname);
	// 	exit(1);
	// }

	// /* Connect to remote TCP port */
	// sa.sin_family = AF_INET;
	// sa.sin_port = htons(port);
	// memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	// fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	// if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
	// 	perror("connect");
	// 	exit(1);
	// }
	// fprintf(stderr, "Connected.\n");

	/* Be careful with buffer overruns, ensure NUL-termination */
	close(ppfd[1]);
	ret=read(ppfd[0],sd,sizeof(int));
	close(ppf[0]);
	strncpy(buf, HELLO_THERE, sizeof(buf));
	buf[sizeof(buf) - 1] = '\0';

	/* Say something... */
	if (insist_write(sd, buf, strlen(buf)) != strlen(buf)) {
		perror("write");
		exit(1);
	}
	fprintf(stdout, "I said:\n%s\nRemote says:\n", buf);
	fflush(stdout);


	/*
	 * Let the remote know we're not going to write anything else.
	 * Try removing the shutdown() call and see what happens.
	 */
	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}

	/* Read answer and write it to standard output */
	for (;;) {
		FD_ZERO(&readfd);
		FD_SET(sd,&readfd);
		FD_SET(fd,&readfd);


		sret=select(sd+1,&readfd,NULL,NULL);

		if(sret<0){
			printf("something went wrong\n");
		}
		else{
			if(FD_ISSET(fd,&readfd))
				char usr[]="";
				rfd=0;	
			else 
				char usr[]="[server]";
				rfd=sd;
			n = read(rfd, buf, sizeof(buf));

			if (n < 0) {
				perror("read");
				exit(1);
			}

			if (n <= 0)
				break;
			insist_write(rfd, usr, sizeof(usr));
			if (insist_write(0, buf, n) != n) {
				perror("write");
				exit(1);
			}
		}
	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}
