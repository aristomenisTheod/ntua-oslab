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

#include "chat-common.h"

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
	int sd, port;
	ssize_t n,sret;
	char buf[100],usr[10],*temp_buf;
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int rfd,fd=0,wfd;
	char key[16];
	fd_set readfd;


	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */
	printf("insert key:\n");
	scanf("%s",key);
	while(sizeof(key)!=16){
		printf("please insert key again(16 characters)\n");
		scanf("%s",key);
	}
	printf("key accepted!\n");
	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");
	
	/* Look up remote hostname on DNS */
	if ( !(hp = gethostbyname(hostname))) {
		printf("DNS lookup failed for host %s\n", hostname);
		exit(1);
	}

	/* Connect to remote TCP port */
	sa.sin_family = AF_INET;
	sa.sin_port = htons(port);
	memcpy(&sa.sin_addr.s_addr, hp->h_addr, sizeof(struct in_addr));
	fprintf(stderr, "Connecting to remote host... "); fflush(stderr);
	if (connect(sd, (struct sockaddr *) &sa, sizeof(sa)) < 0) {
		perror("connect");
		exit(1);
	}
	fprintf(stderr, "Connected.\n");
	const int nfds=(int)sd+1;

	/* Be careful with bufer overruns, ensure NUL-termination */

	for(;;){
		FD_ZERO(&readfd);
		FD_SET(sd,&readfd);
		FD_SET(fd,&readfd);
		/*check if someone has writen to the socket or to stdin*/
		sret=select(nfds,&readfd,NULL,NULL,NULL);
		if(sret<0){
			perror("select");
			break;
		}
		else{
			if(FD_ISSET(sd,&readfd)){
				rfd=sd;
				wfd=1;
				strncpy(usr, SERVER, sizeof(usr));
				n=read(rfd,buf,sizeof(buf));
				// temp=buf;
				if(n<=0){
					printf("connection to peer lost\n");
					break;
				}
				temp_buf=decrypt(buf,sizeof(buf),key);
				printf("encrypted:\n");
					if (insist_write(wfd, buf, n) != n) {
						perror("write to remote peer failed");
						exit(1);
					}
					printf("decrypted:\n");
					if (insist_write(wfd, temp_buf, n) != n) {
						perror("write to remote peer failed");
						exit(1);
					}
			}
			if(FD_ISSET(fd,&readfd)){
				rfd=fd;
				wfd=sd;
				strncpy(usr, EMPTY, sizeof(usr));
				n=read(rfd,buf,sizeof(buf));
				// temp=buf;
				if(n<=0){
					perror("read");
					continue;
				}
				temp_buf=encrypt(buf,sizeof(buf),key);
				printf("original:\n");
					if (insist_write(wfd, buf, n) != n) {
						perror("write to remote peer failed");
						exit(1);
					}
					printf("encrypted:\n");
					if (insist_write(wfd, temp_buf, n) != n) {
						perror("write to remote peer failed");
						exit(1);
					}
			}
		}
		insist_write(1, usr, sizeof(usr));
		if (insist_write(wfd, temp_buf, n) != n) {
			perror("write to remote peer failed");
			exit(1);
		}

	}

	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}
	fprintf(stderr, "\nDone.\n");
	return 0;
}
