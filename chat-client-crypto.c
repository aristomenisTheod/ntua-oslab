#include <stdio.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <sys/stat.h>

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <crypto/cryptodev.h>
#include <sys/ioctl.h>

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

ssize_t insist_read(int fd, void *buf, size_t cnt)
{
        ssize_t ret;
        size_t orig_cnt = cnt;

        while (cnt > 0) {
                ret = read(fd, buf, cnt);
                if (ret < 0)
                        return ret;
                buf += ret;
                cnt -= ret;
        }

        return orig_cnt;
}

static int fill_urandom_buf(unsigned char *buf, size_t cnt)
{
        int crypto_fd;
        int ret = -1;

        crypto_fd = open("/dev/urandom", O_RDONLY);
        if (crypto_fd < 0)
                return crypto_fd;

        ret = insist_read(crypto_fd, buf, cnt);
        close(crypto_fd);

        return ret;
}

int main(int argc, char *argv[])
{
	int sd, port,i;
	ssize_t n,sret;
	char buf[256],usr[10],*temp_buf;
	char *hostname;
	struct hostent *hp;
	struct sockaddr_in sa;
	int rfd,fd=0,wfd,cfd;
	char key[KEY_SIZE],iv[BLOCK_SIZE];
	fd_set readfd;
	struct session_op sess;
	struct crypt_op cryp;
	struct {
		unsigned char 	in[DATA_SIZE],
				encrypted[DATA_SIZE],
				decrypted[DATA_SIZE],
				iv[BLOCK_SIZE],
				key[KEY_SIZE];
	} data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	if (argc != 3) {
		fprintf(stderr, "Usage: %s hostname port\n", argv[0]);
		exit(1);
	}
	hostname = argv[1];
	port = atoi(argv[2]); /* Needs better error checking */

	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	printf("\nInitialization vector (IV):\n");
	for (i = 0; i < BLOCK_SIZE; i++)
		printf("%x", data.iv[i]);
	printf("\n");

	printf("\nEncryption key:\n");
	for (i = 0; i < KEY_SIZE; i++)
		printf("%x", data.key[i]);
	printf("\n");

	
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
	strcpy(data.key,KEY);
	strcpy(data.iv,KEY);
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

	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	if (ioctl(cfd, CIOCGSESSION, &sess)) {
		perror("ioctl(CIOCGSESSION)");
		return 1;
	}	
	cryp.ses = sess.ses;
	cryp.len = sizeof(data.in);

	for(;;){
		FD_ZERO(&readfd);
		FD_SET(sd,&readfd);
		FD_SET(fd,&readfd);
		memset(&buf,'\0',sizeof(buf));
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
				if(n<=0){
					printf("connection to peer lost\n");
					break;
				}
				/*decrypt received message*/		
				memcpy(data.in,buf,sizeof(buf));
				cryp.src = data.in;
				cryp.dst = data.decrypted;
				cryp.iv = data.iv;
				cryp.op = COP_DECRYPT;

				if (ioctl(cfd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}
				memcpy(buf,data.decrypted,sizeof(buf));
			}
			if(FD_ISSET(fd,&readfd)){
				rfd=fd;
				wfd=sd;
				strncpy(usr, EMPTY, sizeof(usr));
				n=read(rfd,buf,sizeof(buf));
				if(n<=0){
					perror("read");
					continue;
				}
				memcpy(data.in,buf,sizeof(buf));
				cryp.src = data.in;
				cryp.dst = data.encrypted;
				cryp.iv = data.iv;
				cryp.op = COP_ENCRYPT;

				if (ioctl(cfd, CIOCCRYPT, &cryp)) {
					perror("ioctl(CIOCCRYPT)");
					return 1;
				}
				memcpy(buf,data.encrypted,sizeof(buf));
			}
		}
		printf("%s",usr);
		fflush(stdout);
		if (insist_write(wfd, buf, sizeof(buf)) != sizeof(buf)) {
			perror("write to remote peer failed");
			exit(1);
		}

	}

	if (shutdown(sd, SHUT_WR) < 0) {
		perror("shutdown");
		exit(1);
	}

	/*Close crypto session*/
	if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
		perror("ioctl(CIOCFSESSION)");
		return 1;
	}
	if(close(cfd)<0){
		perror("close");
	}

	fprintf(stderr, "\nDone.\n");
	return 0;
}
