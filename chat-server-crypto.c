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
#define KEY_SIZE 16  /* AES128 */
#define BLOCK_SIZE 16

/* Convert a temp_bufer to upercase */

void toupper_buf(char *buf, size_t n)
{
	size_t i;

	for (i = 0; i < n; i++)
		buf[i] = toupper(buf[i]);
}

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

int main(int argc, char* argv[])
{
	fd_set readfd;
	char buf[256],*temp_buf;
	char usr[10],key[16],iv[16];
	char addrstr[INET_ADDRSTRLEN];
	int sd, fd=1,wfd, newsd, rfd,cfd, sret,i;
	ssize_t n;
	socklen_t len;
	struct sockaddr_in sa;
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
	/* Make sure a broken connection doesn't kill us */
	signal(SIGPIPE, SIG_IGN);

	/* Create TCP/IP socket, used as main chat channel */
	if ((sd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		exit(1);
	}
	fprintf(stderr, "Created TCP socket\n");

	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return 1;
	}

	/* Bind to a well-known port */
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(TCP_PORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);
	if (bind(sd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		perror("bind");
		exit(1);
	}
	fprintf(stderr, "Bound TCP socket to port %d\n", TCP_PORT);

	/* Listen for incoming connections */
	if (listen(sd, TCP_BACKLOG) < 0) {
		perror("listen");
		exit(1);
	}


	/* Loop forever, accept()ing connections */
	for (;;) {
		fprintf(stderr, "Waiting for an incoming connection...\n");

		/* Accept an incoming connection */
		len = sizeof(struct sockaddr_in);
		if ((newsd = accept(sd, (struct sockaddr *)&sa, &len)) < 0) {
			perror("accept");
			exit(1);
		}
		if (!inet_ntop(AF_INET, &sa.sin_addr, addrstr, sizeof(addrstr))) {
			perror("could not format IP address");
			exit(1);
		}
		fprintf(stderr, "Incoming connection from %s:%d\n", addrstr, ntohs(sa.sin_port));
		const int nfds=(int)newsd+1;

		strcpy(data.key,KEY);
		strcpy(data.iv,KEY);

		/*Initialize crypto session*/

		sess.cipher = CRYPTO_AES_CBC;
		sess.keylen = KEY_SIZE;
		sess.key = data.key;

		if (ioctl(cfd, CIOCGSESSION, &sess)) {
			perror("ioctl(CIOCGSESSION)");
			return 1;
		}	
		cryp.ses = sess.ses;
		cryp.len = sizeof(data.in);
	 	/* We break out of the loop when the remote peer goes away */
	 	for (;;) {
	 		FD_ZERO(&readfd);
			FD_SET(newsd,&readfd);
			FD_SET(fd,&readfd);
			memset(&buf,'\0',sizeof(buf));

	 		sret=select(nfds,&readfd,NULL,NULL,NULL);
	 		if(sret<0){
			perror("select");
			}
			else{
				if(FD_ISSET(fd,&readfd)){
					rfd=fd;
					wfd=newsd;
					n = read(rfd, buf, sizeof(buf));
					strcpy(usr, EMPTY);
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
				else {
					rfd=newsd;
					wfd=1;
					n = read(rfd, buf, sizeof(buf));
					strncpy(usr, CLIENT, sizeof(usr));
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
				
				if (n < 0) {
					perror("read from remote peer failed");
					exit(1);
				}
				if (n == 0){
					printf("lost connection to peer\n");
					break;
				}
				printf("%s",usr);
				fflush(stdout);
				if (insist_write(wfd, buf, sizeof(buf)) != sizeof(buf)) {
					perror("write to remote peer failed");
					exit(1);
				}
			}
	 	}
		/* Make sure we don't leak open files */
		if (close(newsd) < 0)
			perror("close");

		if (ioctl(cfd, CIOCFSESSION, &sess.ses)) {
			perror("ioctl(CIOCFSESSION)");
			return 1;
		}
		if(close(cfd)<0){
			perror("close");
		}

	}
	/* This will never happen */
	return 1;
}

