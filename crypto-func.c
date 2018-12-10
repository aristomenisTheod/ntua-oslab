#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
 
#include <sys/types.h>
#include <sys/stat.h>

#include <crypto/cryptodev.h>

#define KEY_SIZE 16  /* AES128 */
#define BLOCK_SIZE 16

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


static int fill_urandom_buf(char *buf, size_t cnt)
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


char* decrypt(const char *msg,int size,char *key, char *iv){
	struct session_op sess;
	struct crypt_op cryp;
	int cfd;
	struct {
		char in[size],
				encrypted[size],
				decrypted[size],
				*iv,
				*key;
	}data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return NULL;
	}

	// if (fill_urandom_buf(data.iv, BLOCK_SIZE) < 0) {
	// 	perror("getting data from /dev/urandom\n");
	// 	return NULL;
	// }

	strcpy(data.in,msg);
	data.key=key;
	data.iv=iv;
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	cryp.ses = sess.ses;
	cryp.len = sizeof(data.in);
	cryp.src = data.in;
	cryp.iv = data.iv;
	cryp.dst = data.decrypted;
	cryp.op = COP_DECRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return NULL;
	}
	if(close(cfd)<0){
		perror("close");
		return NULL;
	}
	return data.decrypted;
}

char* encrypt(const char *msg,int size,char* key, char *iv){
	struct session_op sess;
	struct crypt_op cryp;
	int cfd;
	struct {
		char in[size],
				encrypted[size],
				decrypted[size],
				iv[size],
				*key;
	}data;

	memset(&sess, 0, sizeof(sess));
	memset(&cryp, 0, sizeof(cryp));

	cfd = open("/dev/crypto", O_RDWR);
	if (cfd < 0) {
		perror("open(/dev/crypto)");
		return NULL;
	}

	if (fill_urandom_buf(data.iv, BLOCK_SIZE) < 0) {
		perror("getting data from /dev/urandom\n");
		return NULL;
	}

	strcpy(data.in,msg);
	data.key=key;
	data.iv=iv;
	sess.cipher = CRYPTO_AES_CBC;
	sess.keylen = KEY_SIZE;
	sess.key = data.key;

	cryp.ses = sess.ses;
	cryp.len = sizeof(data.in);
	cryp.src = data.in;
	cryp.iv = data.iv;
	cryp.dst = data.encrypted;
	cryp.op = COP_DECRYPT;
	if (ioctl(cfd, CIOCCRYPT, &cryp)) {
		perror("ioctl(CIOCCRYPT)");
		return NULL;
	}
	if(close(cfd)<0){
		perror("close");
		return NULL;
	}
	return data.encrypted;
}
