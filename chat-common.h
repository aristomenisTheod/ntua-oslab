/*
 * socket-common.h
 *
 * Simple TCP/IP communication using sockets
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 */

#ifndef _SOCKET_COMMON_H
#define _SOCKET_COMMON_H

/* Compile-time options */
#define TCP_PORT    35001
#define TCP_BACKLOG 8
#define CLIENT "/n[client]:"
#define SERVER "/n[server]:"
#define EMPTY ""
#define KEY_SIZE 16  /* AES128 */
#define BLOCK_SIZE 16

char* decrypt(const char *msg,int size,char* key,char* iv);
char* encrypt(const char *msg,int size,char* key,char* iv);
int fill_urandom_buf(char *buf, size_t cnt);

#endif /* _SOCKET_COMMON_H */

