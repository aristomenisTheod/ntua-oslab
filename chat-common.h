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
#endif /* _SOCKET_COMMON_H */

char* decrypt(const char *msg,int size,char *key);
char* encrypt(const char *msg,int size,char *key);

