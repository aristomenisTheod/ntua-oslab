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
#define CLIENT "[client]:"
#define SERVER "[server]:"
#define EMPTY ""
#define KEY_SIZE 16  /* AES128 */
#define BLOCK_SIZE 16
#define DATA_SIZE 256
#define KEY "1234567891234567"
#endif /* _SOCKET_COMMON_H */

