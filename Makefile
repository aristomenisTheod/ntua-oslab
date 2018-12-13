###################################################
#
# Makefile
# Simple TCP/IP communication using sockets
#
# Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
#
###################################################

CC = gcc

CFLAGS = -Wall
CFLAGS += -g
# CFLAGS += -O2 -fomit-frame-pointer -finline-functions

LIBS = 

BINS= chat-server chat-client chat-client-crypto chat-server-crypto

all: $(BINS)

chat-server: chat-server.c chat-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

chat-client: chat-client.c chat-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

chat-server-crypto: chat-server-crypto.c chat-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

chat-client-crypto: chat-client-crypto.c chat-common.h
	$(CC) $(CFLAGS) -o $@ $< $(LIBS)

clean:
	rm -f *.o *~ $(BINS)

