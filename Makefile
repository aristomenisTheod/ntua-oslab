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

BINS= chat-server chat-client crypt-func.o

all: $(BINS)

crypt-func.o: crypto-func.c chat-common.h
	$(CC) $(CFLAGS) -c -o $@ $< $(LIBS)

chat-server: chat-server.c chat-common.h crypt-func.o
	$(CC) $(CFLAGS) -o $@ $< crypt-func.o $(LIBS)

chat-client: chat-client.c chat-common.h crypt-func.o
	$(CC) $(CFLAGS) -o $@ $< crypt-func.o $(LIBS)

clean:
	rm -f *.o *~ $(BINS)

