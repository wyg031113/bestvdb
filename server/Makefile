all:vdb_server
CFLAGS=-g -I../include -DDEBUG_ON
LIBS=-lgmp -lpbc -lmysqlclient -lpthread -lcrypto
vdb_server_c=vdb_server.c ../lib/config.c ../lib/param.c ../lib/db.c ../lib/vdb.c
CC=gcc

vdb_server:$(vdb_server_c)
	$(CC) $(CFLAGS) $(vdb_server_c) $(LIBS) -o $@
clean:
	rm -rf *.o *~ vdb_server

