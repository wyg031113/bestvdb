all:vdb_client
CFLAGS=-I../include -g -DDEBUG_ON
LIBS=-lpbc -lgmp -lmysqlclient -lcrypto
vdb_client_c=vdb_client.c ../lib/config.c ../lib/param.c ../lib/db.c ../lib/vdb.c
vdb_client:$(vdb_client_c)
	$(CC) $(CFLAGS) $(vdb_client_c) $(LIBS) -o $@
clean:
	rm -rf vdb_client *.o *~
