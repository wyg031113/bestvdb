all:vdb_server
CFLAGS=-I../include -DDEBUG_OFF
LIBS=-lgmp -lpbc -lmysqlclient -lpthread -lcrypto
vdb_server_c=vdb_server.c ../lib/config.c ../lib/param.c ../lib/db.c ../lib/vdb.c
CC=gcc

vdb_server:$(vdb_server_c)
	$(CC) $(CFLAGS) $(vdb_server_c) $(LIBS) -o $@
install:
	rm -rf /usr/local/bin/vdb_server
	rm -rf /etc/vdb_server_conf
	cp ./vdb_server /usr/local/bin
	cp -r ./vdb_server_conf /etc
	chmod 777 /usr/local/bin/vdb_server
	chmod 777 /etc/vdb_server_conf
	@echo "Installed vdb server to /usr/local/bin and config file in /etc/vdb_server_conf"
uninstall:
	rm -rf /usr/local/bin/vdb_server
	rm -rf /etc/vdb_server_conf

clean:
	rm -rf *.o *~ vdb_server

