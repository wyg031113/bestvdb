all:vdb_client
CFLAGS=-I../include -DDEBUG_off
LIBS=-lpbc -lgmp -lmysqlclient -lcrypto
vdb_client_c=vdb_client.c ../lib/config.c ../lib/param.c ../lib/db.c ../lib/vdb.c
vdb_client:$(vdb_client_c)
	$(CC) $(CFLAGS) $(vdb_client_c) $(LIBS) -o $@
install:
	rm -rf /usr/local/bin/vdb_client
	rm -rf /etc/vdb_client_conf
	cp ./vdb_client /usr/local/bin/
	cp -r ./vdb_client_conf /etc/
	chmod 777 /usr/local/bin/vdb_client
	chmod -R 777 /etc/vdb_client_conf
	@echo "Installed vdb client to /usr/local/bin and config file in /etc/vdb_client_conf/"
uninstall:
	rm -rf /usr/local/bin/vdb_client
	rm -rf /etc/vdb_client_conf

clean:
	rm -rf vdb_client *.o *~
