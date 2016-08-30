all:paramgen
CFLAGS=-I../include -DDEBUG_ONx
paramgen_c=paramgen.c ../lib/config.c ../lib/param.c ../lib/db.c
CC=gcc
LIBS=-lpbc -lgmp -lmysqlclient -lcrypto
paramgen:$(paramgen_c)
	$(CC) $(CFLAGS) $(paramgen_c) $(LIBS) -o $@
install:
	rm -rf /usr/local/bin/paramgen
	rm -rf /etc/vdb_paramgen
	cp ./paramgen /usr/local/bin
	cp -r ./vdb_paramgen /etc/
	chmod 777 /usr/local/bin/paramgen
	chmod -R 777 /etc/vdb_paramgen
	@echo "Installed paramgen to /usr/local/bin and config file in /etc/vdb_paramgen"
uninstall:
	rm -rf /usr/local/bin/paramgen
	rm -rf /etc/vdb_paramgen
clean:
	rm -rf *.o paramgen *~

