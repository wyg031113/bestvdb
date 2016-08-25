all:paramgen
CFLAGS=-I../include -DDEBUG_ON -g
paramgen_c=paramgen.c ../lib/config.c ../lib/param.c
CC=gcc
LIBS=-lpbc -lgmp -lpthread
paramgen:$(paramgen_c)
	$(CC) $(CFLAGS) $(paramgen_c) $(LIBS) -o $@
clean:
	rm -rf *.o paramgen

