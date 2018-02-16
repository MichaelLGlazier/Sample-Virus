CC=gcc
CFLAGS= -DNDEBUG -g -pedantic-errors -Wall -std=c99

default: seed all victim2
	$(CC) -o virus virus.o

seed: virus
	cp virus seed
	printf '\xde\xad\xbe\xef' >> seed
	cat host >> seed

all:		virus.o

.PHONY: clean seed

clean:
	rm -rf virus virus.o victim2 victim2.o


victim2: victim2.c
	$(CC) -o victim2 victim2.c
 