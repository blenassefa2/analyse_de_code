CC=gcc
CFLAGS= -fstack-protector 

all: exo1

exo1: exo1.c
	$(CC) -m32 $(CFLAGS) -g  -o $@ $^

clean:
	rm exo1
