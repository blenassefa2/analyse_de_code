CC=gcc
CFLAGS= -fstack-protector 

all: exo2

exo2: exo2.c
	$(CC) -m32 $(CFLAGS) -g  -o $@ $^

clean:
	rm exo2
