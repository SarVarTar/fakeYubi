CC=gcc
CFLAGS=-O2 -Wall -g -lpthread -lcbor -lm -lcrypto
objects = sendpackages.c authenticatorMakeCredential.c authenticatorStatics.c

.PHONY: all

all: fakeYubi

#gcc multi.c -o multi sendpackages.c authenticatorMakeCredential.c authenticatorStatics.c -O2 -Wall -g -lpthread -lcbor -lm -lcrypto

fakeYubi: fakeYubi.c
	$(CC) -o $@ $(objects) $< $(CFLAGS)