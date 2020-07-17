CC=gcc
CFLAGS=-O2 -Wall -g -lpthread -lcbor -lm -lcrypto
objects = sendpackages.c ctaplib.c authenticatorStatics.c interface.c

.PHONY: all

all: fakeYubi

fakeYubi: fakeYubi.c
	$(CC) -o $@ $(objects) $< $(CFLAGS)