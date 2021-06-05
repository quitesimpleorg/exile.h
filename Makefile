prefix = /usr/local
bindir = $(prefix)/bin
CFLAGS = -std=c99 -Wall -Wextra -pedantic

.DEFAULT_GOAL := test


clean:
	rm -f test

test: test.c
	$(CC) test.c -g $(CFLAGS) -o test

check: test
	./test.sh

.PHONY: check
