prefix = /usr/local
bindir = $(prefix)/bin
CFLAGS = -std=c99 -Wall -Wextra -pedantic
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic

.DEFAULT_GOAL := tests


clean:
	rm -f test exile.o testcpp


exile.o: exile.c exile.h
	$(CC) -c exile.c -g $(CFLAGS) -o exile.o

test: test.c exile.h exile.o
	$(CC) test.c exile.o -g $(CFLAGS) -o test

testcpp: test.cpp exile.h exile.hpp exile.o
	$(CXX) test.cpp exile.o -g $(CXXFLAGS) -o testcpp

tests: test testcpp

check: tests
	./test.sh

.PHONY: check
