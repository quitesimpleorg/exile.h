prefix = /usr/local
bindir = $(prefix)/bin
CFLAGS = -std=c99 -Wall -Wextra -pedantic
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic

.DEFAULT_GOAL := test


clean:
	rm -f test testcpp

test: test.c
	$(CC) test.c -g $(CFLAGS) -o test

testcpp: test.cpp
	$(CXX) test.cpp -g $(CXXFLAGS) -o testcpp

check: test
	./test.sh

.PHONY: check
