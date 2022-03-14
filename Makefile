prefix = /usr/local
bindir = $(prefix)/bin
CFLAGS = -std=c99 -Wall -Wextra -pedantic
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic

.DEFAULT_GOAL := tests


clean:
	rm -f test testcpp

test: test.c exile.h
	$(CC) test.c exile.c -g $(CFLAGS) -o test

testcpp: test.cpp exile.h exile.hpp
	$(CXX) test.cpp -g $(CXXFLAGS) -o testcpp

tests: test testcpp

check: tests
	./test.sh

.PHONY: check
