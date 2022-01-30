#include "exile.hpp"
#include "assert.h"
#include <map>

std::string sandboxed_reverse(std::string str)
{
	std::reverse(str.begin(), str.end());
	return str;
}

std::string deserialize_stdstring(const char *buf, size_t n)
{
	return std::string { buf, n };
}

size_t serialize_stdstring(const std::string &t, char *buf, size_t n)
{
	if(n < t.size())
	{
		return 0;
	}
	memcpy(buf, t.data(), t.size());
	return t.size();
}

size_t stdstrlen(const std::string &str)
{
	return str.size();
}

int incrementer(int arg)
{
	return ++arg;
}
int test_exile_launch_trivial()
{
	int u = 22;
	int result = exile_launch<int>(exile_init_policy(), &incrementer, u);
	assert(result == 23);
	return 0;
}

int test_exile_launch()
{
	std::string str = "abc123";
	std::string reversed = exile_launch<std::string>(exile_init_policy(), &serialize_stdstring, &deserialize_stdstring, &sandboxed_reverse, str);

	assert(reversed == "321cba");
	return 0;
}

int main(int argc, char *argv[])
{
	if(argc < 2)
	{
		std::cerr << "Missing test" << std::endl;
		return 1;
	}
	std::map<std::string, int (*)()> map = {
		{ "launch-trivial-cpp", &test_exile_launch_trivial} ,
		{ "launch-cpp", &test_exile_launch }
	};

	std::string test = argv[1];
	if(test == "--dumptests")
	{
		for(auto &entry : map)
		{
			std::cout << entry.first << std::endl;
		}
		return 0;
	}
	int (*fn)() = map[test];
	if(fn != nullptr)
	{
		return fn();
	}
	std::cerr << "Unknown test" << std::endl;
	return 1;
}
