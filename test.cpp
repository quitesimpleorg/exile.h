#include "exile.hpp"
#include "assert.h"
#include <map>
#include <algorithm>

std::string sandboxed_reverse(std::string str)
{
	std::reverse(str.begin(), str.end());
	return str;
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

int test_exile_launch_stdstring()
{
	std::string str = "abc123";
	std::string reversed = exile_launch<std::string>(exile_init_policy(), &sandboxed_reverse, str);
	assert(reversed == "321cba");
	return 0;
}

struct not_trivially_copyable
{
  public:
	std::string somecontent;
};

int test_exile_launch_serializer()
{
	static_assert(!std::is_trivially_copyable_v<not_trivially_copyable>);

	auto serializer = [](const not_trivially_copyable &obj, char *buf, size_t n)
	{
		serialize_stdstring<std::string>(obj.somecontent, buf, n);
		return obj.somecontent.size();
	};

	auto deserializer = [](const char *buffer, size_t n)
	{
		not_trivially_copyable obj;
		obj.somecontent = deserialize_stdstring<std::string>(buffer, n);
		return obj;
	};

	not_trivially_copyable result = exile_launch<not_trivially_copyable>(exile_init_policy(), serializer, deserializer,
																		 []()
																		 {
																			 not_trivially_copyable obj;
																			 obj.somecontent = "Just something";
																			 return obj;
																		 });

	assert(result.somecontent == "Just something");
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
		{"launch-trivial-cpp", &test_exile_launch_trivial},
		{"launch-stdstring-cpp", &test_exile_launch_stdstring},
		{"launch-serializer-cpp", &test_exile_launch_serializer},
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
