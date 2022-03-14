#include "exile.h"
#include <functional>
#include <iostream>
#include <string>
#include <tuple>
#include <memory>
#include <sys/wait.h>

#ifndef EXILE_MMAP_SIZE
#define EXILE_MMAP_SIZE 128 * 1024 * 1024 //128MB
#endif


template<typename T, typename U, typename ... Args>
class launch_arg
{
	static_assert(std::is_trivially_copyable_v<T>);
	static_assert(!std::is_pointer_v<T>);

public:
	struct exile_policy *policy;
	T *result_shm;
	U fn;
	std::tuple<Args...> args;

	launch_arg(struct exile_policy *policy, T *result_shm, U fn, Args && ... args) : policy(policy),
	result_shm(result_shm), fn(fn), args(std::forward<Args>(args)...) {}

};

template<typename T, typename U, typename ... Args>
class launch_arg_serializer
{
	static_assert(std::is_copy_constructible_v<T>);

public:
	struct exile_policy *policy;
	char *serialize_buffer;
	size_t n;
	U fn;
	std::tuple<Args...> args;

	const std::function<size_t (const T &, char *, size_t n)> &serializer;
	const std::function<T(const char * buf, size_t n)> &deserializer;

	launch_arg_serializer(struct exile_policy *policy, char *serialize_buffer, size_t n, const std::function<size_t (const T &, char *, size_t)> &serializer, const std::function<T(const char *, size_t)> &deserializer, U fn, Args && ... args) : policy(policy), serialize_buffer(serialize_buffer), n(n), fn(fn), args(std::forward<Args>(args)...), serializer(serializer), deserializer(deserializer)  {}
};

template<typename T, typename U, typename ... Args>
int exile_clone_handle_trivial(void * arg)
{
	static_assert(std::is_trivially_copyable_v<T>);
	static_assert(!std::is_pointer_v<T>);

	launch_arg<T, U, Args...> *launchargs = (launch_arg<T, U,  Args...> *) arg;
	int ret = exile_enable_policy(launchargs->policy);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("exile_enable_policy() failed: %s\n", strerror(errno));
		return 1;
	}
	T result = std::apply(launchargs->fn, launchargs->args);
	std::cout << result;
	memcpy(launchargs->result_shm, &result, sizeof(T));
	return 0;
}

template<typename T, typename U, typename ... Args>
int exile_clone_handle_serializer(void * arg)
{
	static_assert(std::is_copy_constructible_v<T>);

	launch_arg_serializer<T, U, Args...> *launchargs = (launch_arg_serializer<T, U, Args...> *) arg;
	int ret = exile_enable_policy(launchargs->policy);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("exile_enable_policy() failed: %s\n", strerror(errno));
		return 1;
	}
	T result = std::apply(launchargs->fn, launchargs->args);
	/* TODO: exception handling */
	/* TODO: ugly :S */
	char *target = launchargs->serialize_buffer + sizeof(size_t);
	size_t n = launchargs->n - sizeof(size_t);

	size_t size = launchargs->serializer(result, target, n);
	memcpy(launchargs->serialize_buffer, &size, sizeof(size_t));

	return 0;
}

inline int do_clone(int (*clonefn)(void *), void *launcharg)
{
	struct rlimit rlimit;
	int ret = getrlimit(RLIMIT_STACK, &rlimit);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("Failed to get stack size: %s\n", strerror(errno));
		return ret;
	}
	size_t size = rlimit.rlim_cur;
	char *stack = (char *) calloc(1, size);
	if(stack == NULL)
	{
		EXILE_LOG_ERROR("Failed to allocate stack memory for child\n");
		return 1;
	}
	stack += size;

	ret = clone(clonefn, stack, 17 /* SIGCHLD */, launcharg);
	int status = 0;
	waitpid(ret, &status, __WALL);
	if(WIFEXITED(status))
	{
		return WEXITSTATUS(status);
	}
	/* TODO: exception or what? */
	return 23;
}

template<typename T, typename U, typename ... Args>
typename std::enable_if_t<std::is_trivially_copyable_v<T>, T> exile_launch(struct exile_policy *policy, U fn, Args && ... args)
{
	size_t mapsize = sizeof(T);
	T * sharedbuf =  (T *) mmap(NULL, mapsize , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if(sharedbuf == NULL)
	{
		throw std::runtime_error(std::string("mmap failed: ") + strerror(errno));
	}

	std::shared_ptr<void> deleter(nullptr, [sharedbuf, mapsize](...){ munmap(sharedbuf, mapsize); });
	launch_arg<T, U, Args...> launcharg(policy, sharedbuf, fn, std::forward<Args>(args)...);

	int (*clonefn)(void *) = &exile_clone_handle_trivial<T, U, Args...>;
	/* TODO: exception or what? */
	int ret = do_clone(clonefn, &launcharg);
	if(ret == 0)
	{
		return *sharedbuf;
	}
	throw std::runtime_error(std::string("clone() failed: " + std::to_string(ret)));
	return T();
}



template<typename T, typename U, typename ... Args>
typename std::enable_if_t<!std::is_trivially_copyable_v<T> && std::is_copy_constructible_v<T>, T>
	exile_launch(struct exile_policy *policy, const std::function<size_t (const T &, char *, size_t)> &serializer, const std::function<T(const char *, size_t)> &deserializer, U fn, Args && ... args)
{
	size_t mapsize = EXILE_MMAP_SIZE;
	char *sharedbuf =  (char *) mmap(NULL, mapsize , PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
	if(sharedbuf == NULL)
	{
		throw std::runtime_error(std::string("mmap failed: ") + strerror(errno));
	}
	std::shared_ptr<void> deleter(nullptr, [sharedbuf, mapsize](...){ munmap(sharedbuf, mapsize); });


	launch_arg_serializer<T, U, Args...> launcharg(policy, sharedbuf, mapsize, serializer, deserializer, fn,												   std::forward<Args>(args)...);

	int (*clonefn)(void *) = &exile_clone_handle_serializer<T, U, Args...>;
	/* TODO: exception or what? */
	int ret = do_clone(clonefn, &launcharg);
	if(ret == 0)
	{
		size_t size = 0;
		memcpy(&size, sharedbuf, sizeof(size));

		return deserializer(sharedbuf + sizeof(size_t), size);
	}
	throw std::runtime_error(std::string("clone() failed: " + std::to_string(ret)));
	return T();

}

template<class T>
std::basic_string<typename T::value_type> deserialize_stdstring(const char *buf, size_t n)
{
	return std::basic_string<typename T::value_type> { buf, n };
}

template<class T>
size_t serialize_stdstring(const std::basic_string<typename T::value_type> &t, char *buf, size_t n)
{
	if(n < t.size())
	{
		return 0;
	}
	memcpy(buf, t.data(), t.size());
	return t.size();
}


template<typename T, typename U, typename ... Args>
std::basic_string<typename T::value_type> exile_launch(struct exile_policy *policy, U fn, Args && ... args)
{
	return exile_launch<T, U, Args...>(policy, &serialize_stdstring<T>, &deserialize_stdstring<T>, fn, std::forward<Args>(args) ...);
}
