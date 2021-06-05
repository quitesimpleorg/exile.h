#include "qssb.h"
#include <stdbool.h>
int test_default_main(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int ret = qssb_enable_policy(policy);
	return ret;
}

int test_both_syscalls(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int bla[] = { 1,2,3};
	policy->blacklisted_syscalls = &bla;
	policy->allowed_syscalls = &bla;
	int ret = qssb_enable_policy(policy);
	if(ret != 0)
	{
		return 0;
	}
	return 1;
}

int test_seccomp_blacklisted(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int blacklisted[] = { QSSB_SYS(getuid) };
	policy->blacklisted_syscalls = blacklisted;
	int ret = qssb_enable_policy(policy);
	uid_t pid = geteuid();
	pid = getuid();
	return 0;
}

int test_seccomp_blacklisted_call_permitted(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int blacklisted[] = { QSSB_SYS(getuid) };
	policy->blacklisted_syscalls = blacklisted;
	int ret = qssb_enable_policy(policy);
	//geteuid is not blacklisted, so must succeed
	uid_t pid = geteuid();
	return 0;
}

int test_landlock(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	qssb_append_path_policy(policy, QSSB_FS_ALLOW_READ, "/proc/self/fd");
	int ret = qssb_enable_policy(policy);
	int fd = open("/", O_RDONLY | O_CLOEXEC);
	if(fd < 0)
	{
		return 0;
	}
	return 1;
}

int test_landlock_deny_write(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	qssb_append_path_policy(policy, QSSB_FS_ALLOW_READ, "/tmp/");
	int ret = qssb_enable_policy(policy);
	int fd = open("/tmp/a", O_WRONLY | O_CLOEXEC);
	if(fd < 0)
	{
		return 0;
	}
	return 1;
}

struct dispatcher
{
	char *name;
	int (*f)(int, char **);
	bool must_exit_zero;
};

struct dispatcher dispatchers[] = {
	{ "default", &test_default_main, true },
	{ "seccomp-blacklisted", &test_seccomp_blacklisted, false },
	{ "seccomp-blacklisted-permitted", &test_seccomp_blacklisted_call_permitted, true },
	{ "landlock", &test_landlock, true },
	{ "landlock-deny-write", &test_landlock_deny_write, true }
};

int main(int argc, char *argv[])
{

	if(argc < 2)
	{
		fprintf(stderr, "Usage: %s [testname]\n", argv[0]);
		return EXIT_FAILURE;
	}
	char *test = argv[1];
	if(strcmp(test, "--dumptests") == 0)
	{
		for(unsigned int i = 0; i < sizeof(dispatchers)/sizeof(dispatchers[0]); i++)
		{
			printf("%s:%i\n", dispatchers[i].name, dispatchers[i].must_exit_zero ? 1 : 0);
		}
		return EXIT_SUCCESS;
	}

	for(unsigned int i = 0; i < sizeof(dispatchers)/sizeof(dispatchers[0]); i++)
	{
		struct dispatcher *current = &dispatchers[i];
		if(strcmp(current->name, test) == 0)
		{
			return current->f(argc, argv);
		}
	}
	fprintf(stderr, "Unknown test\n");
	return EXIT_FAILURE;
}
