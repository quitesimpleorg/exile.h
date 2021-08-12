#include "qssb.h"
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>

int test_default_main(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int ret = qssb_enable_policy(policy);
	return ret;
}

int test_both_syscalls(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	int syscalls[] = {1,2,3};

	qssb_append_denied_syscalls(policy, syscalls, 3);
	qssb_append_allowed_syscalls(policy, syscalls, 3);

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

	qssb_append_denied_syscall(policy, QSSB_SYS(getuid));

	int ret = qssb_enable_policy(policy);
	uid_t pid = geteuid();
	pid = getuid();
	return 0;
}

int test_seccomp_blacklisted_call_permitted(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();

	qssb_append_denied_syscall(policy, QSSB_SYS(getuid));

	int ret = qssb_enable_policy(policy);
	//geteuid is not blacklisted, so must succeed
	uid_t pid = geteuid();
	return 0;
}

int test_seccomp_x32_kill(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();

	qssb_append_denied_syscall(policy, QSSB_SYS(getuid));

	int ret = qssb_enable_policy(policy);

	/* Attempt to bypass by falling back to x32 should be blocked */
	syscall(QSSB_SYS(getuid)+__X32_SYSCALL_BIT);
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

int test_nofs(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	policy->no_fs = 1;

	int ret = qssb_enable_policy(policy);
	if(ret != 0)
	{
		fprintf(stderr, "Failed to activate nofs sandbox\n");
		return -1;
	}

	int s = socket(AF_INET,SOCK_STREAM,0);
	if(s == -1)
	{
		fprintf(stderr, "Failed to open socket but this was not requested by policy\n");
		return 0;
	}

	/* Expect seccomp to take care of this */
	if(open("/test", O_CREAT | O_WRONLY) >= 0)
	{
		fprintf(stderr, "Failed: Do not expect write access\n");
		return -1;
	}

	return 0;
}


int test_no_new_fds(int argc, char *argv[])
{
	struct qssb_policy *policy = qssb_init_policy();
	policy->no_new_fds = 1;

	int ret = qssb_enable_policy(policy);
	if(ret != 0)
	{
		fprintf(stderr, "Failed to activate no_new_fd sandbox\n");
		return -1;
	}

	if(open("/tmp/test", O_CREAT | O_WRONLY) >= 0)
	{
		fprintf(stderr, "Failed: Could open new file descriptor\n");
		return -1;
	}

	int s = socket(AF_INET,SOCK_STREAM,0);
	if(s >= 0)
	{
		fprintf(stderr, "Failed: socket got opened but policy denied\n");
		return -1;
	}

	return 0;

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
	{ "seccomp-x32-kill", &test_seccomp_x32_kill, false},
	{ "landlock", &test_landlock, true },
	{ "landlock-deny-write", &test_landlock_deny_write, true },
	{ "no_fs", &test_nofs, false},
	{ "no_new_fds", &test_no_new_fds, true}
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
