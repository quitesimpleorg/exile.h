#include "exile.h"
#include <stdbool.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#define LOG(...) do { fprintf(stdout, "%s(): ", __func__); fprintf(stdout, __VA_ARGS__); } while(0)

int xexile_enable_policy(struct exile_policy *policy)
{
	int ret = exile_enable_policy(policy);
	if(ret != 0)
	{
		LOG("failed: %i\n", ret);
		exit(EXIT_FAILURE);
	}
	return 0;
}

int test_default_main()
{
	struct exile_policy *policy = exile_init_policy();
	return xexile_enable_policy(policy);
}

static int test_expected_kill(int (*f)())
{
	pid_t pid = fork();
	if(pid == 0)
	{
		return f();
	}
	int status = 0;
	waitpid(pid, &status, 0);

	if(WIFSIGNALED(status))
	{
		int c = WTERMSIG(status);
		if(c == SIGSYS)
		{
			LOG("Got expected signal\n");
			return 0;
		}
		LOG("Unexpected status code: %i\n", c);
		return 1;
	}
	else
	{
		int c = WEXITSTATUS(status);
		LOG("Process was not killed, test fails. Status code of exit: %i\n", c);
		return 1;
	}
	return 0;
}


static int test_successful_exit(int (*f)())
{
	pid_t pid = fork();
	if(pid == 0)
	{
		return f();
	}
	int status = 0;
	waitpid(pid, &status, 0);

	if(WIFSIGNALED(status))
	{
		int c = WTERMSIG(status);
		LOG("Received signal, which was not expected. Signal was: %i\n", c);
		return 1;
	}
	else
	{
		int c = WEXITSTATUS(status);
		if(c != 0)
		{
			LOG("Process failed to exit properly. Status code is: %i\n", c);
		}
		return c;
	}
	LOG("Process exited sucessfully as expected");
	return 0;
}


static int do_test_seccomp_blacklisted()
{
	struct exile_policy *policy = exile_init_policy();
	exile_append_syscall_policy(policy,EXILE_SYS(getuid), EXILE_SYSCALL_DENY_KILL_PROCESS, NULL, 0);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);

	xexile_enable_policy(policy);

	uid_t pid = syscall(EXILE_SYS(geteuid));
	pid = syscall(EXILE_SYS(getuid));
	return 0;


}
int test_seccomp_blacklisted()
{
	return test_expected_kill(&do_test_seccomp_blacklisted);
}


static int do_test_seccomp_blacklisted_call_permitted()
{
	struct exile_policy *policy = exile_init_policy();

	exile_append_syscall_policy(policy, EXILE_SYS(getuid),  EXILE_SYSCALL_DENY_KILL_PROCESS, NULL, 0);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);

	xexile_enable_policy(policy);
	//geteuid is not blacklisted, so must succeed
	uid_t pid = syscall(EXILE_SYS(geteuid));
	return 0;
}


int test_seccomp_blacklisted_call_permitted()
{
	return test_successful_exit(&do_test_seccomp_blacklisted_call_permitted);
}

static int do_test_seccomp_x32_kill()
{
	struct exile_policy *policy = exile_init_policy();

	exile_append_syscall_policy(policy, EXILE_SYS(getuid), EXILE_SYSCALL_DENY_KILL_PROCESS, NULL, 0);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);

	xexile_enable_policy(policy);

	/* Attempt to bypass by falling back to x32 should be blocked */
	syscall(EXILE_SYS(getuid)+__X32_SYSCALL_BIT);

	return 0;
}

int test_seccomp_x32_kill()
{
	return test_expected_kill(&do_test_seccomp_x32_kill);
}

/* Tests whether seccomp rules end with a policy matching all syscalls */
int test_seccomp_require_last_matchall()
{
	struct exile_policy *policy = exile_init_policy();

	exile_append_syscall_policy(policy, EXILE_SYS(getuid), EXILE_SYSCALL_DENY_KILL_PROCESS, NULL, 0);

	int status = exile_enable_policy(policy);
	if(status == 0)
	{
		LOG("Failed. Should not have been enabled!");
		return 1;
	}
	return 0;
}

static int do_test_seccomp_errno()
{
	struct exile_policy *policy = exile_init_policy();

	exile_append_syscall_policy(policy, EXILE_SYS(close),EXILE_SYSCALL_DENY_RET_ERROR,  NULL, 0);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);

	xexile_enable_policy(policy);
	uid_t id = syscall(EXILE_SYS(getuid));

	int fd = syscall(EXILE_SYS(close), 0);
	LOG("close() return code: %i, errno: %s\n", fd, strerror(errno));
	return fd == -1 ? 0 : 1;
}



int test_seccomp_errno()
{
	return test_successful_exit(&do_test_seccomp_errno);
}

int test_seccomp_argfilter_allowed()
{
	struct exile_policy *policy = exile_init_policy();

	struct sock_filter argfilter[2] =
	{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, O_WRONLY, 0, EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
	};

	exile_append_syscall_policy(policy, EXILE_SYS(open),EXILE_SYSCALL_DENY_RET_ERROR,  argfilter, 2);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);
	xexile_enable_policy(policy);


	char *t = "/dev/random";
	int ret = (int) syscall(EXILE_SYS(open),t, O_RDONLY);

	if(ret == -1)
	{
		printf("Failed: open was expected to succeed, but returned %i\n", ret);
		return 1;
	}
	return 0;
}

int test_seccomp_argfilter_filtered()
{
	struct exile_policy *policy = exile_init_policy();

	struct sock_filter argfilter[2] =
	{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, O_WRONLY, 0, EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
	};

	exile_append_syscall_policy(policy, EXILE_SYS(open),EXILE_SYSCALL_DENY_RET_ERROR, argfilter, 2);
	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);
	xexile_enable_policy(policy);

	char *t = "/dev/random";
	int ret = (int) syscall(EXILE_SYS(open),t, O_WRONLY);

	if(ret != -1)
	{
		printf("Failed: open was expected to fail, but returned %i\n", ret);
		return 1;
	}
	return 0;
}


int test_seccomp_argfilter_mixed()
{
	struct exile_policy *policy = exile_init_policy();

	struct sock_filter argfilter[2] =
	{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[1]))),
		BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, O_WRONLY, 0, EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
	};

	exile_append_syscall_policy(policy, EXILE_SYS(stat),EXILE_SYSCALL_DENY_RET_ERROR, NULL,0);
	exile_append_syscall_policy(policy, EXILE_SYS(open),EXILE_SYSCALL_DENY_RET_ERROR, argfilter, 2);
	exile_append_syscall_policy(policy, EXILE_SYS(getpid),EXILE_SYSCALL_DENY_RET_ERROR, NULL, 0);

	exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW);
	xexile_enable_policy(policy);

	struct stat statbuf;
	int s = (int) syscall(EXILE_SYS(stat), "/dev/urandom", &statbuf);
	if(s != -1)
	{
		LOG("Failed: stat was expected to fail, but returned %i\n", s);
		return 1;
	}

	pid_t p = (pid_t) syscall(EXILE_SYS(getpid));
	if(p != -1)
	{
		LOG("Failed: getpid was expected to fail, but returned %i\n", p);
		return 1;
	}

	char *t = "/dev/random";
	int ret = (int) syscall(EXILE_SYS(open),t, O_WRONLY);
	if(ret != -1)
	{
		LOG("Failed: open was expected to fail, but returned %i\n", ret);
		return 1;
	}
	ret = (int) syscall(EXILE_SYS(open), t, O_RDONLY);
	if(ret == -1)
	{
		LOG("Failed: open with O_RDONLY was expected to succeed, but returned %i\n", ret);
		return 1;
	}
	return 0;
}


int do_test_seccomp_vow_socket()
{
	struct exile_policy *policy = exile_init_policy();
	policy->vow_promises = EXILE_SYSCALL_VOW_STDIO | EXILE_SYSCALL_VOW_INET | EXILE_SYSCALL_VOW_DENY_ERROR;
	xexile_enable_policy(policy);

	int s = socket(AF_INET, SOCK_STREAM, 0);
	if(s == -1)
	{
		LOG("Failed: socket was expected to succeed, but returned %i\n", s);
		return 1;
	}
	s = socket(AF_UNIX, SOCK_DGRAM, 0);
	if(s != -1)
	{
		LOG("Failed: socket was expected to fail, but returned %i\n", s);
		return 1;
	}
	return 0;
}

int do_test_seccomp_vow_open()
{
	struct exile_policy *policy = exile_init_policy();
	policy->vow_promises = EXILE_SYSCALL_VOW_STDIO | EXILE_SYSCALL_VOW_RPATH | EXILE_SYSCALL_VOW_DENY_ERROR;
	xexile_enable_policy(policy);

	int ret = open("/dev/urandom", O_WRONLY  | O_APPEND);
	if(ret != -1)
	{
		LOG("Failed: open was expected to fail, but returned %i\n", ret);
		return 1;
	}
	ret = open("/dev/urandom", O_RDWR);
	if(ret != -1)
	{
		LOG("Failed: open O_RDWR was expected to fail, but returned %i\n", ret);
		return 1;
	}
	ret = open("/dev/urandom", O_RDONLY);
	if(ret == -1)
	{
		LOG("Failed: open was expected to succceed, but returned %i\n", ret);
		return 1;
	}
	return 0;
}

int test_seccomp_vow()
{
	int ret = test_successful_exit(&do_test_seccomp_vow_open);
	if(ret != 0)
	{
		LOG("Failed: do_test_seccomp_vow_open()\n");
		return 1;
	}
	ret = test_successful_exit(&do_test_seccomp_vow_socket);
	if(ret != 0)
	{
		LOG("Failed: do_test_seccomp_vow_socket()\n");
		return 1;
	}
	return 0;
}

int test_seccomp_exile_vow_multiple()
{

	int ret = exile_vow(EXILE_SYSCALL_VOW_STDIO | EXILE_SYSCALL_VOW_UNIX | EXILE_SYSCALL_VOW_SECCOMP_INSTALL | EXILE_SYSCALL_VOW_DENY_ERROR);
	if(ret != 0)
	{
		LOG("Failed: exile_vow() call 1 failed\n");
		return 1;
	}
	int s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s == -1)
	{
		LOG("Failed: socket was expected to succeed, but returned %i\n", s);
		return 1;
	}

	/* Let's take away unix sockets, so it should not be possible anymore */
	ret = exile_vow(EXILE_SYSCALL_VOW_STDIO | EXILE_SYSCALL_VOW_SECCOMP_INSTALL | EXILE_SYSCALL_VOW_DENY_ERROR);
	if(ret != 0)
	{
		LOG("Failed: exile_vow() call 2 failed\n");
		return 1;
	}
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s != -1)
	{
		LOG("Failed: socket was expected to fail, but returned %i\n", s);
		return 1;
	}

	/* Let's try to regain unix sockets again */
	ret = exile_vow(EXILE_SYSCALL_VOW_STDIO | EXILE_SYSCALL_VOW_UNIX | EXILE_SYSCALL_VOW_SECCOMP_INSTALL | EXILE_SYSCALL_VOW_DENY_ERROR);
	if(ret != 0)
	{
		LOG("Failed: exile_vow() call 3 failed\n");
		return 1;
	}
	s = socket(AF_UNIX, SOCK_STREAM, 0);
	if(s != -1)
	{
		LOG("Failed: socket was still expected to fail, but returned %i\n", s);
		return 1;
	}

	return 0;
}


#if HAVE_LANDLOCK == 1
int test_landlock()
{
	if(!exile_landlock_is_available())
	{
		LOG("landlock not available, so cannot test\n");
		return 1;
	}
	struct exile_policy *policy = exile_init_policy();
	exile_append_path_policies(policy, EXILE_FS_ALLOW_ALL_READ, "/proc/self/fd");
	xexile_enable_policy(policy);

	int fd = open("/", O_RDONLY | O_CLOEXEC);
	if(fd < 0)
	{
		return 0;
	}
	return 1;
}

int test_landlock_deny_write()
{
	struct exile_policy *policy = exile_init_policy();
	exile_append_path_policies(policy, EXILE_FS_ALLOW_ALL_READ, "/tmp/");
	xexile_enable_policy(policy);

	int fd = open("/tmp/a", O_WRONLY | O_CLOEXEC);
	if(fd < 0)
	{
		return 0;
	}
	return 1;
}
#else
int test_landlock()
{
	return 2;
}

int test_landlock_deny_write()
{
	return 2;
}
#endif

int test_nofs()
{
	struct exile_policy *policy = exile_init_policy();
	policy->no_fs = 1;
	xexile_enable_policy(policy);

	int s = socket(AF_INET,SOCK_STREAM,0);
	if(s == -1)
	{
		LOG("Failed to open socket but this was not requested by policy\n");
		return 1;
	}

	/* Expect seccomp to take care of this */
	if(open("/test", O_CREAT | O_WRONLY) >= 0)
	{
		LOG("Failed: We do not expect write access\n");
		return 1;
	}

	return 0;
}


int test_no_new_fds()
{
	struct exile_policy *policy = exile_init_policy();
	policy->no_new_fds = 1;
	xexile_enable_policy(policy);

	if(open("/tmp/test", O_CREAT | O_WRONLY) >= 0)
	{
		LOG("Failed: Could open new file descriptor\n");
		return -1;
	}

	int s = socket(AF_INET,SOCK_STREAM,0);
	if(s >= 0)
	{
		LOG("Failed: socket got opened but policy denied\n");
		return -1;
	}

	return 0;

}

extern int mkpath(const char *p, mode_t mode, int baseisfile);
int test_mkpath()
{
	system("rm -rf /tmp/.exile.h/");
	const char *filepath = "/tmp/.exile.h/test_mkpath/some/sub/dir/file";
	const char *dirpath =  "/tmp/.exile.h/test_mkpath/some/other/sub/dir";
	int ret = mkpath(filepath,  0700, 1);
	if(ret != 0)
	{
		LOG("Failed: mkpath(file) returned: %i\n", ret);
		return 1;
	}
	ret = mkpath(dirpath, 0700, 0);
	if(ret != 0)
	{
		LOG("Failed: mkpath(dirpath) returned: %i\n", ret);
		return 1;
	}

	struct stat statbuf;
	ret = stat(filepath, &statbuf);
	if(ret != 0)
	{
		LOG("Failed: stat on filepath returned: %i\n", ret);
		return 1;
	}
	if(!S_ISREG(statbuf.st_mode))
	{
		LOG("Failed: mkpath did not create a file: %i\n", ret);
		return 1;
	}
	ret = stat(dirpath, &statbuf);
	if(ret != 0)
	{
		LOG("Failed: stat on dirpath returned: %i\n", ret);
		return 1;
	}
	if(!S_ISDIR(statbuf.st_mode))
	{
		LOG("Failed: mkpath did not create a directory: %i\n", ret);
		return 1;
	}
	system("rm -rf /tmp/.exile.h/");
	return 0;
}

int test_fail_flags()
{
	struct exile_policy *policy = exile_init_policy();
	exile_append_path_policies(policy, EXILE_FS_ALLOW_ALL_READ, "/nosuchpathexists");
	int ret = exile_enable_policy(policy);
	if(ret == 0)
	{
		fprintf(stderr, "Failed: A path that does not exist should have set the error flag %i\n", ret);
		return 1;
	}
	return 0;
}


static int *read_pipe = NULL;
int do_launch_test(void *arg)
{
	int num = *(int *)(arg);
	num += 1;
	char buffer[512] = { 0 };
	read(*read_pipe, buffer, sizeof(buffer)-1);
	printf("Sandboxed +1: %i\n", num);
	printf("Echoing: %s\n", buffer);
	fflush(stdout);
	return 0;
}

int test_launch()
{
	struct exile_policy *policy = exile_init_policy();
	struct exile_launch_params params = { 0 };
	struct exile_launch_result res = {0};
	int num = 22;
	params.func = &do_launch_test;
	params.funcarg = &num;
	params.policy = policy;
	read_pipe = &params.child_write_pipe[0];
	int launchfd = exile_launch(&params, &res);
	if(launchfd < 0)
	{
		LOG("Failed to launch\n");
		return 1;
	}

	char buffer[4096] = { 0 };
	write(res.write_fd, "1234", 4);
	int s = read(res.read_fd, buffer, sizeof(buffer)-1);
	write(1, buffer, s);
	LOG("Before wait, got: %i\n", s);
	fflush(stdout);
	if(strstr(buffer, "Echoing: 1234") == NULL)
	{
		LOG("Failed: Did not get back what we wrote\n");
	}
	int status = 0;
	waitpid(res.tid, &status, __WALL);
	if(WIFEXITED(status))
	{
		status = WEXITSTATUS(status);
		return status;
	}
	return 1;

}

#define LAUNCH_GET_TEST_STR "Control yourself. Take only what you need from it.\n"
int do_launch_get_test(void *a)
{
	fprintf(stdout, LAUNCH_GET_TEST_STR);
	return 0;
}

int test_launch_get()
{
	struct exile_policy *policy = exile_init_policy();
	struct exile_launch_params params = { 0 };
	params.func = &do_launch_get_test;
	params.funcarg = NULL;
	params.policy = policy;

	size_t n = 0;
	char *content = exile_launch_get(&params, &n);
	unsigned int len = strlen(LAUNCH_GET_TEST_STR);
	if(n != len)
	{
		LOG("Lenght does not match: %lu vs %u\n", n, len);
		return 1;
	}
	if(strcmp(content, LAUNCH_GET_TEST_STR) != 0)
	{
		LOG("Received content differs\n");
		return 1;
	}
	return 0;
}

int test_vows_from_str()
{
	uint64_t expected = EXILE_SYSCALL_VOW_CHOWN | EXILE_SYSCALL_VOW_WPATH | EXILE_SYSCALL_VOW_INET | EXILE_SYSCALL_VOW_DENY_ERROR;
	uint64_t actual = exile_vows_from_str("chown wpath inet error");
	if(expected != actual)
	{
		LOG("Masks don't match: %lu vs %lu\n", expected, actual);
		return 1;
	}
	return 0;
}

int test_clone3_nosys()
{
	struct exile_policy *policy = exile_init_policy();
	policy->vow_promises = exile_vows_from_str("stdio rpath wpath cpath thread error");

	exile_enable_policy(policy);
	/* While args are invalid, it should never reach clone3 syscall handler, so it's irrelevant for
	 our test*/
	long ret =  syscall(__NR_clone3, NULL, 0);

	if(ret == -1 && errno != ENOSYS)
	{
		LOG("clone3() was not allowed but did not return ENOSYS. It returned: %li, errno: %i\n", ret, errno);
		return 1;
	}
	return 0;
}

int do_test_nsuidmap(const char *path,  const char *firstfield, const char *secondfield, const char *thirdfield)
{
	char *line = NULL;
	size_t n = 0;
	FILE *fp = fopen(path, "r");

	int ret = getdelim(&line, &n, ' ', fp);
	while(ret != -1 && strlen(line) == 1 && *line == ' ')
		ret = getdelim(&line, &n, ' ', fp);
	if(ret == -1)
	{
		LOG("getdelim() failed to read a line from %s\n", path);
		return 1;
	}
	line[ret-1] = '\0';
	if(strcmp(line, firstfield) != 0)
	{
		LOG("Invalid value for first entry in map: Expected: %s, was: %s\n", firstfield, line);
		return 1;
	}

	ret = getdelim(&line, &n, ' ', fp);
	while(ret != -1 && strlen(line) == 1 && *line == ' ')
		ret = getdelim(&line, &n, ' ', fp);
	if(ret == -1)
	{
		LOG("getdelim() failed to read a line from map\n");
		return 1;
	}
	line[ret-1] = '\0';

	if(strcmp(line, secondfield) != 0)
	{
		LOG("Invalid value for second entry in map: Expected: %s, was: %s\n", secondfield, line);
		return 1;
	}


	ret = getdelim(&line, &n, ' ', fp);
	while(ret != -1 && strlen(line) == 1 && *line == ' ')
		ret = getdelim(&line, &n, ' ', fp);
	if(ret == -1)
	{
		LOG("getdelim() failed to read a line from uid_map\n");
		return 1;
	}
	line[ret-1] = '\0';
	if(strcmp(line, thirdfield) != 0)
	{
		LOG("Invalid value for second entry in map: Expected: %s, was: %s\n", thirdfield, line);
		return 1;
	}

	fclose(fp);
	return 0;
}

int test_unshare_user()
{
	char uidstr[64];
	snprintf(uidstr, sizeof(uidstr), "%u", getuid());

	char gidstr[64];
	snprintf(gidstr, sizeof(gidstr), "%u", getgid());

	struct exile_policy *policy = exile_init_policy();
	policy->namespace_options = EXILE_UNSHARE_USER;
	xexile_enable_policy(policy);

	if(do_test_nsuidmap("/proc/self/uid_map", "0", uidstr, "1") != 0)
	{
		LOG("/proc/self/uid_map failed\n");
		return 1;
	}

	if(do_test_nsuidmap("/proc/self/gid_map", "0", gidstr, "1") != 0)
	{
		LOG("/proc/self/gid_map failed\n");
		return 1;
	}

	FILE *fp = fopen("/proc/self/setgroups", "r");

	char buffer[4096] = { 0 };
	fread(buffer, sizeof(buffer), 1, fp);
	fclose(fp);

	if(strcmp(buffer, "deny\n") != 0)
	{
		LOG("/proc/self/setgroups does not contain 'deny'\n");
		return 1;
	}

	return 0;


}

struct dispatcher
{
	char *name;
	int (*f)();
};

struct dispatcher dispatchers[] = {
	{ "default", &test_default_main },
	{ "seccomp-blacklisted", &test_seccomp_blacklisted},
	{ "seccomp-blacklisted-permitted", &test_seccomp_blacklisted_call_permitted},
	{ "seccomp-x32-kill", &test_seccomp_x32_kill},
	{ "seccomp-require-last-matchall", &test_seccomp_require_last_matchall},
	{ "seccomp-errno", &test_seccomp_errno},
	{ "seccomp-argfilter-allowed", &test_seccomp_argfilter_allowed},
	{ "seccomp-argfilter-filtered", &test_seccomp_argfilter_filtered},
	{ "seccomp-argfilter-mixed", &test_seccomp_argfilter_mixed},
	{ "seccomp-vow", &test_seccomp_vow},
	{ "seccomp-vow-exile_vow-multi", &test_seccomp_exile_vow_multiple},
	{ "landlock", &test_landlock},
	{ "landlock-deny-write", &test_landlock_deny_write },
	{ "no_fs", &test_nofs},
	{ "no_new_fds", &test_no_new_fds},
	{ "mkpath", &test_mkpath},
	{ "failflags", &test_fail_flags},
	{ "launch", &test_launch},
	{ "launch-get", &test_launch_get},
	{ "vow_from_str", &test_vows_from_str},
	{ "clone3_nosys", &test_clone3_nosys},
	{ "unshare-user", &test_unshare_user},

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
			printf("%s\n", dispatchers[i].name);
		}
		return EXIT_SUCCESS;
	}

	for(unsigned int i = 0; i < sizeof(dispatchers)/sizeof(dispatchers[0]); i++)
	{
		struct dispatcher *current = &dispatchers[i];
		if(strcmp(current->name, test) == 0)
		{
			return current->f();
		}
	}
	fprintf(stderr, "Unknown test\n");
	return EXIT_FAILURE;
}
