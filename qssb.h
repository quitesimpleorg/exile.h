/*
 * Copyright (c) 2021 Albert S. <mail at quitesimple dot org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef QSSB_H
#define QSSB_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <stdio.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <sys/capability.h>
#include <stddef.h>
#include <inttypes.h>
#include <asm/unistd.h>

#ifndef HAVE_LANDLOCK
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
		/* TODO: Hopefully a fair assumption. But we need to runtime checks */
		#define HAVE_LANDLOCK 1
	#endif
#endif
#if HAVE_LANDLOCK == 1
	#include <linux/landlock.h>
	#if LANDLOCK_CREATE_RULESET_VERSION != (1U << 0)
		#error "This landlock ABI version is not supported by qssb (yet)"
	#endif
#endif

//TODO: stolen from kernel samples/seccomp, GPLv2...?
#define ALLOW \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)
#define DENY \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)
#define SYSCALL(nr, jt) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (nr), 0, 1), jt

#define LOAD_SYSCALL_NR \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, \
		 offsetof(struct seccomp_data, nr))

#define QSSB_UNSHARE_NETWORK 1<<1
#define QSSB_UNSHARE_USER 1<<2
#define QSSB_UNSHARE_MOUNT 1<<3

#ifndef QSSB_LOG_ERROR
#define QSSB_LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef QSSB_TEMP_DIR
#define QSSB_TEMP_DIR "/tmp"
#endif

#define QSSB_SYS(x)		(__NR_##x)

#define QSSB_FS_ALLOW_READ 1<<0
#define QSSB_FS_ALLOW_WRITE (1<<1)
#define QSSB_FS_ALLOW_EXEC 1<<2
#define QSSB_FS_ALLOW_DEV 1<<3
#define QSSB_FS_ALLOW_SETUID 1<<4
//don't mount recursive
#define QSSB_MOUNT_NOT_REC 1<<5

#if HAVE_LANDLOCK == 1
#define QSSB_FS_ALLOW_REMOVE_DIR		(1 << 7)
#define QSSB_FS_ALLOW_REMOVE_FILE		(1 << 8)
#define QSSB_FS_ALLOW_MAKE_CHAR			(1 << 9)
#define QSSB_FS_ALLOW_MAKE_DIR			(1 << 10)
#define QSSB_FS_ALLOW_MAKE_REG			(1 << 11)
#define QSSB_FS_ALLOW_MAKE_SOCK			(1 << 12)
#define QSSB_FS_ALLOW_MAKE_FIFO			(1 << 13)
#define QSSB_FS_ALLOW_MAKE_BLOCK		(1 << 14)
#define QSSB_FS_ALLOW_MAKE_SYM			(1 << 15)
#define QSSB_FS_ALLOW_WRITE_FILE 		(1 << 16)
#define QSSB_FS_ALLOW_READ_DIR			(1 << 17)
#define QSSB_FS_ALLOW_REMOVE 			(1 << 18)

#ifndef landlock_create_ruleset
static inline int landlock_create_ruleset(
		const struct landlock_ruleset_attr *const attr,
		const size_t size, const __u32 flags)
{
	return syscall(__NR_landlock_create_ruleset, attr, size, flags);
}
#endif

#ifndef landlock_add_rule
static inline int landlock_add_rule(const int ruleset_fd,
		const enum landlock_rule_type rule_type,
		const void *const rule_attr, const __u32 flags)
{
	return syscall(__NR_landlock_add_rule, ruleset_fd, rule_type,
			rule_attr, flags);
}
#endif

#ifndef landlock_restrict_self
static inline int landlock_restrict_self(const int ruleset_fd,
		const __u32 flags)
{
	return syscall(__NR_landlock_restrict_self, ruleset_fd, flags);
}
#endif
#endif

/* Most exploits have more need for those syscalls than the
 * exploited programs. In cases they are needed, this list should be
 * filtered or simply not used.
 */
 /* TODO: more execv* in some architectures */
 /* TODO: add more */
static int default_blacklisted_syscals[] = {
	QSSB_SYS(setuid),
	QSSB_SYS(setgid),
	QSSB_SYS(chroot),
	QSSB_SYS(pivot_root),
	QSSB_SYS(mount),
	QSSB_SYS(setns),
	QSSB_SYS(unshare),
	QSSB_SYS(ptrace),
	QSSB_SYS(personality),
	QSSB_SYS(execve),
	QSSB_SYS(process_vm_readv),
	QSSB_SYS(process_vm_writev),
	QSSB_SYS(userfaultfd),
	QSSB_SYS(init_module),
	QSSB_SYS(finit_module),
	QSSB_SYS(delete_module),
};

/* TODO: Check for completion
 * Known blacklisting problem (catch up game, etc.)
 *
 * However, we use it to enhance "no_fs" policy, which does not solely rely
 * on seccomp anyway */
static int fs_access_syscalls[] = {
	QSSB_SYS(chdir),
	QSSB_SYS(truncate),
	QSSB_SYS(stat),
	QSSB_SYS(flock),
	QSSB_SYS(chmod),
	QSSB_SYS(chown),
	QSSB_SYS(setxattr),
	QSSB_SYS(utime),
	QSSB_SYS(ioctl),
	QSSB_SYS(fcntl),
	QSSB_SYS(access),
	QSSB_SYS(open),
	QSSB_SYS(openat),
	QSSB_SYS(unlink),
};

struct qssb_path_policy
{
	const char *path;
	unsigned int policy;
	struct qssb_path_policy *next;
};

struct qssb_allocated_entry
{
	void *data; /* the actual data */
	size_t size; /* number of bytes allocated for size */
	size_t used; /* number of bytes in use */
};

/* Number of bytes to grow the buffer in qssb_allocated_entry  with */
#define QSSB_ENTRY_ALLOC_SIZE 32


/* Policy tells qssb what to do */
struct qssb_policy
{
	int drop_caps;
	int preserve_cwd;
	int not_dumpable;
	int no_new_privs;
	int no_fs;
	int no_new_fds;
	int namespace_options;
	/* Bind mounts all paths in path_policies into the chroot and applies
	 non-landlock policies */
	int mount_path_policies_to_chroot;
	char chroot_target_path[PATH_MAX];
	const char *chdir_path;

	/* Do not manually add policies here, use qssb_append_path_polic*() */
	struct qssb_path_policy *path_policies;
	struct qssb_path_policy **path_policies_tail;

	/* Do not manually add entries here, use qssb_append_denied_syscall() etc. */
	struct qssb_allocated_entry denied_syscalls;
	struct qssb_allocated_entry allowed_syscalls;

};

static int qssb_entry_append(struct qssb_allocated_entry *entry, void *data, size_t bytes)
{
	size_t remaining = entry->size - entry->used;
	if(remaining < bytes)
	{
		size_t expandval = QSSB_ENTRY_ALLOC_SIZE > bytes ? QSSB_ENTRY_ALLOC_SIZE : bytes;
		size_t sizenew = entry->size + expandval;
		int *datanew = (int *) realloc(entry->data, sizenew);
		if(datanew == NULL)
		{
			QSSB_LOG_ERROR("failed to resize array: %s\n", strerror(errno));
			return -1;
		}
		entry->size = sizenew;
		entry->data = datanew;
	}
	uint8_t *target = (uint8_t *) entry->data;
	memcpy(target + entry->used, data, bytes);
	entry->used = entry->used + bytes;
	return 0;
}

static int qssb_append_syscall(struct qssb_allocated_entry *entry, int *syscalls, size_t n)
{
	return qssb_entry_append(entry, syscalls, n * sizeof(int));
}


int qssb_append_denied_syscall(struct qssb_policy *qssb_policy, int syscall)
{
	return qssb_append_syscall(&qssb_policy->denied_syscalls, &syscall, 1);
}

int qssb_append_allowed_syscall(struct qssb_policy *qssb_policy, int syscall)
{
	return qssb_append_syscall(&qssb_policy->allowed_syscalls, &syscall, 1);
}

int qssb_append_allowed_syscalls(struct qssb_policy *qssb_policy, int *syscalls, size_t n)
{

	return qssb_append_syscall(&qssb_policy->allowed_syscalls, syscalls, n);
}

int qssb_append_denied_syscalls(struct qssb_policy *qssb_policy, int *syscalls, size_t n)
{

	return qssb_append_syscall(&qssb_policy->denied_syscalls, syscalls, n);
}

/* Creates the default policy
 * Must be freed using qssb_free_policy
 * @returns: default policy */
struct qssb_policy *qssb_init_policy()
{
	struct qssb_policy *result = (struct qssb_policy *) calloc(1, sizeof(struct qssb_policy));
	result->drop_caps = 1;
	result->not_dumpable = 1;
	result->no_new_privs = 1;
	result->no_fs = 0;
	result->no_new_fds = 0;
	result->namespace_options = QSSB_UNSHARE_MOUNT | QSSB_UNSHARE_USER;
	result->chdir_path = NULL;
	result->mount_path_policies_to_chroot = 0;
	result->chroot_target_path[0] = '\0';
	result->path_policies = NULL;
	result->path_policies_tail = &(result->path_policies);
	result->allowed_syscalls.data = NULL;
	result->allowed_syscalls.size = 0;
	result->allowed_syscalls.used = 0;
	result->denied_syscalls.data = NULL;
	result->denied_syscalls.size = 0;
	result->denied_syscalls.used = 0;

	size_t blacklisted_syscalls_count = sizeof(default_blacklisted_syscals)/sizeof(default_blacklisted_syscals[0]);

	int appendresult = qssb_append_denied_syscalls(result, default_blacklisted_syscals, blacklisted_syscalls_count);
	if(appendresult != 0)
	{
		return NULL;
	}
	return result;
}

/* Appends path policies to the qssb_policy object
 * The last paramater must be NULL
 *
 * This function does not copy parameters. All passed paths
 * MUST NOT be freed until qssb_enable_policy() is called!
 *
 * @returns: 0 on success, -1 on failure */
int qssb_append_path_policies(struct qssb_policy *qssb_policy, unsigned int path_policy, ...)
{
	va_list args;
	const char *path;
	va_start(args, path_policy);

	path = va_arg(args, char*);
	while(path != NULL)
	{
		struct qssb_path_policy *newpolicy = (struct qssb_path_policy *) calloc(1, sizeof(struct qssb_path_policy));
		if(newpolicy == NULL)
		{
			QSSB_LOG_ERROR("Failed to allocate memory for path policy\n");
			return -1;
		}
		newpolicy->path = path;
		newpolicy->policy = path_policy;
		newpolicy->next = NULL;

		*(qssb_policy->path_policies_tail) = newpolicy;
		qssb_policy->path_policies_tail = &(newpolicy->next);
		path = va_arg(args, char*);
	}

	va_end(args);

	return 0;
}

int qssb_append_path_policy(struct qssb_policy *qssb_policy, unsigned int path_policy, const char *path)
{
	return qssb_append_path_policies(qssb_policy, path_policy, path, NULL);
}

/*
 * Fills buffer with random characters a-z.
 * The string will be null terminated.
 *
 * @returns: number of written chars (excluding terminating null byte) on success
 */
int random_string(char *buffer, size_t buffer_length)
{
	int r = getrandom(buffer, buffer_length-1, GRND_NONBLOCK);
	if(r != -1 && (size_t) r == buffer_length-1)
	{
		int i = 0;
		while(i < r)
		{
			buffer[i] = 'a' + ((unsigned int)buffer[i] % 26);
			++i;
		}
		buffer[buffer_length-1] = '\0';
		return i;
	}
	return 0;
}


/* Creates a directory and all necessary parent directories
 *
 * @returns: 0 on success, -ERRNO on failure
 * */
static int mkdir_structure(const char *p, mode_t mode)
{
	char path[PATH_MAX] = { 0 };
	int res = snprintf(path, sizeof(path), "%s/", p);
	if(res < 0)
	{
		QSSB_LOG_ERROR("qssb: mkdir_strucutre: error during path concatination\n");
		return -EINVAL;
	}
	if(res >= PATH_MAX)
	{
		QSSB_LOG_ERROR("qssb: mkdir_structure: path concatination truncated\n");
		return -EINVAL;
	}


	char *begin = path;
	char *end = begin+1;

	while(*end)
	{
		if(*end == '/')
		{
			*end = 0;
			if(mkdir(begin, mode) < 0)
			{
				if(errno == EEXIST)
				{
					//TODO: stat, test if it is a directory, if not, err
				}
				else
				{
					QSSB_LOG_ERROR("Failed to create directory for chroot: %s\n", begin);
					return -1;
				}
			}
			*end = '/';
			++end;
			while(*end == '/')
			{
				++end;
			}
		}
		else
		{
			++end;
		}
	}
	return 0;
}

/* @returns: argument for mount(2) flags */
static int get_policy_mount_flags(struct qssb_path_policy *policy)
{
	int result = 0;

	if( (policy->policy & QSSB_FS_ALLOW_DEV) == 0)
	{
		result |= MS_NODEV;
	}

	if( (policy->policy & QSSB_FS_ALLOW_EXEC) == 0)
	{
		result |= MS_NOEXEC;
	}

	if( (policy->policy & QSSB_FS_ALLOW_SETUID) == 0)
	{
		result |= MS_NOSUID;
	}

	if( (policy->policy & QSSB_FS_ALLOW_WRITE) == 0)
	{
		result |= MS_RDONLY;
	}

	if( (policy->policy & QSSB_MOUNT_NOT_REC) == 0)
	{
		result |= MS_REC;
	}
	return result;
}

/* Helper to mount directories into the chroot path "chroot_target_path"
 * Paths will be created if necessary

 * @returns: 0 on sucess, -ERRNO on failure */
static int mount_to_chroot(const char *chroot_target_path, struct qssb_path_policy *path_policy)
{
	while(path_policy != NULL)
	{

		char path_inside_chroot[PATH_MAX];
		int written = snprintf(path_inside_chroot, sizeof(path_inside_chroot), "%s/%s", chroot_target_path, path_policy->path);
		if(written < 0)
		{
			QSSB_LOG_ERROR("qssb: mount_to_chroot: Error during path concatination\n");
			return -EINVAL;
		}
		if(written >= PATH_MAX)
		{
			QSSB_LOG_ERROR("qssb: mount_to_chroot: path concatination truncated\n");
			return -EINVAL;
		}
		int ret = mkdir_structure(path_inside_chroot, 0700);
		if(ret < 0)
		{
			QSSB_LOG_ERROR("Error creating directory structure while mounting paths to chroot. %s\n", strerror(errno));
			return ret;
		}

		int mount_flags = get_policy_mount_flags(path_policy);

		//all we do is bind mounts
		mount_flags |= MS_BIND;


		if(path_policy->policy & QSSB_FS_ALLOW_READ || path_policy->policy & QSSB_FS_ALLOW_WRITE)
		{
			ret = mount(path_policy->path, path_inside_chroot,  NULL, mount_flags, NULL);
			if(ret < 0 )
			{
				QSSB_LOG_ERROR("Error: Failed to mount %s to %s: %s\n", path_policy->path, path_inside_chroot, strerror(errno));
				return ret;
			}

			//remount so noexec, readonly etc. take effect
			ret = mount(NULL, path_inside_chroot, NULL, mount_flags | MS_REMOUNT, NULL);
			if(ret < 0 )
			{
				QSSB_LOG_ERROR("Error: Failed to remount %s: %s", path_inside_chroot, strerror(errno));
				return ret;
			}
		}
		path_policy = path_policy->next;
	}

	return 0;
}

/*
 * Frees the memory taken by a qssb_policy object
 */
void qssb_free_policy(struct qssb_policy *ctxt)
{
	if(ctxt != NULL)
	{
		struct qssb_path_policy *current = ctxt->path_policies;
		while(current != NULL)
		{
			struct qssb_path_policy *tmp = current;
			current = current->next;
			free(tmp);
		}
		free(ctxt);
	}
}

/* Enters the specified namespaces */
static int enter_namespaces(int namespace_options)
{
	if(namespace_options & QSSB_UNSHARE_USER)
	{
		int ret = unshare(CLONE_NEWUSER);
		if(ret == -1)
		{
			QSSB_LOG_ERROR("Error: Failed to unshare user namespaces: %s\n", strerror(errno));
			return ret;
		}

		uid_t current_uid = getuid();
		gid_t current_gid = getgid();

		//TODO: check errors
		FILE *fp = fopen("/proc/self/setgroups", "w");
		fprintf(fp, "deny");
		fclose(fp);

		fp = fopen("/proc/self/uid_map", "w");
		fprintf(fp, "0 %i", current_uid);
		fclose(fp);

		fp = fopen("/proc/self/gid_map", "w");
		fprintf(fp, "0 %i", current_gid);
		fclose(fp);
	}

	if(namespace_options & QSSB_UNSHARE_MOUNT)
	{
		int ret = unshare(CLONE_NEWNS);
		if(ret == -1)
		{
			QSSB_LOG_ERROR("Error: Failed to unshare mount namespaces: %s\n", strerror(errno));
			return ret;
		}
	}

	if(namespace_options & QSSB_UNSHARE_NETWORK)
	{
		int ret = unshare(CLONE_NEWNET);
		if(ret == -1)
		{
			QSSB_LOG_ERROR("Error: Failed to unshare network namespace: %s\n", strerror(errno));
			return ret;
		}
	}

	return 0;
}

/* Drops all capabiltiies held by the process
 *
 * @returns: 0 on sucess, -1 on error
*/
static int drop_caps()
{
	int cap = 0;
	int res = 0;
	while((res = prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)) == 0)
	{
		++cap;
	}

	if(res == -1 && errno != EINVAL)
	{
		QSSB_LOG_ERROR("Failed to drop the capability bounding set!");
		return -errno;
	}

	//TODO: systems that are not 64 bit
	struct __user_cap_header_struct h = { 0 };
	h.pid = 0;
	h.version = _LINUX_CAPABILITY_VERSION_3;
	struct __user_cap_data_struct drop[2];
	drop[0].effective = 0;
	drop[0].permitted = 0;
	drop[0].inheritable = 0;
	drop[1].effective = 0;
	drop[1].permitted = 0;
	drop[1].inheritable = 0;
	if(capset(&h, drop) == -1)
	{
		QSSB_LOG_ERROR("Failed to drop capabilities: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}

/*
 * Enables the per_syscall seccomp action for system calls
 *
 * syscalls: array of system calls numbers.
 * per_syscall: action to apply for each system call
 * default_action: the default action at the end
 *
 * @returns: 0 on success, -1 on error
 */
static int seccomp_enable(int *syscalls, size_t n, unsigned int per_syscall, unsigned int default_action)
{
	struct sock_filter filter[1024] =
	{
		LOAD_SYSCALL_NR,
	};

	unsigned short int current_filter_index = 1;
	for(size_t i = 0; i < n; i++)
	{
		unsigned int sysc = (unsigned int) syscalls[i];
		struct sock_filter syscall = BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysc, 0, 1);
		struct sock_filter action = BPF_STMT(BPF_RET+BPF_K, per_syscall);
		filter[current_filter_index++] = syscall;
		filter[current_filter_index++] = action;
	}

	struct sock_filter da = BPF_STMT(BPF_RET+BPF_K, default_action);
	filter[current_filter_index] = da;

	++current_filter_index;
	struct sock_fprog prog = {
		.len = current_filter_index ,
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
	{
		QSSB_LOG_ERROR("prctl SET_SECCOMP %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

/*
 * Blacklists the specified systemcalls.
 *
 * syscalls: array of system calls numbers.
 */
static int seccomp_enable_blacklist(int *syscalls, size_t n)
{
	return seccomp_enable(syscalls, n, SECCOMP_RET_KILL, SECCOMP_RET_ALLOW);
}

/*
 * Whitelists the specified systemcalls.
 *
 * syscalls: array of system calls numbers.
 */
static int seccomp_enable_whitelist(int *syscalls, size_t n)
{
	return seccomp_enable(syscalls, n, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL);
}

#if HAVE_LANDLOCK == 1
static unsigned int qssb_flags_to_landlock(unsigned int flags)
{
	unsigned int result = 0;
	if(flags & QSSB_FS_ALLOW_DEV)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
		result |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_BLOCK)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_CHAR)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_DIR;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_FIFO)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_REG)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_REG;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_SOCK)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
	}
	if(flags & QSSB_FS_ALLOW_MAKE_SYM)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_SYM;
	}
	if(flags & QSSB_FS_ALLOW_READ)
	{
		result |= LANDLOCK_ACCESS_FS_READ_FILE;
		result |= LANDLOCK_ACCESS_FS_READ_DIR;
	}
	if(flags & QSSB_FS_ALLOW_REMOVE)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
		result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
	}
	if(flags & QSSB_FS_ALLOW_REMOVE_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
	}
	if(flags & QSSB_FS_ALLOW_REMOVE_FILE)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
	}
	if(flags & QSSB_FS_ALLOW_EXEC)
	{
		result |= LANDLOCK_ACCESS_FS_EXECUTE;
	}
	if(flags & QSSB_FS_ALLOW_WRITE)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_REG;
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	}
	if(flags & QSSB_FS_ALLOW_WRITE_FILE)
	{
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	}
	if(flags & QSSB_FS_ALLOW_READ_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_READ_DIR;
	}
	return result;
}

static int landlock_prepare_ruleset(struct qssb_path_policy *policies)
{
	int ruleset_fd = -1;
	struct landlock_ruleset_attr ruleset_attr;
	/* We here want the maximum possible ruleset, so set the var to the max possible bitmask.
	   Stolen/Adapted from: [linux src]/security/landlock/limits.h
	*/
	ruleset_attr.handled_access_fs = ((LANDLOCK_ACCESS_FS_MAKE_SYM << 1) - 1);

	ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0)
	{
		QSSB_LOG_ERROR("Failed to create landlock ruleset");
		return -1;
	}
	struct qssb_path_policy *policy = policies;
	while(policy != NULL)
	{
		struct landlock_path_beneath_attr path_beneath;
		path_beneath.parent_fd = open(policy->path, O_PATH | O_CLOEXEC);
		if(path_beneath.parent_fd < 0)
		{
			QSSB_LOG_ERROR("Failed to open policy path %s while preparing landlock ruleset\n", policy->path);
			close(ruleset_fd);
			return path_beneath.parent_fd;
		}
		path_beneath.allowed_access = qssb_flags_to_landlock(policy->policy);
		int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
		if(ret)
		{
			QSSB_LOG_ERROR("Failed to update ruleset while processsing policy path %s\n", policy->path);
			close(ruleset_fd);
			return ret;
		}
		policy = policy->next;
	}
	return ruleset_fd;
}
#endif


/* Checks for illogical or dangerous combinations */
static int check_policy_sanity(struct qssb_policy *policy)
{
	if(policy->denied_syscalls.used > 0 && policy->allowed_syscalls.used > 0)
	{
		QSSB_LOG_ERROR("Error: Cannot mix allowed and denied systemcalls in policy\n");
		return -EINVAL;
	}

	if(policy->mount_path_policies_to_chroot == 1)
	{
		if(policy->path_policies == NULL)
		{
			QSSB_LOG_ERROR("Cannot mount path policies to chroot if non are given\n");
			return -1;
		}
		if(!(policy->namespace_options & QSSB_UNSHARE_MOUNT))
		{
			QSSB_LOG_ERROR("mount_path_policies_to_chroot = 1 requires unsharing mount namespace\n");
			return -1;
		}
	}

	if(policy->no_new_privs != 1)
	{
		if(policy->allowed_syscalls.used > 0 || policy->denied_syscalls.used > 0)
		{
			QSSB_LOG_ERROR("no_new_privs = 1 is required for seccomp filtering!\n");
			return -1;
		}
	}

	if(policy->path_policies != NULL)
	{

		if(policy->mount_path_policies_to_chroot != 1)
		{
			#if HAVE_LANDLOCK != 1
				QSSB_LOG_ERROR("Path policies cannot be enforced! System needs landlock support or set mount_path_policies_to_chroot = 1\n");
				return -1;
			#endif
		}
		if(policy->no_fs == 1)
		{
			QSSB_LOG_ERROR("If path_policies are specified, no_fs cannot be set to 1");
			return -1;
		}
	}
	return 0;
}

static void close_file_fds()
{
	long max_files = sysconf(_SC_OPEN_MAX);
	for(long i = 3; i <= max_files; i++)
	{
		close((int)i);
	}
}

/* Takes away file system access from the process
 *
 * We use this when "no_fs" is given in the policy.
 *
 * This is useful for restricted subprocesses that do some computational work
 * and do not require filesystem access
 *
 * @returns: 0 on success, < 0 on error
 */
static int enable_no_fs(struct qssb_policy *policy)
{
		close_file_fds();

		if(chdir("/proc/self/fdinfo") != 0)
		{
			QSSB_LOG_ERROR("Failed to change to safe directory: %s\n", strerror(errno));
			return -1;
		}

		if(chroot(".") != 0)
		{
			QSSB_LOG_ERROR("Failed to chroot into safe directory: %s\n", strerror(errno));
			return -1;
		}

		if(chdir("/") != 0)
		{
			QSSB_LOG_ERROR("Failed to chdir into safe directory inside chroot: %s\n", strerror(errno));
			return -1;
		}

		if(policy->allowed_syscalls.used == 0)
		{
			size_t fs_access_syscalls_count = sizeof(fs_access_syscalls)/sizeof(fs_access_syscalls[0]);

			int ret = qssb_append_denied_syscalls(policy, fs_access_syscalls, fs_access_syscalls_count);
			if(ret != 0)
			{
				QSSB_LOG_ERROR("Failed to add system calls to blacklist\n");
				return -1;
			}
		}
		return 0;
}

/* Enables the specified qssb_policy.
 *
 * This function is not atomic (and can't be). This means some
 * policies can apply, while others may fail.
 *
 * This function returns success only if all policies applied.
 *
 * The state is undefined if this function fails. The process generally
 * should exit.
 *
 * @returns: 0 on success (all policies applied), < 0 on error (none or some policies dit not apply)
 */
int qssb_enable_policy(struct qssb_policy *policy)
{
	if(check_policy_sanity(policy) != 0)
	{
		QSSB_LOG_ERROR("Error: Policy sanity check failed. Cannot apply policy!\n");
		return -EINVAL;
	}

	if(enter_namespaces(policy->namespace_options) < 0)
	{
		QSSB_LOG_ERROR("Error while trying to enter namespaces\n");
		return -1;
	}

	if(policy->mount_path_policies_to_chroot && policy->path_policies != NULL)
	{
		if(*policy->chroot_target_path == '\0')
		{
			char random_str[17];
			if(random_string(random_str, sizeof(random_str)) == 16)
			{
				int res = snprintf(policy->chroot_target_path, sizeof(policy->chroot_target_path), "%s/.sandbox_%" PRIdMAX "_%s", QSSB_TEMP_DIR, (intmax_t)getpid(), random_str);
				if(res < 0)
				{
					QSSB_LOG_ERROR("qssb: qssb_enable_policy: error during path concatination\n");
					return -EINVAL;
				}
				if(res >= PATH_MAX)
				{
					QSSB_LOG_ERROR("qssb: qssb_enable_policy: path concatination truncated\n");
					return -EINVAL;
				}
			}
			else
			{
				QSSB_LOG_ERROR("Error creating random sandbox directory name\n");
				return -1;
			}
		}

		if(mount_to_chroot(policy->chroot_target_path, policy->path_policies) < 0)
		{
			QSSB_LOG_ERROR("mount_to_chroot: bind mounting of path policies failed\n");
			return -1;
		}
	}

	if(*policy->chroot_target_path != '\0')
	{
		if(chroot(policy->chroot_target_path) < 0)
		{
			QSSB_LOG_ERROR("chroot: failed to enter %s\n", policy->chroot_target_path);
			return -1;
		}
	}

#if HAVE_LANDLOCK == 1
	int landlock_ruleset_fd = -1;
	if(policy->path_policies != NULL)
	{
		landlock_ruleset_fd = landlock_prepare_ruleset(policy->path_policies);
		if(landlock_ruleset_fd < 0)
		{
			QSSB_LOG_ERROR("landlock_prepare_ruleset: Failed to prepare landlock ruleset: %s\n", strerror(errno));
			return -1;
		}
	}
#endif
	if(policy->chdir_path == NULL)
	{
		policy->chdir_path = "/";
	}

	if(policy->chdir_path != NULL && chdir(policy->chdir_path) < 0)
	{
		QSSB_LOG_ERROR("chdir to %s failed\n", policy->chdir_path);
		return -1;
	}

	if(policy->no_fs)
	{
		if(enable_no_fs(policy) != 0)
		{
			QSSB_LOG_ERROR("Failed to take away filesystem access of process\n");
			return -1;
		}
	}

	if(policy->no_new_fds)
	{
		const struct rlimit nofile = {0, 0};
		if (setrlimit(RLIMIT_NOFILE, &nofile) == -1)
		{
			QSSB_LOG_ERROR("setrlimit: Failed to set rlimit: %s\n", strerror(errno));
			return -1;
		}
	}

	if(policy->drop_caps)
	{
		if(drop_caps() < 0)
		{
			QSSB_LOG_ERROR("failed to drop capabilities\n");
			return -1;
		}
	}

	if(policy->not_dumpable)
	{
		if(prctl(PR_SET_DUMPABLE, 0) == -1)
		{
			QSSB_LOG_ERROR("prctl: PR_SET_DUMPABLE failed\n");
			return -1;
		}
	}

	if(policy->no_new_privs)
	{
		if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		{
			QSSB_LOG_ERROR("prctl: PR_SET_NO_NEW_PRIVS failed: %s\n", strerror(errno));
			return -1;
		}
	}

#if HAVE_LANDLOCK == 1
	if (policy->path_policies != NULL && landlock_restrict_self(landlock_ruleset_fd, 0) != 0)
	{
		perror("Failed to enforce ruleset");
		close(landlock_ruleset_fd);
		return -1;
	}
	close(landlock_ruleset_fd);
#endif

	if(policy->allowed_syscalls.used > 0)
	{
		int *syscalls = (int *)policy->allowed_syscalls.data;
		size_t n = policy->allowed_syscalls.used / sizeof(int);
		if(seccomp_enable_whitelist(syscalls, n) < 0)
		{
			QSSB_LOG_ERROR("seccomp_enable_whitelist failed\n");
			return -1;
		}
	}

	if(policy->denied_syscalls.used > 0)
	{
		int *syscalls = (int *)policy->denied_syscalls.data;
		size_t n = policy->denied_syscalls.used / sizeof(int);
		if(seccomp_enable_blacklist(syscalls, n) < 0)
		{
			QSSB_LOG_ERROR("seccomp_enable_blacklist failed\n");
			return -1;
		}
	}

	return 0;
}
#endif
