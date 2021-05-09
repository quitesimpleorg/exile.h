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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/capability.h>
#include <stddef.h>
#include <inttypes.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
	#include <linux/landlock.h>
	#define HAVE_LANDLOCK 1
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
#define QSSB_FS_ALLOW_WRITE (1<<1) | QSSB_FS_ALLOW_READ
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
	-1
};

struct qssb_path_policy
{
	const char *path;
	unsigned int policy;
	struct qssb_path_policy *next;
};


/* Policy tells qssb what to do */
struct qssb_policy
{
	int drop_caps;
	int preserve_cwd;
	int not_dumpable;
	int no_new_privs;
	int namespace_options;
	int syscall_default_policy;
	int *blacklisted_syscalls;
	int *allowed_syscalls;
	char chroot_target_path[PATH_MAX];
	const char *chdir_path;
	struct qssb_path_policy *path_policies;
};


/* Creates the default policy
 * Must be freed using qssb_free_policy
 * @returns: default policy */
struct qssb_policy *qssb_init_policy()
{
	struct qssb_policy *result = (struct qssb_policy *) calloc(1, sizeof(struct qssb_policy));
	result->blacklisted_syscalls = default_blacklisted_syscals;
	result->drop_caps = 1;
	result->not_dumpable = 1;
	result->no_new_privs = 1;
	result->namespace_options = QSSB_UNSHARE_MOUNT | QSSB_UNSHARE_USER;
	result->chdir_path = NULL;
	result->chroot_target_path[0] = '\0';
	result->path_policies = NULL;
	return result;
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

	if( ((policy->policy) & (QSSB_FS_ALLOW_WRITE)) == QSSB_FS_ALLOW_READ)
	{
		result |= MS_RDONLY;
	}

	if( !(policy->policy & QSSB_MOUNT_NOT_REC))
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


		if(path_policy->policy & QSSB_FS_ALLOW_READ)
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

/* Ends the policy as best as possible. */
/* TODO: can this function do actually anything useful?*/
int qssb_end_policy(struct qssb_policy *ctxt)
{
	return 0;
}

/*
 * Frees the memory taken by a qssb_policy object
 */
void qssb_free_policy(struct qssb_policy *ctxt)
{
	free(ctxt);
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
		QSSB_LOG_ERROR("Failed to drop capabilities: %s\n", strerror(errno));;
		return -errno;
	}
	return 0;
}

/*
 * Enables the per_syscall seccomp action for system calls
 * 
 * syscalls: array of system calls numbers. -1 must be the last entry.
 * per_syscall: action to apply for each system call
 * default_action: the default action at the end
 * 
 * @returns: 0 on success, -1 on error
 */
static int seccomp_enable(int *syscalls, unsigned int per_syscall, unsigned int default_action)
{
	struct sock_filter filter[1024] =
	{
		LOAD_SYSCALL_NR,
	};

	unsigned short int current_filter_index = 1;
	while(*syscalls >= 0)
	{
		unsigned int sysc = (unsigned int) *syscalls;
		struct sock_filter syscall = BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, sysc, 0, 1);
		struct sock_filter action = BPF_STMT(BPF_RET+BPF_K, per_syscall);
		filter[current_filter_index++] = syscall;
		filter[current_filter_index++] = action;
		
		++syscalls;
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
 * syscalls: array of system calls numbers. -1 must be the last entry.
 */
static int seccomp_enable_blacklist(int *syscalls)
{
	return seccomp_enable(syscalls, SECCOMP_RET_KILL, SECCOMP_RET_ALLOW);
}

/*
 * Blacklists the specified systemcalls.
 * 
 * syscalls: array of system calls numbers. -1 must be the last entry.
 */
static int seccomp_enable_whitelist(int *syscalls)
{
	return seccomp_enable(syscalls, SECCOMP_RET_ALLOW, SECCOMP_RET_KILL);
}

/* Enables the specified qssb_policy.
 * 
 * The calling process is supposed *TO BE WRITTEN* if 
 * this function fails.
 * @returns: 0 on sucess, <0 on error
 */
int qssb_enable_policy(struct qssb_policy *policy)
{
	if(policy->blacklisted_syscalls != NULL && policy->allowed_syscalls != NULL)
	{
		QSSB_LOG_ERROR("Error: Cannot mix blacklisted and whitelisted systemcalls\n");
		return -EINVAL;
	}

	if(enter_namespaces(policy->namespace_options) < 0)
	{
		QSSB_LOG_ERROR("Error while trying to enter namespaces\n");
		return -1;
	}

	if(policy->path_policies != NULL)
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
			QSSB_LOG_ERROR("mount_to_chroot: setup of path policies failed\n");
			return -1;
		}

		if(chroot(policy->chroot_target_path) < 0)
		{
			QSSB_LOG_ERROR("chroot: failed to enter %s\n", policy->chroot_target_path);
			return -1;
		}

		if(policy->chdir_path == NULL)
		{
			policy->chdir_path = "/";
		}
	}

	if(policy->chdir_path != NULL && chdir(policy->chdir_path) < 0)
	{
		QSSB_LOG_ERROR("chdir to %s failed\n", policy->chdir_path);
		return -1;
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

	if(policy->allowed_syscalls != NULL)
	{
		if(seccomp_enable_whitelist(policy->allowed_syscalls) <0)
		{
			QSSB_LOG_ERROR("seccomp_enable_whitelist failed\n");
			return -1;
		}
	}

	if(policy->blacklisted_syscalls != NULL)
	{
		if(seccomp_enable_blacklist(policy->blacklisted_syscalls) <0)
		{
			QSSB_LOG_ERROR("seccomp_enable_blacklist failed\n");
			return -1;
		}
	}

	return 0;
}
#endif
