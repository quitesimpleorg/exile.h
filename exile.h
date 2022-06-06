/*
 * Copyright (c) 2019-2022 Albert Schwarzkopf <mail at quitesimple dot org>
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

#ifndef EXILE_H
#define EXILE_H

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
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <linux/limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/version.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <stddef.h>
#include <inttypes.h>
#include <asm/unistd.h>

#define capget(hdrp,datap) syscall(__NR_capget,hdrp,datap)
#define capset(hdrp,datap) syscall(__NR_capset,hdrp,datap)


#ifndef HAVE_LANDLOCK
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,13,0)
		/* TODO: Hopefully a fair assumption. But we need to runtime checks */
		#define HAVE_LANDLOCK 1
	#endif
#endif
#if HAVE_LANDLOCK == 1
	#include <linux/landlock.h>
	#if LANDLOCK_CREATE_RULESET_VERSION != (1U << 0)
		#error "This landlock ABI version is not supported by exile.h (yet)"
	#endif
#endif


#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error Seccomp support has not been tested for exile.h for this platform yet
#endif

#define EXILE_UNSHARE_NETWORK 1<<1
#define EXILE_UNSHARE_USER 1<<2
#define EXILE_UNSHARE_MOUNT 1<<3
#define EXILE_UNSHARE_AUTOMATIC 1<<4

#ifndef EXILE_LOG_ERROR
#define EXILE_LOG_ERROR(...) do { fprintf(stderr, "exile.h: %s(): Error: ", __func__); fprintf(stderr, __VA_ARGS__); } while(0)
#endif

#ifndef EXILE_TEMP_DIR
#define EXILE_TEMP_DIR "/tmp"
#endif

#define EXILE_SYS(x) __NR_##x

/* Allow all read-effect operations on the path */
#define EXILE_FS_ALLOW_ALL_READ 1<<0
/* Allow all write-effect operations on the path, such as normal writes, creation/deletion of files */
#define EXILE_FS_ALLOW_ALL_WRITE (1<<1)
#define EXILE_FS_ALLOW_EXEC 1<<2
#define EXILE_FS_ALLOW_DEV 1<<3
#define EXILE_FS_ALLOW_SETUID 1<<4

//don't mount recursive
#define EXILE_MOUNT_NOT_REC 1<<5

#ifdef __cplusplus
extern "C" {
#endif


/* Fine-granular approach available with landlock */
#if HAVE_LANDLOCK == 1
#define EXILE_FS_ALLOW_REMOVE_DIR		(1 << 7)
#define EXILE_FS_ALLOW_REMOVE_FILE		(1 << 8)
#define EXILE_FS_ALLOW_MAKE_CHAR		(1 << 9)
#define EXILE_FS_ALLOW_MAKE_DIR			(1 << 10)
#define EXILE_FS_ALLOW_MAKE_REG			(1 << 11)
#define EXILE_FS_ALLOW_MAKE_SOCK		(1 << 12)
#define EXILE_FS_ALLOW_MAKE_FIFO		(1 << 13)
#define EXILE_FS_ALLOW_MAKE_BLOCK		(1 << 14)
#define EXILE_FS_ALLOW_MAKE_SYM			(1 << 15)
#define EXILE_FS_ALLOW_WRITE_FILE 		(1 << 16)
#define EXILE_FS_ALLOW_READ_DIR			(1 << 17)
#define EXILE_FS_ALLOW_REMOVE 			(1 << 18)

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

#if defined(__x86_64__)
#ifndef __NR_pkey_mprotect
#define __NR_pkey_mprotect 329
#endif
#ifndef __NR_pkey_alloc
#define __NR_pkey_alloc 330
#endif
#ifndef __NR_pkey_free
#define __NR_pkey_free 331
#endif
#ifndef __NR_statx
#define __NR_statx 332
#endif
#ifndef __NR_io_pgetevents
#define __NR_io_pgetevents 333
#endif
#ifndef __NR_rseq
#define __NR_rseq 334
#endif
#ifndef __NR_pidfd_send_signal
#define __NR_pidfd_send_signal 424
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#endif
#ifndef __NR_io_uring_enter
#define __NR_io_uring_enter 426
#endif
#ifndef __NR_io_uring_register
#define __NR_io_uring_register 427
#endif
#ifndef __NR_open_tree
#define __NR_open_tree 428
#endif
#ifndef __NR_move_mount
#define __NR_move_mount 429
#endif
#ifndef __NR_fsopen
#define __NR_fsopen 430
#endif
#ifndef __NR_fsconfig
#define __NR_fsconfig 431
#endif
#ifndef __NR_fsmount
#define __NR_fsmount 432
#endif
#ifndef __NR_fspick
#define __NR_fspick 433
#endif
#ifndef __NR_pidfd_open
#define __NR_pidfd_open 434
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_futex_waitv
#define __NR_futex_waitv 449
#endif
#ifndef __NR_close_range
#define __NR_close_range 436
#endif
#ifndef __NR_openat2
#define __NR_openat2 437
#endif
#ifndef __NR_pidfd_getfd
#define __NR_pidfd_getfd 438
#endif
#ifndef __NR_faccessat2
#define __NR_faccessat2 439
#endif
#ifndef __NR_process_madvise
#define __NR_process_madvise 440
#endif
#ifndef __NR_epoll_pwait2
#define __NR_epoll_pwait2 441
#endif
#ifndef __NR_mount_setattr
#define __NR_mount_setattr 442
#endif
#ifndef __NR_quotactl_fd
#define __NR_quotactl_fd 443
#endif
#ifndef __NR_landlock_create_ruleset
#define __NR_landlock_create_ruleset 444
#endif
#ifndef __NR_landlock_add_rule
#define __NR_landlock_add_rule 445
#endif
#ifndef __NR_landlock_restrict_self
#define __NR_landlock_restrict_self 446
#endif
#ifndef __NR_memfd_secret
#define __NR_memfd_secret 447
#endif
#ifndef __NR_process_mrelease
#define __NR_process_mrelease 448
#endif
#endif

struct syscall_vow_map
{
	long syscall;
	uint64_t vowmask;
};

struct str_to_vow_map
{
	const char *str;
	uint64_t value;
};

struct exile_path_policy
{
	const char *path;
	unsigned int policy;
	struct exile_path_policy *next;
};

/* Special values */
#define EXILE_SYSCALL_MATCH_ALL -1
/* exit the bpf filter, not matching policy. Go to the next syscall (or the default action, if none left to check) */
#define EXILE_SYSCALL_EXIT_BPF_NO_MATCH 255
/* exit the bpf filter, go directly to the action for the syscall (skip all other args checks) */
#define EXILE_SYSCALL_EXIT_BPF_RETURN 254

#define EXILE_SYSCALL_ALLOW 1
#define EXILE_SYSCALL_DENY_KILL_PROCESS 2
#define EXILE_SYSCALL_DENY_RET_ERROR 3
#define EXILE_SYSCALL_DENY_RET_NOSYS 4

#define EXILE_BPF_NOP \
BPF_STMT(BPF_JMP+BPF_JA,0)

/* A few more dirty markers to simplify array block initializers. We replace those
in append_syscall_to_bpf(). The k value is meaningless here and we don't expect
to ever have filter code actually wanting to jump that many steps forward. So
they serve as an special value we will replace with actual ones. */
#define EXILE_BPF_RETURN_MATCHING \
BPF_STMT(BPF_JMP+BPF_JA,1234)

#define EXILE_BPF_RETURN_NOT_MATCHING \
BPF_STMT(BPF_JMP+BPF_JA,5678)

#define EXILE_BPF_LOAD_SECCOMP_ARG(nr) \
BPF_STMT(BPF_LD+BPF_W+BPF_ABS, (offsetof(struct seccomp_data, args[nr])))

#define EXILE_BPF_CMP_EQ(val,t,f) \
BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, val, t, f)

#define EXILE_BPF_CMP_SET(val,t,f) \
BPF_JUMP(BPF_JMP+BPF_JSET+BPF_K, val, t, f)

/* Immediatly go to the syscall action, do not process any other arg filters */
#define EXILE_BPF_MATCH(argval) \
	EXILE_BPF_CMP_EQ(argval,  EXILE_SYSCALL_EXIT_BPF_RETURN, 0)

#define EXILE_BPF_MATCH_SET(argval) \
	EXILE_BPF_CMP_SET(argval, EXILE_SYSCALL_EXIT_BPF_RETURN, 0)

/* Immediatly go beyond the syscall action, do not process any other arg filters. What to do with this syscall
is thus up to the default policy  */
#define EXILE_BPF_NO_MATCH(argval) \
	EXILE_BPF_CMP_EQ(argval, EXILE_SYSCALL_EXIT_BPF_NO_MATCH, 0)

#define EXILE_BPF_NO_MATCH_SET(argval) \
	EXILE_BPF_CMP_SET(argval, EXILE_SYSCALL_EXIT_BPF_NO_MATCH, 0)


/* Pledge definitions */
#define EXILE_SYSCALL_VOW_CHOWN ((uint64_t)1<<1)
#define EXILE_SYSCALL_VOW_CLONE ((uint64_t)1<<2)
#define EXILE_SYSCALL_VOW_CPATH ((uint64_t)1<<3)
#define EXILE_SYSCALL_VOW_DPATH ((uint64_t)1<<4)
#define EXILE_SYSCALL_VOW_EXEC ((uint64_t)1<<5)
#define EXILE_SYSCALL_VOW_FATTR ((uint64_t)1<<6)
#define EXILE_SYSCALL_VOW_FSNOTIFY ((uint64_t)1<<7)
#define EXILE_SYSCALL_VOW_ID ((uint64_t)1<<8)
#define EXILE_SYSCALL_VOW_INET ((uint64_t)1<<9)
#define EXILE_SYSCALL_VOW_IOCTL ((uint64_t)1<<10)
#define EXILE_SYSCALL_VOW_PRCTL ((uint64_t)1<<11)
#define EXILE_SYSCALL_VOW_PROC ((uint64_t)1<<12)
#define EXILE_SYSCALL_VOW_PROT_EXEC ((uint64_t)1<<13)
#define EXILE_SYSCALL_VOW_RPATH ((uint64_t)1<<14)
#define EXILE_SYSCALL_VOW_SCHED ((uint64_t)1<<15)
#define EXILE_SYSCALL_VOW_SECCOMP_INSTALL ((uint64_t)1<<16)
#define EXILE_SYSCALL_VOW_SHM ((uint64_t)1<<17)
#define EXILE_SYSCALL_VOW_STDIO ((uint64_t)1<<18)
#define EXILE_SYSCALL_VOW_THREAD ((uint64_t)1<<19)
#define EXILE_SYSCALL_VOW_UNIX ((uint64_t)1<<20)
#define EXILE_SYSCALL_VOW_WPATH ((uint64_t)1<<21)

#define EXILE_SYSCALL_VOW_DENY_ERROR ((uint64_t)1<<63)


#define EXILE_ARGFILTERS_COUNT 60


#define EXILE_FLAG_ADD_PATH_POLICY_FAIL (1u<<1)
#define EXILE_FLAG_ADD_SYSCALL_POLICY_FAIL (1u<<2)

struct exile_syscall_policy
{
	struct sock_filter argfilters[EXILE_ARGFILTERS_COUNT];
	size_t argfilterscount;
	long syscall;
	unsigned int policy;
	struct exile_syscall_policy *next;
};

/* Policy tells exile what to do */
struct exile_policy
{
	int drop_caps;
	int preserve_cwd;
	int not_dumpable;
	int no_new_privs;
	int no_fs;
	int no_new_fds;
	int namespace_options;
	int disable_syscall_filter;
	/* Bind mounts all paths in path_policies into the chroot and applies
	 non-landlock policies */
	int mount_path_policies_to_chroot;
	char chroot_target_path[PATH_MAX];
	const char *chdir_path;

	uint64_t vow_promises;

	/* Do not manually add policies here, use exile_append_path_policies() */
	struct exile_path_policy *path_policies;
	struct exile_path_policy **path_policies_tail;

	/* Do not manually add policies here, use exile_append_syscall_policy() */
	struct exile_syscall_policy *syscall_policies;
	struct exile_syscall_policy **syscall_policies_tail;

	uint32_t exile_flags;
};

/* Converts the whitespace separated vows strings to vows flags
 *
 * This mainly helps readability, as lots of flags ORed together is not
 * very readable.
 *
 * If an unkown string is found, abort() is called.
 */
uint64_t exile_vows_from_str(const char *str);

/*
 * If we can use landlock, return 1, otherwise 0
 */
int exile_landlock_is_available();

int exile_append_syscall_policy(struct exile_policy *exile_policy, long syscall, unsigned int syscall_policy, struct sock_filter *argfilters, size_t n);

int exile_append_syscall_default_policy(struct exile_policy *exile_policy, unsigned int default_policy);

struct exile_syscall_filter
{
	uint64_t vowmask; /* Apply filter if this mask is set. 0 = ignore mask, apply always */
	struct sock_filter filter;
	int whenset; /* 1 = Filter should be added if vowmask is contained in pledge mask, otherwise won't be added. */
};

#define COUNT_EXILE_SYSCALL_FILTER(f) \
	sizeof(f)/sizeof(f[0])

#define EXILE_SYSCALL_FILTER_LOAD_ARG(val) \
{ 0, EXILE_BPF_LOAD_SECCOMP_ARG(val), 0}

/* Returns, for the specific syscall, the correct sock_filter struct for the provided vow_promises
 *
 *	Returns: 0 if none copied, otherwise the number of entries in "filter".
 */
int get_vow_argfilter(long syscall, uint64_t vow_promises, struct sock_filter *filter , int *policy);


int exile_append_vow_promises(struct exile_policy *policy, uint64_t vow_promises);


/* Creates an empty policy struct without opinionated defaults.
 *
 * Must be freed using exile_free_policy()
 * @returns: empty policy
 */
struct exile_policy *exile_create_policy();


/* Creates the default policy
 * Must be freed using exile_free_policy()
 *
 * @returns: default policy
 */
struct exile_policy *exile_init_policy();


/* Appends path policies to the exile_policy object
 * The last paramater must be NULL
 *
 * This function does not copy parameters. All passed paths
 * MUST NOT be freed until exile_enable_policy() is called!
 *
 * @returns: 0 on success, -1 on failure */
int exile_append_path_policies(struct exile_policy *exile_policy, unsigned int path_policy, ...);
#define exile_append_path_policies(e, p, ...) exile_append_path_policies(e, p, __VA_ARGS__, NULL)

int path_policy_needs_landlock(struct exile_path_policy *path_policy);

/*
 * Frees the memory taken by a exile_policy object
 */
void exile_free_policy(struct exile_policy *ctxt);


/*
 * Enables the seccomp policy
 *
 * policy: exile policy object
 *
 * @returns: 0 on success, -1 on error
 */
int exile_enable_syscall_policy(struct exile_policy *policy);


int exile_enable_policy(struct exile_policy *policy);


/* Convenience wrapper for the vow-related subset of exile.h
 *
 * Only installs seccomp filters for the specified vow promises.
 *
 * Useful if only vow is required from exile.h, but nothing else
 *
 * Comparable with OpenBSD's pledge(), subsequent calls can only reduce allowed syscalls.
 *
 * Here, adding more promises than a previous call set may return success, but
 * won't be allowed during execution.
 *
 * Due to the nature of seccomp, it's furthermore required the EXILE_SYSCALL_VOW_SECCOMP_INSTALL promise
 * is set if further calls are expected. Generally, it's reasonable for the last call to
 * exile_vow() a program makes to not set EXILE_SYSCALL_VOW_SECCOMP_INSTALL.
 *
 * There are no seperate exec_promises. All children of the process inherit the filter.
 * .
 * Return value: 0 on success, any other value on failure.
 */
int exile_vow(uint64_t promises);

struct exile_launch_params
{
	struct exile_policy *policy; /* Policy to activate before jumping to func */
	int (*func)(void *); /* Function to be sandboxed */
	void *funcarg; /* Arg to be passed */
	int child_read_pipe[2];
	int child_write_pipe[2];
};

struct exile_launch_result
{
	int tid;
	int read_fd;
	int write_fd;
};

int exile_clone_handle(void *arg); 
/* Helper to easily execute a single function sandboxed.
 *
 * Creates a child-process, then activates the policy contained in launch_params,
 * and jumps to the specified function, passing the specified argument to it.
 * Returns a fd connected to stdout in the child process, as well as a fd allowing to write
 * to the child.
 *
 * if cloneflags is 0, the default ones are passed to clone(), otherwise the value of cloneflags
 *
 * Return value: Negative on error, otherwise the file descriptor to read from*/
int exile_launch(struct exile_launch_params *launch_params, struct exile_launch_result *launch_result);


/* Helper for exile_launch, to easily read all output from a function
* This function will read all output from a sandboxed function. It's up to the caller to ensure
* that enough memory will be available.
*
* The result is \0 terminated. The "n" parameter contains the size of the result, not including the \0.
*
* Return value: All data written by the function. The result should be passed to free() once not needed. NULL will
* be returned on error.
*/
char *exile_launch_get(struct exile_launch_params *launch_params, size_t *n);

#ifdef __cplusplus
}
#endif

#endif
