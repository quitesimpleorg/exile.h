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
		#error "This landlock ABI version is not supported by exile.h (yet)"
	#endif
#endif


#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error Seccomp support has not been tested for exile.h for this platform yet
#endif

#define SYSCALL(nr, jt) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (nr), 0, 1), jt


#define EXILE_UNSHARE_NETWORK 1<<1
#define EXILE_UNSHARE_USER 1<<2
#define EXILE_UNSHARE_MOUNT 1<<3

#ifndef EXILE_LOG_ERROR
#define EXILE_LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
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

#define EXILE_SYSCGROUP_CHROOT ((uint64_t)1<<0)
#define EXILE_SYSCGROUP_CLOCK ((uint64_t)1<<1)
#define EXILE_SYSCGROUP_CLONE ((uint64_t)1<<2)
#define EXILE_SYSCGROUP_DEFAULT_ALLOW ((uint64_t)1<<3)
#define EXILE_SYSCGROUP_DEV ((uint64_t)1<<4)
#define EXILE_SYSCGROUP_EXEC ((uint64_t)1<<5)
#define EXILE_SYSCGROUP_EXIT ((uint64_t)1<<6)
#define EXILE_SYSCGROUP_FANOTIFY ((uint64_t)1<<7)
#define EXILE_SYSCGROUP_FD ((uint64_t)1<<8)
#define EXILE_SYSCGROUP_FS ((uint64_t)1<<9)
#define EXILE_SYSCGROUP_FUTEX ((uint64_t)1<<10)
#define EXILE_SYSCGROUP_HOST ((uint64_t)1<<11)
#define EXILE_SYSCGROUP_ID ((uint64_t)1<<12)
#define EXILE_SYSCGROUP_INOTIFY ((uint64_t)1<<13)
#define EXILE_SYSCGROUP_IO ((uint64_t)1<<14)
#define EXILE_SYSCGROUP_IOCTL ((uint64_t)1<<15)
#define EXILE_SYSCGROUP_IOPL ((uint64_t)1<<16)
#define EXILE_SYSCGROUP_IOURING ((uint64_t)1<<17)
#define EXILE_SYSCGROUP_IPC ((uint64_t)1<<18)
#define EXILE_SYSCGROUP_KEXEC ((uint64_t)1<<19)
#define EXILE_SYSCGROUP_KEYS ((uint64_t)1<<20)
#define EXILE_SYSCGROUP_KILL ((uint64_t)1<<21)
#define EXILE_SYSCGROUP_KMOD ((uint64_t)1<<22)
#define EXILE_SYSCGROUP_LANDLOCK ((uint64_t)1<<23)
#define EXILE_SYSCGROUP_LIB ((uint64_t)1<<24)
#define EXILE_SYSCGROUP_MEMORY ((uint64_t)1<<25)
#define EXILE_SYSCGROUP_MOUNT ((uint64_t)1<<26)
#define EXILE_SYSCGROUP_MQ ((uint64_t)1<<27)
#define EXILE_SYSCGROUP_NEWMOUNT ((uint64_t)1<<28)
#define EXILE_SYSCGROUP_NONE ((uint64_t)1<<29)
#define EXILE_SYSCGROUP_NS ((uint64_t)1<<30)
#define EXILE_SYSCGROUP_PATH ((uint64_t)1<<31)
#define EXILE_SYSCGROUP_PAUSE ((uint64_t)1<<32)
#define EXILE_SYSCGROUP_PERF ((uint64_t)1<<33)
#define EXILE_SYSCGROUP_PERMS ((uint64_t)1<<34)
#define EXILE_SYSCGROUP_PIDFD ((uint64_t)1<<35)
#define EXILE_SYSCGROUP_PKEY ((uint64_t)1<<36)
#define EXILE_SYSCGROUP_POWER ((uint64_t)1<<37)
#define EXILE_SYSCGROUP_PRIO ((uint64_t)1<<38)
#define EXILE_SYSCGROUP_PROCESS ((uint64_t)1<<39)
#define EXILE_SYSCGROUP_PTRACE ((uint64_t)1<<40)
#define EXILE_SYSCGROUP_QUOTA ((uint64_t)1<<41)
#define EXILE_SYSCGROUP_RES ((uint64_t)1<<42)
#define EXILE_SYSCGROUP_RT ((uint64_t)1<<43)
#define EXILE_SYSCGROUP_SCHED ((uint64_t)1<<44)
#define EXILE_SYSCGROUP_SEM ((uint64_t)1<<45)
#define EXILE_SYSCGROUP_SHM ((uint64_t)1<<46)
#define EXILE_SYSCGROUP_SIGNAL ((uint64_t)1<<47)
#define EXILE_SYSCGROUP_SOCKET ((uint64_t)1<<48)
#define EXILE_SYSCGROUP_STAT ((uint64_t)1<<49)
#define EXILE_SYSCGROUP_STDIO ((uint64_t)1<<50)
#define EXILE_SYSCGROUP_SWAP ((uint64_t)1<<51)
#define EXILE_SYSCGROUP_SYS ((uint64_t)1<<52)
#define EXILE_SYSCGROUP_SYSCALL ((uint64_t)1<<53)
#define EXILE_SYSCGROUP_THREAD ((uint64_t)1<<54)
#define EXILE_SYSCGROUP_TIME ((uint64_t)1<<55)
#define EXILE_SYSCGROUP_TIMER ((uint64_t)1<<56)
#define EXILE_SYSCGROUP_TTY ((uint64_t)1<<57)
#define EXILE_SYSCGROUP_UMOUNT ((uint64_t)1<<58)
#define EXILE_SYSCGROUP_UNIMPLEMENTED ((uint64_t)1<<59)
#define EXILE_SYSCGROUP_XATTR ((uint64_t)1<<60)

struct syscall_group_map
{
	long syscall;
	uint64_t groupmask;
};

struct syscall_group_map sc_group_map[] = {
{EXILE_SYS(read), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(write), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(open), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(close), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(stat), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fstat), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(lstat), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(poll), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(lseek), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(mmap), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(mprotect), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(munmap), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(brk), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigaction), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigprocmask), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigreturn), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(ioctl), EXILE_SYSCGROUP_IOCTL|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(pread64), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(pwrite64), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(readv), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(writev), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(access), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(pipe), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(select), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(sched_yield), EXILE_SYSCGROUP_SCHED|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(mremap), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(msync), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(mincore), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(madvise), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(shmget), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(shmat), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(shmctl), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(dup), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(dup2), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(pause), EXILE_SYSCGROUP_PAUSE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(nanosleep), EXILE_SYSCGROUP_TIMER|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getitimer), EXILE_SYSCGROUP_TIMER|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(alarm), EXILE_SYSCGROUP_TIMER|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setitimer), EXILE_SYSCGROUP_TIMER|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getpid), EXILE_SYSCGROUP_PROCESS|EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(sendfile), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(socket), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(connect), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(accept), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(sendto), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(recvfrom), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(sendmsg), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(recvmsg), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(shutdown), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(bind), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(listen), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(getsockname), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(getpeername), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(socketpair), EXILE_SYSCGROUP_SOCKET|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(setsockopt), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(getsockopt), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(clone), EXILE_SYSCGROUP_CLONE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(fork), EXILE_SYSCGROUP_CLONE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(vfork), EXILE_SYSCGROUP_CLONE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(execve), EXILE_SYSCGROUP_CLONE|EXILE_SYSCGROUP_EXEC},
{EXILE_SYS(exit), EXILE_SYSCGROUP_PROCESS|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(wait4), EXILE_SYSCGROUP_EXEC},
{EXILE_SYS(kill), EXILE_SYSCGROUP_KILL},
{EXILE_SYS(uname), EXILE_SYSCGROUP_SYS|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(semget), EXILE_SYSCGROUP_SHM|EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(semop), EXILE_SYSCGROUP_SHM|EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(semctl), EXILE_SYSCGROUP_SHM|EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(shmdt), EXILE_SYSCGROUP_SHM|EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(msgget), EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(msgsnd), EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(msgrcv), EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(msgctl), EXILE_SYSCGROUP_IPC|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(fcntl), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(flock), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(fsync), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(fdatasync), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(truncate), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(ftruncate), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(getdents), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(getcwd), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(chdir), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fchdir), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(rename), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(mkdir), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(rmdir), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(creat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(link), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(unlink), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(symlink), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(readlink), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(chmod), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fchmod), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(chown), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fchown), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(lchown), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(umask), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(gettimeofday), EXILE_SYSCGROUP_TIME|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getrlimit), EXILE_SYSCGROUP_RES|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getrusage), EXILE_SYSCGROUP_RES|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(sysinfo), EXILE_SYSCGROUP_SYS|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(times), EXILE_SYSCGROUP_TIME|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(ptrace), EXILE_SYSCGROUP_PTRACE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getuid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(syslog), EXILE_SYSCGROUP_SYS},
{EXILE_SYS(getgid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setuid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(setgid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(geteuid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getegid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setpgid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(getppid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getpgrp), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setsid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(setreuid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(setregid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(getgroups), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setgroups), EXILE_SYSCGROUP_ID},
{EXILE_SYS(setresuid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(getresuid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setresgid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(getresgid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(getpgid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(setfsuid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(setfsgid), EXILE_SYSCGROUP_ID},
{EXILE_SYS(getsid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(capget), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(capset), EXILE_SYSCGROUP_ID},
{EXILE_SYS(rt_sigpending), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigtimedwait), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigqueueinfo), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(rt_sigsuspend), EXILE_SYSCGROUP_RT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(sigaltstack), EXILE_SYSCGROUP_THREAD|EXILE_SYSCGROUP_SIGNAL},
{EXILE_SYS(utime), EXILE_SYSCGROUP_TIME|EXILE_SYSCGROUP_FS},
{EXILE_SYS(mknod), EXILE_SYSCGROUP_DEV|EXILE_SYSCGROUP_FS},
{EXILE_SYS(uselib), EXILE_SYSCGROUP_LIB|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(personality), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(ustat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_STAT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(statfs), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_STAT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fstatfs), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_STAT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(sysfs), EXILE_SYSCGROUP_SYS|EXILE_SYSCGROUP_FS},
{EXILE_SYS(getpriority), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(setpriority), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_setparam), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_getparam), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_setscheduler), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_getscheduler), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_get_priority_max), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_get_priority_min), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_rr_get_interval), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(mlock), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(munlock), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(mlockall), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(munlockall), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(vhangup), EXILE_SYSCGROUP_TTY},
{EXILE_SYS(modify_ldt), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(pivot_root), EXILE_SYSCGROUP_CHROOT},
{EXILE_SYS(_sysctl), EXILE_SYSCGROUP_SYS},
{EXILE_SYS(prctl), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(arch_prctl), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(adjtimex), EXILE_SYSCGROUP_CLOCK},
{EXILE_SYS(setrlimit), EXILE_SYSCGROUP_RES},
{EXILE_SYS(chroot), EXILE_SYSCGROUP_CHROOT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(sync), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(acct), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(settimeofday), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(mount), EXILE_SYSCGROUP_MOUNT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(umount2), EXILE_SYSCGROUP_UMOUNT|EXILE_SYSCGROUP_FS},
{EXILE_SYS(swapon), EXILE_SYSCGROUP_SWAP},
{EXILE_SYS(swapoff), EXILE_SYSCGROUP_SWAP},
{EXILE_SYS(reboot), EXILE_SYSCGROUP_POWER},
{EXILE_SYS(sethostname), EXILE_SYSCGROUP_HOST},
{EXILE_SYS(setdomainname), EXILE_SYSCGROUP_HOST},
{EXILE_SYS(iopl), EXILE_SYSCGROUP_IOPL},
{EXILE_SYS(ioperm), EXILE_SYSCGROUP_IOPL},
{EXILE_SYS(create_module), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(init_module), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(delete_module), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(get_kernel_syms), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(query_module), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(quotactl), EXILE_SYSCGROUP_QUOTA},
{EXILE_SYS(nfsservctl), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(getpmsg), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(putpmsg), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(afs_syscall), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(tuxcall), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(security), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(gettid), EXILE_SYSCGROUP_ID|EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(readahead), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_FS},
{EXILE_SYS(setxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(lsetxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fsetxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(getxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(lgetxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fgetxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(listxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(llistxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(flistxattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(removexattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(lremovexattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fremovexattr), EXILE_SYSCGROUP_XATTR|EXILE_SYSCGROUP_FS},
{EXILE_SYS(tkill), EXILE_SYSCGROUP_THREAD|EXILE_SYSCGROUP_SIGNAL},
{EXILE_SYS(time), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(futex), EXILE_SYSCGROUP_THREAD|EXILE_SYSCGROUP_FUTEX},
{EXILE_SYS(sched_setaffinity), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_getaffinity), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(set_thread_area), EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(io_setup), EXILE_SYSCGROUP_IO},
{EXILE_SYS(io_destroy), EXILE_SYSCGROUP_IO},
{EXILE_SYS(io_getevents), EXILE_SYSCGROUP_IO},
{EXILE_SYS(io_submit), EXILE_SYSCGROUP_IO},
{EXILE_SYS(io_cancel), EXILE_SYSCGROUP_IO},
{EXILE_SYS(get_thread_area), EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(lookup_dcookie), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_FS},
{EXILE_SYS(epoll_create), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(epoll_ctl_old), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(epoll_wait_old), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(remap_file_pages), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(getdents64), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_FS},
{EXILE_SYS(set_tid_address), EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(restart_syscall), EXILE_SYSCGROUP_SYSCALL},
{EXILE_SYS(semtimedop), EXILE_SYSCGROUP_SEM},
{EXILE_SYS(fadvise64), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_FD},
{EXILE_SYS(timer_create), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(timer_settime), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(timer_gettime), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(timer_getoverrun), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(timer_delete), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(clock_settime), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(clock_gettime), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(clock_getres), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(clock_nanosleep), EXILE_SYSCGROUP_TIME},
{EXILE_SYS(exit_group), EXILE_SYSCGROUP_EXIT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(epoll_wait), EXILE_SYSCGROUP_FD},
{EXILE_SYS(epoll_ctl), EXILE_SYSCGROUP_FD},
{EXILE_SYS(tgkill), EXILE_SYSCGROUP_SIGNAL|EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(utimes), EXILE_SYSCGROUP_PATH},
{EXILE_SYS(vserver), EXILE_SYSCGROUP_UNIMPLEMENTED},
{EXILE_SYS(mbind), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(set_mempolicy), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(get_mempolicy), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(mq_open), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(mq_unlink), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(mq_timedsend), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(mq_timedreceive), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(mq_notify), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(mq_getsetattr), EXILE_SYSCGROUP_MQ|EXILE_SYSCGROUP_IPC},
{EXILE_SYS(kexec_load), EXILE_SYSCGROUP_KEXEC},
{EXILE_SYS(waitid), EXILE_SYSCGROUP_SIGNAL},
{EXILE_SYS(add_key), EXILE_SYSCGROUP_KEYS},
{EXILE_SYS(request_key), EXILE_SYSCGROUP_KEYS},
{EXILE_SYS(keyctl), EXILE_SYSCGROUP_KEYS},
{EXILE_SYS(ioprio_set), EXILE_SYSCGROUP_PRIO},
{EXILE_SYS(ioprio_get), EXILE_SYSCGROUP_PRIO},
{EXILE_SYS(inotify_init), EXILE_SYSCGROUP_INOTIFY},
{EXILE_SYS(inotify_add_watch), EXILE_SYSCGROUP_INOTIFY},
{EXILE_SYS(inotify_rm_watch), EXILE_SYSCGROUP_INOTIFY},
{EXILE_SYS(migrate_pages), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(openat), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(mkdirat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(mknodat), EXILE_SYSCGROUP_DEV|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fchownat), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(futimesat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(newfstatat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(unlinkat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(renameat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(linkat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(symlinkat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(readlinkat), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(fchmodat), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(faccessat), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(pselect6), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(ppoll), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW|EXILE_SYSCGROUP_FS},
{EXILE_SYS(unshare), EXILE_SYSCGROUP_NS|EXILE_SYSCGROUP_FS},
{EXILE_SYS(set_robust_list), EXILE_SYSCGROUP_FUTEX},
{EXILE_SYS(get_robust_list), EXILE_SYSCGROUP_FUTEX},
{EXILE_SYS(splice), EXILE_SYSCGROUP_FD},
{EXILE_SYS(tee), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(sync_file_range), EXILE_SYSCGROUP_FD},
{EXILE_SYS(vmsplice), EXILE_SYSCGROUP_FD},
{EXILE_SYS(move_pages), EXILE_SYSCGROUP_PROCESS},
{EXILE_SYS(utimensat), EXILE_SYSCGROUP_PATH},
{EXILE_SYS(epoll_pwait), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(signalfd), EXILE_SYSCGROUP_SIGNAL},
{EXILE_SYS(timerfd_create), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(eventfd), EXILE_SYSCGROUP_FD},
{EXILE_SYS(fallocate), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_FD},
{EXILE_SYS(timerfd_settime), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(timerfd_gettime), EXILE_SYSCGROUP_TIMER},
{EXILE_SYS(accept4), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(signalfd4), EXILE_SYSCGROUP_FD},
{EXILE_SYS(eventfd2), EXILE_SYSCGROUP_FD},
{EXILE_SYS(epoll_create1), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(dup3), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(pipe2), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(inotify_init1), EXILE_SYSCGROUP_INOTIFY},
{EXILE_SYS(preadv), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(pwritev), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(rt_tgsigqueueinfo), EXILE_SYSCGROUP_RT},
{EXILE_SYS(perf_event_open), EXILE_SYSCGROUP_PERF},
{EXILE_SYS(recvmmsg), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(fanotify_init), EXILE_SYSCGROUP_FANOTIFY},
{EXILE_SYS(fanotify_mark), EXILE_SYSCGROUP_FANOTIFY},
{EXILE_SYS(prlimit64), EXILE_SYSCGROUP_RES},
{EXILE_SYS(name_to_handle_at), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_FS},
{EXILE_SYS(open_by_handle_at), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_FS},
{EXILE_SYS(clock_adjtime), EXILE_SYSCGROUP_CLOCK},
{EXILE_SYS(syncfs), EXILE_SYSCGROUP_FD},
{EXILE_SYS(sendmmsg), EXILE_SYSCGROUP_SOCKET},
{EXILE_SYS(setns), EXILE_SYSCGROUP_NS},
{EXILE_SYS(getcpu), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(process_vm_readv), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(process_vm_writev), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(kcmp), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(finit_module), EXILE_SYSCGROUP_KMOD},
{EXILE_SYS(sched_setattr), EXILE_SYSCGROUP_SCHED},
{EXILE_SYS(sched_getattr), EXILE_SYSCGROUP_SCHED|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(renameat2), EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(seccomp), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(getrandom), EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(memfd_create), EXILE_SYSCGROUP_MEMORY|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(kexec_file_load), EXILE_SYSCGROUP_KEXEC},
{EXILE_SYS(bpf), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(execveat), EXILE_SYSCGROUP_EXEC},
{EXILE_SYS(userfaultfd), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(membarrier), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(mlock2), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(copy_file_range), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(preadv2), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(pwritev2), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(pkey_mprotect), EXILE_SYSCGROUP_PKEY},
{EXILE_SYS(pkey_alloc), EXILE_SYSCGROUP_PKEY},
{EXILE_SYS(pkey_free), EXILE_SYSCGROUP_PKEY},
{EXILE_SYS(statx), EXILE_SYSCGROUP_STAT|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(io_pgetevents), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(rseq), EXILE_SYSCGROUP_THREAD},
{EXILE_SYS(pidfd_send_signal), EXILE_SYSCGROUP_PIDFD},
{EXILE_SYS(io_uring_setup), EXILE_SYSCGROUP_IOURING},
{EXILE_SYS(io_uring_enter), EXILE_SYSCGROUP_IOURING},
{EXILE_SYS(io_uring_register), EXILE_SYSCGROUP_IOURING},
{EXILE_SYS(open_tree), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(move_mount), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(fsopen), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(fsconfig), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(fsmount), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(fspick), EXILE_SYSCGROUP_NEWMOUNT},
{EXILE_SYS(pidfd_open), EXILE_SYSCGROUP_PIDFD},
{EXILE_SYS(clone3), EXILE_SYSCGROUP_CLONE|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(close_range), EXILE_SYSCGROUP_STDIO|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(openat2), EXILE_SYSCGROUP_FD|EXILE_SYSCGROUP_PATH|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(pidfd_getfd), EXILE_SYSCGROUP_PIDFD},
{EXILE_SYS(faccessat2), EXILE_SYSCGROUP_PERMS|EXILE_SYSCGROUP_DEFAULT_ALLOW},
{EXILE_SYS(process_madvise), EXILE_SYSCGROUP_MEMORY},
{EXILE_SYS(epoll_pwait2), EXILE_SYSCGROUP_STDIO},
{EXILE_SYS(mount_setattr), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(quotactl_fd), EXILE_SYSCGROUP_QUOTA},
{EXILE_SYS(landlock_create_ruleset), EXILE_SYSCGROUP_LANDLOCK},
{EXILE_SYS(landlock_add_rule), EXILE_SYSCGROUP_LANDLOCK},
{EXILE_SYS(landlock_restrict_self), EXILE_SYSCGROUP_LANDLOCK},
{EXILE_SYS(memfd_secret), EXILE_SYSCGROUP_NONE},
{EXILE_SYS(process_mrelease), EXILE_SYSCGROUP_NONE}
};


struct exile_path_policy
{
	const char *path;
	unsigned int policy;
	struct exile_path_policy *next;
};

/* Special values */
#define EXILE_SYSCALL_MATCH_ALL -1
#define EXILE_SYSCALL_EXIT_BPF_NO_MATCH 255 //exit the bpf filter, not matching policy

#define EXILE_SYSCALL_ALLOW 1
#define EXILE_SYSCALL_DENY_KILL_PROCESS 2
#define EXILE_SYSCALL_DENY_RET_ERROR 3

#define EXILE_ARGFILTERS_COUNT 60
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

	/* Do not manually add policies here, use exile_append_path_polic*() */
	struct exile_path_policy *path_policies;
	struct exile_path_policy **path_policies_tail;

	/* Do not manually add policies here, use exile_append_syscall_policy() */
	struct exile_syscall_policy *syscall_policies;
	struct exile_syscall_policy **syscall_policies_tail;

};

static int is_valid_syscall_policy(unsigned int policy)
{
	return policy == EXILE_SYSCALL_ALLOW || policy == EXILE_SYSCALL_DENY_RET_ERROR || policy == EXILE_SYSCALL_DENY_KILL_PROCESS;
}

int exile_append_syscall_policy(struct exile_policy *exile_policy, long syscall, unsigned int syscall_policy, struct sock_filter *argfilters, size_t n)
{
	struct exile_syscall_policy *newpolicy = (struct exile_syscall_policy *) calloc(1, sizeof(struct exile_syscall_policy));
	if(newpolicy == NULL)
	{
		EXILE_LOG_ERROR("Failed to allocate memory for syscall policy\n");
		return -1;
	}
	newpolicy->policy = syscall_policy;
	newpolicy->syscall = syscall;
	newpolicy->argfilterscount = n;
	if(n > EXILE_ARGFILTERS_COUNT)
	{
		EXILE_LOG_ERROR("Too many argfilters supplied\n");
		return -1;
	}
	for(size_t i = 0; i < n; i++)
	{
		newpolicy->argfilters[i] = argfilters[i];
	}
	newpolicy->next = NULL;

	*(exile_policy->syscall_policies_tail) = newpolicy;
	exile_policy->syscall_policies_tail = &(newpolicy->next);

	exile_policy->disable_syscall_filter = 0;
	return 0;
}


int exile_append_syscall_default_policy(struct exile_policy *exile_policy, unsigned int default_policy)
{
	return exile_append_syscall_policy(exile_policy, EXILE_SYSCALL_MATCH_ALL, default_policy, NULL, 0);
}

static void get_group_syscalls(uint64_t mask, long *syscalls, size_t *n)
{
	size_t count = 0;
	for(unsigned long i = 0; i < sizeof(sc_group_map)/sizeof(sc_group_map[0]); i++)
	{
		struct syscall_group_map *current = &sc_group_map[i];
		if(current->groupmask & mask)
		{
			syscalls[count] = current->syscall;
			++count;
		}
	}
	*n = count;
}

int exile_append_group_syscall_policy(struct exile_policy *exile_policy, unsigned int syscall_policy, uint64_t groupmask)
{
	long syscalls[400] = { 0 };
	size_t n = 0;

	if(groupmask & EXILE_SYSCGROUP_NONE)
	{
		EXILE_LOG_ERROR("Error: 'None' is an illegal group name\n");
		return -EINVAL;
	}
	get_group_syscalls(groupmask, syscalls, &n);
	if(n == 0)
	{
		EXILE_LOG_ERROR("Error: No syscalls found for group mask\n");
		return -EINVAL;
	}
	for(size_t i = 0; i < n; i++)
	{
		int ret = exile_append_syscall_policy(exile_policy, syscalls[i], syscall_policy, NULL, 0);
		if(ret != 0)
		{
			EXILE_LOG_ERROR("Error: Failed while trying to append group policy\n");
			return ret;
		}
	}

	return 0;
}

/* Creates the default policy
 * Must be freed using exile_free_policy
 * @returns: default policy */
struct exile_policy *exile_init_policy()
{
	struct exile_policy *result = (struct exile_policy *) calloc(1, sizeof(struct exile_policy));
	result->drop_caps = 1;
	result->not_dumpable = 1;
	result->no_new_privs = 1;
	result->no_fs = 0;
	result->no_new_fds = 0;
	result->namespace_options = EXILE_UNSHARE_MOUNT | EXILE_UNSHARE_USER;
	result->disable_syscall_filter = 0;
	result->chdir_path = NULL;
	result->mount_path_policies_to_chroot = 0;
	result->chroot_target_path[0] = '\0';
	result->path_policies = NULL;
	result->path_policies_tail = &(result->path_policies);

	result->syscall_policies = NULL;
	result->syscall_policies_tail = &(result->syscall_policies);

	return result;
}

/* Appends path policies to the exile_policy object
 * The last paramater must be NULL
 *
 * This function does not copy parameters. All passed paths
 * MUST NOT be freed until exile_enable_policy() is called!
 *
 * @returns: 0 on success, -1 on failure */
int exile_append_path_policies(struct exile_policy *exile_policy, unsigned int path_policy, ...)
{
	va_list args;
	const char *path;
	va_start(args, path_policy);

	path = va_arg(args, char*);
	while(path != NULL)
	{
		struct exile_path_policy *newpolicy = (struct exile_path_policy *) calloc(1, sizeof(struct exile_path_policy));
		if(newpolicy == NULL)
		{
			EXILE_LOG_ERROR("Failed to allocate memory for path policy\n");
			return -1;
		}
		newpolicy->path = path;
		newpolicy->policy = path_policy;
		newpolicy->next = NULL;

		*(exile_policy->path_policies_tail) = newpolicy;
		exile_policy->path_policies_tail = &(newpolicy->next);
		path = va_arg(args, char*);
	}

	va_end(args);

	return 0;
}

int exile_append_path_policy(struct exile_policy *exile_policy, unsigned int path_policy, const char *path)
{
	return exile_append_path_policies(exile_policy, path_policy, path, NULL);
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
		EXILE_LOG_ERROR("exile: mkdir_strucutre: error during path concatination\n");
		return -EINVAL;
	}
	if(res >= PATH_MAX)
	{
		EXILE_LOG_ERROR("exile: mkdir_structure: path concatination truncated\n");
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
					EXILE_LOG_ERROR("Failed to create directory for chroot: %s\n", begin);
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
static int get_policy_mount_flags(struct exile_path_policy *policy)
{
	int result = 0;

	if( (policy->policy & EXILE_FS_ALLOW_DEV) == 0)
	{
		result |= MS_NODEV;
	}

	if( (policy->policy & EXILE_FS_ALLOW_EXEC) == 0)
	{
		result |= MS_NOEXEC;
	}

	if( (policy->policy & EXILE_FS_ALLOW_SETUID) == 0)
	{
		result |= MS_NOSUID;
	}

	if( (policy->policy & EXILE_FS_ALLOW_ALL_WRITE) == 0)
	{
		result |= MS_RDONLY;
	}

	if( (policy->policy & EXILE_MOUNT_NOT_REC) == 0)
	{
		result |= MS_REC;
	}
	return result;
}

/* Helper to mount directories into the chroot path "chroot_target_path"
 * Paths will be created if necessary

 * @returns: 0 on sucess, -ERRNO on failure */
static int mount_to_chroot(const char *chroot_target_path, struct exile_path_policy *path_policy)
{
	while(path_policy != NULL)
	{

		char path_inside_chroot[PATH_MAX];
		int written = snprintf(path_inside_chroot, sizeof(path_inside_chroot), "%s/%s", chroot_target_path, path_policy->path);
		if(written < 0)
		{
			EXILE_LOG_ERROR("exile: mount_to_chroot: Error during path concatination\n");
			return -EINVAL;
		}
		if(written >= PATH_MAX)
		{
			EXILE_LOG_ERROR("exile: mount_to_chroot: path concatination truncated\n");
			return -EINVAL;
		}
		int ret = mkdir_structure(path_inside_chroot, 0700);
		if(ret < 0)
		{
			EXILE_LOG_ERROR("Error creating directory structure while mounting paths to chroot. %s\n", strerror(errno));
			return ret;
		}

		int mount_flags = get_policy_mount_flags(path_policy);

		//all we do is bind mounts
		mount_flags |= MS_BIND;


		if(path_policy->policy & EXILE_FS_ALLOW_ALL_READ || path_policy->policy & EXILE_FS_ALLOW_ALL_WRITE)
		{
			ret = mount(path_policy->path, path_inside_chroot,  NULL, mount_flags, NULL);
			if(ret < 0 )
			{
				EXILE_LOG_ERROR("Error: Failed to mount %s to %s: %s\n", path_policy->path, path_inside_chroot, strerror(errno));
				return ret;
			}

			//remount so noexec, readonly etc. take effect
			ret = mount(NULL, path_inside_chroot, NULL, mount_flags | MS_REMOUNT, NULL);
			if(ret < 0 )
			{
				EXILE_LOG_ERROR("Error: Failed to remount %s: %s\n", path_inside_chroot, strerror(errno));
				return ret;
			}
		}
		path_policy = path_policy->next;
	}

	return 0;
}

/*
 * Frees the memory taken by a exile_policy object
 */
void exile_free_policy(struct exile_policy *ctxt)
{
	if(ctxt != NULL)
	{
		struct exile_path_policy *current = ctxt->path_policies;
		while(current != NULL)
		{
			struct exile_path_policy *tmp = current;
			current = current->next;
			free(tmp);
		}

		struct exile_syscall_policy *sc_policy = ctxt->syscall_policies;
		while(sc_policy != NULL)
		{
			struct exile_syscall_policy *tmp = sc_policy;
			sc_policy = sc_policy->next;
			free(tmp);
		}
		free(ctxt);
	}
}

/* Enters the specified namespaces */
static int enter_namespaces(int namespace_options)
{
	if(namespace_options & EXILE_UNSHARE_USER)
	{
		int ret = unshare(CLONE_NEWUSER);
		if(ret == -1)
		{
			EXILE_LOG_ERROR("Error: Failed to unshare user namespaces: %s\n", strerror(errno));
			return ret;
		}

		uid_t current_uid = getuid();
		gid_t current_gid = getgid();

		FILE *fp = fopen("/proc/self/setgroups", "w");
		if(fp == NULL)
		{
			EXILE_LOG_ERROR("fopen failed while trying to deny setgroups\n");
			return -1;
		}
		if(fprintf(fp, "deny") < 0)
		{
			EXILE_LOG_ERROR("fprintf failed while trying to write setgroups\n");
			return -1;
		}
		fclose(fp);

		fp = fopen("/proc/self/uid_map", "w");
		if(fp == NULL)
		{
			EXILE_LOG_ERROR("fopen failed while trying to write uid_map\n");
			return -1;
		}
		if(fprintf(fp, "0 %i", current_uid) < 0)
		{
			EXILE_LOG_ERROR("fprintf failed while trying to write uid_map\n");
			return -1;
		}
		fclose(fp);

		fp = fopen("/proc/self/gid_map", "w");
		if(fp == NULL)
		{
			EXILE_LOG_ERROR("fopen failed while trying to write gid_map\n");
			return -1;
		}
		if(fprintf(fp, "0 %i", current_gid) < 0)
		{
			EXILE_LOG_ERROR("fprintf failed while trying to write gid_map\n");
			return -1;
		}
		fclose(fp);
	}

	if(namespace_options & EXILE_UNSHARE_MOUNT)
	{
		int ret = unshare(CLONE_NEWNS);
		if(ret == -1)
		{
			EXILE_LOG_ERROR("Error: Failed to unshare mount namespaces: %s\n", strerror(errno));
			return ret;
		}
	}

	if(namespace_options & EXILE_UNSHARE_NETWORK)
	{
		int ret = unshare(CLONE_NEWNET);
		if(ret == -1)
		{
			EXILE_LOG_ERROR("Error: Failed to unshare network namespace: %s\n", strerror(errno));
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
		EXILE_LOG_ERROR("Failed to drop the capability bounding set!\n");
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
		EXILE_LOG_ERROR("Failed to drop capabilities: %s\n", strerror(errno));
		return -errno;
	}
	return 0;
}



static void append_syscall_to_bpf(struct exile_syscall_policy *syscallpolicy, struct sock_filter *filter, unsigned short int *start_index)
{
	unsigned int action = syscallpolicy->policy;
	if(action == EXILE_SYSCALL_ALLOW)
	{
		action = SECCOMP_RET_ALLOW;
	}
	if(action == EXILE_SYSCALL_DENY_KILL_PROCESS)
	{
		action = SECCOMP_RET_KILL_PROCESS;
	}
	if(action == EXILE_SYSCALL_DENY_RET_ERROR)
	{
		action = SECCOMP_RET_ERRNO|EACCES;
	}
	long syscall = syscallpolicy->syscall;

	struct sock_filter syscall_load = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr));
	filter[(*start_index)++] = 	syscall_load;
	if(syscall != EXILE_SYSCALL_MATCH_ALL)
	{
			/* How many steps forward to jump when we don't match. This is either the last statement,
			 * i. e. the default action or the next syscall policy */
			__u8 next_syscall_pc =  1;
			if(__builtin_add_overflow(next_syscall_pc,  syscallpolicy->argfilterscount, &next_syscall_pc))
			{
					EXILE_LOG_ERROR("Error: Overflow while trying to calculate jump offset\n");
					/* TODO: Return error */
					return;
			}
			struct sock_filter syscall_check = BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (unsigned int) syscall, 0, next_syscall_pc);
			filter[(*start_index)++] = syscall_check;
			--next_syscall_pc;

			for(size_t i = 0; i < syscallpolicy->argfilterscount; i++)
			{
				filter[*start_index] = syscallpolicy->argfilters[i];
				__u8 jump_count = next_syscall_pc;
				if(filter[*start_index].jt == EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
				{
					filter[*start_index].jt = jump_count;
				}
				if(filter[*start_index].jf == EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
				{
					filter[*start_index].jf = jump_count;
				}
				--next_syscall_pc;
				++*start_index;
			}
	}
	struct sock_filter syscall_action = BPF_STMT(BPF_RET+BPF_K, action);
	/* TODO: we can do better than adding this below every jump */
	filter[(*start_index)++] = syscall_action;
	
}
/*
 * Enables the seccomp policy
 *
 * policy: exile policy object
 *
 * @returns: 0 on success, -1 on error
 */

static int exile_enable_syscall_policy(struct exile_policy *policy)
{
	struct sock_filter filter[1024] =
	{
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS,offsetof(struct seccomp_data, arch)),
		BPF_JUMP (BPF_JMP+BPF_JEQ+BPF_K, SECCOMP_AUDIT_ARCH, 1, 0),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr)),
		BPF_JUMP(BPF_JMP+BPF_JGE+BPF_K, __X32_SYSCALL_BIT, 0, 1),
		BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL_PROCESS),
	};

	unsigned short int current_filter_index = 6;

	struct exile_syscall_policy *current_policy = policy->syscall_policies;
	while(current_policy)
	{
		if(!is_valid_syscall_policy(current_policy->policy))
		{
			EXILE_LOG_ERROR("invalid syscall policy specified\n");
			return -1;
		}
		/* TODO: reintroduce overflow checks */
		append_syscall_to_bpf(current_policy, filter, &current_filter_index);
		current_policy = current_policy->next;
	}

	struct sock_fprog prog = {
		.len = current_filter_index ,
		.filter = filter,
	};

	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1)
	{
		EXILE_LOG_ERROR("prctl SET_SECCOMP %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

#if HAVE_LANDLOCK == 1
static unsigned int exile_flags_to_landlock(unsigned int flags)
{
	unsigned int result = 0;
	if(flags & EXILE_FS_ALLOW_ALL_READ)
	{
		result |= LANDLOCK_ACCESS_FS_READ_FILE;
		result |= LANDLOCK_ACCESS_FS_READ_DIR;
	}
	if(flags & EXILE_FS_ALLOW_ALL_WRITE)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_REG;
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
		result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
		result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
		result |= LANDLOCK_ACCESS_FS_MAKE_SYM;
	}
	if(flags & EXILE_FS_ALLOW_DEV)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
		result |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_BLOCK)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_BLOCK;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_CHAR)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_CHAR;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_DIR;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_FIFO)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_REG)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_REG;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_SOCK)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
	}
	if(flags & EXILE_FS_ALLOW_MAKE_SYM)
	{
		result |= LANDLOCK_ACCESS_FS_MAKE_SYM;
	}
	if(flags & EXILE_FS_ALLOW_REMOVE)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
		result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
	}
	if(flags & EXILE_FS_ALLOW_REMOVE_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
	}
	if(flags & EXILE_FS_ALLOW_REMOVE_FILE)
	{
		result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
	}
	if(flags & EXILE_FS_ALLOW_EXEC)
	{
		result |= LANDLOCK_ACCESS_FS_EXECUTE;
	}
	if(flags & EXILE_FS_ALLOW_WRITE_FILE)
	{
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	}
	if(flags & EXILE_FS_ALLOW_READ_DIR)
	{
		result |= LANDLOCK_ACCESS_FS_READ_DIR;
	}
	return result;
}

static int landlock_prepare_ruleset(struct exile_path_policy *policies)
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
		EXILE_LOG_ERROR("Failed to create landlock ruleset\n");
		return -1;
	}
	struct exile_path_policy *policy = policies;
	while(policy != NULL)
	{
		struct landlock_path_beneath_attr path_beneath;
		path_beneath.parent_fd = open(policy->path, O_PATH | O_CLOEXEC);
		if(path_beneath.parent_fd < 0)
		{
			EXILE_LOG_ERROR("Failed to open policy path %s while preparing landlock ruleset\n", policy->path);
			close(ruleset_fd);
			return path_beneath.parent_fd;
		}
		path_beneath.allowed_access = exile_flags_to_landlock(policy->policy);
		int ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
		if(ret)
		{
			EXILE_LOG_ERROR("Failed to update ruleset while processsing policy path %s\n", policy->path);
			close(ruleset_fd);
			return ret;
		}
		policy = policy->next;
	}
	return ruleset_fd;
}
#endif


/* Checks for illogical or dangerous combinations */
static int check_policy_sanity(struct exile_policy *policy)
{
	if(policy->no_new_privs != 1)
	{
		if(policy->syscall_policies != NULL)
		{
			EXILE_LOG_ERROR("no_new_privs = 1 is required for seccomp filtering!\n");
			return -1;
		}
	}

	/* TODO: check if we have ALLOWED, but no default deny */

	if(policy->mount_path_policies_to_chroot == 1)
	{
		if(policy->path_policies == NULL)
		{
			EXILE_LOG_ERROR("Cannot mount path policies to chroot if non are given\n");
			return -1;
		}
		if(!(policy->namespace_options & EXILE_UNSHARE_MOUNT))
		{
			EXILE_LOG_ERROR("mount_path_policies_to_chroot = 1 requires unsharing mount namespace\n");
			return -1;
		}
	}


	if(policy->path_policies != NULL)
	{

		if(policy->mount_path_policies_to_chroot != 1)
		{
			#if HAVE_LANDLOCK != 1
				EXILE_LOG_ERROR("Path policies cannot be enforced! System needs landlock support or set mount_path_policies_to_chroot = 1\n");
				return -1;
			#endif
		}
		if(policy->no_fs == 1)
		{
			EXILE_LOG_ERROR("If path_policies are specified, no_fs cannot be set to 1\n");
			return -1;
		}
	}

	struct exile_syscall_policy *syscall_policy = policy->syscall_policies;
	if(syscall_policy != NULL)
	{
		/* A few sanitiy checks... but we cannot check overall whether it's reasonable */
		int i = 0;
		int last_match_all = -1;
		int match_all_policy = 0;
		int last_policy = 0;
		while(syscall_policy)
		{
			if(syscall_policy->syscall == EXILE_SYSCALL_MATCH_ALL)
			{
				last_match_all = i;
				match_all_policy = syscall_policy->policy;
			}
			else
			{
				last_policy = syscall_policy->policy;
			}
			syscall_policy = syscall_policy->next;
			++i;
		}
		if(last_match_all == -1 || i - last_match_all != 1)
		{
			EXILE_LOG_ERROR("The last entry in the syscall policy list must match all syscalls (default rule)\n");
			return -1;
		}
		/* Most likely a mistake and not intended */
		if(last_policy == match_all_policy)
		{
			EXILE_LOG_ERROR("Last policy for a syscall matches default policy\n");
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
static int enable_no_fs(struct exile_policy *policy)
{
		close_file_fds();

		if(chdir("/proc/self/fdinfo") != 0)
		{
			EXILE_LOG_ERROR("Failed to change to safe directory: %s\n", strerror(errno));
			return -1;
		}

		if(chroot(".") != 0)
		{
			EXILE_LOG_ERROR("Failed to chroot into safe directory: %s\n", strerror(errno));
			return -1;
		}

		if(chdir("/") != 0)
		{
			EXILE_LOG_ERROR("Failed to chdir into safe directory inside chroot: %s\n", strerror(errno));
			return -1;
		}

		//TODO: we don't have to do this if there whitelisted policies, in that case we will be behind the default deny anyway
		int ret = exile_append_group_syscall_policy(policy, EXILE_SYSCALL_DENY_RET_ERROR, EXILE_SYSCGROUP_FS);
		if(ret != 0)
		{
			EXILE_LOG_ERROR("Failed to add system calls to policy\n");
			return -1;
		}
		if(exile_append_syscall_default_policy(policy, EXILE_SYSCALL_ALLOW) != 0)
		{
			EXILE_LOG_ERROR("Failed to add default policy when adding denied filesystem-related system calls\n");
			return -1;
		}
		return 0;
}

/* Enables the specified exile_policy.
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
int exile_enable_policy(struct exile_policy *policy)
{
	if(check_policy_sanity(policy) != 0)
	{
		EXILE_LOG_ERROR("Error: Policy sanity check failed. Cannot apply policy!\n");
		return -EINVAL;
	}

	if(enter_namespaces(policy->namespace_options) < 0)
	{
		EXILE_LOG_ERROR("Error while trying to enter namespaces\n");
		return -1;
	}

	if(policy->mount_path_policies_to_chroot && policy->path_policies != NULL)
	{
		if(*policy->chroot_target_path == '\0')
		{
			char random_str[17];
			if(random_string(random_str, sizeof(random_str)) == 16)
			{
				int res = snprintf(policy->chroot_target_path, sizeof(policy->chroot_target_path), "%s/.sandbox_%" PRIdMAX "_%s", EXILE_TEMP_DIR, (intmax_t)getpid(), random_str);
				if(res < 0)
				{
					EXILE_LOG_ERROR("exile: exile_enable_policy: error during path concatination\n");
					return -EINVAL;
				}
				if(res >= PATH_MAX)
				{
					EXILE_LOG_ERROR("exile: exile_enable_policy: path concatination truncated\n");
					return -EINVAL;
				}
			}
			else
			{
				EXILE_LOG_ERROR("Error creating random sandbox directory name\n");
				return -1;
			}
		}

		if(mount_to_chroot(policy->chroot_target_path, policy->path_policies) < 0)
		{
			EXILE_LOG_ERROR("mount_to_chroot: bind mounting of path policies failed\n");
			return -1;
		}
	}

	if(*policy->chroot_target_path != '\0')
	{
		if(chroot(policy->chroot_target_path) < 0)
		{
			EXILE_LOG_ERROR("chroot: failed to enter %s\n", policy->chroot_target_path);
			return -1;
		}
		const char *chdir_target_path = policy->chdir_path;
		if(chdir_target_path == NULL)
		{
			chdir_target_path = "/";
		}

		if(chdir(chdir_target_path) < 0)
		{
			EXILE_LOG_ERROR("chdir to %s failed\n", policy->chdir_path);
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
			EXILE_LOG_ERROR("landlock_prepare_ruleset: Failed to prepare landlock ruleset: %s\n", strerror(errno));
			return -1;
		}
	}
#endif

	if(policy->no_fs)
	{
		if(enable_no_fs(policy) != 0)
		{
			EXILE_LOG_ERROR("Failed to take away filesystem access of process\n");
			return -1;
		}
	}

	if(policy->no_new_fds)
	{
		const struct rlimit nofile = {0, 0};
		if (setrlimit(RLIMIT_NOFILE, &nofile) == -1)
		{
			EXILE_LOG_ERROR("setrlimit: Failed to set rlimit: %s\n", strerror(errno));
			return -1;
		}
	}

	if(policy->drop_caps)
	{
		if(drop_caps() < 0)
		{
			EXILE_LOG_ERROR("failed to drop capabilities\n");
			return -1;
		}
	}

	if(policy->not_dumpable)
	{
		if(prctl(PR_SET_DUMPABLE, 0) == -1)
		{
			EXILE_LOG_ERROR("prctl: PR_SET_DUMPABLE failed\n");
			return -1;
		}
	}

	if(policy->no_new_privs)
	{
		if(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1)
		{
			EXILE_LOG_ERROR("prctl: PR_SET_NO_NEW_PRIVS failed: %s\n", strerror(errno));
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

	if(policy->syscall_policies != NULL)
	{
		return exile_enable_syscall_policy(policy);
	}


	return 0;
}
#endif
