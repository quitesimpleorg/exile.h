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
		#error "This landlock ABI version is not supported by qssb (yet)"
	#endif
#endif


#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#else
#error Seccomp support has not been tested for qssb.h for this platform yet
#endif

#define SYSCALL(nr, jt) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (nr), 0, 1), jt


#define QSSB_UNSHARE_NETWORK 1<<1
#define QSSB_UNSHARE_USER 1<<2
#define QSSB_UNSHARE_MOUNT 1<<3

#ifndef QSSB_LOG_ERROR
#define QSSB_LOG_ERROR(...) fprintf(stderr, __VA_ARGS__)
#endif

#ifndef QSSB_TEMP_DIR
#define QSSB_TEMP_DIR "/tmp"
#endif

#define QSSB_SYS(x) __NR_##x

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

#define QSSB_SYSCGROUP_CHROOT ((uint64_t)1<<0)
#define QSSB_SYSCGROUP_CLOCK ((uint64_t)1<<1)
#define QSSB_SYSCGROUP_CLONE ((uint64_t)1<<2)
#define QSSB_SYSCGROUP_DEFAULT_ALLOW ((uint64_t)1<<3)
#define QSSB_SYSCGROUP_DEV ((uint64_t)1<<4)
#define QSSB_SYSCGROUP_EXEC ((uint64_t)1<<5)
#define QSSB_SYSCGROUP_EXIT ((uint64_t)1<<6)
#define QSSB_SYSCGROUP_FANOTIFY ((uint64_t)1<<7)
#define QSSB_SYSCGROUP_FD ((uint64_t)1<<8)
#define QSSB_SYSCGROUP_FS ((uint64_t)1<<9)
#define QSSB_SYSCGROUP_FUTEX ((uint64_t)1<<10)
#define QSSB_SYSCGROUP_HOST ((uint64_t)1<<11)
#define QSSB_SYSCGROUP_ID ((uint64_t)1<<12)
#define QSSB_SYSCGROUP_INOTIFY ((uint64_t)1<<13)
#define QSSB_SYSCGROUP_IO ((uint64_t)1<<14)
#define QSSB_SYSCGROUP_IOCTL ((uint64_t)1<<15)
#define QSSB_SYSCGROUP_IOPL ((uint64_t)1<<16)
#define QSSB_SYSCGROUP_IOURING ((uint64_t)1<<17)
#define QSSB_SYSCGROUP_IPC ((uint64_t)1<<18)
#define QSSB_SYSCGROUP_KEXEC ((uint64_t)1<<19)
#define QSSB_SYSCGROUP_KEYS ((uint64_t)1<<20)
#define QSSB_SYSCGROUP_KILL ((uint64_t)1<<21)
#define QSSB_SYSCGROUP_KMOD ((uint64_t)1<<22)
#define QSSB_SYSCGROUP_LANDLOCK ((uint64_t)1<<23)
#define QSSB_SYSCGROUP_LIB ((uint64_t)1<<24)
#define QSSB_SYSCGROUP_MEMORY ((uint64_t)1<<25)
#define QSSB_SYSCGROUP_MOUNT ((uint64_t)1<<26)
#define QSSB_SYSCGROUP_MQ ((uint64_t)1<<27)
#define QSSB_SYSCGROUP_NEWMOUNT ((uint64_t)1<<28)
#define QSSB_SYSCGROUP_NONE ((uint64_t)1<<29)
#define QSSB_SYSCGROUP_NS ((uint64_t)1<<30)
#define QSSB_SYSCGROUP_PATH ((uint64_t)1<<31)
#define QSSB_SYSCGROUP_PAUSE ((uint64_t)1<<32)
#define QSSB_SYSCGROUP_PERF ((uint64_t)1<<33)
#define QSSB_SYSCGROUP_PERMS ((uint64_t)1<<34)
#define QSSB_SYSCGROUP_PIDFD ((uint64_t)1<<35)
#define QSSB_SYSCGROUP_PKEY ((uint64_t)1<<36)
#define QSSB_SYSCGROUP_POWER ((uint64_t)1<<37)
#define QSSB_SYSCGROUP_PRIO ((uint64_t)1<<38)
#define QSSB_SYSCGROUP_PROCESS ((uint64_t)1<<39)
#define QSSB_SYSCGROUP_PTRACE ((uint64_t)1<<40)
#define QSSB_SYSCGROUP_QUOTA ((uint64_t)1<<41)
#define QSSB_SYSCGROUP_RES ((uint64_t)1<<42)
#define QSSB_SYSCGROUP_RT ((uint64_t)1<<43)
#define QSSB_SYSCGROUP_SCHED ((uint64_t)1<<44)
#define QSSB_SYSCGROUP_SEM ((uint64_t)1<<45)
#define QSSB_SYSCGROUP_SHM ((uint64_t)1<<46)
#define QSSB_SYSCGROUP_SIGNAL ((uint64_t)1<<47)
#define QSSB_SYSCGROUP_SOCKET ((uint64_t)1<<48)
#define QSSB_SYSCGROUP_STAT ((uint64_t)1<<49)
#define QSSB_SYSCGROUP_STDIO ((uint64_t)1<<50)
#define QSSB_SYSCGROUP_SWAP ((uint64_t)1<<51)
#define QSSB_SYSCGROUP_SYS ((uint64_t)1<<52)
#define QSSB_SYSCGROUP_SYSCALL ((uint64_t)1<<53)
#define QSSB_SYSCGROUP_THREAD ((uint64_t)1<<54)
#define QSSB_SYSCGROUP_TIME ((uint64_t)1<<55)
#define QSSB_SYSCGROUP_TIMER ((uint64_t)1<<56)
#define QSSB_SYSCGROUP_TTY ((uint64_t)1<<57)
#define QSSB_SYSCGROUP_UMOUNT ((uint64_t)1<<58)
#define QSSB_SYSCGROUP_UNIMPLEMENTED ((uint64_t)1<<59)
#define QSSB_SYSCGROUP_XATTR ((uint64_t)1<<60)

struct syscall_group_map
{
	long syscall;
	uint64_t groupmask;
};

struct syscall_group_map sc_group_map[] = {
{QSSB_SYS(read), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(write), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(open), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(close), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(stat), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fstat), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(lstat), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(poll), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(lseek), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(mmap), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(mprotect), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(munmap), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(brk), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigaction), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigprocmask), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigreturn), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(ioctl), QSSB_SYSCGROUP_IOCTL|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(pread64), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(pwrite64), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(readv), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(writev), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(access), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(pipe), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(select), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(sched_yield), QSSB_SYSCGROUP_SCHED|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(mremap), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(msync), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(mincore), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(madvise), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(shmget), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(shmat), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(shmctl), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(dup), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(dup2), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(pause), QSSB_SYSCGROUP_PAUSE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(nanosleep), QSSB_SYSCGROUP_TIMER|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getitimer), QSSB_SYSCGROUP_TIMER|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(alarm), QSSB_SYSCGROUP_TIMER|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setitimer), QSSB_SYSCGROUP_TIMER|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getpid), QSSB_SYSCGROUP_PROCESS|QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(sendfile), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(socket), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(connect), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(accept), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(sendto), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(recvfrom), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(sendmsg), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(recvmsg), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(shutdown), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(bind), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(listen), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(getsockname), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(getpeername), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(socketpair), QSSB_SYSCGROUP_SOCKET|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(setsockopt), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(getsockopt), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(clone), QSSB_SYSCGROUP_CLONE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(fork), QSSB_SYSCGROUP_CLONE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(vfork), QSSB_SYSCGROUP_CLONE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(execve), QSSB_SYSCGROUP_CLONE|QSSB_SYSCGROUP_EXEC},
{QSSB_SYS(exit), QSSB_SYSCGROUP_PROCESS|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(wait4), QSSB_SYSCGROUP_EXEC},
{QSSB_SYS(kill), QSSB_SYSCGROUP_KILL},
{QSSB_SYS(uname), QSSB_SYSCGROUP_SYS|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(semget), QSSB_SYSCGROUP_SHM|QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(semop), QSSB_SYSCGROUP_SHM|QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(semctl), QSSB_SYSCGROUP_SHM|QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(shmdt), QSSB_SYSCGROUP_SHM|QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(msgget), QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(msgsnd), QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(msgrcv), QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(msgctl), QSSB_SYSCGROUP_IPC|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(fcntl), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(flock), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(fsync), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(fdatasync), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(truncate), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(ftruncate), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(getdents), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(getcwd), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(chdir), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fchdir), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(rename), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(mkdir), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(rmdir), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(creat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(link), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(unlink), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(symlink), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(readlink), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(chmod), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fchmod), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(chown), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fchown), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(lchown), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(umask), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(gettimeofday), QSSB_SYSCGROUP_TIME|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getrlimit), QSSB_SYSCGROUP_RES|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getrusage), QSSB_SYSCGROUP_RES|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(sysinfo), QSSB_SYSCGROUP_SYS|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(times), QSSB_SYSCGROUP_TIME|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(ptrace), QSSB_SYSCGROUP_PTRACE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getuid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(syslog), QSSB_SYSCGROUP_SYS},
{QSSB_SYS(getgid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setuid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(setgid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(geteuid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getegid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setpgid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(getppid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getpgrp), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setsid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(setreuid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(setregid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(getgroups), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setgroups), QSSB_SYSCGROUP_ID},
{QSSB_SYS(setresuid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(getresuid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setresgid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(getresgid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(getpgid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(setfsuid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(setfsgid), QSSB_SYSCGROUP_ID},
{QSSB_SYS(getsid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(capget), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(capset), QSSB_SYSCGROUP_ID},
{QSSB_SYS(rt_sigpending), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigtimedwait), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigqueueinfo), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(rt_sigsuspend), QSSB_SYSCGROUP_RT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(sigaltstack), QSSB_SYSCGROUP_THREAD|QSSB_SYSCGROUP_SIGNAL},
{QSSB_SYS(utime), QSSB_SYSCGROUP_TIME|QSSB_SYSCGROUP_FS},
{QSSB_SYS(mknod), QSSB_SYSCGROUP_DEV|QSSB_SYSCGROUP_FS},
{QSSB_SYS(uselib), QSSB_SYSCGROUP_LIB|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(personality), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(ustat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_STAT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(statfs), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_STAT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fstatfs), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_STAT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(sysfs), QSSB_SYSCGROUP_SYS|QSSB_SYSCGROUP_FS},
{QSSB_SYS(getpriority), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(setpriority), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_setparam), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_getparam), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_setscheduler), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_getscheduler), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_get_priority_max), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_get_priority_min), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_rr_get_interval), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(mlock), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(munlock), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(mlockall), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(munlockall), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(vhangup), QSSB_SYSCGROUP_TTY},
{QSSB_SYS(modify_ldt), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(pivot_root), QSSB_SYSCGROUP_CHROOT},
{QSSB_SYS(_sysctl), QSSB_SYSCGROUP_SYS},
{QSSB_SYS(prctl), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(arch_prctl), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(adjtimex), QSSB_SYSCGROUP_CLOCK},
{QSSB_SYS(setrlimit), QSSB_SYSCGROUP_RES},
{QSSB_SYS(chroot), QSSB_SYSCGROUP_CHROOT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(sync), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(acct), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(settimeofday), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(mount), QSSB_SYSCGROUP_MOUNT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(umount2), QSSB_SYSCGROUP_UMOUNT|QSSB_SYSCGROUP_FS},
{QSSB_SYS(swapon), QSSB_SYSCGROUP_SWAP},
{QSSB_SYS(swapoff), QSSB_SYSCGROUP_SWAP},
{QSSB_SYS(reboot), QSSB_SYSCGROUP_POWER},
{QSSB_SYS(sethostname), QSSB_SYSCGROUP_HOST},
{QSSB_SYS(setdomainname), QSSB_SYSCGROUP_HOST},
{QSSB_SYS(iopl), QSSB_SYSCGROUP_IOPL},
{QSSB_SYS(ioperm), QSSB_SYSCGROUP_IOPL},
{QSSB_SYS(create_module), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(init_module), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(delete_module), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(get_kernel_syms), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(query_module), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(quotactl), QSSB_SYSCGROUP_QUOTA},
{QSSB_SYS(nfsservctl), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(getpmsg), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(putpmsg), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(afs_syscall), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(tuxcall), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(security), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(gettid), QSSB_SYSCGROUP_ID|QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(readahead), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_FS},
{QSSB_SYS(setxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(lsetxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fsetxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(getxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(lgetxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fgetxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(listxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(llistxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(flistxattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(removexattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(lremovexattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fremovexattr), QSSB_SYSCGROUP_XATTR|QSSB_SYSCGROUP_FS},
{QSSB_SYS(tkill), QSSB_SYSCGROUP_THREAD|QSSB_SYSCGROUP_SIGNAL},
{QSSB_SYS(time), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(futex), QSSB_SYSCGROUP_THREAD|QSSB_SYSCGROUP_FUTEX},
{QSSB_SYS(sched_setaffinity), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_getaffinity), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(set_thread_area), QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(io_setup), QSSB_SYSCGROUP_IO},
{QSSB_SYS(io_destroy), QSSB_SYSCGROUP_IO},
{QSSB_SYS(io_getevents), QSSB_SYSCGROUP_IO},
{QSSB_SYS(io_submit), QSSB_SYSCGROUP_IO},
{QSSB_SYS(io_cancel), QSSB_SYSCGROUP_IO},
{QSSB_SYS(get_thread_area), QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(lookup_dcookie), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_FS},
{QSSB_SYS(epoll_create), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(epoll_ctl_old), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(epoll_wait_old), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(remap_file_pages), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(getdents64), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_FS},
{QSSB_SYS(set_tid_address), QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(restart_syscall), QSSB_SYSCGROUP_SYSCALL},
{QSSB_SYS(semtimedop), QSSB_SYSCGROUP_SEM},
{QSSB_SYS(fadvise64), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_FD},
{QSSB_SYS(timer_create), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(timer_settime), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(timer_gettime), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(timer_getoverrun), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(timer_delete), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(clock_settime), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(clock_gettime), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(clock_getres), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(clock_nanosleep), QSSB_SYSCGROUP_TIME},
{QSSB_SYS(exit_group), QSSB_SYSCGROUP_EXIT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(epoll_wait), QSSB_SYSCGROUP_FD},
{QSSB_SYS(epoll_ctl), QSSB_SYSCGROUP_FD},
{QSSB_SYS(tgkill), QSSB_SYSCGROUP_SIGNAL|QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(utimes), QSSB_SYSCGROUP_PATH},
{QSSB_SYS(vserver), QSSB_SYSCGROUP_UNIMPLEMENTED},
{QSSB_SYS(mbind), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(set_mempolicy), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(get_mempolicy), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(mq_open), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(mq_unlink), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(mq_timedsend), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(mq_timedreceive), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(mq_notify), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(mq_getsetattr), QSSB_SYSCGROUP_MQ|QSSB_SYSCGROUP_IPC},
{QSSB_SYS(kexec_load), QSSB_SYSCGROUP_KEXEC},
{QSSB_SYS(waitid), QSSB_SYSCGROUP_SIGNAL},
{QSSB_SYS(add_key), QSSB_SYSCGROUP_KEYS},
{QSSB_SYS(request_key), QSSB_SYSCGROUP_KEYS},
{QSSB_SYS(keyctl), QSSB_SYSCGROUP_KEYS},
{QSSB_SYS(ioprio_set), QSSB_SYSCGROUP_PRIO},
{QSSB_SYS(ioprio_get), QSSB_SYSCGROUP_PRIO},
{QSSB_SYS(inotify_init), QSSB_SYSCGROUP_INOTIFY},
{QSSB_SYS(inotify_add_watch), QSSB_SYSCGROUP_INOTIFY},
{QSSB_SYS(inotify_rm_watch), QSSB_SYSCGROUP_INOTIFY},
{QSSB_SYS(migrate_pages), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(openat), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(mkdirat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(mknodat), QSSB_SYSCGROUP_DEV|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fchownat), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(futimesat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(newfstatat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(unlinkat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(renameat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(linkat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(symlinkat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(readlinkat), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(fchmodat), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(faccessat), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(pselect6), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(ppoll), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW|QSSB_SYSCGROUP_FS},
{QSSB_SYS(unshare), QSSB_SYSCGROUP_NS|QSSB_SYSCGROUP_FS},
{QSSB_SYS(set_robust_list), QSSB_SYSCGROUP_FUTEX},
{QSSB_SYS(get_robust_list), QSSB_SYSCGROUP_FUTEX},
{QSSB_SYS(splice), QSSB_SYSCGROUP_FD},
{QSSB_SYS(tee), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(sync_file_range), QSSB_SYSCGROUP_FD},
{QSSB_SYS(vmsplice), QSSB_SYSCGROUP_FD},
{QSSB_SYS(move_pages), QSSB_SYSCGROUP_PROCESS},
{QSSB_SYS(utimensat), QSSB_SYSCGROUP_PATH},
{QSSB_SYS(epoll_pwait), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(signalfd), QSSB_SYSCGROUP_SIGNAL},
{QSSB_SYS(timerfd_create), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(eventfd), QSSB_SYSCGROUP_FD},
{QSSB_SYS(fallocate), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_FD},
{QSSB_SYS(timerfd_settime), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(timerfd_gettime), QSSB_SYSCGROUP_TIMER},
{QSSB_SYS(accept4), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(signalfd4), QSSB_SYSCGROUP_FD},
{QSSB_SYS(eventfd2), QSSB_SYSCGROUP_FD},
{QSSB_SYS(epoll_create1), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(dup3), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(pipe2), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(inotify_init1), QSSB_SYSCGROUP_INOTIFY},
{QSSB_SYS(preadv), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(pwritev), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(rt_tgsigqueueinfo), QSSB_SYSCGROUP_RT},
{QSSB_SYS(perf_event_open), QSSB_SYSCGROUP_PERF},
{QSSB_SYS(recvmmsg), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(fanotify_init), QSSB_SYSCGROUP_FANOTIFY},
{QSSB_SYS(fanotify_mark), QSSB_SYSCGROUP_FANOTIFY},
{QSSB_SYS(prlimit64), QSSB_SYSCGROUP_RES},
{QSSB_SYS(name_to_handle_at), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_FS},
{QSSB_SYS(open_by_handle_at), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_FS},
{QSSB_SYS(clock_adjtime), QSSB_SYSCGROUP_CLOCK},
{QSSB_SYS(syncfs), QSSB_SYSCGROUP_FD},
{QSSB_SYS(sendmmsg), QSSB_SYSCGROUP_SOCKET},
{QSSB_SYS(setns), QSSB_SYSCGROUP_NS},
{QSSB_SYS(getcpu), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(process_vm_readv), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(process_vm_writev), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(kcmp), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(finit_module), QSSB_SYSCGROUP_KMOD},
{QSSB_SYS(sched_setattr), QSSB_SYSCGROUP_SCHED},
{QSSB_SYS(sched_getattr), QSSB_SYSCGROUP_SCHED|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(renameat2), QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(seccomp), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(getrandom), QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(memfd_create), QSSB_SYSCGROUP_MEMORY|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(kexec_file_load), QSSB_SYSCGROUP_KEXEC},
{QSSB_SYS(bpf), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(execveat), QSSB_SYSCGROUP_EXEC},
{QSSB_SYS(userfaultfd), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(membarrier), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(mlock2), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(copy_file_range), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(preadv2), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(pwritev2), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(pkey_mprotect), QSSB_SYSCGROUP_PKEY},
{QSSB_SYS(pkey_alloc), QSSB_SYSCGROUP_PKEY},
{QSSB_SYS(pkey_free), QSSB_SYSCGROUP_PKEY},
{QSSB_SYS(statx), QSSB_SYSCGROUP_STAT|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(io_pgetevents), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(rseq), QSSB_SYSCGROUP_THREAD},
{QSSB_SYS(pidfd_send_signal), QSSB_SYSCGROUP_PIDFD},
{QSSB_SYS(io_uring_setup), QSSB_SYSCGROUP_IOURING},
{QSSB_SYS(io_uring_enter), QSSB_SYSCGROUP_IOURING},
{QSSB_SYS(io_uring_register), QSSB_SYSCGROUP_IOURING},
{QSSB_SYS(open_tree), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(move_mount), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(fsopen), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(fsconfig), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(fsmount), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(fspick), QSSB_SYSCGROUP_NEWMOUNT},
{QSSB_SYS(pidfd_open), QSSB_SYSCGROUP_PIDFD},
{QSSB_SYS(clone3), QSSB_SYSCGROUP_CLONE|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(close_range), QSSB_SYSCGROUP_STDIO|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(openat2), QSSB_SYSCGROUP_FD|QSSB_SYSCGROUP_PATH|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(pidfd_getfd), QSSB_SYSCGROUP_PIDFD},
{QSSB_SYS(faccessat2), QSSB_SYSCGROUP_PERMS|QSSB_SYSCGROUP_DEFAULT_ALLOW},
{QSSB_SYS(process_madvise), QSSB_SYSCGROUP_MEMORY},
{QSSB_SYS(epoll_pwait2), QSSB_SYSCGROUP_STDIO},
{QSSB_SYS(mount_setattr), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(quotactl_fd), QSSB_SYSCGROUP_QUOTA},
{QSSB_SYS(landlock_create_ruleset), QSSB_SYSCGROUP_LANDLOCK},
{QSSB_SYS(landlock_add_rule), QSSB_SYSCGROUP_LANDLOCK},
{QSSB_SYS(landlock_restrict_self), QSSB_SYSCGROUP_LANDLOCK},
{QSSB_SYS(memfd_secret), QSSB_SYSCGROUP_NONE},
{QSSB_SYS(process_mrelease), QSSB_SYSCGROUP_NONE}
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
	size_t size; /* number of bytes allocated for data */
	size_t used; /* number of bytes in use */
};

/* Special value */
#define QSSB_SYSCALL_MATCH_ALL -1

#define QSSB_SYSCALL_ALLOW 1
#define QSSB_SYSCALL_DENY_KILL_PROCESS 2
#define QSSB_SYSCALL_DENY_RET_ERROR 3


struct qssb_syscall_policy
{
	struct qssb_allocated_entry syscall;
	unsigned int policy;
	struct qssb_syscall_policy *next;
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
	int disable_syscall_filter;
	/* Bind mounts all paths in path_policies into the chroot and applies
	 non-landlock policies */
	int mount_path_policies_to_chroot;
	char chroot_target_path[PATH_MAX];
	const char *chdir_path;

	/* Do not manually add policies here, use qssb_append_path_polic*() */
	struct qssb_path_policy *path_policies;
	struct qssb_path_policy **path_policies_tail;

	/* Do not manually add policies here, use qssb_append_syscall_policy() */
	struct qssb_syscall_policy *syscall_policies;
	struct qssb_syscall_policy **syscall_policies_tail;

};

static int qssb_entry_append(struct qssb_allocated_entry *entry, void *data, size_t bytes)
{
	size_t remaining = entry->size - entry->used;
	if(remaining < bytes)
	{
		size_t expandval = QSSB_ENTRY_ALLOC_SIZE > bytes ? QSSB_ENTRY_ALLOC_SIZE : bytes;
		size_t sizenew = 0;
		if(__builtin_add_overflow(entry->size, expandval, &sizenew))
		{
			QSSB_LOG_ERROR("overflow in qssb_entry_append\n");
			return -EINVAL;
		}
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

static int qssb_append_syscall(struct qssb_allocated_entry *entry, long *syscalls, size_t n)
{
	size_t bytes = 0;
	if(__builtin_mul_overflow(n, sizeof(long), &bytes))
	{
		QSSB_LOG_ERROR("Overflow while trying to add system calls\n");
		return -EINVAL;
	}
	return qssb_entry_append(entry, syscalls, bytes);
}

static int is_valid_syscall_policy(unsigned int policy)
{
	return policy == QSSB_SYSCALL_ALLOW || policy == QSSB_SYSCALL_DENY_RET_ERROR || policy == QSSB_SYSCALL_DENY_KILL_PROCESS;
}

static void get_syscall_array(struct qssb_syscall_policy *policy, long **syscall, size_t *n)
{
	*syscall = (long *) policy->syscall.data;
	*n = policy->syscall.used / sizeof(long);
}

int qssb_append_syscalls_policy(struct qssb_policy *qssb_policy, unsigned int syscall_policy, long *syscalls, size_t n)
{
	/* Check whether we already have this policy. If so, merge new entries to the existing ones */
	struct qssb_syscall_policy *current_policy = qssb_policy->syscall_policies;
	while(current_policy)
	{
		if(current_policy->policy == syscall_policy)
		{
			return qssb_append_syscall(&current_policy->syscall, syscalls, n);
		}
		current_policy = current_policy->next;
	}

	/* We don't so we create a new policy */
	struct qssb_syscall_policy *newpolicy = (struct qssb_syscall_policy *) calloc(1, sizeof(struct qssb_syscall_policy));
	if(newpolicy == NULL)
	{
		QSSB_LOG_ERROR("Failed to allocate memory for syscall policy\n");
		return -1;
	}

	int ret = qssb_append_syscall(&newpolicy->syscall, syscalls, n);
	if(ret != 0)
	{
		free(newpolicy);
		QSSB_LOG_ERROR("Failed to append syscall\n");
		return -1;
	}

	newpolicy->next = NULL;
	newpolicy->policy = syscall_policy;

	*(qssb_policy->syscall_policies_tail) = newpolicy;
	qssb_policy->syscall_policies_tail = &(newpolicy->next);

	qssb_policy->disable_syscall_filter = 0;
	return 0;
}

int qssb_append_syscall_policy(struct qssb_policy *qssb_policy, unsigned int syscall_policy, long syscall)
{
	return qssb_append_syscalls_policy(qssb_policy, syscall_policy, &syscall, 1);
}

int qssb_append_syscall_default_policy(struct qssb_policy *qssb_policy, unsigned int default_policy)
{
	return qssb_append_syscall_policy(qssb_policy, default_policy, QSSB_SYSCALL_MATCH_ALL);
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

int qssb_append_group_syscall_policy(struct qssb_policy *qssb_policy, unsigned int syscall_policy, uint64_t groupmask)
{
	long syscalls[400] = { 0 };
	size_t n = 0;
	get_group_syscalls(groupmask, syscalls, &n);
	if(n == 0)
	{
		QSSB_LOG_ERROR("Error: No syscalls found for group mask\n");
		return -EINVAL;
	}

	return qssb_append_syscalls_policy(qssb_policy, syscall_policy, syscalls, n);
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
				QSSB_LOG_ERROR("Error: Failed to remount %s: %s\n", path_inside_chroot, strerror(errno));
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

		struct qssb_syscall_policy *sc_policy = ctxt->syscall_policies;
		while(sc_policy != NULL)
		{
			struct qssb_syscall_policy *tmp = sc_policy;
			sc_policy = sc_policy->next;
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

		FILE *fp = fopen("/proc/self/setgroups", "w");
		if(fp == NULL)
		{
			QSSB_LOG_ERROR("fopen failed while trying to deny setgroups\n");
			return -1;
		}
		if(fprintf(fp, "deny") < 0)
		{
			QSSB_LOG_ERROR("fprintf failed while trying to write uid_map\n");
			return -1;
		}
		fclose(fp);

		fp = fopen("/proc/self/uid_map", "w");
		if(fp == NULL)
		{
			QSSB_LOG_ERROR("fopen failed while trying to write uid_map\n");
			return -1;
		}
		if(fprintf(fp, "0 %i", current_uid) < 0)
		{
			QSSB_LOG_ERROR("fprintf failed while trying to write uid_map\n");
			return -1;
		}
		fclose(fp);

		fp = fopen("/proc/self/gid_map", "w");
		if(fp == NULL)
		{
			QSSB_LOG_ERROR("fopen failed while trying to write gid_map\n");
			return -1;
		}
		if(fprintf(fp, "0 %i", current_gid) < 0)
		{
			QSSB_LOG_ERROR("fprintf failed while trying to write gid_map\n");
			return -1;
		}
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
		QSSB_LOG_ERROR("Failed to drop the capability bounding set!\n");
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



static void append_syscalls_to_bpf(long *syscalls, size_t n, unsigned int action, struct sock_filter *filter, unsigned short int *start_index)
{
	if(action == QSSB_SYSCALL_ALLOW)
	{
		action = SECCOMP_RET_ALLOW;
	}
	if(action == QSSB_SYSCALL_DENY_KILL_PROCESS)
	{
		action = SECCOMP_RET_KILL_PROCESS;
	}
	if(action == QSSB_SYSCALL_DENY_RET_ERROR)
	{
		action = SECCOMP_RET_ERRNO|EACCES;
	}
	for(size_t i = 0; i < n; i++)
	{
		long syscall = syscalls[i];
		if(syscall != QSSB_SYSCALL_MATCH_ALL)
		{
			struct sock_filter syscall_check = BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, (unsigned int) syscall, 0, 1);
			filter[(*start_index)++] = syscall_check;
		}
		struct sock_filter syscall_action = BPF_STMT(BPF_RET+BPF_K, action);
		/* TODO: we can do better than adding this below every jump */
		filter[(*start_index)++] = syscall_action;
	}
}
/*
 * Enables the seccomp policy
 *
 * policy: qssb policy object
 *
 * @returns: 0 on success, -1 on error
 */

static int qssb_enable_syscall_policy(struct qssb_policy *policy)
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

	struct qssb_syscall_policy *current_policy = policy->syscall_policies;
	while(current_policy)
	{
		if(!is_valid_syscall_policy(current_policy->policy))
		{
			QSSB_LOG_ERROR("invalid syscall policy specified\n");
			return -1;
		}
		long *syscalls = NULL;
		size_t n = 0;
		get_syscall_array(current_policy, &syscalls, &n);
		unsigned short int newsize;
		if(__builtin_add_overflow(current_filter_index, n, &newsize))
		{
			QSSB_LOG_ERROR("Overflow when trying to add new system calls\n");
			return -EINVAL;
		}
		if(newsize > (sizeof(filter)/sizeof(filter[0]))-1)
		{
			QSSB_LOG_ERROR("Too many system calls added\n");
			return -EINVAL;
		}
		append_syscalls_to_bpf(syscalls, n, current_policy->policy, filter, &current_filter_index);
		current_policy = current_policy->next;
	}

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
		QSSB_LOG_ERROR("Failed to create landlock ruleset\n");
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
	if(policy->no_new_privs != 1)
	{
		if(policy->syscall_policies != NULL)
		{
			QSSB_LOG_ERROR("no_new_privs = 1 is required for seccomp filtering!\n");
			return -1;
		}
	}

	/* TODO: check if we have ALLOWED, but no default deny */

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
			QSSB_LOG_ERROR("If path_policies are specified, no_fs cannot be set to 1\n");
			return -1;
		}
	}

	struct qssb_syscall_policy *syscall_policy = policy->syscall_policies;
	if(syscall_policy != NULL)
	{
		/* A few sanitiy checks... but we cannot check overall whether it's reasonable */
		int i = 0;
		int last_match_all = -1;
		int match_all_policy = 0;
		int last_policy = 0;
		while(syscall_policy)
		{
			long *syscall;
			size_t n = 0;
			get_syscall_array(syscall_policy, &syscall, &n);
			if(syscall[n-1] == QSSB_SYSCALL_MATCH_ALL)
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
			QSSB_LOG_ERROR("The last entry in the syscall policy list must match all syscalls (default rule)\n");
			return -1;
		}
		/* Most likely a mistake and not intended */
		if(last_policy == match_all_policy)
		{
			QSSB_LOG_ERROR("Last policy for a syscall matches default policy\n");
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

		//TODO: we don't have to do this if there whitelisted policies, in that case we will be behind the default deny anyway
		int ret = qssb_append_group_syscall_policy(policy, QSSB_SYSCALL_DENY_RET_ERROR, QSSB_SYSCGROUP_FS);
		if(ret != 0)
		{
			QSSB_LOG_ERROR("Failed to add system calls to policy\n");
			return -1;
		}
		if(qssb_append_syscall_default_policy(policy, QSSB_SYSCALL_ALLOW) != 0)
		{
			QSSB_LOG_ERROR("Failed to add default policy when adding denied filesystem-related system calls\n");
			return -1;
		}
		return 0;
}

static int qssb_append_predefined_standard_syscall_policy(struct qssb_policy *policy)
{
	int appendresult = qssb_append_group_syscall_policy(policy, QSSB_SYSCALL_ALLOW, QSSB_SYSCGROUP_DEFAULT_ALLOW);
	if(appendresult != 0)
	{
		return 1;
	}
	appendresult = qssb_append_syscall_default_policy(policy, QSSB_SYSCALL_DENY_RET_ERROR);
	if(appendresult != 0)
	{
		return 1;
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

	if(policy->syscall_policies == NULL && policy->disable_syscall_filter == 0)
	{
			if(qssb_append_predefined_standard_syscall_policy(policy) != 0)
			{
				QSSB_LOG_ERROR("Failed to add standard predefined syscall policy\n");
				return -1;
			}
	}

	if(policy->syscall_policies != NULL)
	{
		return qssb_enable_syscall_policy(policy);
	}

	return 0;
}
#endif
