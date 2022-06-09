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

#include "exile.h"

static struct syscall_vow_map exile_vow_map[] =
{
	{EXILE_SYS(read), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(write), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(open), EXILE_SYSCALL_VOW_RPATH|EXILE_SYSCALL_VOW_WPATH},
	{EXILE_SYS(close), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(stat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(fstat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(lstat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(poll), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(lseek), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mmap), EXILE_SYSCALL_VOW_STDIO|EXILE_SYSCALL_VOW_PROT_EXEC},
	{EXILE_SYS(mprotect), EXILE_SYSCALL_VOW_STDIO|EXILE_SYSCALL_VOW_PROT_EXEC},
	{EXILE_SYS(munmap), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(brk), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigaction), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigprocmask), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigreturn), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(ioctl), EXILE_SYSCALL_VOW_STDIO|EXILE_SYSCALL_VOW_IOCTL},
	{EXILE_SYS(pread64), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(pwrite64), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(readv), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(writev), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(access), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(pipe), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(select), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sched_yield), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mremap), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(msync), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mincore), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(madvise), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(shmget), EXILE_SYSCALL_VOW_SHM},
	{EXILE_SYS(shmat), EXILE_SYSCALL_VOW_SHM},
	{EXILE_SYS(shmctl), EXILE_SYSCALL_VOW_SHM},
	{EXILE_SYS(dup), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(dup2), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(pause), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(nanosleep), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getitimer), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(alarm), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setitimer), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getpid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sendfile), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(socket), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(connect), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(accept), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(sendto), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(recvfrom), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sendmsg), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(recvmsg), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(shutdown), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(bind), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(listen), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(getsockname), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(getpeername), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(socketpair), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setsockopt), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(getsockopt), EXILE_SYSCALL_VOW_INET|EXILE_SYSCALL_VOW_UNIX},
	{EXILE_SYS(clone), EXILE_SYSCALL_VOW_CLONE|EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(fork), EXILE_SYSCALL_VOW_CLONE},
	{EXILE_SYS(vfork), EXILE_SYSCALL_VOW_CLONE},
	{EXILE_SYS(execve), EXILE_SYSCALL_VOW_EXEC},
	{EXILE_SYS(exit), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(wait4), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(kill), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(uname), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(semget), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(semop), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(semctl), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(shmdt), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(msgget), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(msgsnd), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(msgrcv), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(msgctl), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fcntl), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(flock), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fsync), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fdatasync), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(truncate), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(ftruncate), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getdents), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(getcwd), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(chdir), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(fchdir), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(rename), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(mkdir), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(rmdir), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(creat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(link), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(unlink), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(symlink), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(readlink), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(chmod), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(fchmod), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(chown), EXILE_SYSCALL_VOW_CHOWN},
	{EXILE_SYS(fchown), EXILE_SYSCALL_VOW_CHOWN},
	{EXILE_SYS(lchown), EXILE_SYSCALL_VOW_CHOWN},
	{EXILE_SYS(umask), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(gettimeofday), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getrlimit), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getrusage), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sysinfo), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(times), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getuid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getgid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setuid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(setgid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(geteuid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getegid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setpgid), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(getppid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getpgrp), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setsid), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(setreuid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(setregid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(getgroups), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setgroups), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(setresuid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(getresuid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setresgid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(getresgid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getpgid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setfsuid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(setfsgid), EXILE_SYSCALL_VOW_ID},
	{EXILE_SYS(getsid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(capget), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigpending), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigtimedwait), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigqueueinfo), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(rt_sigsuspend), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(utime), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(mknod), EXILE_SYSCALL_VOW_DPATH},
	{EXILE_SYS(uselib), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(ustat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(statfs), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(fstatfs), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(getpriority), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(setpriority), EXILE_SYSCALL_VOW_SCHED|EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(sched_setparam), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_getparam), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_setscheduler), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_getscheduler), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_get_priority_max), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_get_priority_min), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_rr_get_interval), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(mlock), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(munlock), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mlockall), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(munlockall), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(vhangup), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(prctl), EXILE_SYSCALL_VOW_STDIO|EXILE_SYSCALL_VOW_PRCTL|EXILE_SYSCALL_VOW_SECCOMP_INSTALL},
	{EXILE_SYS(arch_prctl), EXILE_SYSCALL_VOW_STDIO|EXILE_SYSCALL_VOW_PRCTL},
	{EXILE_SYS(setrlimit), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(sync), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(gettid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(readahead), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(setxattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(lsetxattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(fsetxattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(getxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(lgetxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(fgetxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(listxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(llistxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(flistxattr), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(removexattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(lremovexattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(fremovexattr), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(tkill), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(time), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(futex), EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(sched_getaffinity), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(set_thread_area), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(get_thread_area), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(lookup_dcookie), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_create), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_ctl_old), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_wait_old), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(remap_file_pages), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getdents64), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(set_tid_address), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(semtimedop), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fadvise64), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timer_create), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timer_settime), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timer_gettime), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timer_getoverrun), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timer_delete), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(clock_gettime), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(clock_getres), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(clock_nanosleep), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(exit_group), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_wait), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_ctl), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(tgkill), EXILE_SYSCALL_VOW_PROC},
	{EXILE_SYS(utimes), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(mbind), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(get_mempolicy), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_open), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_unlink), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_timedsend), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_timedreceive), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_notify), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(mq_getsetattr), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(waitid), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(inotify_init), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(inotify_add_watch), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(inotify_rm_watch), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(openat), EXILE_SYSCALL_VOW_RPATH|EXILE_SYSCALL_VOW_WPATH},
	{EXILE_SYS(mkdirat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(mknodat), EXILE_SYSCALL_VOW_DPATH},
	{EXILE_SYS(fchownat), EXILE_SYSCALL_VOW_CHOWN},
	{EXILE_SYS(futimesat), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(newfstatat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(unlinkat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(renameat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(linkat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(symlinkat), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(readlinkat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(fchmodat), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(faccessat), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(pselect6), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(ppoll), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(set_robust_list), EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(get_robust_list), EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(splice), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(tee), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sync_file_range), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(vmsplice), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(move_pages), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(utimensat), EXILE_SYSCALL_VOW_FATTR},
	{EXILE_SYS(epoll_pwait), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(signalfd), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timerfd_create), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(eventfd), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fallocate), EXILE_SYSCALL_VOW_WPATH|EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(timerfd_settime), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(timerfd_gettime), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(accept4), EXILE_SYSCALL_VOW_UNIX|EXILE_SYSCALL_VOW_INET},
	{EXILE_SYS(signalfd4), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(eventfd2), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_create1), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(dup3), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(pipe2), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(inotify_init1), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(preadv), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(pwritev), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(recvmmsg), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(fanotify_init), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(fanotify_mark), EXILE_SYSCALL_VOW_FSNOTIFY},
	{EXILE_SYS(prlimit64), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(open_by_handle_at), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(sendmmsg), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(getcpu), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(sched_setattr), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(sched_getattr), EXILE_SYSCALL_VOW_SCHED},
	{EXILE_SYS(renameat2), EXILE_SYSCALL_VOW_CPATH},
	{EXILE_SYS(getrandom), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(memfd_create), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(execveat), EXILE_SYSCALL_VOW_EXEC},
	{EXILE_SYS(mlock2), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(copy_file_range), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(statx), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(rseq), EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(clone3), EXILE_SYSCALL_VOW_CLONE|EXILE_SYSCALL_VOW_THREAD},
	{EXILE_SYS(close_range), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(openat2), EXILE_SYSCALL_VOW_RPATH|EXILE_SYSCALL_VOW_WPATH},
	{EXILE_SYS(faccessat2), EXILE_SYSCALL_VOW_RPATH},
	{EXILE_SYS(process_madvise), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(epoll_pwait2), EXILE_SYSCALL_VOW_STDIO},
	{EXILE_SYS(futex_waitv), EXILE_SYSCALL_VOW_THREAD}
};

struct str_to_vow_map str_to_vow_map[] =
{
	{ "chown", EXILE_SYSCALL_VOW_CHOWN},
	{ "clone", EXILE_SYSCALL_VOW_CLONE},
	{ "cpath", EXILE_SYSCALL_VOW_CPATH},
	{ "dpath", EXILE_SYSCALL_VOW_DPATH},
	{ "exec", EXILE_SYSCALL_VOW_EXEC},
	{ "fattr", EXILE_SYSCALL_VOW_FATTR},
	{ "fsnotify", EXILE_SYSCALL_VOW_FSNOTIFY},
	{ "id", EXILE_SYSCALL_VOW_ID},
	{ "inet", EXILE_SYSCALL_VOW_INET},
	{ "ioctl", EXILE_SYSCALL_VOW_IOCTL},
	{ "prctl", EXILE_SYSCALL_VOW_PRCTL},
	{ "proc", EXILE_SYSCALL_VOW_PROC},
	{ "prot_exec", EXILE_SYSCALL_VOW_PROT_EXEC},
	{ "rpath", EXILE_SYSCALL_VOW_RPATH},
	{ "sched", EXILE_SYSCALL_VOW_SCHED},
	{ "seccomp_install", EXILE_SYSCALL_VOW_SECCOMP_INSTALL},
	{ "shm", EXILE_SYSCALL_VOW_SHM},
	{ "stdio", EXILE_SYSCALL_VOW_STDIO},
	{ "thread", EXILE_SYSCALL_VOW_THREAD},
	{ "unix", EXILE_SYSCALL_VOW_UNIX},
	{ "wpath", EXILE_SYSCALL_VOW_WPATH},
	{ "error", EXILE_SYSCALL_VOW_DENY_ERROR}
};

/* Converts the whitespace separated vows strings to vows flags
 *
 * This mainly helps readability, as lots of flags ORed together is not
 * very readable.
 *
 * If an unkown string is found, abort() is called.
 */
uint64_t exile_vows_from_str(const char *str)
{
	uint64_t result = 0;
	char current[64] = { 0 };
	char *ptr = current;
	const char *end = ptr + sizeof(current)-1;
	do
	{
		while(ptr <= end && *str != '\0' && *str != ' ')
		{
			*ptr = *str;
			++ptr;
			++str;
		}
		int found = 0;
		for(size_t i = 0; i < sizeof(str_to_vow_map)/sizeof(str_to_vow_map[0]); i++)
		{
			if(strcmp(str_to_vow_map[i].str, current) == 0)
			{
				result |= str_to_vow_map[i].value;
				found = 1;
				break;
			}
		}
		if(!found)
		{
			EXILE_LOG_ERROR("No such vow: %s\n", current);
			abort();
		}
		memset(current, 0, sizeof(current));
		ptr = current;
	} while(*str++ != '\0');
	return result;
}

inline int exile_landlock_is_available()
{
	#if HAVE_LANDLOCK == 1
	int ruleset = landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	return ruleset == 1;
	#endif
	return 0;
}
int exile_append_syscall_policy(struct exile_policy *exile_policy, long syscall, unsigned int syscall_policy, struct sock_filter *argfilters, size_t n)
{
	struct exile_syscall_policy *newpolicy = (struct exile_syscall_policy *) calloc(1, sizeof(struct exile_syscall_policy));
	if(newpolicy == NULL)
	{
		EXILE_LOG_ERROR("Failed to allocate memory for syscall policy\n");
		exile_policy->exile_flags |= EXILE_FLAG_ADD_SYSCALL_POLICY_FAIL;
		return -1;
	}
	newpolicy->policy = syscall_policy;
	newpolicy->syscall = syscall;
	newpolicy->argfilterscount = n;
	if(n > EXILE_ARGFILTERS_COUNT)
	{
		EXILE_LOG_ERROR("Too many argfilters supplied\n");
		exile_policy->exile_flags |= EXILE_FLAG_ADD_SYSCALL_POLICY_FAIL;
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

#define COUNT_EXILE_SYSCALL_FILTER(f) \
	sizeof(f)/sizeof(f[0])

#define EXILE_SYSCALL_FILTER_LOAD_ARG(val) \
{ 0, EXILE_BPF_LOAD_SECCOMP_ARG(val), 0}

/* Returns, for the specific syscall, the correct sock_filter struct for the provided vow_promises
 *
 *	Returns: 0 if none copied, otherwise the number of entries in "filter".
 */
int get_vow_argfilter(long syscall, uint64_t vow_promises, struct sock_filter *filter , int *policy)
{

	/* How to read this:
	 * Keep in mind our default action is to deny, unless it's a syscall from a vow promise. Then it will be
	 * accepted if the argument values are good (if we care about them at all).
	 * EXILE_BPF_MATCH() means the argument value is good, and the syscall can be accepted without further checks
	 * EXILE_BPF_NO_MATCH() means the syscall won't be allowed because the value is illegal
	 *
	 * First field (vowmask): The mask to check
	 * Last field (whenset): If mask is set in vow_promises, then add this filter, otherwise don't.
	 */

	struct exile_syscall_filter mmap_filter[] = {
		EXILE_SYSCALL_FILTER_LOAD_ARG(2),
		{ EXILE_SYSCALL_VOW_PROT_EXEC, EXILE_BPF_NO_MATCH_SET(PROT_EXEC), 0},
	};


	struct exile_syscall_filter ioctl_filter[] = {
		EXILE_SYSCALL_FILTER_LOAD_ARG(1),
		{ EXILE_SYSCALL_VOW_IOCTL, EXILE_BPF_NO_MATCH_SET(TIOCSTI), 1 },
		{ EXILE_SYSCALL_VOW_IOCTL, EXILE_BPF_RETURN_MATCHING, 1 },
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(FIONREAD), 1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(FIONBIO), 1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(FIONREAD), 1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(FIOCLEX), 1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(FIONCLEX), 1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_RETURN_NOT_MATCHING, 1}
	};

	struct exile_syscall_filter open_filter[] = {
		EXILE_SYSCALL_FILTER_LOAD_ARG(1),
		{ EXILE_SYSCALL_VOW_CPATH, EXILE_BPF_NO_MATCH_SET(O_CREAT), 0 },
		{ EXILE_SYSCALL_VOW_WPATH, EXILE_BPF_NO_MATCH_SET(O_TMPFILE),0 },
		{ EXILE_SYSCALL_VOW_WPATH, EXILE_BPF_NO_MATCH_SET(O_WRONLY),0 },
		{ EXILE_SYSCALL_VOW_WPATH, EXILE_BPF_NO_MATCH_SET(O_RDWR),0 },
		{ EXILE_SYSCALL_VOW_WPATH, EXILE_BPF_NO_MATCH_SET(O_APPEND),0 },
	};

	struct exile_syscall_filter socket_filter[] = {
		EXILE_SYSCALL_FILTER_LOAD_ARG(0),
		{ EXILE_SYSCALL_VOW_UNIX, EXILE_BPF_MATCH(AF_UNIX), 1 },
		{ EXILE_SYSCALL_VOW_INET, EXILE_BPF_MATCH(AF_INET), 1 },
		{ EXILE_SYSCALL_VOW_INET, EXILE_BPF_MATCH(AF_INET6), 1 },
		{ 0, EXILE_BPF_RETURN_NOT_MATCHING, 0}
	};

	struct exile_syscall_filter setsockopt_filter[] = {
		EXILE_SYSCALL_FILTER_LOAD_ARG(2),
		{ 0, EXILE_BPF_NO_MATCH(SO_DEBUG), 0 },
		{ 0, EXILE_BPF_NO_MATCH(SO_SNDBUFFORCE), 0 }
	};


	struct exile_syscall_filter clone_filter[] = {
		/* It's the first (0) argument for x86_64 */
		EXILE_SYSCALL_FILTER_LOAD_ARG(0),
		{ EXILE_SYSCALL_VOW_CLONE, EXILE_BPF_RETURN_MATCHING, 1 },
		{ EXILE_SYSCALL_VOW_THREAD, EXILE_BPF_CMP_SET(CLONE_VM, 0, EXILE_SYSCALL_EXIT_BPF_NO_MATCH), 1},
		{ EXILE_SYSCALL_VOW_THREAD, EXILE_BPF_CMP_SET(CLONE_THREAD, 0, EXILE_SYSCALL_EXIT_BPF_NO_MATCH), 1},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWCGROUP), 0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWIPC),0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWNET),0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWNS),0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWPID),0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWUSER),0},
		{ 0, EXILE_BPF_NO_MATCH_SET(CLONE_NEWUTS),0},
	};


	struct exile_syscall_filter prctl_filter[] ={
		EXILE_SYSCALL_FILTER_LOAD_ARG(0),
		{ EXILE_SYSCALL_VOW_PRCTL, EXILE_BPF_RETURN_MATCHING, 1},
		{ EXILE_SYSCALL_VOW_SECCOMP_INSTALL, EXILE_BPF_MATCH(PR_SET_SECCOMP), 1 },
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(PR_SET_NO_NEW_PRIVS),1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(PR_GET_NO_NEW_PRIVS),1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(PR_GET_NAME),1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(PR_SET_NAME),1},
		{ EXILE_SYSCALL_VOW_STDIO, EXILE_BPF_MATCH(PR_CAPBSET_READ), 1},
		{ 0, EXILE_BPF_RETURN_NOT_MATCHING, 0}
	};

	struct exile_syscall_filter *current_filter = NULL;
	size_t current_count = 0;

	*policy = EXILE_SYSCALL_ALLOW;
	switch(syscall)
	{
		case EXILE_SYS(mmap):
		case EXILE_SYS(mprotect):
			current_filter = mmap_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(mmap_filter);
			break;
		case EXILE_SYS(ioctl):
			current_filter = ioctl_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(ioctl_filter);
			break;
		case EXILE_SYS(open):
		case EXILE_SYS(openat):
		case EXILE_SYS(open_by_handle_at):
			if(syscall == EXILE_SYS(openat) || syscall ==  EXILE_SYS(open_by_handle_at))
			{
				/* for openat, it's the third arg */
				open_filter[0] = (struct exile_syscall_filter) EXILE_SYSCALL_FILTER_LOAD_ARG(2);
			}
			current_filter = open_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(open_filter);
			break;
		case EXILE_SYS(openat2):
			*policy = EXILE_SYSCALL_DENY_RET_NOSYS;
			return 0;
			break;
		case EXILE_SYS(socket):
			current_filter = socket_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(socket_filter);
			break;
		case EXILE_SYS(setsockopt):
			current_filter = setsockopt_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(setsockopt_filter);
			break;
		case EXILE_SYS(clone):
			current_filter = clone_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(clone_filter);
			break;
		case EXILE_SYS(clone3):
			if((vow_promises & EXILE_SYSCALL_VOW_CLONE) == 0)
			{
				*policy = EXILE_SYSCALL_DENY_RET_NOSYS;
				return 0;
			}
			break;
		case EXILE_SYS(prctl):
			current_filter = prctl_filter;
			current_count = COUNT_EXILE_SYSCALL_FILTER(prctl_filter);
			break;
	}

	int out_filter_index = 0;
	for(size_t i = 0; i < current_count; i++)
	{
		struct exile_syscall_filter *c = &current_filter[i];
		int set = 0;
		if(c->vowmask & vow_promises)
		{
			set = 1;
		}
		if(c->whenset == set || c->vowmask == 0)
		{
			filter[out_filter_index++] = c->filter;
		}
	}
	return out_filter_index;
}

int exile_append_vow_promises(struct exile_policy *policy, uint64_t vow_promises)
{
	for(unsigned int i = 0; i < sizeof(exile_vow_map)/sizeof(exile_vow_map[0]); i++)
	{
		struct syscall_vow_map *current_map = &exile_vow_map[i];
		if(current_map->vowmask & vow_promises)
		{
			struct sock_filter filter[EXILE_ARGFILTERS_COUNT];
			long syscall = current_map->syscall;
			int syscall_policy = EXILE_SYSCALL_ALLOW;
			int argfilters = get_vow_argfilter(syscall, vow_promises, filter, &syscall_policy);
			int ret = exile_append_syscall_policy(policy, syscall, syscall_policy, filter, argfilters);
			if(ret != 0)
			{
				EXILE_LOG_ERROR("Failed adding syscall policy from vow while processing %li\n", syscall);
				return ret;
			}
		}
	}
	int vow_policy = (vow_promises & EXILE_SYSCALL_VOW_DENY_ERROR) ? EXILE_SYSCALL_DENY_RET_ERROR : EXILE_SYSCALL_DENY_KILL_PROCESS;
	return exile_append_syscall_default_policy(policy, vow_policy);
}

/* Creates an empty policy struct without opinionated defaults.
 *
 * Must be freed using exile_free_policy()
 * @returns: empty policy
 */
struct exile_policy *exile_create_policy()
{
	struct exile_policy *result = (struct exile_policy *) calloc(1, sizeof(struct exile_policy));
	if(result == NULL)
	{
		EXILE_LOG_ERROR("Failed to allocate memory for policy\n");
		return NULL;
	}
	result->path_policies_tail = &(result->path_policies);
	result->syscall_policies_tail = &(result->syscall_policies);
	return result;
}

/* Creates the default policy
 * Must be freed using exile_free_policy()
 *
 * @returns: default policy
 */
struct exile_policy *exile_init_policy()
{
	struct exile_policy *result = exile_create_policy();
	if(result == NULL)
	{
		return NULL;
	}
	result->drop_caps = 1;
	result->not_dumpable = 1;
	result->no_new_privs = 1;
	result->namespace_options = EXILE_UNSHARE_MOUNT | EXILE_UNSHARE_USER;
	return result;
}


/* Appends path policies to the exile_policy object
 * The last paramater must be NULL
 *
 * This function does not copy parameters. All passed paths
 * MUST NOT be freed until exile_enable_policy() is called!
 *
 * @returns: 0 on success, -1 on failure */
int (exile_append_path_policies)(struct exile_policy *exile_policy, unsigned int path_policy, ...)
{
	va_list args;
	const char *path;
	va_start(args, path_policy);

	path = va_arg(args, char*);
	while(path != NULL)
	{
		int fd = open(path, O_PATH);
		if(fd == -1)
		{
			EXILE_LOG_ERROR("Failed to open %s: %s\n", path, strerror(errno));
			exile_policy->exile_flags |= EXILE_FLAG_ADD_PATH_POLICY_FAIL;
			return -1;
		}
		close(fd);
		struct exile_path_policy *newpolicy = (struct exile_path_policy *) calloc(1, sizeof(struct exile_path_policy));
		if(newpolicy == NULL)
		{
			EXILE_LOG_ERROR("Failed to allocate memory for path policy\n");
			exile_policy->exile_flags |= EXILE_FLAG_ADD_PATH_POLICY_FAIL;
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


/* Creates a directory/file and all necessary parent directories
* @returns: 0 on success, -ERRNO on failure
*/
int mkpath(const char *p, mode_t mode, int baseisfile)
{
	char path[PATH_MAX + 1] = {0};
	int ret = snprintf(path, sizeof(path), "%s%c", p, (baseisfile) ? '\0' : '/');
	if(ret < 0)
	{
		EXILE_LOG_ERROR("error during path concatination\n");
		return -EINVAL;
	}
	if((size_t)ret >= sizeof(path))
	{
		EXILE_LOG_ERROR("path concatination truncated\n");
		return -EINVAL;
	}

	char *begin = path;
	char *end = begin + 1;

	while(*end)
	{
		if(*end == '/')
		{
			*end = 0;
			if(mkdir(begin, mode) < 0)
			{
				if(errno != EEXIST)
				{
					EXILE_LOG_ERROR("Failed to create directory: %s\n", begin);
					return -1;
				}
			}
			*end = '/';
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
	if(baseisfile)
	{
		ret = creat(p, mode);
		if(ret == -1)
		{
			EXILE_LOG_ERROR("Failed to create file: %s\n", begin);
			return ret;
		}
		close(ret);
		return 0;
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

int path_policy_needs_landlock(struct exile_path_policy *path_policy)
{
	unsigned int policy = path_policy->policy;
#if HAVE_LANDLOCK == 1
	if(policy >= EXILE_FS_ALLOW_REMOVE_DIR)
	{
		return 1;
	}
#endif
	//Can't need it if we don't have support at compile time
	return 0;
}

/* TODO: we can do va_args */
char *concat_path(const char *first, const char *second)
{
	char *result = (char *) calloc(1, PATH_MAX);
	if(result == NULL)
	{
		EXILE_LOG_ERROR("calloc failed\n");
		return NULL;
	}
	//TODO: We can strip multiple redundant slashes
	int written = snprintf(result, PATH_MAX, "%s/%s", first, second);
	if(written < 0)
	{
		EXILE_LOG_ERROR("Error during path concatination\n");
		return NULL;
	}
	if(written >= PATH_MAX)
	{
		EXILE_LOG_ERROR("path concatination truncated\n");
		return NULL;
	}
	return result;
}


/* Creates the file system hierarchy for the chroot
 * @returns: 0 on sucess, -ERRNO on failure */
static int create_chroot_dirs(const char *chroot_target_path, struct exile_path_policy *path_policy)
{
	while(path_policy != NULL)
	{
		struct stat sb;
		int ret = stat(path_policy->path, &sb);
		if(ret < 0)
		{
			EXILE_LOG_ERROR("stat failed\n");
			return ret;
		}

		int baseisfile = 0;
		if(S_ISREG(sb.st_mode))
		{
			baseisfile = 1;
		}

		char *path_inside_chroot = concat_path(chroot_target_path, path_policy->path);
		if(path_inside_chroot == NULL)
		{
			return 1;
		}

		ret = mkpath(path_inside_chroot, 0700, baseisfile);
		if(ret < 0)
		{
			EXILE_LOG_ERROR("Error creating directory structure %s while mounting paths to chroot: %s\n", path_inside_chroot, strerror(errno));
			free(path_inside_chroot);
			return ret;
		}
		path_policy = path_policy->next;
		free(path_inside_chroot);
	}

	return 0;
}

static int perform_mounts(const char *chroot_target_path, struct exile_path_policy *path_policy)
{
	while(path_policy != NULL)
	{
		int mount_flags = get_policy_mount_flags(path_policy);

		char *path_inside_chroot = concat_path(chroot_target_path, path_policy->path);
		if(path_inside_chroot == NULL)
		{
			return 1;
		}
		//all we do is bind mounts
		mount_flags |= MS_BIND;

		if(path_policy->policy & EXILE_FS_ALLOW_ALL_READ || path_policy->policy & EXILE_FS_ALLOW_ALL_WRITE)
		{
			int ret = mount(path_policy->path, path_inside_chroot,  NULL, mount_flags, NULL);
			if(ret < 0 )
			{
				EXILE_LOG_ERROR("Failed to mount %s to %s: %s\n", path_policy->path, path_inside_chroot, strerror(errno));
				free(path_inside_chroot);
				return ret;
			}

			//remount so noexec, readonly etc. take effect
			ret = mount(NULL, path_inside_chroot, NULL, mount_flags | MS_REMOUNT, NULL);
			if(ret < 0 )
			{
				EXILE_LOG_ERROR("Failed to remount %s: %s\n", path_inside_chroot, strerror(errno));
				free(path_inside_chroot);
				return ret;
			}
			path_policy = path_policy->next;
			free(path_inside_chroot);
		}
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
			EXILE_LOG_ERROR("Failed to unshare user namespaces: %s\n", strerror(errno));
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
			EXILE_LOG_ERROR("Failed to unshare mount namespaces: %s\n", strerror(errno));
			return ret;
		}
	}

	if(namespace_options & EXILE_UNSHARE_NETWORK)
	{
		int ret = unshare(CLONE_NEWNET);
		if(ret == -1)
		{
			EXILE_LOG_ERROR("Failed to unshare network namespace: %s\n", strerror(errno));
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


static void assign_filter(struct sock_filter *left, struct sock_filter *right, struct sock_filter *endfilter)
{
	if(left <= endfilter)
	{
		*left = *right;
		return;
	}
	EXILE_LOG_ERROR("Too many syscall filters installed! Aborting.\n");
	abort();
}

static struct sock_filter *append_syscall_to_bpf(struct exile_syscall_policy *syscallpolicy, struct sock_filter *filter, struct sock_filter *endfilter)
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
	if(action == EXILE_SYSCALL_DENY_RET_NOSYS)
	{
		action = SECCOMP_RET_ERRNO|ENOSYS;
	}
	long syscall = syscallpolicy->syscall;

	struct sock_filter syscall_load = BPF_STMT(BPF_LD+BPF_W+BPF_ABS, offsetof(struct seccomp_data, nr));
	assign_filter(filter, &syscall_load, endfilter);
	++filter;

	if(syscall != EXILE_SYSCALL_MATCH_ALL)
	{
			/* How many steps forward to jump when we don't match. This is either the last statement,
			 * i. e. the default action or the next syscall policy */
			__u8 next_syscall_pc =  1;
			if(__builtin_add_overflow(next_syscall_pc,  syscallpolicy->argfilterscount, &next_syscall_pc))
			{
					EXILE_LOG_ERROR("Overflow while trying to calculate jump offset\n");
					abort();
			}
			struct sock_filter syscall_check = EXILE_BPF_CMP_EQ((unsigned int) syscall, 0, next_syscall_pc);
			assign_filter(filter, &syscall_check, endfilter);
			++filter;
			--next_syscall_pc;

			struct sock_filter return_matching = EXILE_BPF_RETURN_MATCHING;
			struct sock_filter return_not_matching = EXILE_BPF_RETURN_NOT_MATCHING;

			for(size_t i = 0; i < syscallpolicy->argfilterscount; i++)
			{
				assign_filter(filter, &syscallpolicy->argfilters[i], endfilter);
				struct sock_filter *current = filter;
				__u8 jump_count_next_syscall = next_syscall_pc;
				__u8 jump_count_return = jump_count_next_syscall - 1;
				if(current->jt == EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
				{
					current->jt = jump_count_next_syscall;
				}
				if(current->jt == EXILE_SYSCALL_EXIT_BPF_RETURN)
				{
					current->jt = jump_count_return;
				}
				if(current->jf == EXILE_SYSCALL_EXIT_BPF_NO_MATCH)
				{
					current->jf = jump_count_next_syscall;
				}
				if(current->jf == EXILE_SYSCALL_EXIT_BPF_RETURN)
				{
					current->jf = jump_count_return;
				}
				if(current->code == return_matching.code && current->k == return_matching.k)
				{
					current->k = jump_count_return;
				}
				if(current->code == return_not_matching.code && current->k == return_not_matching.k)
				{
					current->k = jump_count_next_syscall;
				}
				--next_syscall_pc;
				++filter;
			}
	}
	struct sock_filter syscall_action = BPF_STMT(BPF_RET+BPF_K, action);
	/* TODO: we can do better than adding this below every jump */
	assign_filter(filter, &syscall_action, endfilter);
	return ++filter;
}

static int is_valid_syscall_policy(unsigned int policy)
{
	return policy == EXILE_SYSCALL_ALLOW || policy == EXILE_SYSCALL_DENY_RET_ERROR || policy == EXILE_SYSCALL_DENY_KILL_PROCESS || policy == EXILE_SYSCALL_DENY_RET_NOSYS;
}

/*
 * Enables the seccomp policy
 *
 * policy: exile policy object
 *
 * @returns: 0 on success, -1 on error
 */

int exile_enable_syscall_policy(struct exile_policy *policy)
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

	struct sock_filter *current_target = &filter[6];
	struct sock_filter *end = &filter[1023];

	struct exile_syscall_policy *current_policy = policy->syscall_policies;
	while(current_policy)
	{
		if(!is_valid_syscall_policy(current_policy->policy))
		{
			EXILE_LOG_ERROR("invalid syscall policy specified\n");
			return -1;
		}
		current_target = append_syscall_to_bpf(current_policy, current_target, end);
		current_policy = current_policy->next;
	}

	unsigned short len = (current_target - &filter[0]);
	struct sock_fprog prog = {
		.len = len ,
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
static unsigned int exile_flags_to_landlock(unsigned int flags, int statmode)
{
	unsigned int result = 0;
	if(flags & EXILE_FS_ALLOW_ALL_READ)
	{
		result |= LANDLOCK_ACCESS_FS_READ_FILE;
		if(S_ISDIR(statmode))
		{
			result |= LANDLOCK_ACCESS_FS_READ_DIR;
		}
	}
	if(flags & EXILE_FS_ALLOW_ALL_WRITE)
	{
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
		if(S_ISDIR(statmode))
		{
			result |= LANDLOCK_ACCESS_FS_REMOVE_DIR;
			result |= LANDLOCK_ACCESS_FS_REMOVE_FILE;
			result |= LANDLOCK_ACCESS_FS_MAKE_DIR;
			result |= LANDLOCK_ACCESS_FS_MAKE_FIFO;
			result |= LANDLOCK_ACCESS_FS_MAKE_REG;
			result |= LANDLOCK_ACCESS_FS_MAKE_SOCK;
			result |= LANDLOCK_ACCESS_FS_MAKE_SYM;
		}
	}
	if(flags & EXILE_FS_ALLOW_EXEC)
	{
		result |= LANDLOCK_ACCESS_FS_EXECUTE;
	}
	if(flags & EXILE_FS_ALLOW_WRITE_FILE)
	{
		result |= LANDLOCK_ACCESS_FS_WRITE_FILE;
	}
	if(S_ISDIR(statmode))
	{
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
		if(flags & EXILE_FS_ALLOW_READ_DIR)
		{
			result |= LANDLOCK_ACCESS_FS_READ_DIR;
		}
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
		struct stat sb;
		int ret = fstat(path_beneath.parent_fd, &sb);
		if(ret)
		{
			EXILE_LOG_ERROR("fstat failed %s\n", strerror(errno));
			close(ruleset_fd);
			return ret;
		}
		path_beneath.allowed_access = exile_flags_to_landlock(policy->policy, sb.st_mode);
		ret = landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0);
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

	int can_use_landlock = exile_landlock_is_available();
	if(!can_use_landlock)
	{
		struct exile_path_policy *path_policy = policy->path_policies;
		while(path_policy)
		{
			if(path_policy_needs_landlock(path_policy))
			{
				EXILE_LOG_ERROR("A path policy (%s) needs landlock, but landlock is not available. Fallback not possible\n", path_policy->path);
				return -1;
			}
			path_policy = path_policy->next;
		}
	}

	/* TODO: check if we have ALLOWED, but no default deny */

	if(policy->mount_path_policies_to_chroot == 1)
	{
		if(policy->path_policies == NULL)
		{
			EXILE_LOG_ERROR("Cannot mount path policies to chroot if none are given\n");
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
				if(policy->vow_promises != 0)
				{
					EXILE_LOG_ERROR("It's not possible to specify a default, all matching syscall policy while also using vows\n");
					return -1;
				}
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
		if(policy->vow_promises == 0 && (last_match_all == -1 || i - last_match_all != 1))
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
	if((policy->exile_flags & EXILE_FLAG_ADD_PATH_POLICY_FAIL) || (policy->exile_flags & EXILE_FLAG_ADD_SYSCALL_POLICY_FAIL))
	{
		EXILE_LOG_ERROR("At least one syscall or path policy was not successfully added!\n");
		return -1;
	}
	if(check_policy_sanity(policy) != 0)
	{
		EXILE_LOG_ERROR("Policy sanity check failed. Cannot apply policy!\n");
		return -EINVAL;
	}

	if(enter_namespaces(policy->namespace_options) < 0)
	{
		EXILE_LOG_ERROR("Error while trying to enter namespaces\n");
		return -1;
	}

	int can_use_landlock = exile_landlock_is_available();


	/* Fallback to chroot mechanism to enforce policies. Ignore mount_path_policies_to_chroot
	 * if we have no other option (so no landlock) */
	if((policy->mount_path_policies_to_chroot || !can_use_landlock) && policy->path_policies != NULL)
	{
		if(*policy->chroot_target_path == '\0')
		{
			char random_str[17];
			if(random_string(random_str, sizeof(random_str)) == 16)
			{
				int res = snprintf(policy->chroot_target_path, sizeof(policy->chroot_target_path), "%s/.sandbox_%" PRIdMAX "_%s", EXILE_TEMP_DIR, (intmax_t)getpid(), random_str);
				if(res < 0)
				{
					EXILE_LOG_ERROR("error during path concatination\n");
					return -EINVAL;
				}
				if(res >= PATH_MAX)
				{
					EXILE_LOG_ERROR("path concatination truncated\n");
					return -EINVAL;
				}
			}
			else
			{
				EXILE_LOG_ERROR("Error creating random sandbox directory name\n");
				return -1;
			}
		}

		if(create_chroot_dirs(policy->chroot_target_path, policy->path_policies) < 0)
		{
			EXILE_LOG_ERROR("bind mounting of path policies failed\n");
			return -1;
		}

		if(perform_mounts(policy->chroot_target_path, policy->path_policies) < 0)
		{
			EXILE_LOG_ERROR("Failed to remount\n");
			return -1;
		}
	}

	if(*policy->chroot_target_path != '\0')
	{
		if(chroot(policy->chroot_target_path) < 0)
		{
			EXILE_LOG_ERROR("failed to enter %s\n", policy->chroot_target_path);
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
	if(can_use_landlock && policy->path_policies != NULL)
	{
		landlock_ruleset_fd = landlock_prepare_ruleset(policy->path_policies);
		if(landlock_ruleset_fd < 0)
		{
			EXILE_LOG_ERROR("Failed to prepare landlock ruleset: %s\n", strerror(errno));
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
	if (can_use_landlock && policy->path_policies != NULL && landlock_restrict_self(landlock_ruleset_fd, 0) != 0)
	{
		perror("Failed to enforce ruleset");
		close(landlock_ruleset_fd);
		return -1;
	}
	close(landlock_ruleset_fd);
#endif

	if(policy->vow_promises != 0)
	{
		int ret = exile_append_vow_promises(policy, policy->vow_promises);
		if(ret != 0)
		{
			EXILE_LOG_ERROR("exile_append_vow_promises() failed: %i\n", ret);
			return ret;
		}
	}

	if(policy->syscall_policies != NULL)
	{
		return exile_enable_syscall_policy(policy);
	}


	return 0;
}

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
int exile_vow(uint64_t promises)
{
	struct __user_cap_header_struct h = { 0 };
	h.pid = 0;
	h.version = _LINUX_CAPABILITY_VERSION_3;
	struct __user_cap_data_struct cap[2];
	cap[0].effective = 0;
	cap[0].permitted = 0;
	cap[0].inheritable = 0;
	cap[1].effective = 0;
	cap[1].permitted = 0;
	cap[1].inheritable = 0;
	if(capget(&h, cap) == -1)
	{
		EXILE_LOG_ERROR("Failed to get capabilities: %s\n", strerror(errno));
		return -errno;
	}

	struct exile_policy *policy = exile_create_policy();
	if(policy == NULL)
	{
		EXILE_LOG_ERROR("Failed to create policy\n");
		return 1;
	}

	policy->vow_promises = promises;
	if((cap[0].effective & (1<<CAP_SYS_ADMIN)) == 0)
	{
		policy->no_new_privs = 1;
	}
	int ret = exile_enable_policy(policy);
	exile_free_policy(policy);
	return ret;
}

int exile_clone_handle(void *arg)
{
	struct exile_launch_params *params = (struct exile_launch_params *) arg;
	struct exile_policy *policy = (struct exile_policy *) params->policy;

	int ret = exile_enable_policy(policy);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("Failed to enable policy\n");
		close(params->child_read_pipe[1]);
		close(params->child_write_pipe[0]);
		return 1;
	}
	ret = dup2(params->child_read_pipe[1], 1);
	if(ret == -1)
	{
		EXILE_LOG_ERROR("Failed to redirect stdout to pipe\n");
		return 1;
	}
	ret = params->func(params->funcarg);
	fclose(stdout);
	close(params->child_read_pipe[1]);
	close(params->child_write_pipe[0]);
	return ret;
}



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
int exile_launch(struct exile_launch_params *launch_params, struct exile_launch_result *launch_result)
{
	int ret = pipe(launch_params->child_read_pipe);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("read pipe creation failed\n");
		return ret;
	}

	ret = pipe(launch_params->child_write_pipe);
	if(ret != 0)
	{
		EXILE_LOG_ERROR("write pipe creation failed\n");
		return ret;
	}

	struct rlimit rlimit;
	ret = getrlimit(RLIMIT_STACK, &rlimit);
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
	ret = clone(&exile_clone_handle, stack, 17 /* SIGCHLD */, launch_params);
	if(ret == -1)
	{
		EXILE_LOG_ERROR("clone failed(): %s\n", strerror(errno));
		return ret;
	}
	close(launch_params->child_read_pipe[1]);
	close(launch_params->child_write_pipe[0]);

	launch_result->tid = ret;
	launch_result->read_fd = launch_params->child_read_pipe[0];
	launch_result->write_fd = launch_params->child_write_pipe[1];
	return 0;
}

/* Helper for exile_launch, to easily read all output from a function
* This function will read all output from a sandboxed function. It's up to the caller to ensure
* that enough memory will be available.
*
* The result is \0 terminated. The "n" parameter contains the size of the result, not including the \0.
*
* Return value: All data written by the function. The result should be passed to free() once not needed. NULL will
* be returned on error.
*/
char *exile_launch_get(struct exile_launch_params *launch_params, size_t *n)
{
	*n = 0;
	struct exile_launch_result launch_result;
	int launch = exile_launch(launch_params, &launch_result);
	if(launch < 0)
	{
		return NULL;
	}
	char *result = NULL;
	size_t size = 0;
	FILE *stream = open_memstream(&result, &size);
	while(1)
	{
		char buffer[4096];
		int ret = read(launch_result.read_fd, buffer, sizeof(buffer));
		if(ret == 0)
		{
			break;
		}
		if(ret == -1)
		{
			if(errno == EINTR)
			{
				continue;
			}
			EXILE_LOG_ERROR("Failed to read from read file descriptor\n");
			close(launch_result.read_fd);
			fclose(stream);
			return NULL;
		}
		size_t written = fwrite(buffer, 1, ret, stream);
		if(written != (size_t) ret)
		{
			EXILE_LOG_ERROR("Short item write");
			/* TODO: can we seek and free? */
			close(launch_result.read_fd);
			fclose(stream);
			return NULL;
		}
	}
	fclose(stream);
	int seek = fseek(stream, 0, SEEK_SET);
	if(seek == -1)
	{
		EXILE_LOG_ERROR("fseek failed\n");
		close(launch_result.read_fd);
		return NULL;
	}
	close(launch_result.read_fd);
	*n = size;
	return result;
}
