 #ifndef SYSTRACE_H
 #define SYSTRACE_H

/* hardware breakpoint vector_swi address */
// 0xc0016298 sys_hello
// 0xc0065e9c sys_clock_gettime
// 0xc00128c0 vector_swi
// 0xc00e76cc sys_open
// 0xc00fb418 sys_poll
#define SWI_ADDR 0xc00128c0
/* length of the hardware breakpoint */
#define BKPT_LENGTH 4
/* maximum # of characters to be read from memory (arguments) */
#define MAX_MEM_READ 1000
/* offset from thread_info to thread_info->task_struct */
#define TASK_STRUCT_OFFSET 0x0000000c
/* offset from task_struct to task_struct->pid */
#define PID_OFFSET 0x000001d8
/* offset from task_struct to task_struct->comm */
#define COMM_OFFSET 0x000002b4
/* size of each kernel thread */
#define KERNEL_THREAD_SIZE 8192
/* size to be sent to md command */
#define BYTE_SIZE 1
#define WORD_SIZE 4

#define SIZE_OF_CHAR 1
#define NUM_CHARS_CHAR 3

#define SIZE_OF_PTR 4
//#define NUM_CHARS_PTR 11
#define NUM_CHARS_PTR 15

#define SIZE_OF_INT 4
//#define NUM_CHARS_INT 12
#define NUM_CHARS_INT 22
#define SIZE_OF_UINT 4
//#define NUM_CHARS_UINT 12
#define NUM_CHARS_UINT 22
#define SIZE_OF_UNSIGNED 4
//#define NUM_CHARS_UNSIGNED 12
#define NUM_CHARS_UNSIGNED 22
#define SIZE_OF_LONG 4
//#define NUM_CHARS_LONG 12
#define NUM_CHARS_LONG 22
#define SIZE_OF_ULONG 4
//#define NUM_CHARS_ULONG 12
#define NUM_CHARS_ULONG 22

#define SIZE_OF_SHORT 2
//#define NUM_CHARS_SHORT 7
#define NUM_CHARS_SHORT 12
#define SIZE_OF_USHORT 2
//#define NUM_CHARS_USHORT 7
#define NUM_CHARS_USHORT 12

#define SIZE_OF_LONG_LONG 8
//#define NUM_CHARS_LONG_LONG 22
#define NUM_CHARS_LONG_LONG 32

#define NUM_SYSCALLS 388

 char *syscalls_map[] = {
	"sys_restart_syscall", "sys_exit", "sys_fork_wrapper", "sys_read", "sys_write",
	"sys_open", "sys_close", "sys_ni_syscall (was sys_waitpid)", "sys_creat", "sys_link",
	"sys_unlink", "sys_execve_wrapper", "sys_chdir", "OBSOLETE(sys_time)	(used by libc4)", "sys_mknod",
	"sys_chmod", "sys_lchown16", "sys_ni_syscall	(was sys_break)", "sys_ni_syscall (was sys_stat)", "sys_lseek",
	"sys_getpid", "sys_mount", "OBSOLETE(sys_oldumount))	(used by libc4)", "sys_setuid16", "sys_getuid16",
	"OBSOLETE(sys_stime)", "sys_ptrace", "OBSOLETE(sys_alarm))	(used by libc4)", "sys_ni_syscall)	(was sys_fstat)", "sys_pause",
	"OBSOLETE(sys_utime))	(used by libc4)", "sys_ni_syscall)	(was sys_stty)", "sys_ni_syscall)	(was sys_getty)", "sys_access", "sys_nice",
	"sys_ni_syscall)	(was sys_ftime)", "sys_sync", "sys_kill", "sys_rename", "sys_mkdir",
	"sys_rmdir", "sys_dup", "sys_pipe", "sys_times", "sys_ni_syscall)	(was sys_prof)",
	"sys_brk", "sys_setgid16", "sys_getgid16", "sys_ni_syscall)	(was sys_signal)", "sys_geteuid16",
	"sys_getegid16", "sys_acct", "sys_umount", "sys_ni_syscall)	(was sys_lock)", "sys_ioctl",
	"sys_fcntl", "sys_ni_syscall)	(was sys_mpx)", "sys_setpgid", "sys_ni_syscall)	(was sys_ulimit)", "sys_ni_syscall)	(was sys_olduname)",
	"sys_umask", "sys_chroot", "sys_ustat", "sys_dup2", "sys_getppid",
	"sys_getpgrp", "sys_setsid", "sys_sigaction", "sys_ni_syscall)	(was sys_sgetmask)", "sys_ni_syscall)	(was sys_ssetmask)",
	"sys_setreuid16", "sys_setregid16", "sys_sigsuspend", "sys_sigpending", "sys_sethostname",
	"sys_setrlimit", "OBSOLETE(sys_old_getrlimit)) (used by libc4)", "sys_getrusage", "sys_gettimeofday", "sys_settimeofday",
	"sys_getgroups16", "sys_setgroups16", "OBSOLETE(sys_old_select))	(used by libc4)", "sys_symlink", "sys_ni_syscall)	(was sys_lstat)",
	"sys_readlink", "sys_uselib", "sys_swapon", "sys_reboot", "OBSOLETE(sys_old_readdir))	(used by libc4)",
	"OBSOLETE(sys_old_mmap))	(used by libc4)", "sys_munmap", "sys_truncate", "sys_ftruncate", "sys_fchmod",
	"sys_fchown16", "sys_getpriority", "sys_setpriority", "sys_ni_syscall)	(was sys_profil)", "sys_statfs",
	"sys_fstatfs", "sys_ni_syscall)	(sys_ioperm)", "OBSOLETE(ABI(sys_socketcall, sys_oabi_socketcall))", "sys_syslog", "sys_setitimer",
	"sys_getitimer", "sys_newstat", "sys_newlstat", "sys_newfstat", "sys_ni_syscall)	(was sys_uname)",
	"sys_ni_syscall)	(was sys_iopl)", "sys_vhangup", "sys_ni_syscall", "OBSOLETE(sys_syscall))	(call a syscall)", "sys_wait4",
	"sys_swapoff", "sys_sysinfo", "OBSOLETE(ABI(sys_ipc, sys_oabi_ipc))", "sys_fsync", "sys_sigreturn_wrapper",
	"sys_clone_wrapper", "sys_setdomainname", "sys_newuname", "sys_ni_syscall)	(modify_ldt)", "sys_adjtimex",
	"sys_mprotect", "sys_sigprocmask", "sys_ni_syscall)	(was sys_create_module)", "sys_init_module", "sys_delete_module",
	"sys_ni_syscall)	(was sys_get_kernel_syms)", "sys_quotactl", "sys_getpgid", "sys_fchdir", "sys_bdflush",
	"sys_sysfs", "sys_personality", "sys_ni_syscall)	(reserved for afs_syscall)", "sys_setfsuid16", "sys_setfsgid16",
	"sys_llseek", "sys_getdents", "sys_select", "sys_flock", "sys_msync",
	"sys_readv", "sys_writev", "sys_getsid", "sys_fdatasync", "sys_sysctl",
	"sys_mlock", "sys_munlock", "sys_mlockall", "sys_munlockall", "sys_sched_setparam",
	"sys_sched_getparam", "sys_sched_setscheduler", "sys_sched_getscheduler", "sys_sched_yield", "sys_sched_get_priority_max",
	"sys_sched_get_priority_min", "sys_sched_rr_get_interval", "sys_nanosleep", "sys_mremap", "sys_setresuid16",
	"sys_getresuid16", "sys_ni_syscall)	(vm86)", "sys_ni_syscall)	(was sys_query_module)", "sys_poll", "sys_ni_syscall)	(was nfsservctl)",
	"sys_setresgid16", "sys_getresgid16", "sys_prctl", "sys_rt_sigreturn_wrapper", "sys_rt_sigaction",
	"sys_rt_sigprocmask", "sys_rt_sigpending", "sys_rt_sigtimedwait", "sys_rt_sigqueueinfo", "sys_rt_sigsuspend",
	"ABI(sys_pread64, sys_oabi_pread64)", "ABI(sys_pwrite64, sys_oabi_pwrite64)", "sys_chown16", "sys_getcwd", "sys_capget",
	"sys_capset", "sys_sigaltstack_wrapper", "sys_sendfile", "sys_ni_syscall)	(getpmsg)", "sys_ni_syscall)	(putpmsg)",
	"sys_vfork_wrapper", "sys_getrlimit", "sys_mmap2", "ABI(sys_truncate64, sys_oabi_truncate64)", "ABI(sys_ftruncate64, sys_oabi_ftruncate64)",
	"ABI(sys_stat64, sys_oabi_stat64)", "ABI(sys_lstat64, sys_oabi_lstat64)", "ABI(sys_fstat64, sys_oabi_fstat64)", "sys_lchown", "sys_getuid",
	"sys_getgid", "sys_geteuid", "sys_getegid", "sys_setreuid", "sys_setregid",
	"sys_getgroups", "sys_setgroups", "sys_fchown", "sys_setresuid", "sys_getresuid",
	"sys_setresgid", "sys_getresgid", "sys_chown", "sys_setuid", "sys_setgid",
	"sys_setfsuid", "sys_setfsgid", "sys_getdents64", "sys_pivot_root", "sys_mincore",
	"sys_madvise", "ABI(sys_fcntl64, sys_oabi_fcntl64)", "sys_ni_syscall) (TUX)", "sys_ni_syscall", "sys_gettid",
	"ABI(sys_readahead, sys_oabi_readahead)", "sys_setxattr", "sys_lsetxattr", "sys_fsetxattr", "sys_getxattr",
	"sys_lgetxattr", "sys_fgetxattr", "sys_listxattr", "sys_llistxattr", "sys_flistxattr",
	"sys_removexattr", "sys_lremovexattr", "sys_fremovexattr", "sys_tkill", "sys_sendfile64",
	"sys_futex", "sys_sched_setaffinity", "sys_sched_getaffinity", "sys_io_setup", "sys_io_destroy",
	"sys_io_getevents", "sys_io_submit", "sys_io_cancel", "sys_exit_group", "sys_lookup_dcookie",
	"sys_epoll_create", "ABI(sys_epoll_ctl, sys_oabi_epoll_ctl)", "ABI(sys_epoll_wait, sys_oabi_epoll_wait)", "sys_remap_file_pages", "sys_ni_syscall)	(sys_set_thread_area)",
	"sys_ni_syscall)	(sys_get_thread_area)", "sys_set_tid_address", "sys_timer_create", "sys_timer_settime", "sys_timer_gettime",
	"sys_timer_getoverrun", "sys_timer_delete", "sys_clock_settime", "sys_clock_gettime", "sys_clock_getres",
	"sys_clock_nanosleep", "sys_statfs64_wrapper", "sys_fstatfs64_wrapper", "sys_tgkill", "sys_utimes",
	"sys_arm_fadvise64_64", "sys_pciconfig_iobase", "sys_pciconfig_read", "sys_pciconfig_write", "sys_mq_open",
	"sys_mq_unlink", "sys_mq_timedsend", "sys_mq_timedreceive", "sys_mq_notify", "sys_mq_getsetattr",
	"sys_waitid", "sys_socket", "ABI(sys_bind, sys_oabi_bind)", "ABI(sys_connect, sys_oabi_connect)", "sys_listen",
	"sys_accept", "sys_getsockname", "sys_getpeername", "sys_socketpair", "sys_send",
	"ABI(sys_sendto, sys_oabi_sendto)", "sys_recv", "sys_recvfrom", "sys_shutdown", "sys_setsockopt",
	"sys_getsockopt", "ABI(sys_sendmsg, sys_oabi_sendmsg)", "sys_recvmsg", "ABI(sys_semop, sys_oabi_semop)", "sys_semget",
	"sys_semctl", "sys_msgsnd", "sys_msgrcv", "sys_msgget", "sys_msgctl",
	"sys_shmat", "sys_shmdt", "sys_shmget", "sys_shmctl", "sys_add_key",
	"sys_request_key", "sys_keyctl", "ABI(sys_semtimedop, sys_oabi_semtimedop)", "sys_ni_syscall", "sys_ioprio_set",
	"sys_ioprio_get", "sys_inotify_init", "sys_inotify_add_watch", "sys_inotify_rm_watch", "sys_mbind",
	"sys_get_mempolicy", "sys_set_mempolicy", "sys_openat", "sys_mkdirat", "sys_mknodat",
	"sys_fchownat", "sys_futimesat", "ABI(sys_fstatat64,  sys_oabi_fstatat64)", "sys_unlinkat", "sys_renameat",
	"sys_linkat", "sys_symlinkat", "sys_readlinkat", "sys_fchmodat", "sys_faccessat",
	"sys_pselect6", "sys_ppoll", "sys_unshare", "sys_set_robust_list", "sys_get_robust_list",
	"sys_splice", "sys_sync_file_range2", "sys_tee", "sys_vmsplice", "sys_move_pages",
	"sys_getcpu", "sys_epoll_pwait", "sys_kexec_load", "sys_utimensat", "sys_signalfd",
	"sys_timerfd_create", "sys_eventfd", "sys_fallocate", "sys_timerfd_settime", "sys_timerfd_gettime",
	"sys_signalfd4", "sys_eventfd2", "sys_epoll_create1", "sys_dup3", "sys_pipe2",
	"sys_inotify_init1", "sys_preadv", "sys_pwritev", "sys_rt_tgsigqueueinfo", "sys_perf_event_open",
	"sys_recvmmsg", "sys_accept4", "sys_fanotify_init", "sys_fanotify_mark", "sys_prlimit64",
	"sys_name_to_handle_at", "sys_open_by_handle_at", "sys_clock_adjtime", "sys_syncfs", "sys_sendmmsg",
	"sys_setns", "sys_process_vm_readv", "sys_process_vm_writev", "sys_hello"
};

#define BILLION 1000000000L

uint64_t RDTSCNano(void)
{
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);  /* mark the end time */
  return BILLION * t.tv_sec + t.tv_nsec;
}
#endif
