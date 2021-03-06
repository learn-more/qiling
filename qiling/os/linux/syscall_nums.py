#!/usr/bin/env python3
# 
# Cross Platform and Multi Architecture Advanced Binary Emulation Framework
# Built on top of Unicorn emulator (www.unicorn-engine.org) 

# Linux syscall numbers

NR_read = 0
NR_write = 1
NR_open = 2
NR_close = 3
NR_stat = 4
NR_fstat = 5
NR_lstat = 6
NR_poll = 7
NR_lseek = 8
NR_mmap = 9
NR_mprotect = 10
NR_munmap = 11
NR_brk = 12
NR_rt_sigaction = 13
NR_rt_sigprocmask = 14
NR_rt_sigreturn = 15
NR_ioctl = 16
NR_pread64 = 17
NR_pwrite64 = 18
NR_readv = 19
NR_writev = 20
NR_access = 21
NR_pipe = 22
NR_select = 23
NR_sched_yield = 24
NR_mremap = 25
NR_msync = 26
NR_mincore = 27
NR_madvise = 28
NR_shmget = 29
NR_shmat = 30
NR_shmctl = 31
NR_dup = 32
NR_dup2 = 33
NR_pause = 34
NR_nanosleep = 35
NR_getitimer = 36
NR_alarm = 37
NR_setitimer = 38
NR_getpid = 39
NR_sendfile = 40
NR_socket = 41
NR_connect = 42
NR_accept = 43
NR_sendto = 44
NR_recvfrom = 45
NR_sendmsg = 46
NR_recvmsg = 47
NR_shutdown = 48
NR_bind = 49
NR_listen = 50
NR_getsockname = 51
NR_getpeername = 52
NR_socketpair = 53
NR_setsockopt = 54
NR_getsockopt = 55
NR_clone = 56
NR_fork = 57
NR_vfork = 58
NR_execve = 59
NR_exit = 60
NR_wait4 = 61
NR_kill = 62
NR_uname = 63
NR_semget = 64
NR_semop = 65
NR_semctl = 66
NR_shmdt = 67
NR_msgget = 68
NR_msgsnd = 69
NR_msgrcv = 70
NR_msgctl = 71
NR_fcntl = 72
NR_flock = 73
NR_fsync = 74
NR_fdatasync = 75
NR_truncate = 76
NR_ftruncate = 77
NR_getdents = 78
NR_getcwd = 79
NR_chdir = 80
NR_fchdir = 81
NR_rename = 82
NR_mkdir = 83
NR_rmdir = 84
NR_creat = 85
NR_link = 86
NR_unlink = 87
NR_symlink = 88
NR_readlink = 89
NR_chmod = 90
NR_fchmod = 91
NR_chown = 92
NR_fchown = 93
NR_lchown = 94
NR_umask = 95
NR_gettimeofday = 96
NR_getrlimit = 97
NR_getrusage = 98
NR_sysinfo = 99
NR_times = 100
NR_ptrace = 101
NR_getuid = 102
NR_syslog = 103
NR_getgid = 104
NR_setuid = 105
NR_setgid = 106
NR_geteuid = 107
NR_getegid = 108
NR_setpgid = 109
NR_getppid = 110
NR_getpgrp = 111
NR_setsid = 112
NR_setreuid = 113
NR_setregid = 114
NR_getgroups = 115
NR_setgroups = 116
NR_setresuid = 117
NR_getresuid = 118
NR_setresgid = 119
NR_getresgid = 120
NR_getpgid = 121
NR_setfsuid = 122
NR_setfsgid = 123
NR_getsid = 124
NR_capget = 125
NR_capset = 126
NR_rt_sigpending = 127
NR_rt_sigtimedwait = 128
NR_rt_sigqueueinfo = 129
NR_rt_sigsuspend = 130
NR_sigaltstack = 131
NR_utime = 132
NR_mknod = 133
NR_uselib = 134
NR_personality = 135
NR_ustat = 136
NR_statfs = 137
NR_fstatfs = 138
NR_sysfs = 139
NR_getpriority = 140
NR_setpriority = 141
NR_sched_setparam = 142
NR_sched_getparam = 143
NR_sched_setscheduler = 144
NR_sched_getscheduler = 145
NR_sched_get_priority_max = 146
NR_sched_get_priority_min = 147
NR_sched_rr_get_interval = 148
NR_mlock = 149
NR_munlock = 150
NR_mlockall = 151
NR_munlockall = 152
NR_vhangup = 153
NR_modify_ldt = 154
NR_pivot_root = 155
NR__sysctl = 156
NR_prctl = 157
NR_arch_prctl = 158
NR_adjtimex = 159
NR_setrlimit = 160
NR_chroot = 161
NR_sync = 162
NR_acct = 163
NR_settimeofday = 164
NR_mount = 165
NR_umount2 = 166
NR_swapon = 167
NR_swapoff = 168
NR_reboot = 169
NR_sethostname = 170
NR_setdomainname = 171
NR_iopl = 172
NR_ioperm = 173
NR_create_module = 174
NR_init_module = 175
NR_delete_module = 176
NR_get_kernel_syms = 177
NR_query_module = 178
NR_quotactl = 179
NR_nfsservctl = 180
NR_getpmsg = 181
NR_putpmsg = 182
NR_afs_syscall = 183
NR_tuxcall = 184
NR_security = 185
NR_gettid = 186
NR_readahead = 187
NR_setxattr = 188
NR_lsetxattr = 189
NR_fsetxattr = 190
NR_getxattr = 191
NR_lgetxattr = 192
NR_fgetxattr = 193
NR_listxattr = 194
NR_llistxattr = 195
NR_flistxattr = 196
NR_removexattr = 197
NR_lremovexattr = 198
NR_fremovexattr = 199
NR_tkill = 200
NR_time = 201
NR_futex = 202
NR_sched_setaffinity = 203
NR_sched_getaffinity = 204
NR_set_thread_area = 205
NR_io_setup = 206
NR_io_destroy = 207
NR_io_getevents = 208
NR_io_submit = 209
NR_io_cancel = 210
NR_get_thread_area = 211
NR_lookup_dcookie = 212
NR_epoll_create = 213
NR_epoll_ctl_old = 214
NR_epoll_wait_old = 215
NR_remap_file_pages = 216
NR_getdents64 = 217
NR_set_tid_address = 218
NR_restart_syscall = 219
NR_semtimedop = 220
NR_fadvise64 = 221
NR_timer_create = 222
NR_timer_settime = 223
NR_timer_gettime = 224
NR_timer_getoverrun = 225
NR_timer_delete = 226
NR_clock_settime = 227
NR_clock_gettime = 228
NR_clock_getres = 229
NR_clock_nanosleep = 230
NR_exit_group = 231
NR_epoll_wait = 232
NR_epoll_ctl = 233
NR_tgkill = 234
NR_utimes = 235
NR_vserver = 236
NR_mbind = 237
NR_set_mempolicy = 238
NR_get_mempolicy = 239
NR_mq_open = 240
NR_mq_unlink = 241
NR_mq_timedsend = 242
NR_mq_timedreceive = 243
NR_mq_notify = 244
NR_mq_getsetattr = 245
NR_kexec_load = 246
NR_waitid = 247
NR_add_key = 248
NR_request_key = 249
NR_keyctl = 250
NR_ioprio_set = 251
NR_ioprio_get = 252
NR_inotify_init = 253
NR_inotify_add_watch = 254
NR_inotify_rm_watch = 255
NR_migrate_pages = 256
NR_openat = 257
NR_mkdirat = 258
NR_mknodat = 259
NR_fchownat = 260
NR_futimesat = 261
NR_newfstatat = 262
NR_unlinkat = 263
NR_renameat = 264
NR_linkat = 265
NR_symlinkat = 266
NR_readlinkat = 267
NR_fchmodat = 268
NR_faccessat = 269
NR_pselect6 = 270
NR_ppoll = 271
NR_unshare = 272
NR_set_robust_list = 273
NR_get_robust_list = 274
NR_splice = 275
NR_tee = 276
NR_sync_file_range = 277
NR_vmsplice = 278
NR_move_pages = 279
NR_utimensat = 280
NR_epoll_pwait = 281
NR_signalfd = 282
NR_timerfd_create = 283
NR_eventfd = 284
NR_fallocate = 285
NR_timerfd_settime = 286
NR_timerfd_gettime = 287
NR_accept4 = 288
NR_signalfd4 = 289
NR_eventfd2 = 290
NR_epoll_create1 = 291
NR_dup3 = 292
NR_pipe2 = 293
NR_inotify_init1 = 294
NR_preadv = 295
NR_pwritev = 296
NR_rt_tgsigqueueinfo = 297
NR_perf_event_open = 298
NR_recvmmsg = 299
NR_fanotify_init = 300
NR_fanotify_mark = 301
NR_prlimit64 = 302
NR_name_to_handle_at = 303
NR_open_by_handle_at = 304
NR_clock_adjtime = 305
NR_syncfs = 306
NR_sendmmsg = 307
NR_setns = 308
NR_getcpu = 309
NR_process_vm_readv = 310
NR_process_vm_writev = 311
NR_kcmp = 312
NR_finit_module = 313
NR_sched_setattr = 314
NR_sched_getattr = 315
NR_renameat2 = 316
NR_seccomp = 317
NR_getrandom = 318
NR_memfd_create = 319
NR_kexec_file_load = 320
NR_bpf = 321
NR_execveat = 322
NR_userfaultfd = 323
NR_membarrier = 324
NR_mlock2 = 325
NR_copy_file_range = 326
NR_preadv2 = 327
NR_pwritev2 = 328
NR_pkey_mprotect = 329
NR_pkey_alloc = 330
NR_pkey_free = 331
NR_statx = 332
