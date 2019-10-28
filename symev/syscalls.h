// syscalls.h - syscall table identification rules and data
//
// Copyright (C) 2017 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/syscalls.h>

#define SYSCALL_MINIMUM_MATCHES 5

struct sc_lookup
{
    int sc_num;
    char *sc_name;
};

static struct sc_lookup sc_lookuplist[] =
{
#ifdef __NR_dup
    {__NR_dup, "sys_dup"},
#endif
#ifdef __NR_fcntl
    {__NR_fcntl, "sys_fcntl"},
#endif
#ifdef __NR_madvise
    {__NR_madvise, "sys_madvise"},
#endif
#ifdef __NR_restart_syscall
    {__NR_restart_syscall, "sys_restart_syscall"},
#endif
#ifdef __NR_mkdirat
    {__NR_mkdirat, "sys_mkdirat"},
#endif
#ifdef __NR_mprotect
    {__NR_mprotect, "sys_mprotect"},
#endif
#ifdef __NR_sethostname
    {__NR_sethostname, "sys_sethostname"},
#endif
#ifdef __NR_ptrace
    {__NR_ptrace, "sys_ptrace"},
#endif
#ifdef __NR_llistxattr
    {__NR_llistxattr, "sys_llistxattr"},
#endif
#ifdef __NR_timer_settime
    {__NR_timer_settime, "sys_timer_settime"},
#endif
#ifdef __NR_ioprio_set
    {__NR_ioprio_set, "sys_ioprio_set"},
#endif
#ifdef __NR_tgkill
    {__NR_tgkill, "sys_tgkill"},
#endif
};
    
