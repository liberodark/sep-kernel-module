// utils.c - misc support utility functions for Linux
//
// Copyright (C) 2005 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#	include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/unistd.h>
#include <linux/timer.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
#	include <linux/cred.h>
#endif

// external defs for these and other utility functions
#include <symtypes.h>
#include <symkutil.h>

#include "symevl.h"

#include "symev.h"
#include "hnfs.h"

// sym_timer_create - create (but do not yet set) a timer
SYMCALL sym_timer_t *
sym_timer_create(SYMCALL void (*fp)(unsigned long), unsigned long fd)
{
    struct timer_list *tp = 
	(struct timer_list *) kmalloc(sizeof(struct timer_list), GFP_KERNEL);

    if (!tp)
	return NULL;

    memset((char *)tp, 0, sizeof(struct timer_list));
    init_timer(tp);

    tp->function = (void (*)(unsigned long))fp;
    tp->data = fd;

    return (sym_timer_t *)tp;
}

// sym_timer_destroy() - release a timer object
// - done synchronously so it won't return till the timer thread has
// been stopped and is not executing its bh
SYMCALL void
sym_timer_destroy(sym_timer_t *tp)
{
    if (!tp)
	return;

    // unschedule the timer first, if necessary
    if (timer_pending((struct timer_list *)tp))
	del_timer_sync((struct timer_list *)tp);

    memset(tp, 0, sizeof(struct timer_list));	// safe

    kfree((char *)tp);
}

// sym_timer_set() - set a timer to expire at time exp
// - timer must not currently be set
SYMCALL void
sym_timer_set(sym_timer_t *tp, unsigned long exp)
{
    if (tp)
    {
	((struct timer_list *)tp)->expires = exp;

	add_timer((struct timer_list *)tp);
    }
}

// sym_timer_update() - change the expiration time on an existing,
// already-active timer
SYMCALL void
sym_timer_update(sym_timer_t *tp, unsigned long exp)
{
    if (tp)
	mod_timer((struct timer_list *)tp, exp);
}

// sym_timer_get() - get timer's current expiration time
SYMCALL unsigned long
sym_timer_get(sym_timer_t *tp)
{
    return tp ? ((struct timer_list *)tp)->expires : 0;
}

// sym_timer_is_set() - return whether a timer is set to trigger
SYMCALL int
sym_timer_is_set(sym_timer_t *tp)
{
    return tp ? (timer_pending((struct timer_list *)tp)) : 0;
}

SYMCALL void
sym_timer_cancel(sym_timer_t *tp)
{
    if (tp)
    {
	del_timer_sync((struct timer_list *)tp);
	((struct timer_list *)tp)->expires = 0;		// sanity
    }
}


// sym_clock_get - get system clock value
SYMCALL unsigned long
sym_clock_get(void)
{
    return jiffies;
}

// sym_hz_get - get system clock rate (HZ)
SYMCALL unsigned long
sym_hz_get(void)
{
    return HZ;
}


// --- Mutex abstraction ---

// Mutexes on Linux are an instance of Semaphore, that's intialized
// and utilized in a certain way.  

struct sym_mutex
{
    struct semaphore sem;
};

// sym_mutex_new() - allocate and intialize (unlocked) a mutex
// - returns an opaque mutex pointer, or NULL if an alloc failure
SYMCALL sym_mutex_t *sym_mutex_new(void)
{
    sym_mutex_t *pmut;

    if (!(pmut = kmalloc(sizeof(sym_mutex_t), GFP_KERNEL)))
	return NULL;

    sema_init(&(pmut->sem),1);

    return pmut;
}

// sym_mutex_delete() - delete the memory associated with a mutex
// @pmut: pointer to the mutex
// This should only be called when it's not locked or being waited-on,
// and there's no further chance of it being accessed.
SYMCALL void
sym_mutex_delete(sym_mutex_t *pmut)
{
    kfree(pmut);
}

// sym_mutex_lock() - lock a mutex
// @pmut: pointer to the mutex
SYMCALL void
sym_mutex_lock(sym_mutex_t *pmut)
{
#ifdef LRL_MUTEX_DEBUG
    if (down_trylock(&pmut->sem))
    {
	printk("<1>mutex_waiting\n");
	down(&pmut->sem);
    }
#else // LRL_MUTEX_DEBUG
    down(&pmut->sem);
#endif
}

// sym_mutex_lock() - unlock a mutex
// @pmut: pointer to the mutex
SYMCALL void
sym_mutex_unlock(sym_mutex_t *pmut)
{
    up(&pmut->sem);
}


// --- printk support ---

// sym_printk() - send a message to the console and/or syslog
// - in the spirit of portability, this abstracts the log-level so it
//   can be implemented on multiple OSes
// - unfortunately there's no vprintk, so we need to do the arg formatting
//   ourself; there is a slight extra overhead, and we waste the space of
//   our extra buffer on the stack, but it's rarely used so we live with it.
SYMCALL void
sym_printk(int level, char *fmt, ...)
{
#define BSZ 512
    char buf[BSZ];
    static const char *fs[3] = { KERN_INFO "%s", KERN_WARNING "%s", KERN_ERR "%s" };
    va_list argv;

    va_start(argv, fmt);
    vsnprintf(buf, BSZ, fmt, argv);
    va_end(argv);

    // ensure null termination
    buf[BSZ-1] = 0;

    // send to printk, passing log level
    if (level < SYM_PRINTK_INFO || level > SYM_PRINTK_ERR)
	level = SYM_PRINTK_ERR;

    (void) printk(fs[level], buf);
}

// --- string library support ---

// sym_snprintf() - access snprintf functionality
SYMCALL int
sym_snprintf(char *buf, size_t sz, const char *fmt, ...)
{
    int rc;
    va_list argv;

    va_start(argv, fmt);
    rc = vsnprintf(buf, sz, fmt, argv);
    va_end(argv);

    return rc;
}

SYMCALL int
sym_strnicmp(const char *s1, const char *s2, size_t len)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4,0,0)
    return strnicmp(s1, s2, len);
#else
	return strncasecmp(s1, s2, len);
#endif
}

SYMCALL void *
sym_memset(void *m, char c, size_t len)
{
    return memset(m, c, len);
}

// kmalloc, kfree -- contiguous memory allocation
SYMCALL void *
sym_kmalloc(size_t sz)
{
    return kmalloc(sz, GFP_KERNEL);
}

SYMCALL void
sym_kfree(void *p)
{
    kfree(p);
}

// kmalloc, kfree -- virtual memory allocation
SYMCALL void *
sym_vmalloc(size_t sz)
{
    return vmalloc(sz);
}

SYMCALL void
sym_vfree(void *p)
{
    vfree(p);
}


// --- Attributes of current process ---

// Return TRUE if the current thread is running with superuser authority
// (real or effective)
SYMCALL int
sym_curr_is_su(void)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 29))
    return ((current->uid == 0 || current->euid == 0) ? 1 : 0);
#else
    return ((SYM_GET_ID(current->real_cred->uid) == 0 || SYM_GET_ID(current->real_cred->euid) == 0) ? 1 : 0);
#endif
}

// Get Thread ID
// - on Linux, this is actually the pid
SYMCALL sym_pid_t
sym_curr_gettid(void)
{
    return (sym_pid_t) current->pid;
}

// Get Process ID, the ID that refers to all threads in the process
// - on Linux, the PID shown to users is actually the tgid
// - OTOH on the older RHEL2.1 2.4.9 kernels, the tgid field is the same
//   as the pid and is different on each thread within a process
SYMCALL sym_pid_t
sym_curr_getpid(void)
{
    return (sym_pid_t) current->tgid;
}

// Get Thread Group ID, the ID that refers to all threads in the process
// - on older RHEL2.1 2.4.9 kernels, we use something else as the TGID
//   since the actual current->tgid is not preserved
SYMCALL sym_pid_t
sym_curr_gettgid(void)
{
#if (LINUX_VERSION_CODE <= KERNEL_VERSION(2, 4, 9))
    // old kernel - return memory map ptr, which is shared across all
    // threads in a process; mask it to a positive int first
    return ((sym_pid_t) current->mm) & 0x7fffffff;
#else
    return (sym_pid_t) current->tgid;
#endif
}


// --- system information -------------------------------------------

// Return the physical memory size of the machine, in KB.  This will
// be useful for dynamically sizing data structures but won't necessarily
// be exactly right.
// - returns memory size in KB, or 0 if unknown (which currently can't happen)
SYMCALL unsigned long sym_sys_getmemsize(void)
{
    struct sysinfo si;

    // obtain memory info from running kernel
    si_meminfo(&si);

    return (si.totalram * (si.mem_unit / 1024));
}


// --- Wait-queue abstraction ---

struct sym_wq
{
    wait_queue_head_t	wq;
};

// Create a new WQ
// returns the WQ pointer, or NULL if unable to create (malloc error)
SYMCALL sym_wq_t *
sym_wq_new(void)
{
    sym_wq_t *wq;

    // allocate, return NULL on failure
    if (!(wq = kmalloc(sizeof(sym_wq_t), GFP_KERNEL)))
	return NULL;

    init_waitqueue_head(&wq->wq);

    return wq;
}

// Delete an existing WQ
// - we assume the caller knows the thing isn't in use any more
SYMCALL void
sym_wq_delete(sym_wq_t *wq)
{
    if (wq)
	kfree(wq);
}

// return nonzero if anyone waiting on the WQ
// - obviously this is susceptible to races, so use it wisely
// - some *nix implementations can't do this, for them we return 0 always
SYMCALL int
sym_wq_waiting(sym_wq_t *wq)
{
    return waitqueue_active(&wq->wq);
}


// wait until...
// - signal received, OR
// - awake and !readyf || (*readyf)() != 0)
// If (mut) then assume it is held on entry; release during sleep but retake
// during readyf test and for return
// Return 0 if OK, -errno if awakened due to signal etc.
SYMCALL int
sym_wq_wait(sym_wq_t *wq, sym_mutex_t *mut, SYMCALL int (*readyf)(void *), void *d)
{
    int rc;

    while (!readyf || !(*readyf)(d))
    {
	if (mut)
	    sym_mutex_unlock(mut);

	rc = wait_event_interruptible(wq->wq, (!readyf || (*readyf)(d)));

	if (mut)
	    sym_mutex_lock(mut);

	// if sleep returned error, return it without considering condition
	if (rc < 0)
	    return rc;

	// loop around to retest condition while holding mutex
    }

    // when we get here, we're awake and the condition is true
    return 0;
}

// wake up all sleepers
SYMCALL void
sym_wq_wakeup(sym_wq_t *wq)
{
    wake_up_interruptible(&wq->wq);
}


// --- Abstract accesses related to fs.h objects ---

// set the private_data member of the file pointer
SYMCALL void
sym_file_set_pvt(struct file *fp, void *val)
{
    fp->private_data = val;
}

// get the private_data member of the file pointer
SYMCALL void *
sym_file_get_pvt(struct file *fp)
{
    return fp->private_data;
}

// --- Misc stuff ---
                                                                                
static int _sym_errnums[] =
{
    0,		// _sym_err_noerror
    EFAULT,	// _sym_err_badaddr
    EIO,	// _sym_err_ioerror
    EBUSY,	// _sym_err_devbusy
    ENOMEM,	// _sym_err_outofmem
    ENOTTY,	// _sym_err_badioctl
    EINVAL,	// _sym_err_invalarg
    ESHUTDOWN,	// _sym_err_shutting
    EACCES,	// _sym_err_permission
};

// get an errno value (positive, as defined) corresponding to a portable
// error selector.  these should be used to generate errno values to return
// but not to test returns from OS APIs.
SYMCALL int sym_err_getnum(enum sym_errsels errsel)
{
    if (errsel < 0 || errsel > sym_errnum_max)
	return EIO;
    
    return _sym_errnums[errsel];
}


// usermode access from kernel

// check if address/range is writable by user
// - returns true if OK to write
SYMCALL int sym_user_okwrite(void *addr, size_t len)
{
    // simply wrap access_ok
    return access_ok(VERIFY_WRITE, addr, len);
}

// copy from kernel to user
// - checks for destination to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (note this is different from
// Linux copy_to_user())
SYMCALL int sym_user_copyto(void *to, const void *from, const unsigned long len)
{
    if (copy_to_user(to, from, len) != 0)
	return -EFAULT;

    return 0;
}

// copy from user to kernel
// - checks for source to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (note this is different from
// Linux copy_to_user())
SYMCALL int sym_user_copyfrom(void *to, const void *from, const unsigned long len)
{
    if (copy_from_user(to, from, len) != 0)
	return -EFAULT;

    return 0;
}

// write an "int" value to a user space address
// - checks for destination to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (similar to put_user)
SYMCALL int sym_user_intto(const int v, int *to)
{
    return put_user(v, to);
}

// Get vfsmount struct based on file pointer
struct vfsmount* sym_get_vfs_mount(struct file* fp)
{
    if(fp == NULL)
	return NULL;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,9,0)
    return fp->f_vfsmnt;
#else
    return (fp->f_path).mnt;
#endif
}

