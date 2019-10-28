/********************************************************************************************************
 * SYMANTEC:     Copyright (c) 2011-2016 Symantec Corporation. All rights reserved.
 *
 * THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC CORPORATION.  USE,
 * DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR EXPRESS WRITTEN PERMISSION OF SYMANTEC
 * CORPORATION.
 *
 * The Licensed Software and Documentation are deemed to be commercial computer software as defined in
 * FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial Computer
 * Software - Restricted Rights" and DFARS 227.7202, Rights in "Commercial Computer Software or Commercial
 * Computer Software Documentation," as applicable, and any successor regulations, whether delivered by
 * Symantec as on premises or hosted services.  Any use, modification, reproduction release, performance,
 * display or disclosure of the Licensed Software and Documentation by the U.S. Government shall be solely
 * in accordance with the terms of this Agreement.
 ********************************************************************************************************/
// symkutil.h - assorted kernel-mode utility and portability functions
//
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.
//
// These functions are available to support the implementation of kernel
// modules such as symap.  They may be implemented in symev, in some
// other support module, or in a module wrapper, depending upon platform
// and port.  Some may not be available to symev - refer to the implementation
// for details.

#include <symtypes.h>
#include <linux/version.h>

// --- kernel timers and timekeeping -----------------------------------

// incomplete struct used to refer to kernel timers
typedef struct sym_timer_str sym_timer_t;

// sym_timer_create() - create a timer (doesn't arm it yet)
// @fp - pointer to function to call at expiration
// @fd - data to pass to (*fp)
// returns (opaque) pointer that will be used later to set, change, and
// destroy the timer.  caller must destroy when no longer needed, else
// will leak some memory.
SYMCALL sym_timer_t *sym_timer_create(SYMCALL void (*fp)(unsigned long), unsigned long fd);

// sym_timer_set() - set a timer to expire in the future
// @tp - timer's address returned by sym_timer_create()
// @exp - expiration time, absolute system clock units
SYMCALL void sym_timer_destroy(sym_timer_t *tp);

SYMCALL void sym_timer_set(sym_timer_t *tp, unsigned long exp);

// sym_timer_get() - get timer's current expiration time
SYMCALL unsigned long sym_timer_get(sym_timer_t *tp);

// sym_timer_is_set() - inquire whether timer is set
SYMCALL int sym_timer_is_set(sym_timer_t *tp);

SYMCALL void sym_timer_update(sym_timer_t *tp, unsigned long exp);

// sym_timer_cancel() - unschedule timer callback
SYMCALL void sym_timer_cancel(sym_timer_t *tp);

// sym_clock_get - get system clock value
SYMCALL unsigned long sym_clock_get(void);

// sym_hz_get - get system clock rate (HZ)
SYMCALL unsigned long sym_hz_get(void);

// compare 32-bit jiffies values, accounting for wrap
// - jiffies could always wrap, but as of 2.6 on i386 T=49 days
//   so wraps will happen pretty often.
// - we use the same heuristics implicit in linux/timer.c, namely,
//   that the unsigned difference must be less than half the range

// return (ja > jb) per the above heuristics
static inline int sym_clock_greater(const unsigned long ja,
    const unsigned long jb)
{
    return (((signed long)(ja - jb)) > 0);
}

// return (ja <= jb) per the above heuristics
static inline int sym_clock_less_eq(const unsigned long ja,
    const unsigned long jb)
{
    return (((signed long)(ja - jb)) <= 0);
}

// return (ja < jb) per the above heuristics
static inline int sym_clock_less(const unsigned long ja,
    const unsigned long jb)
{
    return (((signed long)(ja - jb)) < 0);
}


// --- mutexes ----------------------------------------------------

// opaque (incomplete) struct to refer to a kernel mutex
typedef struct sym_mutex sym_mutex_t;

SYMCALL sym_mutex_t *sym_mutex_new(void);		// create a mutex
SYMCALL void sym_mutex_delete(sym_mutex_t *);		// destroy a mutex
SYMCALL void sym_mutex_lock(sym_mutex_t *);		// lock a mutex
SYMCALL void sym_mutex_unlock(sym_mutex_t *);		// unlock a mutex


// --- printk/cmn_err replacement ---------------------------------

// this interface has been designed to port to other OSes; one
// constraint though is that on Linux, fmt must be a string literal,
// and cannot be a variable.

// NB: order of these is significant in implementation
#define SYM_PRINTK_ERR	2
#define SYM_PRINTK_WARN	1
#define SYM_PRINTK_INFO	0

SYMCALL void sym_printk(int, char *, ...)
        __attribute__((format(printf, 2, 3)));		// gcc args checking


// --- standard library function replacements ---------------------

#ifndef NULL
#define NULL ((void *)0)
#endif

extern SYMCALL int sym_snprintf(char *, sym_size_t, const char *, ...)
        __attribute__((format(printf, 3, 4)));		// gcc args checking
extern SYMCALL int sym_strnicmp(const char *, const char *, sym_size_t);
extern SYMCALL void *sym_memset(void *m, char c, sym_size_t len);
extern SYMCALL void *sym_kmalloc(sym_size_t);
extern SYMCALL void sym_kfree(void *);	// contiguous malloc
extern SYMCALL void *sym_vmalloc(sym_size_t);
extern SYMCALL void sym_vfree(void *);	// virtual mem malloc

static inline int sym_strlen(const char *s)
{
    const char *s0 = s;
    while (*s)
	s++;
    return (s - s0);
}

static inline int sym_strcmp(const char *s1, const char *s2)
{
    while (1)
    {
	if (*s1 != *s2)		// chars differ => strings differ
	    return 1;

	if (!*s1++)		// (both) at null => strings were equal
	    return 0;

	s2++;
    }
}


// --- attributes of current process -------------------------------

// Return TRUE if the current thread is running with superuser authority
// (real or effective)
SYMCALL int sym_curr_is_su(void);

// Get Thread ID
// - on Linux, this is actually the pid
SYMCALL sym_pid_t sym_curr_gettid(void);

// Get Process ID, the PID that should refer to all threads in the process
// - on Linux, this is actually the tgid, but on 2.4.9 it doesn't refer
//   to all threads (see sym_curr_gettgid() below)
// - we keep this function since it's useful for diagnostics
SYMCALL sym_pid_t sym_curr_getpid(void);

// Get Thread Group ID, the ID that refers to all threads in the process
// - on 2.4.9 kernels we use something other than the non-useful tgid
SYMCALL sym_pid_t sym_curr_gettgid(void);


// --- system information -------------------------------------------

// Return the physical memory size of the machine, in KB.  This will
// be useful for dynamically sizing data structures but won't necessarily
// be exactly right.
// - returns memory size in KB, or 0 if unknown (which currently can't happen)
SYMCALL unsigned long sym_sys_getmemsize(void);


// --- Wait-queue abstraction ---------------------------------------

// incomplete struct to refer to a kernel wait-queue
typedef struct sym_wq sym_wq_t;

// create a wait-queue head
SYMCALL sym_wq_t *sym_wq_new(void);

// destroy a wait-queue head
SYMCALL void sym_wq_delete(sym_wq_t *);

// return nonzero if anyone waiting (or zero if not knowable on this system)
SYMCALL int sym_wq_waiting(sym_wq_t *);

// return after being awakened or signalled
SYMCALL int sym_wq_wait(sym_wq_t *, sym_mutex_t *, SYMCALL int (*)(void *), void *);

// wake up all sleepers on this queue
// -- it's assumed the caller has made the condition true first,
//    otherwise this will be a waste of time
SYMCALL void sym_wq_wakeup(sym_wq_t *);


// --- Abstract accesses related to fs.h, file.h objects -----------

// system types that will be treated at least as opaque
struct file;
struct inode;

// set the private_data member of the file pointer
SYMCALL void sym_file_set_pvt(struct file *, void *);

// get the private_data member of the file pointer
SYMCALL void *sym_file_get_pvt(struct file *fp);


// --- errno support -----------------------------------------------
// used by modules that need to be portable but also may need to
// return platform-specific errno values.  use these interfaces to
// obtain these values.

// the implementation depends on this list being 0-based and relatively
// contiguous; the enum values should not change in future releases though
// new ones can be added.  0 is "OK"; the rest of the errno values are
// mapped un symev/utils.c
enum sym_errsels {
    _sym_err_noerror = 0,
    _sym_err_badaddr = 1,
    _sym_err_ioerror = 2,
    _sym_err_devbusy = 3,
    _sym_err_outofmem = 4,
    _sym_err_badioctl = 5,
    _sym_err_invalarg = 6,
    _sym_err_shutting = 7,
    _sym_err_permission = 8,
    sym_errnum_max = 8
};

// get an errno value (positive, as defined) corresponding to a portable
// error selector
SYMCALL int sym_err_getnum(enum sym_errsels);


// --- linked-list manipulation ----------------------------------

// - these lists are circularly-linked, with semantics like those of the
//   Linux sturct list_headi, but not promised to be interchangeable.
struct sym_list_head { struct sym_list_head *next, *prev; };

// macros to iterate the list in either direction
#define sym_list_for_each(A, B) for ((A) = (B)->next; (A) != (B); (A) = (A)->next)
#define sym_list_for_each_prev(A, B) for ((A) = (B)->prev; (A) != (B); (A) = (A)->prev)

// macros to find the start of a struct given the address of its member
// #define offsetof(T, M) ((size_t)&((T *)0)->M)
// #define list_entry(I, T, M) ((T *)(((char *)(I)) - offsetof(T, M)))
#define sym_list_entry(I, T, M) ((T *)(((char *)(I)) - ((sym_size_t)&((T *)0)->M)))

// macros to declare and manipulate lists -- pretty basic stuff
#define _BLOCK(BLK)	do { BLK } while (0)
#define SYM_LIST_HEAD(H)	struct sym_list_head H = { &(H), &(H) }
#define INIT_SYM_LIST_HEAD(M) _BLOCK((M)->next = (M); (M)->prev = (M);)
#define sym_list_add(I, H)		_BLOCK( (H)->next->prev = (I); \
					(I)->next = (H)->next; \
					(I)->prev = (H); \
					(H)->next = (I); \
					)
#define sym_list_add_tail(I, H)	_BLOCK( (H)->prev->next = (I); \
					(I)->prev = (H)->prev; \
					(I)->next = (H); \
					(H)->prev = (I); \
					)

static inline void sym_list_del(struct sym_list_head *m)
{
    if (m->next == (void *) NULL || m->prev == (void *) NULL)
        return; // do nothing since the node has been deleted.
    m->prev->next = m->next;
    m->next->prev = m->prev;
    m->next = (void *) NULL;
    m->prev = (void *) NULL;
}

// test for no members
#define sym_list_empty(H)	((H)->next == (H))


// --- usermode access from kernel --------------------------------

// check if address/range is writable by user
// - returns true if OK to write
SYMCALL int sym_user_okwrite(void *addr, sym_size_t len);

// copy from kernel to user
// - checks for destination to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (note this is different from
// Linux copy_to_user())
SYMCALL int sym_user_copyto(void *to, const void *from, const unsigned long len);

// write an "int" value to a user space address
// - checks for destination to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (similar to put_user)
SYMCALL int sym_user_intto(const int v, int *to);

// copy from user to kernel
// - checks for target to be writable by user
// - may sleep (due to page fault)
// returns 0 on success, -errno on failure (note this is different from
// Linux copy_to_user())
SYMCALL int sym_user_copyfrom(void *to, const void *from, const unsigned long len);


// --- spinlocks -----------------------------------------------------

// these are likely to be implemented in module wrappers

// sym_spinlock_new() - create a new spinlock
SYMCALL void *sym_spinlock_new(void);

// sym_spinlock_delete() - destroy a new spinlock
// - we count on the caller to ensure it's no longer in use
SYMCALL void sym_spinlock_delete(void *sl);

// sym_spin_lock() - spin_lock wrapper
SYMCALL void sym_spin_lock(void *sl);

// sym_spin_unlock() - spin_unlock wrapper
SYMCALL void sym_spin_unlock(void *sl);

// sym_spin_lock_bh() - spin_lock wrapper at handler (BH) level
SYMCALL void sym_spin_lock_bh(void *sl);

// sym_spin_unlock_bh() - spin_unlock wrapper at handler (BH) level
SYMCALL void sym_spin_unlock_bh(void *sl);

// --- atomic operations -----------------------------------------------------
typedef struct sym_atomic sym_atomic_t;
SYMCALL sym_atomic_t* sym_atomic_new(void);
SYMCALL void sym_atomic_delete(sym_atomic_t* v);
SYMCALL int  sym_atomic_read(sym_atomic_t* v);
SYMCALL void sym_atomic_set(sym_atomic_t* v, int i);
SYMCALL void sym_atomic_inc(sym_atomic_t *v);
SYMCALL void sym_atomic_dec(sym_atomic_t *v);

// --- Cross kernel variants unique interfaces -------------------------------
struct file;
struct vfsmount;
struct vfsmount* sym_get_vfs_mount(struct file* fp);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    #define SYM_GET_ID(k_id)  ((k_id).val)
#else
  #ifdef CONFIG_UIDGID_STRICT_TYPE_CHECKS
    #define SYM_GET_ID(k_id)  ((k_id).val)
  #else
    #define SYM_GET_ID(k_id)  (k_id)
  #endif
#endif

// Etrack 4016923: adjust pre-processor guard to match version where kernel 
// change took place, also account for RHEL 7.3 backport of these changes to 3.10 kernel
#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
  #if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(7,3)
    #define SYM_I_MMAP_WRITABLE_IS_ATOMIC_T 0
  #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0) || defined(SYM_I_MMAP_WRITABLE_IS_ATOMIC_T)
  #define SYM_I_MMAP_WRITABLE(count) ((count).counter)
#else
  #define SYM_I_MMAP_WRITABLE(count) (count)
#endif
