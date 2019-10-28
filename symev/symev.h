// symev.h - internal include for symev implementation
//
// Copyright (C) 2018 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/version.h>

// "debug" and "trace" do the same thing, except that sym_debug is only
// compiled in for a DEBUG build, while symev_trace will default to off,
// but will be available to turn on in all builds
extern int symev_trace_level;
#define symev_trace(n, fstr, args...) do {if ( (n) <= symev_trace_level) printk(KERN_INFO fstr, ##args);} while (0)

#ifdef DEBUG

#define sym_debug(n, fstr, args...) do {if ( (n) <= symev_trace_level) printk(KERN_INFO fstr, ##args);} while (0)

#else

#define sym_debug(n, fstr, args...) do {} while (0)

#endif

// Semaphore to manage access to the hooked handlers.
// Currently use a rw_semaphore to manage access to the table, to
// ensure it won't go away out from under us.  We hold this lock until
// we're about to exit the handler, giving us the best assurances
// available (still imperfect) that our module won't unload while it's
// still executing on a user's thread (via a hook).
extern struct rw_semaphore symev_hooks_rwsem;
extern atomic_t handler_depth;

// call this on entering a hook handler; it will lock the module in place
// until leave_handler() is called, but it will sleep if the "original"
// handlers are being updated.  always check that handler address while
// holding this lock.
static inline void enter_handler(void)
{
    down_read(&symev_hooks_rwsem);
#ifdef DEBUG
    atomic_inc(&handler_depth);
#endif
}

// call this on leaving a hook handler
static inline void leave_handler(void)
{
    up_read(&symev_hooks_rwsem);
#ifdef DEBUG
    atomic_dec(&handler_depth);
#endif
}

// acquire write lock on the "original" hook handlers
static inline void lock_hooks(void)
{
    down_write(&symev_hooks_rwsem);
}

// reease write lock on the "original" hook handlers
static inline void unlock_hooks(void)
{
    up_write(&symev_hooks_rwsem);
}

// private state information that's carried around as part of the
// event struct; this must be no larger than sizeof(ev->ev_pvt)
//
// NB:  currently, this struct holds a ref count on the dentry and mnt
// for the file whose name it holds.  Holding this longer than
// necessary will prevent unmounting of the filesystem where the file
// lives (similar to keeping the file open).  In addition, the total
// allocation is somewhere over one page (4k) when a filename has been
// obtained.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define INO_TIME_T	time_t
#else
#define INO_TIME_T	struct timespec
#endif


struct symev_pvt_data
{
    atomic_t		refs;		// reference count
    char		*namebuf;	// points to a kmalloc'd filename buffer (or NULL)
    struct dentry	*dentry;	// points to a ref'd dentry (or NULL)
    struct vfsmount	*mnt;		// points to a ref'd vfsmount (or NULL)
    INO_TIME_T		atime_saved;	// saved inode last-access time
    INO_TIME_T		mtime_saved;	// saved inode last-modified time
    INO_TIME_T		ctime_saved;	// saved inode last-changed time
};

// evaluate to the private data given an ev pointer
#define EVPVT(evp)	((struct symev_pvt_data *)&((evp)->ev_pvt[0]))

// indicate an event based on accessing a file by dentry/vfsmnt
extern int symev_dm_event(const unsigned long ev, unsigned long fl,
    unsigned long data1, const char *funct,
    struct dentry *dep, struct vfsmount *vmp);
