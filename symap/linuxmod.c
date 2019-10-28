// linuxmod - Linux Auto-Protect module container
//
// PROPRIETARY/CONFIDENTIAL.  Use of this product is subject to license terms.
// Copyright (C) 2005 Symantec Corporation.  All rights reserved.
//

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#	include <linux/config.h>
#endif

#include <linux/module.h>
#ifndef UTS_RELEASE
#	include <linux/vermagic.h>
#endif
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/interrupt.h>

#include <symevl.h>
#include <symkutil.h>

#include <symap-core.h>

#include "symap_cfg.h"
#include "symprocfs.h"

// define the module license mode
MODULE_LICENSE("Proprietary");

// make an alias for easier load/unload (2.6 and newer)
#ifdef MODULE_ALIAS
MODULE_ALIAS("symap");
#endif

// major number of our chrdev entry - so usermode apps can talk to us
static int lsymap_devmajor = 0;

// *** support for /proc/symap *******************************************

// /proc/symap handle - need to store this and pass to close
static struct sym_procfs_info *symap_proc_entry = NULL;

// produce a string to represent the version of the kernel headers we are
// built for, including SMP option
#ifdef CONFIG_SMP
  #define SYMAP_SMP_STRING " (SMP)"
#else
  #define SYMAP_SMP_STRING 
#endif

#ifdef DEBUG
  #define SYMAP_DEBUG_STRING " (DEBUG)"
#else
  #define SYMAP_DEBUG_STRING 
#endif

static char *lsymap_ver = UTS_RELEASE SYMAP_SMP_STRING SYMAP_DEBUG_STRING;

// ----- Module entry points  -----------------------------------

// read /proc/symap -- return interesting state information
//   currently, we expect the entire read will happen in one call, so we
//   ignore the start/offset flags (which is safe)
int
lsymap_read_proc_symap(char *buf, int *offp, int count)
{
    // restrict access to root only - otherwise this could be a back
    // channel to lots of interesting stuff
    if (!sym_curr_is_su())
	return -EPERM;

    sym_procfs_printf(buf, offp, count, "=== BUILD ===\n"
    	"MODULE=%s (lsymap)\n"
	"BLD=%s" 
#ifdef DEBUG
	    " (DEBUG)"
#endif
	"\n"
	"devmajor=%d\n"
	,
	SYMAP_MODULENAME,
	lsymap_ver,
	lsymap_devmajor
    );

    // add AP info
    symap_read_proc_symap(buf, offp, count);

    // return bytes read
    return *offp;
}

// write /proc/symap -- sets the symap trace level
//   a single digit (0, 1, 2, 3) sets all categories to that level
//   a 3-char cat name followed by a digit sets that cat only
//   an "=" sign followed by hex digits sets it explicitly
int
lsymap_write_proc_symap(const char __user *buf, int count)
{
    return symap_write_proc_symap(buf, count);
}

// open - instantiate the driver for a user thread
//  @ino - pointer to inode to open (includes our dev major number)
//  @filp - pointer to file struct to fill in
static int
lsymap_open(struct inode *ino, struct file *filp)
{
    // access control - root only; don't just trust device perms
    // NB: some day we might want to use a different rule
    // XXX maybe test this explicitly and eliminate is_su?
    if (!sym_curr_is_su())
	return -EBUSY;

    return symap_open((void *)filp);
}

// release - release the device for a user thread
//  @inop - pointer to inode struct being released
//  @filp - pointer to file struct to release
// this occurs when the last open descriptor on this file is
// closed
static int
lsymap_release(struct inode *inop, struct file *filp)
{
    return symap_release((void *)filp);
}

// write - request an operation of us (via write() syscall)
// @filp - the open file struct
// @buf - command and args (ptr to struct symap_ctl_str)
// @sz - size of buf
// @ppos - addr of file pointer in fd (unused)
// - this implements an equivalent interface to ioctl() except that it
// uses write syscall semantics.  the main advantage is that the
// ioctl interface still holds the BKL which can defeat hopes of
// concurrency, while write doesn't.
// - we violate the usual constraints by modifying the passed buffer
// but this seems to be OK!
ssize_t
lsymap_write(struct file *filp, const char *buf, size_t sz, loff_t *ppos)
{
    return symap_write((void *)filp, buf, sz, ppos);
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
// ioctl - request an operation of us (deprecated - via ioctl())
//  @ino - dentry->d_inode for this open file (unused)
//  @filp = the open file struct
//  @cmd - the ioctl command to execute (SYMAP_IOCTL_*)
//  @arg - command-specific argument word
// - we prefer not to use this method because Linux holds the BKL at the
// sys_ioctl interface
static int
lsymap_ioctl(struct inode *ino, struct file *filp, unsigned int cmd,
    unsigned long arg)
{
    return symap_ioctl((void *)filp, cmd, arg);
}
#endif

// read to (user) buf, sz bytes, starting at (user) *ppos; update *ppos
// - this doesn't really provide any important function other than
//   confirmation that we're here
static ssize_t
lsymap_read(struct file *filp, char *buf, size_t sz, loff_t *ppos)
{
    char sbuf[128];
    int len;

    if (*ppos < 0 || sz < 12)
	return -EIO;

    // copy out the dev major number
    len = sym_snprintf(sbuf, sizeof(sbuf), "symap=%d\nCopyright (C) Symantec Corporation\n", lsymap_devmajor);

    // return the portion of the (generated) message that's consumed
    // by the request
    if (len > 0)
    {
	// starting at/past the end -- eof
	if (*ppos >= len)
	    return 0;

	if ((sz + *ppos) >= len)
	    sz = len - *ppos;

	if (sym_user_copyto(buf, sbuf + *ppos, sz))
	    return -EFAULT;
	*ppos += sz;

	return sz;
    }

    return -EIO;
}


// the file_operations struct provides the driver entry points that
// will be accessible from usermode via system calls.  currently, symap
// responds to open, close, and ioctl; we will also support read to
// give a sanity check response.
struct file_operations lsymap_file_operations = {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,35)
    ioctl: lsymap_ioctl,
#endif
    open: lsymap_open,
    // flush: lsymap_flush,
    release: lsymap_release,
    read: lsymap_read,
    write: lsymap_write,
    owner: THIS_MODULE,		// hack to set owner field, 2.4.x & later
};

// ----- Module Housekeeping ----------------------------------------------

// symap_init - driver init (module load)
int
lsymap_init(void)
{
    int rc = 0;

#ifdef DEBUG
    sym_printk(SYM_PRINTK_INFO, SYMAP_MODULENAME ": init: buildver=%s\n",
    	lsymap_ver);
#endif

    if ((rc = symap_init_1()) < 0)
	goto bail1;

    // Make the /proc/symap node
    if (!(symap_proc_entry = sym_procfs_new(SYMAP_PROCFILE, lsymap_read_proc_symap,
	lsymap_write_proc_symap)))
    {
	// we'll consider this non-fatal but it's risky
	sym_printk(SYM_PRINTK_WARN, SYMAP_MODULENAME ": failed to create %s!\n",
	    SYMAP_PROCFILE);
    }

    // make /dev/ entry (using dynamic dev number)
    if ((rc = register_chrdev(0, SYMAP_DEVNAME, &lsymap_file_operations)) < 0)
    {
	// registration failed.  we're hosed.
	sym_printk(SYM_PRINTK_ERR,
	    SYMAP_MODULENAME ": cannot register device\n");
	goto bail2;
    }

    lsymap_devmajor = rc;

    // OK so far, complete init
    if ((rc = symap_init_2()) < 0)
	goto bail3;

#ifdef DEBUG
    sym_printk(SYM_PRINTK_INFO, "symap: registered %s as chrdev %d\n", SYMAP_DEVNAME, 
	lsymap_devmajor);
#endif   

    // -- initialized OK --
    return 0;

bail3:
    symap_exit_2();
bail2:
    if (lsymap_devmajor)
	unregister_chrdev(lsymap_devmajor, SYMAP_DEVNAME);
bail1:
    symap_exit_1();

    return rc;
}


// symap_exit() - module unload
// Unfortunately, module unloads cannot fail, so if there's trouble
// (e.g. cannot unregister from symev) the system is probably toast. 
// On the other hand, the rmmod won't be permitted to get this far if
// there are any scanner threads still holding an open on the module,
// so in theory it shouldn't be possible to get here with any client
// or scanner threads still running.  So worst case ought to be that
// the scanners have closed and it's taking a long time to wake up all
// the users.
// - in general, release in the opposite order of init
void
lsymap_exit(void)
{
    // pre dev-unregister
    symap_exit_2();

    // unregister our char device
    if (lsymap_devmajor)
    {
        int rc = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)
        unregister_chrdev(lsymap_devmajor, SYMAP_DEVNAME);
#else
	rc = unregister_chrdev(lsymap_devmajor, SYMAP_DEVNAME);
#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,23)

	if (rc == 0)
	{
#ifdef DEBUG
	    sym_printk(SYM_PRINTK_INFO,
		"symap: unregistered %s from chrdev %d\n", SYMAP_DEVNAME,
		lsymap_devmajor);
#endif   
	    lsymap_devmajor = 0;
	}
	else
	{
	    // the only cause for this error is if we're not registered
	    // (at least, not in the stated slot!)
	    sym_printk(SYM_PRINTK_ERR,
		"symap: unable to unregister chrdev %d: error code %d\n",
		lsymap_devmajor, -rc);
	}
    }

    // remove /proc/symc/symap
    // - have to do this since the read routine could crash once the
    //   various data structures start to be dismantled
    if (symap_proc_entry)
    {
	sym_procfs_delete(SYMAP_PROCFILE, symap_proc_entry);
	symap_proc_entry = NULL;
    }

    // post dev-unregister
    symap_exit_1();
}

// defs
module_init(lsymap_init);
module_exit(lsymap_exit);


// system interfacing

// - spinlocks - defined in include/symkutil.h, but we supply them in the
// wrapper module since we want them defined in the module that's using them

// sym_spinlock_new() - create a new spinlock
SYMCALL void *
sym_spinlock_new(void)
{
    spinlock_t *sl;

    sl = sym_kmalloc(sizeof(spinlock_t));

    if (sl)
	spin_lock_init(sl);

    return (void *) sl;
}

// sym_spinlock_delete() - destroy a new spinlock
// - we count on the caller to ensure it's no longer in use
SYMCALL void
sym_spinlock_delete(void *sl)
{
    sym_kfree(sl);
}

// sym_spin_lock() - spin_lock wrapper
SYMCALL void
sym_spin_lock(void *sl)
{
    spin_lock((spinlock_t *)sl);
}

// sym_spin_unlock() - spin_unlock wrapper
SYMCALL void
sym_spin_unlock(void *sl)
{
    spin_unlock((spinlock_t *)sl);
}


// sym_spin_lock_bh() - spin_lock wrapper at handler (BH) level
SYMCALL void
sym_spin_lock_bh(void *sl)
{
    spin_lock_bh((spinlock_t *)sl);
}

// sym_spin_unlock_bh() - spin_unlock wrapper at handler (BH) level
SYMCALL void
sym_spin_unlock_bh(void *sl)
{
    spin_unlock_bh((spinlock_t *)sl);
}

