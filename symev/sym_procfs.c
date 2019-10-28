// symprocfs.c - Abstract accesses to procfs functions
//
// Copyright (C) 2014 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#	include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/proc_fs.h>
#include <linux/slab.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
#include <linux/uaccess.h>
#else
#include <asm/uaccess.h>
#endif

#include "symprocfs.h"

// --- Abstract accesses to procfs functions

// pvt struct to keep track of stuff
struct sym_procfs_info
{
    struct proc_dir_entry *pde;

    sym_procfs_readfunc_t *readfunc;
    sym_procfs_writefunc_t *writefunc;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))
    struct file_operations fop;
#endif

};

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
// generic "read" function, allows us to abstract this whole thing
// for portability
static int
sym_procfs_genread(char *page, char **start, off_t off,
		    int count, int *eof, void *data)
{
    // current impl ignores start and off, i.e. is limited to returning
    // one PAGESIZE of results
    struct sym_procfs_info *proc_info;
    int rc, bo = 0;
    proc_info = (struct sym_procfs_info *)data;

    rc = proc_info->readfunc(page, &bo, count);

    *eof = 1;			// always complete, today
    return rc;			// bytes read
}

// generic "write" function, allows us to abstract this whole thing
// for portability
static int
sym_procfs_genwrite(struct file *file, const char __user *buffer,
		    unsigned long count, void *data)
{
    // current implementation ignores current file offset therefore 
    // assumes all writes are at offset 0
    struct sym_procfs_info *proc_info;
    int wc;
    proc_info = (struct sym_procfs_info *)data;

    wc = proc_info->writefunc(buffer, count);

    return wc;			// bytes wrote
}

#else //means (LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0))

// procfs "read" function based on struct file_operations, allows us to abstract this whole thing
// for portability
// current impl ignores ppos, i.e. is limited to returning
// one PAGESIZE of results
static ssize_t
sym_procfs_fopread(struct file *filp, char __user *buf, size_t sz, loff_t *ppos)
{
    char page[4096];
    int rc, off=0;
    ssize_t len=0;
    struct sym_procfs_info *proc_info = (struct sym_procfs_info *)PDE_DATA(filp->f_inode);

    rc = proc_info->readfunc(page, &off, sizeof(page));
    if (rc > 0)
    {
	// starting at/past the end -- eof
	if (*ppos >= rc)
        {
	    return 0; //0 means eof
        }

	len = sz;
	if ((sz + *ppos) >= rc)
        {
	    len = rc - *ppos;
        }

	if (copy_to_user(buf, page + *ppos, len))
	    return -EFAULT; //failed
	else
	    *ppos += len;
    }

    return len; //always return EOF
}

// procfs "write" function based on struct file_operations, allows us to abstract this whole thing
// for portability
static ssize_t
sym_procfs_fopwrite(struct file *filp, const char __user *buf, size_t sz, loff_t *ppos)
{
    ssize_t wc;
    struct sym_procfs_info *proc_info = (struct sym_procfs_info *)PDE_DATA(filp->f_inode);

    wc = proc_info->writefunc(buf, sz);
    return wc;
}

#endif

// create new procfs node; filename is absolute
// - this allocates a struct whose address it returns, which needs
//   to be passed to the _delete call
struct sym_procfs_info *
sym_procfs_new(const char *filename, sym_procfs_readfunc_t *readfunc,
	       sym_procfs_writefunc_t *writefunc)
{
    struct sym_procfs_info *proc_info;	// holds our stuff
    struct proc_dir_entry *proc_dentry;		// procfs dir node

    if (!(proc_info = kmalloc(sizeof(struct sym_procfs_info), GFP_KERNEL)))
	return NULL;

    memset(proc_info, 0, sizeof(*proc_info));

    proc_info->readfunc = readfunc;
    proc_info->writefunc = writefunc;
    //  create /proc entry
#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
    if (!(proc_dentry = create_proc_entry(filename, S_IFREG | S_IRUSR | S_IWUSR,
	NULL)))
    {
	// diagnostic?
	kfree(proc_info);
	return NULL;
    }

    // point the /proc node at our generic read/write functions
    proc_dentry->data = (void *)proc_info;
    proc_dentry->read_proc = sym_procfs_genread;
    proc_dentry->write_proc = sym_procfs_genwrite;
#else
    // point the /proc node at our generic file_operations based read/write functions
    proc_info->fop.owner = THIS_MODULE;
    proc_info->fop.read = sym_procfs_fopread;
    proc_info->fop.write = sym_procfs_fopwrite;
    if (!(proc_dentry = proc_create_data(filename, S_IFREG | S_IRUSR | S_IWUSR,
	NULL, &(proc_info->fop),proc_info)))
    {
	// diagnostic?
	kfree(proc_info);
	return NULL;
    }

#endif
    // create and populate our struct to hold the callbacks
    proc_info->pde = proc_dentry;

    return proc_info;
}

// destroy procfs node created by sym_procfs_new
// - passed again the same abs pathname AND the handle from the
//   create, so the implementation can use either or both
void
sym_procfs_delete(const char *filename, struct sym_procfs_info *pfe)
{
    remove_proc_entry(filename, NULL);
    if (pfe)
	kfree(pfe);
}

// sprintf into buffer, updating pointers, stopping when full
// returns 0 if OK, nonzero if truncated
int
sym_procfs_printf(char *buf, int *offp, int count, const char *fmt, ...)
{
    int rc;
    int max;
    va_list argv;

    max = count - *offp;

    // no room left (need 1 char for vsnprintf's null-term)
    if (max <= 1)
	return 1;

    // room for something... copy as much as will fit
    va_start(argv, fmt);
    rc = vsnprintf(buf+*offp, max, fmt, argv);
    va_end(argv);

    // adjust *offp and return status
    if (rc >= max)
    {
	// truncated...
	*offp = count-1;
	return (rc - count);
    }

    // not truncated
    *offp += rc;
    return 0;
}
