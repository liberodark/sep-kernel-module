// fileops.h - interface for symev file_operations hooks
//
// Copyright (C) 2005 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/stat.h>
#include <linux/fs.h>
#include <linux/version.h>

/* makes sure that the kernel version is appropriate since the predeccessor kernels have slightly
different structure members. */
#ifndef KERNEL_VERSION_FILE_DENTRY
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
#define KERNEL_VERSION_FILE_DENTRY(pfile) (pfile)->f_path.dentry
#else
#define KERNEL_VERSION_FILE_DENTRY(pfile) (pfile)->f_dentry
#endif	/* #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0) */
#endif	/* #ifndef KERNEL_VERSION_FILE_DENTRY */


static struct file_operations *_dummy_fop;
typedef typeof (*_dummy_fop->flush) symev_fop_flush_t;

extern symev_fop_flush_t symev_fop_flush;	// call underlying OS flush
extern int symev_fops_unhook(void);		// unhook all fops hooks
extern int symev_fops_release(void);		// release all fops hook data

extern void symev_fops_devread(char *buf, int *plen, int mlen);  // read info


// symev_check_fopmap() - check that the file's file_operations
// have been hooked; if not, hook them now
extern void _symev_check_fopmap(struct file *file);

static inline void
symev_check_fopmap(struct file *file)
{
    extern symev_fop_flush_t symev_flush_null;
    extern symev_fop_flush_t symev_flush;
    symev_fop_flush_t *pflush = file->f_op->flush;

    // pre-check, no locks, no looking back -- this is the usual case so we
    // want it fast.
    if ((pflush == symev_flush) || (pflush == symev_flush_null))
	return;

    // make sure it's a regular file
	if(!S_ISREG(KERNEL_VERSION_FILE_DENTRY(file)->d_inode->i_mode))
	{
		return;
	}

    // OK, not yet hooked.  Should be very rare.  Do the deed.
    _symev_check_fopmap(file);
}

