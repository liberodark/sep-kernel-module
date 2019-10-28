// fileops.c - managing our modifications to the file_operations structs
//
// Copyright (C) 2005 Symantec Corporation. 
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2. 
// See the "COPYING" file distributed with this software for more info.


#define NO_VERSION

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#	include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/types.h>
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/file.h>
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/slab.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif 

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
#include <linux/magic.h> //PROC_SUPER_MAGIC pulled in from linux/proc_fs.h above on earlier kernels
#endif // KERNEL_VERSION(2,6,19)

#include "symevl.h"

#include "symev.h"
#include "fileops.h"
#include "symkutil.h"

// These routines support hooking over file_operations->flush, which
// we need to do to catch file closes down at the vfs level.
//
// Each filesystem has one or more file_operations structs, whose
// address gets written into (struct inode)->i_fop, when the inode is
// created or read from disk, and is copied into (struct file)->f_op
// when the file is opened.  Some of these structs are specific for
// special kinds of files or filesystems; others are general-purpose.
//
// Our strategy is to patch the .flush member of the file_operations
// structure for "real" regular files for each filesystem.  We do this
// when we complete an open() or creat() syscall, by checking that
// it's a regular file and that it's not already been patched.  We
// keep a table of file_operations addresses and their original
// contents, so we can restore them when we unload, without having to
// patch any actual file or inode structs.
//

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
// NB:  As of 2.6.18, all (struct file_operations) structs and
// pointers are declared "const", so we can no longer patch the
// content of the structures themselves.  So, for these kernels, we
// instead allocate a new struct, initialize it from the original,
// patch that copy, and point to that copy instead of the original. 
// Because open files will now hold pointers to our data, it will be
// impossible to unload symev on these systems, but that's OK since
// unloading isn't allowed anyway.

#	define CONST_FILE_OPS
#	define FILE_OPS_SCLASS	const
#	define FOP_HASH_N	16

#else

#	define FILE_OPS_SCLASS
#	define FOP_HASH_N	1

#endif

#define FOPMAP_SIZE_INCR	16	// alloc/grow by # entries at a time

// the file_operations map, a linked list of structs, protected by a
// spinlock for modifications
struct fopmap_str
{
    FILE_OPS_SCLASS struct file_operations *os_fop;	// addr of the native file_operations
    const char *fsname;			// addr of filesystem name (for dbg)
    struct file_operations orig_fop;	// copy of orig struct (or, our patched version)
};

static struct fopmaps_str
{
    struct fopmaps_str *next;		// link forward
    struct fopmap_str fopmaps[FOPMAP_SIZE_INCR];
} *symev_fopmap[FOP_HASH_N] = {NULL};

// number of items allocated, currently in use
static int symev_fopmap_n[FOP_HASH_N] = {0};
static int symev_fopmap_cnt[FOP_HASH_N] = {0};

#ifndef CONST_FILE_OPS
// the file_operations map that records structs we've patched where the
// original handler was NULL.  This is the most common case so keeping these
// separate allows us to search (the other list) faster when there is one.
// This is protected by the same spinlock
static struct fopmap_null_str
{
    struct file_operations *os_fop;	// addr of the native file_operations
    const char *fsname;			// addr of filesystem name (for dbg)
} *symev_fopmap_null = NULL;

// number of items allocated, currently in use
static int symev_fopmapnull_n = 0;
#endif
static int symev_fopmapnull_cnt = 0;

// counters
static __u64 symev_fopmap_patch = 0;		// file_ops patched
static __u64 symev_fopmap_nopatch = 0;		// times unable to patch (bad)
static __u64 symev_fopmap_reuse = 0;		// times reused an old patch (good)

// mutex to coordinate access to these maps
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,36)
static DECLARE_MUTEX(fop_mutex);
#else
static DEFINE_SEMAPHORE(fop_mutex);
#endif

#define FOP_LOCK()	down(&fop_mutex)
#define FOP_UNLOCK()	up(&fop_mutex)

// hash (with optimization if no hashing needed in this build)
static inline int hash_pmap(const void *pfop)
{
#if FOP_HASH_N == 1
    return 0;
#elif FOP_HASH_N == 16
    int i = (int)(((long)(pfop)) >> 16); 	// only care about upper word
    int j = i ^ (i >> 8);	// convolve to lower byte of j
    j ^= (j >> 4);		// and to the lower nyb
    
    return j & 0xf;
#else
#warn	unexpected value of fop_hash_n
#endif
}

// find the file_operations pointer value in the map
// return with pmap and ppos pointing to the map block and
// the actual entry giving the first match.  return value
// is 0 if found, nonzero if not.  pmap/ppos will be
// unchanged if not found.
static inline int symev_fops_find(const void *fop_to_find, 
    const void *fop_to_store, struct fopmaps_str **ppmap, struct fopmap_str **pppos)
{
    int i;
    struct fopmaps_str *pmap;

    pmap = symev_fopmap[hash_pmap(fop_to_store)];

    while (pmap)
    {
	// walk list of arrays to find an unused slot
	for (i = 0; i < FOPMAP_SIZE_INCR; i++)
	{
	    if (pmap->fopmaps[i].os_fop == fop_to_find)
	    {
		*pppos = &pmap->fopmaps[i];
		*ppmap = pmap;
		return 0;
	    }
	}

	pmap = pmap->next;
    }

    return 1;
}

// find and map the 1st unused entry; we assume this will be called
// by the inline'd version that checks for being patched before calling us.
void
_symev_check_fopmap(struct file *file)
{
    FILE_OPS_SCLASS struct file_operations *pfop = file->f_op;
    extern symev_fop_flush_t symev_flush_null;
    extern symev_fop_flush_t symev_flush;
    struct fopmaps_str *pmap;
    struct fopmap_str *ppos;
    
    FOP_LOCK();

    // ensure we have not yet patched this one, to be safe
    if ((pfop->flush == symev_flush) || (pfop->flush == symev_flush_null))
    {
	// already patched!  wish we'd noticed this the 1st time...
	FOP_UNLOCK();
	return;
    }
	//Etrack 3869840: replacing f_op pointer on namespace files causes setns() syscall to fail as it uses static f_op pointer address
	//to verify it is a valid namespace file.  To avoid this and avoid other issues, don't hook flush/write on proc filesystem.
	if (KERNEL_VERSION_FILE_DENTRY(file)->d_sb->s_magic == PROC_SUPER_MAGIC
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
		//also exclude NSFS (namespace filesystem) on kernels where namespace files exist in nsfs.
		|| KERNEL_VERSION_FILE_DENTRY(file)->d_sb->s_magic == NSFS_MAGIC
#endif //KERNEL_VERSION(3,19,0)
		)
	{
		symev_trace(2, "Skipping flush hook on proc filesystem: inode %llu filesystem type id %lu\n",
		(unsigned long long)KERNEL_VERSION_FILE_DENTRY(file)->d_inode->i_ino, KERNEL_VERSION_FILE_DENTRY(file)->d_sb->s_magic);
		FOP_UNLOCK();
		return;
	}

#ifdef CONST_FILE_OPS
    // in this variant, the usual case is that the file_ops have already
    // been seen and a patched copy made, so all we need to do is to notice
    // that and point this new comer at that copy
    ppos = NULL;
    if (symev_fops_find(pfop, pfop, &pmap, &ppos) == 0)
    {
	file->f_op = &ppos->orig_fop;	// reuse existing one
	symev_fopmap_reuse++;		// reused patch count

	FOP_UNLOCK();

	symev_trace(2, "fopmap_check_entry: reused f_op %p (%s), slot %p/%d (normal handler)\n",
	    pfop, ppos->fsname, pmap, (int)(ppos - &pmap->fopmaps[0]) );

	return;
    }
#endif

#ifndef CONST_FILE_OPS
    // definitely need to patch this one... find an empty slot and grab
    // it, while holding spinlock
    if (pfop->flush == NULL)
    {
	int i;

	// (re)allocate map if necessary
	if (symev_fopmapnull_cnt >= symev_fopmapnull_n)
	{
	    struct fopmap_null_str *newmap =
		kmalloc((sizeof(struct fopmap_null_str) *
		    (symev_fopmapnull_n + FOPMAP_SIZE_INCR)), GFP_KERNEL);

	    if (!newmap)
	    {
		// unable to (re)allocate table - debug and forget it
		symev_trace(2, "fopmap_check_entry: could not (re)allocate %d-entry fopmap_null table\n",
		    symev_fopmapnull_n + FOPMAP_SIZE_INCR);

		FOP_UNLOCK();
		return;
	    }

	    // copy over any existing data and release it
	    if (symev_fopmap_null)
	    {
		memcpy((void *)newmap, (void *)symev_fopmap_null,
		    (symev_fopmapnull_n * sizeof(struct fopmap_null_str)));
		kfree(symev_fopmap_null);
	    }

	    symev_fopmap_null = newmap;

	    // erase the new part
	    memset((void *)(symev_fopmap_null + symev_fopmapnull_n),
		0, (FOPMAP_SIZE_INCR * sizeof(struct fopmap_null_str)));

	    symev_fopmapnull_n += FOPMAP_SIZE_INCR;

	    symev_trace(1, "fopmap_check_entry: alloc new fopmap_null %d entries\n",
		symev_fopmapnull_n);
	}

	for (i = 0; i < symev_fopmapnull_n; i++)
	{
	    if (symev_fopmap_null[i].os_fop == NULL)
	    {
		// save info about the original system fops
		symev_fopmap_null[i].fsname = sym_get_vfs_mount(file)->mnt_sb->s_type->name;  // name, for dbg
		symev_fopmap_null[i].os_fop = pfop;	// save address

		// install our hook; as of this point it's live
		// -- we have a special optimized hook that knows there is
		// no system flush routine, which is very common on linux.
		pfop->flush = symev_flush_null;

		// count
		symev_fopmap_patch++;		// times patched
		symev_fopmapnull_cnt++;	// current patch count

		FOP_UNLOCK();

		symev_trace(1, "fopmap_check_entry: patched f_op %p (%s), slot %d (null handler)\n",
		    pfop, symev_fopmap_null[i].fsname, i);
		return;
	    }
	}
    }
    else
#endif // CONST_FILE_OPS
    {
	int hslot;

	// get this guy's hash slot
	hslot = hash_pmap(pfop);

	// allocate a new map if necessary
	if (symev_fopmap_cnt[hslot] >= symev_fopmap_n[hslot])
	{
	    struct fopmaps_str *newmap =
		kmalloc(sizeof(struct fopmaps_str), GFP_KERNEL);

	    if (!newmap)
	    {
		// unable to allocate table - debug and forget it
		symev_trace(2, "fopmap_check_entry: could not allocate %d-entry fopmap table for slot %d\n",
		    FOPMAP_SIZE_INCR, hslot);

		FOP_UNLOCK();
		return;
	    }

	    // erase the new block
	    memset((void *)newmap, 0, sizeof(struct fopmaps_str));

	    // link the new block at the head of the list
	    newmap->next = symev_fopmap[hslot];
	    symev_fopmap[hslot] = newmap;

	    symev_fopmap_n[hslot] += FOPMAP_SIZE_INCR;

	    symev_trace(1, "fopmap_check_entry: alloc slot %d fopmap at %p, total %d entries\n",
		hslot, symev_fopmap[hslot], symev_fopmap_n[hslot]);
	}

	ppos = NULL;

	symev_fops_find(NULL, pfop, &pmap, &ppos);	// find an empty slot

	// if we found an entry, populate it and return
	if (ppos)
	{
	    ppos->orig_fop = *pfop;	// struct asn existing
	    ppos->fsname = sym_get_vfs_mount(file)->mnt_sb->s_type->name;  // name, for dbg
	    ppos->os_fop = pfop;	// save address

#ifdef CONST_FILE_OPS
	    // install our hook; as of this point it's live
	    ppos->orig_fop.flush = (pfop->flush ? symev_flush : symev_flush_null);
	    file->f_op = &ppos->orig_fop;
#else
	    // install our hook; as of this point it's live
	    pfop->flush = symev_flush;
#endif

	    // count
	    symev_fopmap_patch++;		// times patched
	    symev_fopmap_cnt[hslot]++;		// current patch count

	    FOP_UNLOCK();

	    symev_trace(1, "fopmap_check_entry: patched f_op %p (%s), slot %p/%d (normal handler)\n",
		pfop, ppos->fsname, pmap, (int)(ppos - &pmap->fopmaps[0]) );
	    return;
	}
    }

    symev_fopmap_nopatch++;	// count this no-patch

    FOP_UNLOCK();

    // should not happen but we want to know if it does
    printk("<1>fopmap_check_entry: table is full, cannot patch pfop=%p (%s)\n",
	pfop, sym_get_vfs_mount(file)->mnt_sb->s_type->name);
    return;
}


// symev_fops_unhook() - restore the file_operations handlers we've hooked
// this does not deallocate the pointers to the original fops routines;
// that's done in the _release function in a second phase
// -- again, this isn't absolutely safe but should be OK for debugging
// -- and it can't be done at all on CONST_FILE_OPS systems
// NB: since support for CONST_FILE_OPS was added (2/2007), this code is
// untested, and probably shouldn't be counted on to work
int
symev_fops_unhook(void)
{
    // NB:  there is a little race, in the linux filp_close routine,
    // where it checks f_op->flush for non-null, then derefs it; the
    // fs code does not expect this to change out from under it.  This
    // could only be a risk on an SMP machine, when the module is
    // unloaded, which never happens in production.

    int h, i;
    extern symev_fop_flush_t symev_flush_null;
    extern symev_fop_flush_t symev_flush;
    struct fopmaps_str *pmap;

    FOP_LOCK();

    // iterate over the (locked) fops cache and restore them in turn.

    // walk list of arrays to find an unused slot
    for (h = 0; h < FOP_HASH_N; h++)
    {
	pmap = symev_fopmap[h];

	while (pmap)
	{
	    for (i = 0; i < FOPMAP_SIZE_INCR; i++)
	    {
		// if this slot is being used
		if (pmap->fopmaps[i].os_fop != NULL)
		{
		    FILE_OPS_SCLASS struct file_operations *pfop;
		    struct fopmap_str *ppos;

		    ppos = &pmap->fopmaps[i];		// this slot's fopmap_str
		    pfop = ppos->os_fop;		// addr of system original file_ops

#ifdef CONST_FILE_OPS
		    // restore the pointer in the file_operations struct we've
		    // forced them to use, regardless of what's currently there
		    ppos->orig_fop.flush = pfop->flush;
#else
		    if (pfop->flush == symev_flush)
		    {
			// yes, looks like we had patched it
			if (ppos->orig_fop.flush != pfop->flush)
			{
			    // and looks like unpatching is safe, so we do it
			    pfop->flush = ppos->orig_fop.flush;

			    symev_fopmap_cnt[h]--;

			    symev_trace(1, "symev_fops_unhook: unpatched f_op %p, slot %d; flush now back at %p\n",
				pfop, i, pfop->flush);
			}
			else
			{
			    // we've recursively patched; not good!
			    pfop->flush = NULL;
			    symev_trace(1, "symev_fops_unhook: unpatched f_op %p, slot %d; set flush to NULL due to recursion!\n",
				pfop, i);
			}
		    }
		    else if (pfop->flush == ppos->orig_fop.flush)
		    {
			symev_trace(1, "symev_fops_unhook: already unpatched f_op %p, slot %d\n",
			    pfop, i);
		    }
		    else
		    {
			symev_trace(1, "symev_fops_unhook: didn't unpatch f_op %p, slot %d; flush was %p, not one of ours!\n",
			    pfop, i, pfop->flush);
		    }
#endif
		}
	    }

	    // next block of maps
	    pmap = pmap->next;
	}
    }

#ifndef CONST_FILE_OPS
    // iterate over the (locked) fops null cache and restore them in turn.
    for (i = 0; i < symev_fopmapnull_n; i++)
    {
	// if slot is in use
	if (symev_fopmap_null[i].os_fop != NULL)
	{
	    struct file_operations *pfop = symev_fopmap_null[i].os_fop;

	    if (pfop->flush == symev_flush_null)
	    {
		// yes, looks like we had patched it
		pfop->flush = NULL;

		symev_fopmapnull_cnt--;

		symev_trace(1, "symev_fops_unhook: unpatched f_op %p, slot %d (null); flush now back at %p\n",
		    pfop, i, pfop->flush);
	    }
	    else if (pfop->flush == NULL)
	    {
		symev_trace(1, "symev_fops_unhook: already unpatched f_op %p, slot %d (null)\n",
		    pfop, i);
	    }
	    else
	    {
		symev_trace(1, "symev_fops_unhook: didn't unpatch f_op %p, slot %d (null); flush was %p, not one of ours!\n",
		    pfop, i, pfop->flush);
	    }
	}
    }
#endif

    FOP_UNLOCK();
    return 0;
}

// release all information about the old fops handlers.  this
// should be called holding the hooks lock, and only when we believe
// the handlers are no longer running
//  -- again, this isn't absolutely safe but should be OK for debugging
// NB: since support for CONST_FILE_OPS was added (2/2007), this code is
// untested, and probably shouldn't be counted on to work
int
symev_fops_release(void)
{
#ifdef CONST_FILE_OPS
    symev_trace(1, "symev_fops_release: cannot release fops memory on this system\n");

    return -EOPNOTSUPP;
#else
    int i;

    FOP_LOCK();

    // for each hash bucket, blank and free all the blocks that were allocated
    for (i = 0; i < FOP_HASH_N; i++)
    {
	struct fopmaps_str *next;

	if (symev_fopmap_n[i])
	{
	    while (symev_fopmap[i])
	    {
		next = symev_fopmap[i]->next;

		// wipe out the handler addresses (just to be safe) and then free
		memset((char *)symev_fopmap[i], 0, sizeof(struct fopmaps_str));

		kfree(symev_fopmap[i]);
		symev_fopmap[i] = next;
		symev_fopmap_n[i] -= FOPMAP_SIZE_INCR; 
	    }
	}

	symev_fopmap_cnt[i] = 0;
    }

    if (symev_fopmapnull_n)
    {
	memset((char *)symev_fopmap_null, 0, 
	    (sizeof(struct fopmap_null_str) * symev_fopmapnull_n));

	kfree(symev_fopmap_null);
	symev_fopmap_null = NULL;
	symev_fopmapnull_n = symev_fopmapnull_cnt = 0;
    }

    FOP_UNLOCK();
    return 0;

#endif // CONST_FILE_OPS
}


// translate a pointer to one of our file_operations blocks to the map struct
static inline struct fopmap_str *fop_to_map(const struct file_operations *fop)
{
    const void *_fop = fop;
    struct fopmap_str d;

    return (struct fopmap_str *)(_fop - ((caddr_t)(&d.orig_fop) - (caddr_t)&d));
}

// symev_fop_flush() - find and call the sys flush handler for the given file
int
symev_fop_flush(struct file *fp
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
            , fl_owner_t id
#endif
	)
{
    int ret = 0;
    struct fopmap_str *ppos;

#ifdef CONST_FILE_OPS
    // the filesystem's real flush handler is in ppos->os_fop
    ppos = fop_to_map(fp->f_op);

    // the expected case: we know how to call the system handler (if any)
    if (ppos->os_fop->flush)
    {
	symev_trace(2, "symev_fop_flush: calling native flush routine at %p\n",
	    ppos->os_fop->flush);
	ret = (*ppos->os_fop->flush)(fp
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
	    , id
#endif
	    );
    }
    else
	symev_trace(2, "symev_fop_flush: no native flush routine\n");
#else // CONST_FILE_OPS
    struct fopmaps_str *pmap;

    // the filesystem's real flush handler is in ppos->orig_fop
    if (symev_fops_find(fp->f_op, fp->f_op, &pmap, &ppos))
    {
	symev_trace(1, "symev_fop_flush: couldn't find map for %p\n",
	    fp->f_op);
    }
    else if (ppos->orig_fop.flush)
    {
	symev_trace(2, "symev_fop_flush: calling native flush routine at %p\n",
	    ppos->orig_fop.flush);
	ret = (*ppos->orig_fop.flush)(fp
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
	    , id
#endif
	    );
    }
    else
	symev_trace(2, "symev_fop_flush: no native flush routine\n");
#endif

    return ret;
}

// /dev/symev access
void
symev_fops_devread(char *buf, int *plen, int mlen)
{
    // read out the current status of the fops map
    int i, h, ret;
    char *bp = buf + *plen;
    int left = mlen - *plen;
    struct fopmaps_str *pmap;

    ret = snprintf(bp, left, "=== FOPMAPS %s===\n"
	"patch       = %llu\n"
	"nopatch     = %llu\n"
	"reuse       = %llu\n"
	"mapnull_cnt = %d\n",
#ifdef CONST_FILE_OPS
    	"(C) ",		// indicate CONST_FILE_OPS
#else
	"",		// normal
#endif   
	symev_fopmap_patch,
	symev_fopmap_nopatch,
	symev_fopmap_reuse,
	symev_fopmapnull_cnt);
    if (ret > 0) { bp += ret; left -= ret; }

    for (h = 0; h < FOP_HASH_N; h++)
    {
	pmap = symev_fopmap[h];
	if (pmap)
	{
	    ret = snprintf(bp, left, "=== FOPS %d [%d/%d] ===\n", 
		h, symev_fopmap_cnt[h], symev_fopmap_n[h]);
	    if (ret > 0) { bp += ret; left -= ret; }
	}

	while ((left > 0) && pmap)
	{
	    for (i = 0; (left > 0) && i < FOPMAP_SIZE_INCR; i++)
	    {
		if (pmap->fopmaps[i].os_fop)
		{
#ifdef CONST_FILE_OPS
		    ret = snprintf(bp, left, "f[%p]=%s/%p\n",
			&pmap->fopmaps[i], pmap->fopmaps[i].fsname, pmap->fopmaps[i].os_fop);
#else
		    ret = snprintf(bp, left, "f[%p]=%s/%p:%p\n",
			&pmap->fopmaps[i], pmap->fopmaps[i].fsname, pmap->fopmaps[i].os_fop,
			pmap->fopmaps[i].orig_fop.flush);
#endif
		    if (ret > 0) { bp += ret; left -= ret; }
		}
	    }

	    pmap = pmap->next;
	}
    }

#ifndef CONST_FILE_OPS
    ret = snprintf(bp, left, "=== FOPS_NULL [%d] ===\n", symev_fopmapnull_n);
    if (ret > 0) { bp += ret; left -= ret; }

    for (i = 0; (left > 0) && (i < symev_fopmapnull_n); i++)
    {
	if (symev_fopmap_null[i].os_fop)
	{
	    ret = snprintf(bp, left, "fopmap_null[%d].os_fop=%p (%s)\n",
		i, symev_fopmap_null[i].os_fop, symev_fopmap_null[i].fsname);
	    if (ret > 0) { bp += ret; left -= ret; }
	}
    }
#endif

    // adjust pointer for caller
    if (left > 0)
	*plen = mlen - left;	// room left
    else
	*plen = mlen;	// full

    return;
}
