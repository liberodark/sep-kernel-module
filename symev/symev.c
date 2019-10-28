// symev - Linux OS hooks module
//
// Copyright (C) 2017 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

// the following preprocessor symbols control the build
//  define CONFIG_SMP for an SMP version of the driver
//  define MODULE to make us loadable

// allow export of symbols
#define EXPORT_SYMTAB

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#include <linux/config.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
#define __KERNEL_SYSCALLS__
#endif

#include <linux/module.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <linux/moduleparam.h>
#endif

#include <linux/types.h>
#include <linux/utsname.h>

#ifndef UTS_RELEASE
#include <linux/vermagic.h>
#endif

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/unistd.h>

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,27)
#include <asm/syscalls.h>
#endif

#include <linux/syscalls.h>
#include <linux/namei.h>

#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/genhd.h>		// for get_gendisk (drive typing)
#include <scsi/scsi.h>			// for SCSI device typing (ugh!)
#include <linux/rwsem.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
#include <linux/smp_lock.h>
#endif

#include <linux/rwsem.h>
#include <asm/atomic.h>
#include <asm/uaccess.h>
#include <asm/mman.h>			// for mmap wrapper

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
#include <asm/cacheflush.h>		// for page protection
#endif

#ifdef __x86_64__
#include <linux/ptrace.h>
#endif

#ifdef CONFIG_COMPAT
  #if LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    asmlinkage long compat_sys_open(const char __user *filename, int flags,int mode);
  #else
    #include <linux/compat.h>
  #endif
#endif

#include <linux/workqueue.h>

// define the module license mode
MODULE_LICENSE("GPL");

// make an alias for easier load/unload (2.6 and newer)
#ifdef MODULE_ALIAS
MODULE_ALIAS("symev");
#endif

#include <symevl.h>
#include <symtypes.h>
#include "symkutil.h"
#include "symprocfs.h"
#include "distribution.h"

#ifdef DEBIAN_VERSION
#define DEBIAN_VERSION_FINAL DEBIAN_VERSION
#else //DEBIAN_VERSION
#define DEBIAN_VERSION_FINAL 0
#endif //DEBIAN_VERSION

#if DEBIAN_VERSION_FINAL >= 2048 //=Debian 8.0 calculated by 8<<8 + 0
#define FILE_MMAP_WRITABLE_ATOMIC_READ
#endif //DEBIAN_VERSION_FINAL >= 2048

#ifndef UBUNTU_OS
#define UBUNTU_OS 0
#endif

#include "symev.h"
#include "fileops.h"
#include "hnfs.h"

extern void * symev_find_syscall_table(void);

// all builds can enable tracing via symev_trace
int symev_trace_level = 0;

// interval, in seconds, to re-check for NFS being loaded
// NB: should make this tunable and disable-able, in case it might cause
// problems for some folks
#define NFS_CHECK_INT   15

// forward
int symev_getfinfo(symev_ev_t *, unsigned long flags, char *);
int symev_fgetfinfo(symev_ev_t *, int);
int symev_fpgetfinfo(symev_ev_t *, struct file *);
int symev_dmgetfinfo(symev_ev_t *, struct dentry *, struct vfsmount *);

// forward decls for hook services (as needed)
symev_fop_flush_t symev_flush_null;
symev_fop_flush_t symev_flush;

// forward decls for registry functions
void symev_reg_devread(char *buf, int *plen, int mlen);
void symev_deliver(symev_ev_t *ev);

void **symev_syscall_table = NULL;        // our ptr to the syscall tbl

extern unsigned long symbol_in_kallsyms(const char* sym, const char* mod);
typedef struct vm_area_struct* (*_pfn_find_vma_prev)(struct mm_struct * mm, unsigned long addr, struct vm_area_struct **pprev);
_pfn_find_vma_prev symev_find_vma_prev = NULL;


#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
int set_addr_rw(long unsigned int _addr, int ipages)
{
    unsigned int level;
	int rc = 0;
	int i = 0;
	long unsigned int address = _addr;

	do
	{
		address += i*PAGE_SIZE;

		symev_trace(1, "symev: set_addr_rw.\n");
		pte_t *pte = lookup_address(_addr, &level);

		if(pte)
		{
			if (pte->pte &~ _PAGE_RW) 
			{
				pte->pte |= _PAGE_RW;
				symev_trace(1, "symev: successfully set the page to RW.\n");
			}
			else
				symev_trace(1, "symev: page is already RW.\n");
		}
		else
		{
			symev_trace(1, "symev: lookup_address failed to find the kernel page.\n");
			rc =1;
		}
	}
	while (++i < ipages);

	return rc;
}

int set_addr_ro(long unsigned int _addr, int ipages)
{
    unsigned int level;
	int rc =0;
	int i = 0;
	long unsigned int address = _addr;

	do
	{
		address += i*PAGE_SIZE;

		pte_t *pte = lookup_address(_addr, &level);
		if(pte)
		{
			pte->pte = pte->pte &~_PAGE_RW;
		}
		else
		{
			symev_trace(1, "symev: lookup_address failed to find the kernel page.\n");   
			rc = 1;
		}
	} while (++i < ipages);
	return rc;
}

#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)


#if( LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,41) )

// above kernel version 3.6, function kern_path_parent doesn't exist any more
// port it's implementation (to symev_kern_path_parent) from kernel v3.5
// after kernel version 3.8.13, function do_path_lookup cannot be found in /proc/kallsym. Maybe, it is inlined
// port it's implementation (to symev_kern_path_parent) from kernel v3.7
// the filename_lookup is added in kernel v3.7
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)

int (*symev_kern_path_parent)(const char *, struct nameidata *) = NULL;

#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)

int (*symev_do_path_lookup)(int, const char *, unsigned int, struct nameidata *) = NULL;
static int symev_kern_path_parent(const char *name, struct nameidata *nd)
{
    // invoke do_path_lookup(AT_FDCWD, name, LOOKUP_PARENT, nd);
    return symev_do_path_lookup(AT_FDCWD, name, LOOKUP_PARENT, nd);
}

#else 

int (*symev_filename_lookup)(int, struct filename *, unsigned int, struct nameidata *) = NULL;
static int symev_kern_path_parent(const char *name, struct nameidata *nd)
{
    // after kernel v3.8.13, the do_path_lookup cannot be found in /proc/kallsyms
    // invoke filename_lookup which is added in is kernel v3.7
    struct filename filename = { .name = name };
    return symev_filename_lookup(AT_FDCWD, &filename, LOOKUP_PARENT, nd);
}

#endif // LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,41)

// RHEL 6.5(kernel 2.6.32-431) back ported getname/putname, their signatures change just like in kernel version 3.7.0,
// whilst putname is still exported as a difference
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,1,0)
typedef char sym_filename_t;
static char* sym_filename_str(sym_filename_t* fn) { return fn; }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
typedef struct filename sym_filename_t;
static char* sym_filename_str(sym_filename_t* fn) { return fn==NULL? NULL: fn->name; }
#else //LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
#if defined(RHEL_RELEASE_CODE) && defined(RHEL_RELEASE_VERSION)
#if RHEL_RELEASE_CODE >= RHEL_RELEASE_VERSION(6,5)
typedef struct filename sym_filename_t;
static char* sym_filename_str(sym_filename_t* fn) { return fn==NULL? NULL: fn->name; }
#else
typedef char sym_filename_t;
static char* sym_filename_str(sym_filename_t* fn) { return fn; }
#endif
#else
typedef char sym_filename_t;
static char* sym_filename_str(sym_filename_t* fn) { return fn; }
#endif
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)

// above kernel v3.7, getname changes its signature and putname doesnt export any more,
// we implement putname here, also getname in pair
void symev_putname(sym_filename_t *name)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
    putname(name); //call kernel exported putname directly
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    if (name->separate) {
        __putname(name->name);
        kfree(name);
    } else {
        __putname(name);
    }
#else
	//Etrack 3906089: partner to "getname" below.
	if (name) {
    	__putname(name);
	}
#endif
}

// copy getname_flags's implementation except audit_ parts
#define EMBEDDED_NAME_MAX	(PATH_MAX - sizeof(struct filename))
sym_filename_t * symev_getname(const char * filename)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
    return getname(filename); //call kernel exported getname directly
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,1,0)
    int flags = 0;
    int *empty = NULL;
	struct filename *result, *err;
	int len;
	long max;
	char *kname;

	result = __getname();
	if (unlikely(!result))
		return ERR_PTR(-ENOMEM);

	/*
	 * First, try to embed the struct filename inside the names_cache
	 * allocation
	 */
	kname = (char *)result + sizeof(*result);
	result->name = kname;
	result->separate = false;
	max = EMBEDDED_NAME_MAX;

recopy:
	len = strncpy_from_user(kname, filename, max);
	if (unlikely(len < 0)) {
		err = ERR_PTR(len);
		goto error;
	}

	/*
	 * Uh-oh. We have a name that's approaching PATH_MAX. Allocate a
	 * separate struct filename so we can dedicate the entire
	 * names_cache allocation for the pathname, and re-do the copy from
	 * userland.
	 */
	if (len == EMBEDDED_NAME_MAX && max == EMBEDDED_NAME_MAX) {
		kname = (char *)result;

		result = kzalloc(sizeof(*result), GFP_KERNEL);
		if (!result) {
			err = ERR_PTR(-ENOMEM);
			result = (struct filename *)kname;
			goto error;
		}
		result->name = kname;
		result->separate = true;
		max = PATH_MAX;
		goto recopy;
	}

	/* The empty path is special. */
	if (unlikely(!len)) {
		if (empty)
			*empty = 1;
		err = ERR_PTR(-ENOENT);
		if (!(flags & LOOKUP_EMPTY))
			goto error;
	}

	err = ERR_PTR(-ENAMETOOLONG);
	if (unlikely(len >= PATH_MAX))
		goto error;

	result->uptr = filename;
	return result;

error:
	symev_putname(result);
	return err;
#else
	//Etrack 3906089: Implement our own "getname" instead of copying from the kernel again, and stop using 
	// filename struct.  It made sense when kernel exported this function, but it doesn't anymore.
	char *kname;
	int len;
 
	kname = __getname();
	if (unlikely(!kname))
		return ERR_PTR(-ENOMEM);
 
	len = strncpy_from_user(kname, filename, PATH_MAX);
	if (unlikely(len < 0)) {
		__putname(kname);
		return ERR_PTR(len);
	}
	if (unlikely(len == PATH_MAX)) {
		__putname(kname);
		return ERR_PTR(-ENAMETOOLONG);
	}
	if (unlikely(!len)) {
		__putname(kname);
		return ERR_PTR(-ENOENT);
	}

    return kname;
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
#define lock_kernel()   do {} while (0)
#define unlock_kernel() do {} while (0)
#endif

#define HOOK_SYSCALL(index, syscall, wrapper) \
    if (symev_syscall_table[index]) \
    { \
        symev_hooked.syscall = symev_syscall_table[index]; \
        symev_syscall_table[index] = wrapper; \
        symev_trace(1, "symev: hooked %s with %s at %p\n", #syscall, \
            #wrapper, (void *) wrapper); \
    } else { symev_trace(1, "symev: NOTICE: did not hook %s\n", #syscall); }

#define HOOK_SYSCALL_EX(index, syscall, wrapper, orig_function_backup) \
    if (symev_syscall_table[index]) \
    { \
        symev_hooked.syscall = symev_syscall_table[index]; \
        orig_function_backup = symev_syscall_table[index]; \
        symev_syscall_table[index] = wrapper; \
        symev_trace(1, "symev: hooked %s with %s at %p\n", #syscall, \
            #wrapper, (void *) wrapper); \
    } else { symev_trace(1, "symev: NOTICE: did not hook %s\n", #syscall); }

#define UNHOOK_SYSCALL(index, syscall, wrapper) \
    if (symev_syscall_table[index] == wrapper)	\
        symev_syscall_table[index] = symev_hooked.syscall; \
    else symev_trace(1, "symev: NOTICE: did not unhook %s\n", #syscall);


#ifdef CONFIG_COMPAT
extern void *symev_find_ia32_syscall_table(void);
long* symev_ia32_syscall_table = NULL;   // our ptr to the ia32 syscall tbl

//run 32-bit programs under a 64-bit kernel.
//the following are the syscall number on 32bit, and they aren't same to 64bit.
#define __NR_compat_write     4
#define __NR_compat_open      5
#define __NR_compat_creat     8
#define __NR_compat_link      9
#define __NR_compat_unlink   10
#define __NR_compat_rename   38
#define __NR_compat_symlink  83
#define __NR_compat_truncate 92

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#define __NR_compat_unlinkat 301
#define __NR_compat_renameat 302
#define __NR_compat_linkat 303
#define __NR_compat_symlinkat 304
#endif

#define HOOK_IA32SYSCALL(index, ia32syscall, wrapper) \
    if (symev_ia32_syscall_table[index]) \
    { \
        symev_ia32_hooked.ia32syscall = (void*)symev_ia32_syscall_table[index]; \
        symev_ia32_syscall_table[index] = (long)wrapper; \
        symev_trace(1, "symev: ia32syscall hooked %s with %s at %p\n", #ia32syscall, \
            #wrapper, (void *) wrapper); \
    } else { symev_trace(1, "symev: NOTICE: did not ia32syscall hook %s\n", #ia32syscall); }

#define UNHOOK_IA32SYSCALL(index, ia32syscall, wrapper) \
    if (symev_ia32_syscall_table[index] == (long)wrapper)	\
        symev_ia32_syscall_table[index] = (long)symev_ia32_hooked.ia32syscall; \
    else symev_trace(1, "symev: NOTICE: did not unhook ia32syscall %s\n", #ia32syscall);

#endif

// statistics counters
//  must hold symev_counters_lock for these
struct symev_ctr_str
{
    __u64 events;		// number of events deliverable
    __u64 namerr;		// number of name lookup errors
    __u64 nofinfo;		// number of file lookups that failed
    __u64 nomem;		// num of events dropped due to out of memory
    __u64 getfn;		// num of filename lookups
    __u64 r_denied;		// num of denied accesses (failure returns)
} symev_counters = {
    0, 0, 0, 0, 0, 0,
};

spinlock_t symev_counters_lock =
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        SPIN_LOCK_UNLOCKED;
#else
        __SPIN_LOCK_UNLOCKED(symev_counters_lock);
#endif

static struct workqueue_struct *interval_queue = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
static struct delayed_work interval_work;
#else
static struct work_struct interval_work;
#endif

// pointers to original system syscall handler routines we've hooked
// on 2.6 we have prototypes for all syscalls; 2.4, we fake it
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)

  #ifdef __i386__
    // this struct copied form kernel source code
    struct mmap_arg_struct {
        unsigned long addr;
        unsigned long len;
        unsigned long prot;
        unsigned long flags;
        unsigned long fd;
        unsigned long offset;
    };
    #if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,27)
      asmlinkage int old_mmap(struct mmap_arg_struct __user *arg);
    #endif
  #endif

  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19) 
    // above kernel v3.8, function sys_execve's declaration moved to include/linux/syscalls.h
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) && LINUX_VERSION_CODE <= KERNEL_VERSION(3,8,0)
      long sys_execve(const char __user *,
                      const char __user *const __user *,
                      const char __user *const __user *, struct pt_regs *);
    #elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
    #else
      int sys_execve(struct pt_regs regs);
    #endif

    #ifdef __x86_64__
      long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags,
        unsigned long fd, unsigned long off);
    #endif // __x86_64__

  #endif // LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)

  #define SC_DECLARE(SC)    typeof(SC) *SC

#else

  #if __GNUC__ == 2
    // very old 2.4 built with GCC2.96 doesn't accept the asmlinkage attribute
    // in the function pointer struct members
    #define SC_DECLARE(SC)  long (*SC)()
  #else
    #define SC_DECLARE(SC)  asmlinkage long (*SC)()
  #endif

#endif

#ifdef __x86_64__
asmlinkage void stub_execve(void);
#endif //__x86_64__

struct
{
    // syscalls
    SC_DECLARE(sys_open);
    SC_DECLARE(sys_creat);
    // SC_DECLARE(sys_close);
    // SC_DECLARE(sys_dup);
    // SC_DECLARE(sys_dup2);
#ifdef __i386__
    SC_DECLARE(sys_execve);
#else
    SC_DECLARE(stub_execve);
#endif //__i386__
    SC_DECLARE(sys_truncate);
    SC_DECLARE(sys_ftruncate);
    SC_DECLARE(sys_write);
    SC_DECLARE(sys_writev);
#ifdef __NR_pwrite64
    SC_DECLARE(sys_pwrite64);
#else
    SC_DECLARE(sys_pwrite);
#endif
#ifdef __NR_io_submit
    SC_DECLARE(sys_io_submit);
#endif
    SC_DECLARE(sys_sendfile);
    SC_DECLARE(sys_sendfile64);
#ifdef __i386__
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
    SC_DECLARE(old_mmap);
  #else
    SC_DECLARE(sys_old_mmap);
  #endif
#endif // __i386__
#ifdef __x86_64__
    SC_DECLARE(sys_mmap);
#endif // __x86_64__
    SC_DECLARE(sys_mprotect);
    SC_DECLARE(sys_unlink);
    SC_DECLARE(sys_rename);
    SC_DECLARE(sys_link);
    SC_DECLARE(sys_symlink);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    SC_DECLARE(sys_unlinkat);
    SC_DECLARE(sys_renameat);
    SC_DECLARE(sys_linkat);
    SC_DECLARE(sys_symlinkat);
#endif

    // SC_DECLARE(sys_chmod);
    // SC_DECLARE(sys_fchmod);
} symev_hooked = {NULL};

void* orig_stub_execve = NULL;

extern void* orig_stub_execve;

#ifdef CONFIG_COMPAT
struct
{
    /*Include code to run 32-bit programs under a 64-bit kernel.*/
    /*Kernel compatibililty routines for e.g. 32 bit syscall support
      on 64 bit kernels.*/
    SC_DECLARE(sys_write);
    SC_DECLARE(compat_sys_open);
    SC_DECLARE(sys_creat);
    SC_DECLARE(sys_link);
    SC_DECLARE(sys_unlink);
    SC_DECLARE(sys_rename);
    SC_DECLARE(sys_symlink);
    SC_DECLARE(sys_truncate);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    SC_DECLARE(sys_unlinkat);
    SC_DECLARE(sys_renameat);
    SC_DECLARE(sys_linkat);
    SC_DECLARE(sys_symlinkat);
#endif
} symev_ia32_hooked = {NULL};
#endif

// Semaphore to manage access to the hooked handlers (see symev.h)
DECLARE_RWSEM(symev_hooks_rwsem);

#ifdef DEBUG
// debug: handler_depth tracks nesting depth of handler call -- should
// track the same as the symev_hooks_rwsem semaphore's read count
atomic_t handler_depth = ATOMIC_INIT(0);

// debug: alloc_bal counts the balance between kmalloc and kfree
// calls; should generally be nonnegative and not ever-increasing.
atomic_t alloc_bal = ATOMIC_INIT(0);
#define	INC_ALLOC_CNT()	atomic_inc(&alloc_bal)
#define	DEC_ALLOC_CNT()	atomic_dec(&alloc_bal)

// debug: evref_bal counts the balance between event struct refs and
// derefs; it is the current number of outstanding refs
atomic_t evref_bal = ATOMIC_INIT(0);
#define	INC_EVREF_CNT()	atomic_inc(&evref_bal)
#define	DEC_EVREF_CNT()	atomic_dec(&evref_bal)

#else //DEBUG

#define	INC_ALLOC_CNT()	do {} while (0)
#define	DEC_ALLOC_CNT()	do {} while (0)

#define	INC_EVREF_CNT()	do {} while (0)
#define	DEC_EVREF_CNT()	do {} while (0)
#endif // DEBUG

//
// *** support for /proc/symev *******************************************
//

static const int symev_smp_build =
#ifdef CONFIG_SMP
  1;
#else
  0;
#endif

static const int symev_debug_build =
#ifdef DEBUG
  1;
#else
  0;
#endif

static const char * const symev_uts_release = UTS_RELEASE;	// capture for reporting

//nameidata structure definition has been picked up from /linux-3.19.0/fs/namei.c
//This structure may need to be updated when it is changed in the above kernel source file
//Else this may lead to runtime failures.
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,19,0)
 struct nameidata {
   struct path      path;
   struct qstr      last;
   struct path      root;
   struct inode     *inode;
   unsigned int     flags;
   unsigned         seq, m_seq;
   int              last_type;
   unsigned         depth;
   struct file      *base;
   char *saved_names[MAX_NESTED_LINKS + 1];
 };
#endif

// read /proc/symev -- return interesting state information
//   currently, we expect the entire read will happen in one call, so we
//   ignore the start/offset flags (which is safe)
int
symev_read_proc_symev(char *page, int *offp, int count)
{
    int len;
    struct symev_ctr_str ctrsnap;
    
    spin_lock(&symev_counters_lock);
    ctrsnap = symev_counters;		// structasn
    spin_unlock(&symev_counters_lock);

    len = snprintf(page, count, "=== BUILD ===\n"
        "MODULE=%s\n"
        "VER=%d.%d\n"
        "BUILD=%s"
#ifdef CONFIG_SMP
        " (SMP)"
#endif
#ifdef CONFIG_DEBUG_RODATA
        " (ROD)"
#endif
#ifdef DEBUG
        " (DEBUG)"
#endif
        "\n"
        "=== STATUS ===\n"
        "utsname=%s\n"
        "use_count=%d\n"
        "trace_level=%d\n"
        "sct=%p\n"
#ifdef DEBUG
        "handler_depth=%d\n"
        "alloc_bal=%d\n"
        "evref_bal=%d\n"
#endif
        "=== STATS ===\n"
        "events     = %lld\n"
        "getfn      = %lld\n"
        "nofinfo    = %lld\n"
        "namerr     = %lld\n"
        "nomem      = %lld\n"
        "r_denied   = %lld\n",
        "symev",
        SYMEV_VER_MAJOR, SYMEV_VER_MINOR,
        symev_uts_release,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
        UTS_RELEASE,
#else
        system_utsname.release,
#endif
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
        module_refcount(THIS_MODULE),		// 2.6 way
#else
        GET_USE_COUNT(THIS_MODULE),		// 2.4 way
#endif
        symev_trace_level,
        symev_syscall_table,
#ifdef DEBUG
        atomic_read(&handler_depth),
        atomic_read(&alloc_bal),
        atomic_read(&evref_bal),
#endif
        // stats
        ctrsnap.events, ctrsnap.getfn, ctrsnap.nofinfo,
        ctrsnap.namerr, ctrsnap.nomem, ctrsnap.r_denied);

    if (len > count)	// check for truncation
        len = count;

    // append the status of callback registrations
    symev_reg_devread(page, &len, count);

    // append the status of the file_operations patches
    symev_fops_devread(page, &len, count);

    // append the status of the NFS patches
    symev_hnfs_devread(page, &len, count);

    return len;
}


// write /proc/symev -- currently, this expects a character which represents
//   is the debug level to set (0=off, 1=normal, 2+=lots more)
int
symev_write_proc_symev(const char __user *buf, int count)
{
    char ubuf[64];
    
    // expect a small buffer containing an integer debug level
    if (count > sizeof(ubuf))
        return -EIO;

    if (copy_from_user(ubuf, buf, count))
        return -EFAULT;

    if (ubuf[0] >= '0' && ubuf[0] <= '9')
    {
        symev_trace_level = ubuf[0] - '0';
        printk("symev: set new trace level = %d"
#ifdef DEBUG
               " (DEBUG BUILD)"
#endif
               "\n", symev_trace_level);
    }

    if (ubuf[0] == '-')
    {
        symev_hnfs_reset();
    }
    if (ubuf[0] == '+')
    {
        int ret;
        ret = symev_hnfs_hook(eSTARTUPTOHOOK);   // re-check NFS hooks
        if (ret == 0)
            printk("symev: nfsd hooked.\n");
        else
            printk("symev: nfsd hook failed.\n");
    }

    return count;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#define D_PATH          d_path
#define PATH_RELEASE    path_release
#else
char* D_PATH(struct dentry *dentry, struct vfsmount *vfsmnt, char *buf, int buflen)
{
    struct path ph;
    ph.dentry = dentry;
    ph.mnt = vfsmnt;
    return d_path(&ph, buf, buflen);
}
void PATH_RELEASE(struct nameidata *nd)
{
    path_put(&nd->path);
}
#endif

// UTILITIES -------------------------------------------------------------
// return the event name, for debugging
static const char *
symev_evname(int ev)
{
    switch(ev)
    {
        case SEL_EV_ACCESS: return "USE";
        case SEL_EV_MODIFY: return "MODIFY";
        case SEL_EV_DONE: return "DONE";
        case SEL_EV_MODIFY_DONE: return "MODIFY_DONE";
        case SEL_EV_RENAME: return "RENAME";
        default: return "(?)";
    }
    // NOTREACHED
}

// EVENT MANAGEMENT ---------------------------------------------------

// symev_evnew() - obtain a new event structure
// can return NULL if alloc fails
static inline symev_ev_t *
symev_evnew(void)
{
    symev_ev_t *ev = NULL;

    // create and populate an event structure
    // XXX should pool these for efficiency
    if (!(ev = kmalloc(sizeof(symev_ev_t), GFP_KERNEL)))
    {
        spin_lock(&symev_counters_lock);
        symev_counters.nomem++;
        spin_unlock(&symev_counters_lock);

        return NULL;
    }

    INC_ALLOC_CNT();

    // initialize to empty w/ 1 ref
    memset(ev, 0, sizeof(symev_ev_t));

    atomic_set(&EVPVT(ev)->refs, 1);
    INC_EVREF_CNT();

    return ev;
}

// symev_evget() - get a reference to an existing event struct
SYMCALL symev_ev_t *
symev_evget(symev_ev_t *ev)
{
    atomic_inc(&EVPVT(ev)->refs);
    INC_EVREF_CNT();

    return ev;
}

// symev_evput() - release a reference to an existing event, and free
// it if this was the last reference
SYMCALL void
symev_evput(symev_ev_t *ev)
{
    if (!ev)
       return;

    DEC_EVREF_CNT();

    if (atomic_dec_and_test(&EVPVT(ev)->refs))
    {
        // we just decremented to zero -- our job to free it
        if (EVPVT(ev)->namebuf)
        {
            // was a name allocated -- need to free it also
            kfree(EVPVT(ev)->namebuf);
            DEC_ALLOC_CNT();
        }

        // release file references (OK if NULL)
        dput(EVPVT(ev)->dentry);
        mntput(EVPVT(ev)->mnt);

        kfree(ev);
        DEC_ALLOC_CNT();
    }
}


// EVENT HANDLERS -------------------------------------------------------

// the common filesystem event handler code -- after a fd or filename
// has been dug up, this populates the provided event struct, calls
// any registered callbacks and returns the right status.  Returns 0
// to allow completion, or -errno to force an error.  This is inlined
// into the variant event handlers for efficiency.
static inline int symev_fs_event(symev_ev_t *evp, const unsigned long ev,
    unsigned long fl, unsigned long data1, const char *funct)
{
    int ret = 0;
// Linux 2.6 kernel expanded dev_t and eliminated kdev_t
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    kdev_t kdev;
#else
    dev_t kdev;
#endif
    const char *fstype;

    // check conditions on generating an event
    if ((fl & SEL_EF_LASTLINK) && (evp->nlinks > 1))
    {
        // no event unless this is the last link to the file
        goto out;
    }

    // tally
    spin_lock(&symev_counters_lock);
    symev_counters.events++;
    spin_unlock(&symev_counters_lock);
    
    evp->event = ev;	// current event, flags, data
    evp->flags = fl;
    evp->evdata_1 = data1;

    // set file type -- an abstraction of the mode bits
    switch (evp->mode & S_IFMT)
    {
        case S_IFSOCK:
        case S_IFIFO:
            // socket or FIFO (comms endpoint)
            evp->fil_type = SEL_FIL_COMM;
            break;

        case S_IFBLK:
        case S_IFCHR:
            // block or char special
            evp->fil_type = SEL_FIL_DEV;
            break;

        case S_IFDIR:
            // directory
            evp->fil_type = SEL_FIL_DIR;
            break;

        case S_IFLNK:
            // symlink -- classify as LNK only on NOFOLLOW events (unlink)
            // otherwise it's a missing file (dangling symlink)
            evp->fil_type = (fl & SEL_EF_NOFOLLOW) ? SEL_FIL_LNK : SEL_FIL_FILE;
            break;

        default:
            symev_trace(1, "symev_fs_event: unknown file type 0%o, fid=%llx\n",
                (evp->mode & S_IFMT), evp->file_id);
            // fallthru to return as "regular" file
        case S_IFREG:
            // regular file
            evp->fil_type = SEL_FIL_FILE;

            // set a flag for client if MANDATORY LOCKING applies
            if (EVPVT(evp)->dentry && EVPVT(evp)->dentry->d_inode &&
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
                MANDATORY_LOCK(EVPVT(evp)->dentry->d_inode))
#else
                mandatory_lock(EVPVT(evp)->dentry->d_inode))
#endif
                evp->flags |= SEL_EF_MANDLOCK;
        break;
    }

    // set volume type -- see linux/major.h 
    //  XXX these are build-time constants; would be better to be able
    //  to resolve these device types based on runtime kernel
    evp->vol_type = SEL_VOL_FIXED;		// default assumption

    kdev = EVPVT(evp)->dentry->d_inode->i_sb->s_dev;	// dev number
    fstype = EVPVT(evp)->mnt->mnt_sb->s_type->name;  	// fs type

    if (MAJOR(kdev) == FLOPPY_MAJOR)			// floppy (by MAJOR)
        evp->vol_type = SEL_VOL_FLOPPY;
    else if (strncmp(fstype, "iso9660", 8) == 0)	// removable (by fstype)
        evp->vol_type = SEL_VOL_REMOVABLE;
    else if (strncmp(fstype, "proc", 5) == 0	// dynamic (by fstype)
        || strncmp(fstype, "sysfs", 6) == 0
#if( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE == 655872 )
        || strncmp(fstype, "nfsd", 5) == 0
#endif
        )
        // NB: we don't include other dynamic fstypes here (e.g. devfs)
        // because they won't ever hold regular files -- they could/should
        // be added if this optimization becomes undesirable
        evp->vol_type = SEL_VOL_DYNAMIC;
    else if (strncmp(fstype, "smbfs", 6) == 0	// remote (by fstype)
        || strncmp(fstype, "cifs", 5) == 0
        || strncmp(fstype, "afs", 4) == 0
        || strncmp(fstype, "nfs", 4) == 0
        || strncmp(fstype, "nfs4", 5) == 0
        || strncmp(fstype, "vmhgfs", 7) == 0
        )
        evp->vol_type = SEL_VOL_REMOTE;
    else
    {
        // get removeable bit from gendisk (partitions) table
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        struct gendisk *gp = get_gendisk(kdev);

        if (gp && gp->flags &&
            (gp->flags[(MINOR(kdev) >> gp->minor_shift)] & GENHD_FL_REMOVABLE))
            evp->vol_type = SEL_VOL_REMOVABLE;
#else
        // 2.6 kernel: now there is one gendisk per block_device,
        // easiest to get it via the inode->superblock
        struct inode *di = EVPVT(evp)->dentry->d_inode;
        struct super_block *sb = di ? di-> i_sb : NULL;
        struct block_device *ib = sb ? sb->s_bdev : NULL;
        struct gendisk *bd = ib ? ib->bd_disk : NULL;
        unsigned long fl = bd ? bd->flags : 0;

        // printk("EV: di=%p sb=%p ib=%p bd=%p fl=%x\n", di, sb, ib, bd, fl);
        if (fl & GENHD_FL_REMOVABLE)
            evp->vol_type = SEL_VOL_REMOVABLE;
#endif

#if 0
	// XXX one other test we'd like to do: find out if this is a USB
	// device, and if it is, consider it removable.  Sadly this is
	// going to be very hard to find out, esp. if we need to be polite.
	// We can look into the private SCSI
	// host data, via (SDev->host->hostt->name eq "usb-storage").  We
	// get SDev from gendisk->real_devices.  Woo.  How do we know
	// it's a scsi disk?  Via the MAJOR number of course.  Trouble is,
	// the scsi data structures are private to its driver; not only
	// would it be bad form to reach in there (and have such a dependency)
	// but we currently don't have the headers to do it :-)
	switch(MAJOR(kdev))
	{
	    case SCSI_DISK0_MAJOR:
	    case SCSI_DISK1_MAJOR:
	    case SCSI_DISK2_MAJOR:
	    case SCSI_DISK3_MAJOR:
	    case SCSI_DISK4_MAJOR:
	    case SCSI_DISK5_MAJOR:
	    case SCSI_DISK6_MAJOR:
	    case SCSI_DISK7_MAJOR:
		if (gp &&
		    strncmp((((Scsi_Device *)gp->real_devices)->host->hostt->name),
			"usb-storage", 12) == 0)
		{
		    // this is a USB device hidden under SCSI
		    evp->vol_type = SEL_VOL_REMOVABLE;
		}
	}
#endif
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
    evp->uid = current->uid;	// context info
    evp->gid = current->gid;
#else
    evp->uid = SYM_GET_ID(current->real_cred->uid);
    evp->gid = SYM_GET_ID(current->real_cred->gid);
#endif
    evp->pid = current->tgid;

    evp->ret = 0;			// default allow

    symev_trace(((ev == SEL_EV_MODIFY) ? 3 : 2),
        "symev_fs_event(%s%s/%s): d=0x%lx, fid=0x%llx, ft=%d, vt=%d, fl=%lx, u/g=%d/%d, pid=%d\n",
        symev_evname(evp->event),
            (evp->flags & SEL_EF_COMPLETION) ? "-post" : "", funct,
             evp->evdata_1, evp->file_id, evp->fil_type, evp->vol_type, evp->flags,
             evp->uid, evp->gid, evp->pid);

    // dispatch to registered handlers
    symev_deliver(evp);

    // release the event struct (capture return value 1st)
    ret = evp->ret;
    // fallthru to clean up and return

    if (ret)
    {
        // tally denied accesses
        spin_lock(&symev_counters_lock);
        symev_counters.r_denied++;
        spin_unlock(&symev_counters_lock);
    }

out:
    symev_evput(evp);	// release the event
    return ret;
}

// symev_fname_event() - process an event based on a filename
// the passed name is in USER space; the return indicates whether
// to proceed (0) or return an error (-errno).
//
// errors in processing such as nonexistent file will allow the operation
// to complete
int
symev_fname_event(const unsigned long ev, unsigned long fl,
    unsigned long data1, const char *funct, const char *ufname)
{
    symev_ev_t *evp = NULL;

    sym_filename_t *tname = symev_getname(ufname);
    int ret;

    // can get name being opened
    if (IS_ERR(tname))
    {
        symev_trace(2, "symev_fname_event(%s/%s): failed to get file name\n",
            symev_evname(ev), funct);
        return 0;
    }

    // make a new event
    if (!(evp = symev_evnew()))
        return 0; // alloc failed

    // look up what we need to know about the filename
    if ((ret = symev_getfinfo(evp, fl, sym_filename_str(tname) )))
    {
        // failed to get info on the file
        symev_trace(2, "symev_fname_event(%s/%s): !<%s> (%d)\n", symev_evname(ev),funct,sym_filename_str(tname),ret);
        symev_putname(tname);

        // count up dropped events
        spin_lock(&symev_counters_lock);
        symev_counters.nofinfo++;
        spin_unlock(&symev_counters_lock);

        symev_evput(evp);
        return (ret == -ERESTARTSYS) ? ret : 0;
    }

    symev_putname(tname);

    // process the event (this also releases the event)
    return symev_fs_event(evp, ev, fl, data1, funct);
}

// symev_fd_event() - process an event based on an open descriptor
// the passed fd refers to an open file (or is in error); the return
// indicates whether to proceed (0) or return an error (-errno).
//
// errors in processing such as nonexistent file will allow the operation
// to complete
int
symev_fd_event(const unsigned long ev, unsigned long fl, unsigned long data1,
    const char *funct, int fd)
{
    symev_ev_t *evp = NULL;

    // make a new event
    if (!(evp = symev_evnew()))
        return 0; // alloc failed

    // look up what we need to know about the filename
    if (symev_fgetfinfo(evp, fd))
    {
        // if the file does not yet exist, we do not send an event
        symev_trace(2, "symev_fd_event(%s/%s): !<%d>\n", symev_evname(ev), funct,fd);

        // count up dropped events
        spin_lock(&symev_counters_lock);
        symev_counters.nofinfo++;
        spin_unlock(&symev_counters_lock);

        symev_evput(evp);
        return 0;
    }

    // process the event (this also releases the event)
    return symev_fs_event(evp, ev, fl, data1, funct);
}

// symev_filp_event() - process an event based on an open file pointer
// the passed filp refers to an open file; the return
// indicates whether to proceed (0) or return an error (-errno).
//
// errors in processing such as nonexistent file will allow the operation
// to complete
int
symev_filp_event(const unsigned long ev, unsigned long fl, unsigned long data1,
    const char *funct, struct file *filp)
{
    symev_ev_t *evp = NULL;

    // make a new event
    if (!(evp = symev_evnew()))
        return 0; // alloc failed

    // look up what we need to know about the filename
    if (symev_fpgetfinfo(evp, filp))
    {
        // if the file does not yet exist, we do not send an event
        symev_trace(2, "symev_filp_event(%s/%s): !<%p>\n", symev_evname(ev), funct,filp);

        // count up dropped events
        spin_lock(&symev_counters_lock);
        symev_counters.nofinfo++;
        spin_unlock(&symev_counters_lock);

        symev_evput(evp);
        return 0;
    }

    // process the event (this also releases fi)
    return symev_fs_event(evp, ev, fl, data1, funct);
}


// symev_dm_event() - process an event based on a dentry + vfsmount pointer
// the passed information refers to an open file; the return
// indicates whether to proceed (0) or return an error (-errno).
//
// errors in processing such as nonexistent file will allow the operation
// to complete
int
symev_dm_event(const unsigned long ev, unsigned long fl, unsigned long data1,
    const char *funct, struct dentry *dep, struct vfsmount *vmp)
{
    symev_ev_t *evp = NULL;

    // make a new event
    if (!(evp = symev_evnew()))
        return 0; // alloc failed

    // look up what we need to know about the filename
    if (symev_dmgetfinfo(evp, dep, vmp))
    {
        // if the file does not yet exist, we do not send an event
        symev_trace(2, "symev_dm_event(%s/%s): !<%p,%p>\n", symev_evname(ev),funct,dep,vmp);

        // count up dropped events
        spin_lock(&symev_counters_lock);
        symev_counters.nofinfo++;
        spin_unlock(&symev_counters_lock);

        symev_evput(evp);
        return 0;
    }

    // process the event (this also releases fi)
    return symev_fs_event(evp, ev, fl, data1, funct);
}

// WRAPPERS --------------------------------------------------------------

// symev_open() -- wrap the sys_open() syscall: normalize the name and
// open() options, etc.
// NB: for open(O_CREAT) and creat() -- if the file doesn't preexist the
// call, there won't be an inode before, so we can't make the clean-cache
// entry, so the file will be considered "dirty" at close even if not
// written (i.e. it stays zero length).
#include <linux/delay.h>
#define LDB(s) { printk(s); /* mdelay(500); */ }
asmlinkage long
symev_open(const char *fn, int flags, int mode)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_open)
    {
        if ((ret = symev_fname_event(SEL_EV_ACCESS, 0, ((flags & O_ACCMODE) != 0),
            "open", fn)) != 0)
            goto out;

        ret = (*symev_hooked.sys_open)(fn, flags, mode);

        // check and remap the file_operations->flush handler
        // so we can catch closes
        if (ret >= 0)
        {
            struct file *file = fget(ret);
            if (file)
            {
                symev_check_fopmap(file);
                fput(file);
            }
        }

        // present the POST event
        if (ret >= 0)
        {
            (void) symev_fname_event(SEL_EV_ACCESS, SEL_EF_COMPLETION,
                ((flags & O_ACCMODE) != 0), "open", fn);
        }
    }
out:
    leave_handler();

    return ret;
}

#ifdef CONFIG_COMPAT
asmlinkage long
symev_compat_open(const char *fn, int flags, int mode)
{
    int ret = -EIO;

    enter_handler();
    if (symev_ia32_hooked.compat_sys_open)
    {
        if ((ret = symev_fname_event(SEL_EV_ACCESS, 0, ((flags & O_ACCMODE) != 0),
            "open", fn)) != 0)
        {
#ifdef DEBUG
            printk(KERN_ERR "refused by user rtvscand in function: %s, line: %d\r\n",__FUNCTION__,__LINE__);
#endif
            goto out;
        }

        ret = (*symev_ia32_hooked.compat_sys_open)(fn, flags, mode);
        // check and remap the file_operations->flush handler
        // so we can catch closes
        if (ret >= 0)
        {
            struct file *file = fget(ret);
            if (file)
            {
                symev_check_fopmap(file);
                fput(file);
            }
        }

        // present the POST event
        if (ret >= 0)
        {
            (void) symev_fname_event(SEL_EV_ACCESS, SEL_EF_COMPLETION,
                ((flags & O_ACCMODE) != 0), "open", fn);
        }
    }
out:
    leave_handler();

    return ret;
}
#endif

asmlinkage long
symev_creat(const char *fn, int mode)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_creat)
    {
        if ((ret = symev_fname_event(SEL_EV_ACCESS, 0, 1, "creat", fn)) < 0)
            goto out;

        ret = (*symev_hooked.sys_creat)(fn, mode);

        // check and remap the file_operations->flush handler
        // so we can catch closes
        if (ret >= 0)
        {
            struct file *file = fget(ret);
            if (file)
            {
                symev_check_fopmap(file);
                fput(file);
            }
        }

        // present the POST event
        if (ret >= 0)
        {
            // cannot affect the return value
            (void) symev_fname_event(SEL_EV_ACCESS, SEL_EF_COMPLETION, 1,
                "creat", fn);
        }
    }
out:
    leave_handler();

    return ret;
}

// ############## sys_execve wrapper ##############
//
// there are different versions of this wrapper for different
// OS versions, and possibly in the future different compiler
// environments.  see the detailed comments inline as to why.
// 
#ifdef __x86_64__
extern asmlinkage void symev_stub_execve(void);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
asmlinkage long symev_execve(const char __user *name,
                             const char __user *const __user *argv,
                             const char __user *const __user *envp)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
asmlinkage long symev_execve(const char __user *name,
                             const char __user *const __user *argv,
                             const char __user *const __user *envp,
                             struct pt_regs *regs)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
asmlinkage long symev_execve(const char __user *name, 
                             const char __user *const __user *argv,
                             const char __user *const __user *envp,
                             struct pt_regs regs)
#else //LINUX_VERSION_CODE
asmlinkage long symev_execve()
#endif //LINUX_VERSION_CODE
{
    int ret = -EIO;

    symev_trace(2, "symev_execve-0: calling into symev_execve\n");

    enter_handler();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    if (symev_hooked.stub_execve)  //Make sure the stub_execve is still hooked
    {
        ret = symev_fname_event(SEL_EV_ACCESS, SEL_EF_EXECUTE, 0, "execve", name);
    }
    else
    {
        ret = 0;  //return 0 to let the "symev_stub_execve" to call the orignal "stub_execve" function
    }
#endif //LINUX_VERSION_CODE

    leave_handler();

    return ret;
}
#endif //__x86_64__

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0) || defined(CONFIG_FRAME_POINTER)
// this implementation of sys_execve is x86-specific, for 2.4 kernels

#ifdef __i386__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
asmlinkage long symev_execve(const char __user *filename,
                             const char __user *const __user *argv,
                             const char __user *const __user *envp)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33)
asmlinkage long symev_execve(const char __user *filename,
                             const char __user *const __user *argv,
                             const char __user *const __user *envp,
                             struct pt_regs *regs)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
asmlinkage int symev_execve(struct pt_regs *regs)
#else
asmlinkage int symev_execve(struct pt_regs regs)
#endif
{
    int ret = -EIO;

    // sys_execve is special, since it modifies the process's register
    // state (passed as a struct on the stack). 

    // So we restore the stack (delete our stack frame) and then jump
    // to the original exec handler, so it sees the stack as we saw it
    // on entry

    enter_handler();

    if (symev_hooked.sys_execve)
        ret = symev_fname_event(SEL_EV_ACCESS, SEL_EF_EXECUTE, 0, "execve",
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) 
                (void *) filename );
#elif  LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,30)
                (void *)regs->bx);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
                (void *)regs.bx);
#else
                (void *)regs.ebx);
#endif

    leave_handler();

    if (ret < 0)
        return ret;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0)
    // Etrack 3949452: starting in kernel 4.4.0, syscall table is not
    // called directly from Entry_32.S assembly, and is instead called
    // by intermediary C function.  Means that compiler optimization
    // interacts poorly with stack unwind via "leave", but also stores
    // and restores registers regardless of our hook so we don't have to.
    symev_trace(2, "symev_execve: calling into sys_execve at %p...\n",
            symev_hooked.sys_execve);

    ret = (*symev_hooked.sys_execve)(filename, argv, envp);

    return ret;
#else    
    symev_trace(2, "symev_execve: about to jmp to %p...\n",
            symev_hooked.sys_execve);

    // NOTE:  this won't work unless this module is compiled with
    // optimization turned OFF, since gcc tends to not clean up the
    // stack from a preceding function call before inserting this
    // inline assembly, and the stack pointer needs to be in the same
    // place as it was on entry for it to work.  OTOH maybe we should
    // be saving ESP on entry (after the frame is pushed), and forcing
    // it back here (before the /leave/)?
    __asm__ __volatile__ (
            "leave\n"
            "jmp *%0\n"
            : /* no output - no return, in fact */
            // : "r" (_fp)
            : "m" (symev_hooked.sys_execve)
    );

    /*NOTREACHED*/
    symev_trace(1, "symev_execve: jmp'd sys_execve returned somehow -- we're scrod!\n");
    return -EINVAL;
#endif
}
#endif // __i386__

#else

// this implementation of sys_execve is x86-specific, for 2.6 kernels,
// with REGPARM compilations, no frame pointers, and the standard -O2
// optimization (which all affect the argument passing protocol and
// stack manipulations)

// NB: well, actually, it may be OK with !defined(CONFIG_REGPARM) but
// this is untested.  It certainly needs to be different for
// defined(CONFIG_FRAME_POINTER) -- more like in 2.4...

#ifdef __i386__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) && !defined(CONFIG_FRAME_POINTER)
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25) && LINUX_VERSION_CODE < KERNEL_VERSION(3,0,0)
    #define fastcall	asmregparm
  #else
    #define fastcall
  #endif

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) && DEBIAN_VERSION_FINAL >= 2048) || (UBUNTU_OS > 0 && LINUX_VERSION_CODE >= KERNEL_VERSION(4,7,0))

asmlinkage long symev_execve(const char __user *filename,
                             const char __user *const __user *argv,
                             const char __user *const __user *envp)
{
    int ret = -EIO;

    enter_handler();

    if (symev_hooked.sys_execve)
        ret = symev_fname_event(SEL_EV_ACCESS, SEL_EF_EXECUTE, 0, "execve",
                (void *) filename );

    leave_handler();

    if (ret < 0)
        return ret;

    symev_trace(2, "symev_execve: calling into sys_execve at %p...\n",
            symev_hooked.sys_execve);

    ret = (*symev_hooked.sys_execve)(filename, argv, envp);

    return ret;

}

#else // LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) && DEBIAN_VERSION_FINAL >= 2048

fastcall int _symev_execve(const unsigned long **esp, const char *fname);

asmlinkage static int _symev_execve_failed(void)
{
    symev_trace(1, "symev_execve: returning failure on denied execve\n");
    return -EIO;
}

asmlinkage int symev_execve(struct pt_regs regs)
{
    register unsigned long **savesp = NULL;

    // save the stack pointer for reset at return
    __asm__ __volatile__ (
        "push %1\n"
        "movl %%esp,%0\n"
        : "=r" (savesp), "=m" (symev_hooked.sys_execve)
    );

    // one last bit of nastiness:  because we pushed an extra return
    // address onto the stack, and because we are declared as
    // asmlinkage (so args are on the stack), reference to our
    // argument (a struct) must be offset by the 4 bytes that the %esp
    // moved
    return _symev_execve((const unsigned long**)savesp,
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        (char*)(((struct pt_regs *)(((unsigned long *)&regs) + 1))->ebx));
#else
        (char*)(((struct pt_regs *)(((unsigned long *)&regs) + 1))->bx));
#endif
}

fastcall 
int _symev_execve(const unsigned long **esp, const char *fname)
{
    int ret = -EIO;

    // sys_execve is special, since it modifies the process's register
    // state (passed as a struct on the stack). 

    // So we restore the stack (delete our stack frame) and then jump
    // to the original exec handler, so it sees the stack as we saw it
    // on entry

    enter_handler();

    if (symev_hooked.sys_execve)
        ret = symev_fname_event(SEL_EV_ACCESS, SEL_EF_EXECUTE, 0, "execve",fname);

    leave_handler();

    if (ret < 0)
    {
        // magic: set my return address to a dummy (failure) routine
        *esp = (unsigned long *)_symev_execve_failed;
        return ret;
    }

    symev_trace(2, "symev_execve: about to jmp to %p...\n",symev_hooked.sys_execve);
    return 0;
#if 0
    // NOTE:  This only works when stack frames are disabled
    // (-fomit-frame-pointer) and this function is a regparm(>=2).
    // That's because we depend upon the fact that
    // the parent function (symev_execve) doesn't have to
    // change its %esp before it calls _symev_execve.
    __asm__ __volatile__ (
	    "movl %0,%%esp\n"
	    "jmp *%1\n"
	    : /* no output - no return, in fact */
	    : "r" (esp), "r" (symev_hooked.sys_execve)
    );

    /*NOTREACHED*/

    symev_trace(1, "symev_execve: jmp'd sys_execve returned somehow -- we're scrod!\n");
    return -EINVAL;
#endif
}

#endif // LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0) && DEBIAN_VERSION_FINAL >= 2048
#endif // defined(CONFIG_REGPARM) && !defined(CONFIG_FRAME_POINTER)
#endif // __i386__
#endif // (version)

asmlinkage long
symev_truncate(const char *fn, unsigned long len)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_truncate)
    {
        ret = (*symev_hooked.sys_truncate)(fn, len);

        // if the truncate succeeds, notify the file modified
        if (ret >= 0)
            (void) symev_fname_event(SEL_EV_MODIFY,
                SEL_EF_COMPLETION | (len == 0 ? SEL_EF_TRUNCZERO : 0), 0,
                "truncate", fn);
    }
    leave_handler();

    return ret;
}

asmlinkage long 
symev_ftruncate(unsigned int fd, unsigned long len)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_ftruncate)
    {
        ret = (*symev_hooked.sys_ftruncate)(fd, len); 

        // if the truncate succeeds, notify the file modified
        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY,
                SEL_EF_COMPLETION | (len == 0 ? SEL_EF_TRUNCZERO : 0), 0,
                "ftruncate", fd);
    }
    leave_handler();

    return ret;
}

asmlinkage ssize_t 
symev_write(unsigned int fd, const char *buf, size_t cnt)
{
    int ret = -EIO;

    enter_handler();	// can sleep
    if (symev_hooked.sys_write)
    {
        ret = (*symev_hooked.sys_write)(fd, buf, cnt);

        // if the write succeeds, notify the file modified
        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "write", fd);
    }
    leave_handler();

    return ret;
}

#ifdef __NR_io_submit
asmlinkage long
symev_io_submit(aio_context_t ctx, long nr,struct iocb **iocbs)
{
    int ret = -EIO;

    enter_handler();

    if (symev_hooked.sys_io_submit)
    {
        int i;

        ret = (*symev_hooked.sys_io_submit)(ctx, nr, iocbs);

        // upon successful submit, walk the requests and send MODIFY
        // events for any writes.  sys_io_submit returns the number
        // of iocb's submitted, which can be < nr in case of errors
        if (ret > 0)
        {
            // check user addrs -- this is probably redundant given that
            // the underlying syscall has succeeded, but better safe
            // than panic.  once this check is done it's OK to use
            // __get_user on the array inside the loop
            if (access_ok(VERIFY_READ, iocbs, (ret * sizeof(*iocbs))))
            {
                struct iocb thisioc, *uiocbp;
                int lastfd = -1;	// simple optimization

                for (i = 0; i < ret; i++)
                {
                    // get the user iocb ptr from the user array
                    // then get the user iocb from that ptr
                    // and submit a modify event if it was a write
                    if (!__get_user(uiocbp, iocbs + i)
                        && !copy_from_user(&thisioc, uiocbp, sizeof(struct iocb))
                        && thisioc.aio_lio_opcode == IOCB_CMD_PWRITE)
                    {
                        // XXX technically, this is not a completion event but
                        // rather queueing a request.  sadly we cannot easily
                        // do better (other than maybe *also* looking for
                        // receipt of the completions, but that might never
                        // occur)
                        // we will submit only one MODIFY event with multiple
                        // sequential writes to the same fd
                        if (thisioc.aio_fildes != lastfd)
                            (void) symev_fd_event(SEL_EV_MODIFY,
                            SEL_EF_COMPLETION,
                            0, "io_submit", thisioc.aio_fildes);
                        lastfd = thisioc.aio_fildes;
                    }
                }
            }
        }
    }

    leave_handler();

    return ret;
}
#endif // __NR_io_submit

asmlinkage ssize_t
symev_writev(unsigned long fd, const struct iovec *vec, unsigned long count)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_writev)
    {
        ret = (*symev_hooked.sys_writev)(fd, vec, count);
        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "writev",fd);
    }
    leave_handler();

    return ret;
}

asmlinkage ssize_t
symev_pwrite(unsigned int fd, const char *buf, size_t cnt, loff_t pos)
{
    int ret = -EIO;

#ifdef __NR_pwrite64
#define PWRITE_CALL	sys_pwrite64
#else
#define PWRITE_CALL	sys_pwrite
#endif

    enter_handler();
    if (symev_hooked.PWRITE_CALL)
    {
        ret = (*symev_hooked.PWRITE_CALL)(fd, buf, cnt, pos);
        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "pwrite",fd);
    }
    leave_handler();

    return ret;
}

#ifdef __NR_sendfile64
// symev_sendfile64 - sendfile64() wrapper
// the sendfile64() syscall copies data from ifd to ofd
asmlinkage ssize_t
symev_sendfile64(int ofd, int ifd, loff_t *off, size_t cnt)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_sendfile64)
    {
        ret = (*symev_hooked.sys_sendfile64)(ofd, ifd, off, cnt);

        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "sendfile64",ofd);
    }
    leave_handler();

    return ret;
}
#endif // __NR_sendfile64

// symev_sendfile - sendfile() wrapper
// the sendfile() syscall copies data from ifd to ofd
asmlinkage ssize_t
symev_sendfile(int ofd, int ifd, off_t *off, size_t cnt)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_sendfile)
    {
        ret = (*symev_hooked.sys_sendfile)(ofd, ifd, off, cnt);

        if (ret >= 0)
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "sendfile",ofd);
    }
    leave_handler();

    return ret;
}

// this implementation of mmap (sys_mmap2) is x86-specific
// NB:  this approach to mmap handling is a little risky, in that it
// will allow data to be written to the file without flushing it from
// the cleanfile cache.  This is because it's removed from the cache
// at the time of the mmap call (via a MODIFY event), not when data is
// actually written (which happens down at the level of the paging/mm
// subsystem).  So if the file is opened for write, mmap'd, opened for
// read (scanned and found clean) then it can be written thru the
// existing memory mapping and will still look "clean" at close time.
#ifdef __i386__
asmlinkage int symev_old_mmap(struct mmap_arg_struct __user *arg)
{
    long ret = -EIO;
    struct mmap_arg_struct a;

    if (copy_from_user(&a, arg, sizeof(a)))
        return ret;

    enter_handler();
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
    if (symev_hooked.old_mmap)
  #else
    if (symev_hooked.sys_old_mmap)
  #endif
    {
        // NB: on i386, at least, internally, mmap returns a (signed)
        // long.  negative values are error codes, nonneg are success
      #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
        ret = (*symev_hooked.old_mmap)((struct mmap_arg_struct __user *)arg);
      #else
        ret = (*symev_hooked.sys_old_mmap)((struct mmap_arg_struct __user *)arg);
      #endif

        // see if this could modify the underlying file
        //   the test is, does the mapping allow writes, and is it
        //   backed by a file
		// Notice: all of the "MAP_SHARED" map can be written by calling mprotect.
        if ((ret >= 0) &&
            (a.prot & PROT_WRITE) &&
           ((a.flags & (MAP_SHARED | MAP_ANONYMOUS)) == MAP_SHARED))
        {
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "old_mmap", a.fd);
        }
    }
    leave_handler();

    return ret;
}
#endif // __i386__
#ifdef __x86_64__
asmlinkage long symev_mmap(unsigned long addr, unsigned long len,
        unsigned long prot, unsigned long flgs,
        unsigned long fd, unsigned long off)
{
    long ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_mmap)
    {
        // NB: on i386, at least, internally, mmap returns a (signed)
        // long.  negative values are error codes, nonneg are success
        // codes (and probably addresses!)
        ret = (*symev_hooked.sys_mmap)(addr, len, prot, flgs, fd, off);

        // see if this could modify the underlying file
        //   the test is, does the mapping allow writes, and is it
        //   backed by a file
		// Notice: all of the "MAP_SHARED" map can be written by calling mprotect.
        if ((ret >= 0) &&
            (prot & PROT_WRITE) &&
            ((flgs & (MAP_SHARED | MAP_ANONYMOUS)) == MAP_SHARED))
        {
            (void) symev_fd_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "mmap", fd);
        }
    }
    leave_handler();

    return ret;
}
#endif // __x86_64__

asmlinkage long symev_mprotect(unsigned long start, size_t len, unsigned long prot)
{
    long ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_mprotect)
    {
        ret = (*symev_hooked.sys_mprotect)(start, len, prot);

        if(0 ==ret && (prot&PROT_WRITE))
        {
            //change VMA property to PROT_WRITE sucessfully
            struct vm_area_struct *vma = NULL, *prev = NULL;
            struct file *filp = NULL;
            unsigned long vm_flags = 0;

            down_write(&current->mm->mmap_sem);

            vma = symev_find_vma_prev(current->mm, start, &prev);

            if(vma)
            {
                filp = vma->vm_file;
                vm_flags = vma->vm_flags;
            }
            up_write(&current->mm->mmap_sem);

            if((vm_flags&VM_SHARED) && filp)
            {
                (void)symev_filp_event(SEL_EV_MODIFY, SEL_EF_COMPLETION, 0, "mprotect", filp);
            }
        }
    }
    leave_handler();

    return ret;
}
// symev_unlink() - wrapper for unlink syscall
// we need to know about unlinks so we can remove the cleanfile cache
// entry for a file that's gone -- otherwise it might be possible
// for the inode to be reallocated and then belived clean
asmlinkage long symev_unlink(const char *fn)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_unlink)
    {
        // send MODIFY event *iff* last link is abt to be removed
        // XXX this could be a race -- two threads unlinking the last
        // two links to one file, at the same time, might both see two
        // links here and then both unlink it
        // MODIFY events cannot affect control flow, so we ignore ret
        // we pass the NOFOLLOW flag since unlinks delete the symlink, not
        // the file
        (void) symev_fname_event(SEL_EV_MODIFY, SEL_EF_NOFOLLOW | SEL_EF_LASTLINK, 0,
            "unlink", fn);

        ret = (*symev_hooked.sys_unlink)(fn);
    }
    leave_handler();

    return ret;
}

asmlinkage long symev_rename(const char * oldn, const char * newn)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_rename)
    {
        ret = (*symev_hooked.sys_rename)(oldn, newn);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"rename", newn);
    }

    leave_handler();
    return ret;
}

asmlinkage long symev_link(const char *oldn, const char *newn)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_link)
    {
        ret = (*symev_hooked.sys_link)(oldn, newn);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"link", newn);
    }

    leave_handler();
    return ret;
}

asmlinkage long symev_symlink(const char *oldn, const char *newn)
{
    int ret = -EIO;
    
    enter_handler();

    if (symev_hooked.sys_symlink)
    {
        ret = (*symev_hooked.sys_symlink)(oldn, newn);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"symlink", newn);
    }

    leave_handler();
    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
// symev_unlinkat() - wrapper for sys_unlinkat syscall
// we need to know about unlinks so we can remove the cleanfile cache
// entry for a file that's gone -- otherwise it might be possible
// for the inode to be reallocated and then belived clean
asmlinkage long symev_unlinkat(int dfd, const char __user * pathname, int flag)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_unlinkat)
    {
        // send MODIFY event *iff* last link is abt to be removed
        // XXX this could be a race -- two threads unlinking the last
        // two links to one file, at the same time, might both see two
        // links here and then both unlink it
        // MODIFY events cannot affect control flow, so we ignore ret
        // we pass the NOFOLLOW flag since unlinks delete the symlink, not
        // the file
        (void) symev_fname_event(SEL_EV_MODIFY, SEL_EF_NOFOLLOW | SEL_EF_LASTLINK, 0,
            "unlinkat", pathname);

        ret = (*symev_hooked.sys_unlinkat)(dfd, pathname, flag);
    }
    leave_handler();

    return ret;
}

asmlinkage long symev_renameat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_renameat)
    {
        ret = (*symev_hooked.sys_renameat)(olddfd, oldname, newdfd, newname);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"renameat", newname);
    }

    leave_handler();
    return ret;
}

asmlinkage long symev_linkat(int olddfd, const char __user * oldname, int newdfd, const char __user * newname, int flags)
{
    int ret = -EIO;

    enter_handler();
    if (symev_hooked.sys_linkat)
    {
        ret = (*symev_hooked.sys_linkat)(olddfd, oldname, newdfd, newname, flags);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"linkat", newname);
    }

    leave_handler();
    return ret;
}

asmlinkage long symev_symlinkat(const char __user * oldname, int newdfd, const char __user * newname)
{
    int ret = -EIO;
    
    enter_handler();

    if (symev_hooked.sys_symlinkat)
    {
        ret = (*symev_hooked.sys_symlinkat)(oldname, newdfd, newname);
        if (ret == 0)
            (void) symev_fname_event(SEL_EV_RENAME, SEL_EF_COMPLETION, 0,"symlinkat", newname);
    }

    leave_handler();
    return ret;
}
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)

// asmlinkage long symev_chmod(const char *fn, mode_t mode)
// { return (*symev_hooked.sys_chmod)(fn, mode); }

// asmlinkage long symev_fchmod(unsigned int fd, mode_t mode)
// { return (*symev_hooked.sys_fchmod)(fd, mode); }

//
// ----- filesystem flush callbacks ----------------------------------------
//
// NB:  in 2.4.x, these get called with the BKL held; after calling the
// system's flush, we drop the BKL, send the event, then lock BKL
// again.  Sad but true.  This has changed in 2.6...  BKL is grabbed
// in individual flush routines as necessary.

static inline void _symev_flush(struct file *fp)
{
    (void) symev_filp_event(SEL_EV_DONE, (SEL_EF_COMPLETION |
                ((fp->f_mode & FMODE_WRITE) ? SEL_EF_WRITEMODE : 0)),
                0, "_flush", fp);
}

// symev_flush_null - special optimized version of flush handler for
// the case when there is no filesystem-specific flush handler.  we can
// avoid having to find that out and (not) call it.
// On 2.4.x kernels, this is called with the BKL held
// NB: IF it were possible for someone to hold the BKL and then try to
// get a write-lock on the handler semaphore, this code could cause
// a deadlock.
int
symev_flush_null(struct file *fp
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
        , fl_owner_t id
#endif
    )
{
    enter_handler();

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    // unlock BKL for 2.4.x kernels
    unlock_kernel();
#endif

    // handle the event
    _symev_flush(fp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    // re-lock BKL for 2.4.x kernels
    lock_kernel();
#endif

    leave_handler();

    return 0;
}

// symev_flush() - general case flush handler
//   We invoke the system's flush handler to actually close the file,
//   then send the event to symev's clients.
// on 2.4.x kernels, this is called with the BKL held
// NB: IF it were possible for someone to hold the BKL and then try to
// get a write-lock on the handler semaphore, this code could cause
// a deadlock.
int
symev_flush(struct file *fp
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
        , fl_owner_t id
#endif
    )
{
    int ret = 0;

    enter_handler();	// it's OK to sleep while holding the BKL, it will temporarily be given up

    // call the native flush handler
    ret = symev_fop_flush(fp
#if( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,17) ) || ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) // SLES10sp2
        , id
#endif
    );

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    // unlock BKL for 2.4.x kernels
    unlock_kernel();
#endif

    // rest of the implementation (does our callback) is here...
    _symev_flush(fp);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    // re-lock BKL for 2.4.x kernels
    lock_kernel();
#endif

    leave_handler();

    return ret;
}

//
// ---- routines to install and manage hooks ------------------------------
//

// The RH5 kernel config includes the write-protect-readonly patch,
// although it is nominally a debug patch.  When this is in place we
// need to change the page protection flags for the page containing
// the syscall table before we patch it.
#ifdef CONFIG_DEBUG_RODATA

#if( !( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27) && defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) ) \
  &&( !(LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22) && defined(CONFIG_X86_PAE) && !defined(__x86_64__) ) ) )
#include <asm/tlbflush.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
static pte_t* symev_lookup_address(unsigned long address, unsigned int *level)
{
    pgd_t *pgd = pgd_offset_k(address);
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    *level = 0;
    if (pgd_none(*pgd))
        return NULL;
    pud = pud_offset(pgd, address);
    if (!pud_present(*pud))
        return NULL;
    pmd = pmd_offset(pud, address);
    if (!pmd_present(*pmd))
        return NULL;
    if (pmd_large(*pmd))
        return (pte_t *)pmd;
    pte = pte_offset_kernel(pmd, address);
    if (pte && !pte_present(*pte))
        pte = NULL;
    return pte;
}
#endif

static int symev_set_memory_rw(unsigned long address, int numpages, int rw)
{
    unsigned int level;
    pte_t *kpte, old_pte, new_pte;
    pgprot_t new_prot;
    unsigned long pfn;
    int i = 0;

    do {
        address += i * PAGE_SIZE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27)        
        kpte = lookup_address(address, &level);
#else
        kpte = symev_lookup_address(address, &level);
#endif

        if (!kpte) {
            printk(KERN_ERR "symev: failed to lookup_address(%p)\n", (void*)address); 
            return 1; // error, not found
        }
        old_pte = *kpte;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25) && defined(__i386__)
        #define pte_pgprot(x) __pgprot(pte_val(x))
#endif
        new_prot = pte_pgprot(old_pte);
        pfn = pte_pfn(old_pte);
        if (rw)
            pgprot_val(new_prot) |= pgprot_val(__pgprot(_PAGE_RW));
        else
            pgprot_val(new_prot) &= ~pgprot_val(__pgprot(_PAGE_RW));
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        new_pte = pfn_pte(pfn, canon_pgprot(new_prot));
        set_pte_atomic(kpte, new_pte);
#else
        new_pte = pfn_pte(pfn, new_prot);
        set_pte(kpte, new_pte);
#endif
        i++;
    } while (i < numpages);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)    
     __flush_tlb_all();
#else
    global_flush_tlb();
#endif
    return 0;    
}
#endif

static int fix_sct_prot(int unprot)
{
    int rs = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,27) && defined(CONFIG_SUSE_KERNEL) && LINUX_VERSION_CODE < KERNEL_VERSION(3,11,0) // SUSE 11 series, but not SUSE 12 series
    if (unprot) 
        mark_rodata_rw();
    else
        mark_rodata_ro();
#elif LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,22) && defined(CONFIG_X86_PAE) && !defined(__x86_64__) // RHEL 5 PAE kernels
    change_page_attr(virt_to_page(symev_syscall_table), 2, unprot ? (PAGE_KERNEL) : (PAGE_KERNEL_RO));
    global_flush_tlb();
#else 
  #define SYMEV_PFN_ALIGN(x) (((unsigned long)(x)) & PAGE_MASK)
    rs = symev_set_memory_rw(SYMEV_PFN_ALIGN(symev_syscall_table), 2, unprot);
  #ifdef CONFIG_COMPAT
    if (rs) return rs;
    rs += symev_set_memory_rw(SYMEV_PFN_ALIGN(symev_ia32_syscall_table), 2, unprot);
  #endif

#endif 

    return rs;
}
#endif // CONFIG_DEBUG_RODATA

int symev_hook_syscalls(void)
{
    // grab BKL and hack away at the syscall table
    lock_kernel();

    HOOK_SYSCALL(__NR_open, sys_open, symev_open);
    HOOK_SYSCALL(__NR_creat, sys_creat, symev_creat);
#ifdef __i386__
    HOOK_SYSCALL(__NR_execve, sys_execve, symev_execve);
#else //__i386__
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    HOOK_SYSCALL_EX(__NR_execve, stub_execve, symev_stub_execve, orig_stub_execve);
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#endif // __i386__
    HOOK_SYSCALL(__NR_truncate, sys_truncate, symev_truncate);
    HOOK_SYSCALL(__NR_ftruncate, sys_ftruncate, symev_ftruncate);
    HOOK_SYSCALL(__NR_write, sys_write, symev_write);
    HOOK_SYSCALL(__NR_writev, sys_writev, symev_writev);
#ifdef __NR_pwrite64
    HOOK_SYSCALL(__NR_pwrite64, sys_pwrite64, symev_pwrite);
#else
    HOOK_SYSCALL(__NR_pwrite, sys_pwrite, symev_pwrite);
#endif
    HOOK_SYSCALL(__NR_sendfile, sys_sendfile, symev_sendfile);
#ifdef __NR_sendfile64
    HOOK_SYSCALL(__NR_sendfile64, sys_sendfile64, symev_sendfile64);
#endif // __NR_sendfile64
#ifdef __NR_io_submit
    HOOK_SYSCALL(__NR_io_submit, sys_io_submit, symev_io_submit);
#endif // __NR_io_submit
#ifdef __i386__
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
    HOOK_SYSCALL(__NR_mmap, old_mmap, symev_old_mmap);
  #else
    HOOK_SYSCALL(__NR_mmap, sys_old_mmap, symev_old_mmap);
  #endif
#endif // __i386__
#ifdef __x86_64__
    HOOK_SYSCALL(__NR_mmap, sys_mmap, symev_mmap);
#endif // __x86_64__
    HOOK_SYSCALL(__NR_mprotect, sys_mprotect, symev_mprotect);
    HOOK_SYSCALL(__NR_unlink, sys_unlink, symev_unlink);
    HOOK_SYSCALL(__NR_rename, sys_rename, symev_rename);
    HOOK_SYSCALL(__NR_link, sys_link, symev_link);
    HOOK_SYSCALL(__NR_symlink, sys_symlink, symev_symlink);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    HOOK_SYSCALL(__NR_unlinkat, sys_unlinkat, symev_unlinkat);
    HOOK_SYSCALL(__NR_renameat, sys_renameat, symev_renameat);
    HOOK_SYSCALL(__NR_linkat, sys_linkat, symev_linkat);
    HOOK_SYSCALL(__NR_symlinkat, sys_symlinkat, symev_symlinkat);
#endif

    unlock_kernel();
    return 0;
}



// NB:  the design does not require this (unhook) capability but it is
// very useful for testing, and it should be safe in controlled
// situations.  The driver will prevent unloading (thus prevent calling this
// function) unless built in DEBUG mode.
int
symev_unhook_syscalls(void)
{
    if (!symev_syscall_table)
        return 1;

    // grab BKL and hack away at the syscall table
    lock_kernel();

    UNHOOK_SYSCALL(__NR_open, sys_open, symev_open);
    UNHOOK_SYSCALL(__NR_creat, sys_creat, symev_creat);
#ifdef __i386__
    UNHOOK_SYSCALL(__NR_execve, sys_execve, symev_execve);
#else
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    //Do not reset this variable to avoid crash. 
    //After the stub_execve is unhooked, 
    //there is still possibility to use it in symev_stub_execve for very short time.
    //But, I don't think it will be used after the "symev_unhook_syscalls" function return.
    //So, it will be safe to unload this KO from kernel at that time.
    //And actually, "symev" will not be unloaded. it will be renamed by ".symevrm".
    //orig_stub_execve = NULL;  
    UNHOOK_SYSCALL(__NR_execve, stub_execve, symev_stub_execve);
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#endif // __i386__
    UNHOOK_SYSCALL(__NR_truncate, sys_truncate, symev_truncate);
    UNHOOK_SYSCALL(__NR_ftruncate, sys_ftruncate, symev_ftruncate);
    UNHOOK_SYSCALL(__NR_write, sys_write, symev_write);
    UNHOOK_SYSCALL(__NR_writev, sys_writev, symev_writev);
#ifdef __NR_pwrite64
    UNHOOK_SYSCALL(__NR_pwrite64, sys_pwrite64, symev_pwrite);
#else
    UNHOOK_SYSCALL(__NR_pwrite, sys_pwrite, symev_pwrite);
#endif
    UNHOOK_SYSCALL(__NR_sendfile, sys_sendfile, symev_sendfile);
#ifdef __NR_sendfile64
    UNHOOK_SYSCALL(__NR_sendfile64, sys_sendfile64, symev_sendfile64);
#endif // __NR_sendfile64
#ifdef __NR_io_submit
    UNHOOK_SYSCALL(__NR_io_submit, sys_io_submit, symev_io_submit);
#endif // __NR_io_submit
#ifdef __i386__
  #if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,34)
    UNHOOK_SYSCALL(__NR_mmap, old_mmap, symev_old_mmap);
  #else
    UNHOOK_SYSCALL(__NR_mmap, sys_old_mmap, symev_old_mmap);
  #endif
#endif // __i386__
#ifdef __x86_64__
    UNHOOK_SYSCALL(__NR_mmap, sys_mmap, symev_mmap);
#endif // __x86_64__
    UNHOOK_SYSCALL(__NR_mprotect, sys_mprotect, symev_mprotect);
    UNHOOK_SYSCALL(__NR_unlink, sys_unlink, symev_unlink);
    UNHOOK_SYSCALL(__NR_rename, sys_rename, symev_rename);
    UNHOOK_SYSCALL(__NR_link, sys_link, symev_link);
    UNHOOK_SYSCALL(__NR_symlink, sys_symlink, symev_symlink);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    UNHOOK_SYSCALL(__NR_unlinkat, sys_unlinkat, symev_unlinkat);
    UNHOOK_SYSCALL(__NR_renameat, sys_renameat, symev_renameat);
    UNHOOK_SYSCALL(__NR_linkat, sys_linkat, symev_linkat);
    UNHOOK_SYSCALL(__NR_symlinkat, sys_symlinkat, symev_symlinkat);
#endif

    unlock_kernel();
    return 0;
}


#ifdef CONFIG_COMPAT
//-------for ia32 syscall function--------
int symev_hook_ia32syscalls(void)
{
#ifdef DEBUG
    printk(KERN_ERR "symev: symev_syscall_table at %p\r\n",symev_syscall_table );
    printk(KERN_ERR "symev: symev_ia32_syscall_table at %p\r\n",symev_ia32_syscall_table );
#endif
    // grab BKL and hack away at the syscall table
    lock_kernel();

    HOOK_IA32SYSCALL(__NR_compat_write, sys_write, symev_write);
    HOOK_IA32SYSCALL(__NR_compat_open, compat_sys_open, symev_compat_open);
    HOOK_IA32SYSCALL(__NR_compat_creat, sys_creat, symev_creat);
    HOOK_IA32SYSCALL(__NR_compat_link, sys_link, symev_link);
    HOOK_IA32SYSCALL(__NR_compat_unlink, sys_unlink, symev_unlink);
    HOOK_IA32SYSCALL(__NR_compat_rename, sys_rename, symev_rename);
    HOOK_IA32SYSCALL(__NR_compat_symlink, sys_symlink, symev_symlink);
    HOOK_IA32SYSCALL(__NR_compat_truncate, sys_truncate, symev_truncate);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    HOOK_IA32SYSCALL(__NR_compat_unlinkat, sys_unlinkat, symev_unlinkat);
    HOOK_IA32SYSCALL(__NR_compat_renameat, sys_renameat, symev_renameat);
    HOOK_IA32SYSCALL(__NR_compat_linkat, sys_linkat, symev_linkat);
    HOOK_IA32SYSCALL(__NR_compat_symlinkat, sys_symlinkat, symev_symlinkat);
#endif

    unlock_kernel();
    return 0;
}

int symev_unhook_ia32syscalls(void)
{
    if (!symev_ia32_syscall_table)
        return 1;

    // grab BKL and hack away at the syscall table
    lock_kernel();

    UNHOOK_IA32SYSCALL(__NR_compat_write, sys_write, symev_write);
    UNHOOK_IA32SYSCALL(__NR_compat_open, compat_sys_open, symev_compat_open);
    UNHOOK_IA32SYSCALL(__NR_compat_creat, sys_creat, symev_creat);
    UNHOOK_IA32SYSCALL(__NR_compat_link, sys_link, symev_link);
    UNHOOK_IA32SYSCALL(__NR_compat_unlink, sys_unlink, symev_unlink);
    UNHOOK_IA32SYSCALL(__NR_compat_rename, sys_rename, symev_rename);
    UNHOOK_IA32SYSCALL(__NR_compat_symlink, sys_symlink, symev_symlink);
    UNHOOK_IA32SYSCALL(__NR_compat_truncate, sys_truncate, symev_truncate);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    UNHOOK_IA32SYSCALL(__NR_compat_unlinkat, sys_unlinkat, symev_unlinkat);
    UNHOOK_IA32SYSCALL(__NR_compat_renameat, sys_renameat, symev_renameat);
    UNHOOK_IA32SYSCALL(__NR_compat_linkat, sys_linkat, symev_linkat);
    UNHOOK_IA32SYSCALL(__NR_compat_symlinkat, sys_symlinkat, symev_symlinkat);
#endif

    unlock_kernel();
    return 0;
}
#endif // CONFIG_COMPAT

// release any knowledge of the original syscall handlers
// -- this will be called with the hooks struct locked
int
symev_forget_syscalls(void)
{
    memset((char *)&symev_hooked, 0, sizeof(symev_hooked));
    return 0;
}

// symev_sleep() - go to sleep for a number of seconds
// returns 0 unless interrputed
// -- if @interruptible is set, a signal can break out early,
//    and this will cause a nonzero return
SYMCALL int
symev_sleep(int secs, int interruptible)
{
    current->state =
        (interruptible ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
    return schedule_timeout(secs * HZ);
}

// symev_msleep() - go to sleep for a number of milliseconds
// returns 0 unless interrputed
// -- if @interruptible is set, a signal can break out early,
//    and this will cause a nonzero return
int
symev_msleep(int msecs, int interruptible)
{
    current->state =
        (interruptible ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
    return schedule_timeout(msecs * HZ / 1000);
}

static void
timer_func(struct work_struct* arg)
{
    int ret;
    ret = symev_hnfs_hook(eTIMERTOHOOK);   // re-check NFS hooks
    if (ret == 0) {
        symev_trace(1, "symev: timer_func: hooked nfsd successfully.\n");
    } else {
        symev_trace(1, "symev: timer_func: nfsd hook failed.\n");
        schedule_delayed_work(&interval_work, NFS_CHECK_INT * sym_hz_get());
    } 
}

// MODULE INIT (load)

// drivier init (module load)
//  check compat with the kernel we're loading into
//  initialize our data structures
//  initialize our char device
//  create our /proc status file(s)
static struct sym_procfs_info *symev_proc_entry = NULL;

int
symev_init(void)
{
    int rc = 0;
    symev_ev_t *_ev;	// used only for sizeof
    char* rls;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19)
    rls = system_utsname.release;
#else
    rls = UTS_RELEASE;
#endif

    symev_trace(1, "symev: init: config: buildver=%s (smp=%d debug=%d), current=%s\n",
        symev_uts_release, symev_smp_build, symev_debug_build, rls);

    // Issue this warning if running on an out-of-range kernel
    // based on testing and known support
    if (LINUX_VERSION_CODE < KERNEL_VERSION(2, 4, 9))
        symev_trace(1, "symev: init: WARNING: kernel version may be unsupported!\n");

    // ensure the developer has allocated enough room in the event
    // struct for the private data -- this assertion is based on
    // object sizes that are determined at compile-time; by putting it
    // here we can prevent a crash (and hopefully fail a test) if it's
    // not set up right.
    if (sizeof(_ev->ev_pvt) < sizeof(struct symev_pvt_data))
    {
        printk(KERN_ERR "symev: ev_pvt is too small\n");
        return -E2BIG;
    }

    // ensure we can patch at least the syscall table
    if ((symev_syscall_table = symev_find_syscall_table()) == NULL)
    {
        printk(KERN_ERR "symev: failed to locate the syscall table's address\n");
        return -ESRCH;
    }

    symev_find_vma_prev = (_pfn_find_vma_prev)symbol_in_kallsyms("find_vma_prev", NULL);
    if( NULL == symev_find_vma_prev )
    {
        printk(KERN_ERR "symev: can't get the address of find_vma_prev function.\n");
        return -ESRCH;
    }

#if( (LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) && LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,41) )
    symev_kern_path_parent = (int (*)(const char *, struct nameidata *))symbol_in_kallsyms("kern_path_parent", NULL);
    if( NULL == symev_kern_path_parent )
    {
        printk(KERN_ERR "symev: can't get the address of kern_path_parent function.\n");
        return -ESRCH;
    }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,6,0) && LINUX_VERSION_CODE < KERNEL_VERSION(3,7,0)
    symev_do_path_lookup = (int (*)(int, const char *, unsigned int, struct nameidata *))symbol_in_kallsyms("do_path_lookup", NULL);
    if( NULL == symev_do_path_lookup )
    {
        printk(KERN_ERR "symev: can't get the address of do_path_lookup function.\n");
        return -ESRCH;
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,7,0)
    symev_filename_lookup = (int (*)(int, struct filename *, unsigned int, struct nameidata *))symbol_in_kallsyms("filename_lookup", NULL);
    if( NULL == symev_filename_lookup )
    {
	printk(KERN_ERR "symev: can't get the address of filename_lookup function.\n");
	return -ESRCH;
    }
#endif

#ifdef CONFIG_COMPAT
    // ensure we can patch at least the ia32 syscall table
    if (( symev_ia32_syscall_table = symev_find_ia32_syscall_table() ) == NULL)
    {
        printk(KERN_ERR "symev: failed to locate the ia32 syscall table's address\n");
        return -ESRCH;
    }
#endif

    if (!(symev_proc_entry = sym_procfs_new("symev", symev_read_proc_symev,
	symev_write_proc_symev)))
    {
	symev_trace(1, "symev: failed to create /proc/symev!\n");
    }

#ifdef CONFIG_DEBUG_RODATA
    if (fix_sct_prot(1))	// de-protect
    {
        printk(KERN_ERR "symev: failed to de-protect,at %s,line:%d\n",__FUNCTION__,__LINE__);
        return -ESRCH;
    }
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	symev_trace(1, "symev: symev_init setting the sys_call_table page to read-write.\n");
	set_addr_rw((long unsigned int)symev_syscall_table, 2);
#endif

    // hook the syscall table (global ptr was set above)
    if (symev_hook_syscalls())  
    {
        printk(KERN_ERR "symev: failed to hook the syscall table,at %d\n",__LINE__);
        rc = -EPERM; 
        goto failed;
    }

#ifdef CONFIG_COMPAT
    // hook the syscall table (global ptr was set above)
    if (symev_hook_ia32syscalls())  
    {
        printk(KERN_ERR "symev: failed to hook the ia32 syscall table\n");
        rc = -EPERM; 
        goto failed;
    }
#endif
    // hook the NFS server(s) (if available)
    // (if NFS can't be hooked, do it in the timer, but the error won't be returned.
    // trace messages were issued within the call)
    rc = symev_hnfs_hook(eSTARTUPTOHOOK);

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	symev_trace(1, "symev: symev_init setting the sys_call_table page to read-only.\n");
	set_addr_ro((long unsigned int)symev_syscall_table, 2);
#endif

    // set the timer to re-check NFS hooks periodically
    // initialize recurring timer
    if (rc) {
        interval_queue = create_workqueue("hnfs");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
        INIT_DELAYED_WORK(&interval_work, timer_func);
#else
        INIT_WORK(&interval_work, timer_func, 0);
#endif
        schedule_delayed_work(&interval_work, NFS_CHECK_INT * sym_hz_get());
        symev_trace(1, "symev: started interval work queue 0x%p\n", interval_queue);
    }

#ifdef CONFIG_DEBUG_RODATA    
    fix_sct_prot(0);		// re-protect
#endif

    // if a production build, prevent rmmod'ing
#ifndef DEBUG
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    MOD_INC_USE_COUNT;
#else
    if (!try_module_get(THIS_MODULE)) {
        printk(KERN_ERR "symev: failed to invoke the try_module_get function\n");
        return -EPERM; 
    }
#endif
#endif

    return 0;
    
failed:		// had nothing
//set the kernel page of syscall_table back to read-only in case of failure
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	symev_trace(1, "symev: symev_init setting the sys_call_table page to read-only.\n");
	set_addr_ro((long unsigned int)symev_syscall_table, 2);
#endif

#ifdef CONFIG_DEBUG_RODATA    
    fix_sct_prot(0);		// re-protect
#endif
	
    return rc;
}

// symev_exit() - unload our module
// - This is an inherently unsafe operation but we take steps to make
// it as safe as possible.  Currently it won't be used in production
// code (it will be disabled by intentionally leaking a ref count in
// _init).  But it's a mighty fine debugging and testing aid so it will
// be permitted in DEBUG mode builds.
void
symev_exit(void)
{
    symev_trace(1, "symev: exit\n");

    // first, disable the interval queue
    if(interval_queue) 
		destroy_workqueue(interval_queue);
    symev_trace(1, "symev_exit: stopped interval work queue 0x%p\n", interval_queue);
    interval_queue = NULL;

    // Phase 1: remove hooks (replacement handlers) from svc routines
    symev_trace(1, "symev_exit: unhook nfsd and syscalls ...\n");

#ifdef CONFIG_DEBUG_RODATA
    if (fix_sct_prot(1))	// de-protect
        printk(KERN_ERR "symev: failed to de-protect,at %s,line:%d\n",__FUNCTION__,__LINE__);
#endif

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	symev_trace(1, "symev: symev_exit setting the sys_call_table page to read-write.\n");
	set_addr_rw((long unsigned int)symev_syscall_table, 2);
#endif

    symev_hnfs_unhook();        // unhook the NFS server(s)

#ifdef CONFIG_COMPAT
    symev_unhook_ia32syscalls();    // unhook syscalls
#endif

    symev_unhook_syscalls();    // unhook syscalls
    symev_trace(1, "symev_exit: unhook nfsd and syscalls done.\n");

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	symev_trace(1, "symev: symev_exit setting the sys_call_table page to read-only.\n");
	set_addr_ro((long unsigned int)symev_syscall_table, 2);
#endif

#ifdef CONFIG_DEBUG_RODATA    
    fix_sct_prot(0);		// re-protect
#endif

    // Phase 2: wait for current handlers to complete
    // - sleep for a second to give any callers racing against the unhooks
    // to get into the handler
    // - acquire write-lock on handler lock (can sleep)
    symev_sleep(1, 0);	// one last chance to get into handlers in case of race

    symev_trace(1, "symev_exit: wait for the wrlock...\n");
    lock_hooks();	// sleeps till all pending calls into wrappers complete
    symev_trace(1, "symev_exit: got the wrlock\n");

    // at this point, all handlers have exited OR there may be some
    // sleeping before testing for their wrapped function's existence,
    // thought hopefully we've avoided this case above.

    // Phase 3: Release our knowledge of the handler routines
    symev_forget_syscalls();		// forget the syscall hooks
    symev_hnfs_release();		// forget the NFS hooks

    // Phase 4: Release the handler lock
    // - this will wake up any handlers in which a caller had raced
    // in above, but still managed to get in after we'd grabbed the lock.
    // They will unfortunately get a failed result since we can no longer
    // call their underlying function.
    // - after unlocking we sleep for a second to allow any exiting
    // handlers to return (since the semapore is unlocked right before
    // they return)
    unlock_hooks();
    symev_trace(1, "symev_exit: sleep to let sys hooks drain\n");
    symev_sleep(1, 0); // sleep for a second to let any hooks drain

    // Phase 5: unhook f_op->flush handlers 
    // - we do this last since the other handlers can actually update
    // the fops data, which we want not to happen by this point
    (void) symev_fops_unhook();

    // Phase 6: Release our knowledge of the flush handler routines
    lock_hooks();			// re-lock handlers
    (void) symev_fops_release();	// forget them
    unlock_hooks();			// unlock
    symev_trace(1, "symev_exit: sleep to let fops hooks drain\n");
    symev_sleep(1, 0); // sleep for a second to let any hooks drain

    // remove /proc/symc/symev
    if (symev_proc_entry)
    {
	sym_procfs_delete("symev", symev_proc_entry);
	symev_proc_entry = NULL;
    }

    symev_trace(1, "symev_exit: done\n");
}

// defs
module_init(symev_init);
module_exit(symev_exit);

#ifndef __x86_64__ 
// compute the (long long) FileID from a dentry ptr
#define symev_fileid(DENT) \
        ((((unsigned long long)(DENT)->d_inode->i_sb->s_dev) << 32) + \
        (unsigned long long)(DENT)->d_inode->i_ino);
#else
#define symev_fileid(DENT) \
        (unsigned long long)(DENT)->d_inode->i_ino;
#endif

// ITIMES_EQUAL() - compare inode time values for equality
// - this depends on kernel version -- 2.6 uses struct timespec
//   which can't be directly compared
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
#define ITIME_ZERO(A)						((A) == 0)
#define ITIMES_EQUAL(A, B)					((A) == (B))
#else
#define ITIME_ZERO(A)						((A).tv_sec == 0 && (A).tv_nsec == 0)
#define ITIMES_EQUAL(A, B)					((A).tv_sec == (B).tv_sec && (A).tv_nsec == (B).tv_nsec)
#endif

// symev_getfinfo() - find the file from the provided name; allocate and
// populate the event struct with system info abt the file
// Returns 0 or -errno if an error
// -- we are still in the user's context; we use path_lookup to resolve the
//    name into a nameidata using the user's context
// -- this can be costly, but everything will be cached.  so unless
//    we're seriously thrashing, the time spent will be recovered
//    when the access completes.
int
symev_getfinfo(symev_ev_t *evp, unsigned long flags, char *fn)
{
    int err = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    struct path path;
    memset((char *)&path, 0, sizeof(struct path));
#else
    struct nameidata nd;	// will fill in with info about the file
    memset((char *)&nd, 0, sizeof(struct nameidata));
    // want to resolve the actual, existing file, if any.  cannot
    // make cache entry if the file doesn't yet exist!
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    err = kern_path(fn, 
            ((flags & SEL_EF_NOFOLLOW) ? 0 : LOOKUP_FOLLOW),
            &path);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    err = path_lookup(fn, 
            ((flags & SEL_EF_NOFOLLOW) ? 0 : LOOKUP_FOLLOW),
            &nd);
#else
    if (path_init(fn,
            (((flags & SEL_EF_NOFOLLOW) ? 0 : LOOKUP_FOLLOW) |
            LOOKUP_POSITIVE),
            &nd))
            err = path_walk(fn, &nd);
#endif

    if (err)
        return err;

    // at this point, the nameidata struct holds ref counts that
    // must be released with path_release().  we will release them
    // here if an error occurs, or hold them if OK and release later on
    // in symev_putfinfo().

    // Get the file & device info (other than the name)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    if (nd.dentry->d_inode)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    if (path.dentry->d_inode)
#else
    if (nd.path.dentry->d_inode)
#endif
    {
        // file exists - populate the finfo struct and return it
        // (taking new refs to the needed structures)
        struct dentry *dentry;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        EVPVT(evp)->dentry = dentry = dget(nd.dentry);
        EVPVT(evp)->mnt = mntget(nd.mnt);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
        EVPVT(evp)->dentry = dentry = dget(path.dentry);
        EVPVT(evp)->mnt = mntget(path.mnt);
#else
        EVPVT(evp)->dentry = dentry = dget(nd.path.dentry);
        EVPVT(evp)->mnt = mntget(nd.path.mnt);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
        path_put(&path);
#else
        PATH_RELEASE(&nd);		// we've grabbed what we need
#endif
        // fill in shortcuts to isolate kernel deps for later
        evp->file_id = symev_fileid(dentry);	// compute the fileID
#ifdef __x86_64__
        evp->s_dev   = dentry->d_inode->i_sb->s_dev;
#endif
        evp->nlinks = dentry->d_inode->i_nlink;  // link cnt
        evp->mode = dentry->d_inode->i_mode;	// file mode

#ifdef FILE_MMAP_WRITABLE_ATOMIC_READ 
	evp->file_mmap_writable = atomic_read(&SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable));
#else //FILE_MMAP_WRITABLE_ATOMIC_READ
        evp->file_mmap_writable = SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable);
#endif //FILE_MMAP_WRITABLE_ATOMIC_READ

        symev_trace(3, "symev_getfinfo: fid=%llx, type=%s, mmap_writable=%d\n",
                    evp->file_id,   // the FileID
                    S_ISREG(evp->mode) ? "<file>" :
                   (S_ISDIR(evp->mode) ? "<dir>" : 
                   (S_ISLNK(evp->mode) ? "<link>" : "<other>")),
				   evp->file_mmap_writable);

        // return success, still holding the dcache refs
        return 0;
    }

    // doesn't exist -- it's a negative dentry
    symev_trace(2, "symev_getfinfo: name=<%s>, does not exist\n", fn);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    path_put(&path);
#else
    PATH_RELEASE(&nd);
#endif

    // return error code in pointer value
    return -ENOENT;
}

// same as above but by FD rather than name
int
symev_fgetfinfo(symev_ev_t *evp, int fd)
{
    struct file *file = NULL;

    // get the file from the fd
    if (!(file = fget(fd)))
    {
        // bogus FD was passed
        return -EBADF;
    }

    // Get the file & device info (other than the name)
	if(KERNEL_VERSION_FILE_DENTRY(file)->d_inode)
    {
        struct dentry *dentry;

        // file exists - populate the finfo struct and return it
        // (taking new refs to the needed structures)
        EVPVT(evp)->dentry = dentry = dget(KERNEL_VERSION_FILE_DENTRY(file));
        EVPVT(evp)->mnt = mntget(sym_get_vfs_mount(file));
        fput(file);

        // fill in shortcuts to isolate kernel deps for later
        evp->file_id = symev_fileid(dentry);	// compute the fileID
#ifdef __x86_64__
        evp->s_dev   = dentry->d_inode->i_sb->s_dev;
#endif
        evp->nlinks = dentry->d_inode->i_nlink;  // link cnt
        evp->mode = dentry->d_inode->i_mode;	// file mode

#ifdef FILE_MMAP_WRITABLE_ATOMIC_READ 
	evp->file_mmap_writable = atomic_read(&SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable));
#else //FILE_MMAP_WRITABLE_ATOMIC_READ
        evp->file_mmap_writable = SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable);
#endif //FILE_MMAP_WRITABLE_ATOMIC_READ

        symev_trace(3, "symev_fgetfinfo: fid=%llx, type=%s, mmap_writable=%d\n",
                evp->file_id,   // the FileID
                S_ISREG(dentry->d_inode->i_mode) ? "<file>" :
                (S_ISDIR(dentry->d_inode->i_mode) ? "<dir>" : "<other>"),
				evp->file_mmap_writable);

        // return the valid finfo, still holding the ref on the nameidata
        return 0;
    }

    // doesn't exist -- it's a negative dentry
    symev_trace(2, "symev_fgetfinfo: fd=<%d>, does not exist\n", fd);

    fput(file);

    return -EBADF;
}


// same as above but by filp rather than name
int
symev_fpgetfinfo(symev_ev_t *evp, struct file *filp)
{
    // validate, for safety
    if (!filp)
    {
        // bogus filp was passed
        return -EFAULT;
    }

    // Get the file & device info (other than the name)
	if(KERNEL_VERSION_FILE_DENTRY(filp)->d_inode)
    {
        struct dentry *dentry;

        // file exists - populate the finfo struct and return it
        // (taking new refs to the needed structures)
        EVPVT(evp)->dentry = dentry = dget(KERNEL_VERSION_FILE_DENTRY(filp));
        EVPVT(evp)->mnt = mntget(sym_get_vfs_mount(filp));

        // fill in shortcuts to isolate kernel deps for later
        evp->file_id = symev_fileid(dentry);	// compute the fileID
#ifdef __x86_64__
        evp->s_dev   = dentry->d_inode->i_sb->s_dev;
#endif
        evp->nlinks = dentry->d_inode->i_nlink;  // link cnt
        evp->mode = dentry->d_inode->i_mode; 	// file mode

#ifdef FILE_MMAP_WRITABLE_ATOMIC_READ 
	evp->file_mmap_writable = atomic_read(&SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable));
#else //FILE_MMAP_WRITABLE_ATOMIC_READ
        evp->file_mmap_writable = SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable);
#endif //FILE_MMAP_WRITABLE_ATOMIC_READ

        symev_trace(3, "symev_fpgetfinfo: filp=<%p>, fid=%llx, type=%s, mmap_writable=%d\n",
                filp, // the passed ptr
                evp->file_id,   // the FileID
                S_ISREG(dentry->d_inode->i_mode) ? "<file>" :
                (S_ISDIR(dentry->d_inode->i_mode) ? "<dir>" : "<other>"),
				evp->file_mmap_writable);

        // return the valid finfo, still holding the dcache refs
        return 0;
    }

    // doesn't exist -- it's a negative dentry
    symev_trace(2, "symev_fpgetfinfo: filp=<%p>, does not exist\n", filp);

    return -ENOENT;
}

// same as above but by dentry+vfsmnt rather than name
int
symev_dmgetfinfo(symev_ev_t *evp, struct dentry *dep, struct vfsmount *vmp)
{
    // validate, for safety
    if (!dep || !vmp)
        return -EFAULT;	// bogus ptr was passed

    // Get the file & device info (other than the name)
    if (dep->d_inode)
    {
        struct dentry *dentry;

        // file exists - populate the finfo struct and return it
        // (taking new refs to the needed structures)
        EVPVT(evp)->dentry = dentry = dget(dep);
        EVPVT(evp)->mnt = mntget(vmp);

        // fill in shortcuts to isolate kernel deps for later
        evp->file_id = symev_fileid(dentry);	// compute the fileID
#ifdef __x86_64__
        evp->s_dev   = dentry->d_inode->i_sb->s_dev;
#endif
        evp->nlinks = dentry->d_inode->i_nlink;  // link cnt
        evp->mode = dentry->d_inode->i_mode; 	// file mode

#ifdef FILE_MMAP_WRITABLE_ATOMIC_READ 
	evp->file_mmap_writable = atomic_read(&SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable));
#else //FILE_MMAP_WRITABLE_ATOMIC_READ
        evp->file_mmap_writable = SYM_I_MMAP_WRITABLE(dentry->d_inode->i_data.i_mmap_writable);
#endif //FILE_MMAP_WRITABLE_ATOMIC_READ

        symev_trace(3, "symev_dmgetfinfo: fid=%llx, type=%s, mmap_writable=%d\n",
                evp->file_id,   // the FileID
                S_ISREG(dentry->d_inode->i_mode) ? "<file>" :
               (S_ISDIR(dentry->d_inode->i_mode) ? "<dir>" : "<other>"),
			   evp->file_mmap_writable);

        // return success, still holding dcache refs
        return 0;
    }

    // doesn't exist -- it's a negative dentry
    symev_trace(2, "symev_dmgetfinfo: dentry=<%p>, does not exist\n", dep);

    return -ENOENT;
}

// ------------ event info functions -------------------------------------
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
static struct dentry* 
symev_cached_lookup(struct dentry * parent, struct qstr * name, struct nameidata *nd)
{
    struct dentry *dentry = NULL;

    /* lockess __d_lookup may fail due to concurrent d_move() 
     * in some unrelated directory, so try with d_lookup
     */
    if (!dentry)
        dentry = d_lookup(parent, name);

    if (dentry && dentry->d_op && dentry->d_op->d_revalidate) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
        if (!dentry->d_op->d_revalidate(dentry, nd) && !d_invalidate(dentry)) {
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,19,0)
        if (!dentry->d_op->d_revalidate(dentry, nd->flags) && !d_invalidate(dentry)) {
#else
        if (!dentry->d_op->d_revalidate(dentry, nd->flags)) {
            d_invalidate(dentry);
#endif
            dput(dentry);
            dentry = NULL;
        }
    }
    return dentry;
}

static struct dentry*
symev_lookup_hash_imp(struct qstr *name, struct dentry * base, struct nameidata *nd)
{
    struct dentry *dentry;
    struct inode *inode;
    int err;

    inode = base->d_inode;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
    err = permission(inode, MAY_EXEC, nd);
#else
    err = inode_permission(inode, MAY_EXEC);
#endif
    dentry = ERR_PTR(err);
    if (err)
        goto out;

    /*
     * See if the low-level filesystem might want
     * to use its own hash..
     */
    if (base->d_op && base->d_op->d_hash) {
#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,38) && LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
        err = base->d_op->d_hash(base,nd->inode, name);
#else
        err = base->d_op->d_hash(base, name);
#endif
        dentry = ERR_PTR(err);
        if (err < 0)
            goto out;
    }

    dentry = symev_cached_lookup(base, name, nd);
    if (!dentry) {
        struct dentry *new = d_alloc(base, name);
        dentry = ERR_PTR(-ENOMEM);
        if (!new)
            goto out;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
        dentry = inode->i_op->lookup(inode, new, nd);
#else
        dentry = inode->i_op->lookup(inode, new, nd->flags);
#endif
        if (!dentry)
            dentry = new;
        else
            dput(new);
    }
out:
    return dentry;
}

static struct dentry*
symev_lookup_hash(struct nameidata *nd)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    return symev_lookup_hash_imp(&nd->last, nd->dentry, nd);
#else
    return symev_lookup_hash_imp(&nd->last, nd->path.dentry, nd);
#endif
}
#endif

static struct dentry*
symev_lookup_create(struct nameidata *nd, int is_dir)
{
    struct dentry *dentry = ERR_PTR(-EEXIST);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
    down(&nd->dentry->d_inode->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    mutex_lock(&nd->dentry->d_inode->i_mutex);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
    mutex_lock(&nd->path.dentry->d_inode->i_mutex);
#else
    down_write(&nd->path.dentry->d_inode->i_rwsem);
#endif

    if (nd->last_type != LAST_NORM)
        goto fail;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    nd->flags &= ~LOOKUP_PARENT;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    nd->flags |= LOOKUP_CREATE;
// above kernel v3.6(include), struct nameidata doesnt have member intent any more
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,6,0)
    nd->intent.open.flags = O_EXCL;
#endif
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
    dentry = lookup_hash(&nd->last, nd->dentry);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,15)
    dentry = lookup_hash(nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    dentry = symev_lookup_hash(nd);
#endif

    if (IS_ERR(dentry))
        goto fail;

    if (!is_dir && nd->last.name[nd->last.len] && !dentry->d_inode)
        goto enoent;

    return dentry;

enoent:
    dput(dentry);
    dentry = ERR_PTR(-ENOENT);

fail:
    return dentry;
}

static int
symev_do_symlink(char *oldname, char *newname)
{
    int error = 0;
    struct dentry *dentry;

    struct nameidata nd;

#if( LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,41) )
    error = symev_kern_path_parent(newname, &nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    error = kern_path_parent(newname, &nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    error = path_lookup(newname, LOOKUP_PARENT, &nd);
#else
    if (path_init(newname, LOOKUP_PARENT, &nd))
        error = path_walk(newname, &nd);
#endif

    if (error)
        return error;

    dentry = symev_lookup_create(&nd, 0);

    error = PTR_ERR(dentry);
    if (!IS_ERR(dentry)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,7)
        error = vfs_symlink(nd.dentry->d_inode, dentry, oldname);
#else
    #if ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,31) && defined(KSOURCECODE_UBUNTU) ) // Ubuntu 9.10
        error = vfs_symlink(nd.path.dentry->d_inode, dentry, oldname);
    #elif ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25) && ( defined(KSOURCECODE_UBUNTU) || defined(CONFIG_SUSE_KERNEL) ) ) // Ubuntu 9.04 and SLES11
        error = vfs_symlink(nd.path.dentry->d_inode, dentry, nd.path.mnt, oldname);
    #elif ( LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) && defined(KSOURCECODE_UBUNTU) ) //Ubuntu 7.x 
        error = vfs_symlink(nd.dentry->d_inode, dentry, nd.mnt, oldname, S_IALLUGO);
    #elif defined(SLE_VERSION_CODE) && ( SLE_VERSION_CODE >= 655872 ) //  >=SLES10sp2
        error = vfs_symlink(nd.dentry->d_inode, dentry, nd.mnt, oldname, S_IALLUGO);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        error = vfs_symlink(nd.dentry->d_inode, dentry, oldname, S_IALLUGO);
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
        error = vfs_symlink(nd.path.dentry->d_inode, dentry, oldname, S_IALLUGO);
    #else
        error = vfs_symlink(nd.path.dentry->d_inode, dentry, oldname);
    #endif
#endif
        dput(dentry);
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
    up(&nd.dentry->d_inode->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    mutex_unlock(&nd.dentry->d_inode->i_mutex);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
    mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
#else
    up_write(&nd.path.dentry->d_inode->i_rwsem);
#endif

    PATH_RELEASE(&nd);

    return error;
}

static int
symev_symlink_ex(char* oldpath, char* newpath, int retry)
{
    int rs;
    int i = 0;

    do
    {
        rs = strlen(newpath);
        if (!i)
        {
            sprintf(newpath + rs, ".%lx", jiffies);
        } else
        {
            sprintf(newpath + rs, ".%lx.%x", jiffies, i);
        }
        i++;

        rs = symev_do_symlink(oldpath, newpath);
        if (rs != EEXIST) break;
    } while (retry--);

    return rs;
}

static char*
symev_create_shortpath(char *oldpath, char *newpath, unsigned long long ino)
{
    int i;
    int len;
    int offset;
    int sect = 3072; // 3KB
    char* buf;

    if (!(buf = kmalloc(PATH_MAX, GFP_KERNEL)))
    {
        symev_trace(1, "symev_create_shortpath: fail to alloc memory.\n");
        return NULL;
    }

    len = strlen(oldpath);
    len--;
    while (oldpath[len] != '/') { len--; }

    for (offset = 0, i = 0; i <= len; i++)
    {
        if ((oldpath[i] == '/' && i >= sect) || (i == len))
        {
            if (offset == 0)
            {
                strncpy(newpath, oldpath, i);
                newpath[i] = '\0';
            } else
            {
                sprintf(newpath + strlen(newpath), "/%llx", ino);
                strncpy(buf, oldpath+offset, i-offset);
                buf[i-offset] = '\0';
                if (symev_symlink_ex(buf, newpath, 10))
                {
                    kfree(buf);
                    return NULL;
                }
            }

            sect = sect + 3072;
            offset = i + 1;
        }
    }

    strcat(newpath, oldpath + len);
    kfree(buf);
    return newpath;
}

static int
symev_do_unlink(char *name)
{
    int error = 0;
    struct dentry *dentry;
    struct nameidata nd;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    struct inode *inode = NULL;
#endif

#if( LINUX_VERSION_CODE >= KERNEL_VERSION(3,1,0) || LINUX_VERSION_CODE == KERNEL_VERSION(2,6,41) )
    error = symev_kern_path_parent(name, &nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    error = kern_path_parent(name, &nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    error = path_lookup(name, LOOKUP_PARENT, &nd);
#else
    if (path_init(name, LOOKUP_PARENT, &nd))
        error = path_walk(name, &nd);
#endif

    if (error)
        goto exit;

    error = -EISDIR;

    if (nd.last_type != LAST_NORM)
        goto exit1;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
    down(&nd.dentry->d_inode->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    mutex_lock(&nd.dentry->d_inode->i_mutex);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
    mutex_lock(&nd.path.dentry->d_inode->i_mutex);
#else
    down_write(&nd.path.dentry->d_inode->i_rwsem);
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,15)
    dentry = lookup_hash(&nd.last, nd.dentry);
#elif LINUX_VERSION_CODE == KERNEL_VERSION(2,6,15)
    dentry = lookup_hash(nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
    dentry = symev_lookup_hash(&nd);
#endif

    error = PTR_ERR(dentry);
    if (!IS_ERR(dentry)) {
        if (nd.last.name[nd.last.len])
            goto slashes;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
        inode = dentry->d_inode;
        if (inode)
            atomic_inc(&inode->i_count);
#endif

#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25) && defined(CONFIG_SUSE_KERNEL) )
        error = vfs_unlink(nd.path.dentry->d_inode, dentry, nd.path.mnt);
#elif ( defined(SLE_VERSION_CODE) && SLE_VERSION_CODE >= 655872 ) //SLES10sp2
        error = vfs_unlink(nd.dentry->d_inode, dentry, nd.mnt);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
        error = vfs_unlink(nd.dentry->d_inode, dentry);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
	error = vfs_unlink(nd.path.dentry->d_inode, dentry);
/* Etrack#3836119: Added kernel support for 3.11.x for Ubuntu 12.04 LTS */
#elif ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) && LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0)) 
	error = vfs_unlink(nd.path.dentry->d_inode, dentry);
#else
        error = vfs_unlink(nd.path.dentry->d_inode, dentry,NULL);
#endif
    exit2:
        dput(dentry);
    }
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
    up(&nd.dentry->d_inode->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    mutex_unlock(&nd.dentry->d_inode->i_mutex);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
    mutex_unlock(&nd.path.dentry->d_inode->i_mutex);
#else
    up_write(&nd.path.dentry->d_inode->i_rwsem);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,10)
    if (inode)
        iput(inode);
#endif

exit1:
    PATH_RELEASE(&nd);

exit:
    return error;

slashes:
    error = !dentry->d_inode ? -ENOENT :
            S_ISDIR(dentry->d_inode->i_mode) ? -EISDIR : -ENOTDIR;
    goto exit2;
}

static int
symev_is_symlink(char* name)
{
    int rs = 0;
    int error = 0;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    struct path path;
#else
    struct nameidata nd;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    error = kern_path(name, 0, &path);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    error = path_lookup(name, 0, &nd);
#else
    if (path_init(name, LOOKUP_POSITIVE, &nd))
        error = path_walk(name, &nd);
#endif

    if (!error) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
        if (path.dentry && path.dentry->d_inode) {
            rs = S_ISLNK(path.dentry->d_inode->i_mode) ? 1 : 0;		
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,25)
        if (nd.path.dentry && nd.path.dentry->d_inode) {
            rs = S_ISLNK(nd.path.dentry->d_inode->i_mode) ? 1 : 0;		
#else
        if (nd.dentry && nd.dentry->d_inode) {
            rs = S_ISLNK(nd.dentry->d_inode->i_mode) ? 1 : 0;
            // printk("inode: %ld, imode %x, symlink: %d\n", nd.dentry->d_inode->i_ino, nd.dentry->d_inode->i_mode, rs);
#endif
        }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
        path_put(&path);
#else
        PATH_RELEASE(&nd);
#endif
    }

    return rs;
}

SYMCALL int
symev_delete_shortpath(char *path)
{
    int rs = 0;
    int len = 0;

    do
    {
        len = strlen(path);
        while (path[len] != '/' && len > 0) { len--; }

        if (len < 3072) // 3kb
        {
            return rs;
        } else
        {
            path[len] = '\0';
            if (symev_is_symlink(path))
            {
                rs = symev_do_unlink(path);
            }
        }

    } while (len > 0);

    return rs;
}

// symev_evgetfname() - obtain caller-absolute pathname for
// file described in an event struct
// Returns 0 on success, -errno if some failure

//
// - the filename will be relative the the calling thread's root,
//   and will fail if the file does not live beneath that root
// - a buffer is allocated in the finfo pointed to by the event,
//   and the name is written into it; a pointer in the event is pointed
//   to the start of the name in that buffer
// - if the buffer is already present, it will be reused
// - the buffer will be released by symev_putfinfo, so that must
//   not be called until you're done with the name in the event
// - event structs don't have concurrency controls, so we assume
//   exclusive access here
SYMCALL int
symev_evgetfname(symev_ev_t *evp)
{
    char *name;
    char *lnamebuf = NULL;
    int lnamelen = PATH_MAX;
    int count = 3;

    // validate, for safety
    if (!evp)
        return -EFAULT;	// bogus event ptr was passed

    if (!EVPVT(evp)->dentry || !EVPVT(evp)->mnt)
        return -EFAULT;	// bogus event ptr was passed

    // allocate the name buffer if not already done
    if (!EVPVT(evp)->namebuf)
    {
        if (!(EVPVT(evp)->namebuf = kmalloc(PATH_MAX, GFP_KERNEL)))
            return -ENOMEM;

        INC_ALLOC_CNT();
    }

    // count for stats
    spin_lock(&symev_counters_lock);
    symev_counters.getfn++;
    spin_unlock(&symev_counters_lock);

    // Get the pathname
    evp->name = NULL;		// safe

    name = D_PATH(EVPVT(evp)->dentry, EVPVT(evp)->mnt, EVPVT(evp)->namebuf, PATH_MAX);

    if (IS_ERR(name))
    {
        // couldn't resolve the name - probably just too long
        // XXX - this case needs to be handled
        do
        {
            if (PTR_ERR(name) == -ENAMETOOLONG)
            {
                lnamelen = lnamelen * 2;
                if (!(lnamebuf = kmalloc(lnamelen, GFP_KERNEL)))
                {
                    symev_trace(1, "symev_evgetfname: fail to alloc memory for long name, fid=0x%llx\n", evp->file_id);
                    return -ENOMEM;
                }
                memset(lnamebuf, 0, lnamelen);
                name = D_PATH(EVPVT(evp)->dentry, EVPVT(evp)->mnt, lnamebuf, lnamelen);
                if (!IS_ERR(name))
                {
                    name = symev_create_shortpath(name, EVPVT(evp)->namebuf, evp->file_id);
                    kfree(lnamebuf);
                    if (name)
                    {
                        evp->name = name;
                        return 0;
                    }
                    else
                    {
                        symev_trace(1, "symev_evgetfname: fail to create symbolic link to long name, fid=0x%llx\n", evp->file_id);
                        name = ERR_PTR(-ENAMETOOLONG); // restore original return value
                        break;
                    }
                }

                kfree(lnamebuf);
            } else
                break; // not handle other error

        } while (count--);

        symev_trace(1, "symev_evgetfname: could not get name - err=%ld, fid=0x%llx\n",
            PTR_ERR(name), evp->file_id);

        // count missed name
        spin_lock(&symev_counters_lock);
        symev_counters.namerr++;
        spin_unlock(&symev_counters_lock);

        return PTR_ERR(name);
    }
    else
    {
        evp->name = name;
        symev_trace(3, "symev_evgetfname: fid=%llx, name=<%s>\n",evp->file_id, name);
    }

    return 0;
}

// symev_evsvtimes() - save the last-access time of the file
// described in an event struct
//
// - the event private data has space to store the system-dependent
//   data we need to save and later restore the last-access time
// - we do this here because AP likes to cover its tracks (when it's
//   had to access the file) and as a user it's impossible to reset
//   the atime without updating the ctime
// - event structs don't have concurrency controls, so we assume
//   exclusive access here
SYMCALL void
symev_evsvtimes(symev_ev_t *evp)
{
    if (evp && EVPVT(evp)->dentry && EVPVT(evp)->dentry->d_inode)
    {
        EVPVT(evp)->atime_saved = EVPVT(evp)->dentry->d_inode->i_atime;
        EVPVT(evp)->ctime_saved = EVPVT(evp)->dentry->d_inode->i_ctime;
        EVPVT(evp)->mtime_saved = EVPVT(evp)->dentry->d_inode->i_mtime;
    }

    // funny pointer use below is because on 2.6 kernels the times are
    // struct timespec's, while on 2.4 they're time_t's
    symev_trace(3, "symev_evsvtimes: fid=%llx, acmtimes=%lx/%lx/%lx\n",
        evp->file_id,
        *(unsigned long *)(&EVPVT(evp)->atime_saved),
        *(unsigned long *)(&EVPVT(evp)->ctime_saved),
        *(unsigned long *)(&EVPVT(evp)->mtime_saved));
}

// symev_evrstimes() - restore the last-access time of the file
// described in an event struct, if all looks OK
// - this won't ask for a change if anything else looks to have changed
//   besides the atime (or if the atime hasn't actually changed)
SYMCALL void
symev_evrstimes(symev_ev_t *evp)
{
    // ensure the event, its dentry, and inode are still present
    if (evp && EVPVT(evp)->dentry && EVPVT(evp)->dentry->d_inode)
    {
        struct inode *in = EVPVT(evp)->dentry->d_inode;

        // lock down the inode
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
        down(&in->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
        mutex_lock(&in->i_mutex);
#else
        down_write(&in->i_rwsem);
#endif

        // if the inode hasn't changed (other than the last-access time)
        // and this is a regular file, then let's update it
        if (evp && !ITIME_ZERO(EVPVT(evp)->dentry->d_inode->i_atime) &&
            ITIMES_EQUAL(in->i_mtime, EVPVT(evp)->mtime_saved) &&
            ITIMES_EQUAL(in->i_ctime, EVPVT(evp)->ctime_saved) &&
           !ITIMES_EQUAL(in->i_atime, EVPVT(evp)->atime_saved) &&
            S_ISREG(in->i_mode))
        {
            int rc;
            struct iattr ia;		// attr updater

            ia.ia_atime = EVPVT(evp)->atime_saved;
            ia.ia_valid = ATTR_ATIME | ATTR_ATIME_SET;

            // ask the vfs to change the atime in the usual way; we will
            // debug-log a failure here but won't propagate it up
#if ( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31) && LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,22) && ( defined(KSOURCECODE_UBUNTU) || defined(CONFIG_SUSE_KERNEL) ) ) // Ubuntu series
           rc = notify_change(EVPVT(evp)->dentry, EVPVT(evp)->mnt, &ia);
#elif defined(SLE_VERSION_CODE) && ( SLE_VERSION_CODE >= 655872 ) // SLES10sp2
            rc = notify_change(EVPVT(evp)->dentry, EVPVT(evp)->mnt, &ia);
#elif ( LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0) )
	    rc = notify_change(EVPVT(evp)->dentry, &ia);
/* Etrack#3836119: Added kernel support for 3.11.x for Ubuntu 12.04 LTS */
#elif ( LINUX_VERSION_CODE >= KERNEL_VERSION(3,11,0) && LINUX_VERSION_CODE < KERNEL_VERSION(3,12,0))
	    rc = notify_change(EVPVT(evp)->dentry, &ia);
#else
            rc = notify_change(EVPVT(evp)->dentry, &ia, NULL);
#endif

            // release
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
            up(&in->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
            mutex_unlock(&in->i_mutex);
#else
            up_write(&in->i_rwsem);
#endif

            symev_trace(rc ? 1 : 3,
                "symev_evrstimes: fid=%llx, atime=%lx; rc=%d\n",
                evp->file_id, *(unsigned long *)(&EVPVT(evp)->atime_saved), rc);
        }
        else
        {
            // release
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,10)
            up(&in->i_sem);
#elif LINUX_VERSION_CODE < KERNEL_VERSION(4,7,0)
            mutex_unlock(&in->i_mutex);
#else
            up_write(&in->i_rwsem);
#endif

            symev_trace(3, "symev_evrstimes: fid=%llx, not restoring\n",
                evp->file_id);
        }
    }
}


// ------------ registration functions -------------------------------------

#define REG_SLOT_MAX 16

static struct symev_cbfs
{
    sel_ev_cb_func_t *cbfp;	// callback function address
    void *cpvt;			// callback private value
    unsigned long ctyp;		// event-type requested
    unsigned long cflg;		// event flags requested
    void *cprm;			// event filter parameter
    atomic_t *pending;          // count of pending callback routines
} symev_cbreg[REG_SLOT_MAX] = {{NULL, NULL}};

spinlock_t symev_cbreg_lock =
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,39)
        SPIN_LOCK_UNLOCKED;
#else
        __SPIN_LOCK_UNLOCKED(symev_cbreg_lock);
#endif

// symev_register() - register interest in event callbacks
// (see description in symevl.h)
// currently, all events are delivered to all customers, though
// in the future values for the filters (ev_type, ev_flags, ev_param)
// will be implemented
SYMCALL symev_handle_t
symev_register(sel_ev_cb_func_t *cbfp, void *cpvt,
    unsigned long ev_type, unsigned long ev_flags, void *ev_param)
{
    int i;

    if (!cbfp)
        return NULL;

    // find an open slot and register there
    spin_lock(&symev_cbreg_lock);
    for (i = 0; i < REG_SLOT_MAX; i++)
    {
        if (!symev_cbreg[i].cbfp && !symev_cbreg[i].pending)
        {
            // register in this slot
            symev_cbreg[i].cbfp = cbfp;
            symev_cbreg[i].cpvt = cpvt;
            symev_cbreg[i].ctyp = ev_type;
            symev_cbreg[i].cflg = ev_flags;
            symev_cbreg[i].cprm = ev_param;
            symev_cbreg[i].pending = kmalloc(sizeof(atomic_t), GFP_KERNEL);
            atomic_set(symev_cbreg[i].pending, 0);

            spin_unlock(&symev_cbreg_lock);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
            // add a refcnt to the module, to prevent unloading
            MOD_INC_USE_COUNT;
#endif

            symev_trace(1, "symev_register: registered (%p(%p) for 0x%lx) at handle %p (slot %d)\n",
                cbfp, cpvt, ev_type, &symev_cbreg[i], i);

            // return the handle
            return ((symev_handle_t) &symev_cbreg[i]);
        }
    }

    // no free slots!
    spin_unlock(&symev_cbreg_lock);
    printk("<1> symev_register: no slots left!\n");
    return NULL;
}

// symev_deliver() - deliver an event to all registered handlers
// @ev - pointer to the event struct to deliver
// The event is delivered in turn to all registered handlers or until
// a handler sets a failure status
void
symev_deliver(symev_ev_t *ev)
{
    int i;
    sel_ev_cb_func_t *cbfp;
    void *cpvt;

    for (i = 0; ((ev->ret == 0) && (i < REG_SLOT_MAX)); i++)
    {
        // deliver to a handler registered for anything, for the
        // whole class, or for just this event
        // filesystem events (SEL_EV_FS_x)
        spin_lock(&symev_cbreg_lock);

        if (symev_cbreg[i].cbfp &&
            (symev_cbreg[i].ctyp == SEL_EV_x ||
            symev_cbreg[i].ctyp == (ev->event & SEL_EV_CLMASK) ||
            symev_cbreg[i].ctyp == ev->event))
        {
            // lock against modifying the table
            cbfp = symev_cbreg[i].cbfp;
            cpvt = symev_cbreg[i].cpvt;
            spin_unlock(&symev_cbreg_lock);

            // call the callback
            atomic_inc(symev_cbreg[i].pending);
            (*cbfp)(ev, cpvt);
            atomic_dec(symev_cbreg[i].pending);
        }
        else
            spin_unlock(&symev_cbreg_lock);
    }
}

// symev_unregister() - remove a registered handler
// @hcb - callback handle to unregister; had been returned from symev_register
SYMCALL int
symev_unregister(symev_handle_t hcb)
{
    struct symev_cbfs *cbsp = (struct symev_cbfs *) hcb;
    int slot = (cbsp - symev_cbreg);
    int rs = 0;

    spin_lock(&symev_cbreg_lock);
    if (hcb && slot >= 0 && slot < REG_SLOT_MAX && cbsp->cbfp)
    {
        cbsp->cbfp = NULL; // stop file event forwarding
        spin_unlock(&symev_cbreg_lock);

        symev_trace(1, "symev_unregister: unregister slot %d\n", slot);
        if (cbsp->pending) {
            int i = 0;
            do {
                if (!atomic_read(cbsp->pending))
                    break;
                else {
                    symev_trace(1, "symev_unregister: wait<%d> a millisecond for %d pending callbacks\n",
                                i, atomic_read(cbsp->pending));
                    symev_msleep(1, 0);
                }
            } while (++i < 1000);

            if (atomic_read(cbsp->pending)) {
                printk(KERN_ERR "symev_unregister: exiting even though %d pending callbacks are not done!\n", atomic_read(cbsp->pending));
                rs = 1;
            }
            kfree(cbsp->pending);
        }
        memset(cbsp, 0, sizeof(struct symev_cbfs)); // forget this client

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
        MOD_DEC_USE_COUNT;
#endif

        return rs;
    }

    // else - not registered in this slot!
    spin_unlock(&symev_cbreg_lock);

    printk(KERN_ERR "symev_unregister: bogus unregister <%p>, base <%p>, slot=%d, cbfp=%p\n", cbsp,
        symev_cbreg, slot, hcb ? cbsp->cbfp : NULL);

    return 1;
}

// /dev/symev access
void
symev_reg_devread(char *buf, int *plen, int mlen)
{
    // read out the current status of the callback registry
    int i, ret;
    char *bp = buf + *plen;
    int left = mlen - *plen;

    ret = snprintf(bp, left, "=== REG [%d] ===\n", REG_SLOT_MAX);
    if (ret > 0) { bp += ret; left -= ret; }

    for (i = 0; (left > 0) && (i < REG_SLOT_MAX); i++)
    {
        if (symev_cbreg[i].cbfp)
        {
            ret = snprintf(bp, left, "cbreg[%d].cbfp=%p .cpvt=%p .pending=%d\n",
                i, symev_cbreg[i].cbfp, symev_cbreg[i].cpvt, atomic_read(symev_cbreg[i].pending));
            if (ret > 0) { bp += ret; left -= ret; }
        }
    }

    // adjust pointer for caller
    if (left > 0)
        *plen = mlen - left;    // room left
    else
        *plen = mlen;   // full

    return;
}

// Retrieve module version information
// - the major number changes when the protocol changes
// - the minor number changes when the module is upgraded
// This just returns the values of SYMEV_VER_MAJOR and SYMEV_VER_MINOR
// from module compile time.
SYMCALL void
symev_version(int *major, int *minor)
{
    if (major)
        *major = SYMEV_VER_MAJOR;

    if (minor)
        *minor = SYMEV_VER_MINOR;
}

// exports

// newer kernels don't define EXPORT_SYMBOL_NOVERS
#ifndef EXPORT_SYMBOL_NOVERS
#define EXPORT_SYMBOL_NOVERS	EXPORT_SYMBOL
#endif //EXPORT_SYMBOL_NOVERS

EXPORT_SYMBOL_NOVERS(symev_register);
EXPORT_SYMBOL_NOVERS(symev_unregister);
EXPORT_SYMBOL_NOVERS(symev_evgetfname);
EXPORT_SYMBOL_NOVERS(symev_delete_shortpath);
EXPORT_SYMBOL_NOVERS(symev_evsvtimes);
EXPORT_SYMBOL_NOVERS(symev_evrstimes);
EXPORT_SYMBOL_NOVERS(symev_evget);
EXPORT_SYMBOL_NOVERS(symev_evput);
EXPORT_SYMBOL_NOVERS(symev_sleep);
EXPORT_SYMBOL_NOVERS(symev_msleep);
EXPORT_SYMBOL_NOVERS(symev_version);

// utils from utils.c
EXPORT_SYMBOL_NOVERS(sym_timer_create);
EXPORT_SYMBOL_NOVERS(sym_timer_destroy);
EXPORT_SYMBOL_NOVERS(sym_timer_set);
EXPORT_SYMBOL_NOVERS(sym_timer_update);
EXPORT_SYMBOL_NOVERS(sym_timer_get);
EXPORT_SYMBOL_NOVERS(sym_timer_is_set);
EXPORT_SYMBOL_NOVERS(sym_timer_cancel);
EXPORT_SYMBOL_NOVERS(sym_clock_get);
EXPORT_SYMBOL_NOVERS(sym_hz_get);

EXPORT_SYMBOL_NOVERS(sym_mutex_new);
EXPORT_SYMBOL_NOVERS(sym_mutex_delete);
EXPORT_SYMBOL_NOVERS(sym_mutex_lock);
EXPORT_SYMBOL_NOVERS(sym_mutex_unlock);

EXPORT_SYMBOL_NOVERS(sym_printk);

EXPORT_SYMBOL_NOVERS(sym_snprintf);
EXPORT_SYMBOL_NOVERS(sym_strnicmp);
EXPORT_SYMBOL_NOVERS(sym_memset);

EXPORT_SYMBOL_NOVERS(sym_kmalloc);
EXPORT_SYMBOL_NOVERS(sym_kfree);
EXPORT_SYMBOL_NOVERS(sym_vmalloc);
EXPORT_SYMBOL_NOVERS(sym_vfree);

EXPORT_SYMBOL_NOVERS(sym_curr_is_su);
EXPORT_SYMBOL_NOVERS(sym_curr_getpid);
EXPORT_SYMBOL_NOVERS(sym_curr_gettgid);
EXPORT_SYMBOL_NOVERS(sym_curr_gettid);

EXPORT_SYMBOL_NOVERS(sym_sys_getmemsize);

EXPORT_SYMBOL_NOVERS(sym_wq_new);
EXPORT_SYMBOL_NOVERS(sym_wq_delete);
EXPORT_SYMBOL_NOVERS(sym_wq_waiting);
EXPORT_SYMBOL_NOVERS(sym_wq_wait);
EXPORT_SYMBOL_NOVERS(sym_wq_wakeup);

EXPORT_SYMBOL_NOVERS(sym_file_set_pvt);
EXPORT_SYMBOL_NOVERS(sym_file_get_pvt);

EXPORT_SYMBOL_NOVERS(sym_err_getnum);

EXPORT_SYMBOL_NOVERS(sym_user_okwrite);
EXPORT_SYMBOL_NOVERS(sym_user_copyto);
EXPORT_SYMBOL_NOVERS(sym_user_copyfrom);
EXPORT_SYMBOL_NOVERS(sym_user_intto);
