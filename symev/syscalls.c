// syscalls.c - manage hooks on Linux system calls
//
// Copyright (C) 2005 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#define __NO_VERSION__

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
  #include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/utsname.h>
#include <linux/kernel.h>
#include <linux/init.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
  #include <linux/syscalls.h>
#endif

#include <linux/proc_fs.h>
#include <linux/slab.h>
#include <asm/unistd.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
  #include <linux/file.h>
  #include <linux/namei.h>
  #include <asm/uaccess.h>
#endif

#include "symevl.h"
#include "symev.h"
#include "syscalls.h"


// we need one or more of these externs to resolve, in order to find
// the sys_call_table.  we use "weak" binding so that the dynamic link
// (insmod) will not fail if one or more happen not to be found.
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
extern void *sys_call_table __attribute__ ((weak));
#endif


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
unsigned long (*symev_module_kallsyms_lookup_name) (const char *name) = 0;
unsigned long (*symev_kallsyms_lookup_name) (const char *name) = 0;

#ifdef CONFIG_COMPAT
// used to store contents of IDT register
struct {
  unsigned short limit;
  unsigned long base;
} __attribute__ ((packed)) idtr;

// based on gate_struct in asm/desc.h
struct {
  u16 offset_low;
  u16 segment;
  unsigned ist : 3, zero0 : 5, type : 5, dpl : 2, p : 1;
  u16 offset_middle;
  u32 offset_high;
  u32 zero1;
} __attribute__ ((packed)) idt;

#define CALLOFF 0x100     /* we'll read first 100 bytes of int $0x80*/

static void *memmem(const void *haystack, size_t haystack_len,
            const void *needle, size_t needle_len)
{
    const char *begin;
    const char *const last_possible
        = (const char *) haystack + haystack_len - needle_len;

    if (needle_len == 0)
        /* The first occurrence of the empty string is deemed to occur at
           the beginning of the string.  */
        return (void *) haystack;

    /* Sanity check, otherwise the loop might search through the whole
       memory.  */
    if (__builtin_expect(haystack_len < needle_len, 0))
        return NULL;

    for (begin = (const char *) haystack; begin <= last_possible;
         ++begin)
        if (begin[0] == ((const char *) needle)[0]
            && !memcmp((const void *) &begin[1],
                   (const void *) ((const char *) needle + 1),
                   needle_len - 1))
            return (void *) begin;

    return NULL;
}

static void** get_ia32_from_interrupt_table(void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,18)
    void **ia32_sct = NULL;
    unsigned long ia32_sc_off;
    char sc_asm[CALLOFF],*p;
 
    // ask processor for interrupt discriptor table
    asm ("sidt %0" : "=m" (idtr));
 
    symev_trace(1, "get_ia32_from_interrupt_table idtr = %p\n",(void *)idtr.base);

    // read-in IDT for 0x80 vector (ia32_syscall)
    memcpy(&idt,(void *)idtr.base+16*0x80,sizeof(idt));
#ifdef __x86_64__
    ia32_sc_off = ((u64)idt.offset_high << 32) | ((u32)idt.offset_middle << 16) | (u16)idt.offset_low;
#else
    ia32_sc_off = (((unsigned long)idt.offset_high ) << 32) | (((idt.offset_middle << 16) | idt.offset_low) & 0x00000000ffffffff );
#endif
    symev_trace(1, "get_ia32_from_interrupt_table ia32_sc_off = %p\n", (void *)ia32_sc_off);
    
    memcpy(sc_asm,(void *)ia32_sc_off,CALLOFF);

    p = (char*)memmem (sc_asm,CALLOFF,"\xff\x14\xc5",3);
    if (p)
    {
#ifdef __x86_64__
        ia32_sct = (void **)*(unsigned *)(p+3);
        ia32_sct = (void **)((u64)ia32_sct | ((u64)idt.offset_high << 32));
#else
        ia32_sct = (void **)*(unsigned long *) (p + 3);
#endif
        symev_trace(1, "get_ia32_from_interrupt_table pattern found. ia32_sys_call_table = %p\n",ia32_sct);
        return ia32_sct;
    }

#endif

    return NULL;
}
#endif

#endif

// utility: convert hex-string to unsigned long
static 
unsigned long hexstr_ulong(const char* hex)
{
    int i = 0;
    unsigned long val = 0;

    for (i = 0; i < sizeof(unsigned long) * 2; i++) {
        if (hex[i] >= '0' && hex[i] <= '9') {
            val = val << 4;
            val = val + (hex[i] - '0');
        }
        else if (hex[i] >= 'a' && hex[i] <= 'f') {
            val = val << 4;
            val = val + (hex[i] - 'a') + 10;
        }
        else if (hex[i] >= 'A' && hex[i] <= 'F') {
            val = val << 4;
            val = val + (hex[i] - 'A') + 10;
        }
        else break;
    }

    return val;
}

// utility: get string length
static 
unsigned int func_len(const char* str)
{
    unsigned int i = 0;

    if (*(str-1) != ' ' && *(str-1) != '\t')
        return 0xffffffff;
 
    while ( 1 )
    {
        if (str[i] == '\0' || str[i] == ' ' || str[i] == '\t' || str[i] == '\n')
            break;
        i++;
    }

    return i;
}

// find the symbol address from /proc/kallsyms
// @sym - symbol string
// @mod - kernel module name, e.g. "[nfs]", if NULL, search the symbols in kernel range
// return the symbol address if found, otherwise NULL.
unsigned long symbol_in_kallsyms(const char* sym, const char* mod)
{
    const char* fname = "/proc/kallsyms";
    unsigned long address = 0;
    ssize_t ret = -EBADF;
    mm_segment_t fs;
    struct file *fp;
    char *buffer, *p;
    int i = 0;
    int end = 0;

    if ( !(buffer = kmalloc(128, GFP_KERNEL)) )
        return 0;

    if ( !(fp = filp_open(fname, O_RDONLY, 0)) ) {
        kfree(buffer);
        return 0;
    }

    fs = get_fs();
    set_fs(KERNEL_DS);

    memset(buffer, 0, 128);
    while (!end)
    {
        i = 0;
        do {
            // read a line
            ret = fp->f_op->read(fp, buffer + i, 1, &fp->f_pos);
            if (ret <= 0) end = 1;
            if (buffer[i] == '\n') break;
            if (i >= 126) break; 

            i++;
        } while (ret > 0);

        p = strstr(buffer, sym);
        if (p) {
            if (!mod) { // kernel symbol
                if (func_len(p) == strlen(sym)) {
                    address = hexstr_ulong(buffer);
                    symev_trace(2, "symev: located symbol '%s' in %s at %lx\n", sym, "kernel", address);
                    break;
                }               
            } else { // module symbol 
                if (func_len(p) == strlen(sym) && strstr(buffer, mod)) {
                    address = hexstr_ulong(buffer);
                    symev_trace(2, "symev: located symbol '%s' in %s at %lx\n", sym, mod, address);
                    break;
                }
            }
        } // if(p)

    } // while

    set_fs(fs);
    fput(fp);
    kfree(buffer);
    return address;
}

static void *
symev_kernel_start_address(void)
{
    unsigned long addr = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    addr = (unsigned long) (void*) &kernel_thread;
#else
    // in mr11 we only support 2.6.32 later kernel, so remove here
    addr = symbol_in_kallsyms("__start_rodata", NULL);
    if( !addr )
       addr = symbol_in_kallsyms("_stext", NULL); // we found the previous sym in debian 6

    // note: the following two lines are NOT related to kernel start_address,
    // we need to get these symbols address, which should be possibly used in other places.
    symev_module_kallsyms_lookup_name = (void*) symbol_in_kallsyms("module_kallsyms_lookup_name", NULL);
    symev_kallsyms_lookup_name = (void*) symbol_in_kallsyms("kallsyms_lookup_name", NULL);
#endif

    return (void*) addr; 
}

// table of syscall handlers and where we expect to see them called
struct sc_tbl
{
    int	sc_num;		// syscall index number
    void *sc_addr;	// exported syscall handler address
};

// For defect 3806382:
// Used different syscall handlers that are NOT hooked by  
// Tripwire and hopefully NOT by other applications to find the syscall table address for AP modules to load successfully

static struct sc_tbl sc_ltbl[sizeof(sc_lookuplist)/sizeof(sc_lookuplist[0])];

static void symev_init_sc_ltbl(void)
{
    int i;
    int iterations = sizeof(sc_ltbl) / sizeof(sc_ltbl[0]);

    for (i = 0; i < iterations; i++)
    {
        sc_ltbl[i].sc_num = sc_lookuplist[i].sc_num;
        sc_ltbl[i].sc_addr = (void*) symbol_in_kallsyms(sc_lookuplist[i].sc_name, NULL);
    }
}

#ifdef CONFIG_COMPAT

#define __NR_compat_open  5

// run 32-bit programs under a 64-bit kernel. and this isn't same on 64 platform
// from linux-3.0.3/arch/x86/ia32/ia32entry.S
/*
ia32_sys_call_table:
	.quad sys_restart_syscall       // 0
	.quad sys_exit                  // 1
	.quad stub32_fork               // 2
	.quad sys_read                  // 3
	.quad sys_write                 // 4
	.quad compat_sys_open		// 5
        ...
        .quad compat_sys_time           // 13
        ...
        .quad compat_sys_ioctl          // 54
        ...
        .quad sys_umask                 // 60
        ...
        .quad sys_truncate              // 92
*/

static struct sc_tbl ia32sc_ltbl[] =
{
    { 3, 0 }, //sys_read 
    { 13, 0 }, //compat_sys_time
    { 54, 0 }, //compat_sys_ioctl
    { 60, 0 }, //sys_umask
    { 92, 0 }, //sys_truncate
};

static void symev_init_ia32sc_ltbl(void)
{
    // the system call number aren't same on 32/64 platform.
    ia32sc_ltbl[0].sc_addr = (void*) symbol_in_kallsyms("sys_read", NULL);  
    ia32sc_ltbl[1].sc_addr = (void*) symbol_in_kallsyms("compat_sys_time", NULL);
    ia32sc_ltbl[2].sc_addr = (void*) symbol_in_kallsyms("compat_sys_ioctl", NULL);
    ia32sc_ltbl[3].sc_addr = (void*) symbol_in_kallsyms("sys_umask", NULL);
    ia32sc_ltbl[4].sc_addr = (void*) symbol_in_kallsyms("sys_truncate", NULL);
}
#endif

// find the address of (ia32) sys_call_table
// we will probably have to search kernel memory to find it.  in the process
// we could possibly segfault.  if that happens, since this is called
// at module load time, we'll log an Oops and the insmod will be killed
// with a SIGSEGV.
void *symev_find_sys_table( int ia32_syscall_table )
{
    int i = 0;
    int nnz = 0;
    int ntotry = 0;
    int sc_max_index = 0;

    void **ptr;
    void *upperlimit;

    static void *stpt = (void*)NULL;
    struct sc_tbl *ltbl = (void*)NULL;

    // otherwise (more likely) we will search for it
    stpt = symev_kernel_start_address();
    if (stpt == (void*) NULL) {
        symev_trace(1, "symev: could not find the sys_call_table\n");
        return NULL;
    }

    // Set upper end of range to search.  Recent 2.6 SuSE kernels
    // have moved some things around so we need to search a wider range.  Also
    // since we're possibly locating our starting address using a code address
    // we need to align to a dword boundary before starting
#ifndef __x86_64__
    stpt = (void *)((unsigned long)stpt & ~3L);		// align to dword boundary
    upperlimit = stpt + (1403 * PAGE_SIZE); // increase from 1024 to 1280 for Debian 8 kernel 3.16.0-4, For kernel 4.7 changed to 1403
#else
    stpt = (void *)((unsigned long)stpt & ~7L);
    upperlimit = stpt + 2560 * PAGE_SIZE;
#endif 

    symev_trace(1, "symev: searching for sys_call_table between %p and %p\n", stpt, upperlimit);

    if (ia32_syscall_table)
    {
#ifdef CONFIG_COMPAT
        ptr = NULL;
        ptr = get_ia32_from_interrupt_table();
        if(ptr) return ptr;
        ltbl = ia32sc_ltbl;
        ntotry = sizeof(ia32sc_ltbl) / sizeof(ia32sc_ltbl[0]);
        symev_init_ia32sc_ltbl();
#endif
    }
    else
    {
        ltbl = sc_ltbl;
        ntotry = sizeof(sc_ltbl) / sizeof(sc_ltbl[0]);
        symev_init_sc_ltbl();
    }

    if (NULL == ltbl)
    {
        printk(KERN_ERR "symev: failed to get (ia32) local syscall number table!\n");
        return NULL;
    }

    for (i = 0 ; i < ntotry; i++)
    {
        if (ltbl[i].sc_addr != 0)
        {
            nnz++;
            if (ltbl[i].sc_num > sc_max_index)
                sc_max_index = ltbl[i].sc_num;
            symev_trace(1, "symev: fsct slot %d (#%d) is 0x%p\n",
                i, ltbl[i].sc_num, ltbl[i].sc_addr);
        }
        else
        {
            symev_trace(1, "symev: fsct slot %d (#%d) unresolved\n",
                i, ltbl[i].sc_num);
        }
    }

    // detect case where we have nothing even to look for
    if (SYSCALL_MINIMUM_MATCHES > nnz)
    {
        printk(KERN_ERR "symev: unable to resolve sufficient installation points\n");
        return NULL;
    }

    // Adjust upper limit to not pass page boundary during checks, should relieve page faults
    // should we be unable to find syscall table
    upperlimit = upperlimit - (sc_max_index * sizeof(void*));

    // search for the sys_call_table by looking for known (exported) syscall handlers in
    // their right spots
    for (ptr = (void **)stpt; ptr < (void **)upperlimit; ptr++)
    {
        int nmatched = 0;

        for (i = 0; i < ntotry; i++)
        {
            if (ltbl[i].sc_addr != 0)
            {
                if (ptr[ltbl[i].sc_num] == ltbl[i].sc_addr)
                {
                    nmatched++;
                    symev_trace(1, "symev: fsct matched slot %d (#%d, 0x%p) at %p[+%d]\n",
                        i, ltbl[i].sc_num, ltbl[i].sc_addr, ptr, ltbl[i].sc_num);
                }
            }
        }

        if (nmatched >= SYSCALL_MINIMUM_MATCHES)
        {
            symev_trace(1, "symev: (ia32) fsct matched %d of %d(%d)\n", nmatched, nnz, ntotry);
            break;
        }
    }

    if (ptr >= (void **)upperlimit)
    {
        printk(KERN_ERR "symev: unable to locate installation points\n");
        return NULL;
    }

    // ptr is our base
    symev_trace(1, "symev: found sys_call_table at %p\n", ptr);


#if 0
    // these don't add any value but I don't want to actually
    // delete them yet...
    printk("<1>symev: sys_open = %p\n", ptr[__NR_open]);
    printk("<1>symev: sys_creat = %p\n", ptr[__NR_creat]);
    printk("<1>symev: sys_close = %p\n", ptr[__NR_close]);
    printk("<1>symev: sys_dup = %p\n", ptr[__NR_dup]);
    printk("<1>symev: sys_dup2 = %p\n", ptr[__NR_dup2]);
    printk("<1>symev: sys_execve = %p\n", ptr[__NR_execve]);
    printk("<1>symev: sys_truncate = %p\n", ptr[__NR_truncate]);
    printk("<1>symev: sys_ftruncate = %p\n", ptr[__NR_ftruncate]);
    printk("<1>symev: sys_write = %p\n", ptr[__NR_write]);
    printk("<1>symev: sys_writev = %p\n", ptr[__NR_writev]);
    printk("<1>symev: sys_sendfile = %p\n", ptr[__NR_sendfile]);
    printk("<1>symev: sys_mmap = %p\n", ptr[__NR_mmap]);
    printk("<1>symev: sys_unlink = %p\n", ptr[__NR_unlink]);
    printk("<1>symev: sys_rename = %p\n", ptr[__NR_rename]);
    printk("<1>symev: sys_link = %p\n", ptr[__NR_link]);
    printk("<1>symev: sys_symlink = %p\n", ptr[__NR_symlink]);
    printk("<1>symev: sys_chmod = %p\n", ptr[__NR_chmod]);
    printk("<1>symev: sys_fchmod = %p\n", ptr[__NR_fchmod]);
#endif

    return ptr;
}

// find the address of sys_call_table
void * symev_find_syscall_table(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0)
    // see if we find it at link time (not expected in modern kernels)
    if (&sys_call_table != 0)
    {
        symev_trace(1, "symev: sys_call_table found by link at <%p>\n", sys_call_table);
        return &sys_call_table;
    }
#endif

    return symev_find_sys_table(0);
}

#ifdef CONFIG_COMPAT

// find the address of ia32_sys_call_table
void *symev_find_ia32_syscall_table(void)
{
    long *symev_ia32_syscall_table = NULL;
    long *symev_ia32_syscall_end   = NULL;
    long symev_compat_sys_open     = 0;

    if (symev_kallsyms_lookup_name)
    {
        symev_ia32_syscall_table = (long*)(*symev_kallsyms_lookup_name)("ia32_sys_call_table");
        symev_ia32_syscall_end   = (long*)(*symev_kallsyms_lookup_name)("ia32_syscall_end");
        symev_compat_sys_open    = (long)(*symev_kallsyms_lookup_name)("compat_sys_open");
    }

    if ( symev_ia32_syscall_table && symev_compat_sys_open )
    {
        if( symev_compat_sys_open == symev_ia32_syscall_table[__NR_compat_open] )
        {
#ifdef DEBUG
            printk( "ia32_sys_call_table:%p\r\n",(void*) symev_ia32_syscall_table );
            printk( "ia32_syscall_end:%p\r\n",(void*)symev_ia32_syscall_end );
            printk( "compat_sys_open:%p \r\n",(void*)symev_compat_sys_open );
#endif
            return symev_ia32_syscall_table;
        }
    }

    return symev_find_sys_table(1);
}
#endif //CONFIG_COMPAT





