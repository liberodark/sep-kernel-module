/********************************************************************************************************
 * SYMANTEC:     Copyright (c) 2011-2015 Symantec Corporation. All rights reserved.
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
#ifndef _SYMEVL_20130723
#define _SYMEVL_20130723
// symevl.h - SymEvent for Linux - interface
//
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.
//
// This file describes the upper kernel interface to symevl.
// It is modeled roughly on the Windows heritage SymEvent facility
// but has been adapted to the Linux environment, both in the nature
// of events that it describes, and in the interfaces implemented within
// the Linux kernel.

// common typedefs for portability
#include <symtypes.h>

// Version Numbers
// - SYMEV_VER_MAJOR changes when the interface changes
// - SYMEV_VER_MINOR changes when the module is upgraded without affecting
//   the interface
// See symev_version() below for more info.
#define SYMEV_VER_MAJOR		2
#define SYMEV_VER_MINOR		1

#define SYMEV_VER_MAJOR_MMAP_WRITABLE_SUPPORT	2

// Filesystem Event Codes
//   These are the codes provided in the event callback indicating what
//   event occurred.  All events provide all file information *except*
//   that SEL_EV_MODIFY only provides the file_id, and specifically not
//   the name, for performance reasons.
// The _x values are "wildcards" matching whole classes, useful in
// the symev_register function.
#define SEL_EV_x	0xffff		// match all events
#define SEL_EV_CLMASK	0xff00		// mask to retrieve class name (_x)

#define SEL_EV_FS_x	0x0000		// all Filesystem events (in register only)
#define SEL_EV_ACCESS	0x0001		// start using object
#define SEL_EV_MODIFY	0x0002		// modify object (name not provided)
#define SEL_EV_DONE	0x0003		// done using object
#define SEL_EV_MODIFY_DONE	0x0004	// modify object; consider done after timeout
#define SEL_EV_RENAME	0x0005		// rename an object

// Event Flags
//   These flags can be combined (or'd) as necessary
#define SEL_EF_COMPLETION	0x0001		// is a completion event
#define SEL_EF_LASTLINK		0x0002		// only send event if last link
#define SEL_EF_EXECUTE		0x0004		// ACCESS is for execute
#define SEL_EF_WRITEMODE	0x0008		// DONE access was for write
#define SEL_EF_NFS		0x0010		// request is from NFS
#define SEL_EF_NOFOLLOW		0x0020		// won't follow tail symlink
#define SEL_EF_TRUNCZERO	0x0040		// MODIFY is truncation to zero-length
#define SEL_EF_MANDLOCK		0x0080		// Mandatory locking applies to this file

// Volume Types
//   These volume types are provided by symevl for its clients
enum sel_vol_type {
    SEL_VOL_FIXED = 0,		// local fixed (internal, non-removable)
    SEL_VOL_FLOPPY = 1,		// local floppy disk
    SEL_VOL_REMOVABLE = 2,	// local other removable (flash, optical, ...)
    SEL_VOL_REMOTE = 3,		// remote mount (any physical type)
    SEL_VOL_DYNAMIC = 4,	// dynamic (/proc, devfs /dev)
};

// File Types
//   These file types are provided by symevl for its clients
enum sel_fil_type {
    SEL_FIL_FILE = 0,		// regular file (or other/unknown)
    SEL_FIL_DIR = 1,		// directory
    SEL_FIL_COMM = 2,		// socket, pipe, other IPC
    SEL_FIL_DEV = 3,		// device or other special file
    SEL_FIL_LNK = 4,		// symlink (only if SEL_EF_NOFOLLOW was set)
};

// FileID
//   The type used to hold an opaque, unique file ID.
typedef unsigned long long sel_file_id_t;

typedef struct _FILE_TIME
{
	long int tv_sec;
	long int tv_nsec;
} file_time;

// Event Structure
//   This structure is passed to the client event handler to describe
//   the event, and allow the client to indicate its decision as to whether
//   the event should be processed by the system.
//
//   The data pointed to by 'name' must be copied by the client before
//   returning from the callback, as it will not necessarily persist.
#define EVT_PVTCNT	10
struct sel_geneventdata
{
    // these fields are set by SymEv for event client

    // information about the event
    unsigned long	event;		// Event code (SEL_EV_*)
    unsigned long	flags;		// Event flags (or'd SEL_EF_*)

    // information about the object being accessed
    char		*name;		// ptr to object name (may be NULL)
    unsigned long	evdata_1;	// (depends on event)
#ifdef __x86_64__
    // on 64 bit, the member i_ino in inode  already is 64bit, so this member needed
    unsigned int	s_dev;
#endif
    sel_file_id_t	file_id;	// Unique FileID

    enum sel_vol_type	vol_type;	// Volume type (SEL_VOL_*)
    enum sel_fil_type	fil_type;	// File type (SEL_FIL_*)
    int			nlinks;		// number of links (names) for the file
    unsigned int	mode;		// file mode

    // information about the accessor
    sym_pid_t		pid;		// process ID
    sym_uid_t		uid;		// user ID of process
    sym_gid_t		gid;		// group ID of process

    // these fields are set by client for SymEv
    int			ret;		// what to return
    int			scount;		// scan count (ignored by SymEv)

    // data private to SymEv - clients should not touch
    void		*ev_pvt[EVT_PVTCNT];

	// the "file_mmap_writable" is added in "SYMEV_VER_MAJOR==2" and "SYMEV_VER_MINOR==1"
	unsigned int    file_mmap_writable;		// file inode.i_data.i_mmap_writable
};

typedef struct sel_geneventdata symev_ev_t;


// Event-specific data
//   SEL_EV_ACCESS:  evdata_1 != 0 ==> access allows writing

// Prototype for the client's callback function
//   The (void *) is an opaque value provided by the client when it
//   registered.  The client will examine the event data, set the
//   action, and return.
//
//   The callback MUST NOT sleep uninterruptibly.  The callback
//   must be threadsafe (i.e. it can be called multiple times in parallel
//   on different threads) and MP-safe (as appropriate).  The callback
//   MUST NOT expect the sel_geneventdata struct itself, or anything it
//   points to, to be stable after the callback returns.
typedef SYMCALL void (sel_ev_cb_func_t)(struct sel_geneventdata *, void *);

// Registration functions (exported by symev module)

// symev_register() - register interest in event callbacks
// returns a nonzero handle when it succeeds in registering
// for events.
// @ev_handler - handler function pointer
// @refdata - opaque data passed to handler
// @ev_type - event type filter (currently ignored)
// @ev_flags - event flags filter (currently ignored)
// @ev_param - additional filter param (currently ignored)
// - The client must be prepared to receive event callbacks
//   before calling symev_register.
typedef void *symev_handle_t;
extern SYMCALL symev_handle_t symev_register(sel_ev_cb_func_t *ev_handler,
    void *refdata, unsigned long ev_type, unsigned long ev_flags,
    void *ev_param);

// symev_unregister() - delete request for event callbacks
// - symev_unregister returns 0 on success or nonzero on failure to
//   unregister the provided handle.  If this fails, something is really
//   wrong, and instability is likely to result (moreso if the client
//   module unloads).  In that case, duck and cover.
extern SYMCALL int symev_unregister(symev_handle_t);

// Utility functions

// symev_evgetfname() - obtain caller-absolute pathname for
// file described in an event struct.  Returns 0 or -errno in case of
// a failure.
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
extern SYMCALL int symev_evgetfname(struct sel_geneventdata *);
extern SYMCALL int symev_delete_shortpath(char *path);

// symev_evsvtimes() & symev_evrstimes() - save and restore last-access time
// on the file referred-to in the event struct
// - this is used by event clients who want to access the file and then
//   cover their tracks
// - it will only restore the last-access time if nothing else has changed
//   in the interim
extern SYMCALL void symev_evsvtimes(struct sel_geneventdata *);
extern SYMCALL void symev_evrstimes(struct sel_geneventdata *);

// Manage references to events
// symev_evget() - get a reference to an event
// symev_evput() - put back a reference to an event
extern SYMCALL symev_ev_t *symev_evget(symev_ev_t *);
extern SYMCALL void symev_evput(symev_ev_t *);

// Sleep efficiently
// - passing interruptible != 0 allows signals to interrupt the sleep
// - returns 0 unless interrupted
extern SYMCALL int symev_sleep(int secs, int interruptible);

// Retrieve module version information
// - the major number changes when the protocol changes
// - the minor number changes when the module is upgraded
// This just returns the values of SYMEV_VER_MAJOR and SYMEV_VER_MINOR
// from module compile time.  It's expected that these numbers
// retrieved at runtime from the module may be compared to the
// SYMEV_VER_MAJOR and SYMEV_VER_MINOR from this header file from
// compile time, to determine compatibility of event clients.
extern SYMCALL void symev_version(int *major, int *minor);

#endif //_SYMEVL_20130723
