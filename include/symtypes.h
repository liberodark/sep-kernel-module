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
// symtypes.h - SymEvent for Linux - type definitions for module portability
//
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#ifndef _SYMTYPES_H
#define _SYMTYPES_H

// The SYMCALL attribute specifies a consistent calling sequence to
// use on the interfaces between clients and symev -- the kernel
// makefiles sometimes set regparm across the board, but consistency
// against parts that compile outside the kernel makefiles is needed
// for both APIs and callbacks
#define	SYMCALL		__attribute__((regparm(3)))

// System-independent typedefs
//   These types are used instead of system-specific types to enhance
//   portability.  These are generic but need to be compatible with
//   those used natively on the host system.
#ifdef __i386__
typedef unsigned short	sym_uid_t;
typedef unsigned short	sym_gid_t;
typedef int		sym_pid_t;
typedef unsigned int	sym_size_t;
typedef int		sym_ssize_t;
typedef unsigned long	sym_off_t;
typedef unsigned long long sym_loff_t;

//   These types are used generically by SYMC drivers
typedef unsigned long long sym_u64_t;		// unsigned 64-bit int (%llu)
#endif // __i386__

#ifdef __x86_64__
typedef unsigned short  sym_uid_t;
typedef unsigned short  sym_gid_t;
typedef int             sym_pid_t;
typedef unsigned long   sym_size_t;
typedef long            sym_ssize_t;
typedef long   	        sym_off_t;
typedef long long       sym_loff_t;

//   These types are used generically by SYMC drivers
typedef unsigned long long sym_u64_t;           // unsigned 64-bit int (%llu)
#endif // __x86_64__

#endif //_SYMTYPES_H
