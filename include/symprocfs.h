/********************************************************************************************************
 * SYMANTEC:     Copyright (c) 2014-2015 Symantec Corporation. All rights reserved.
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
// symprocfs.h - Abstract accesses to procfs functions
//
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.
//

#ifndef SYM_PROC_FS_H_
#define SYM_PROC_FS_H_

// --- Abstract accesses to procfs functions ------------------------

// abstracted i/o function prototypes
typedef int (sym_procfs_readfunc_t)(char *buf, int *offp, int count);
typedef int (sym_procfs_writefunc_t)(const char /*__user*/ *buf, int count);

// opaque handle for procfs nodes
struct sym_procfs_info;

// create new procfs entry
struct sym_procfs_info *sym_procfs_new(const char *filename,
    sym_procfs_readfunc_t *readfunc, sym_procfs_writefunc_t *writefunc);

// delete procfs entry created using sym_procfs_new()
void sym_procfs_delete(const char *, struct sym_procfs_info *);

// sprintf into buffer, updating pointers, stopping when full
int sym_procfs_printf(char *buf, int *offp, int count, const char *, ...)
    __attribute__((format(printf, 4, 5)));		// gcc args checking

#endif //SYM_PROC_FS_H_
