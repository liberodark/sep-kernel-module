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
// symap-core.h: interface for symap module core
//

// external declarations for entry points into symap-core.o
// - refer to symap-core source for details

#include <symtypes.h>

extern SYMCALL int symap_read_proc_symap(char *, int *, int);
extern SYMCALL int symap_write_proc_symap(const char *, int);
extern SYMCALL int symap_open(void *);
extern SYMCALL int symap_release(void *);
extern SYMCALL sym_ssize_t symap_write(void *, const char *, sym_size_t, sym_loff_t *);
extern SYMCALL int symap_ioctl(void *, unsigned int, unsigned long);
extern SYMCALL int symap_init_1(void);
extern SYMCALL int symap_init_2(void);
extern SYMCALL void symap_exit_1(void);
extern SYMCALL void symap_exit_2(void);
