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
// symap_cfg.h - external build-time config parameters for symap driver
//

// these parameters may be unique to a particular OS

#ifndef _SYMAP_CFG_H
#define _SYMAP_CFG_H

// the module name, registered with the OS
#define SYMAP_MODULENAME	"symap"

// the device name, registered with the OS
#define SYMAP_DEVNAME		"symap"

// the device nodename, used to access SymAP from usermode
#define SYMAP_NODENAME		"/dev/" SYMAP_DEVNAME

// the /proc filename and pathname
#define SYMAP_PROCFILE		"symap"
#define SYMAP_PROCPATH		"/proc/" SYMAP_PROCFILE

#endif //_SYMAP_CFG_H
