// hnfs.h - NFS server vfs-layer hook management
//
// Copyright (C) 2005 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

// hook the NFS service callbacks

enum nfs_hook_mode_e { eSTARTUPTOHOOK, eTIMERTOHOOK };

extern int symev_hnfs_hook( enum nfs_hook_mode_e );

// unhook the NFS service callbacks
extern int symev_hnfs_unhook(void);

// release information stored about the NFS service callbacks
// -- this is called after any running hooks have exited
extern int symev_hnfs_release(void);

// reset the symev_nfsd pointers to make sure next rehook will happen
extern void symev_hnfs_reset(void);

// fill in data for /proc info file
extern void symev_hnfs_devread(char *buf, int *plen, int mlen);  // read info
