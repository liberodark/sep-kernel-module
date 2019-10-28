// hnfs.c - SymEv NFS hooks
//
// Copyright (C) 2017 Symantec Corporation.
// This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
// See the "COPYING" file distributed with this software for more info.

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
#	include <linux/config.h>
#endif

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mount.h>
#include <linux/proc_fs.h>
#include <linux/unistd.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/dcache.h>
#include <linux/sched.h>
#include <linux/rwsem.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,23)
#include <linux/nfsd/interface.h>
#endif

#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/stats.h>
#include <linux/proc_fs.h>

#if defined(RHEL_MAJOR) && RHEL_MAJOR == 6
  #define RHEL6 1
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) || defined(RHEL6) // RedHat Enterprise Linux 6 merges some code to 2.6.32
#include <nfsd.h>
#include <cache.h>
#include <xdr.h>
#include <xdr3.h>
  #if LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
#include <vfs.h>
  #endif //LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
  #if defined(CONFIG_NFSD_V4)
#include <state.h>
#include <nfsfh.h>
#include <xdr4.h>
  #endif //CONFIG_NFSD_V4
#else //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) || defined(RHEL6)
#include <linux/nfsd/nfsd.h>
#include <linux/nfsd/cache.h>
#include <linux/nfsd/xdr.h>
#include <linux/nfsd/xdr3.h>
  #if defined(CONFIG_NFSD_V4)
#include <linux/nfsd/state.h>
#include <linux/nfsd/xdr4.h>
  #endif //CONFIG_NFSD_V4
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,33) || defined(RHEL6)

#include <linux/nfs2.h>
#include <linux/nfs3.h>
#if defined(CONFIG_NFSD_V4)
#include <linux/nfs4.h>
#include <linux/namei.h>
#endif //CONFIG_NFSD_V4

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,24)
#include <net/net_namespace.h>
#endif

#include <linux/nfsd/nfsfh.h>
#include <linux/nfsd/stats.h>
#include "symevl.h"

#include "symev.h"
#include "symkutil.h"
#include "hnfs.h"

#define UNUSED(x) (void)(x)

// forward
extern struct sym_finfo *symev_fhgetfinfo(struct svc_fh *, int);
extern unsigned long symbol_in_kallsyms(const char* sym, const char* mod);
static int hook_nfs2(void), unhook_nfs2(void), release_nfs2(void);
static int hook_nfs3(void), unhook_nfs3(void), release_nfs3(void);
#if defined(CONFIG_NFSD_V4)
static int hook_nfs4( enum nfs_hook_mode_e ), unhook_nfs4(void), release_nfs4(void);
#endif
static int check_nfs(void);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
extern int set_addr_rw(long unsigned int _addr, int ipages);
extern int set_addr_ro(long unsigned int _addr, int ipages);
#endif //LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)

/*kernel 4.13 changed the nfsiXXXX APIS signatures
from 
	int nfs3svc_encode_attrstat(struct svc_rqst *rqstp, __be32 *p, struct nfsd3_attrstat *resp)
To
	int nfs3svc_encode_attrstat(struct svc_rqst *rqstp, __be32 *p)
So define svc_procfunc and kxdrproc_t as needed for Kernel 4.13 
*/
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
typedef __be32	(*svc_procfunc)(struct svc_rqst *);
typedef void	(*kxdrproc_t)(struct svc_rqst *);
#endif


// === hooks state ===
// We find the svc_version structures for the NFSv2 and NFSv3 sunrpc
// handlers, which we store in the pointers symev_nfsd_v2 and symev_nfsd_v3.
// When we "hook" the NFS servers, what we do is replace certain of the
// rpc callbacks with our own wrappers, and the original callback addresses
// get parked in the nfs2_hooked and nfs3_hooked structs.

// hook storage for v2
static struct svc_version *symev_nfsd_v2 = NULL;	// NFSv2 server

static struct {
    svc_procfunc create;
    svc_procfunc read;
    svc_procfunc write;
    svc_procfunc remove;
    svc_procfunc rename;
    svc_procfunc link;
} nfs2_hooked = {NULL};

// hook storage for v3
static struct svc_version *symev_nfsd_v3 = NULL;	// NFSv3 server
static struct {
    svc_procfunc create;
    svc_procfunc access;
    svc_procfunc read;
    svc_procfunc write;
    svc_procfunc remove;
    svc_procfunc rename;
    svc_procfunc link;
    svc_procfunc commit;
} nfs3_hooked = {NULL};

#if defined(CONFIG_NFSD_V4)
// hook storage for v4
static struct svc_version *symev_nfsd_v4 = NULL;        // NFSv4 server
static struct {
    svc_procfunc compound;
} nfs4_hooked = {NULL};
#endif

const char*             	nfsd_proc_name = "/proc/net/rpc/nfsd";  // proc_net_rpc_nfsd file path name
const struct file_operations	*symev_nfsd_fops = NULL;                // proc_net_rpc_nfsd file operations
struct dentry       		*symev_nfsd_dentry = NULL;              // proc_net_rpc_nfsd file dentry

static struct dentry* sym_get_file_dentry(const char* filename)
{
    int err = 0;
    struct dentry* dentry = NULL;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    struct path path;
    memset((char *)&path, 0, sizeof(struct path));
#else
    struct nameidata nd;
    memset((char *)&nd, 0, sizeof(struct nameidata));
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    err = kern_path(filename, 0, &path);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0)
    err = path_lookup(filename, 0, &nd);
#else
    if (path_init(fn, LOOKUP_POSITIVE, &nd))
        err = path_walk(filename, &nd);
#endif

    if(err)
    {
        return NULL;
    }

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    if (nd.dentry->d_inode)
    {
        dentry = dget(nd.dentry);
    }
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    if (path.dentry->d_inode)
    {
        dentry = dget(path.dentry);
    }
#else
    if (nd.path.dentry->d_inode)
    {
        dentry = dget(nd.path.dentry);
    }
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
    path_release(&nd);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,39)
    path_put(&path);
#else
    path_put(&(nd.path));
#endif

    return dentry;
}

static void sym_put_file_dentry(struct dentry* dentry)
{
    dput(dentry);
}

// macros to access rpcsvc dispatch table fields
#define NFS_HFUNC(v, index) (symev_nfsd_v ## v->vs_proc && (index < symev_nfsd_v ## v->vs_nproc) \
    ? symev_nfsd_v ## v->vs_proc[index].pc_func : NULL)

#define NFS_RFUNC(v, index) (symev_nfsd_v ## v->vs_proc && (index < symev_nfsd_v ## v->vs_nproc) \
    ? symev_nfsd_v ## v->vs_proc[index].pc_release : NULL)


static struct svc_stat *sym_get_nfsd_stat(const struct file_operations **nfsd_fops)
{
    symev_nfsd_dentry = sym_get_file_dentry(nfsd_proc_name);

    if( (NULL == symev_nfsd_dentry) || (NULL == symev_nfsd_dentry->d_inode) )
    {
	symev_trace(1,"symev: cannot get valid inode for /proc/net/rpc/nfsd\n");
        return NULL;
    }

    if(nfsd_fops)
        *nfsd_fops = symev_nfsd_dentry->d_inode->i_fop;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
    return (struct svc_stat *) (PDE(symev_nfsd_dentry->d_inode)->data);
#else //means LINUX_VERSION_CODE >= KERNEL_VERSION(3,10,0)
    return (struct svc_stat *)(PDE_DATA(symev_nfsd_dentry->d_inode));
#endif //LINUX_VERSION_CODE < KERNEL_VERSION(3,10,0)
}

static void sym_increase_nfs_ref(void)
{
/*
 * Increase ref count of nfsd to prevent it from being removed.
 * Allowing nfsd to be removed siliently is dangeous for sav and
 * can cause panic.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) 
    if(symev_nfsd_fops)
    {
        try_module_get(symev_nfsd_fops->owner);
    }
#endif

    printk("symev: hold nfsd module\n");
}

static void sym_decrease_nfs_ref(void)
{
/*
 * Increase ref count of nfsd to prevent it from being removed.
 * Allowing nfsd to be removed siliently is dangeous for sav and
 * can cause panic.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0) 
    if(symev_nfsd_fops)
    {
        module_put(symev_nfsd_fops->owner);
    }
#endif

    printk("symev: release nfsd module\n");
}

// hook the NFS servers
// In order to find the NFS servers RPC service, we wind our way
// down thru the /proc filesystem to /proc/net/rpc/nfsd.  This
// node has a pointer to nfsd's svc_stat struct, which luckily happens
// to have a pointer to the svc_program struct for nfsd.  From there
// it is a simple matter to find the handler structs for the v2 and v3
// protocols...
int
symev_hnfs_hook( enum nfs_hook_mode_e nfs_hook_mode )
{
    struct svc_stat *nfsd_svcstats = NULL;
    struct svc_program *pprog = NULL;
    int rc = 0;
    const struct file_operations *nsfd_fops=NULL;

    // if already/still hooked, all set
    if (check_nfs())
	return 0;
 
    // now find the nfsd2 and nfsd3 "program" structs, via the
    // svcstats block...
    if (!(nfsd_svcstats = sym_get_nfsd_stat(&nsfd_fops)))
    {
	// failed sanity check
	symev_trace(1, "symev_nfsd_hook: failed to hook nfsd(C)\n");
	return -1;
    }

    if (!(pprog = nfsd_svcstats->program))
    {
	// failed sanity check
	symev_trace(1, "symev_nfsd_hook: failed to hook nfsd(D)\n");
	return -1;
    }

    // -- NFS v2 --
    // grab the progam version for v2 from there
    if (2 >= pprog->pg_nvers
	|| !pprog->pg_vers
	|| !(symev_nfsd_v2 = pprog->pg_vers[2]))
    {
	symev_trace(1, "symev_nfsd_hook: failed to hook nfsd2(E)\n");
    }
    else
    {
		symev_trace(1, "symev_hnfs_hook: going to hook nfsd2\n");
		// try to hook, indicate status
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_rw(symev_nfsd_v2->vs_proc, 2);
		#endif
		rc = hook_nfs2();
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		set_addr_ro(symev_nfsd_v2->vs_proc, 2);
		#endif
	symev_trace(1, "symev_nfsd_hook: hooked nfsd2 at %p\n", symev_nfsd_v2);
    }

    // grab the progam version for v3
    if (3 >= pprog->pg_nvers
	|| !pprog->pg_vers
	|| !(symev_nfsd_v3 = pprog->pg_vers[3]))
    {
	symev_trace(1, "symev_nfsd_hook: failed to hook nfsd3(F)\n");
    }
    else
    {
	int v3rc = 0;
	symev_trace(1, "symev_nfsd_hook: going to hook nfsd3\n");
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		set_addr_rw(symev_nfsd_v3->vs_proc, 2);		
	#endif

	// try to hook, indicate status
	if (hook_nfs3() >= 0)
	    rc = v3rc;
	
	#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
		set_addr_ro(symev_nfsd_v3->vs_proc, 2);	
	#endif

	symev_trace(1, "symev_nfsd_hook: hooked nfsd3 at %p\n", symev_nfsd_v3);
    }

#if defined(CONFIG_NFSD_V4)
    // grab the progam version for v4
    if (4 >= pprog->pg_nvers
        || !pprog->pg_vers
        || !(symev_nfsd_v4 = pprog->pg_vers[4]))
    {
        symev_trace(1, "symev_nfsd_hook: failed to hook nfsd4(F)\n");
    }
    else
    {
        int v4rc = 0;
		symev_trace(1, "symev_nfsd_hook: going to hook nfsd4\n");
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_rw(symev_nfsd_v4->vs_proc, 2);	
		#endif
			// try to hook, indicate status
		if (hook_nfs4( nfs_hook_mode ) >= 0)
				rc = v4rc;

		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_ro(symev_nfsd_v4->vs_proc, 2);	
		#endif

		symev_trace(1, "symev_nfsd_hook: hooked nfsd4 at %p\n", symev_nfsd_v4);
    }
#endif

    // or if neither hooked, indicate error anyway
    if ( !symev_nfsd_v2 && !symev_nfsd_v3
#if defined(CONFIG_NFSD_V4)
         && !symev_nfsd_v4
#endif
    ) {
	symev_trace(1, "symev_nfsd_hook: did not hook any nfs version\n");
	return -1;
    }

    //increase the /proc/net/rpc/nfsd reference to avoid it is unloaded
    if (symev_nfsd_fops==NULL)
    {
        //first time hook
        symev_nfsd_fops = nsfd_fops;
        sym_increase_nfs_ref();
    } 
    else 
    {
        printk("symev: already hooked. symev_proc_net_rpc_nfsd was %p\n",
            symev_nfsd_fops);
    }

    return rc;
}

int
symev_hnfs_unhook(void)
{

    if (symev_nfsd_v2)
	{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_rw(symev_nfsd_v2->vs_proc, 2);	
		#endif
		unhook_nfs2();

		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_ro(symev_nfsd_v2->vs_proc, 2);	
		#endif
	}

    if (symev_nfsd_v3)
	{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_rw(symev_nfsd_v3->vs_proc, 2);
		#endif

		unhook_nfs3();

		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_ro(symev_nfsd_v3->vs_proc, 2);
		#endif
	}

#if defined(CONFIG_NFSD_V4)
    if (symev_nfsd_v4)
	{
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_rw(symev_nfsd_v4->vs_proc, 2);	
		#endif

		unhook_nfs4();
	
		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0))
			set_addr_ro(symev_nfsd_v4->vs_proc, 2);	
		#endif
	}
#endif

    return 0;
}

int
symev_hnfs_release(void)
{
    if (symev_nfsd_v2)
	release_nfs2();

    if (symev_nfsd_v3)
	release_nfs3();

#if defined(CONFIG_NFSD_V4)
    if (symev_nfsd_v4)
        release_nfs4();
#endif

    if(symev_nfsd_dentry)
    {
        sym_put_file_dentry(symev_nfsd_dentry);
        symev_nfsd_dentry = NULL;
    }

    return 0;
}

void
symev_hnfs_reset(void)
{
    symev_nfsd_v2 = NULL;
    symev_nfsd_v3 = NULL;

#if defined(CONFIG_NFSD_V4)
    symev_nfsd_v4 = NULL;
#endif

    if (symev_nfsd_fops) { 
        /*
        * User asked for release of nfsd. 
        * Now remove all the nfsd hooks.
        */
        sym_decrease_nfs_ref();
        symev_nfsd_fops = NULL;
    }

    printk("symev: nfsd reset\n");
}


// == nfsv2 hooks ==

// each NFS2 service routine is called with a predefined args and rets type

// symev_nfsd2_proc_create - wrapper for NFSv2 create handler
// calling sequence and return are as for any rpc service callback
// CREATE: after calling underlying create function, send ACCESS event
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_create(struct svc_rqst *qp)
{
	struct nfsd_createargs *ap = qp->rq_argp;
	struct nfsd_diropres *rp = qp->rq_resp;
#else
int symev_nfsd2_proc_create(struct svc_rqst *qp,
    struct nfsd_createargs *ap,
    struct nfsd_diropres *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd2: CREATE \n");

    if (nfs2_hooked.create)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs2_hooked.create(qp);
	ap = qp->rq_argp;
	rp = qp->rq_resp;
#else
	rc = nfs2_hooked.create(qp, ap, rp);
#endif
	// if a file got created, send an event for it
	// -- a v2 create can create directories and other non-scanned
	// objects
	if (rc == 0 &&
	    rp->fh.fh_dentry && rp->fh.fh_dentry->d_inode &&
	    S_ISREG(rp->fh.fh_dentry->d_inode->i_mode) && rp->fh.fh_export)
	{
	    (void) symev_dm_event(SEL_EV_ACCESS,
		SEL_EF_NFS | SEL_EF_COMPLETION, 1,
		"nfs2_create", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd2_proc_read() - wrapper for NFSv2 read handler
// calling sequence and return are as for any rpc service callback
// NFS's statelessness demands that we treat each READ as if it were an
// OPEN.  As long as the file cache is enabled this should be OK.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_read(struct svc_rqst *qp)
{
	struct nfsd_readargs *ap = qp->rq_argp;
	struct nfsd_readres *rp = qp->rq_resp;
#else
int symev_nfsd2_proc_read(struct svc_rqst *qp,
    struct nfsd_readargs *ap,
    struct nfsd_readres *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call
    int ret;

    enter_handler();

    symev_trace(2, "symev_nfsd2: READ \n");

    if (nfs2_hooked.read)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs2_hooked.read(qp);
	ap = qp->rq_argp;
	rp = qp->rq_resp;
#else
	rc = nfs2_hooked.read(qp, ap, rp);
#endif
	// NOW process an ACCESS event, while we're holding the
	// results of that read.  (It hasn't been cached yet in the
	// nfsd cache so retries will reenter here...).
	if (rc == 0 && rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    ret = symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS, O_RDONLY,
		"nfs2_read", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif
	    // map the errno (wishing we had access to nfserrno())
	    switch(ret)
	    {
		case 0:		break;	// preserve above return
		case -EPERM:	rc = nfserr_perm; break;
		case -EIO:	rc = nfserr_io; break;
		case -EACCES:	rc = nfserr_acces; break;
		case -ENOMEM:	rc = nfserr_dropit; break;
		default:	rc = nfserr_io; break;
	    }
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd2_proc_write - wrapper for NFSv2 write handler
// calling sequence and return are as for any rpc service callback
// NFS's statelessness demands that we treat each v2 WRITE as if it
// were a MODIFY followed (after a timeout) by a DONE.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_write(struct svc_rqst *qp)
{
	struct nfsd_writeargs *ap = qp->rq_argp;
	struct nfsd_attrstat *rp = qp->rq_resp;
#else
int symev_nfsd2_proc_write(struct svc_rqst *qp,
    struct nfsd_writeargs *ap,
    struct nfsd_attrstat *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd2: WRITE \n");

    if (nfs2_hooked.write)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs2_hooked.write(qp);
	ap = qp->rq_argp;
	rp = qp->rq_resp;
#else
	rc = nfs2_hooked.write(qp, ap, rp);
#endif
	// NOW process an ACCESS event, while we're holding the
	// results of that read.  (It hasn't been cached yet in the
	// nfsd cache so retries will reenter here...).
	if (rc == 0 && rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    (void) symev_dm_event(SEL_EV_MODIFY_DONE,
		SEL_EF_COMPLETION | SEL_EF_WRITEMODE | SEL_EF_NFS,
		0, "nfs2_write", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd2_proc_remove - wrapper for NFSv2 remove handler
// calling sequence and return are as for any rpc service callback
// ap->fh is the filehandle of the directory to delete from, and
// ap->name/len is the name to delete.  We need to treat this as a
// MODIFY so we don't need a name, but we DO need the file's dentry.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_remove(struct svc_rqst *qp)
{
	struct nfsd_diropargs *ap = qp->rq_argp;
	struct nfsd_attrstat *rp = qp->rq_resp;
	UNUSED(rp);
#else
int symev_nfsd2_proc_remove(struct svc_rqst *qp,
    struct nfsd_diropargs *ap,
    void *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call
    svc_procfunc lookup_hdl_f = NFS_HFUNC(2, NFSPROC_LOOKUP);
    kxdrproc_t lookup_rel_f = NFS_RFUNC(2, NFSPROC_LOOKUP);

    enter_handler();

    symev_trace(2, "symev_nfsd2: REMOVE \n");

    if (nfs2_hooked.remove)
    {
	// we use the nfs2 "lookup" method to resolve the fh+name (in
	// the args) into a FH.  if that FH ends up containing a non-negative
	// dentry, then it's our file to be deleted
	if (lookup_hdl_f)
	{
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		struct nfsd_diropres* presp = qp->rq_resp;
#else
	    struct nfsd_diropargs iarg;
	    struct nfsd_diropres ires;

	    // populate a "lookup" request from the leftover FHs
	    iarg.fh = ap->fh;
	    iarg.name = ap->name;
	    iarg.len = ap->len;
#endif
	    symev_trace(2, "nfsd2_remove: calling lookup_hdl\n");

#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		if (!(lookup_hdl_f(qp)))
		{
			// check the file FH
			if (presp->fh.fh_dentry && presp->fh.fh_dentry->d_inode && presp->fh.fh_export)
			{
				// there's an inode, by golly, so send a pre-unlink event
				(void) symev_dm_event(SEL_EV_MODIFY,
				SEL_EF_LASTLINK | SEL_EF_NFS, 0, "nfs2_remove",
				presp->fh.fh_dentry, 
				presp->fh.fh_export->ex_path.mnt);	
#else
	    if (!(lookup_hdl_f(qp, &iarg, &ires)))
		{
			// check the file FH
			if (ires.fh.fh_dentry && ires.fh.fh_dentry->d_inode && ires.fh.fh_export)
			{
				// there's an inode, by golly, so send a pre-unlink event
				(void) symev_dm_event(SEL_EV_MODIFY,
				SEL_EF_LASTLINK | SEL_EF_NFS, 0, "nfs2_remove",
				ires.fh.fh_dentry, 
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
							ires.fh.fh_export->ex_mnt);
		#else
							ires.fh.fh_export->ex_path.mnt);
		#endif
#endif
	  
			}
			else
			{
				symev_trace(2, "nfsd2_remove: negative dentry for <%.*s>\n", ap->len, ap->name);
			}
	    }

	    // put back the FHs that lookup allocated
	    if (lookup_rel_f)
	    {
		symev_trace(2, "nfsd2_remove: calling lookup_rel\n");
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		(void) lookup_rel_f(qp);
#else
		(void) lookup_rel_f(qp, NULL, &ires);
#endif
	    }
	}

	symev_trace(2, "nfsd2_remove: calling underlying\n");
	// we're going to call the remove func even if our little
	// folly above failed
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs2_hooked.remove(qp);
#else
	rc = nfs2_hooked.remove(qp, ap, rp);
#endif
    }

    leave_handler();

    return rc;
}

// symev_nfs2_rename_hook() - send RENAME for file whose name is changed
// obtain a FH for a file given its directory FH and filename,
// and submit a RENAME event for that file
// -- this code is common between rename and link
static inline void symev_nfs2_rename_hook(char *dbg,
    struct svc_rqst *qp, svc_fh *fh, char *name, int len)
{
    svc_procfunc lookup_hdl_f = NFS_HFUNC(2, NFSPROC_LOOKUP);
    kxdrproc_t lookup_rel_f = NFS_RFUNC(2, NFSPROC_LOOKUP);

    if (lookup_hdl_f)
    {
	
		// do the lookup... if it succeeds, we got a FH
		symev_trace(2, "nfs2_rename_hook/%s: calling lookup_hdl\n", dbg);
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		if (!lookup_hdl_f(qp))
		{
			// if the FH is positive, send it a RENAME
			struct nfsd_diropres *pres = qp->rq_resp;
			if (pres->fh.fh_dentry && pres->fh.fh_dentry->d_inode && pres->fh.fh_export)
			{
				(void) symev_dm_event(SEL_EV_RENAME,
					SEL_EF_NFS | SEL_EF_COMPLETION, 0,
					dbg, pres->fh.fh_dentry,
					pres->fh.fh_export->ex_path.mnt);
	#else
		struct nfsd_diropargs iarg;
		struct nfsd_diropres ires;

		// populate a "lookup" request from the leftover FHs
		iarg.fh = *fh;
		iarg.name = name;
		iarg.len = len;

		if (!lookup_hdl_f(qp, &iarg, &ires))
		{
			if (ires.fh.fh_dentry && ires.fh.fh_dentry->d_inode && ires.fh.fh_export)
			{
				(void) symev_dm_event(SEL_EV_RENAME,
					SEL_EF_NFS | SEL_EF_COMPLETION, 0,
					dbg, ires.fh.fh_dentry,
			#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
					ires.fh.fh_export->ex_mnt);
			#else
							ires.fh.fh_export->ex_path.mnt);
			#endif
	#endif //KERNEL_VERSION(4,13,0)
	    }
	    else
	    {
		symev_trace(2, "nfs2_rename_hook/%s: negative dentry for <%.*s>\n",
		    dbg, len, name);
	    }
	}

	// put back the FHs that lookup allocated
	if (lookup_rel_f)
	{
	    symev_trace(2, "nfs2_rename_hook/%s: calling lookup_rel\n", dbg);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
		(void) lookup_rel_f(qp);
#else
	    (void) lookup_rel_f(qp, NULL, &ires);
#endif
	}
    }
}


// symev_nfsd2_proc_rename - wrapper for NFSv2 rename handler
// calling sequence and return are as for any rpc service callback
// ap->ffh is the filehandle of the directory to rename from,
// ap->fname/flen is the name to rename, and ->tfh/tname/tlen are the
// directory and name to rename to.  We need to do a RENAME event on
// the tname.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_rename(struct svc_rqst *qp)
{
	struct nfsd_renameargs *ap = qp->rq_argp;
	struct nfsd_renameres *rp = qp->rq_resp;
	UNUSED(rp);
#else
int symev_nfsd2_proc_rename(struct svc_rqst *qp,
    struct nfsd_renameargs *ap,
    void *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd2: RENAME \n");

    if (nfs2_hooked.rename)
    {
	svc_fh arg_tfh = ap->tfh;	// copy this before it's used

	// do the underlying rename...
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	if (!(rc = nfs2_hooked.rename(qp)))
#else
	if (!(rc = nfs2_hooked.rename(qp, ap, rp)))
#endif
	{
	    // and send a RENAME event for the new name
	    symev_nfs2_rename_hook("nfs2_rename", qp,
		&arg_tfh, ap->tname, ap->tlen);
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd2_proc_link - wrapper for NFSv2 link handler
// calling sequence and return are as for any rpc service callback
// ap->ffh is the filehandle of the file to link from, ap->fname/flen
// is the name of the file, and ->tfh/tname/tlen are the directory and
// name to link to.  We need to do a RENAME event on the tname so this
// is similar to rename above.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd2_proc_link(struct svc_rqst *qp)
{
	struct nfsd_linkargs *ap = qp->rq_argp;
	struct nfsd_linkres  *rp = qp->rq_resp;
	UNUSED(rp);
#else
int symev_nfsd2_proc_link(struct svc_rqst *qp,
    struct nfsd_linkargs *ap,
    void *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd2: LINK \n");

    if (nfs2_hooked.link)
    {
	svc_fh arg_tfh = ap->tfh;	// copy this before it's used

	// do the underlying link...
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	if (!(rc = nfs2_hooked.link(qp)))
#else
	if (!(rc = nfs2_hooked.link(qp, ap, rp)))
#endif
	{
	    // it succeeded... send a RENAME event if possible
	    symev_nfs2_rename_hook("nfs2_link",
		qp, &arg_tfh, ap->tname, ap->tlen);
	}
    }

    leave_handler();

    return rc;
}

#if ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0) ) 
	#define HOOK_NFSCB(v, index, name, wrapper) \
	if (symev_nfsd_v ## v->vs_proc && (index < symev_nfsd_v ## v->vs_nproc)) \
	{ \
	nfs ## v ## _hooked.name = symev_nfsd_v ## v->vs_proc[index].pc_func; \
	symev_trace(1, "symev: before hooking v%d.%s with %s at %p\n", v, #index, \
		#wrapper, (void *) wrapper); \
		set_addr_rw(((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func,2); \
		((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func = (svc_procfunc) wrapper; \
		set_addr_ro(((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func,2); \
		symev_trace(1, "symev: hooked v%d.%s with %s at %p\n", v, #index, \
			#wrapper, (void *) wrapper); \
		} else { symev_trace(1, "symev: NOTICE: did not hook v%d.%s\n", v, #index); } 

	#define UNHOOK_NFSCB(v, index, name, wrapper) \
    	if ((symev_nfsd_v ## v->vs_proc) && (index < symev_nfsd_v ## v->vs_nproc) \
	&& (nfs ## v ## _hooked.name) \
	&& (symev_nfsd_v ## v->vs_proc[index].pc_func == (svc_procfunc) wrapper)) { \
	symev_trace(1, "symev: going to unhook v%d.%s with %s at %p\n", v, #index, #wrapper, (void *) wrapper); \
	set_addr_rw(((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func,2); \
	((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func = nfs ## v ## _hooked.name; \
	set_addr_ro(((struct svc_procedure *)(symev_nfsd_v ## v->vs_proc))[index].pc_func,2); \
	symev_trace(1, "symev: unhooked v%d.%s from %s to %p\n", v, #index, \
	    #wrapper, (void *) nfs ## v ## _hooked.name); \
    	} else { symev_trace(1, "symev: NOTICE: did not unhook v%d.%s\n", \
	v, #index); } 
#elif ( LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0) )
	#define HOOK_NFSCB(v, index, name, wrapper) \
		if (symev_nfsd_v ## v->vs_proc && (index < symev_nfsd_v ## v->vs_nproc)) \
		{ \
		nfs ## v ## _hooked.name = symev_nfsd_v ## v->vs_proc[index].pc_func; \
		set_addr_rw(symev_nfsd_v ## v->vs_proc[index].pc_func,2); \
		symev_nfsd_v ## v->vs_proc[index].pc_func = (svc_procfunc) wrapper; \
		set_addr_ro(symev_nfsd_v ## v->vs_proc[index].pc_func,2); \
		symev_trace(1, "symev: hooked v%d.%s with %s at %p\n", v, #index, \
			#wrapper, (void *) wrapper); \
		} else { symev_trace(1, "symev: NOTICE: did not hook v%d.%s\n", v, #index); }

	#define UNHOOK_NFSCB(v, index, name, wrapper) \
    if ((symev_nfsd_v ## v->vs_proc) && (index < symev_nfsd_v ## v->vs_nproc) \
	&& (nfs ## v ## _hooked.name) \
	&& (symev_nfsd_v ## v->vs_proc[index].pc_func == (svc_procfunc) wrapper)) { \
		set_addr_rw(symev_nfsd_v ## v->vs_proc[index].pc_func,2); \
		symev_nfsd_v ## v->vs_proc[index].pc_func = nfs ## v ## _hooked.name; \
		set_addr_ro(symev_nfsd_v ## v->vs_proc[index].pc_func,2); \
		symev_trace(1, "symev: unhooked v%d.%s from %s to %p\n", v, #index, \
			#wrapper, (void *) nfs ## v ## _hooked.name); \
    } else { symev_trace(1, "symev: NOTICE: did not unhook v%d.%s\n", \
	v, #index); }
#else 
	#define HOOK_NFSCB(v, index, name, wrapper) \
		if (symev_nfsd_v ## v->vs_proc && (index < symev_nfsd_v ## v->vs_nproc)) \
		{ \
		nfs ## v ## _hooked.name = symev_nfsd_v ## v->vs_proc[index].pc_func; \
		symev_nfsd_v ## v->vs_proc[index].pc_func = (svc_procfunc) wrapper; \
		symev_trace(1, "symev: hooked v%d.%s with %s at %p\n", v, #index, \
			#wrapper, (void *) wrapper); \
		} else { symev_trace(1, "symev: NOTICE: did not hook v%d.%s\n", v, #index); }

	#define UNHOOK_NFSCB(v, index, name, wrapper) \
    if ((symev_nfsd_v ## v->vs_proc) && (index < symev_nfsd_v ## v->vs_nproc) \
	&& (nfs ## v ## _hooked.name) \
	&& (symev_nfsd_v ## v->vs_proc[index].pc_func == (svc_procfunc) wrapper)) { \
		symev_nfsd_v ## v->vs_proc[index].pc_func = nfs ## v ## _hooked.name; \
		symev_trace(1, "symev: unhooked v%d.%s from %s to %p\n", v, #index, \
			#wrapper, (void *) nfs ## v ## _hooked.name); \
    } else { symev_trace(1, "symev: NOTICE: did not unhook v%d.%s\n", \
	v, #index); }
#endif

#define ISHOOK_NFSCB(v, index, name, wrapper) \
    ((symev_nfsd_v ## v->vs_proc) && (index < symev_nfsd_v ## v->vs_nproc) \
	&& (nfs ## v ## _hooked.name) \
	&& (symev_nfsd_v ## v->vs_proc[index].pc_func == (svc_procfunc) wrapper))


// hook_nfs2 -- install hooks into the NFSv2 server based on the global
// pointer to the server's structure in symev_nfsd_v2
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
hook_nfs2(void)
{
    if (!symev_nfsd_v2->vs_proc)
	return -1;
	symev_trace(1, "hook_nfs2: going to hook nfsd2\n");
    HOOK_NFSCB(2, NFSPROC_CREATE, create, symev_nfsd2_proc_create);
    HOOK_NFSCB(2, NFSPROC_READ, read, symev_nfsd2_proc_read);
    HOOK_NFSCB(2, NFSPROC_WRITE, write, symev_nfsd2_proc_write);
    HOOK_NFSCB(2, NFSPROC_REMOVE, remove, symev_nfsd2_proc_remove);
    HOOK_NFSCB(2, NFSPROC_RENAME, rename, symev_nfsd2_proc_rename);
    HOOK_NFSCB(2, NFSPROC_LINK, link, symev_nfsd2_proc_link);

    return 0;
}

// unhook_nfs2 -- install hooks into the NFSv2 server based on the global
// pointer to the server's structure in symev_nfsd_v2
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
unhook_nfs2(void)
{
    if (!symev_nfsd_v2->vs_proc)
	return -1;
	symev_trace(1, "hook_nfs2: going to unhook nfsd2\n");
    UNHOOK_NFSCB(2, NFSPROC_CREATE, create, symev_nfsd2_proc_create);
    UNHOOK_NFSCB(2, NFSPROC_READ, read, symev_nfsd2_proc_read);
    UNHOOK_NFSCB(2, NFSPROC_WRITE, write, symev_nfsd2_proc_write);
    UNHOOK_NFSCB(2, NFSPROC_REMOVE, remove, symev_nfsd2_proc_remove);
    UNHOOK_NFSCB(2, NFSPROC_RENAME, rename, symev_nfsd2_proc_rename);
    UNHOOK_NFSCB(2, NFSPROC_LINK, link, symev_nfsd2_proc_link);

    return 0;
}

// release_nfs2 -- forget the hooks into the NFSv2 server and the global
// pointer to the server's structure in symev_nfsd_v2
// returns 0 on success (which is assured currently)
// -- this will be called with wrlock held
static int
release_nfs2(void)
{
    // wipe out the hook addresses
    memset((char *)&nfs2_hooked, 0, sizeof(nfs2_hooked));

    return 0;
}

// == nfsv3 hooks ==

// each NFS3 service routine is called with a predefined args and rets type


// symev_nfsd3_proc_read() - wrapper for NFSv3 getattr handler
// calling sequence and return are as for any rpc service callback
// Even the file is cached, the nfs3 client will check the access permission again
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_access(struct svc_rqst *qp)
{
	struct nfsd3_accessargs *ap = qp->rq_argp ;
	struct nfsd3_accessres *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_access(struct svc_rqst *qp, 
    struct nfsd3_accessargs *ap, 
    struct nfsd3_accessres *rp)
{
#endif //KERNEL_VERSION(4,13,0)

    int rc = nfserr_dropit;		// in case we have nothing to call
    int ret;

    enter_handler();

    symev_trace(2, "symev_nfsd3: ACCESS \n");

    if (nfs3_hooked.access)
    {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		rc = nfs3_hooked.access(qp);
#else
        // returns FH for resulting file in rp->fh
        rc = nfs3_hooked.access(qp, ap, rp);
#endif
        // NOW process an ACCESS event, while we're holding the
        // results of that read.  (It hasn't been cached yet in the
        // nfsd cache so retries will reenter here...).
        if (rc == 0 && rp->fh.fh_dentry && rp->fh.fh_export)
        {
            ret = symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS, O_RDONLY,
                "nfs3_access", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif

            // map the errno (wishing we had access to nfserrno())
            switch(ret)
            {
            case 0:		break;	// preserve above return
            case -EPERM:	rc = nfserr_perm; break;
            case -EIO:	rc = nfserr_io; break;
            case -EACCES:	rc = nfserr_acces; break;
            case -ENOMEM:	rc = nfserr_dropit; break;
            default:	rc = nfserr_io; break;
            }
        }
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_create - wrapper for NFSv3 create handler
// calling sequence and return are as for any rpc service callback
// CREATE: after calling underlying create function, send ACCESS event
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_create(struct svc_rqst *qp)
{
	struct nfsd3_createargs *ap = qp->rq_argp;
	struct nfsd3_diropres *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_create(struct svc_rqst *qp,
    struct nfsd3_createargs *ap,
    struct nfsd3_diropres *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd3: CREATE \n");

    if (nfs3_hooked.create)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs3_hooked.create(qp);
#else
	rc = nfs3_hooked.create(qp, ap, rp);
#endif
	if (rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    // if a file got created, send an event for it
	    (void) symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS | SEL_EF_COMPLETION, 1,
		"nfs3_create", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_read() - wrapper for NFSv3 read handler
// calling sequence and return are as for any rpc service callback
// NFS's statelessness demands that we treat each READ as if it were an
// OPEN.  As long as the file cache is enabled this should be OK.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_read(struct svc_rqst *qp)
{
	struct nfsd3_readargs *ap = qp->rq_argp;
	struct nfsd3_readres *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_read(struct svc_rqst *qp,
    struct nfsd3_readargs *ap,
    struct nfsd3_readres *rp)
{
#endif //KERNEL_VERSION(4,13,0)

    int rc = nfserr_dropit;		// in case we have nothing to call
    int ret;

    enter_handler();

    symev_trace(2, "symev_nfsd3: READ \n");

    if (nfs3_hooked.read)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs3_hooked.read(qp);
#else
	rc = nfs3_hooked.read(qp, ap, rp);
#endif

	// NOW process an ACCESS event, while we're holding the
	// results of that read.  (It hasn't been cached yet in the
	// nfsd cache so retries will reenter here...).
	if (rc == 0 && rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    ret = symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS, O_RDONLY,
		"nfs3_read", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif

	    // map the errno (wishing we had access to nfserrno())
	    switch(ret)
	    {
		case 0:		break;	// preserve above return
		case -EPERM:	rc = nfserr_perm; break;
		case -EIO:	rc = nfserr_io; break;
		case -EACCES:	rc = nfserr_acces; break;
		case -ENOMEM:	rc = nfserr_dropit; break;
		default:	rc = nfserr_io; break;
	    }
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_write - wrapper for NFSv3 write handler
// calling sequence and return are as for any rpc service callback
// NFS's statelessness demands that we treat each v3 WRITE as if it
// were a MODIFY, followed (after a timeout) by a DONE unless the
// open or access mode indicate async behavior, in which case a COMMIT
// will be sent later.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_write(struct svc_rqst *qp)
{
	struct nfsd3_writeargs *ap = qp->rq_argp;
	struct nfsd3_writeres *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_write(struct svc_rqst *qp,
    struct nfsd3_writeargs *ap,
    struct nfsd3_writeres *rp)
{
#endif

    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd3: WRITE \n");

    if (nfs3_hooked.write)
    {
	// returns FH for resulting file in rp->fh
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs3_hooked.write(qp);
#else
	rc = nfs3_hooked.write(qp, ap, rp);
#endif

	// NOW process an MODIFY event, while we're holding the
	// results of that read.  (It hasn't been cached yet in the
	// nfsd cache so retries will reenter here...).
	// NB: NFSv3 needs MODIFY_DONE only if resp->committed is TRUE
	if (rc == 0 && rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    (void) symev_dm_event(
		rp->committed ? SEL_EV_MODIFY_DONE : SEL_EV_MODIFY,
		SEL_EF_COMPLETION | SEL_EF_WRITEMODE | SEL_EF_NFS, 0,
		"nfs3_write", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif

	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_remove - wrapper for NFSv3 remove handler
// calling sequence and return are as for any rpc service callback
// ap->fh is the filehandle of the directory to delete from, and
// ap->name/len is the name to delete.  We need to treat this as a
// MODIFY so we don't need a name, but we DO need the file's dentry.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_remove(struct svc_rqst *qp)
{
	struct nfsd3_diropargs *ap = qp->rq_argp;
	struct nfsd3_attrstat *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_remove(struct svc_rqst *qp,
    struct nfsd3_diropargs *ap,
    struct nfsd3_attrstat *rp)
{
#endif 

    int rc = nfserr_dropit;		// in case we have nothing to call
    svc_procfunc lookup_hdl_f = NFS_HFUNC(3, NFS3PROC_LOOKUP);
    kxdrproc_t lookup_rel_f = NFS_RFUNC(3, NFS3PROC_LOOKUP);

    enter_handler();

    symev_trace(2, "symev_nfsd3: REMOVE \n");

    if (nfs3_hooked.remove)
    {

	// we need to send the event before we actually remove
	// the file, so on this one we'll take the extra overhead
	// to decide the args before calling the underlying function

	// we use the nfs3 "lookup" method to resolve the fh+name (in
	// the args) into a FH.  if that FH ends up containing a non-negative
	// dentry, then it's our file to be deleted

	if (lookup_hdl_f)
	{
	    symev_trace(2, "nfsd3_remove: calling lookup_hdl\n");
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		struct nfsd3_diropres* presp;
		if (!(lookup_hdl_f(qp)))
		{
			presp = qp->rq_resp;
			// check the file FH
			if (presp->fh.fh_dentry && presp->fh.fh_dentry->d_inode && presp->fh.fh_export)
			{
				// there's an inode, by golly, so send a pre-unlink event
				(void) symev_dm_event(SEL_EV_MODIFY,
				SEL_EF_LASTLINK | SEL_EF_NFS, 0, "nfs3_remove",
				presp->fh.fh_dentry, 
				presp->fh.fh_export->ex_path.mnt);	
#else
		struct nfsd3_diropres iresp;
	    if (!(lookup_hdl_f(qp, ap, &iresp)))
	    {

			// check the file FH
			if (iresp.fh.fh_dentry && iresp.fh.fh_dentry->d_inode && iresp.fh.fh_export)
			{
				// there's an inode, by golly, so send a pre-unlink event
				(void) symev_dm_event(SEL_EV_MODIFY,
				SEL_EF_LASTLINK | SEL_EF_NFS, 0, "nfs3_remove",
				iresp.fh.fh_dentry, 
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
							iresp.fh.fh_export->ex_mnt);
		#else
							iresp.fh.fh_export->ex_path.mnt);
		#endif //KERNEL_VERSION(2,6,25)
#endif	//KERNEL_VERSION(4,13,0)

		}
		else
		{
		    symev_trace(2, "nfsd3_remove: negative dentry for <%.*s>\n", ap->len, ap->name);
		}
	    }

	    // put back the FHs that lookup allocated
	    if (lookup_rel_f)
	    {
		symev_trace(2, "nfsd3_remove: calling lookup_rel\n");
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		(void) lookup_rel_f(qp);
#else
		(void) lookup_rel_f(qp, NULL, &iresp);
#endif
	    }
	}

	// we're going to call the remove func even if our little
	// folly above failed
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	rc = nfs3_hooked.remove(qp);
#else
	rc = nfs3_hooked.remove(qp, ap, rp);
#endif
    }

    leave_handler();

    return rc;
}

// symev_nfs3_rename_hook() - send RENAME for file whose name is changed
// obtain a FH for a file given its directory FH and filename,
// and submit a RENAME event for that file
// -- this code is common between rename and link
static inline void symev_nfs3_rename_hook(char *dbg,
    struct svc_rqst *qp, svc_fh *fh, char *name, int len)
{
    svc_procfunc lookup_hdl_f = NFS_HFUNC(3, NFS3PROC_LOOKUP);
    kxdrproc_t lookup_rel_f = NFS_RFUNC(3, NFS3PROC_LOOKUP);

    if (lookup_hdl_f)
    {
	
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		struct nfsd3_diropres* presp;
	#else
		struct nfsd3_diropargs iarg;
		struct nfsd3_diropres ires;

		// populate a "lookup" request from the leftover FHs
		iarg.fh = *fh;
		iarg.name = name;
		iarg.len = len;
	#endif

		// do the lookup... if it succeeds, we got a FH
		symev_trace(2, "nfs3_rename_hook/%s: calling lookup_hdl\n", dbg);
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))	
		if (!lookup_hdl_f(qp))
		{
			presp = qp->rq_resp;
			// if the FH is positive, send it a RENAME
			if (presp->fh.fh_dentry && presp->fh.fh_dentry->d_inode && presp->fh.fh_export)
			{
			(void) symev_dm_event(SEL_EV_RENAME,
				SEL_EF_NFS | SEL_EF_COMPLETION, 0,
				dbg, presp->fh.fh_dentry,
				presp->fh.fh_export->ex_path.mnt);	
	#else
		if (!lookup_hdl_f(qp, &iarg, &ires))
		{
			// if the FH is positive, send it a RENAME
			if (ires.fh.fh_dentry && ires.fh.fh_dentry->d_inode && ires.fh.fh_export)
			{
			(void) symev_dm_event(SEL_EV_RENAME,
				SEL_EF_NFS | SEL_EF_COMPLETION, 0,
				dbg, ires.fh.fh_dentry,
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
				ires.fh.fh_export->ex_mnt);
		#else
						ires.fh.fh_export->ex_path.mnt);
		#endif	//KERNEL_VERSION(2,6,25)
	#endif	//KERNEL_VERSION(4,13,0)
			}
			else
			{
			symev_trace(2, "nfs3_rename_hook/%s: negative dentry for <%.*s>\n",
				dbg, len, name);
			}
		}

		// put back the FHs that lookup allocated
		if (lookup_rel_f)
		{
			symev_trace(2, "nfs3_rename_hook/%s: calling lookup_rel\n", dbg);
	#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))	    
			(void) lookup_rel_f(qp);
	#else		
			(void) lookup_rel_f(qp, NULL, &ires);
	#endif
		}
    }
}

// symev_nfsd3_proc_rename - wrapper for NFSv3 rename handler
// calling sequence and return are as for any rpc service callback
// ap->ffh is the filehandle of the directory to rename from,
// ap->fname/flen is the name to rename, and ->tfh/tname/tlen are the
// directory and name to rename to.  We need to do a RENAME event on
// the tname.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_rename(struct svc_rqst *qp)
{
	struct nfsd3_renameargs *ap = qp->rq_argp;
	struct nfsd3_renameres *rp = qp->rq_resp;
	UNUSED(rp);
#else
int symev_nfsd3_proc_rename(struct svc_rqst *qp,
    struct nfsd3_renameargs *ap,
    struct nfsd3_renameres *rp)
{
#endif

    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd3: RENAME \n");

    if (nfs3_hooked.rename)
    {
	// do the underlying rename
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	if (!(rc = nfs3_hooked.rename(qp)))
#else
	if (!(rc = nfs3_hooked.rename(qp, ap, rp)))
#endif
	{
	    // send a RENAME event if possible
	    symev_nfs3_rename_hook("nfs3_rename", qp,
		&ap->tfh, ap->tname, ap->tlen);
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_link - wrapper for NFSv3 link handler
// calling sequence and return are as for any rpc service callback
// ap->ffh is the filehandle of the file to link from, and
// ->tfh/tname/tlen are the directory and name to link to.  We need
// to do a RENAME event on the tname so this is similar to rename
// above.
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_link(struct svc_rqst *qp)
{
	struct nfsd3_linkargs *ap = qp->rq_argp;
	struct nfsd3_linkres  *rp = qp->rq_resp;
	UNUSED(rp);
#else
int symev_nfsd3_proc_link(struct svc_rqst *qp,
    struct nfsd3_linkargs *ap,
    struct nfsd3_linkres *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd3: LINK \n");

    if (nfs3_hooked.link)
    {
	// do the link
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
	if (!(rc = nfs3_hooked.link(qp)))
#else
	if (!(rc = nfs3_hooked.link(qp, ap, rp)))
#endif
	{
	    // it succeeded... send a RENAME event if possible
	    symev_nfs3_rename_hook("nfs3_link",
		qp, &ap->tfh, ap->tname, ap->tlen);
	}
    }

    leave_handler();

    return rc;
}

// symev_nfsd3_proc_commit - wrapper for NFSv3 commit handler
// calling sequence and return are as for any rpc service callback
// rp->fh is the filehandle of the file just committed.  We treat this
// as a DONE event (assuming MODIFYs have been done at each write).
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
int symev_nfsd3_proc_commit(struct svc_rqst *qp)
{
	struct nfsd3_commitargs *ap = qp->rq_argp;
	struct nfsd3_commitres *rp = qp->rq_resp;
	UNUSED(ap);
#else
int symev_nfsd3_proc_commit(struct svc_rqst *qp,
    struct nfsd3_commitargs *ap,
    struct nfsd3_commitres *rp)
{
#endif
    int rc = nfserr_dropit;		// in case we have nothing to call

    enter_handler();

    symev_trace(2, "symev_nfsd3: COMMIT \n");

    if (nfs3_hooked.commit)
    {
#if(LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0))
		rc = nfs3_hooked.commit(qp);
#else
	rc = nfs3_hooked.commit(qp, ap, rp);
#endif
	if (rp->fh.fh_dentry && rp->fh.fh_export)
	{
	    (void) symev_dm_event(SEL_EV_DONE,
		SEL_EF_COMPLETION | SEL_EF_WRITEMODE | SEL_EF_NFS, 0,
		"nfs3_commit", rp->fh.fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                rp->fh.fh_export->ex_mnt);
#else
                rp->fh.fh_export->ex_path.mnt);
#endif
	}
    }

    leave_handler();

    return rc;
}


// hook_nfs3 -- install hooks into the NFSv3 server based on the global
// pointer to the server's structure in symev_nfsd_v3
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
hook_nfs3(void)
{
    if (!symev_nfsd_v3->vs_proc)
	return -1;

    HOOK_NFSCB(3, NFS3PROC_CREATE, create, symev_nfsd3_proc_create);
    HOOK_NFSCB(3, NFS3PROC_ACCESS, access, symev_nfsd3_proc_access);
    HOOK_NFSCB(3, NFS3PROC_READ, read, symev_nfsd3_proc_read);
    HOOK_NFSCB(3, NFS3PROC_WRITE, write, symev_nfsd3_proc_write);
    HOOK_NFSCB(3, NFS3PROC_REMOVE, remove, symev_nfsd3_proc_remove);
    HOOK_NFSCB(3, NFS3PROC_RENAME, rename, symev_nfsd3_proc_rename);
    HOOK_NFSCB(3, NFS3PROC_LINK, link, symev_nfsd3_proc_link);
    HOOK_NFSCB(3, NFS3PROC_COMMIT, commit, symev_nfsd3_proc_commit);

    return 0;
}

// unhook_nfs3 -- remove hooks from the NFSv3 server based on the global
// pointer to the server's structure in symev_nfsd_v3
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
unhook_nfs3(void)
{
    if (!symev_nfsd_v3->vs_proc)
	return -1;

    UNHOOK_NFSCB(3, NFS3PROC_CREATE, create, symev_nfsd3_proc_create);
    UNHOOK_NFSCB(3, NFS3PROC_ACCESS, access, symev_nfsd3_proc_access);
    UNHOOK_NFSCB(3, NFS3PROC_READ, read, symev_nfsd3_proc_read);
    UNHOOK_NFSCB(3, NFS3PROC_WRITE, write, symev_nfsd3_proc_write);
    UNHOOK_NFSCB(3, NFS3PROC_REMOVE, remove, symev_nfsd3_proc_remove);
    UNHOOK_NFSCB(3, NFS3PROC_RENAME, rename, symev_nfsd3_proc_rename);
    UNHOOK_NFSCB(3, NFS3PROC_LINK, link, symev_nfsd3_proc_link);
    UNHOOK_NFSCB(3, NFS3PROC_COMMIT, commit, symev_nfsd3_proc_commit);

    return 0;
}

// release_nfs3 -- forget the hooks into the NFSv2 server and the global
// pointer to the server's structure in symev_nfsd_v3
// returns 0 on success (which is currenty assured)
// -- this will be called with wrlock held
static int
release_nfs3(void)
{
    // wipe out the hook addresses
    memset((char *)&nfs3_hooked, 0, sizeof(nfs3_hooked));

    return 0;
}

#if defined(CONFIG_NFSD_V4)
extern unsigned long (*symev_module_kallsyms_lookup_name) (const char *name);
extern unsigned long (*symev_kallsyms_lookup_name) (const char *name);

void (*symev_fh_put) (struct svc_fh *fhp) = 0;
u32  (*symev_fh_verify) (struct svc_rqst *rqstp, struct svc_fh *fhp, int type, int access) = 0;

static inline int
symev_nfsd4_putfh(struct svc_rqst *rqstp, struct svc_fh *current_fh, struct nfsd4_putfh *putfh)
{
    current_fh->fh_handle.fh_size = putfh->pf_fhlen;
    memcpy(&current_fh->fh_handle.fh_base, putfh->pf_fhval, putfh->pf_fhlen);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27)
    return (*symev_fh_verify)(rqstp, current_fh, 0, MAY_NOP);
#else
    return (*symev_fh_verify)(rqstp, current_fh, 0, NFSD_MAY_NOP);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
static int
symev_nfsd4_proc_compound(struct svc_rqst *rqstp)
{
	struct nfsd4_compoundargs *args = rqstp->rq_argp;
	struct nfsd4_compoundres *resp = rqstp->rq_resp;
	UNUSED(resp);
#else
static int
symev_nfsd4_proc_compound(struct svc_rqst *rqstp,
    struct nfsd4_compoundargs *args,
    struct nfsd4_compoundres *resp)
{
#endif
    struct nfsd4_op *op = NULL;
    u32 opcnt = 0;
    struct svc_fh *current_fh = NULL;
    int status = 0;
    int predo = 0;
    int opnum = -1;
    int opoffset = -1;
    int putfh = -1;
    int rs;
    struct dentry *dentry = NULL, *rdentry = NULL;

    enter_handler();

    symev_trace(2, "symev_nfsd4: COMPOUND \n");

    if (!nfs4_hooked.compound) {
        leave_handler();
        return nfserr_dropit; 
    }
    
    while (opcnt < args->opcnt) {
        op = &args->ops[opcnt++];
        if (op != NULL) {
            
            switch (op->opnum) {
            case OP_PUTFH:
                putfh = opcnt - 1;
                break;
            case OP_OPEN_CONFIRM:
                opnum = OP_OPEN_CONFIRM;
                opoffset = opcnt - 1;
                break;
            case OP_ACCESS:
                opnum = OP_ACCESS;
                opoffset = opcnt - 1;
                break;
            case OP_READ:
                opnum = OP_READ;
                opoffset = opcnt - 1;
                predo = 1;
                break;
            case OP_WRITE:
                opnum = OP_WRITE;
                opoffset = opcnt - 1;
                break;
            case OP_COMMIT:
                opnum = OP_COMMIT;
                opoffset = opcnt - 1;
                break;
            case OP_RENAME:
                opnum = OP_RENAME;
                opoffset = opcnt - 1;
                break;
            case OP_REMOVE:
                opnum = OP_REMOVE;
                opoffset = opcnt - 1;
                predo = 1;
                break;
            case OP_LINK:
                opnum = OP_LINK;
                opoffset = opcnt - 1;
                break;
            default:
                ;
            }
        }
    }

    if (opnum >= 0) {
        current_fh = kmalloc(sizeof(*current_fh), GFP_KERNEL);
        if (current_fh != NULL)
            fh_init(current_fh, NFS4_FHSIZE);
    }

    if ((opnum >= 0) && predo) { 
        if (putfh >= 0 && current_fh) {

            op = &args->ops[putfh];
            rs = symev_nfsd4_putfh(rqstp, current_fh, &op->u.putfh);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
            if (!rs && current_fh->fh_dentry && current_fh->fh_export && current_fh->fh_export->ex_mnt) {
#else
            if (!rs && current_fh->fh_dentry && current_fh->fh_export && current_fh->fh_export->ex_path.mnt) {
#endif
 
                switch (opnum) {
                case OP_READ:
                    rs = symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS, O_RDONLY, "nfs4_read",
                                        current_fh->fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                        current_fh->fh_export->ex_mnt);
#else
                                        current_fh->fh_export->ex_path.mnt);
#endif
                    // map the errno (wishing we had access to nfserrno())
                    switch(rs)
                    {
                    case 0:         break;  // preserve above return
                    case -EPERM:    status = nfserr_perm; break;
                    case -EIO:      status = nfserr_io; break;
                    case -EACCES:   status = nfserr_acces; break;
                    case -ENOMEM:   status = nfserr_dropit; break;
                    default:        status = nfserr_io; break;
                    }
                    if (status) {
                        op = &args->ops[opoffset];
                        op->status = status;
                    }
                    break;
                case OP_REMOVE:
                    dentry = current_fh->fh_dentry;
                    op = &args->ops[opoffset];
                    /* Etrack 4124061: Distro agnostic way of locking the parent dentry before calling into lookup_one_len()
                     * Unlock will occur as part of calling fh_put() by way of *symev_fh_put().  This lock has to be obtained 
                     * only when needed because:
                     * -If the scan target isn't a child dentry, holding the lock while calling symev_dm_event will lead to
                     *    a deadlock in rtvscand
                     * -lock cannot be held on any of the involved dentry by the time we call native function
                     * -we want to avoid calling fh_put() against the same svc_fh twice.
                    */ 
                    fh_lock(current_fh);
                    rdentry = lookup_one_len(op->u.remove.rm_name, dentry, op->u.remove.rm_namelen);
                    if (IS_ERR(rdentry)) {
                        symev_trace(2, "nfsd4_remove: negative dentry for <%.*s>\n", op->u.remove.rm_namelen, op->u.remove.rm_name);
                    } else {
                        // there's an inode, by golly, so send a pre-unlink event
                        (void) symev_dm_event(SEL_EV_MODIFY, SEL_EF_LASTLINK | SEL_EF_NFS, 0, "nfs4_remove",
                                              rdentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                              current_fh->fh_export->ex_mnt);
#else
                                              current_fh->fh_export->ex_path.mnt);
#endif
                    }
                   break;
                default:
                   ;
                }
            }
        }
        // Etrack 4124061: call *symev_fh_put() here.  If we are in this block, all of our work on
        // current_fh is done by this time, and we need to unlock the dentry before calling native
        // function.  Same fh_lock/fh_put idea is applied to post-op scanning as well. 
        (*symev_fh_put)(current_fh);
    }

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
	status = nfs4_hooked.compound(rqstp);
#else
    status = nfs4_hooked.compound(rqstp, args, resp);
#endif

    if ((opnum >= 0) && !predo && !args->ops[opoffset].status) {
        if (putfh >= 0 && current_fh) {

            op = &args->ops[putfh];
            rs = symev_nfsd4_putfh(rqstp, current_fh, &op->u.putfh);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
            if (!rs && current_fh->fh_dentry && current_fh->fh_export && current_fh->fh_export->ex_mnt) {
#else
            if (!rs && current_fh->fh_dentry && current_fh->fh_export && current_fh->fh_export->ex_path.mnt) {
#endif

                switch (opnum) {
                case OP_ACCESS:
                    rs = symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS, O_RDONLY, "nfs4_access",
                                          current_fh->fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif

                    // map the errno (wishing we had access to nfserrno())
                    switch(rs)
                    {
                    case 0:         break;  // preserve above return
                    case -EPERM:    status = nfserr_perm; break;
                    case -EIO:      status = nfserr_io; break;
                    case -EACCES:   status = nfserr_acces; break;
                    case -ENOMEM:   status = nfserr_dropit; break;
                    default:        status = nfserr_io; break;
                    }
                    if (status) {
                        op = &args->ops[opoffset];
                        op->status = status;
                    }

                    break;
                case OP_OPEN_CONFIRM:
                    (void) symev_dm_event(SEL_EV_ACCESS, SEL_EF_NFS | SEL_EF_COMPLETION, 1, "nfs4_create", 
                                          current_fh->fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif
                    break;
                case OP_WRITE:
                    // First write should be scanned synchronously, this bring the user a quick response.
                    // the following write(s) should be scanned asynchronously.
                    (void) symev_dm_event(args->ops[opoffset].u.write.wr_offset <= 4096 ? SEL_EV_DONE : SEL_EV_MODIFY_DONE,
                                          SEL_EF_COMPLETION | SEL_EF_WRITEMODE | SEL_EF_NFS, 0, "nfs4_write", 
                                          current_fh->fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif
                    break;
                case OP_COMMIT:
                    (void) symev_dm_event(SEL_EV_DONE, SEL_EF_COMPLETION | SEL_EF_WRITEMODE | SEL_EF_NFS, 0, "nfs4_commit", 
                                          current_fh->fh_dentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif
                    break;
                default:
                    ;
                }
            }

            dentry = current_fh->fh_dentry;

            if (opnum == OP_RENAME) {
                op = &args->ops[opoffset];
                fh_lock(current_fh);
                rdentry = lookup_one_len(op->u.rename.rn_tname, dentry, op->u.rename.rn_tnamelen);
                if (IS_ERR(rdentry)) {
                    symev_trace(2, "nfs4_rename: negative dentry for <%.*s>\n", op->u.rename.rn_tnamelen, op->u.rename.rn_tname);
                } else {
                    (void) symev_dm_event(SEL_EV_RENAME, SEL_EF_NFS | SEL_EF_COMPLETION, 0, "nfs4_rename", 
                                          rdentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif
                }
            }

            if (opnum == OP_LINK) {
                op = &args->ops[opoffset];
                fh_lock(current_fh);
                rdentry = lookup_one_len(op->u.link.li_name, dentry, op->u.link.li_namelen);
                if (IS_ERR(rdentry)) {
                    symev_trace(2, "nfs4_link: negative dentry for <%.*s>\n", op->u.link.li_namelen, op->u.link.li_name);
                } else {
                    (void) symev_dm_event(SEL_EV_RENAME, SEL_EF_NFS | SEL_EF_COMPLETION, 0, "nfs4_link",
                                          rdentry, 
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
                                          current_fh->fh_export->ex_mnt);
#else
                                          current_fh->fh_export->ex_path.mnt);
#endif
                }
            }
        }
        (*symev_fh_put)(current_fh);
    }

    if (rdentry) 
        dput(rdentry);
    if (current_fh) 
        kfree(current_fh);

    leave_handler();
    return status;
}

// hook_nfs4 -- install hooks into the NFSv4 server based on the global
// pointer to the server's structure in symev_nfsd_v4
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
hook_nfs4( enum nfs_hook_mode_e nfs_hook_mode )
{
    if (!symev_nfsd_v4->vs_proc)
        return -1;

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,32)

    (void) nfs_hook_mode;

    if (!symev_kallsyms_lookup_name)
       return -1;

    if (!(symev_fh_put    = (void*)(*symev_kallsyms_lookup_name)("fh_put")))
        return -1;
    if (!(symev_fh_verify = (void*)(*symev_kallsyms_lookup_name)("fh_verify")))
        return -1;
	symev_trace(1, "hook_nfsd4: after checking fh_put n fh_verify in symev_kallsyms_lookup_name \n");
#else

    if (!symev_module_kallsyms_lookup_name)
       return -1;

    if (nfs_hook_mode == eTIMERTOHOOK )
    {
        if (!(symev_fh_put = (void*) (*symev_module_kallsyms_lookup_name) ("nfsd:fh_put")))
            return -1;
        if (!(symev_fh_verify = (void*) (*symev_module_kallsyms_lookup_name) ("nfsd:fh_verify")))
            return -1;
    }
    else
    {
        if (!(symev_fh_put = (void*) symbol_in_kallsyms("fh_put","nfsd")))
            return -1;
        if (!(symev_fh_verify = (void*) symbol_in_kallsyms("fh_verify","nfsd")))
            return -1;
    }

#endif
	symev_trace(1, "hook_nfsd4: before calling HOOK_NFSCB for COMPOUND \n");
    HOOK_NFSCB(4, NFSPROC4_COMPOUND, compound, symev_nfsd4_proc_compound);
	symev_trace(1, "hook_nfsd4: after calling HOOK_NFSCB for COMPOUND \n");
    return 0;
}

// unhook_nfs4 -- remove hooks from the NFSv4 server based on the global
// pointer to the server's structure in symev_nfsd_v4
// returns 0 on success, -1 if svc_version is NULL (which shouldn't happen).
static int
unhook_nfs4(void)
{
    if (!symev_nfsd_v4->vs_proc)
        return -1;

    UNHOOK_NFSCB(4, NFSPROC4_COMPOUND, compound, symev_nfsd4_proc_compound);

    return 0;
}

// release_nfs4 -- forget the hooks into the NFSv2 server and the global
// pointer to the server's structure in symev_nfsd_v4
// returns 0 on success (which is currenty assured)
// -- this will be called with wrlock held
static int
release_nfs4(void)
{
    // wipe out the hook addresses
    memset((char *)&nfs4_hooked, 0, sizeof(nfs4_hooked));

    return 0;
}
#endif // defined(CONFIG_NFSD_V4)


// check_nfs() - return status whether NFS is hooked or not
static int
check_nfs(void)
{
    if (   (symev_nfsd_v2 &&
	    ISHOOK_NFSCB(2, NFSPROC_CREATE, create, symev_nfsd2_proc_create))
	|| (symev_nfsd_v3 &&
	    ISHOOK_NFSCB(3, NFS3PROC_CREATE, create, symev_nfsd3_proc_create))
#if defined(CONFIG_NFSD_V4)
        || (symev_nfsd_v4 && 
            ISHOOK_NFSCB(4, NFSPROC4_COMPOUND, compound, symev_nfsd4_proc_compound))
#endif
      )
    {
	// yes, still hooked!
	return 1;
    }

    return 0;
}

// === status of NFS hooks ===

// symev_nfs_devread() - read out status of NFS hooks
void
symev_hnfs_devread(char *buf, int *plen, int mlen)
{
    // read out the current status of the NFS hooks
    int ret;
    char *bp = buf + *plen;
    int left = mlen - *plen;

    ret = snprintf(bp, left, "=== NFS ===\n"
        "symev_nfsd_v2 = %p\n"
        "symev_nfsd_v3 = %p\n"
#if defined(CONFIG_NFSD_V4)
        "symev_nfsd_v4 = %p\n"
#endif
        ,
        symev_nfsd_v2,
        symev_nfsd_v3
#if defined(CONFIG_NFSD_V4)
        ,
        symev_nfsd_v4
#endif
        );
    if (ret > 0) { bp += ret; left -= ret; }

    // adjust pointer for caller
    if (left > 0)
        *plen = mlen - left;    // room left
    else
        *plen = mlen;   // full

    return ;
}
