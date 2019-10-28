/*                                                     
 * symevrm - Kernel remove module tool
 * Copyright (C) 2005 Symantec Corporation.
 * This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
 * See the "COPYING" file distributed with this software for more info.
 */

#include <linux/version.h>                                                  
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/kobject.h>
#include <linux/jiffies.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,8,0)
#include <linux/sched.h>
#endif

MODULE_LICENSE("GPL");

// make an alias for easier load/unload (2.6 and newer)
#ifdef MODULE_ALIAS
MODULE_ALIAS("symevrm");
#endif

#include <symevl.h>
#include <symtypes.h>
#include "symkutil.h"
#include "symprocfs.h"

#include "symev.h"

int symev_trace_level = 0;

extern unsigned long symbol_in_kallsyms(const char* sym, const char* mod);

//define prefix for symap.
static const char *PREFIX_SYMAP = "symap";

//define prefix for symev.
static const char *PREFIX_SYMEV = "symev";


// find the old symap and symev if they exist and unload them.
// if reference count of symap is non-zero, don't unload symap and symev, and symev_init will fail.
// if reference count of symap is zero, we will unload symap and decreate the reference count of
// symev to zero then unload symev.
// @prefix: the name of "symev" or "symap" which doesn't contain the version information.
// @return: the pointer to the module we found, otherwise, return NULL.

static struct module * symevrm_find_module(const char *prefix)
{
	struct module *mod = NULL;

	if(!prefix || !prefix[0])
	{
		printk(KERN_ERR "symevrm: find_module, input empty name.\n");
		return mod;
	}

	do
	{
		list_for_each_entry(mod, &(THIS_MODULE->list), list)
		{
			if(!mod->name || !mod->name[0])
				continue;

			symev_trace(1, "symevrm: find mod: %s\n", mod->name);

			if(strlen(mod->name) < strlen(prefix))
				continue;

			if(strncmp(mod->name, prefix, strlen(prefix)) == 0)
			{
				//skip itself currently loaded..
				if(strcmp(mod->name, THIS_MODULE->name) == 0)
					continue;
				return mod;
			}
		}

	}while(0);

	return NULL;
}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32))
typedef struct _SYMEV_MODULE_FIND
{
	struct module **mod;
	const char *prefix;
}SYMEV_MODULE_FIND;

static int symevrm_try_find_module(void *param)
{
	SYMEV_MODULE_FIND *find = (SYMEV_MODULE_FIND *)param;
	if(!find)
		return -EINVAL;

	*(find->mod) = NULL;
	*(find->mod) = symevrm_find_module(find->prefix);
	if(*(find->mod))
	{
		return 0;
	}

	return -ENOENT;
}
typedef  int (*_pfn_stop_machine_run)(int (*fn)(void *), void *data, unsigned int cpu);
#endif

static struct module *symevrm_get_module(const char *prefix)
{
	struct module *mod = NULL;
#if( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) )
	SYMEV_MODULE_FIND find = {.mod=&mod, .prefix=prefix};
	_pfn_stop_machine_run stop_machine_run = (_pfn_stop_machine_run)symbol_in_kallsyms("stop_machine_run", NULL);
	if(!stop_machine_run)
	{
		symev_trace(0, "symev_get_module: cannot get stop_machine_run\n");
		return NULL;
	}

	if(0 != stop_machine_run(symevrm_try_find_module, (void *)&find, NR_CPUS))
		return NULL;
#else
	if(mutex_lock_interruptible(&module_mutex) != 0)
	{
		printk(KERN_ERR "symevrm: find_module, cannot get module lock.\n");
		return NULL;
	}

	mod = symevrm_find_module(prefix);

	mutex_unlock(&module_mutex);
#endif
	return mod;
}


#ifdef CONFIG_GENERIC_BUG
static void sym_module_bug_cleanup(struct module *mod)
{
    list_del(&mod->bug_list);
}

#else	/* !CONFIG_GENERIC_BUG */

static void sym_module_bug_cleanup(struct module *mod) {}
#endif	/* CONFIG_GENERIC_BUG */


/*
 * unlink the module with the whole machine is stopped with interrupts off
 * - this defends against kallsyms not taking locks
 */
static int sym_unlink_module(void *_mod)
{
    struct module *mod = _mod;

    /* Unlink carefully: kallsyms could be walking list. */
    list_del_rcu(&mod->list);
    /* Remove this module from bug list, this uses list_del_rcu */
    sym_module_bug_cleanup(mod);
    /* Wait for RCU synchronizing before releasing mod->list and buglist. */
    synchronize_rcu();

	return 0;
}

static int symevrm_unlink_module(struct module *mod)
{
	typedef int (*_pfn_unlink_module)(void *mod);
	_pfn_unlink_module unlink = (_pfn_unlink_module)symbol_in_kallsyms("__unlink_module", NULL);

#if( LINUX_VERSION_CODE < KERNEL_VERSION(2,6,32) )
	if(!unlink)
	{
		symev_trace(0, "symevrm: cannot get unlink func.\n");
		return -EINVAL;
	}

	_pfn_stop_machine_run stop_machine_run = (_pfn_stop_machine_run)symbol_in_kallsyms("stop_machine_run", NULL);
	if(!stop_machine_run)
	{
		symev_trace(0, "symevrm_unlink_module: cannot get stop_machine_run\n");
		return -EINVAL;
	}

	if(0 != stop_machine_run(unlink, (void *)mod, NR_CPUS))
	{
		symev_trace(0, "symevrm_unlink_module: cannot unlink module: %s\n", mod->name);
		return -EINVAL;
	}

	symev_trace(0, "symevrm_unlink_module: unlink module %s successfully\n", mod->name);
#else
	if(mutex_lock_interruptible(&module_mutex) != 0)
	{
		symev_trace(0, "symevrm_unlink_module: cannot get module lock.\n");
		return -EINVAL;
	}

    if(unlink)
    {
	    unlink(mod);
    }
    else
    {
        sym_unlink_module(mod);
    }

	mutex_unlock(&module_mutex);

	symev_trace(0, "symevrm_unlink_module: unlink module %s successfully.\n", mod->name);

#endif

	return 0;
}

static int symevrm_is_module_used(struct module *mod)
{
	int ret = 0;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
	ret = list_empty(&mod->modules_which_use_me);
#else
	ret = list_empty(&mod->source_list);
#endif

	return !ret;
}

static void symevrm_mark_module_del(struct module *mod)
{
	int name_len = 0;
	int suffix_len = 0;
	char suffix[MODULE_NAME_LEN] = {0};

	sprintf(suffix, "_del_%llu", (unsigned long long)jiffies);

	name_len = strlen(mod->name);
	suffix_len = strlen(suffix);
	if((name_len + suffix_len) < sizeof(mod->name))
	{
		strcat(mod->name, suffix);
	}
	else //set module name to suffix.
	{
		strcpy(mod->name, suffix);
	}
}

static int symevrm_disable_module(struct module* mod)
{
	int ret = 0;
	
	if(!mod)
	{
		ret = -ENOENT;
		printk(KERN_ALERT "symevrm: module_unload: input null\n");
		return ret;
	}

	if(symevrm_is_module_used(mod))
	{
		ret = -EWOULDBLOCK;
		symev_trace(0, "symevrm: module(%s) has still been used by others.\n", mod->name);
		return ret;
	}
	
	symevrm_unlink_module(mod);

	//call exit
	if(mod->exit)
	{
		mod->exit();
		symev_trace(0, "symevrm: call exit of module: %s\n", mod->name);
	}

	//rename module name.
	symevrm_mark_module_del(mod);

	symev_trace(0, "symevrm: change module name to %s\n", mod->name);

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,27))
	typedef int (*_pfn_kobject_rename)(struct kobject *kobj, const char *new_name);
	_pfn_kobject_rename kobject_rename = (_pfn_kobject_rename)symbol_in_kallsyms("kobject_rename", NULL);
	if(!kobject_rename)
	{
		symev_trace(0, "symevrm: cannot find kobject_rename.\n");
		return -EINVAL;
	}

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11))
	ret = kobject_rename(&mod->mkobj->kobj, mod->name);
#else
	ret = kobject_rename(&mod->mkobj.kobj, mod->name);
#endif

#else
	ret = kobject_rename(&mod->mkobj.kobj, mod->name);
#endif
	if(ret)
	{
		symev_trace(0, "symevrm: failed to change sysfs name %s\n", mod->name);
		return ret;
	}
	
	symev_trace(0, "symevrm: succeeded to change sysfs name.\n");
	
	
	return 0;

}


static int symevrm_unload_module(struct module* mod)
{
	int ret = 0;
	int ref = 0; //reference count of the module.
	int i = 0; //loop index.
	typedef asmlinkage long (*_pfn_delete_module)(const char __user *name_user, unsigned int flags);
	_pfn_delete_module sys_delete_module = NULL;
	
	if(!mod)
	{
		ret = -ENOENT;
		printk(KERN_ALERT "symevrm: module_unload: input null\n");
		return ret;
	}

	ref = module_refcount(mod);
	symev_trace(0, "symevrm: got %s, reference count: %d\n", mod->name, ref);

	for(; i<ref; i++)
	{
		module_put(mod);
	}

	ref = module_refcount(mod);

	if(ref > 0)
	{
		ret = -EWOULDBLOCK;
		symev_trace(0, "symevrm: module(%s) with reference count: %d, cannot remove it.\n", 
				mod->name, ref);
		return ret;
	}

	sys_delete_module = (_pfn_delete_module)symbol_in_kallsyms("sys_delete_module", NULL);
	if(sys_delete_module)
	{
		mm_segment_t fs;
		fs = get_fs();
		set_fs(KERNEL_DS);
		symev_trace(0, "symevrm: begin to remove %s\n", mod->name);
		ret = sys_delete_module(mod->name, O_NONBLOCK|O_TRUNC);
		set_fs(fs);
		if(0 == ret)
		{
			symev_trace(0, "symevrm: Succeeded to free the specified module\n");
		}
		else
		{
			symev_trace(0, "symevrm: failed to remove the specified module, err: %d\n", ret);
		}

		return ret;
	}

	symev_trace(0, "symevrm: cannot get the syscall to free module\n");

	return -EFAULT;
}

// check & remove old symev & symap.
static int try_remove_old_modules(void)
{
	int ret = 0;
	int ref = 0;
	struct module *symap = NULL;
	struct module *symev = NULL;

	symap = symevrm_get_module(PREFIX_SYMAP);
	if(symap)
	{
		symev_trace(0, "symevrm: find old %s\n", symap->name);
		do
		{

			//check reference count.
			ref = module_refcount(symap);
			if(ref > 0)
			{
				symev_trace(0, "symevrm: the reference of %s is: %d\n", symap->name, ref);
				return -EWOULDBLOCK;
			}

			//remove the module by using sys_delete_module.
			ret = symevrm_unload_module(symap);
			if(ret)
			{
				symev_trace(0, "symevrm: cannot free old symap\n");
				return ret;
			}
		}while(0);
	}
	else
	{
		symev_trace(0, "symevrm: cannot find old symap\n");
	}

	symev = symevrm_get_module(PREFIX_SYMEV);
	if(!symev)
	{
		symev_trace(0, "cannot find old symev\n");
		return 0;
	}

	symev_trace(0, "symevrm: find old %s\n", symev->name);

	ret = symevrm_disable_module(symev);
	if(ret)
	{
		symev_trace(0, "symevrm: failed to remove old symev\n");
	}
	else
	{
		symev_trace(0, "symevrm: succeeded to remove old symev\n");
	}

	return ret;
}

//define module_use
struct symevrm_module_use
{
		struct list_head list;
		struct module *module_which_uses;
};

int symevrm_read_proc(char *page, int *offp, int count)
{
	int len = 0;
	struct module *symap = NULL;
	struct module *symev = NULL;
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
	struct symevrm_module_use *dependent = NULL;
#else
	struct module_use *dependent = NULL;
#endif
	int ref = 0;

	len = snprintf(page, count, "======symap======\n");

	symap = symevrm_get_module("symap");
	if(!symap)
	{
		len += snprintf(page+strlen(page), count-strlen(page), "status: Not loaded.\n");
	}
	else
	{
		len += snprintf(page+strlen(page), count-strlen(page), "status: Loaded(%s).\n", symap->name);
		ref = module_refcount(symap);
		len += snprintf(page+strlen(page), count - strlen(page), "refence: %d\n", ref);

#ifdef CONFIG_MODULE_UNLOAD
		len += snprintf(page + strlen(page), count - strlen(page), "dependent: ");

#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
		list_for_each_entry(dependent, &symap->modules_which_use_me, list)
		{
			if(!dependent->module_which_uses->name || !dependent->module_which_uses->name[0])
				continue;
			len += snprintf(page + strlen(page), count - strlen(page), "%s ", dependent->module_which_uses->name);
		}
#else
		list_for_each_entry(dependent, &symap->source_list, source_list)
		{
			if(!dependent->source->name || !dependent->source->name[0])
				continue;
			len += snprintf(page + strlen(page), count - strlen(page), "%s ", dependent->source->name);
		}
#endif

		len += snprintf(page + strlen(page), count - strlen(page), "\n");
#endif
	}

	symev = symevrm_get_module("symev");
	len += snprintf(page + strlen(page), count - strlen(page), "======symev======\n");
	if(!symev)
	{
		len += snprintf(page + strlen(page), count - strlen(page), "status: Not loaded.\n");
	}
	else
	{
		len += snprintf(page + strlen(page), count - strlen(page), "status: Loaded(%s).\n", symev->name);
		ref = module_refcount(symev);
		len += snprintf(page + strlen(page), count - strlen(page), "reference: %d\n", ref);

#ifdef CONFIG_MODULE_UNLOAD
		len += snprintf(page + strlen(page), count - strlen(page), "dependent: ");
#if(LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35))
		list_for_each_entry(dependent, &symev->modules_which_use_me, list)
		{
			if(!dependent->module_which_uses->name || !dependent->module_which_uses->name[0])
				continue;
			len += snprintf(page + strlen(page), count - strlen(page), "%s ", dependent->module_which_uses->name);
		}
#else
		list_for_each_entry(dependent, &symev->source_list, source_list)
		{
			if(!dependent->source->name || !dependent->source->name[0])
				continue;
			len += snprintf(page + strlen(page), count - strlen(page), "%s ", dependent->source->name);
		}
#endif

		len += snprintf(page + strlen(page), count - strlen(page), "\n");
#endif
	}

	return len;
}

static struct sym_procfs_info *symevrm_proc_entry = NULL;

static int symevrm_init(void)
{
	printk(KERN_ALERT "=====>loaded %s<=====\n", THIS_MODULE->name);

	//try to remove symap & symev.
	try_remove_old_modules();

	//create proc entry.
	if (!(symevrm_proc_entry = sym_procfs_new("symevrm", symevrm_read_proc,NULL)))
	{
	    symev_trace(0, "cannot create proc entry for symevrm.\n");
	}
	
	return 0;
}

static void symevrm_exit(void)
{
	if (symevrm_proc_entry)
	{
	    sym_procfs_delete("symevrm", symevrm_proc_entry);
	    symevrm_proc_entry = NULL;
	}
	printk(KERN_ALERT "=====>freed %s<=====\n", THIS_MODULE->name);
}

module_init(symevrm_init);
module_exit(symevrm_exit);
