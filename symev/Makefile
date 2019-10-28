# Makefile for symev

# DEBUG flag is generally passed in the environment by the build script
ifdef DEBUG
  DBG_FLAG=-DDEBUG
  BINDIR=${OUTPUTDIR}/bin.ida
  LIBDIR=${OUTPUTDIR}/lib.ida
  DASHG=-g
else
  BINDIR=${OUTPUTDIR}/bin.ira
  LIBDIR=${OUTPUTDIR}/lib.ira
  SYMDIR=${OUTPUTDIR}/sym.ira
  DASHG=
endif

# non-i386 platform (e.g. x86_64) postfix
NON_I386=
# define arch flag (e.g. __x86_64__) macro
ARCH_FLAG=
# define private GCC options
GCC_OPTIONS=
# x86_64 utils
LD_X64=ld-2.16.1-x86_64

MOD=symev

MOD_RM=symevrm

MOD_OFILES = symev.o syscalls.o fileops.o hnfs.o utils.o sym_procfs.o sym_stub_execve.o

MOD_BUILD_SUFFIX = $(subst .,_,$(subst -,_,$(BUILDSUFFIX)))

MOD_NAME = $(MOD)_$(MOD_BUILD_SUFFIX)

MOD_RM_NAME = $(MOD_RM)_$(MOD_BUILD_SUFFIX)

MOD_RM_OFILES = symevrm.o syscalls.o sym_procfs.o

# Support the 2.6 kernel builds which are recursive.  This Makefile
# is included by the kernel module make, in which case it supplies
# a few variable settings that will affect the module build.
ifneq ($(KBUILD_MODULES),)
# Set the variables used by the 2.6 module build
obj-m := $(MOD_NAME).o $(MOD_RM_NAME).o
$(MOD_NAME)-objs := $(MOD_OFILES)
$(MOD_RM_NAME)-objs := $(MOD_RM_OFILES)
ifdef USE_EXTRAFLAGS
EXTRA_CFLAGS += -I$(MOD_TOPDIR)/../include $(DBG_FLAG)
ifdef KERNEL_HEADER_VERSION
EXTRA_CFLAGS +=  -I$(MOD_TOPDIR)/../kernelsource/linux$(KERNEL_HEADER_VERSION)/fs/nfsd
endif #KERNEL_HEADER_VERSION
else #USE_EXTRAFLAGS
CFLAGS += -I$(@D)/../include -I$(@D)/../kernelsource/include$(KERNEL_HEADER_VERSION) $(DBG_FLAG)
ifdef KERNEL_HEADER_VERSION
CFLAGS += -I$(@D)/../kernelsource/linux$(KERNEL_HEADER_VERSION)/fs/nfsd
endif #KERNEL_HEADER_VERSION
endif #USE_EXTRAFLAGS
else
# "traditional" make, needed for 2.4 kernels

### configuration parameters -- defaults are provided,
### but generally the build script will override them on the cmd line
MODULESUFFIX=rh-EL-21AS-2.4.9-e.3-i386
KERNELINCDIR=../include/kernel/rh-EL-21AS-2.4.9-e.3
BUILD_SMP=0

# these affect the build and the resulting module filename
# BUILD_GCC can select an alternative compiler if needed
BUILD_GCC=gcc-4.1.0.new
CC=$(BUILD_GCC)
GCCINSDIR=${shell $(CC) -print-search-dirs | sed -ne 's/install: \(.*\)/\1/gp'}
GCCINCDIR=$(GCCINSDIR)/include

# set the __module__smp flag if SMP compile is desired; this enables the
# SMP-specific kernel configs
ifeq ($(BUILD_SMP),0)
  SMPFLAGS=
else
  SMPFLAGS=-D__module__smp
endif

# compiler switches needed for 2.4 build
MOD_CFLAGS=-D__KERNEL__ -DMODULE $(SMPFLAGS) $(DBG_FLAG) -I$(KERNELINCDIR) -I$(GCCINCDIR) -I. -I../include \
	   -O -Wall $(DASHG) -nostdinc $(GCC_OPTIONS)
MOD_LDFLAGS=-r $(DASHG)
## the following actually apply to 2.6 builds, when this makefile
# wraps a recursive call to the kernel's makefile
# output subdir used by some outer 2.6 builds (where config is done)
BUILDDIR := $(CURDIR)/.build-$(MODULESUFFIX)
MODVERDIR := $(CURDIR)/.tmp_versions-$(MODULESUFFIX)
BUILDSUFFIX = $(subst .,_,$(MODULESUFFIX))
export MODULESUFFIX BUILDSUFFIX

endif

# only strip modules for release version of savap's package
ifdef FAILFLAG
ifndef DEBUG
  STRIP_AP_MODULES=1
endif
endif

# source_file_name  output_dir_name  output_file_name
ifndef STRIP_AP_MODULES
define output-file
	cp $1 $2/$(notdir $3)
endef
else
define output-file
	cp $1 $2/$(notdir $3)
	cp $1 $(SYMDIR)/$(notdir $3)
	strip --strip-debug $2/$(notdir $3)
	objcopy --add-gnu-debuglink=$(SYMDIR)/$(notdir $3) $2/$(notdir $3)
endef
endif

all: $(MOD)-$(MODULESUFFIX).o $(MOD_RM)-$(MODULESUFFIX).o

# Wrapper for SuSE new-style (>= 2.6.5) builds, from "scratch" (but
# borrowing the Module.symvers file from the -obj for now)
# Pass	KDIR=linux-(ver)	(we append -obj/(arch)/(flavor))
#	KARCH=(arch)		(e.g. i386 -- a subdir of $KDIR-obj)
#	KFLAV=(flavor)		(e.g. smp -- a subdir of $KDIR-obj/$ARCH)
#	MODULESUFFIX=(vnd)-(prod)-(ver)-(flavor)-(arch)
# Builds $(obj-m) but with .ko suffix.  Really.
mod2.6-suse-new:
	@rm -rf $(CURDIR)/Module.symvers
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/.config $(BUILDDIR)/.config
	$(MAKE) -C $(KDIR) HOSTCC=$(CC) O=$(BUILDDIR) silentoldconfig
	$(MAKE) -C $(KDIR) HOSTCC=$(CC) O=$(BUILDDIR) modules_prepare
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CC=$(CC) O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(MODULESUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(MODULESUFFIX).ko)
	if [ -f $(CURDIR)/Module.symvers ] ; then cp $(CURDIR)/Module.symvers Module.symvers-$(MODULESUFFIX) ; fi

mod2.6-suse-new-x86_64:
	@rm -rf $(CURDIR)/Module.symvers
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/.config $(BUILDDIR)/.config
	$(MAKE) -C $(KDIR) HOSTCC=$(HOSTCC) O=$(BUILDDIR) silentoldconfig
	$(MAKE) -C $(KDIR) HOSTCC=$(HOSTCC) O=$(BUILDDIR) modules_prepare
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CC=$(CC) LD=$(LD_X64) O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(MODULESUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(MODULESUFFIX).ko)
	if [ -f $(CURDIR)/Module.symvers ] ; then cp $(CURDIR)/Module.symvers Module.symvers-$(MODULESUFFIX) ; fi


# Red Hat Enterprise 4 series
el4:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	cp $(MOD_NAME).ko $(BINDIR)/$(MOD)-$(BUILDSUFFIX).ko
	cp $(MOD_RM_NAME).ko $(BINDIR)/.$(MOD_RM)-$(BUILDSUFFIX).ko

# Red Hat Enterprise 4 x86_64 series
el4-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 5 series
# same as el4 except autoconf isn't automatically updated
el5:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Red Hat Enterprise 5 x86_64 series
# same as el4 except autoconf isn't automatically updated
el5-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Red Hat Enterprise 6 series                                                                                                                                 
# same as el4 except autoconf isn't automatically updated                                                                                                     
el6:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Red Hat Enterprise 6 x86_64 series                                                                                                                         
el6-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Red Hat Enterprise 7 x86_64 series                                                                                                                         

el7-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Ubuntu 7.x
ub7-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts

ub7:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Ubuntu 7.x x86_64
ub7-x86_64-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) HOSTCC=$(HOSTCC) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) HOSTCC=$(HOSTCC) ARCH=x86_64 KARCH=x86_64 scripts

ub7-x86_64:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Ubuntu 11.x+ x86
ub11-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts

ub11:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

# Ubuntu 11.x+ x86_64
ub11-x86_64-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts

ub11-x86_64:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)

or6u5-x86_64-kernel-header:
	MAKE=make make -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	MAKE=make make -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts

or6u5-x86_64:
	MAKE=make make -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)


# Debian 4.x
db4:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	if [ -f $(CURDIR)/Module.symvers ] ; then cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX) ; fi

# Debian 4.x-x86_64
db4-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	if [ -f $(CURDIR)/Module.symvers ] ; then cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX) ; fi

# Customer Native builds
custom:
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)
	$(call output-file,$(MOD_RM_NAME).ko,$(BINDIR),.$(MOD_RM)-$(BUILDSUFFIX).ko)
	-cp $(CURDIR)/Module.symvers Module.symvers-$(BUILDSUFFIX)


# Native 2.4-style builds, based on pointing KERNELINCDIR at the "include"
# subdirectory beneath a preconfigured kernel build tree
$(MOD)-$(MODULESUFFIX).o: symev-o-$(MODULESUFFIX).o syscalls-o-$(MODULESUFFIX).o fileops-o-$(MODULESUFFIX).o hnfs-o-$(MODULESUFFIX).o utils-o-$(MODULESUFFIX).o sym_procfs-o-$(MODULESUFFIX).o
	$(LD)$(NON_I386) $(MOD_LDFLAGS) -o $(MOD)-$(MODULESUFFIX).o $^
	$(call output-file,$(MOD)-$(MODULESUFFIX).o,$(BINDIR),$(MOD)-$(MODULESUFFIX).o)

$(MOD_RM)-$(MODULESUFFIX).o: symevrm-o-$(MODULESUFFIX).o syscalls-o-$(MODULESUFFIX).o
	$(LD)$(NON_I386) $(MOD_LDFLAGS) -o $(MOD_RM)-$(MODULESUFFIX).o $^
	$(call output-file,$(MOD_RM)-$(MODULESUFFIX).o,$(BINDIR),.$(MOD_RM)-$(MODULESUFFIX).o)

symevrm-o-$(MODULESUFFIX).o: symevrm.c symev.h ../include/symevl.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

symev-o-$(MODULESUFFIX).o: symev.c fileops.h symev.h ../include/symevl.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

syscalls-o-$(MODULESUFFIX).o: syscalls.c symev.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

fileops-o-$(MODULESUFFIX).o: fileops.c fileops.h symev.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

hnfs-o-$(MODULESUFFIX).o: hnfs.c hnfs.h symev.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

utils-o-$(MODULESUFFIX).o: utils.c symev.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

sym_procfs-o-$(MODULESUFFIX).o: sym_procfs.c ../include/symprocfs.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

# the basic "clean" target cleans only ths currently configured version
clean:
	rm -f *-$(MODULESUFFIX).o symev-$(MODULESUFFIX).ko symev-$(MODULESUFFIX).mod.[co] .symev-$(MODULESUFFIX).*.cmd *.ko.unsigned symevrm-$(MODULESUFFIX).ko symev-$(MODULESUFFIX).mod.[co]
	rm -rf .tmp_versions-$(MODULESUFFIX) .build-$(MODULESUFFIX)
	rm -rf modules.order Module.symvers Module.symvers-$(BUILDSUFFIX)

# the extended "clean" target cleans all configurations
realclean:
	rm -f *.o *.ko *.mod.c .*.cmd modules.order Module.symvers* Module.markers Modules.symvers *.ko.unsigned Makefile.xen
	rm -rf .tmp_versions* .build-*
