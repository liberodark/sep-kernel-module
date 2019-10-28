# Makefile for symap

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

MOD=symap

MOD_OFILES=linuxmod.o ../symev/sym_procfs.o

# the core object component of this module, linked in as a binary
CORE_OBJ=$(LIBDIR)/$(MOD)-core$(NON_I386).o

# the module name whose '.' and '-' will be replaced by '_'
MOD_SUFFIX = $(subst .,_,$(subst -,_,$(BUILDSUFFIX)))
MOD_NAME = $(MOD)_$(MOD_SUFFIX)

# Support the 2.6 kernel builds which are recursive.  This Makefile
# is included by the kernel module make, in which case it supplies
# a few variable settings that will affect the module build.
ifneq ($(KBUILD_MODULES),)
# Set the variables used by the 2.6 module build
obj-m := $(MOD_NAME).o
$(MOD_NAME)-objs := $(MOD_OFILES)
ifdef USE_EXTRAFLAGS
EXTRA_CFLAGS += -I$(MOD_TOPDIR)/../include $(DBG_FLAG)
EXTRA_LDFLAGS += $(CORE_OBJ)
else
CFLAGS += -I$(@D)/../include $(DBG_FLAG)
LDFLAGS += $(CORE_OBJ)
endif
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
MOD_CFLAGS=-D__KERNEL__ -DMODULE $(SMPFLAGS) $(DBG_FLAG) \
	-I$(KERNELINCDIR) -I$(GCCINCDIR) -I. -I../include -O -Wall $(DASHG) \
	-nostdinc $(GCC_OPTIONS)
MOD_LDFLAGS=-r $(DASHG)

## the following actually apply to 2.6 builds, when this makefile
# wraps a recursive call to the kernel's makefile
# output subdir used by some outer 2.6 builds (where config is done)
ORIGDIR := $(CURDIR)
BUILDDIR := $(CURDIR)/.build-$(MODULESUFFIX)
MODVERDIR := $(CURDIR)/.tmp_versions-$(MODULESUFFIX)
BUILDSUFFIX = $(subst .,_,$(MODULESUFFIX))
export ORIGDIR MODULESUFFIX BUILDSUFFIX

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

all: $(MOD)-$(MODULESUFFIX).o

# Wrapper for SuSE new-style (>= 2.6.5) builds, from "scratch" (but
# borrowing the Module.symvers file from the -obj for now)
# Pass	KDIR=linux-(ver)	(we append -obj/(arch)/(flavor))
#	KARCH=(arch)		(e.g. i386 -- a subdir of $KDIR-obj)
#	KFLAV=(flavor)		(e.g. smp -- a subdir of $KDIR-obj/$ARCH)
#	MODULESUFFIX=(vnd)-(prod)-(ver)-(flavor)-(arch)
# Builds $(obj-m) but with .ko suffix.  Really.
mod2.6-suse-new: $(CORE_OBJ)
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/.config $(BUILDDIR)/.config
	$(MAKE) -C $(KDIR) HOSTCC=$(CC) O=$(BUILDDIR) silentoldconfig
	$(MAKE) -C $(KDIR) HOSTCC=$(CC) O=$(BUILDDIR) modules_prepare
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/Module.symvers $(BUILDDIR)/Module.symvers
	if [ -f ../symev/Module.symvers-$(MODULESUFFIX) ] ; then cp ../symev/Module.symvers-$(MODULESUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) O=$(BUILDDIR) M=$(CURDIR) modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(MODULESUFFIX).ko)

mod2.6-suse-new-x86_64: $(CORE_OBJ)
	 -mkdir -p $(BUILDDIR)
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/.config $(BUILDDIR)/.config
	$(MAKE) -C $(KDIR) HOSTCC=$(HOSTCC) O=$(BUILDDIR) silentoldconfig
	$(MAKE) -C $(KDIR) HOSTCC=$(HOSTCC) O=$(BUILDDIR) modules_prepare
	cp -f $(KDIR)-obj/$(KARCH)/$(KFLAV)/Module.symvers $(BUILDDIR)/Module.symvers
	if [ -f ../symev/Module.symvers-$(MODULESUFFIX) ] ; then cp ../symev/Module.symvers-$(MODULESUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) CC=$(CC) LD=$(LD_X64) O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(MODULESUFFIX).ko)


# Red Hat Enterprise 4 series
el4:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 4 x86_64 series
el4-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 5 series
# same as el4 except autoconf isn't automatically updated
el5:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 5 x86_64 series
# same as el4 except autoconf isn't automatically updated
el5-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)


# Red Hat Enterprise 6 series
el6:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts   
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 6 x86_64 series
el6-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Red Hat Enterprise 7 x86_64 series
el7-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts
	make -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Ubuntu 7.x
ub7-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts

ub7:
	-rm -rf  Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Ubuntu 7.x x86_64
ub7-x86_64-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) HOSTCC=$(HOSTCC) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) HOSTCC=$(HOSTCC) ARCH=x86_64 KARCH=x86_64 scripts

ub7-x86_64:
	-rm -rf  Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Ubuntu 11.x+ x86
ub11-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 scripts

ub11:
	-rm -rf  Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Ubuntu 11.x+ x86_64
ub11-x86_64-kernel-header:
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	$(MAKE) -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts

ub11-x86_64:
	-rm -rf  Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

or6u5-x86_64-kernel-header:
	MAKE=make make -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 silentoldconfig
	MAKE=make make -C $(KDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 scripts

or6u5-x86_64:
	-rm -rf  Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	MAKE=make make -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Debian 4.x
db4:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) CROSS_COMPILE=i686-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=i386 KARCH=i386 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Debian 4.x-x86_64
db4-x86_64:
	-mkdir -p $(BUILDDIR)
	cp -f $(KDIR)/.config $(BUILDDIR)/.config
	cp -f $(KDIR)/Module.symvers $(BUILDDIR)/Module.symvers
	-rm -rf Module.symvers
	if [ -f ../symev/Module.symvers-$(BUILDSUFFIX) ] ; then cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers ; fi
	$(MAKE) -C $(KDIR) CROSS_COMPILE=x86_64-symantec-linux-gnu- O=$(BUILDDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) ARCH=x86_64 KARCH=x86_64 modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)

# Customer Native builds
custom:
	-rm -rf Module.symvers
	-cp ../symev/Module.symvers-$(BUILDSUFFIX) Module.symvers
	$(MAKE) -C $(KDIR) M=$(CURDIR) MODVERDIR=$(MODVERDIR) modules
	$(call output-file,$(MOD_NAME).ko,$(BINDIR),$(MOD)-$(BUILDSUFFIX).ko)


# Native 2.4-style builds, based on pointing KERNELINCDIR at the "include"
# subdirectory beneath a preconfigured kernel build tree
$(MOD)-$(MODULESUFFIX).o: linuxmod-o-$(MODULESUFFIX).o sym_procfs-o-$(MODULESUFFIX).o $(CORE_OBJ)
	$(LD)$(NON_I386) $(MOD_LDFLAGS) -o $(MOD)-$(MODULESUFFIX).o $^
	$(call output-file,$(MOD)-$(MODULESUFFIX).o,$(BINDIR),$(MOD)-$(MODULESUFFIX).o)

# building the (test) binaries
TEST_UTILS=symap_test
SYMAP_TEST_OFILES=symap_test.o
TEST_CFLAGS=-std=c99 -g -D_BSD_SOURCE -I../include -O -Wall
TEST_LDFLAGS=

linuxmod-o-$(MODULESUFFIX).o: linuxmod.c ../include/symevl.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<

sym_procfs-o-$(MODULESUFFIX).o: ../symev/sym_procfs.c ../include/symprocfs.h
	$(CC) $(MOD_CFLAGS) -c -o $@ $<
    
# the basic "clean" target cleans only ths currently configured version
# -- note that symap's .mod file goes into ../symev, so shared symbols can
# be resolved
clean:
	rm -f *-$(MODULESUFFIX).o symap-$(MODULESUFFIX).ko $(MOD_OFILES) \
	   symap-$(MODULESUFFIX).mod.[co] .symap-$(MODULESUFFIX).*.cmd \
	   ../symev/.tmp_versions-$(MODULESUFFIX)/symap-$(MODULESUFFIX).mod \
	   *.ko.unsigned
	rm -rf .build-$(MODULESUFFIX)
	rm -rf modules.order Module.symvers Module.symvers-$(BUILDSUFFIX)

# the extended "clean" target cleans all configurations
realclean:
	rm -f *.o *.ko *.mod.c .*.cmd modules.order Module.symvers* Module.markers Modules.symvers *.ko.unsigned Makefile.xen symap_test
	rm -rf ../symev/.tmp_versions* .build-*

# this is actually building test utilities, not running them
test: $(TEST_UTILS)
	cp $(TEST_UTILS) $(BINDIR)

symap_test: $(SYMAP_TEST_OFILES)
	$(CC) $(TEST_LDFLAGS) -o $@ $(SYMAP_TEST_OFILES) -lc

symap_test.o: symap_test.c ../include/symevl.h
	$(CC) $(TEST_CFLAGS) -c -o $@ $<
