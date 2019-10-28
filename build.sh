#!/bin/bash
# Symantec Anti-virus for Linux Auto-Protect Kernel Modules Build Script.
#
# Copyright (C) 2010 Symantec Corporation.
# This file is distributed under the GNU GENERAL PUBLIC LICENSE (GPL) Version 2.
# See the "COPYING" file distributed with this software for more info.

if [[ ${0:0:1} != "/" ]] ; then
  CWD=$PWD/`dirname $0`
else
  CWD=`dirname $0`
fi

# Initialization
buildDebug=0
buildFlags=""
kernelSourceDir=""
kernelRelease=""
kernelVersion24=0
kernelVerNumber=0
redhat6=0
redhat7dot3=0
FAILFLAG=failure

LOG=$(dirname ~/sepfl-kbuild.log)/sepfl-kbuild.log

#$1: log message string.
writelog()
{
	echo "$1" | tee -a "$LOG"
	return 0
}


buildFailure()
{
  echo
  writelog "$(date): Build failed"
  exit 1
}

isrpmsupported()
{
	which rpm > /dev/null 2>&1
	if [ ! 0 -eq $? ] ; then
		return 0
	fi

	rpm -qa | grep rpm > /dev/null 2>&1
	if [ 0 -eq $? ] ; then
		return 1
	fi

	return 0
}

stopdaemons()
{
	local daemons="smcd rtvscand symcfgd"
	for daemon in $daemons
	do
		if [ -f /etc/init.d/${daemon} ] ; then
			/etc/init.d/${daemon} stop
		fi
	done
}

startdaemons()
{
	local daemons="symcfgd rtvscand smcd"
	for daemon in $daemons
	do
		if [ -f /etc/init.d/${daemon} ] ; then
			/etc/init.d/${daemon} start
		fi
	done
}


depmodkernel()
{
	local sourcedir="$1"
	local apdir="$sourcedir"
	local kerneldir="/lib/modules/$(uname -r)/kernel/drivers/char"
	local symev=$(lsmod | grep -e "^symev" | awk -F' ' '{print $1}')
	local symap=$(lsmod | grep -e "^symap" | awk -F' ' '{print $1}')

	if [ "$symev" = "" ] ; then
		writelog "kernel drivers are not loaded."
		return 0
	fi

	rm -f $kerneldir/$symev.ko 

	rm -f $kerneldir/$symap.ko

	pushd $apdir
	local evfiles=$(ls symev* | xargs)
	for ev in $evfiles
	do
		local tempevfile=$(echo $ev | sed -e 's/\.ko//g' -e 's/\./-/g' -e 's/_/-/g')
		local tempev=$(echo $symev | sed -e 's/\./-/g' -e 's/_/-/g')
		if [ "$tempev" = "$tempevfile" ] ; then
			ln -s $apdir/$ev $kerneldir/$symev.ko
			if [ 0 -eq $? ] ; then
				writelog "succeed to make link $kerneldir/$symev.ko"
			else
				writelog "failed to make link $kerneldir/symev.ko , err: $?"
			fi
			break
		fi
	done

	if [ "$symap" = "" ] ; then
		writelog "symap is not loaded."
		popd
		return 0
	fi

	local apfiles=$(ls symap* | xargs)
	for ap in $apfiles
	do
		local tempapfile=$(echo $ap | sed -e 's/\.ko//g' -e 's/\./-/g' -e 's/_/-/g')
		local tempap=$(echo $symap | sed -e 's/\./-/g' -e 's/_/-/g')
		if [ "$tempapfile" = "$tempap" ] ; then
			ln -s $apdir/$ap $kerneldir/$symap.ko
			if [ 0 -eq $? ] ; then
				writelog "succeed to make link $kerneldir/$symap.ko"
			else
				writelog "failed to make link $kerneldir/$symap.ko, err: $?"
			fi

			break
		fi
	done

	/sbin/depmod -A

	popd
	return 0
}


installDrivers()
{
	local source_dir=bin.ira
	if [ ! "" = "$buildDebug" -a 1 -eq $buildDebug ] ; then
		source_dir=bin.ida
	fi

	local symc_dir=$(cat /etc/Symantec.conf | grep BaseDir | awk -F'=' '{print $2}')
	local ap_dir=${symc_dir}/autoprotect

	if [ ! -d ${ap_dir} ] ; then
		mkdir -p ${ap_dir}
	fi
	
	cp -f ${source_dir}/*.ko ${ap_dir}
	if [ ! 0 -eq $? ] ; then
		writelog "failed to copy compiled drivers, err: $?"
		return 1
	fi
	
	cp -f ${source_dir}/.symevrm*.ko ${ap_dir}
	if [ ! 0 -eq $? ] ; then
		writelog "failed to copy symevrm, err: $?"
	fi

	stopdaemons

	local symev=$(lsmod | grep -E "^symev" | awk -F' ' '{print $1}' | sed 's/_/\-/g')
	if [ ! -z "symev" ] ; then
		/etc/init.d/autoprotect remove
	fi

	/etc/init.d/autoprotect restart

	depmodkernel "$PWD/$source_dir"

	startdaemons

}

buildSuccess()
{
  echo
  writelog "$(date): Build succeeded"
  installDrivers
  exit 0
}

buildClean()
{
  local ret=0
  local buildList="symev symap"

  rm -rf bin.ida/*.ko bin.ira/*.ko

  for i in $buildList
  do
      pushd $i
      make realclean 
      popd
  done

  return $ret
}

updateDistributionInfo()
{
  if [ -f /etc/debian_version ] # Debian
  then
    vstr=`cat /etc/debian_version`
    case $vstr in
      8.*) echo "#define DEBIAN_VERSION 2048" > "${CWD}/include/distribution.h" ;;
    esac
  fi

  # check if we have Ubuntu OS
  linux_distro=`lsb_release -i`
  if echo $linux_distro | grep -q "Ubuntu"; then
    writelog "Ubuntu distribution detected"
    echo "#define UBUNTU_OS 1" > "${CWD}/include/distribution.h"
    echo "#define KSOURCECODE_UBUNTU 1" > "${CWD}/include/distribution.h"
  fi

  # RHEL 6 or CentOS 6
  if cat $kernelSourceDir/include/linux/version.h | grep "#define RHEL_MAJOR 6" >/dev/null 2>&1 ; then
    writelog "RedHat/CentOS release 6.x detected"
    redhat6=1
  fi

  # RHEL 7.3 or later
  if cat $kernelSourceDir/include/linux/version.h | grep "#define RHEL_MAJOR 7" >/dev/null 2>&1 ; then
    rhel7minor=`grep RHEL_MINOR $kernelSourceDir/include/linux/version.h | awk '{print $3}'`
    if [ "$rhel7minor" -ge "3" ] ; then
      writelog "RedHat/CentOS release 7.3 or later detected"
      redhat7dot3=1
    fi
  fi
}

buildAll()
{
  updateDistributionInfo

  local ret=0
  local buildList="symev symap"

  if [ $kernelVersion24 = 0 ] ; then
	  if [ "$kernelVerNumber" -ge "264972" ] ; then   #kernel version >= 4.11.0
          buildFlags="$buildFlags KERNEL_HEADER_VERSION=4.11.0"	
      elif [ "$kernelVerNumber" -ge "263936" ] ; then   #kernel version >= 4.7.0
          buildFlags="$buildFlags KERNEL_HEADER_VERSION=4.7.0"
      elif [ "$kernelVerNumber" -ge "199168" -a "$redhat7dot3" = "1" ] ; then #kernel 3.10.0 with redhat updates
          buildFlags="$buildFlags KERNEL_HEADER_VERSION=3.10.0-514"
      elif [ "$kernelVerNumber" -ge "199168" ] ; then   #kernel version >= 3.10.0
          buildFlags="$buildFlags KERNEL_HEADER_VERSION=3.10.0"
      elif [ "$kernelVerNumber" -gt "132641" -o "$redhat6" = "1" ] ; then #kernel version >= 2.6.33 or redhat 6
          buildFlags="$buildFlags KERNEL_HEADER_VERSION=2.6.33"
      fi

      if [ "$kernelVerNumber" -gt "132632" ] ; then   #kernel version > 2.6.24
          buildFlags="$buildFlags USE_EXTRAFLAGS=1"
      fi

  fi

  if [ `uname -m` = "x86_64" ] ; then
      buildFlags="$buildFlags NON_I386=-x86_64"

      if [ $kernelVersion24 = 1 ] ; then
          buildFlags="$buildFlags GCC_OPTIONS=\"-mcmodel=kernel\""
      fi
  fi

  for i in $buildList
  do
      pushd $i
      if [ $kernelVersion24 = 1 ] ; then
          (make KERNELINCDIR=$kernelSourceDir BUILDSUFFIX=$moduleSuffixStr MODULESUFFIX=$moduleSuffixStr CC=gcc $buildFlags || /bin/touch "$FAILFLAG" 2>/dev/null) 2>&1 | tee -a "$LOG"
      else
          (make custom KDIR=$kernelSourceDir BUILDSUFFIX=$moduleSuffixStr MODULESUFFIX=$moduleSuffixStr $buildFlags MOD_TOPDIR=$PWD || /bin/touch "$FAILFLAG" 2>/dev/null) 2>&1 | tee -a "$LOG"
      fi

	  if [ -f "$FAILFLAG" ] ; then
		ret=1
		rm -f "$FAILFLAG"
	  fi
      popd

      [ $ret != 0 ] && buildFailure
  done

  return $ret
}

#$1: string which may contains whitespaces. $1 must not be empty.
#return: 1 if contains whitespace, 0 if not. if $1 is empty, just return 0.
checkWhitespace()
{
	local str="$1"

	if [ -z "$str" ] ; then
		return 0
	fi

	local truncstr=$(echo "$str" | tr -cd "[\ \n\t]")

	if [ ! -z "$truncstr" ] ; then
		return 1
	fi

	return 0
}

prepEnvironment()
{
  local archstr=`uname -m`
  local usedefaultkernel=0

  if [ $buildDebug = 1 ] ; then
      writelog "Debug build of kernel modules"
      export DEBUG=1
  fi

  if [ "$kernelRelease" = "" ] ; then
      kernelRelease=`uname -r`
      writelog "Kernel release not specified. Build kernel modules for current kernel version `uname -r`"
  fi
  kernelRelease=`echo $kernelRelease | /bin/sed -e 's/\.PAE/PAE/' | /bin/sed -e 's/\.'$archstr'//'`
  moduleKernelRelease=$kernelRelease
  
  if [ "$kernelSourceDir" = "" ] ; then
	usedefaultkernel=1

	if [ -d "/lib/modules/${kernelRelease}/build" ] ; then
		kernelSourceDir="/lib/modules/${kernelRelease}/build"
	elif [ -d "/usr/src/kernel-headers-${kernelRelease}" ] ; then
		kernelSourceDir="/usr/src/kernel-headers-${kernelRelease}"
	elif [ -d "/usr/src/linux" ] ; then
		kernelSourceDir="/usr/src/linux"
	fi

  fi

  if [ -z "$kernelSourceDir" ] ; then
	  kernelRelease=`uname -r`
	  if [ -d "/lib/modules/${kernelRelease}/build" ] ; then
		  kernelSourceDir="/lib/modules/${kernelRelease}/build"
	  elif [ -d "/usr/src/kernel-headers-${kernelRelease}" ] ; then
		  kernelSourceDir="/usr/src/kernel-headers-${kernelRelease}"
	  elif [ -d "/usr/src/linux" ] ; then
		  kernelSourceDir="/usr/src/linux"
	  fi
  fi

  if [ 1 = "${usedefaultkernel}" -a -d "${kernelSourceDir}" ] ; then
      writelog "Kernel source directory not specified. Use default $kernelSourceDir"
  fi

  if [ ! -d "$kernelSourceDir" ] ; then
      writelog "$kernelSourceDir does not exist"
      buildFailure
  fi

  #check whether kernel source contains linux/version.h, if not, try to ln -s from it.
  if [ ! -f "$kernelSourceDir/include/linux/version.h" ] ; then
	  if [ -f "$kernelSourceDir/include/generated/uapi/linux/version.h" ] ; then
          if [ ! -d "$kernelSourceDir/include/linux" ] ; then
              mkdir "$kernelSourceDir/include/linux" >> "${LOG}" 2>&1
          fi
		  ln -s "$kernelSourceDir/include/generated/uapi/linux/version.h" "$kernelSourceDir/include/linux/version.h" >> "${LOG}" 2>&1
	  fi
  fi

  if [ -f $kernelSourceDir/include/linux/version.h ] ; then
      kernelVerNumber=`grep LINUX_VERSION_CODE $kernelSourceDir/include/linux/version.h | awk '{print $3}'`

      if [ "$kernelVerNumber" -lt "132352" ] ; then   #kernel version 2.4.x
          kernelVersion24=1
      fi
  else
      writelog "Could not detect the file $kernelSourceDir/include/linux/version.h."
      buildFailure 
  fi

  if [ $kernelVersion24 = 1 ] ; then
      kernelSourceDir="$kernelSourceDir/include"
  fi

  # check whether $PWD contains whitespace.
  if ! checkWhitespace "$PWD" ; then
	  writelog "The path \"$PWD\" contains whitespace which are not permitted for kernel build. Please use another path which doesn't contain whitespace and try again."
	  buildFailure
  fi

  export moduleSuffixStr="custom-$moduleKernelRelease-`uname -m`"
  
  # Get the output folder
  export OUTPUTDIR=$PWD
}

usage()
{
  echo "Usage: build.sh [options] "
  echo "Options:"
  echo "  --kernel-dir [DIRECTORY]  : DIRECTORY is to set kernel headers/makefiles directory to build kernel modules"
  if echo "`uname -r`" | grep "`uname -m`" > /dev/null 2>&1 ; then
  echo "                              The default is /usr/src/kernels/`uname -r`"
  else
  echo "                              The default is /usr/src/kernels/`uname -r`-`uname -m`"
  fi
  echo "  --kernel-rel [RELEASE]    : RELEASE is to set which kernel release the kernel modules are builded for"
  echo "                              The default is the current kernel release(`uname -r`)"
  echo "  --debug                   : Build the kernel modules with debugging information"
  echo "  --clean                   : Delete all generated files"
  echo "  --version                 : Display the version number of the build script"
  echo "  --help                    : Display this help"
  echo
}


# =====================================================
#  Execution starts here
# =====================================================
# Parse command line
while [ $# -ge 1 ] ; do
  case $1 in
    --kernel-dir)   shift; kernelSourceDir=$1;;
    --kernel-rel)   shift; kernelRelease=$1;;
    --debug)        buildDebug=1;;
    --clean)        buildClean; exit 0;; 
    --version)      echo -n "build.sh v"; cat VERSION; exit 0;;
    --help)         usage; exit 0;;
    *)              echo "Unknown Option: $1"; echo; usage; exit 1;;
  esac
  shift
done

writelog "$(date): starting to build kernel modules of SEP for Linux"
prepEnvironment

# Build kernel modules
buildClean
buildAll
buildSuccess
# End
