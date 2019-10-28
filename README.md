=======================================================================================

Symantec AntiVirus(TM) for Linux README.TXT Date: August 2012 Copyright (c) 2012 Symantec Corporation. All rights reserved. Symantec, the Symantec Logo, and Symantec AntiVirus are trademarks or registered trademarks of Symantec Corporation or its affiliates in the U.S. and other countries. Other names may be trademarks of their respective owners. The Licensed Software and Documentation are deemed to be "commercial computer software" and "commercial computer software documentation" as defined in FAR Sections 12.212 and DFARS Section 227.7202.

=======================================================================================

========================================================================================
HOW TO COMPILE AND INSTALL AUTO-PROTECT KERNEL MODULES

Please read this document if you want to compile and install Auto-Protect kernel 
modules yourself for use in your local Linux environment.

There are hundreds of Linux distributions and versions around the world. It is not 
possible for Symantec to officially support all of them. If you do not see Auto-Protect 
kernel modules for your Linux distribution and versions in the latest release, you can 
try to compile your own kernel modules by using the source code and library files that 
Symantec provides. 

========================================================================================

 - Make sure the source for your kernel is installed. If you are using a vendor-supplied
   kernel, such as RedHat's, which provides a development package for building kernel
   modules to match the kernel, this package often installs the kernel headers 
   and makefiles for compiling kernel modules into /usr/src/linux-<kernel version>.

 - Configure the kernel source. If you are using a vender-supplied kernel, the 
   corresponding development package often contains the matched kernel configuration 
   file, .config, in the top-level directory. If it does not, you must copy the matched 
   kernel configuration file to the top-level directory using the filename .config, and 
   then apply the configuration file to your kernel source by using the following
   command lines:

       # cd <kernel source dir>
       # make silentoldconfig   (# make oldconfig for kernel 2.4.x)
       # make scripts

   Note that some Linux distributions, such as Ubuntu, Debian, and so on, provide a
   development package that has been applied with the matched configuration file. 
   For these distributions, you do not need to perform the steps above. If your Linux 
   distribution does not provide a development package, you must refer to their 
   documentation to configure the kernel source.  For example, the SUSE Linux Enterprise 
   Server documentation contains an example of how to configure kernel source:

       # rpm -Uhv kernel-source-2.6.xx.xx-xx   (install kernel source package)
       # cd /usr/src/linux-2.6.xx.xx-xx
       # cp ../linux-2.6.xx.xx-xx.obj/yourarch/yourconfig/.config .config 
       # make silentoldconfig
       # make modules_prepare
       # cp ../linux-2.6.xx.xx-xx-obj/yourarch/yourconfig/Module.symvers Module.symvers

 - Compile the kernel modules. Unpack the Auto-Protect source tarball file in an 
   appropriate directory and cd to that directory. You should see the script file, 
   build.sh. Execute build.sh to compile all source directories:

       # ./build.sh --kernel-dir <kernel source dir>
   
   If you compile the source successfully, you should see the two kernel module files 
   (symev-custom-`uname -r`-`uname -m`.ko, symap-custom-`uname -r`-`uname -m`.ko) under
   the bin.ira directory. 

   Note that you must not rename kernel module files, because the Auto-Protect service 
   script, /etc/init.d/autoprotect, has file name matching rules that are needed to load 
   the appropriate kernel module files.
   
   To see more build options, please run ./build.sh --help.

 - Install the kernel modules. Copy the two kernel module files to the savfl autoprotect 
   installation directory, /opt/Symantec/autoprotect, and then either restart 
   Auto-Protect and the rtvscan service or restart your computer:

       # /etc/init.d/autoprotect restart
       # /etc/init.d/rtvscand restart   

   If the Auto-Protect service restarts successfully, check to see if the kernel modules
   are loaded by using the following command:

       # lsmod | grep sym

   For more detailed information, look at the /proc/symev and /proc/symap files.

 - The product team is seeking feedback and suggestions on these open sourced modules.
   For example, what kernels have you been able to compile using our open sourced modules,
   what issues are you encountering, what suggestions do you have for the product teams.
   Please join "Linux AV Open Source" Group:
   https://www-secure.symantec.com/connect/groups/linux-av-open-source/
