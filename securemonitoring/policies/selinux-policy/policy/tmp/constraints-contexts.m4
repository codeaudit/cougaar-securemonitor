#line 1 "tmp/program_used_flags.te"

































#line 1 "tmp/all_macros.te"
#
# Macros for all admin domains.
#

#
# admin_domain(domain_prefix)
#
# Define derived types and rules for an administrator domain.
#
# The type declaration and role authorization for the domain must be
# provided separately.  Likewise, domain transitions into this domain
# must be specified separately.  If the every_domain() rules are desired,
# then these rules must also be specified separately.
#

#line 150

##############################
#
# Global macros for the type enforcement (TE) configuration.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser  
# Modified: Howard Holm (NSA), <hdholm@epoch.ncsc.mil>
#           System V IPC added
#
#################################
# 
# Macros for groups of classes and 
# groups of permissions.
#

#
# All directory and file classes
#


#
# All non-directory file classes.
#


#
# Non-device file classes.
#


#
# Device file classes.
#


#
# All socket classes.
#


#
# Datagram socket classes.
# 


#
# Stream socket classes.
#


#
# Unprivileged socket classes (exclude rawip, netlink, packet).
#



# 
# Permissions for getting file attributes.
#


# 
# Permissions for executing files.
#


# 
# Permissions for reading files and their attributes.
#


# 
# Permissions for reading and executing files.
#


# 
# Permissions for reading and writing files and their attributes.
#


# 
# Permissions for reading and appending to files.
#


#
# Permissions for linking, unlinking and renaming files.
# 


#
# Permissions for creating and using files.
# 


# 
# Permissions for reading directories and their attributes.
#


# 
# Permissions for reading and writing directories and their attributes.
#


# 
# Permissions for reading and adding names to directories.
#



#
# Permissions for creating and using directories.
# 


#
# Permissions to mount and unmount file systems.
#


#
# Permissions for using sockets.
# 


#
# Permissions for creating and using sockets.
# 


#
# Permissions for using stream sockets.
# 


#
# Permissions for creating and using stream sockets.
# 



#
# Permissions for sending all signals.
#


#
# Permissions for sending and receiving network packets.
#


#
# Permissions for using System V IPC
#







#################################
# 
# Macros for type transition rules and
# access vector rules.
#

#
# Simple combinations for reading and writing both
# directories and files.
# 
#line 328


#line 333


#line 338


#line 343


#line 348


#line 353


#line 358


#################################
#
# domain_trans(parent_domain, program_type, child_domain)
#
# Permissions for transitioning to a new domain.
#

#line 405


#################################
#
# domain_auto_trans(parent_domain, program_type, child_domain)
#
# Define a default domain transition and allow it.
#
#line 416


#line 421


#################################
#
# uses_shlib(domain)
#
# Permissions for using shared libraries.
#
#line 438


#line 448


#################################
#
# can_ptrace(domain, domain)
#
# Permissions for running ptrace (strace or gdb) on another domain
#
#line 458


#################################
#
# can_exec(domain, type)
#
# Permissions for executing programs with
# a specified type without changing domains.
#
#line 469


#################################
#
# can_exec_any(domain)
#
# Permissions for executing a variety
# of executable types.
#
#line 487



#################################
#
# file_type_trans(domain, dir_type, file_type)
#
# Permissions for transitioning to a new file type.
#

#line 514


#################################
#
# file_type_auto_trans(creator_domain, parent_directory_type, file_type, object_class)
#
# the object class will default to notdevfile_class_set if not specified as
# the fourth parameter
#
# Define a default file type transition and allow it.
#
#line 535


#################################
#
# can_network(domain)
#
# Permissions for accessing the network.
# See types/network.te for the network types.
# See net_contexts for security contexts for network entities.
#
#line 613


#################################
#
# can_unix_connect(client, server)
#
# Permissions for establishing a Unix stream connection.
#
#line 623


#################################
#
# can_unix_send(sender, receiver)
#
# Permissions for sending Unix datagrams.
#
#line 633


#################################
#
# can_tcp_connect(client, server)
#
# Permissions for establishing a TCP connection.
#
#line 646


#################################
#
# can_udp_send(sender, receiver)
#
# Permissions for sending/receiving UDP datagrams.
#
#line 657


#################################
#
# can_sysctl(domain)
#
# Permissions for modifying sysctl parameters.
#
#line 681



##################################
#
# can_create_pty(domain_prefix, attributes)
#
# Permissions for creating ptys.
#
#line 710



##################################
#
# can_create_other_pty(domain_prefix,other_domain)
#
# Permissions for creating ptys for another domain.
#
#line 734




################################################
#
# The following macros are an attempt to start
# partitioning every_domain into finer-grained subsets
# that can be used by individual domains.
#

#
# general_domain_access(domain)
#
# Grant permissions within the domain.
# This includes permissions to processes, /proc/PID files,
# file descriptors, pipes, Unix sockets, and System V IPC objects
# labeled with the domain.
#
#line 778


#
# general_proc_read_access(domain)
#
# Grant read/search permissions to most of /proc, excluding
# the /proc/PID directories and the /proc/kmsg and /proc/kcore files.
# The general_domain_access macro grants access to the domain /proc/PID
# directories, but not to other domains.  Only permissions to stat
# are granted for /proc/kmsg and /proc/kcore, since these files are more
# sensitive.
# 
#line 813


#
# base_file_read_access(domain)
#
# Grant read/search permissions to a few system file types.
#
#line 837


#
# general_file_read_access(domain)
#
# Grant read/search permissions to many system file types.
#
#line 976


#
# general_file_write_access(domain)
#
# Grant write permissions to a small set of system file types, e.g. 
# /dev/tty, /dev/null, etc.
#
# For shared directories like /tmp, each domain should have its own derived
# type (with a file_type_auto_trans rule) for files created in the shared
# directory.
#
#line 997


#
# every_test_domain(domain)
#
# Grant permissions common to the test domains.
#
#line 1034


################################
#
# every_domain(domain)
#
# Grant permissions common to most domains.
#
# This macro replaces the rules formerly located in domains/every.te.
# An every_domain macro has been inserted into each domain .te file
# for each domain defined within that file.  If you want a new domain
# to inherit these rules, then you can likewise use this macro in
# your new domain .te file.  However, for least privilege purposes, you 
# may want to consider using macros or individual rules that only include 
# a subset of these permissions for your new domain.  This macro has already 
# been partitioned into a few subsets, with corresponding macros defined 
# above and used in defining this macro.  
#
#line 1061


#######################
# daemon_base_domain(domain_prefix, attribs)
#
# Define a daemon domain with a base set of type declarations
# and permissions that are common to most daemons.
# attribs is the list of attributes which must start with `,' if it is not empty
#
# Author:  Russell Coker <russell@coker.com.au>
#
#line 1097

#line 1113

#line 1119


# define a sub-domain, $1_t is the parent domain, $2 is the name
# of the sub-domain.
#
#line 1147



#line 1153


#line 1158


#line 1163


#line 1168


#######################
# application_domain(domain_prefix)
#
# Define a domain with a base set of type declarations
# and permissions that are common to simple applications.
#
# Author:  Russell Coker <russell@coker.com.au>
#
#line 1184


#line 1190


#line 1198



#
# Macros for all user login domains.
#

#
# user_domain(domain_prefix)
#
# Define derived types and rules for an ordinary user domain.
#
# The type declaration and role authorization for the domain must be
# provided separately.  Likewise, domain transitions into this domain
# must be specified separately.  
#

#line 1430



###########################################################################
#
# Domains for ordinary users.
#

#line 1538



#line 1545



#
# Macros for chkpwd domains.
#

#
# chkpwd_domain(domain_prefix)
#
# Define a derived domain for the *_chkpwd program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/su.te. 
#

#line 1594

#line 1594

#line 1594

#line 1594


# macro for chroot environments
# Author Russell Coker

# chroot(initial_domain, basename, role, tty_device_type)
#line 1726

#
# Macros for clamscan
#
# Author:  Brian May <bam@snoopy.apana.org.au>
#

#
# clamscan_domain(domain_prefix)
#
# Define a derived domain for the clamscan program when executed
#
#line 1761


#line 1770

#
# Macros for crond domains.
#

#
# Authors:  Jonathan Crowley (MITRE) <jonathan@mitre.org>,
#	    Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser
#

#
# crond_domain(domain_prefix)
#
# Define a derived domain for cron jobs executed by crond on behalf 
# of a user domain.  These domains are separate from the top-level domain
# defined for the crond daemon and the domain defined for system cron jobs,
# which are specified in domains/program/crond.te.
#

#line 1841


# When system_crond_t domain executes a type $1 executable then transition to
# domain $2, allow $2 to interact with crond_t as well.
#line 1851

#
# Macros for crontab domains.
#

#
# Authors:  Jonathan Crowley (MITRE) <jonathan@mitre.org>
# Revised by Stephen Smalley <sds@epoch.ncsc.mil>
#

#
# crontab_domain(domain_prefix)
#
# Define a derived domain for the crontab program when executed by
# a user domain.  
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/crontab.te. 
#

#line 1929

#
# Macro for fingerd
#
# Author:  Russell Coker <russell@coker.com.au>
#

#
# fingerd_macro(domain_prefix)
#
# allow fingerd to create a fingerlog file in the user home dir
#
#line 1944

#
# Macros for gpg and pgp
#
# Author:  Russell Coker <russell@coker.com.au>
#
# based on the work of:
# Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser
#

#
# gpg_domain(domain_prefix)
#
# Define a derived domain for the gpg/pgp program when executed by
# a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/gpg.te.
#
#line 2029

#
# Macros for gnome-pty-helper domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser 
#

#
# gph_domain(domain_prefix)
#
# Define a derived domain for the gnome-pty-helper program when
# executed by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/gnome-pty-helper.te. 
#
# The *_gph_t domains are for the gnome_pty_helper program.
# This program is executed by gnome-terminal to handle
# updates to utmp and wtmp.  In this regard, it is similar
# to utempter.  However, unlike utempter, gnome-pty-helper
# also creates the pty file for the terminal program.
# There is one *_gph_t domain for each user domain.  
#

#line 2101


#
# Macros for irc domains.
#

#
# Author:  Russell Coker <russell@coker.com.au>
#

#
# irc_domain(domain_prefix)
#
# Define a derived domain for the irc program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/irc.te. 
#

#line 2191

#line 2191

#line 2191

#line 2191

#line 2191

#
# Macros for lpr domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser 
#

#
# lpr_domain(domain_prefix)
#
# Define a derived domain for the lpr/lpq/lprm programs when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/lpr.te. 
#

#line 2280

#
# Macros for mount
#
# Author:  Brian May <bam@snoopy.apana.org.au>
# Extended by Russell Coker <russell@coker.com.au>
#

#
# mount_domain(domain_prefix,dst_domain_prefix)
#
# Define a derived domain for the mount program for anyone.
#
#line 2322

#
# Macros for MTA domains.
#

#
# Author:   Russell Coker <russell@coker.com.au>
# Based on the work of: Stephen Smalley <sds@epoch.ncsc.mil>
#                       Timothy Fraser 
#

#
# mail_domain(domain_prefix)
#
# Define a derived domain for the sendmail program when executed by
# a user domain to send outgoing mail.  These domains are separate and
# independent of the domain used for the sendmail daemon process.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/mta.te. 
#

#line 2413

#
# Macros for netscape/mozilla (or other browser) domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser 
#

#
# netscape_domain(domain_prefix)
#
# Define a derived domain for the netscape/mozilla program when executed by
# a user domain.  
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/netscape.te. 
#
#line 2450

# $1 is the source domain (or domains), $2 is the source role (or roles) and $3
# is the base name for the domain to run.  $1 is normally sysadm_t, and $2 is
# normally sysadm_r.  $4 is the type of program to run and $5 is the domain to
# transition to.
# sample usage:
# run_program(sysadm_t, sysadm_r, init, etc_t, initrc_t)
#
# if you have several users who run the same run_init type program for
# different purposes (think of a run_db program used by several database
# administrators to start several databases) then you can list all the source
# domains in $1, all the source roles in $2, but you may not want to list all
# types of programs to run in $4 and target domains in $5 (as that may permit
# entering a domain from the wrong type).  In such a situation just specify
# one value for each of $4 and $5 and have some rules such as the following:
# domain_trans(run_whatever_t, whatever_exec_t, whatever_t)

#line 2493

#
# Macros for screen domains.
#

#
# Author: Russell Coker <russell@coker.com.au>
# Based on the work of Stephen Smalley <sds@epoch.ncsc.mil>
# and Timothy Fraser
#

#
# screen_domain(domain_prefix)
#
# Define a derived domain for the screen program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/screen.te. 
#

#line 2583

#line 2583

#line 2583

#line 2583

#line 2583

#
# Macros for sendmail domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser 
#           Russell Coker <russell@coker.com.au>
#

#
# sendmail_user_domain(domain_prefix)
#
# Define a derived domain for the sendmail program when executed by
# a user domain to send outgoing mail.  These domains are separate and
# independent of the domain used for the sendmail daemon process.
#

#line 2623


#
# Macros for ssh domains.
#

#
# Author:  Stephen Smalley <sds@epoch.ncsc.mil>
#

# 
# ssh_domain(domain_prefix)
#
# Define a derived domain for the ssh program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/ssh.te. 
#

#line 2783

#line 2783

#line 2783

#line 2783

#
# Macros for su domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser
#

#
# su_domain(domain_prefix)
#
# Define a derived domain for the su program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/su.te. 
#


#line 2866

#line 2866

#line 2866

#line 2866

#
# Macros for xauth domains.
#

#
# Author:  Russell Coker <russell@coker.com.au>
#

#
# xauth_domain(domain_prefix)
#
# Define a derived domain for the xauth program when executed
# by a user domain.
#
# The type declaration for the executable type for this program is
# provided separately in domains/program/xauth.te. 
#

#line 2964

#line 2964

#line 2964

#line 2964

#
# Macros for X client programs ($2 etc)
#

#
# Author: Russell Coker <russell@coker.com.au>
# Based on the work of Stephen Smalley <sds@epoch.ncsc.mil>
# and Timothy Fraser 
#

#
# x_client_domain(domain_prefix)
#
# Define a derived domain for an X program when executed by
# a user domain.  
#
# The type declaration for the executable type for this program ($2_exec_t)
# must be provided separately!
#
# The first parameter is the base name for the domain/role (EG user or sysadm)
# The second parameter is the program name (EG $2)
# The third parameter is the attributes for the domain (if any)
#
#line 3103
#
# Macros for X server domains.
#

#
# Authors:  Stephen Smalley <sds@epoch.ncsc.mil> and Timothy Fraser
#

#################################
#
# xserver_domain(domain_prefix)
#
# Define a derived domain for the X server when executed
# by a user domain (e.g. via startx).  See the xdm_t domain
# in domains/program/xdm.te if using an X Display Manager.
#
# The type declarations for the executable type for this program 
# and the log type are provided separately in domains/program/xserver.te. 
#
# FIXME!  The X server requires far too many privileges.
#

#line 3264

#line 3264

#line 3264

#line 3264

#line 3264


#line 1 "constraints"
#
# Define m4 macros for the constraints
#

#
# Define the constraints
#
# constrain class_set perm_set expression ;
#
# expression : ( expression ) 
#	     | not expression
#	     | expression and expression
#	     | expression or expression
#	     | u1 op u2
#	     | r1 role_op r2
#	     | t1 op t2
#	     | u1 op names
#	     | u2 op names
#	     | r1 op names
#	     | r2 op names
#	     | t1 op names
#	     | t2 op names
#
# op : == | != 
# role_op : == | != | eq | dom | domby | incomp
#
# names : name | { name_list }
# name_list : name | name_list name#		
#

#
# Restrict the ability to transition to other users
# or roles to a few privileged types.
#

constrain process transition
	( u1 == u2 or t1 == privuser or (t1 == crond_t and t2 == user_crond_domain) );

constrain process transition 
	( r1 == r2 or t1 == privrole) ;

#
# Restrict the ability to label objects with other
# user identities to a few privileged types.
#

constrain { dir file lnk_file sock_file fifo_file chr_file blk_file } { create relabelto relabelfrom } 
	( u1 == u2 or t1 == privowner );

constrain { tcp_socket udp_socket rawip_socket netlink_socket packet_socket unix_stream_socket unix_dgram_socket } { create relabelto relabelfrom } 
	( u1 == u2 or t1 == privowner );
#line 1 "initial_sid_contexts"
# FLASK

#
# Define the security context for each initial SID
# sid sidname   context

sid kernel	system_u:system_r:kernel_t
sid security	system_u:object_r:security_t
sid unlabeled	system_u:object_r:unlabeled_t
sid fs		system_u:object_r:fs_t
sid file	system_u:object_r:file_t
sid file_labels	system_u:object_r:file_labels_t
sid init	system_u:system_r:init_t
sid any_socket 	system_u:system_r:any_socket_t
sid port	system_u:object_r:port_t
sid netif	system_u:object_r:netif_t
sid netmsg	system_u:object_r:netmsg_t
sid node	system_u:object_r:node_t
sid igmp_packet system_u:system_r:igmp_packet_t
sid icmp_socket system_u:system_r:icmp_socket_t
sid tcp_socket  system_u:system_r:tcp_socket_t
sid sysctl_modprobe	system_u:object_r:sysctl_modprobe_t
sid sysctl	system_u:object_r:sysctl_t
sid sysctl_fs	system_u:object_r:sysctl_fs_t
sid sysctl_kernel	system_u:object_r:sysctl_kernel_t
sid sysctl_net	system_u:object_r:sysctl_net_t
sid sysctl_net_unix	system_u:object_r:sysctl_net_unix_t
sid sysctl_vm	system_u:object_r:sysctl_vm_t
sid sysctl_dev	system_u:object_r:sysctl_dev_t
sid kmod	system_u:system_r:kernel_t
sid policy	system_u:object_r:policy_config_t
sid scmp_packet	system_u:system_r:scmp_packet_t

# FLASK
#line 1 "fs_use"
#
# Define the labeling behavior for inodes in particular filesystem types.
# This information was formerly hardcoded in the SELinux module.

# Use persistent label mappings for the following filesystem types.
# This is appropriate for filesystems with unique and persistent 
# inode numbers.  Be sure to apply setfiles to each filesystem (typically 
# via make relabel) to initialize the mapping.
fs_use_psid ext2;
fs_use_psid ext3;
fs_use_psid reiserfs;
fs_use_psid jfs;
fs_use_psid jffs2;

# Use the allocating task SID to label inodes in the following filesystem
# types, and label the filesystem itself with the specified context.
# This is appropriate for pseudo filesystems that represent objects
# like pipes and sockets, so that these objects are labeled with the same
# type as the creating task.  
fs_use_task pipefs system_u:object_r:fs_t;
fs_use_task sockfs system_u:object_r:fs_t;

# Use a transition SID based on the allocating task SID and the
# filesystem SID to label inodes in the following filesystem types,
# and label the filesystem itself with the specified context.
# This is appropriate for pseudo filesystems like devpts and tmpfs
# where we want to label objects with a derived type.
fs_use_trans devpts system_u:object_r:devpts_t;
fs_use_trans tmpfs system_u:object_r:tmpfs_t;
fs_use_trans shm system_u:object_r:tmpfs_t;

# The separate genfs_contexts configuration can be used for filesystem 
# types that cannot support persistent label mappings or use
# one of the fixed label schemes specified here.  
#line 1 "genfs_contexts"
# FLASK

#
# Security contexts for files in filesystems that
# cannot support persistent label mappings or use one of the
# fixed labeling schemes specified in fs_use.
#
# Each specifications has the form:
# 	genfscon fstype pathname-prefix [ -type ] context
#
# The entry with the longest matching pathname prefix is used.
# / refers to the root directory of the file system, and
# everything is specified relative to this root directory.
# If there is no entry with a matching pathname prefix, then 
# the unlabeled initial SID is used.
#
# The optional type field specifies the file type as shown in the mode
# field by ls, e.g. use -c to match only character device files, -b
# to match only block device files.
#

# proc (excluding /proc/PID)
genfscon proc /				system_u:object_r:proc_t
genfscon proc /kmsg			system_u:object_r:proc_kmsg_t
genfscon proc /kcore			system_u:object_r:proc_kcore_t
genfscon proc /sysvipc			system_u:object_r:proc_t
genfscon proc /sys			system_u:object_r:sysctl_t
genfscon proc /sys/kernel		system_u:object_r:sysctl_kernel_t
genfscon proc /sys/kernel/modprobe	system_u:object_r:sysctl_modprobe_t
genfscon proc /sys/net			system_u:object_r:sysctl_net_t
genfscon proc /sys/net/unix		system_u:object_r:sysctl_net_unix_t
genfscon proc /sys/vm			system_u:object_r:sysctl_vm_t
genfscon proc /sys/dev			system_u:object_r:sysctl_dev_t

# nfs
genfscon nfs /				system_u:object_r:nfs_t

# iso9660
genfscon iso9660 /			system_u:object_r:iso9660_t

# vfat, msdos
genfscon vfat /				system_u:object_r:dosfs_t
genfscon msdos /			system_u:object_r:dosfs_t

# sysfs
genfscon sysfs /			system_u:object_r:sysfs_t

# usbdevfs
genfscon usbdevfs /			system_u:object_r:usbdevfs_t
genfscon usbdevfs /0 -- 		system_u:object_r:usbdevfs_device_t

# devfs
genfscon devfs /			system_u:object_r:device_t
genfscon devfs /.devfsd			system_u:object_r:devfs_control_t
genfscon devfs /null			system_u:object_r:null_device_t
genfscon devfs /zero			system_u:object_r:zero_device_t
genfscon devfs /console		system_u:object_r:console_device_t
genfscon devfs /kmem			system_u:object_r:memory_device_t
genfscon devfs /mem			system_u:object_r:memory_device_t
genfscon devfs /port			system_u:object_r:memory_device_t
genfscon devfs /random		system_u:object_r:random_device_t
genfscon devfs /urandom		system_u:object_r:random_device_t
genfscon devfs /tty	-c		system_u:object_r:devtty_t
genfscon devfs /tts	-c		system_u:object_r:tty_device_t
genfscon devfs /vc -c			system_u:object_r:tty_device_t
genfscon devfs /pts			system_u:object_r:devpts_t
genfscon devfs /scsi	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /ide	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /rd	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /md	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /cdroms -b		system_u:object_r:removable_device_t
genfscon devfs /floppy -b		system_u:object_r:removable_device_t
genfscon devfs /evms	-c		system_u:object_r:fixed_disk_device_t
genfscon devfs /evms	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /ubd	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /cciss	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /ida	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /dasd	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /flash	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /ataraid	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /loop	-b		system_u:object_r:fixed_disk_device_t
genfscon devfs /misc/rtc		system_u:object_r:clock_device_t
genfscon devfs /net/tun			system_u:object_r:tun_tap_device_t
#line 86

#line 91

genfscon devfs /ppp			system_u:object_r:ppp_device_t
genfscon devfs /fb	-c		system_u:object_r:framebuf_device_t
genfscon devfs /initctl		system_u:object_r:initctl_t
#line 97

genfscon devfs /misc/psaux		system_u:object_r:mouse_device_t
genfscon devfs /misc/nvram		system_u:object_r:memory_device_t
genfscon devfs /input/mouse		system_u:object_r:mouse_device_t
genfscon devfs /input/mice		system_u:object_r:mouse_device_t
genfscon devfs /input/event		system_u:object_r:mouse_device_t
genfscon devfs /cpu/mtrr		system_u:object_r:mtrr_device_t
genfscon devfs /v4l	-c		system_u:object_r:mtrr_device_t
#line 107

genfscon devfs /ptmx			system_u:object_r:ptmx_t
genfscon devfs /misc/apm_bios		system_u:object_r:apm_bios_t
genfscon devfs /sound -c		system_u:object_r:sound_device_t
#line 114


#line 118


# romfs
genfscon romfs /			system_u:object_r:root_t
genfscon romfs /bin			system_u:object_r:bin_t
genfscon romfs /bin/mount		system_u:object_r:mount_exec_t
genfscon romfs /bin/umount		system_u:object_r:mount_exec_t
genfscon romfs /bin/ash			system_u:object_r:shell_exec_t
genfscon romfs /etc			system_u:object_r:etc_t
genfscon romfs /lib			system_u:object_r:lib_t
genfscon romfs /lib/ld-linux.so.2	system_u:object_r:ld_so_t
genfscon romfs /lib/libc.so.6		system_u:object_r:shlib_t
genfscon romfs /lib/modules		system_u:object_r:modules_object_t
genfscon romfs /linuxrc			system_u:object_r:init_exec_t
genfscon romfs /linuxrc.conf		system_u:object_r:etc_t
genfscon romfs /loadmodules		system_u:object_r:shell_exec_t
genfscon romfs /sbin			system_u:object_r:sbin_t
genfscon romfs /sbin/init		system_u:object_r:init_exec_t
genfscon romfs /sbin/insmod		system_u:object_r:insmod_exec_t
genfscon romfs /sbin/modprobe		system_u:object_r:insmod_exec_t
genfscon romfs /scripts			system_u:object_r:sbin_t
genfscon romfs /tmp			system_u:object_r:tmp_t
genfscon romfs /usr			system_u:object_r:sbin_t
#line 1 "net_contexts"
# FLASK

#
# Security contexts for network entities
# If no context is specified, then a default initial SID is used.
#

# Modified by Reino Wallin <reino@oribium.com>
# Multi NIC, and IPSEC features

# Modified by Russell Coker
# ifdefs to encapsulate domains, and many additional port contexts

#
# Port numbers (default = initial SID 'port')
# 
# protocol number context
# protocol low-high context
#



portcon tcp 22 system_u:object_r:ssh_port_t


#line 27




#line 35

#line 39


#line 48


#line 54








#line 66

#line 70








# Network interfaces (default = initial SID 'netif' and 'netmsg')
#
# interface netif_context default_msg_context
#
netifcon lo system_u:object_r:netif_lo_t system_u:object_r:netmsg_lo_t
netifcon eth0 system_u:object_r:netif_eth0_t system_u:object_r:netmsg_eth0_t
netifcon eth1 system_u:object_r:netif_eth1_t system_u:object_r:netmsg_eth1_t
netifcon eth2 system_u:object_r:netif_eth2_t system_u:object_r:netmsg_eth2_t
netifcon ippp0 system_u:object_r:netif_ippp0_t system_u:object_r:netmsg_ippp0_t
netifcon ipsec0 system_u:object_r:netif_ipsec0_t system_u:object_r:netmsg_ipsec0_t
netifcon ipsec1 system_u:object_r:netif_ipsec1_t system_u:object_r:netmsg_ipsec1_t
netifcon ipsec2 system_u:object_r:netif_ipsec2_t system_u:object_r:netmsg_ipsec2_t

# Nodes (default = initial SID 'node')
#
# address mask context
#
# The first matching entry is used.
#
nodecon 127.0.0.1 255.255.255.255 system_u:object_r:node_lo_t

# FLASK
