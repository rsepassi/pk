
/*
 * *********** WARNING **************
 * This file generated by ModPerl::WrapXS/0.01
 * Any changes made here will be lost
 * ***********************************
 * 01: /AppleInternal/Library/BuildRoots/0032d1ee-80fd-11ee-8227-6aecfccc70fe/Library/Caches/com.apple.xbs/Binaries/apache_mod_perl/install/TempContent/Objects/mod_perl-2.0.9/blib/lib/ModPerl/WrapXS.pm:708
 * 02: /AppleInternal/Library/BuildRoots/0032d1ee-80fd-11ee-8227-6aecfccc70fe/Library/Caches/com.apple.xbs/Binaries/apache_mod_perl/install/TempContent/Objects/mod_perl-2.0.9/blib/lib/ModPerl/WrapXS.pm:1170
 * 03: Makefile.PL:435
 * 04: Makefile.PL:333
 * 05: Makefile.PL:59
 */


#ifndef MODPERL_XS_TYPEDEFS_H
#define MODPERL_XS_TYPEDEFS_H

#include "apr_uuid.h"
#include "apr_sha1.h"
#include "apr_md5.h"
#include "apr_base64.h"
#include "apr_getopt.h"
#include "apr_hash.h"
#include "apr_lib.h"
#include "apr_general.h"
#include "apr_signal.h"
#include "apr_thread_rwlock.h"
#include "util_script.h"
typedef apr_array_header_t * APR__ArrayHeader;
typedef apr_bucket_brigade * APR__Brigade;
typedef apr_bucket * APR__Bucket;
typedef apr_bucket_alloc_t * APR__BucketAlloc;
typedef apr_bucket_type_t * APR__BucketType;
typedef apr_time_exp_t * APR__ExplodedTime;
typedef apr_finfo_t * APR__Finfo;
typedef apr_getopt_t * APR__Getopt;
typedef apr_getopt_option_t * APR__GetoptOption;
typedef apr_hash_t * APR__Hash;
typedef apr_in_addr_t * APR__InAddr;
typedef apr_ipsubnet_t * APR__IpSubnet;
typedef apr_md5_ctx_t * APR__MD5;
typedef apr_mmap_t * APR__Mmap;
typedef apr_pool_t * APR__Pool;
typedef apr_proc_t * APR__Process;
typedef apr_sha1_ctx_t * APR__SHA1;
typedef apr_sockaddr_t * APR__SockAddr;
typedef apr_socket_t * APR__Socket;
typedef apr_table_t * APR__Table;
typedef apr_thread_mutex_t * APR__ThreadMutex;
typedef apr_thread_rwlock_t * APR__ThreadRWLock;
typedef apr_uri_t * APR__URI;
typedef apr_uuid_t * APR__UUID;
typedef cmd_parms * Apache2__CmdParms;
typedef command_rec * Apache2__Command;
typedef ap_conf_vector_t * Apache2__ConfVector;
typedef ap_configfile_t * Apache2__ConfigFile;
typedef conn_rec * Apache2__Connection;
typedef ap_directive_t * Apache2__Directive;
typedef ap_filter_t * Apache2__Filter;
typedef ap_filter_rec_t * Apache2__FilterRec;
typedef ap_method_list_t * Apache2__MethodList;
typedef module * Apache2__Module;
typedef modperl_filter_t * Apache2__OutputFilter;
typedef piped_log * Apache2__PipedLog;
typedef process_rec * Apache2__Process;
typedef request_rec * Apache2__RequestRec;
typedef server_addr_rec * Apache2__ServerAddr;
typedef server_rec * Apache2__ServerRec;
typedef subrequest_rec * Apache2__SubRequest;
typedef modperl_interp_pool_t * ModPerl__InterpPool;
typedef modperl_interp_t * ModPerl__Interpreter;
typedef modperl_tipool_t * ModPerl__TiPool;
typedef modperl_tipool_config_t * ModPerl__TiPoolConfig;

#endif /* MODPERL_XS_TYPEDEFS_H */
