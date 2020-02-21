#ifndef __BEVGRIND_H
#define __BEVGRIND_H

#define BG_(str)		VGAPPEND(vgBevgrind_,str)

#define BAIDU_1503		1
#define QIHOO_1603		0
#define IJIAMI_1603		0
#define BANGCLE_1603	0
#define BANGCLE_1503	1
#define M_PERFORMANCE 1

//#define ONLY_DUMP	0
#define TRACE_DVM_PLATFORM		1
//#define TRACE_ART_PLATFORM	1


//#define BANGCLE_ART_1603		1



typedef	unsigned short	sa_family_t;
typedef int							socklen_t;

struct sockaddr {
	UShort sa_family;
	UChar sa_data[14];
};

struct in_addr {
	unsigned long s_addr;
};

struct sockaddr_in {
	Short	sa_family;
	UShort	sa_port;
	struct	in_addr	addr;
	HChar		sa_zero[8];
};

#define AF_UNSPEC       0
#define AF_UNIX         1       /* Unix domain sockets          */
#define AF_LOCAL        1       /* POSIX name for AF_UNIX       */
#define AF_INET         2       /* Internet IP Protocol         */

#define NTOHL(n)	((((n) & 0xff) << 24)	\
		| (((n) & 0xff00) << 8) \
		| (((n) & 0xff0000) >> 8) \
		| (((n) & 0xff000000) >> 24))

#define HTONL(n)	((((n) & 0xff) << 24)	\
		| (((n) & 0xff00) << 8) \
		| (((n) & 0xff0000) >> 8) \
		| (((n) & 0xff000000) >> 24))

#define NTOHS(n)	((((UShort)(n) & 0xff00) >> 8) \
		| (((UShort)(n) & 0x00ff) << 8))

#define HTONS(n)	((((UShort)(n) & 0xff00) >> 8) \
		| (((UShort)(n) & 0x00ff) << 8))

/* Copy from mman.h */
#define PROT_NONE       0x00            /* page can not be accessed */
#define PROT_READ       0x01            /* page can be read */
#define PROT_WRITE      0x02            /* page can be written */
#define PROT_EXEC       0x04            /* page can be executed */

#define MAP_SHARED	0x01			/* Share changes.  */
#define MAP_PRIVATE	0x02			/* Changes are private.  */

#define MAP_FIXED	0x10				/* Interpret addr exactly.  */
#define MAP_FILE	0
#define MAP_ANONYMOUS	0x20    /* Don't use a file.  */
#define MAP_ANON	MAP_ANONYMOUS

#define MAP_DENYWRITE	0x0800  /* ETXTBSY */
#define MAP_FOOBAR	0x0800  /* ETXTBSY */

/* End */

/* (from /dalvik/vm/Thread.h)
 * Current status; these map to JDWP constants, so don't rearrange them.
 * (If you do alter this, update the strings in dvmDumpThread and the
 * conversion table in VMThread.java.)
 *   
 * Note that "suspended" is orthogonal to these values (so says JDWP).
 */
typedef
enum {
	THREAD_UNDEFINED    = -1,       /* makes enum compatible with int32_t */

	/* these match up with JDWP values */
	THREAD_ZOMBIE       = 0,        /* TERMINATED */
	THREAD_RUNNING      = 1,        /* RUNNABLE or running now */
	THREAD_TIMED_WAIT   = 2,        /* TIMED_WAITING in Object.wait() */
	THREAD_MONITOR      = 3,        /* BLOCKED on a monitor */
	THREAD_WAIT         = 4,        /* WAITING in Object.wait() */
	/* non-JDWP states */
	THREAD_INITIALIZING = 5,        /* allocated, not yet running */
	THREAD_STARTING     = 6,        /* started, not yet on thread list */
	THREAD_NATIVE       = 7,        /* off in a JNI native method */
	THREAD_VMWAIT       = 8,        /* waiting on a VM resource */
	THREAD_SUSPENDED    = 9,        /* suspended, usually by GC or debugger */
} ThreadStatus;

typedef 
enum {
	/*--- Taint infor related requests                        ---*/
	VG_USERREQ__MAKE_MEM_NOACCESS,
	VG_USERREQ__COPY_MEM_TAINT,
	VG_USERREQ__MAKE_MEM_TAINTED,
	VG_USERREQ__CHECK_MEM_TAINTED,
	VG_USERREQ__MAKE_MEM_UNTAINTED,
	VG_USERREQ__WRAPPER_GETTIMEOFDAY,
	VG_USERREQ__WRAPPER_SIGPROCMASK,
	VG_USERREQ__WRAPPER_SIGACTION,
	VG_USERREQ__WRAPPER_SIGNAL,
	VG_USERREQ__WRAPPER_READ,
	VG_USERREQ__WRAPPER_WRITE,
	VG_USERREQ__WRAPPER_SOCKET,
	VG_USERREQ__WRAPPER_LISTEN,
	VG_USERREQ__WRAPPER_BIND,
	VG_USERREQ__WRAPPER_ACCEPT,
	VG_USERREQ__WRAPPER_CONNECT_PRE,
	VG_USERREQ__WRAPPER_CONNECT,
	VG_USERREQ__WRAPPER_STRCMP,
	VG_USERREQ__WRAPPER_STRNCMP,
	VG_USERREQ__WRAPPER_STRSTR,
	VG_USERREQ__WRAPPER_MEMCHR,
	VG_USERREQ__WRAPPER_SEND,
	VG_USERREQ__WRAPPER_SENDTO,
	VG_USERREQ__WRAPPER_RECV_PRE,
	VG_USERREQ__WRAPPER_RECV,
	VG_USERREQ__WRAPPER_RECVFROM_PRE,
	VG_USERREQ__WRAPPER_RECVFROM,
	VG_USERREQ__WRAPPER_SHUTDOWN,
	VG_USERREQ__WRAPPER_DLOPEN,
	VG_USERREQ__WRAPPER_OPEN,
	VG_USERREQ__WRAPPER_FOPEN,
	VG_USERREQ__WRAPPER_FSEEK,
	VG_USERREQ__WRAPPER_LSEEK,
	VG_USERREQ__WRAPPER_FREAD,
	VG_USERREQ__WRAPPER_FWRITE,
	VG_USERREQ__WRAPPER_CLOSE,
	VG_USERREQ__WRAPPER_FCLOSE,
	VG_USERREQ__WRAPPER_MMAP,
	VG_USERREQ__WRAPPER_MUNMAP,
	VG_USERREQ__WRAPPER_MPROTECT,
	VG_USERREQ__WRAPPER_MADVISE,
	VG_USERREQ__WRAPPER_MADVISE_PRE,
	VG_USERREQ__WRAPPER_EXIT_PRE,
	VG_USERREQ__WRAPPER_PTRACE,
#ifdef TRACE_DVM_PLATFORM
	VG_USERREQ__WRAPPER_DEXFILEPARSE_PRE,
	VG_USERREQ__WRAPPER_DEXFILEPARSE,
	VG_USERREQ__WRAPPER_DVMCONOPT_PRE,
	VG_USERREQ__WRAPPER_DVMCONOPT,
	VG_USERREQ__WRAPPER_DVMINVOKEMTH_PRE,
	VG_USERREQ__WRAPPER_DVMINVOKEMTH,
	VG_USERREQ__WRAPPER_DVMCALLMETHOD_PRE,
	VG_USERREQ__WRAPPER_DVMCALLMETHOD,
	VG_USERREQ__WRAPPER_DVMCALLJNIMTH_PRE,
	VG_USERREQ__WRAPPER_DVMCALLJNIMTH,
	VG_USERREQ__WRAPPER_DVMFINDCLASSBYNAME_PRE,
	VG_USERREQ__WRAPPER_DVMFINDCLASSBYNAME,
	VG_USERREQ__WRAPPER_DVMDEFINECLASS_PRE,
	VG_USERREQ__WRAPPER_DVMDEFINECLASS,
	VG_USERREQ__WRAPPER_DVMLOADNATIVE_PRE,
	VG_USERREQ__WRAPPER_DVMLOADNATIVE,
	VG_USERREQ__WRAPPER_DVMPREPAREDEX_PRE,
	VG_USERREQ__WRAPPER_DVMPREPAREDEX,
	VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN_PRE,
	VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN,
	VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY_PRE,
	VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY,
	VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD_PRE,
	VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD,
	VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL_PRE,
	VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL,
	VG_USERREQ__WRAPPER_DVMINTERPRET_PRE,
	VG_USERREQ__WRAPPER_DVMINTERPRET,
	VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE_PRE,
	VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE,
	VG_USERREQ__WRAPPER_DVMMTERPSTD_PRE,
	VG_USERREQ__WRAPPER_DVMMTERPSTD,
	VG_USERREQ__WRAPPER_DVMMTERPSTDRUN_PRE,
	VG_USERREQ__WRAPPER_DVMMTERPSTDRUN,
	VG_USERREQ__WRAPPER_DVMCHANGESTATUS,
#endif
	//VG_USERREQ__WRAPPER_CALLPREP,
#ifdef TRACE_ART_PLATFORM
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE,
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS,
	VG_USERREQ__WRAPPER_ART_DEXFILE_PRE,
	VG_USERREQ__WRAPPER_ART_DEXFILE,
	VG_USERREQ__WRAPPER_ART_TEST_PRE,
	VG_USERREQ__WRAPPER_ART_TEST,
#endif
#if 0
	VG_USERREQ__START_MEM_TAINT,
	VG_USERREQ__STOP_MEM_TAINT,
	VG_USERREQ__DISCARD_INS_CACHE,
	VG_USERREQ__WRAPPER_LISTEN,
	VG_USERREQ__WRAPPER_ACCEPT,
	VG_USERREQ__WRAPPER_CONNECT,
	VG_USERREQ__WRAPPER_SENDMSG,
	VG_USERREQ__WRAPPER_RECVMSG,
#endif
	VG_USERREQ__WRAPPER_SYSTEM
} Vg_DatatraceClientRequest;

/* Client-code macros to manipulate the state of memory. */

#define VALGRIND_DISCARD_INS_CACHE(_qzz_s)\
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0/* default return */,\
			VG_USERREQ__DISCARD_INS_CACHE,\
			(_qzz_s), 0, 0, 0, 0)

/* Check memory taint information */
#define VALGRIND_CHECK_MEM_TAINTED(_qzz_s, _qzz_addr, _qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0/* default return */,\
			VG_USERREQ__CHECK_MEM_TAINTED,\
			(_qzz_s), (_qzz_addr), (_qzz_len), 0, 0)

/* Mark memory at _qzz_addr as unaddressable for _qzz_len bytes. */
#define VALGRIND_MAKE_MEM_NOACCESS(_qzz_s, _qzz_addr,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,\
			VG_USERREQ__MAKE_MEM_NOACCESS,\
			(_qzz_s), (_qzz_addr), (_qzz_len), 0, 0)

/* Similarly, mark memory at _qzz_addr as addressable but undefined
	 for _qzz_len bytes. */
#define VALGRIND_MAKE_MEM_TAINTED(_qzz_s, _qzz_addr,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,\
			VG_USERREQ__MAKE_MEM_TAINTED,\
			(_qzz_s), (_qzz_addr), (_qzz_len), 0, 0)

/* Similarly, mark memory at _qzz_addr as addressable and defined
	 for _qzz_len bytes. */
#define VALGRIND_MAKE_MEM_UNTAINTED(_qzz_s, _qzz_addr,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,\
			VG_USERREQ__MAKE_MEM_UNTAINTED,\
			(_qzz_s), (_qzz_addr), (_qzz_len), 0, 0)

#define VALGRIND_COPY_MEM_TAINT(_qzz_s, _qzz_src, _qzz_dst ,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,\
			VG_USERREQ__COPY_MEM_TAINT,\
			(_qzz_s), (_qzz_src), (_qzz_dst), (_qzz_len), 0)
#if 0
/* Similar to VALGRIND_MAKE_MEM_DEFINED except that addressability is
	 not altered: bytes which are addressable are marked as defined,
	 but those which are not addressable are left unchanged. */
#define VALGRIND_MAKE_MEM_DEFINED_IF_ADDRESSABLE(_qzz_addr,_qzz_len)     \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,              \
			VG_USERREQ__MAKE_MEM_DEFINED_IF_ADDRESSABLE, \
			(_qzz_addr), (_qzz_len), 0, 0, 0)

/* Create a block-description handle.  The description is an ascii
	 string which is included in any messages pertaining to addresses
	 within the specified memory range.  Has no other effect on the
	 properties of the memory range. */
#define VALGRIND_CREATE_BLOCK(_qzz_addr,_qzz_len, _qzz_desc)	   \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,        \
			VG_USERREQ__CREATE_BLOCK,              \
			(_qzz_addr), (_qzz_len), (_qzz_desc),  \
			0, 0)

/* Discard a block-description-handle. Returns 1 for an
	 invalid handle, 0 for a valid handle. */
#define VALGRIND_DISCARD(_qzz_blkindex)                          \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,      \
			VG_USERREQ__DISCARD,                 \
			0, (_qzz_blkindex), 0, 0, 0)


/* Client-code macros to check the state of memory. */

/* Check that memory at _qzz_addr is addressable for _qzz_len bytes.
	 If suitable addressibility is not established, Valgrind prints an
	 error message and returns the address of the first offending byte.
	 Otherwise it returns zero. */
#define VALGRIND_CHECK_MEM_IS_ADDRESSABLE(_qzz_addr,_qzz_len)      \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                             \
			VG_USERREQ__CHECK_MEM_IS_ADDRESSABLE,  \
			(_qzz_addr), (_qzz_len), 0, 0, 0)

/* Check that memory at _qzz_addr is addressable and defined for
	 _qzz_len bytes.  If suitable addressibility and definedness are not
	 established, Valgrind prints an error message and returns the
	 address of the first offending byte.  Otherwise it returns zero. */
#define VALGRIND_CHECK_MEM_IS_DEFINED(_qzz_addr,_qzz_len)        \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                           \
			VG_USERREQ__CHECK_MEM_IS_DEFINED,    \
			(_qzz_addr), (_qzz_len), 0, 0, 0)

/* Use this macro to force the definedness and addressibility of an
	 lvalue to be checked.  If suitable addressibility and definedness
	 are not established, Valgrind prints an error message and returns
	 the address of the first offending byte.  Otherwise it returns
	 zero. */
#define VALGRIND_CHECK_VALUE_IS_DEFINED(__lvalue)                \
	VALGRIND_CHECK_MEM_IS_DEFINED(                                \
			(volatile unsigned char *)&(__lvalue),                     \
			(unsigned long)(sizeof (__lvalue)))


/* Do a full memory leak check (like --leak-check=full) mid-execution. */
#define VALGRIND_DO_LEAK_CHECK                                   \
	VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DO_LEAK_CHECK,   \
			0, 0, 0, 0, 0)

/* Same as VALGRIND_DO_LEAK_CHECK but only showing the entries for
	 which there was an increase in leaked bytes or leaked nr of blocks
	 since the previous leak search. */
#define VALGRIND_DO_ADDED_LEAK_CHECK                            \
	VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DO_LEAK_CHECK,  \
			0, 1, 0, 0, 0)

/* Same as VALGRIND_DO_ADDED_LEAK_CHECK but showing entries with
	 increased or decreased leaked bytes/blocks since previous leak
	 search. */
#define VALGRIND_DO_CHANGED_LEAK_CHECK                          \
	VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DO_LEAK_CHECK,  \
			0, 2, 0, 0, 0)

/* Do a summary memory leak check (like --leak-check=summary) mid-execution. */
#define VALGRIND_DO_QUICK_LEAK_CHECK                             \
	VALGRIND_DO_CLIENT_REQUEST_STMT(VG_USERREQ__DO_LEAK_CHECK,   \
			1, 0, 0, 0, 0)

/* Return number of leaked, dubious, reachable and suppressed bytes found by
	 all previous leak checks.  They must be lvalues.  */
#define VALGRIND_COUNT_LEAKS(leaked, dubious, reachable, suppressed)     \
	/* For safety on 64-bit platforms we assign the results to private
		 unsigned long variables, then assign these to the lvalues the user
		 specified, which works no matter what type 'leaked', 'dubious', etc
		 are.  We also initialise '_qzz_leaked', etc because
		 VG_USERREQ__COUNT_LEAKS doesn't mark the values returned as
		 defined. */                                                        \
{                                                                     \
	unsigned long _qzz_leaked    = 0, _qzz_dubious    = 0;               \
		unsigned long _qzz_reachable = 0, _qzz_suppressed = 0;               \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                                     \
				VG_USERREQ__COUNT_LEAKS,                  \
				&_qzz_leaked, &_qzz_dubious,              \
				&_qzz_reachable, &_qzz_suppressed, 0);    \
		leaked     = _qzz_leaked;                                            \
		dubious    = _qzz_dubious;                                           \
		reachable  = _qzz_reachable;                                         \
		suppressed = _qzz_suppressed;                                        \
}

/* Return number of leaked, dubious, reachable and suppressed bytes found by
	 all previous leak checks.  They must be lvalues.  */
#define VALGRIND_COUNT_LEAK_BLOCKS(leaked, dubious, reachable, suppressed) \
	/* For safety on 64-bit platforms we assign the results to private
		 unsigned long variables, then assign these to the lvalues the user
		 specified, which works no matter what type 'leaked', 'dubious', etc
		 are.  We also initialise '_qzz_leaked', etc because
		 VG_USERREQ__COUNT_LEAKS doesn't mark the values returned as
		 defined. */                                                        \
{                                                                     \
	unsigned long _qzz_leaked    = 0, _qzz_dubious    = 0;               \
		unsigned long _qzz_reachable = 0, _qzz_suppressed = 0;               \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                                     \
				VG_USERREQ__COUNT_LEAK_BLOCKS,            \
				&_qzz_leaked, &_qzz_dubious,              \
				&_qzz_reachable, &_qzz_suppressed, 0);    \
		leaked     = _qzz_leaked;                                            \
		dubious    = _qzz_dubious;                                           \
		reachable  = _qzz_reachable;                                         \
		suppressed = _qzz_suppressed;                                        \
}


/* Get the validity data for addresses [zza..zza+zznbytes-1] and copy it
	 into the provided zzvbits array.  Return values:
	 0   if not running on valgrind
	 1   success
	 2   [previously indicated unaligned arrays;  these are now allowed]
	 3   if any parts of zzsrc/zzvbits are not addressable.
	 The metadata is not copied in cases 0, 2 or 3 so it should be
	 impossible to segfault your system by using this call.
	 */
#define VALGRIND_GET_VBITS(zza,zzvbits,zznbytes)                \
	(unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                \
			VG_USERREQ__GET_VBITS,      \
			(const char*)(zza),         \
			(char*)(zzvbits),           \
			(zznbytes), 0, 0)

/* Set the validity data for addresses [zza..zza+zznbytes-1], copying it
	 from the provided zzvbits array.  Return values:
	 0   if not running on valgrind
	 1   success
	 2   [previously indicated unaligned arrays;  these are now allowed]
	 3   if any parts of zza/zzvbits are not addressable.
	 The metadata is not copied in cases 0, 2 or 3 so it should be
	 impossible to segfault your system by using this call.
	 */
#define VALGRIND_SET_VBITS(zza,zzvbits,zznbytes)                \
	(unsigned)VALGRIND_DO_CLIENT_REQUEST_EXPR(0,                \
			VG_USERREQ__SET_VBITS,      \
			(const char*)(zza),         \
			(const char*)(zzvbits),     \
			(zznbytes), 0, 0 )

/* Disable and re-enable reporting of addressing errors in the
	 specified address range. */
#define VALGRIND_DISABLE_ADDR_ERROR_REPORTING_IN_RANGE(_qzz_addr,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,    \
			VG_USERREQ__DISABLE_ADDR_ERROR_REPORTING_IN_RANGE,      \
			(_qzz_addr), (_qzz_len), 0, 0, 0)

#define VALGRIND_ENABLE_ADDR_ERROR_REPORTING_IN_RANGE(_qzz_addr,_qzz_len) \
	VALGRIND_DO_CLIENT_REQUEST_EXPR(0 /* default return */,    \
			VG_USERREQ__ENABLE_ADDR_ERROR_REPORTING_IN_RANGE,       \
			(_qzz_addr), (_qzz_len), 0, 0, 0)
#endif




//typedef UInt size_t;

#undef DO_CREQ_v_W
#undef DO_CREQ_W_W
#undef DO_CREQ_v_WW
#undef DO_CREQ_W_WW
#undef DO_CREQ_v_WWW
#undef DO_CREQ_W_WWW

#define DO_CREQ_v_W(_creqF, _ty1F,_arg1F)                \
	do {                                                  \
		long int _arg1;                                    \
		_arg1 = (long int)(_arg1F);                        \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
				(_creqF),               \
				_arg1, 0,0,0,0);        \
	} while (0)

#define DO_CREQ_W_W(_resF, _dfltF, _creqF, _ty1F,_arg1F) \
	do {                                                  \
		long int _arg1;                                    \
		_arg1 = (long int)(_arg1F);                        \
		_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(        \
				(_dfltF),               \
				(_creqF),               \
				_arg1, 0,0,0,0);        \
		_resF = _qzz_res;                                  \
	} while (0)

#define DO_CREQ_v_WW(_creqF, _ty1F,_arg1F, _ty2F,_arg2F) \
	do {                                                  \
		long int _arg1, _arg2;                             \
		_arg1 = (long int)(_arg1F);                        \
		_arg2 = (long int)(_arg2F);                        \
		VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
				(_creqF),               \
				_arg1,_arg2,0,0,0);     \
	} while (0)

#define DO_CREQ_v_WWW(_creqF, _ty1F,_arg1F,              \
		_ty2F,_arg2F, _ty3F, _arg3F)       \
do {                                                  \
	long int _arg1, _arg2, _arg3;                      \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	VALGRIND_DO_CLIENT_REQUEST_STMT(                   \
			(_creqF),               \
			_arg1,_arg2,_arg3,0,0); \
} while (0)

#define DO_CREQ_W_WWW(_resF, _dfltF, _creqF, _ty1F,_arg1F, \
		_ty2F,_arg2F, _ty3F, _arg3F)       \
do {                                                  \
	long int _qzz_res;                                 \
	long int _arg1, _arg2, _arg3;                      \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	_qzz_res = VALGRIND_DO_CLIENT_REQUEST_EXPR(        \
			(_dfltF),               \
			(_creqF),               \
			_arg1,_arg2,_arg3,0,0); \
	_resF = _qzz_res;                                  \
} while (0)

#define DO_CREQ_v_WWWW(_creqF, _ty1F, _arg1F,         \
		_ty2F, _arg2F, _ty3F, _arg3F,     \
		_ty4F, _arg4F)                    \
do {                                                  \
	long int _arg1, _arg2, _arg3, _arg4;                \
	_arg1 = (long int)(_arg1F);                         \
	_arg2 = (long int)(_arg2F);                         \
	_arg3 = (long int)(_arg3F);                         \
	_arg4 = (long int)(_arg4F);                         \
	VALGRIND_DO_CLIENT_REQUEST_STMT(										\
			(_creqF),										\
			_arg1,_arg2,_arg3,_arg4,0); \
} while (0)

#define DO_CREQ_v_WWWWW(_creqF, _ty1F,_arg1F,        \
		_ty2F, _arg2F, _ty3F, _arg3F,     \
		_ty4F, _arg4F, _ty5F, _arg5F)     \
do {                                                 \
	long int _arg1, _arg2, _arg3, _arg4, _arg5;        \
	_arg1 = (long int)(_arg1F);                        \
	_arg2 = (long int)(_arg2F);                        \
	_arg3 = (long int)(_arg3F);                        \
	_arg4 = (long int)(_arg4F);                        \
	_arg5 = (long int)(_arg5F);												 \
	VALGRIND_DO_CLIENT_REQUEST_STMT(									 \
			(_creqF),							          \
			_arg1,_arg2,_arg3,_arg4,_arg5); \
} while (0)

#endif // __BEVGRIND_H
