#ifndef __PACKERRIND_H
#define __PACKERRIND_H

//#include "valgrind.h"
//#define BAIDU_1503		1
//#define QIHOO_1603		1
//#define IJIAMI_1603		1
//#define BANGCLE_1603	1
//#define IJIAMI_1603			0
//#define ONLY_DUMP			1
//#define APK_PROTECT		1	
//#define M_PERFORMANCE	1

//#define TRACE_DVM_PLATFORM	1
#define TRACE_ART_PLATFORM		1
#define BANGCLE_ART_1603			0


#define TG_N_THREADS 500 

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
};

typedef 
enum {
	/*--- Taint infor related requests                        ---*/
	VG_USERREQ__MAKE_MEM_NOACCESS,
	VG_USERREQ__WRAPPER_GETTIMEOFDAY,
	VG_USERREQ__WRAPPER_SETITIMER,
	VG_USERREQ__WRAPPER_TIMER_SETTIME,
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
	VG_USERREQ__WRAPPER_MEMCMP,
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
	VG_USERREQ__WRAPPER_SYSTEM,
	
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE,
	VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE,
	VG_USERREQ__WRAPPER_ART_DEFINECLASS,
	VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE_PRE,
	VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE,
	VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE_PRE,
	VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE,
	VG_USERREQ__WRAPPER_ART_REGISTERNATIVE,
	VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD,
	VG_USERREQ__WRAPPER_ART_JNIGETMETHODID,
	VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID,
	VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD_PRE,
	VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD,
	VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE_PRE,
	VG_USERREQ__WRAPPER_ART_EXECUTESWITCH_PRE,
	VG_USERREQ__WRAPPER_ART_EXECUTESWITCH,
	VG_USERREQ__WRAPPER_ART_EXECUTEGOTO_PRE,
	VG_USERREQ__WRAPPER_ART_EXECUTEGOTO,
	VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE,
	VG_USERREQ__WRAPPER_ART_OATFILESETUP_PRE,
	VG_USERREQ__WRAPPER_ART_OATFILESETUP,
	VG_USERREQ__WRAPPER_ART_OATFILEOPEN_PRE,
	VG_USERREQ__WRAPPER_ART_OATFILEOPEN,
	VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE_PRE,
	VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE,
	VG_USERREQ__WRAPPER_ART_OPENDEXFILE_PRE,
	VG_USERREQ__WRAPPER_ART_OPENDEXFILE,
	VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY_PRE,
	VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY,
	VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT_PRE,
	VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT,
	VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES_PRE,
	VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES,
	VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE_PRE,
	VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE,
	VG_USERREQ__WRAPPER_ART_ENTERINTERPRETERFROMINVOKE_PRE,
	VG_USERREQ__WRAPPER_ART_TEST_PRE,
	VG_USERREQ__WRAPPER_ART_TEST
} Vg_DatatraceClientRequest;


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
