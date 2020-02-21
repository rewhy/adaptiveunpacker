#ifndef _BG_WRAPPERS_h
#define _BG_WRAPPERS_h

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_hashtable.h"


#include "pg_translate.h"

#define	STACK_TRACE_SIZE					20
#define	BG_MALLOC_REDZONE_SZB			16


struct iovec {
	Addr  iov_base;
	Int		iov_len;
};


enum OpenedFdType { 
	FdSystemLib = 1,
	FdFrameworkJar,
	FdFrameworkDex,
	FdDevice,
	FdProcMap,
	FdAppLib,
	FdAppDex,
	FdAppApk,
	FdAppJar,
	FdUnknown
};

struct fd_info {
	HChar name[255];
	UInt	offset;
	enum OpenedFdType  type;
};

struct MemList {
	HChar	name[255];
	Addr	addr;
	Int		size;
	Int   prot;
	struct MemList *next;
};
/*-------------------- From bg_translate.c -------------------*/
void addMemMap(Addr addr, Int size, Int prot, HChar *info);
Bool getMemMapInfo(Addr addr, Int prot, HChar **pinfo); 
void delMemMap(Addr addr, Int size);
/*------------------------------------------------------------*/
/*--- Profiling of memory events                           ---*/
/*------------------------------------------------------------*/

/* Define to collect detailed performance info. */
// #define BG_PROFILE_MEMORY

#ifdef BG_PROFILE_MEMORY
#  define N_PROF_EVENTS 500

UInt   BG_(event_ctr)[N_PROF_EVENTS];
HChar* BG_(event_ctr_name)[N_PROF_EVENTS];

#  define PROF_EVENT(ev, name) \
	do { tl_assert((ev) >= 0 && (ev) < N_PROF_EVENTS);     \
		/* crude and inaccurate check to ensure the same */  \
		/* event isn't being used with > 1 name */           \
		if (BG_(event_ctr_name)[ev])                         \
		tl_assert(name == BG_(event_ctr_name)[ev]);          \
		BG_(event_ctr)[ev]++;                                \
		BG_(event_ctr_name)[ev] = (name);                    \
	} while (False);
#else
#  define PROF_EVENT(ev, name) /* */
#endif   /* BG_PROFILE_MEMORY */



/* This describes a heap block. Nb: first two fields must match core's 
 * VgHashNode. */
typedef struct _HP_Chunk {
	struct	_HP_Chunk *next;
	Addr		data;								// Address of the actual block
	SizeT		req_szB;						// Size requested
	SizeT		slop_szB;						// Extra bytes given above those requested
} HP_Chunk;

extern	VgHashTable	*BG_(malloc_list);

void* BG_(malloc)               ( ThreadId tid, SizeT n );                                                                                                                      
void* BG_(__builtin_new)        ( ThreadId tid, SizeT n );                                                                                                                      
void* BG_(__builtin_vec_new)    ( ThreadId tid, SizeT n );                                                                                                                      
void* BG_(memalign)             ( ThreadId tid, SizeT align, SizeT n );                                                                                                         
void* BG_(calloc)               ( ThreadId tid, SizeT nmemb, SizeT size1 );                                                                                                     
void  BG_(free)                 ( ThreadId tid, void* p );                                                                                                                      
void  BG_(__builtin_delete)     ( ThreadId tid, void* p );                                                                                                                      
void  BG_(__builtin_vec_delete) ( ThreadId tid, void* p );                                                                                                                      
void* BG_(realloc)              ( ThreadId tid, void* p, SizeT new_size );                                                                                                      
SizeT BG_(malloc_usable_size)   ( ThreadId tid, void* p );  


/* Functions defined in dt_syswrap.c */
/* System call wrappers */
extern void BG_(syscall_execv)(tid, args, nArgs);
extern void BG_(syscall_pre_unlinkat)(tid, args, nArgs);

extern void BG_(syscall_unlink)(tid, args, nArgs, res);
extern void BG_(syscall_unlinkat)(tid, args, nArgs, res);
extern void BG_(syscall_mmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_mprotect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_munmap)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_preadv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern Bool BG_(syscall_allowed_check)(ThreadId tid, int syscallno);
extern void BG_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_connect)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);
extern void BG_(syscall_rt_sigreturn)(ThreadId tid, UWord* args, UInt nArgs, SysRes res);

/* SOAAP-related data */
extern HChar* client_binary_name;
#define FNNAME_MAX 100

//extern UInt persistent_sandbox_nesting_depth;
//extern UInt ephemeral_sandbox_nesting_depth;
//extern Bool have_created_sandbox;

#define FD_MAX			256              
#define FD_MAX_PATH	256
#define FD_READ			0x1
#define FD_WRITE		0x2
#define FD_STAT			0x4


#define VAR_MAX			100
#define	VAR_READ		0x1
#define VAR_WRITE		0x2

//#define IN_SANDBOX (persistent_sandbox_nesting_depth > 0 || ephemeral_sandbox_nesting_depth > 0)

extern struct fd_info	fds[TG_N_THREADS][FD_MAX];

extern Int	guest_status;
extern Bool is_loading_native;

extern Int		th_status[TG_N_THREADS];
extern Bool		th_is_loading[TG_N_THREADS];

#define SYSCALLS_MAX	500
extern Bool allowed_syscalls[];
#define IS_SYSCALL_ALLOWED(no) (allowed_syscalls[no] == True)
void dumpMemBlock( Addr addr, SizeT size );

HChar *inet_ntoa(struct in_addr in);
#endif // _BG_WRAPPERS_H
