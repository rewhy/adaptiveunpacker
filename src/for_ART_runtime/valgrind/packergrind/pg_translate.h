#ifndef _BG_TRANSLATE_H
#define _BG_TRANSLATE_H

#include "packergrind.h"
#include "pub_tool_basics.h"
#include "pub_tool_xarray.h"
#include "pub_tool_tooliface.h"

//#include "dt_structs.h"

#define BG_(str)		VGAPPEND(vgBevgrind_,str)

#ifndef INLINE
#define INLINE			inline __attribute__((always_inline))
#endif

#define BG_WHITE_LIST		1
//Stack of strings---------------------------------------
#define MAX_LEN 256
#define STACK_SIZE 102400

extern Bool BG_(is_instrument_load);
extern Bool BG_(is_instrument_store);


HChar* mmap_proto2a(Int flag);

typedef enum { Orig=1, VSh=2 } //, BSh=3 }  Not doing origin tracking
TempKind;

typedef struct {
	TempKind kind;
	IRTemp   shadowV;
	//      IRTemp   shadowB;      Not doing origin tracking
} TempMapEnt;

typedef struct _BGEnv {
	IRSB*			sb;
	Bool			trace;
	XArray*		tmpMap;
	Bool			bogusLiterals;
	const VexGuestLayout*	layout;
	IRType		hWordTy;
} BGEnv;


void BG_(set_instrumentsate)(const HChar *reason, Bool state);

IRSB* BG_(instrument)( VgCallbackClosure* closure,
		IRSB* sbIn,
		const VexGuestLayout*		guestlayout,
		const VexGuestExtents*	vge, 
		const VexArchInfo*			archinfo_host,
		IRType	gWordTy, IRType	hWordTy );

/*---------- from pg_stmt.c ---------------*/

/* SMT2 functions */
#define TI_MAX 2100 
#define RI_MAX 740 

typedef		IRExpr	IRAtom;

#if 0

enum VariableType { Local = 3, Global = 4 };
enum VariableLocation { GlobalFromApplication = 5, GlobalFromElsewhere = 6 };

// Tmp variable indices; the MSB indicates whether it's tainted (1) or not (0)
extern UInt  ti[TI_MAX];
// Tmp variable values
extern ULong tv[TI_MAX];
// Reg variable indices 
extern UInt  ri[RI_MAX];
// Tmp variable Types/Widths
extern UInt  tt[TI_MAX];

extern struct   myStringArray lvar_s;
extern int      lvar_i[STACK_SIZE];
#endif

VG_REGPARM(3) void BG_(h32_store_tt) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_store_tc) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_store_ct) ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h64_store_tt) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_store_tc) ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_store_ct) ( IRStmt *, ULong, ULong );

VG_REGPARM(3) void BG_(h32_load)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h64_load)   ( IRStmt *, ULong, ULong );

/*VG_REGPARM(3) void BG_(h32_load_t)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_load_c)   ( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h64_load_t)   ( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_load_c)   ( IRStmt *, ULong, ULong );*/

VG_REGPARM(3) void BG_(h32_loadg_addr)		( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_loadg_alt)			( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h64_loadg_addr)		( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_loadg_alt)			( IRStmt *, ULong, ULong );

#if 0
VG_REGPARM(3) void BG_(h32_loadg_tt)			( IRStmt *, UInt, UInt, UInt, UInt );
VG_REGPARM(3) void BG_(h32_loadg_addr_t)	( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_loadg_addr_c)	( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_loadg_alt_t)		( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h32_loadg_alt_c)		( IRStmt *, UInt, UInt );
VG_REGPARM(3) void BG_(h64_loadg_tt)			( IRStmt *, ULong, ULong, ULong, ULong );
VG_REGPARM(3) void BG_(h64_loadg_addr_t)	( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_loadg_addr_c)	( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_loadg_alt_t)		( IRStmt *, ULong, ULong );
VG_REGPARM(3) void BG_(h64_loadg_alt_c)		( IRStmt *, ULong, ULong );

VG_REGPARM(3) void BG_(h32_loadg_tt_test) ( UInt, UInt, UInt, UInt, IRStmt * );
VG_REGPARM(3) void BG_(h64_loadg_tt_test) ( ULong, ULong, ULong, ULong, IRStmt * );
#endif
#define _ti(ltmp) ti[ltmp] & 0x7fffffff
#define is_tainted(ltmp) (ti[ltmp] >> 31)


/*----------  end pg_stmt.c ---------------*/

void insertStmt ( HChar cat, BGEnv* bge, IRStmt* st );
void BG_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize, enum VariableType* type, enum VariableLocation* loc);

#endif // _BG_TRANSLATE_H
