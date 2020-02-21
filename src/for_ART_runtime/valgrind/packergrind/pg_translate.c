// pg_translate.c
#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"  // tl_assert
#include "pub_tool_libcbase.h"    // VG_STREQN, VG_(memset), VG_(random)
#include "pub_tool_libcprint.h"   // VG_(message), VG_(printf)
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"  // VG_(malloc), VG_(free)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
#include "pub_tool_replacemalloc.h" // 0
#include "pub_tool_stacktrace.h"  // VG_get_StackTrace
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"      // VG_(sizeXA), VG_(newXA), VG_(addtoXA)

#include "packergrind.h"
#include "pg_debug.h"
#include "pg_wrappers.h"
#include "pg_memtrace.h"
#include "pg_translate.h"

/*-----------------------------------------------------------*/
/*--- Construct output IR basic block                     ---*/
/*-----------------------------------------------------------*/

extern Bool BG_(is_instrument);
extern Bool BG_(is_trace_framework);

extern Bool BG_(clo_trace_begin);

static BGEnv		bge;
/*---------------------- 2.0 stmt tracing related helpers  ------------------------------*/

static IRTemp newTemp ( BGEnv* bge, IRType ty, TempKind kind )
{
	IRTemp     tmp = newIRTemp(bge->sb->tyenv, ty);
	return tmp;
}

/* Set the annotations on a dirty helper to indicate that the stack
	 pointer and instruction pointers might be read.  This is the
	 behaviour of all 'emit-a-complaint' style functions we might
	 call. */
static void setHelperAnns ( BGEnv* bge, IRDirty* di ) {
	di->nFxState = 2;
	di->fxState[0].fx     = Ifx_Read;
	di->fxState[0].offset = bge->layout->offset_SP;
	di->fxState[0].size   = bge->layout->sizeof_SP;
	di->fxState[0].nRepeats  = 0;
	di->fxState[0].repeatLen = 0;
	di->fxState[1].fx     = Ifx_Read;
	di->fxState[1].offset = bge->layout->offset_IP;
	di->fxState[1].size   = bge->layout->sizeof_IP;
	di->fxState[1].nRepeats  = 0;
	di->fxState[1].repeatLen = 0;
}

/* add stmt to a bb */
static INLINE void stmt ( HChar cat, BGEnv* bge, IRStmt* st ) { //385
	if (bge->trace) {
		VG_(printf)("  %c: ", cat);
		ppIRStmt(st);
		VG_(printf)("\n");
	}
	addStmtToIRSB(bge->sb, st);
}
void insertStmt( HChar cat, BGEnv* bge, IRStmt* st) {
	return stmt(cat, bge, st);
}
/* assign value to tmp */
static INLINE
void assign ( HChar cat, BGEnv* bge, IRTemp tmp, IRExpr* expr ) {
	stmt(cat, bge, IRStmt_WrTmp(tmp,expr));
}

/* build various kinds of expressions *///400
#define triop(_op, _arg1, _arg2, _arg3) \
	IRExpr_Triop((_op),(_arg1),(_arg2),(_arg3))
#define binop(_op, _arg1, _arg2) IRExpr_Binop((_op),(_arg1),(_arg2))
#define unop(_op, _arg)          IRExpr_Unop((_op),(_arg))
#define mkU1(_n)                 IRExpr_Const(IRConst_U1(_n))
#define mkU8(_n)                 IRExpr_Const(IRConst_U8(_n))
#define mkU16(_n)                IRExpr_Const(IRConst_U16(_n))
#define mkU32(_n)                IRExpr_Const(IRConst_U32(_n))
#define mkU64(_n)                IRExpr_Const(IRConst_U64(_n))
#define mkV128(_n)               IRExpr_Const(IRConst_V128(_n))
#define mkexpr(_tmp)             IRExpr_RdTmp((_tmp))

/* Bind the given expression to a new temporary, and return the
 * temporary.  This effectively converts an arbitrary expression into
 * an atom.
 *
 * 'ty' is the type of 'e' and hence the type that the new temporary
 * needs to be.  But passing it in is redundant, since we can deduce
 * the type merely by inspecting 'e'.  So at least use that fact to
 * assert that the two types agree. 
 */
static IRAtom* assignNew ( HChar cat, BGEnv* bge, IRType ty, IRExpr* e )
{
	TempKind k;
	IRTemp   t;
	IRType   tyE = typeOfIRExpr(bge->sb->tyenv, e);
	tl_assert(tyE == ty); /* so 'ty' is redundant (!) */
	switch (cat) {
		case 'V': k = VSh;  break;
		case 'C': k = Orig; break;
							/* happens when we are making up new "orig"
								 expressions, for IRCAS handling */
		default: tl_assert(0);
	}
	t = newTemp(bge, ty, k);
	assign(cat, bge, t, e);
	return mkexpr(t);
}
/* (used for sanity checks only): is this an atom which looks
	 like it's from original code? */
static Bool isOriginalAtom ( BGEnv* bge, IRAtom* a1 )
{
	if (a1->tag == Iex_Const)
		return True;
	if (a1->tag == Iex_RdTmp) {
		// TempMapEnt* ent = VG_(indexXA)( bge->tmpMap, a1->Iex.RdTmp.tmp );
		return True; //ent->kind == Orig;
	}
	return False;
}

static IRExpr* convert_Value( BGEnv* bge, IRAtom* value ){
	IRType ty = typeOfIRExpr(bge->sb->tyenv, value);
	IRType tyH = bge->hWordTy;

	if(tyH == Ity_I32){
		switch( ty ){
			case Ity_I1:
				return assignNew( 'C', bge, tyH, unop(Iop_1Uto32, value) );
			case Ity_I8:
				return assignNew( 'C', bge, tyH, unop(Iop_8Uto32, value) );
			case Ity_I16:
				return assignNew( 'C', bge, tyH, unop(Iop_16Uto32, value) );
			case Ity_I32:
				return value;
			case Ity_I64:
				return assignNew( 'C', bge, tyH, unop(Iop_64to32, value) );
			case Ity_F32:
				return assignNew( 'C', bge, tyH, unop(Iop_ReinterpF32asI32, value) );
			case Ity_F64:
				return assignNew( 'C', bge, tyH, unop(Iop_64to32, 
							assignNew( 'C', bge, Ity_I64, unop(Iop_ReinterpF64asI64, value) ) ) );
			case Ity_V128: // Comment by Rewhy
				return assignNew('C', bge, Ity_I32, IRExpr_Const( IRConst_U32( 0x0 )));
			default:
				ppIRType(ty);
				VG_(tool_panic)("bg_translate.c: convert_Value");
		}
	}else if(tyH == Ity_I64){
		switch( ty ){
			case Ity_I1:
				return assignNew( 'C', bge, tyH, unop(Iop_1Uto64, value) );
			case Ity_I8:
				return assignNew( 'C', bge, tyH, unop(Iop_8Uto64, value) );
			case Ity_I16:
				return assignNew( 'C', bge, tyH, unop(Iop_16Uto64, value) );
			case Ity_I32:
				return assignNew( 'C', bge, tyH, unop(Iop_32Uto64, value) );
			case Ity_I64:
				return value;
			case Ity_I128:
				return assignNew( 'C', bge, tyH, unop(Iop_128to64, value) );
			case Ity_F32:
				return assignNew( 'C', bge, tyH, unop(Iop_ReinterpF64asI64, 
							assignNew( 'C', bge, Ity_F64, unop(Iop_F32toF64, value) ) ) );
			case Ity_F64:
				return assignNew( 'C', bge, tyH, unop(Iop_ReinterpF64asI64, value) );
			case Ity_V128: // Comment by Rewhy
				return assignNew( 'C', bge, tyH, unop(Iop_V128to64, value) );
			default:
				ppIRType(ty);
				VG_(tool_panic)("dt_translate.c: convert_Value");
		}
	}else{
		ppIRType(tyH);
		VG_(tool_panic)("dt_translate.c: convert_Value");
	}
	return NULL;
}

IRDirty* create_dirty_LOAD( BGEnv* bge, IRStmt *clone, IRTemp tmp,
		Bool isLL, IREndness end,
		IRType ty, IRAtom* addr ){
	Int      nargs = 3;
	const HChar*   nm;
	void*    fn;
	IRExpr** args;

	args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
			convert_Value( bge, addr),
			convert_Value( bge, IRExpr_RdTmp( tmp ) ));

	if(bge->hWordTy == Ity_I32){
		/*if ( addr->tag == Iex_RdTmp ) {
			fn    = &BG_(h32_load_t);
			nm    = "BG_(h32_load_t)";
			} else {
			fn    = &BG_(h32_load_c);
			nm    = "BG_(h32_load_c)";
			}*/
		fn    = &BG_(h32_load);
		nm    = "BG_(h32_load)";
	}else if(bge->hWordTy == Ity_I64){
		/*if ( addr->tag == Iex_RdTmp ) {
			fn    = &BG_(h64_load_t);
			nm    = "BG_(h64_load_t)";
			} else {
			fn    = &BG_(h64_load_c);
			nm    = "BG_(h64_load_c)";
			}*/
		fn    = &BG_(h64_load);
		nm    = "BG_(h64_load)";
	}else
		VG_(tool_panic)("dt_translate.c: create_dirty_LOAD: Unknown platform");

	return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}


IRDirty* create_dirty_WRTMP( BGEnv* bge, IRStmt *clone, IRTemp tmp, IRExpr* e ){

	switch( e->tag ){
		case Iex_Load:
			return create_dirty_LOAD( bge, clone, tmp, False /*isLL*/, e->Iex.Load.end,
					e->Iex.Load.ty,
					e->Iex.Load.addr );

#if 0
		case Iex_Get:
			return create_dirty_GET( bge, clone, tmp, e->Iex.Get.offset, e->Iex.Get.ty );

		case Iex_GetI:
			return create_dirty_GETI( bge, clone, tmp, e->Iex.GetI.descr,
					e->Iex.GetI.ix,
					e->Iex.GetI.bias );

		case Iex_RdTmp:
			return create_dirty_RDTMP( bge, clone, tmp, e->Iex.RdTmp.tmp );

		case Iex_Qop:
			return create_dirty_QOP(
					bge, clone, tmp,
					e->Iex.Qop.details->op,
					e->Iex.Qop.details->arg1, e->Iex.Qop.details->arg2,
					e->Iex.Qop.details->arg3, e->Iex.Qop.details->arg4
					);

		case Iex_Triop:
			return create_dirty_TRIOP(
					bge, clone, tmp,
					e->Iex.Triop.details->op,
					e->Iex.Triop.details->arg1, e->Iex.Triop.details->arg2,
					e->Iex.Triop.details->arg3
					);

		case Iex_Binop:
			return create_dirty_BINOP(
					bge, clone, tmp,
					e->Iex.Binop.op,
					e->Iex.Binop.arg1, e->Iex.Binop.arg2
					);

		case Iex_Unop:
			return create_dirty_UNOP( bge, clone, tmp,
					e->Iex.Unop.op, e->Iex.Unop.arg );

		case Iex_CCall:
			return create_dirty_CCALL( bge, clone, tmp, e->Iex.CCall.cee,
					e->Iex.CCall.retty,
					e->Iex.CCall.args );

		case Iex_ITE:
			return create_dirty_ITE( bge, clone, tmp,
					e->Iex.ITE.cond, e->Iex.ITE.iftrue,
					e->Iex.ITE.iffalse );
		case Iex_Const:
			return create_dirty_WRTMP_const( ); // Rewhy
#endif
		default:
			return NULL;
#if 0
			VG_(printf)("\n");
			ppIRExpr(e);
			VG_(printf)("\n");
			VG_(tool_panic)("dt_translate.c: create_dirty_WRTMP: Unhandled expression");
#endif
	}
}

IRDirty* create_dirty_LOADG_alt( BGEnv* bge, IRStmt *clone, IRTemp tmp,
		IREndness end, IRAtom* valt) {
	UInt nargs = 3;
	const HChar*   nm;
	void*    fn;
	IRExpr** args;

	args = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
			convert_Value( bge, valt ),
			convert_Value( bge, IRExpr_RdTmp( tmp ) ));
	if(bge->hWordTy == Ity_I32){
		if ( valt->tag == Iex_RdTmp || valt->tag == Iex_Const ) {
			fn    = &BG_(h32_loadg_alt);
			nm    = "BG_(h32_loadg_alt)";
			/*} else if ( valt->tag == Iex_Const) {
				fn    = &BG_(h32_loadg_alt_c);
				nm    = "BG_(h32_loadg_alt_c)";*/
	}	else {
		VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: not tmp");
	}
	} else if(bge->hWordTy == Ity_I64){
		if ( valt->tag == Iex_RdTmp || valt->tag == Iex_Const ) {
			fn    = &BG_(h64_loadg_alt);
			nm    = "BG_(h64_loadg_alt)";
			/*} else if ( valt->tag == Iex_Const) {
				fn    = &BG_(h64_loadg_alt_c);
				nm    = "BG_(h64_loadg_alt_c)";*/
	} else {
		VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: not tmp");
	}
	return NULL;
	} else {
		VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: Unknown platform");
	} 
	return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_LOADG_addr( BGEnv* bge, IRStmt *clone, IRTemp tmp,
		IREndness end, IRAtom* addr, 
		UInt bias) {

	UInt nargs = 3;
	const HChar*   nm;
	void*    fn;
	IRExpr** args;

	args = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
			convert_Value( bge, addr ),
			convert_Value( bge, IRExpr_RdTmp( tmp ) ));

	if(bge->hWordTy == Ity_I32){
		if ( addr->tag == Iex_RdTmp || addr->tag == Iex_Const ) {
			fn    = &BG_(h32_loadg_addr);
			nm    = "BG_(h32_loadg_addr)";
		}	else {
			VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: not tmp");
		}
	} else if(bge->hWordTy == Ity_I64){
		if ( addr->tag == Iex_RdTmp || addr->tag == Iex_Const ) {
			fn    = &BG_(h64_loadg_addr);
			nm    = "BG_(h64_loadg_addr)";
		}	else {
			VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: not tmp");
		}
	} else
		VG_(tool_panic)("dt_translate.c: create_dirty_LOADG: Unknown platform");

	return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}

IRDirty* create_dirty_STORE(BGEnv* bge, IRStmt *clone,
		IREndness end, IRTemp resSC,
		IRExpr* addr, IRExpr* data) {
	Int						nargs = 3;
	const	HChar*	nm;
	void*					fn;
	IRExpr**			args;

	if ( addr->tag == Iex_Const && data->tag == Iex_Const ) return NULL;

	args  = mkIRExprVec_3( mkIRExpr_HWord((HWord)clone),
			convert_Value( bge, addr ),
			convert_Value( bge, data ) );

	if(bge->hWordTy == Ity_I32) {
		if ( addr->tag == Iex_RdTmp && data->tag == Iex_RdTmp) {
			fn		= &BG_(h32_store_tt);
			nm		= "BG_(h32_store_tt)";
		} else if ( addr->tag == Iex_RdTmp && data->tag == Iex_Const ) {
			fn		= &BG_(h32_store_tc);
			nm		= "BG_(h32_store_td)";
		} else if ( addr->tag == Iex_Const && data->tag == Iex_RdTmp ) {
			fn		= &BG_(h32_store_ct);
			nm		= "BG_(h32_store_ct)";
		} else {
			ppIRExpr(addr);
			ppIRExpr(data);
			VG_(tool_panic)("bg_translate.c: create_dirty_STORE: unk 32-bit cfg");
		}
	} /*else if(bge->hWordTy == Ity_I64){
		if ( addr->tag == Iex_RdTmp && data->tag == Iex_RdTmp ) {
			fn    = &BG_(h64_store_tt);
			nm    = "BG_(h64_store_tt)";
		} else if ( addr->tag == Iex_RdTmp && data->tag == Iex_Const ) {
			fn    = &BG_(h64_store_tc);
			nm    = "BG_(h64_store_tc)";
		} else if ( addr->tag == Iex_Const && data->tag == Iex_RdTmp ) {
			fn    = &BG_(h64_store_ct);
			nm    = "BG_(h64_store_ct)";
		} else {
			ppIRExpr(addr);
			ppIRExpr(data);
			VG_(tool_panic)("bg_translate.c: create_dirty_STORE: unk 64-bit cfg");
		} 
	}*/ else
		VG_(tool_panic)("bg_translate.c: create_dirty_STORE: Unknown platform");

	return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}


static void do_trace_WRTMP ( BGEnv* bge, IRStmt *clone, IRTemp tmp, IRExpr* expr )
{
	IRDirty* di2;
	/* Do taint check for tmp */
	di2 = create_dirty_WRTMP( bge, clone, tmp, expr );
	if( di2 != NULL ) {
		setHelperAnns( bge, di2 );
		stmt( 'V', bge, IRStmt_Dirty(di2));
	}
}

/* ST<end>(<addr>) = <data> */
static void do_trace_Store( BGEnv* bge,
		IRStmt *clone,
		IREndness end,
		IRAtom* addr, 
		UInt bias,
		IRAtom* data, 
		IRAtom* guard)
{
	IRType				tyAddr;
	void*					helper = NULL;
	const HChar*  hname  = NULL;
	IRDirty* di2;

	tyAddr = bge->hWordTy;
	tl_assert( tyAddr == Ity_I32 || tyAddr == Ity_I64 );
	tl_assert( end == Iend_LE || end == Iend_BE );
	if(guard) {
		tl_assert(typeOfIRExpr(bge->sb->tyenv, guard) == Ity_I1);
	}
	if (data) {
		tl_assert(isOriginalAtom(bge, data));
		tl_assert(bias == 0);
	}

	tl_assert(isOriginalAtom(bge, addr));

	if (guard) {
		tl_assert(isOriginalAtom(bge, guard));
		tl_assert(typeOfIRExpr(bge->sb->tyenv, guard) == Ity_I1);
	}

	if( data && clone ) { /* Ist_Store */
		di2 = create_dirty_STORE( bge, clone, end, 0/*resSC*/, addr, data );
		if ( di2 ) {
			if(guard) {
				di2->guard = guard;
			}
			setHelperAnns( bge, di2 );
			stmt( 'V', bge, IRStmt_Dirty(di2));
		}
		return;
	}
}

static void do_trace_StoreG( BGEnv* bge, 
		IRStmt *clone,
		IRStoreG* sg) 
{
	do_trace_Store( bge, clone, sg->end,
			sg->addr, 0,
			sg->data,
			sg->guard);
}

static void do_trace_LoadG( BGEnv* bge, 
		IRStmt *clone,
		IRLoadG *lg ) {

	IRDirty* di1, *di2;
	tl_assert( lg->alt->tag == Iex_RdTmp || lg->alt->tag == Iex_Const );
	tl_assert( lg->addr->tag == Iex_RdTmp || lg->addr->tag == Iex_Const );

	di1 = create_dirty_LOADG_addr( bge, clone, lg->dst,
			lg->end, lg->addr, 0 );
	if(di1) {
		di1->guard = lg->guard;
		setHelperAnns( bge, di1 );
		stmt( 'V', bge, IRStmt_Dirty(di1));
	}

	IRType ty = typeOfIRExpr(bge->sb->tyenv, lg->guard);
	tl_assert(ty == Ity_I1);
	IRExpr* guard1 = assignNew( 'V', bge, ty, unop(Iop_Not1, lg->guard));

	di2 = create_dirty_LOADG_alt( bge, clone, lg->dst, 
			lg->end, lg->alt );

	if( di2 ) {
		di2->guard = guard1;
		setHelperAnns( bge, di2 );
		stmt( 'V', bge, IRStmt_Dirty(di2));
	}
}

/*----------------------- 2.0 End --------------------------------------------------------*/

//#define OUTPUT_BB	1
IRSB* BG_(instrument)( VgCallbackClosure* closure,
		IRSB* sbIn,
		const VexGuestLayout*		guestlayout,
		const VexGuestExtents*	vge, 
		const VexArchInfo*			archinfo_host,
		IRType	gWordTy, IRType	hWordTy )
{
	Int i, j;
	IRStmt*	st;
	IRSB*		sbOut;
	//return sbIn;
	if( BG_(is_instrument) == False )
		return sbIn;
	if( BG_(clo_trace_begin) == False ) {
		return sbIn;
	}
	if (gWordTy != hWordTy) {
		VG_(tool_panic)("host/guest word size dismatch");
	}

#if  OUTPUT_BB
	VG_(printf)("Input: \n");
	ppIRSB(sbIn);
#endif

	/* Set up sbOut according to sbIn without stmts */
	sbOut = deepCopyIRSBExceptStmts(sbIn);

	VG_(memset)(&bge, 0, sizeof(bge));
	bge.sb				= sbOut;
	bge.trace			= False;
	bge.layout		= guestlayout;
	bge.hWordTy		= hWordTy;
	bge.bogusLiterals = False;


	i = 0;
	while(i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
		st = sbIn->stmts[i];
		tl_assert(st);
		tl_assert(isFlatIRStmt(st));
		stmt( 'C', &bge, st );
		i++;
	}

	tl_assert(sbIn->stmts_used > 0);
	tl_assert(i < sbIn->stmts_used);
	tl_assert(sbIn->stmts[i]->tag == Ist_IMark);

	// Insert additional stmt for tracking Java method invocation
	if( BG_(is_trace_framework) )
		trackJavaMethod(&bge, guestlayout, vge);

	for( ; i < sbIn->stmts_used; i ++ ) {
		st = sbIn->stmts[i];
		IRStmt *stclone = deepMallocIRStmt(st);
		switch (st->tag) {
			case Ist_WrTmp:
				stmt( 'C', &bge, st );
#if INS_LOAD
				if( BG_(is_instrument_load) ) {
					do_trace_WRTMP( &bge,
							stclone,
							st->Ist.WrTmp.tmp,
							st->Ist.WrTmp.data);
				}
#endif
				break;
			case Ist_Put:
			case Ist_PutI:
				stmt( 'C', &bge, st );
				break;
			case Ist_Store:				/* ST<end>(<addr>) = <data> */
#if INS_STORE
				if( BG_(is_instrument_store) ) {
					do_trace_Store( &bge, 
							stclone, 
							st->Ist.Store.end,
							st->Ist.Store.addr,
							0,
							st->Ist.Store.data,
							NULL);
				}
#endif
				stmt( 'C', &bge, st );
				break;
			case Ist_StoreG:			/* if(<guard>) ST<end>(<addr>) = <data> */
#if INS_STORE
				if( BG_(is_instrument_store) ) {
					do_trace_StoreG( &bge,
							stclone,
							st->Ist.StoreG.details);
				}
#endif
				stmt( 'C', &bge, st );
				break;
			case Ist_LoadG:				/* t<tmp> = if(<guard>) <cvt>(LD<end>(<addr>)) else <alt> */
				stmt( 'C', &bge, st );
#if INS_LOAD
				if( BG_(is_instrument_load) ) {
					do_trace_LoadG( &bge,
							stclone,
							st->Ist.LoadG.details);
				}
#endif
				break;
			case Ist_IMark:
			case Ist_NoOp:
			case Ist_MBE:
			case Ist_Dirty:
			case Ist_AbiHint:
			case Ist_LLSC:
			case Ist_Exit:
				stmt( 'C', &bge, st );
				break;
			default:
				VG_(printf)("\n");      
				ppIRStmt(st);         
				VG_(printf)("\n");           
				VG_(tool_panic)("dt_translate.c: BG_(instrument): unhandled IRStmt");
		}
	}

#ifdef  OUTPUT_BB
	VG_(printf)("Output: \n");
	ppIRSB(sbOut);
#endif
	return sbOut;
}
