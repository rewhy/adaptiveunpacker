// bg_stmt.c
#include "pub_tool_tooliface.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_addrinfo.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcassert.h"

#include "pg_copy.h"
#include "packergrind.h"
#include "pg_debug.h"
#include "pg_string.h"
#include "pg_memtrace.h"
#include "pg_translate.h"

Int ctoi( HChar c );
Int ctoi_test( HChar c );
Int atoi( HChar *s );

Int extract_IRConst( IRConst* con ){
	switch(con->tag){
		case Ico_U1:
			return con->Ico.U1;
		case Ico_U8:
			return con->Ico.U8;
		case Ico_U16:
			return con->Ico.U16;
		case Ico_U32:
			return con->Ico.U32;
		case Ico_U64: 
			return con->Ico.U64;
		case Ico_F64:
			return con->Ico.F64;
		case Ico_F64i:
			return con->Ico.F64i;
		case Ico_V128:
			return con->Ico.V128;
		default:
			ppIRConst(con);
			VG_(tool_panic)("bg_translate.c: convert_IRConst");
	}
}

ULong extract_IRConst64( IRConst* con ){
	switch(con->tag){
		case Ico_U1:
			return con->Ico.U1;
		case Ico_U8:
			return con->Ico.U8;
		case Ico_U16:
			return con->Ico.U16;
		case Ico_U32:
			return con->Ico.U32;
		case Ico_U64:
			return con->Ico.U64;
		case Ico_F64:
			return con->Ico.F64;
		case Ico_F64i:
			return con->Ico.F64i;
		case Ico_V128:
			return con->Ico.V128;
		default:
			ppIRConst(con);
			VG_(tool_panic)("bg_translate.c: convert_IRConst");
	}
}

Int extract_IRAtom( IRAtom* atom ){

	if(atom->tag == Iex_RdTmp)
		return atom->Iex.RdTmp.tmp;
	else if(atom->tag == Iex_Const)
		return extract_IRConst( atom->Iex.Const.con );
	else

		tl_assert(0);
}

Int ctoi_test( HChar c ){
	switch(c){
		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
		case 'a':
		case 'A':
		case 'b':
		case 'B':
		case 'c':
		case 'C':
		case 'd':
		case 'D':
		case 'e':
		case 'E':
		case 'f':
		case 'F':
			return 1;
		default:
			return 0;
	}
}

Int ctoi( HChar c ){
	tl_assert( ctoi_test(c) );

	switch(c){
		case '0':
			return 0;
		case '1':
			return 1;
		case '2':
			return 2;
		case '3':
			return 3;
		case '4':
			return 4;
		case '5':
			return 5;
		case '6':
			return 6;
		case '7':
			return 7;
		case '8':
			return 8;
		case '9':
			return 9;
		case 'a':
		case 'A':
			return 0xa;
		case 'b':
		case 'B':
			return 0xb;
		case 'c':
		case 'C':
			return 0xc;
		case 'd':
		case 'D':
			return 0xd;
		case 'e':
		case 'E':
			return 0xe;
		case 'f':
		case 'F':
			return 0xf;
		default: {
							 tl_assert(0);
							 break;
						 }
	}
	return -1; // unreachable
}

Int atoi( HChar *s ){
	Int result = 0;
	Int multiplier = 1;
	Int i;

	for( i = VG_(strlen)(s)-1; i>=0; i-- ){
		tl_assert( ctoi_test( s[i] ) );
		result += multiplier * ctoi(s[i]);
		// Assume decimal
		multiplier *= 10;
	}

	return result;
}


/*--------------------------------------------------------------------------*/
/*-------------- Helper functions for information flows --------------------*/
/*--------------------------------------------------------------------------*/
// tmp variables go from t0, t1, t2,..., t255
// reg variables go from r0, r4, r8,..., r320
// see libvex_guest_amd64.h
// These arrays are initialised to 0 in BG_(clo_post_init)
// Tmp variable indices; the MSB indicates whether it's tainted (1) or not (0)
UInt  ti[TI_MAX];
// Tmp variable values
ULong tv[TI_MAX];
// Reg variable indices; values are obtained in real-time
UInt  ri[RI_MAX];

struct   myStringArray lvar_s;

HChar* client_binary_name = NULL;

static Int myStringArray_getIndex( struct myStringArray *a, const HChar* string ){
	int i;
	for( i = 0; i < a->size; i++ ){
		if( VG_(strstr)(a->m[i], string) != NULL && VG_(strstr)(string, a->m[i]) != NULL )
			return i;
	}
	return -1;
};

static Int myStringArray_push( struct myStringArray *a, const HChar* string ){
	Int idx;
	if( a->size >= STACK_SIZE ){
		VG_(printf)("***Error - myStringArray.push: max stack limit reached %d\n", STACK_SIZE);
		return -1;
	}
	if ((idx = myStringArray_getIndex(a, string)) == -1) {
		VG_(snprintf)( a->m[a->size], MAX_LEN-1, "%s", string );
		idx = a->size;
		a->size++;
	}
	return idx;
}

Int get_and_check_reg( HChar *reg ){
	Int regnum = atoi( reg );
	if( regnum % 4 ){
		BG_LOGE("get_and_check_tvar: regnum %d mod 4 != 0\n", regnum );
	}
	if( regnum >= RI_MAX ){
		BG_LOGE("get_and_check_reg: regnum %d >= %d\n", regnum, RI_MAX );
	}
	return regnum;
}

Int get_and_check_tvar( HChar *tmp ){

	Int tmpnum = atoi( tmp );
	tl_assert( tmpnum < TI_MAX );
	return tmpnum;
}


/*void infer_client_binary_name(UInt pc) {
	if (client_binary_name == NULL) {
		DebugInfo* di = VG_(find_DebugInfo)(pc);
		if (di && VG_(strcmp)(VG_(DebugInfo_get_soname)(di), "NONE") == 0) {
			client_binary_name = (HChar*)VG_(malloc)("client_binary_name",sizeof(HChar)*(VG_(strlen)(VG_(DebugInfo_get_filename)(di)+1)));
			VG_(strcpy)(client_binary_name, VG_(DebugInfo_get_filename)(di));
		}
	}
}*/

static const HChar *anonymous_file = "???";

static 
Bool is_system_lib(UInt pc) {
	const HChar *objname;
	Bool res = VG_(get_objname)(pc, &objname);
	if( res == False) {
		return False;
	}
	if(objname) {
		if( VG_(memcmp)(objname, "/dev/", 5) == 0 ) {
			return True;
		}
		if( VG_(memcmp)(objname, "/system/", 8) == 0 ) {
			return True;
		}
	}
	return False;
}

static HChar info[255];
static HChar* BG_(describe_IP)(Addr pc) {
	HChar *fileName;
	Bool res = getTraceMemMapInfo(pc, PROT_EXEC, &fileName);
	if( res )
		VG_(sprintf)(info, "0x%08X: %s", pc, fileName);
	else
		VG_(sprintf)(info, "0x%08X: ???", pc);
	return info;
}

#define H32_PC_PRE \
	UInt  pc = VG_(get_IP)( VG_(get_running_tid)() ); \
if(is_system_lib(pc)) return; \
HChar	*info = NULL; \
if( isInTraceMemMap(address, &info) == False) return; \
HChar str[128]; \
const HChar *pcinfo = BG_(describe_IP) ( pc );

#define H64_PC_PRE \
	ULong  pc = VG_(get_IP)( VG_(get_running_tid)() ); \
if(is_system_lib(pc)) return; \
HChar	*info = NULL; \
if( isInTraceMemMap(address, &info) == False) return; \
HChar str[128]; \
const HChar *pcinfo = BG_(describe_IP) ( pc );

#define H32_PRINT_PC \
	VG_(printf)("[INSN] %s | %s | 0x%x |", pcinfo, str, value);

#define H64_PRINT_PC \
	VG_(printf)("[INSN] %s | %s | 0x%llx | ", pcinfo, str, value);


#define PARSE_IST_STORE \
	IRExpr *addr, *data; \
HChar  *it; \
if( clone->tag == Ist_Store) {  \
	addr = clone->Ist.Store.addr; \
	data = clone->Ist.Store.data; \
	it = "STORE "; \
} else { \
	addr = clone->Ist.StoreG.details->addr; \
	data = clone->Ist.StoreG.details->data; \
	it = "STOREG"; \
}


/*------------------- For ARM64 -------------------*/

/*----------------- End ARM64 CPU -----------------*/


// STORE <end> atmp = dtmp
VG_REGPARM(3) void BG_(h32_store_tt) (
		IRStmt *clone, 
		UInt address,
		UInt value) 
{
	H32_PC_PRE;
	PARSE_IST_STORE;
	UInt atmp = addr->Iex.RdTmp.tmp;  // storing address
	UInt dtmp = data->Iex.RdTmp.tmp;	// storing data
	tl_assert( dtmp < TI_MAX );
	tl_assert( atmp < TI_MAX );


	VG_(sprintf)( str, "%s t%d_%d = t%d_%d", it,
			atmp, _ti(atmp),
			dtmp, _ti(dtmp) );

	H32_PRINT_PC;

	VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);

}

// STORE atmp = const
VG_REGPARM(3) void BG_(h32_store_tc) (
		IRStmt *clone,
		UInt address,
		UInt value) 
{
	H32_PC_PRE;
	PARSE_IST_STORE;
	UInt atmp    = addr->Iex.RdTmp.tmp;
	UInt c       = extract_IRConst(data->Iex.Const.con);

	tl_assert( atmp < TI_MAX );
	tl_assert( c == value );

	VG_(sprintf)( str, "%s t%d_%d = 0x%x", it, atmp, _ti(atmp), c );

	H32_PRINT_PC;

	VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);
}

// STORE const = dtmp
VG_REGPARM(3) void BG_(h32_store_ct) (
		IRStmt *clone,
		UInt address,
		UInt value) 
{
	H32_PC_PRE;
	PARSE_IST_STORE;
	UInt c       = extract_IRConst(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;

	tl_assert( dtmp < TI_MAX );
	tl_assert( address == c);

	VG_(sprintf)( str, "%s 0x%x = t%d_%d", it, c, dtmp, _ti(dtmp) );

	H32_PRINT_PC;
	VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);
}
// STORE atmp = dtmp
VG_REGPARM(3) void BG_(h64_store_tt) (
		IRStmt *clone, 
		ULong address,
		ULong value) 
{
	H64_PC_PRE;

	PARSE_IST_STORE;
	UInt atmp = addr->Iex.RdTmp.tmp;
	UInt dtmp = data->Iex.RdTmp.tmp;

	tl_assert( atmp < TI_MAX );
	tl_assert( dtmp < TI_MAX );

	VG_(sprintf)( str, "%s t%d_%d = t%d_%d", it,
			atmp, _ti(atmp),
			dtmp, _ti(dtmp) );
	H64_PRINT_PC;
	VG_(printf)(" *(a_0x%llx) <- v_0x%llx | %s\n", address, value, info);
}

// STORE atmp = c
VG_REGPARM(3) void BG_(h64_store_tc) (
		IRStmt *clone, 
		ULong address,
		ULong value) 
{
	H64_PC_PRE;

	PARSE_IST_STORE;
	UInt atmp    = addr->Iex.RdTmp.tmp;
	ULong c      = extract_IRConst64(data->Iex.Const.con);

	tl_assert( atmp < TI_MAX );
	tl_assert( value == c);

	VG_(sprintf)( str, "%s t%d_%d = 0x%llx", it, atmp, _ti(atmp), c );
	H64_PRINT_PC;
	VG_(printf)(" *(a_0x%llx) <- v_0x%llx | %s\n", address, value, info);
}

// STORE c = dtmp
VG_REGPARM(3) void BG_(h64_store_ct) (
		IRStmt *clone,
		ULong address,
		ULong value) 
{
	H64_PC_PRE;

	PARSE_IST_STORE;
	ULong c      = extract_IRConst64(addr->Iex.Const.con);
	UInt dtmp    = data->Iex.RdTmp.tmp;

	tl_assert( dtmp < TI_MAX );
	tl_assert( address == c );

	VG_(sprintf)( str, "%s 0x%llx = t%d_%d", it, c, dtmp, _ti(dtmp) );
	H64_PRINT_PC;
	VG_(printf)(" *(a_0x%llx) <- v_0x%llx | %s\n", address, value, info);

}

VG_REGPARM(3) void BG_(h32_load) (
		IRStmt *clone, 
		UInt address,
		UInt value) 
{
	H32_PC_PRE;

	UInt ltmp = clone->Ist.WrTmp.tmp; 
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value;
	UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
	IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
	if ( addr->tag == Iex_RdTmp ) { 
		UInt atmp    = addr->Iex.RdTmp.tmp;
		tl_assert( atmp < TI_MAX );

		VG_(sprintf)( str, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp),
				IRType_string[ty], atmp, _ti(atmp) );
	} 
	else {
		UInt c       = extract_IRConst(addr->Iex.Const.con);
		tl_assert(address == c);

		VG_(sprintf)( str, "t%d_%d = LOAD %s 0x%08x", ltmp, _ti(ltmp),
				IRType_string[ty], c );
	}
	VG_(printf)("%s | %s | 0x%x |", pcinfo, str, value);
	VG_(printf)(" 0x%x <- *(a_0x%08x) | %s\n", value, address, info);
}

VG_REGPARM(3) void BG_(h64_load) (
		IRStmt *clone, 
		ULong address,
		ULong value) 
{ 
	H64_PC_PRE;

	UInt ltmp = clone->Ist.WrTmp.tmp; 
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value;
	UInt ty      = clone->Ist.WrTmp.data->Iex.Load.ty - Ity_INVALID;
	IRExpr* addr = clone->Ist.WrTmp.data->Iex.Load.addr;
	if ( addr->tag == Iex_RdTmp ) { 
		UInt atmp    = addr->Iex.RdTmp.tmp;
		tl_assert( atmp < TI_MAX );

		VG_(sprintf)( str, "t%d_%d = LOAD %s t%d_%d", ltmp, _ti(ltmp),
				IRType_string[ty], atmp, _ti(atmp) );
	} else {
		ULong c       = extract_IRConst(addr->Iex.Const.con);
		tl_assert(address == c);

		VG_(sprintf)( str, "t%d_%d = LOAD %s 0x%llx", ltmp, _ti(ltmp),
				IRType_string[ty], c );
	}
	VG_(printf)("%s | %s | 0x%llx |", pcinfo, str, value);
	VG_(printf)(" 0x%llx <- *(a_0x%llx) | %s\n", value, address, info);
}

VG_REGPARM(3) void BG_(h32_loadg_addr)(
		IRStmt *clone,
		UInt address,
		UInt value ) 
{ 
	H32_PC_PRE;

	IRLoadG* lg = clone->Ist.LoadG.details;
	UInt ltmp = lg->dst;
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value; 

	IROp		vwiden = Iop_INVALID;
	IRType	loadedTy = Ity_INVALID;
	switch (lg->cvt) {
		case ILGop_Ident64: loadedTy = Ity_I64; vwiden = Iop_INVALID; break;
		case ILGop_Ident32: loadedTy = Ity_I32; vwiden = Iop_INVALID; break;
		case ILGop_16Uto32: loadedTy = Ity_I16; vwiden = Iop_16Uto32; break;
		case ILGop_16Sto32: loadedTy = Ity_I16; vwiden = Iop_16Sto32; break;
		case ILGop_8Uto32:  loadedTy = Ity_I8;  vwiden = Iop_8Uto32;  break;
		case ILGop_8Sto32:  loadedTy = Ity_I8;  vwiden = Iop_8Sto32;  break;
		default: VG_(tool_panic)("BG_(h32_loadg_addr)");
	} 
	UInt ty = loadedTy - Ity_INVALID;
	if ( lg->addr->tag == Iex_RdTmp ) { 
		UInt atmp    = lg->addr->Iex.RdTmp.tmp;
		tl_assert( atmp < TI_MAX );
		VG_(sprintf)( str, "t%d_%d = LOADG %s t%d_%d", ltmp, _ti(ltmp),	IRType_string[ty], atmp, _ti(atmp) );
	} else {
		UInt c  = extract_IRConst(lg->addr->Iex.Const.con);
		tl_assert(address == c);
		VG_(sprintf)( str, "t%d_%d = LOADG %s 0x%lx", ltmp, _ti(ltmp),	IRType_string[ty], c);
	}
	VG_(printf)("%s | %s | 0x%x |", pcinfo, str, value);
	VG_(printf)(" v_0x%x <- *(a_0x%08x) | %s\n", value, address, info);
}

VG_REGPARM(3) void BG_(h64_loadg_addr)(
		IRStmt *clone,
		ULong address,
		ULong value ) 
{ 
	H64_PC_PRE;

	IRLoadG* lg = clone->Ist.LoadG.details;
	UInt ltmp = lg->dst;
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value; 

	IROp		vwiden = Iop_INVALID;
	IRType	loadedTy = Ity_INVALID;
	switch (lg->cvt) {
		case ILGop_Ident64: loadedTy = Ity_I64; vwiden = Iop_INVALID; break;
		case ILGop_Ident32: loadedTy = Ity_I32; vwiden = Iop_INVALID; break;
		case ILGop_16Uto32: loadedTy = Ity_I16; vwiden = Iop_16Uto32; break;
		case ILGop_16Sto32: loadedTy = Ity_I16; vwiden = Iop_16Sto32; break;
		case ILGop_8Uto32:  loadedTy = Ity_I8;  vwiden = Iop_8Uto32;  break;
		case ILGop_8Sto32:  loadedTy = Ity_I8;  vwiden = Iop_8Sto32;  break;
		default: VG_(tool_panic)("BG_(h32_loadg_addr)");
	} 
	UInt ty = loadedTy - Ity_INVALID;
	if ( lg->addr->tag == Iex_RdTmp ) { 
		UInt atmp    = lg->addr->Iex.RdTmp.tmp;
		tl_assert( atmp < TI_MAX );
		VG_(sprintf)( str, "t%d_%d = LOADG %s t%d_%d", ltmp, _ti(ltmp),	IRType_string[ty], atmp, _ti(atmp) );
	} else {
		ULong c  = extract_IRConst(lg->addr->Iex.Const.con);
		tl_assert(address == c);
		VG_(sprintf)( str, "t%d_%d = LOADG %s 0x%llx", ltmp, _ti(ltmp),	IRType_string[ty], c);
	}
	VG_(printf)("%s | %s | 0x%llx |", pcinfo, str, value);
	VG_(printf)(" v_0x%llx <- *(a_0x%llx) | %s\n", value, address, info);
}

VG_REGPARM(3) void BG_(h32_loadg_alt)(
		IRStmt *clone,
		UInt alt,
		UInt value) 
{
	UInt  pc = VG_(get_IP)( VG_(get_running_tid)() );
	if(is_system_lib(pc)) return;
	HChar str[128];
	const HChar *pcinfo = BG_(describe_IP) ( pc );

	IRLoadG* lg = clone->Ist.LoadG.details;
	UInt ltmp = lg->dst;
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value;

	if( lg->alt->tag == Iex_RdTmp ) {
		UInt rtmp		 = lg->alt->Iex.RdTmp.tmp;
		VG_(sprintf)( str, "t%d_%d = alt(t%d_%d)", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
		VG_(printf)("%s | %s | 0x%x |", pcinfo, str, value);
		VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp));
	} else {
		VG_(sprintf)( str, "t%d_%d = alt(%d)", ltmp, _ti(ltmp), alt);
		VG_(printf)("%s | %s | 0x%x |", pcinfo, str, value);
		VG_(printf)("\n");
	}
}

VG_REGPARM(3) void BG_(h64_loadg_alt)(
		IRStmt *clone,
		ULong alt,
		ULong value) 
{
	ULong pc = VG_(get_IP)( VG_(get_running_tid)() );
	if(is_system_lib(pc)) return;
	HChar str[128];
	const HChar *pcinfo = BG_(describe_IP) ( pc );
	IRLoadG* lg = clone->Ist.LoadG.details;
	UInt ltmp = lg->dst;
	if ( ltmp >= TI_MAX ) {
		VG_(printf)("ltmp %d\n", ltmp);
		tl_assert( ltmp < TI_MAX );
	}
	tv[ltmp] = value;

	if( lg->alt->tag == Iex_RdTmp ) {
		UInt rtmp		 = lg->alt->Iex.RdTmp.tmp;
		VG_(sprintf)( str, "t%d_%d = alt(t%d_%d)", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
		VG_(printf)("%s | %s | 0x%llx |", pcinfo, str, value);
		VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp));
	} else {
		VG_(sprintf)( str, "t%d_%d = alt(%d)", ltmp, _ti(ltmp), alt);
		VG_(printf)("%s | %s | 0x%llx |", pcinfo, str, value);
		VG_(printf)("\n");
	}
}
