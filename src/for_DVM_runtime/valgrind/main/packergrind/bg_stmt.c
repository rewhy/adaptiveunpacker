// bg_stmt.c
#include "pub_tool_tooliface.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_debuginfo.h"
#include "pub_tool_addrinfo.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_libcassert.h"

#include "copy.h"
#include "bevgrind.h"
#include "bg_debug.h"
#include "bg_string.h"
#include "bg_translate.h"

// -Start- Forward declarations for Taintgrind
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


UInt  ti[TI_MAX];
ULong tv[TI_MAX];
UInt  ri[RI_MAX];

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

void infer_client_binary_name(UInt pc) {
	if (client_binary_name == NULL) {
		DebugInfo* di = VG_(find_DebugInfo)(pc);
		if (di && VG_(strcmp)(VG_(DebugInfo_get_soname)(di), "NONE") == 0) {
			client_binary_name = (HChar*)VG_(malloc)("client_binary_name",sizeof(HChar)*(VG_(strlen)(VG_(DebugInfo_get_filename)(di)+1)));
			VG_(strcpy)(client_binary_name, VG_(DebugInfo_get_filename)(di));
		}
	}
}

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

static HChar pcInfo[255];
static HChar* BG_(describe_IP)(Addr pc) {
	HChar *fileName;
	Bool res = getMemMapInfo(pc, PROT_EXEC, &fileName);
	Int i = 0, j = 0;
	if( res ) {
		while( fileName[i] != '\0' ) {
			if(fileName[i] == '/')
				j = i+1;
		}
		VG_(sprintf)(pcInfo, "%08x: %s", pc, &fileName[j]);
	}	else {
		VG_(sprintf)(pcInfo, "%08x: ???", pc);
	}
	return pcInfo;
}


#define H32_PC \
	UInt  pc = VG_(get_IP)( VG_(get_running_tid)() ); \
if(is_system_lib(pc)) return; \
HChar	*info = NULL; \
if( isInFilterList(dlibl, address, &info) == False) return;\
HChar aTmp[128]; \
const HChar *fnname = BG_(describe_IP) ( pc );
//const HChar *fnname = VG_(describe_IP) ( pc, NULL );

#define H64_PC \
	ULong pc = VG_(get_IP)( VG_(get_running_tid)() ); \
if(is_system_lib(pc)) return; \
HChar	*info = NULL; \
if( isInFilterList(dlibl, address, &info) == False) return;\
HChar aTmp[128]; \ 
const HChar *fnname = BG_(describe_IP) ( pc );

#define H_VAR \
	HChar varname[1024]; \
ThreadId tid = VG_(get_running_tid()); \
enum VariableType type = 0; \
enum VariableLocation var_loc; \
BG_(describe_data)(address, varname, 1024, &type, &var_loc); 

#define H_WRTMP_BOOKKEEPING1 \
	IRLoadG* lg = clone->Ist.LoadG.details; \
UInt ltmp = lg->dst; \
if ( ltmp >= TI_MAX ) \
VG_(printf)("ltmp %d\n", ltmp); \
tl_assert( ltmp < TI_MAX ); \
tv[ltmp] = value;


#define H_WRTMP_BOOKKEEPING \
	UInt ltmp = clone->Ist.WrTmp.tmp; \
if ( ltmp >= TI_MAX ) \
VG_(printf)("ltmp %d\n", ltmp); \
tl_assert( ltmp < TI_MAX ); \
tv[ltmp] = value;


#define H32_PRINT_STORE \
	VG_(printf)("%s | %32s | *(0x%08x) <- 0x%08x | %s\n", fnname, aTmp, address, value, info)

#define H32_PRINT_LOAD \
	VG_(printf)("%s | %32s | 0x%08x <- *(0x%08x) | %s\n", fnname, aTmp, value, address, info)

#define H64_PRINT_STORE \
	VG_(printf)("%s | %s | *(0x%llx) <- 0x%08x | %s\n ", fnname, aTmp, address, value, info)

#define H64_PRINT_LOAD \
	VG_(printf)("%s | %s | 0x%08x <- *(0x%llx) | %s\n", fnname, aTmp, value, address, info)

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

// STORE <end> atmp = dtmp
VG_REGPARM(3)
	void BG_(h32_store_tt) (
			IRStmt *clone, 
			UInt address,
			UInt value) {

		H32_PC;
		PARSE_IST_STORE;
		UInt atmp = addr->Iex.RdTmp.tmp;  // storing address
		UInt dtmp = data->Iex.RdTmp.tmp;	// storing data
		tl_assert( dtmp < TI_MAX );
		tl_assert( atmp < TI_MAX );

		VG_(sprintf)( aTmp, "%s(t%d_%d) = t%d_%d", it,
				atmp, _ti(atmp),
				dtmp, _ti(dtmp) );

		H32_PRINT_STORE;
		//VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);

	}

// STORE atmp = const
VG_REGPARM(3)
	void BG_(h32_store_tc) (
			IRStmt *clone,
			UInt address,
			UInt value) {

		H32_PC;
		PARSE_IST_STORE;
		UInt atmp    = addr->Iex.RdTmp.tmp;
		UInt c       = extract_IRConst(data->Iex.Const.con);

		tl_assert( atmp < TI_MAX );
		tl_assert( c == value );


		VG_(sprintf)( aTmp, "%s(t%d_%d) = 0x%x", it, atmp, _ti(atmp), c );

		H32_PRINT_STORE;
		//VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);
	}

// STORE const = dtmp
VG_REGPARM(3)
	void BG_(h32_store_ct) (
			IRStmt *clone,
			UInt address,
			UInt value) {

		H32_PC;

		PARSE_IST_STORE;
		UInt c       = extract_IRConst(addr->Iex.Const.con);
		UInt dtmp    = data->Iex.RdTmp.tmp;

		tl_assert( dtmp < TI_MAX );
		tl_assert( address == c);

		VG_(sprintf)( aTmp, "%s(0x%x) = t%d_%d", it, c, dtmp, _ti(dtmp) );

		H32_PRINT_STORE;
		//VG_(printf)(" *(a_0x%08x) <- v_0x%x | %s\n", address, value, info);
	}
// STORE atmp = dtmp
VG_REGPARM(3)
	void BG_(h64_store_tt) (
			IRStmt *clone, 
			ULong address,
			ULong value) {

		H64_PC;

		PARSE_IST_STORE;
		UInt atmp = addr->Iex.RdTmp.tmp;
		UInt dtmp = data->Iex.RdTmp.tmp;

		tl_assert( atmp < TI_MAX );
		tl_assert( dtmp < TI_MAX );

		VG_(sprintf)( aTmp, "%s(t%d_%d) = t%d_%d", it,
				atmp, _ti(atmp),
				dtmp, _ti(dtmp) );
		H64_PRINT_STORE;
		//VG_(printf)(" *(a_0x%llx) <- v_0x%x | %s\n", address, value, info);
	}

// STORE atmp = c
VG_REGPARM(3)
	void BG_(h64_store_tc) (
			IRStmt *clone, 
			ULong address,
			ULong value) {

		H64_PC;

		PARSE_IST_STORE;
		UInt atmp    = addr->Iex.RdTmp.tmp;
		ULong c      = extract_IRConst64(data->Iex.Const.con);

		tl_assert( atmp < TI_MAX );
		tl_assert( value == c);

		VG_(sprintf)( aTmp, "%s(t%d_%d) = 0x%llx", it, atmp, _ti(atmp), c );
		H64_PRINT_STORE;
		//VG_(printf)(" *(a_0x%llx) <- v_0x%x | %s\n", address, value, info);
	}

// STORE c = dtmp
VG_REGPARM(3)
	void BG_(h64_store_ct) (
			IRStmt *clone,
			ULong address,
			ULong value) {

		H64_PC;

		PARSE_IST_STORE;
		ULong c      = extract_IRConst64(addr->Iex.Const.con);
		UInt dtmp    = data->Iex.RdTmp.tmp;

		tl_assert( dtmp < TI_MAX );
		tl_assert( address == c );

		VG_(sprintf)( aTmp, "%s(0x%llx) = t%d_%d", it, c, dtmp, _ti(dtmp) );
		H64_PRINT_STORE;
		//VG_(printf)(" *(a_0x%llx) <- v_0x%x | %s\n", address, value, info);

	}

VG_REGPARM(3)
	void BG_(h32_load) (
			IRStmt *clone, 
			UInt address,
			UInt value) {

		H32_PC;

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

			VG_(sprintf)( aTmp, "t%d_%d = LOAD:%s(t%d_%d)", ltmp, _ti(ltmp),
					IRType_string[ty], atmp, _ti(atmp) );
		} 
		else {
			UInt c       = extract_IRConst(addr->Iex.Const.con);
			tl_assert(address == c);

			VG_(sprintf)( aTmp, "t%d_%d = LOAD:%s(0x%08x)", ltmp, _ti(ltmp),
					IRType_string[ty], c );
		}
		H32_PRINT_LOAD;
		//VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
		//VG_(printf)(" 0x%x <- *(a_0x%08x) | %s\n", value, address, info);
	}
VG_REGPARM(3)
	void BG_(h64_load) (
			IRStmt *clone, 
			ULong address,
			ULong value) {

		H64_PC;

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

			VG_(sprintf)( aTmp, "t%d_%d = LOAD:%s(t%d_%d)", ltmp, _ti(ltmp),
					IRType_string[ty], atmp, _ti(atmp) );
		} else {
			ULong c       = extract_IRConst(addr->Iex.Const.con);
			tl_assert(address == c);

			VG_(sprintf)( aTmp, "t%d_%d = LOAD:%s(0x%llx)", ltmp, _ti(ltmp),
					IRType_string[ty], c );
		}
		H64_PRINT_LOAD;
		//VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
		//VG_(printf)(" 0x%x <- *(a_0x%llx) | %s\n", value, address, info);
	}

VG_REGPARM(3)
	void BG_(h32_loadg_addr)(
			IRStmt *clone,
			UInt address,
			UInt value ) { 

		H32_PC;

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
			VG_(sprintf)( aTmp, "t%d_%d = LOADG:%s(t%d_%d)", ltmp, _ti(ltmp),	IRType_string[ty], atmp, _ti(atmp) );
		} else {
			UInt c  = extract_IRConst(lg->addr->Iex.Const.con);
			tl_assert(address == c);
			VG_(sprintf)( aTmp, "t%d_%d = LOADG:%s(0x%08x)", ltmp, _ti(ltmp),	IRType_string[ty], c);
		}
		H32_PRINT_LOAD;
		//VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
		//VG_(printf)(" v_0x%x <- *(a_0x%08x) | %s\n", value, address, info);
	}

VG_REGPARM(3)
	void BG_(h64_loadg_addr)(
			IRStmt *clone,
			ULong address,
			ULong value ) { 

		H64_PC;

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
			VG_(sprintf)( aTmp, "t%d_%d = LOADG:%s(t%d_%d)", ltmp, _ti(ltmp),	IRType_string[ty], atmp, _ti(atmp) );
		} else {
			ULong c  = extract_IRConst(lg->addr->Iex.Const.con);
			tl_assert(address == c);
			VG_(sprintf)( aTmp, "t%d_%d = LOADG:%s(0x%llx)", ltmp, _ti(ltmp),	IRType_string[ty], c);
		}
		H64_PRINT_LOAD;
		//VG_(printf)("%s | %s | 0x%llx |", fnname, aTmp, value);
		//VG_(printf)(" v_0x%llx <- *(a_0x%llx) | %s\n", value, address, info);
	}

VG_REGPARM(3)
	void BG_(h32_loadg_alt)(
			IRStmt *clone,
			UInt alt,
			UInt value) {

		UInt  pc = VG_(get_IP)( VG_(get_running_tid)() );
		if(is_system_lib(pc)) return;
		HChar aTmp[128];
		const HChar *fnname = BG_(describe_IP) ( pc );

		IRLoadG* lg = clone->Ist.LoadG.details;
		UInt ltmp = lg->dst;
		if ( ltmp >= TI_MAX ) {
			VG_(printf)("ltmp %d\n", ltmp);
			tl_assert( ltmp < TI_MAX );
		}
		tv[ltmp] = value;

		if( lg->alt->tag == Iex_RdTmp ) {
			UInt rtmp		 = lg->alt->Iex.RdTmp.tmp;
			VG_(sprintf)( aTmp, "t%d_%d = alt(t%d_%d)", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
			VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
			VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp));
		} else {
			VG_(sprintf)( aTmp, "t%d_%d = alt(%d)", ltmp, _ti(ltmp), alt);
			VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
			VG_(printf)("\n");
		}
	}
VG_REGPARM(3)
	void BG_(h64_loadg_alt)(
			IRStmt *clone,
			ULong alt,
			ULong value) {

		ULong pc = VG_(get_IP)( VG_(get_running_tid)() );
		if(is_system_lib(pc)) return;
		HChar aTmp[128];
		const HChar *fnname = BG_(describe_IP) ( pc );
		IRLoadG* lg = clone->Ist.LoadG.details;
		UInt ltmp = lg->dst;
		if ( ltmp >= TI_MAX ) {
			VG_(printf)("ltmp %d\n", ltmp);
			tl_assert( ltmp < TI_MAX );
		}
		tv[ltmp] = value;

		if( lg->alt->tag == Iex_RdTmp ) {
			UInt rtmp		 = lg->alt->Iex.RdTmp.tmp;
			VG_(sprintf)( aTmp, "t%d_%d = alt(t%d_%d)", ltmp, _ti(ltmp), rtmp, _ti(rtmp) );
			VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
			VG_(printf)("t%d_%d <- t%d_%d\n", ltmp, _ti(ltmp), rtmp, _ti(rtmp));
		} else {
			VG_(sprintf)( aTmp, "t%d_%d = alt(%d)", ltmp, _ti(ltmp), alt);
			VG_(printf)("%s | %s | 0x%x |", fnname, aTmp, value);
			VG_(printf)("\n");
		}
	}

/*------------------------------------------------------------*/
/*--- utility function for finding local/global variable   ---*/
/*--- name from data address, using debug symbol tables.   ---*/
/*------------------------------------------------------------*/

static void processDescr1(XArray* descr1, HChar* varnamebuf, UInt bufsize)
{
	//VG_(printf)("descr1: %s descr2: %s\n", (HChar*)VG_(indexXA)(descr1,0), (HChar*)VG_(indexXA)(descr2,0));

	// descr1 will either be of the form:
	// (1) Location 0xbef29644 is 0 bytes inside local var "n"
	// or
	// (2) Location 0xbed42644 is 0 bytes inside n[1],
	// or
	// (3) Location 0xbebb842c is 0 bytes inside args.str,
	// or
	// (4) Location 0xbebb842c is 0 bytes inside args[1].str,
	// or
	// (5) Location 0xbebb842c is 0 bytes inside args.str[0],
	//
	// So, the terminator for a variable name is either '"' or ','

	HChar* descr1str =  (HChar*)VG_(indexXA)(descr1, 0);
	const char* commonVarPrefix = "bytes inside ";
	char* varPrefixPtr = VG_(strstr)(descr1str, commonVarPrefix);

	tl_assert(varPrefixPtr != NULL);

	// fast forward to start of var name
	varPrefixPtr += (VG_(strlen)(commonVarPrefix)*sizeof(HChar));

	// disambiguate between local var or others
	const char* localVarPrefix = "local var ";
	char* varStart = VG_(strstr)(varPrefixPtr, localVarPrefix);
	HChar* varEnd;
	int varNameLen = 0;

	if (varStart == NULL) {
		// case 2, 3, 4 or 5
		varStart = varPrefixPtr;
		varEnd = VG_(strchr)(varStart, ',');
		//VG_(printf)("varStart: %s, varEnd: %s, descr1: %s, descr2: %s\n", varStart, varEnd, descr1str, (HChar*)VG_(indexXA)(descr2,0));
		tl_assert(varEnd != NULL);
	}
	else {
		// case 1: local variable
		varStart += ((VG_(strlen)(localVarPrefix)+1)*sizeof(HChar)); // +1 to skip first "
		varEnd = VG_(strchr)(varStart, '"');
	}

	tl_assert(varStart != NULL);
	tl_assert(varEnd != NULL);

	//VG_(printf)("varStart: %s, varEnd: %s, descr1: %s, descr2: %s\n", varStart, varEnd, descr1str, (HChar*)VG_(indexXA)(descr2,0));
	//VG_(printf)("varStart: %s, varEnd: %s\n", varStart, varEnd);

	varNameLen = VG_(strlen)(varStart) - VG_(strlen)(varEnd);
	if (varNameLen >= bufsize) {
		varNameLen = bufsize-1;
	}
	//VG_(printf)("first: %s, second: %s, varnamelen: %d\n", first, second, varnamelen);
	VG_(strncpy)(varnamebuf, varStart, varNameLen);
	varnamebuf[varNameLen] = '\0';

	//VG_(printf)("Addr: %x, Var: %s\n", addr, varnamebuf);
}

void BG_(describe_data)(Addr addr, HChar* varnamebuf, UInt bufsize, enum VariableType* type, enum VariableLocation* loc) {

	const HChar *cvarname;

	// first try to see if it is a global var
	PtrdiffT pdt;
	if ( VG_(get_datasym_and_offset)( addr, &cvarname, &pdt ) )
	{
		VG_(strncpy)(varnamebuf, cvarname, bufsize);
		return;
	}

	AddrInfo ai; 
	ai.tag = Addr_Undescribed;
	VG_(describe_addr)(addr, &ai);
	//VG_(pp_addrinfo)(addr, &ai);
	//VG_(printf)("ai->tag %x\n", ai.tag);

	if ( ai.tag == Addr_DataSym )
	{
		VG_(strncpy)(varnamebuf, ai.Addr.DataSym.name, bufsize);
		return;
	} else if ( ai.tag == Addr_Variable )
	{
		//VG_(printf)("descr1 %s\n", VG_(indexXA)(ai.Addr.Variable.descr1,0) );
		//VG_(printf)("descr2 %s\n", VG_(indexXA)(ai.Addr.Variable.descr2,0) );
		processDescr1(ai.Addr.Variable.descr1, varnamebuf, bufsize);
		return;
	} else //if ( ai.tag == Addr_Stack )
	{
		// now let's try for local var
		XArray* descr1
			= VG_(newXA)( VG_(malloc), "dt.da.descr1",
					VG_(free), sizeof(HChar) );
		XArray* descr2
			= VG_(newXA)( VG_(malloc), "dt.da.descr2",
					VG_(free), sizeof(HChar) );

		(void) VG_(get_data_description)( descr1, descr2, addr );
		/* If there's nothing in descr1/2, free them.  Why is it safe to to
			 VG_(indexXA) at zero here?  Because VG_(get_data_description)
			 guarantees to zero terminate descr1/2 regardless of the outcome
			 of the call.  So there's always at least one element in each XA
			 after the call.
			 */
		if (0 == VG_(strlen)( VG_(indexXA)( descr1, 0 ))) {
			VG_(deleteXA)( descr1 );
			descr1 = NULL;
		}

		if (0 == VG_(strlen)( VG_(indexXA)( descr2, 0 ))) {
			VG_(deleteXA)( descr2 );
			descr2 = NULL;
		}

		/* Assume (assert) that VG_(get_data_description) fills in descr1
			 before it fills in descr2 */
		if (descr1 == NULL)
			tl_assert(descr2 == NULL);

		/* If we could not obtain the variable name, then just use "unknownobj" */
		if (descr1 == NULL) {
			VG_(sprintf)( varnamebuf, "%lx_unknownobj", addr );
		}
		else {
			processDescr1(descr1, varnamebuf, bufsize);
		}

		if (descr1 != NULL) {
			VG_(deleteXA)( descr1 );
		}

		if (descr2 != NULL) {
			VG_(deleteXA)( descr2 );
		}

		*type = Local;
	}
}
