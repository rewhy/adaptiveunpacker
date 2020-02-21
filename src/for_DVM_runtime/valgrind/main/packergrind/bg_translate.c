
#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"   // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"  // tl_assert
#include "pub_tool_libcbase.h"    // VG_STREQN, VG_(memset), VG_(random)
#include "pub_tool_libcprint.h"   // VG_(message), VG_(printf)
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_mallocfree.h"  // VG_(malloc), VG_(free)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
//#include "pub_tool_options.h"   // VG_STR/BHEX/BINT_CLO
#include "pub_tool_replacemalloc.h" // 0
#include "pub_tool_stacktrace.h"  // VG_get_StackTrace
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"      // VG_(sizeXA), VG_(newXA), VG_(addtoXA)

#include "bevgrind.h"
#include "bg_debug.h"
#include "bg_wrappers.h"
#include "bg_translate.h"

/*-----------------------------------------------------------*/
/*--- Construct output IR basic block                     ---*/
/*-----------------------------------------------------------*/

struct LibList *llist = NULL;
static Int filterNum = 0;

/* List storing the debuginfo of the elf files of which all the .text or part of the .text
 * have no need to be instrumented */
struct FilterList *fl			= NULL; /* Filter list of system libraries */
struct FilterList *dml		= NULL;
struct FilterList *dlibl	= NULL; /* List of the importy address realated to file data (mmap/read) */
struct FilterList *m_list		= NULL; /* memory mapped executable segments */



void init_soaap_data() {
#ifdef BG_WHITE_LIST
	addFilterFun("libwebviewchromium_loader.so", NULL);
	addFilterFun( "libjnigraphics.so", NULL);
	addFilterFun( "libcompiler_rt.so", NULL);
	addFilterFun( "libsc-a3xx.so", NULL);
	addFilterFun( "libGLESv2_adreno.so", NULL);
	addFilterFun( "libGLESv1_CM_adreno.so", NULL);
	addFilterFun( "libadreno_utils.so", NULL);
	addFilterFun( "libgsl.so", NULL);
	addFilterFun( "libEGL_adreno.so", NULL);
	addFilterFun( "bkeymaster1.so", NULL);
	addFilterFun( "libkeymaster_messages.so", NULL);
	addFilterFun( "libsoftkeymasterdevice.so", NULL);
	addFilterFun( "libkeystore_binder.so", NULL);
	addFilterFun( "libkeystore-engine.so", NULL);
	addFilterFun( "libpowermanager.so", NULL);
	addFilterFun( "libstagefright_yuv.so", NULL);
	addFilterFun( "libstagefright_omx.so", NULL);
	addFilterFun( "libmediautils.so", NULL);
	addFilterFun( "libETC1.so", NULL);
	addFilterFun( "libGLESv2.so", NULL);
	addFilterFun( "libGLESv1_CM.so", NULL);
	addFilterFun( "libEGL.so", NULL);
	addFilterFun( "libskia.so", NULL);
	addFilterFun( "libcamera_metadata.so", NULL);
	addFilterFun( "libcamera_client.so", NULL);
	addFilterFun( "libgui.so", NULL);
	addFilterFun( "libandroid_runtime.so", NULL);
	addFilterFun( "libbinder.so", NULL);
	addFilterFun( "libhwui.so", NULL);
	addFilterFun( "libradio_metadata.so", NULL);
	addFilterFun( "libsoundtrigger.so", NULL);
	addFilterFun( "libmedia.so", NULL);
	addFilterFun( "libicui18n.so", NULL);
	addFilterFun( "libselinux.so", NULL);
	addFilterFun( "libhardware_legacy.so", NULL);
	addFilterFun( "libhardware.so", NULL);
	addFilterFun( "libwilhelm.so", NULL);
	addFilterFun( "vgpreload_datatrace-arm-linux.so", NULL);
	addFilterFun( "libc.so", "pthread_mutex_lock");
	addFilterFun( "libc.so", "pthread_mutex_trylock");
	addFilterFun( "libc.so", "pthread_mutex_unlock");
#else
#endif
	//persistent_sandbox_nesting_depth = 0;
	//ephemeral_sandbox_nesting_depth = 0;
	//have_created_sandbox = False;

	//VG_(memset)(shared_vars_perms, 0, sizeof(Int)*VAR_MAX);
	//VG_(memset)(shared_fds, 0, sizeof(Int)*FD_MAX);
	//VG_(memset)(allowed_syscalls, 0, sizeof(Bool)*SYSCALLS_MAX);

	//next_shared_variable_to_update = NULL;
}


void addMemMap(Addr addr, Int size, Int prot, HChar *info)
{
#if 0
	addFilterList(&m_list, info, addr, size);
	struct MemList *ml = m_list;
	while(ml) {
		if(ml->addr <= addr && ml->addr+ml->size > addr) {
			if (addr != ml->addr || size != ml->size) {
				VG_(printf)("Add map address error!!!!( 0x%08x-0x%08x / 0x%08x-0x%08x)\n",
						addr, addr+size, ml->addr, ml->addr+ml->size);
#if 1
				struct MemList *tml = m_list;
				while(tml) {
					VG_(printf)("0x%08x-0x%08x %s\n", tml->addr, tml->addr+tml->size, tml->name);
					tml = tml->next;
				}
#endif
			}
			ml->prot = prot;
			if( info )
				VG_(strcpy)(ml->name, info);
			return;
		}
		ml = ml->next;
	}
	ml = VG_(malloc)("Mmap.segment.x", sizeof(struct MemList));
	tl_assert(ml);
	VG_(strcpy)(ml->name, info);
	ml->addr = addr;
	ml->size = size;
	ml->prot = prot;
	ml->next = m_list;
	m_list = ml;
#if 0
	while(ml) {
		VG_(printf)("0x%08x-0x%08x %s\n", ml->addr, ml->addr+ml->size, ml->name);
		ml = ml->next;
	}
#endif
#endif
}
Bool getMemMapInfo(Addr addr, Int prot, HChar **pinfo) 
{
	Addr a = isInFilterList(m_list, addr, pinfo);
	if(a > 0) {
		return True;
	}
	else {
		return False;
	}
#if 0
	struct MemList *ml = m_list;
	while(ml) {
		if ((addr >= ml->addr) && (addr < ml->addr+ml->size)) {
			if(ml->prot & prot == 0) {
				BG_LOGI("Found buf miss match permission 0x%x(0x%x)\n", ml->prot, prot);
			}
			*pinfo = ml->name;
			return True;
		}
		ml = ml->next;
	}
	return False;
#endif
}
void delMemMap(Addr addr, Int size)
{
#if 0
	delFilterList(&m_list, "memory.map",  addr, size);
	struct MemList *pl = NULL, *ml = m_list;
	while(ml) {
		if(addr <= ml->addr && addr+size >= ml->addr+ml->size) {
			if(pl) {
				pl->next = ml->next;
				VG_(free)(ml);
				ml = pl;
			} else {
				m_list = ml->next;
				VG_(free)(ml);
				ml = m_list;
				continue;
			}
		} else if(addr >= ml->addr && addr < ml->addr+ml->size) {
			if (addr != ml->addr || size != ml->size) {
				VG_(printf)("Del map address error!!!!( 0x%08x-0x%08x / 0x%08x-0x%08x)\n",
						addr, addr+size, ml->addr, ml->addr+ml->size);
#if 1
				struct MemList *tml = m_list;
				while(tml) {
					VG_(printf)("0x%08x-0x%08x %s\n", tml->addr, tml->addr+tml->size, tml->name);
					tml = tml->next;
				}
#endif
			}
			if( addr > ml->addr ) {
				addMemMap(ml->addr, addr-ml->addr, ml->prot, ml->name);
			}
			if( addr+size < ml->addr+ml->size) {
				addMemMap(addr+size, (ml->addr+ml->size)-(addr+size), ml->prot, ml->name);
			}
			break;
		}
		pl = ml;
		ml = ml->next;
	}
	if(ml) { /* Found */
		if(pl) { /* Not head */
			pl->next = ml->next;
		} else {
			m_list = ml->next;
		}
		VG_(free)(ml);
#if 0
		ml = m_list;
		while(ml) {
			VG_(printf)("0x%08x-0x%08x %s\n", ml->addr, ml->addr+ml->size, ml->name);
			ml = ml->next;
		}
#endif
	}
#endif
}
/* If fnname is null, all the .text section is added to the filter list;
 * else only the code range of symbol funname in soname is added */
Bool addFilterFun(const HChar* soname, const HChar* fnname) {
	struct LibList *tll = llist;
	struct FunList *tfl, *nfl;
	tl_assert(soname);
	while( tll ) {
		if( VG_(strcmp)(soname, tll->name) == 0) {
			break;
		}
		tll = tll->next;
	}
	/* add new library to the head of the filter list */
	if( !tll ) {
		tll = (struct LibList*)VG_(malloc)("addFilterFun.1", sizeof(struct LibList));
		tl_assert(tll);
		VG_(strcpy)(tll->name, soname);
		tll->flist = NULL;
		tll->next = llist;
		llist = tll;
	}
	/* the libaray alread exists in filter list */
	tfl = tll->flist;
	if( fnname ) {
		while( tfl ) {
			if(VG_(strcmp)(fnname, tfl->name) == 0) {
				BG_LOGI("add %s in %s already existed\n", fnname, soname);
				return False;
			}
			tfl = tfl->next;
		}
		/* Add one new function node to the head of lib's function list */
		tfl = (struct FunList*)VG_(malloc)("addFilterFun.2", sizeof(struct FunList));
		VG_(strcpy)(tfl->name, fnname);
		tfl->next = tll->flist;
		tll->flist = tfl;
		//BG_LOGI("add %s in %s\n", fnname, soname);
		return True;
	} else { /* Add all lib's .text section to filter list */
		while( tfl ) {
			nfl = tfl->next;
			VG_(free)(tfl);
			tfl = nfl;
		}
		tll->flist = NULL;
		//BG_LOGI("all .text in %s added\n", soname);
		return True;
	}
}

/* Get the library filter node of soname */
static struct LibList* findLib(const HChar* soname) {
	BG_LOGI("Check so %s\n", soname);
	struct LibList *tll = llist;
	while ( tll ) {
		if( VG_(strcmp) ( soname, tll->name ) == 0 )
			return tll;
		tll = tll->next;
	}
	return NULL;
}

void dumpFilterList(struct FilterList *pfl) {
	struct FilterList* ttt = pfl;
	while(ttt) {
		VG_(printf)("Filter map: 0x%08x - 0x%08x info:%s\n", 
				ttt->begin, ttt->end, ttt->info);
		ttt = ttt->next;
	}
}

void delFilterList(struct FilterList** ppfl, const HChar *info, Addr avma, SizeT size )
{
	struct FilterList *tfl, *nlfl = NULL, *llfl = NULL, *lfl, *lffl = NULL, *ffl = *ppfl;
	Addr b = avma;
	Addr e = avma+size;
	Int  isDel = 0;
	if( ffl == NULL ) 
		return;

	while( ffl ) {
		if( ffl->begin >= b)
			break;
		lffl = ffl;
		ffl  = ffl->next;
	};

	lfl = *ppfl;
	while( lfl ) {
		if( lfl->end > e)
			break;
		llfl = lfl;
		lfl = lfl->next;
	}

	// VG_(printf)("Del filter range: 0x%08x 0x%08x - 0x%08x %10d(0x%08x)\n", ffl, b, e, size, size);
	if( lffl ) {
		if ( lfl == lffl ) { /* b-e is loacated in the same range */
			tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
			tfl->begin = e;
			tfl->end = lfl->end;
			VG_(strcpy)(tfl->info, lfl->info);
			lfl->end = b;
			tfl->next = lfl->next;
			lfl->next = tfl;
			isDel = 1;
			//VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
			//		isDel, ffl, b, e, size, size, lfl->info);
			return;
		}
	}
	if(ffl == NULL) { /* b is larger than the begin addr of the last range */
		if (lfl == NULL) { /* e is larger than the end addr of the last range */
			tl_assert( llfl == lffl );
			if ( lffl->end > b ) {  /* Overlap is (lffl->end->end - b) */
				lffl->end = b;
				isDel = 2;
			}
		}
	} else { /* b < ffl->begin */
		nlfl = lfl;
		/* Delete ranges between b and e */
		while( ffl != nlfl ) {
			tfl = ffl;
			ffl = ffl->next;
			VG_(free)(tfl);
			isDel = 3;
		}
		/* process the overlab */
		if( lffl ) { /* the first range is not freed */
			if( b < lffl->end ) { /* overlab is ( b - lffl->end ) */
				lffl->end = b;
				isDel = 4;
			}
			if( nlfl ) {
				if ( nlfl->begin < e ) { /* overlab is ( nlfl->begin - e) */
					nlfl->begin = e;
					isDel = 5;
				}
			}
			lffl->next = nlfl;
		} else { /* the first range node is also deleted */
			if( nlfl ) {
				if ( nlfl->begin < e ) { /* overlab is ( nlfl->begin - e) */
					nlfl->begin = e;
					isDel = 6; 
				}
			}
			*ppfl = nlfl;
		}
	}
	if( isDel > 0)
	{
		//VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
		//		isDel, ffl, b, e, size, size, info);
	}
	//if(isDel >= 5 && *ppfl == m_list)
	//	dumpFilterList(*ppfl);
}

void addFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size ) {
	struct FilterList *tfl, *llfl = NULL, *lfl = NULL, *lffl = NULL, *ffl = *ppfl;
	Addr b = avma;
	Addr e = avma+size;
	struct FilterList *nfl = NULL;
	Int isAdd = 0;
	if( size < 1 )
		return;

	if( ffl == NULL ) {
		tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
		tfl->begin = b;
		tfl->end = e;
		tfl->next = NULL;
		*ppfl = tfl;
		VG_(printf)("Add filter range(1): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", ffl, b, e, size, size, info);
		VG_(strcpy)(tfl->info, info);
		return;
	}
	while( ffl ) {
		if( ffl->begin >= b)
			break;
		lffl = ffl;
		ffl = ffl->next;
	}

	lfl = *ppfl;
	while( lfl ) {
		if ( lfl->end > e )
			break;
		llfl = lfl;
		lfl = lfl->next;
	}

	if( lffl && (lfl == lffl) ) {
		/* b-e is loacated in the same range */
		return;
	}

	if(ffl == NULL) { /* b is larger than the begin addr of the last range */
		if (lfl == NULL) { /* e is larger than the end addr of the last range */
			tl_assert( llfl == lffl );
			if ( lffl->end > b )  {/* new range is (lffl->end->end - e) */
				lffl->end = e;
			}	else { /* new range is ( b - e ) */
				tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
				nfl = tfl;
				isAdd = 1;
				tfl->begin = b;
				tfl->end = e;
				tfl->next = NULL;
				lffl->next = tfl;
			}
		}
	} else { /* b < ffl->begin */
		/* if lfl is NULL, b-e include all ranges */
		/* Delete ranges between b and e */
		while( ffl != lfl ) {
			tfl = ffl;
			ffl = ffl->next;
			VG_(free)(tfl);
		}
		/* process the overlab */
		if( lffl ) { /* the first range is not freed */
			if( lfl == NULL) {
				if ( b < lffl->end ) { /* new range is (lffl->end - e ) */
					lffl->end = e;
					lffl->next = NULL;
				} else { /* new range is ( b - e ) */
					tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
					nfl = tfl;
					isAdd = 2;
					tfl->begin = b;
					tfl->end = e;
					tfl->next = NULL;
					lffl->next = tfl;
				}
			} else {
				if ( b <= lffl->end ) { /* new range is (lffl->end - e ) */
					if ( e < lfl->begin ) {
						lffl->end = e;
						lffl->next = lfl;
					} else { /* new range is (lffl->end - lfl->begin) */
						lffl->end = lfl->end;
						lffl->next = lfl->next;
						VG_(free)(lfl);
					}
				} else { /* b > lffl->end */
					if ( e < lfl->begin ) { /* new range is (b-e) */
						tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
						nfl = tfl;
						isAdd = 3;
						tfl->begin = b;
						tfl->end = e;
						tfl->next = lfl;
						lffl->next = tfl;
					} else { /* e >= lfl->begin */
						/* new range is (b-lfl->begin) */
						lfl->begin = b;
						lffl->next = lfl;
					}
				}
			}
		} else { /* first range node is also freed */
			if ( lfl == NULL ||  e < lfl->begin ) { /* new range is (b-e) */
				tfl = (struct FilterList*)VG_(malloc)("addFilterList.1", sizeof( struct FilterList ));
				nfl = tfl;
				isAdd = 4;
				tfl->begin = b;
				tfl->end = e;
				tfl->next = lfl;
				*ppfl = tfl;
			} else { /* e >= lfl->begin */
				/* new range is (b-lfl->begin) */
				lfl->begin = b;
				*ppfl = lfl;
			}
		}
	}
	if( isAdd > 0 ) {
		tl_assert(nfl);
		VG_(printf)("Add filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", isAdd, ffl, b, e, size, size, info);
		VG_(strcpy)(nfl->info, info);
	}
	//if( size == 4668 )
	//	dumpFilterList(*ppfl);
}
void initFilterlist() {
	HChar *soname;
	Addr avma;
	SizeT size;
	struct LibList *tll;
	struct FunList *tfl;
	DebugInfo* di = VG_(next_DebugInfo) ( NULL );
	BG_LOGI("first di_0x%x\n", (Addr)di);
	while(di) {
		soname = VG_(DebugInfo_get_filename)(di);

		if( VG_(memcmp)(soname, "/data/", 6) != 0)
		{
			avma = VG_(DebugInfo_get_text_avma) (di);
			size = VG_(DebugInfo_get_text_size) (di);
			addFilterList( &fl, soname, avma, size );
		}
#if 0
		soname = VG_(DebugInfo_get_soname)(di);
#ifdef OAT_TRACK
		if(VG_(is_oat)(di)) {
			BG_LOGI("Found OAT file %s \n", soname);
			Addr oatdata, oatexec;
			UInt datasize, execsize;
			if(VG_(get_oat_range)(di, &oatdata, &datasize, &oatexec, &execsize, NULL)) {
				if(oatdata > 0)
					oatDexParse(oatdata, datasize, oatexec, execsize);
			}
		}
#endif
		/* Get the debug info of soname */
		tll = findLib( soname );
		if( tll )
		{
			BG_LOGI("Add library %s to list\n", soname);
			tfl = tll->flist;
			if( tfl ) {
				while( tfl ) {
					tl_assert(tfl->name);
					BG_LOGI("Add function %s to list\n", tfl->name);
					if ( VG_(get_symbol_range_SLOW)( di, tfl->name, &avma, &size ) )
						addFilterList( avma, size );
					tfl = tfl->next;
				}
			} else {
				avma = VG_(DebugInfo_get_text_avma) (di);
				size = VG_(DebugInfo_get_text_size) (di);
				addFilterList( avma, size );
			}
		}
#endif
		di = VG_(next_DebugInfo)(di);
	}
}

void releaseFilterlist(struct FilterList** ppfl) {
	struct FilterList* tfl = *ppfl, *nfl;
	while ( tfl ) {
		nfl = tfl->next;
		VG_(free) ( tfl );
		tfl = nfl;
	}
	*ppfl = NULL;
}

Addr isInFilterList(struct FilterList* pfl, Addr a, HChar** pInfo) {
	struct FilterList* tfl = pfl;
	while ( tfl ) {
		if( a < tfl->begin )
			return 0;
		if( a < tfl->end ) {
			if(pInfo)
				*pInfo = tfl->info;
			return tfl->begin;
		}
		tfl = tfl->next;
	}
	return 0;
}

static INLINE
Bool is_instrument_needed( VgCallbackClosure* closure ) {
	Addr a = closure->nraddr;
	return !isInFilterList(fl, a, NULL);
}

/*---------------------- 2.0 stmt tracing related helpers  ------------------------------*/

static IRTemp newTemp ( BGEnv* bge, IRType ty, TempKind kind )
{
	//Word       newIx;
	//TempMapEnt ent;
	IRTemp     tmp = newIRTemp(bge->sb->tyenv, ty);
	//ent.kind    = kind;
	//   ent.shadowV = IRTemp_INVALID;
	//   ent.shadowB = IRTemp_INVALID;
	//newIx = VG_(addToXA)( bge->tmpMap, &ent );
	//tl_assert(newIx == (Word)tmp);
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
static inline void stmt ( HChar cat, BGEnv* bge, IRStmt* st ) { //385
	if (bge->trace) {
		VG_(printf)("  %c: ", cat);
		ppIRStmt(st);
		VG_(printf)("\n");
	}
	addStmtToIRSB(bge->sb, st);
}
/* assign value to tmp */
static inline
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
	//   IRExpr* e;

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
				//         return assignNew( 'C', bge, Ity_I32, unop(Iop_F64toI32,
				//                      assignNew( 'C', bge, Ity_I32, unop(Iop_F32toF64, value) ) ) );
			case Ity_F64:
				return assignNew( 'C', bge, tyH, unop(Iop_64to32, 
							assignNew( 'C', bge, Ity_I64, unop(Iop_ReinterpF64asI64, value) ) ) );
				//         return assignNew( 'C', bge, Ity_I32, unop(Iop_F64toI32U, value) );
			case Ity_V128: // Comment by Rewhy
				// return assignNew( 'C', bge, tyH, unop(Iop_V128to32, value) );
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
	} else if(bge->hWordTy == Ity_I64){
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
	}else
		VG_(tool_panic)("bg_translate.c: create_dirty_STORE: Unknown platform");

	return unsafeIRDirty_0_N ( nargs/*regparms*/, nm, VG_(fnptr_to_fnentry)( fn ), args );
}


	static
void do_trace_WRTMP ( BGEnv* bge, IRStmt *clone, IRTemp tmp, IRExpr* expr )
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
	static
void do_trace_Store( BGEnv* bge,
		IRStmt *clone,
		IREndness end,
		IRAtom* addr, UInt bias,
		IRAtom* data, IRAtom* vdata,
		IRAtom* guard)
{
	IRType				tyAddr;
	void*					helper = NULL;
	const HChar*  hname  = NULL;
	IRDirty* di2;

	tyAddr = bge->hWordTy;
	tl_assert( tyAddr == Ity_I32 || tyAddr == Ity_I64 );
	tl_assert( end == Iend_LE || end == Iend_BE );
	if(guard)
		tl_assert(typeOfIRExpr(bge->sb->tyenv, guard) == Ity_I1);

	if (data) {
		tl_assert(isOriginalAtom(bge, data));
		tl_assert(bias == 0);
	}

	tl_assert(isOriginalAtom(bge, addr));

	if (guard) {
		tl_assert(isOriginalAtom(bge, guard));
		tl_assert(typeOfIRExpr(bge->sb->tyenv, guard) == Ity_I1);
	}

	/* Get the type of vdata */
	//ty = typeOfIRExpr(bge->sb->tyenv, vdata);

	if( data && clone ){ /* Ist_Store */
		di2 = create_dirty_STORE( bge, clone, end, 0/*resSC*/, addr, data );
		if ( di2 ) {
			if(guard) {
				di2->guard = guard;
			}
			setHelperAnns( bge, di2 );
			stmt( 'V', bge, IRStmt_Dirty(di2));
		} else {
		}
		return;
	}
}

static
void do_trace_StoreG( BGEnv* bge, 
		IRStmt *clone,
		IRStoreG* sg) {
	do_trace_Store( bge, clone, sg->end,
			sg->addr, 0,
			sg->data,
			NULL,
			sg->guard);
}

static
void do_trace_LoadG( BGEnv* bge, 
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
#if 1
static void trace_superblock(Addr addr)
{
	HChar* client_binary_name;
	DebugInfo* di = VG_(find_DebugInfo)(addr);
	if (di && VG_(strcmp)(VG_(DebugInfo_get_soname)(di), "NONE") == 0) {
		client_binary_name = (HChar*)VG_(malloc)("client_binary_name",sizeof(HChar)*(VG_(strlen)(VG_(DebugInfo_get_filename)(di)+1)));
		VG_(strcpy)(client_binary_name, VG_(DebugInfo_get_filename)(di));
	}
	const HChar *fnname = VG_(describe_IP) ( addr, NULL );
	VG_(printf)("SB %08lx %s %s\n", addr, client_binary_name, fnname);
}
#endif 
//#define OUTPUT_BB	1
IRSB* BG_(instrument)( VgCallbackClosure* closure,
		IRSB* sbIn,
		const VexGuestLayout*		guestlayout,
		const VexGuestExtents*	vge, 
		const VexArchInfo*			archinfo_host,
		IRType	gWordTy, IRType	hWordTy )
{
	if( BG_(clo_trace_begin) == False ) {
		return sbIn;
	}
	if(BG_(is_instrument_load) == False  && BG_(is_instrument_store) == False)
		return sbIn;
	Int i, j;
	IRStmt*	st;
	BGEnv		bge;
	IRSB*		sbOut;
#if 0
	HChar *fnname = VG_(describe_IP) ( closure->nraddr, NULL );
	VG_(printf)("BB: %s\n", fnname);
#endif

#if 0 // For debug
	if( BG_(clo_trace_begin) == False )
		return sbIn;
	IRDirty*   di;
	sbOut = deepCopyIRSBExceptStmts(sbIn);
	i = 0;
	while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
		addStmtToIRSB( sbOut, sbIn->stmts[i] );
		i++;
	}
	di = unsafeIRDirty_0_N( 
			0, "trace_superblock", 
			VG_(fnptr_to_fnentry)( &trace_superblock ),
			mkIRExprVec_1( mkIRExpr_HWord( vge->base[0] ) ) 
			);
	addStmtToIRSB( sbOut, IRStmt_Dirty(di) );
	for (/*use current i*/; i < sbIn->stmts_used; i++) {
		IRStmt* st = sbIn->stmts[i];
		if (!st || st->tag == Ist_NoOp) continue;
		addStmtToIRSB( sbOut, st );
	}
	//VG_(printf)("sbOut:\n");
	ppIRSB(sbOut);
	return sbOut;
#endif
	if( LIKELY(is_instrument_needed( closure ) == False)) {
		return sbIn;
	}
	if (gWordTy != hWordTy) {
		VG_(tool_panic)("host/guest word size dismatch");
	}

#if  OUTPUT_BB
	VG_(printf)("Input: \n");
	ppIRSB(sbIn);
#endif

	/* set up SB */
	sbOut = deepCopyIRSBExceptStmts(sbIn);

	VG_(memset)(&bge, 0, sizeof(bge));
	bge.sb				= sbOut;
	bge.trace			= False;
	bge.layout		= guestlayout;
	bge.hWordTy		= hWordTy;
	bge.bogusLiterals = False;

	//	mce.tmpMap = VG_(newXA)( VG_(malloc), "bg.BG_(instrument).1", VG_(free),
	//      sizeof(TempMapEnt));

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

	for( ; i < sbIn->stmts_used; i ++ ) {
		st = sbIn->stmts[i];
		IRStmt *stclone = deepMallocIRStmt(st);
		switch (st->tag) {
			case Ist_WrTmp:
				stmt( 'C', &bge, st );
				if( BG_(is_instrument_load) ) {
					do_trace_WRTMP( &bge,
							stclone,
							st->Ist.WrTmp.tmp,
							st->Ist.WrTmp.data);
				}
				break;
			case Ist_Put:
			case Ist_PutI:
				stmt( 'C', &bge, st );
				break;
			case Ist_Store:				/* ST<end>(<addr>) = <data> */
				if( BG_(is_instrument_store) ) {
					do_trace_Store( &bge, 
							stclone, 
							st->Ist.Store.end,
							st->Ist.Store.addr,
							0,
							st->Ist.Store.data,
							NULL, 
							NULL);
				}
				stmt( 'C', &bge, st );
				break;
			case Ist_StoreG:			/* if(<guard>) ST<end>(<addr>) = <data> */
				if( BG_(is_instrument_store) ) {
					do_trace_StoreG( &bge,
							stclone,
							st->Ist.StoreG.details);
				}
				stmt( 'C', &bge, st );
				break;
			case Ist_LoadG:				/* t<tmp> = if(<guard>) <cvt>(LD<end>(<addr>)) else <alt> */
				stmt( 'C', &bge, st );
				if( BG_(is_instrument_load) ) {
					do_trace_LoadG( &bge,
							stclone,
							st->Ist.LoadG.details);
				}
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
