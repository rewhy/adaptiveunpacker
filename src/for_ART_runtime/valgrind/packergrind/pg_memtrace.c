// pg_memtrace.c

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)

#include "pg_debug.h"
#include "pg_memtrace.h"

static Int filterNum  = 0;
static struct LibList* lib_list = NULL;
/* List storing the debuginfo of the elf files of which all the .text or part of the .text
 * have no need to be instrumented */
static struct FilterList* fl_mem_syslib	= NULL;   /* Filter list of system libraries */
static struct FilterList* fl_mem_file		= NULL;   /* List of the important address realated to file data (mmap/read) */
static struct FilterList* fl_mem_map		= NULL; /* memory mapped executable segments */
// struct FilterList *dml						= NULL;

static void dumpFilterList(struct FilterList *pfl) {
	struct FilterList* ttt = pfl;
	while(ttt) {
		VG_(printf)("Filter map: 0x%08x - 0x%08x info:%s\n", 
				ttt->begin, ttt->end, ttt->info);
		ttt = ttt->next;
	}
}

static void delFilterList(struct FilterList** ppfl, const HChar *info, Addr avma, SizeT size )
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
			VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
					isDel, ffl, b, e, size, size, lfl->info);
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
		VG_(printf)("Del filter range(%d): 0x%08x 0x%08x - 0x%08x %10d(0x%08x) %s\n", 
				isDel, ffl, b, e, size, size, info);
	}
	//if(isDel >= 5 && *ppfl == fl_mem_map)
	//	dumpFilterList(*ppfl);
}

static void addFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size ) {
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

static void releaseFilterList(struct FilterList** ppfl) {
	struct FilterList* tfl = *ppfl, *nfl;
	while ( tfl ) {
		nfl = tfl->next;
		VG_(free) ( tfl );
		tfl = nfl;
	}
	*ppfl = NULL;
}

static Addr isInFilterList(struct FilterList* pfl, Addr a, HChar** pInfo) {
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


/* Get the library filter node of soname */
static struct LibList* findLib(const HChar* soname) {
	BG_LOGI("Check so %s\n", soname);
	struct LibList *tll = lib_list;
	while ( tll ) {
		if( VG_(strcmp) ( soname, tll->name ) == 0 )
			return tll;
		tll = tll->next;
	}
	return NULL;
}



/* If fnname is null, all the .text section is added to the filter list;
 * else only the code range of symbol funname in soname is added */
Bool addFilterFun(const HChar* soname, const HChar* fnname) {
	struct LibList *tll = lib_list;
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
		tll->next = lib_list;
		lib_list = tll;
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
			addFilterList( &fl_mem_syslib, soname, avma, size );
		}
		di = VG_(next_DebugInfo)(di);
	}
}

void initSoaapData() {
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
}

Bool isInstrumentNeeded( VgCallbackClosure* closure ) {
	Addr a = closure->nraddr;
	return !isInFilterList(fl_mem_syslib, a, NULL);
}


/* Exported functions released to memory map list */
void addTraceMemMap(Addr addr, Int size, Int prot, HChar *info)
{
	addFilterList(&fl_mem_map, info, addr, size);
}

void delTraceMemMap(Addr addr, Int size)
{
	delFilterList(&fl_mem_map, "memory.map",  addr, size);
}

void releaseTraceMemMap(void) {
	releaseFilterList(fl_mem_map);
}

Bool isInTraceMemMap(Addr a, HChar** pInfo) {
	//return True;
	return isInFilterList(fl_mem_map, a, pInfo);
}

Bool getTraceMemMapInfo(Addr addr, Int prot, HChar **pinfo) 
{
	Addr a = isInFilterList(fl_mem_map, addr, pinfo);
	if(a > 0) {
		return True;
	}
	else {
		return False;
	}
}

// Release the monitored memory of system libraries
void releaseTraceMemSyslib(void) {
	releaseFilterList(fl_mem_syslib);
}

// Release the monitored memory of important files
void releaseTraceMemFile(void) {
	releaseFilterList(fl_mem_file);
}

// Check whether the target address locating in monitore files' memory
Bool isInTraceMemFile(Addr a, HChar** pInfo) {
	return isInFilterList(fl_mem_file, a, pInfo);
}

Bool isInTraceMemSyslib(Addr a, HChar** pInfo) {
	return isInFilterList(fl_mem_syslib, a, pInfo);
}

