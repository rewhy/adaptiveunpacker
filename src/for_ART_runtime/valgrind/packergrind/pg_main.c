// bg_main.c

#include "pub_tool_basics.h"
#include "pub_tool_tooliface.h"
#include "pub_core_libcsignal.h"
#include "pub_tool_vki.h"           // keeps libcproc.h happy, syscall nums
#include "pub_tool_vkiscnums.h"
#include "pub_tool_aspacemgr.h"     // VG_(am_shadow_alloc)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)
#include "pub_tool_hashtable.h"     // For tnt_include.h, VgHashtable
#include "pub_tool_libcassert.h"    // tl_assert
#include "pub_tool_libcbase.h"      // VG_STREQN
#include "pub_tool_libcprint.h"     // VG_(message)
#include "pub_tool_libcproc.h"      // VG_(getenv)
#include "pub_tool_replacemalloc.h" // VG_(replacement_malloc_process_cmd_line_option)
#include "pub_tool_machine.h"       // VG_(get_IP)
#include "pub_tool_mallocfree.h"    // VG_(out_of_memory_NORETURN)
#include "pub_tool_options.h"       // VG_STR/BHEX/BINT_CLO
#include "pub_tool_oset.h"          // OSet operations
#include "pub_tool_threadstate.h"   // VG_(get_running_tid)
#include "pub_tool_xarray.h"        // VG_(*XA)
#include "pub_tool_stacktrace.h"    // VG_(get_and_pp_StackTrace)
#include "pub_tool_libcfile.h"      // VG_(readlink)
#include "pub_tool_addrinfo.h"      // VG_(describe_addr)
#include "pub_tool_machine.h"
#include "pub_tool_transtab.h"    // VG_(discard_translations_safely)

#include "unistd-asm-arm.h"

#include "packergrind.h"
#include "pg_debug.h"
#include "pg_translate.h"
#include "pg_wrappers.h"
#include "pg_mthtrace.h"
#include "pg_framework.h"
#include "pg_dexparse.h"
#include "pg_oatparse.h"

#ifdef VMP_SUPPORT
extern Int    pg_start_method_index;
extern HChar* pg_start_clazz;
extern HChar* pg_start_method_name;
extern HChar* pg_start_method_shorty;

extern Int    pg_stop_method_index;
extern HChar* pg_stop_clazz;
extern HChar* pg_stop_method_name;
extern HChar* pg_stop_method_shorty;

extern HChar* pg_main_activity;

extern Int    pg_main_oncreate_index;
#endif

static DebugInfo*	di_libart		= NULL;
static Addr libart_text_addr	= 0;
static UInt libart_text_size	= 0;

static Addr base_oatdata_addr = 0;
static UInt base_oatdata_size = 0;
static Addr base_oatexec_addr = 0;
static UInt base_oatexec_size = 0;
static Addr boot_oatdata_addr = 0;
static UInt boot_oatdata_size = 0;
static Addr boot_oatexec_addr = 0;
static UInt boot_oatexec_size = 0;

/* Command parameters */
Bool BG_(is_instrument)  	= False;
Bool BG_(is_instrument_load)	= False;
Bool BG_(is_instrument_store)	= False;
Bool BG_(is_trace_syscall)  	= False;
Bool BG_(is_trace_framework)	= False;
UInt BG_(time_slow)						= 1;

HChar*	pg_trace_package		= NULL;

/* End */

struct fd_info fds[TG_N_THREADS][FD_MAX];
Bool BG_(clo_trace_begin) = False;
Int		th_status[TG_N_THREADS] = {-1};
Bool  th_is_loading[TG_N_THREADS] = {False};

#if DBG_OAT_PARSE
Bool is_parse_oat = False;
#endif
UInt	oat_file_type = oatTypeUnknown;



struct DexFilePlus*	pAppDexFileObj = NULL;
//char loadLibrary[256] = {'\0'};
#if 0
void dumpTest() {
	VG_(printf)("%s\n" , "DUMP TEST:");
	struct FilterList *ttt;
	addFilterList(&ttt, "test", 928559144, 4076);
	addFilterList(&ttt, "test", 928559104, 5760);
	addFilterList(&ttt, "test", 100, 100);
	addFilterList(&ttt, "test", 200, 300);
	addFilterList(&ttt, "test", 1000, 200);
	addFilterList(&ttt, "test", 1400, 100);
	addFilterList(&ttt, "test", 1600, 100);
	addFilterList(&ttt, "test", 1800, 100);
	addFilterList(&ttt, "test", 2800, 200);
	addFilterList(&ttt, "test", 2800, 200);
	addFilterList(&ttt, "test", 3000, 200);
	addFilterList(&ttt, "test", 3400, 200);
	addFilterList(&ttt, "test", 200, 1000);
	addFilterList(&ttt, "test", 1, 1);
	addFilterList(&ttt, "test", 5, 1);
	addFilterList(&ttt, "test", 10, 1);
	addFilterList(&ttt, "test", 15, 1);
	tl_assert(0);
}
#endif

static void  parseOatMem(HChar *oatFile, Bool isParse)
{
	HChar*	soname = NULL;
	Addr		oatdata, oatexec;
	SizeT		oatdataSize, oatexecSize;
	BG_LOGI("Try to pase oat file: %s\n", oatFile);
	DebugInfo* di = VG_(next_DebugInfo)(NULL);
	while(di) {
		if(!VG_(DebugInfo_is_oat)(di)) {
			di = VG_(next_DebugInfo)(di);
			continue;
		}
		soname = VG_(DebugInfo_get_soname)(di);
		if(VG_(strstr)(oatFile, soname) != NULL) {
			if(VG_(get_symbol_range_SLOW)(di, "oatdata", &oatdata, &oatdataSize) 
					&& VG_(get_symbol_range_SLOW)(di, "oatexec", &oatexec, &oatexecSize)) {
				BG_LOGI("oatexec: 0x%08x - 0x%08x len=%d\n", oatexec, oatexec+oatexecSize, oatexecSize);
				BG_LOGI("oatdata: 0x%08x - 0x%08x len=%d\n", oatdata, oatdata+oatdataSize, oatdataSize);
#if DBG_OAT_PARSE
				is_parse_oat = isParse;
#endif
				oatDexParse(NULL, oatdata, oatdataSize, oatexec, oatexecSize);
#if DBG_OAT_PARSE
				is_parse_oat = False;
#endif
				break;
			}
		}
		di = VG_(next_DebugInfo)(di);
	}
}


static void parseOatFile(HChar *oatFile) {
	HChar *soname = NULL;
	Addr oatdata, oatexec;
	SizeT oatdataSize, oatexecSize;

	DebugInfo* di = VG_(next_DebugInfo) (NULL);
	VG_(printf)("Try to parse the Oat files...\n");
	while(di) {
		soname = VG_(DebugInfo_get_soname)(di);
		if(VG_(DebugInfo_is_oat)(di)) {
			BG_LOGI("Meet oat file: %s\n", soname);
			if((oatFile != NULL) && (VG_(strcmp)(soname, oatFile) != 0))
				continue;
			if(VG_(get_symbol_range_SLOW)(di, "oatdata", &oatdata, &oatdataSize)) {
				BG_LOGI("oatdata: 0x%08x - 0x%08x len=%d\n", oatdata, oatdata+oatdataSize, oatdataSize);
				if(VG_(get_symbol_range_SLOW)(di, "oatexec", &oatexec, &oatexecSize)) {
					BG_LOGI("oatexec: 0x%08x - 0x%08x len=%d\n", oatexec, oatexec+oatexecSize, oatexecSize);
					//if( (VG_(strcmp)("classes.oat", soname) == 0) ) // Custom oat file of Qihoo
					if( (VG_(strcmp)("base.odex", soname) == 0) ) // Custom oat file of Baidu
					{
#if DBG_OAT_PARSE
						is_parse_oat = True;
						//is_parse_oat = False;
#endif
						oatDexParse(NULL, oatdata, oatdataSize, oatexec, oatexecSize);
#if DBG_OAT_PARSE
						is_parse_oat = False;
#endif
						base_oatdata_addr = oatdata;
						base_oatdata_size = oatdataSize;
						base_oatexec_addr = oatexec;
						base_oatexec_size = oatexecSize;
					} else if (( VG_(strcmp)("system@framework@boot.oat", soname) == 0) ) { // Framework oat file
						if(boot_oatdata_addr == 0) {
							// is_parse_oat = True;
							// oatDexParse(oatdata, oatdataSize, oatexec, oatexecSize);
							// is_parse_oat = False;
							boot_oatdata_addr = oatdata;
							boot_oatdata_size = oatdataSize;
							boot_oatexec_addr = oatexec;
							boot_oatexec_size = oatexecSize;
						}
					} else {
#if DBG_OAT_PARSE
						is_parse_oat = True;
#endif
						oatDexParse(NULL, oatdata, oatdataSize, oatexec, oatexecSize);
#if DBG_OAT_PARSE
						is_parse_oat = False;
#endif
					}
				}
			}
		} else if(oatFile == NULL){
			BG_LOGI("Meet so file: %s\n", soname);
			if(VG_(strcmp)("libart.so", soname) == 0) {
				di_libart = di;
				libart_text_addr = VG_(DebugInfo_get_text_avma) (di);
				libart_text_size = VG_(DebugInfo_get_text_size) (di);
				BG_LOGI("Meet so file: %s 0x%08x - 0x%08x\n", soname, libart_text_addr, libart_text_addr + libart_text_size);
				//VG_(print_sym_table)(di);
			}
		}
		di = VG_(next_DebugInfo)(di);
	}
}

Bool isFrameworkClass(HChar* desc) {
	if(VG_(memcmp)("Ljava", desc, 5) == 0)
		return True;
	if(VG_(memcmp)("Landroid", desc, 8) == 0)
		return True;
	if(VG_(memcmp)("Llibcore", desc, 8) == 0)
		return True;
	if(VG_(memcmp)("Lcom/lang/", desc, 10) == 0)
		return True;
	if(VG_(memcmp)("Lcom/google/", desc, 12) == 0)
		return True;
	if(VG_(memcmp)("Lcom/android/", desc, 13) == 0)
		return True;
	if(VG_(memcmp)("Ldalvik/system/", desc, 15) == 0)
		return True;
	return False;
}

static void BG_(print_usage)(void) {}
static void BG_(print_debug_usage)(void){}

static Bool BG_(process_cmd_line_option)(const HChar* arg)
{
	if VG_STR_CLO(arg,  "--trace-package", pg_trace_package){}
	else if	VG_BOOL_CLO(arg, "--instrument",		BG_(is_instrument)) {}
	else if	VG_BOOL_CLO(arg, "--trace-load",		BG_(is_instrument_load)) {}
	else if VG_BOOL_CLO(arg, "--trace-store",		BG_(is_instrument_store)) {}
	else if VG_BOOL_CLO(arg, "--trace-syscall",	BG_(is_trace_syscall)) {}
	else if VG_BOOL_CLO(arg, "--trace-framework",	BG_(is_trace_framework)) {}
	else if VG_INT_CLO(arg, "--time-slow",    BG_(time_slow)) {}
#ifdef VMP_SUPPORT
	else if VG_INT_CLO(arg, "--start-index",    pg_start_method_index){}
	else if VG_STR_CLO(arg, "--start-method",   pg_start_method_name){VG_(printf)("Start method: %s\n", pg_start_method_name);}
	else if VG_STR_CLO(arg, "--start-shorty",   pg_start_method_shorty){VG_(printf)("Start shorty: %s\n", pg_start_method_shorty);}
	else if VG_INT_CLO(arg, "--stop-index",     pg_stop_method_index){}
	else if VG_STR_CLO(arg, "--stop-method",    pg_stop_method_name){VG_(printf)("Stop method: %s\n", pg_stop_method_name);}
	else if VG_STR_CLO(arg, "--start-class",    pg_start_clazz) {VG_(printf)("Start class: %s\n", pg_start_clazz);}
	else if VG_STR_CLO(arg, "--main-activity",  pg_main_activity) {VG_(printf)("Main activity: %s\n", pg_main_activity);}
	else if VG_STR_CLO(arg, "--stop-class",     pg_stop_clazz) {VG_(printf)("Stop class: %s\n", pg_stop_clazz);}
#endif
	else 
		return VG_(replacement_malloc_process_cmd_line_option)(arg);

	return True;
}

void BG_(set_instrument_state)(const HChar *reason, Bool state) {
	if( BG_(clo_trace_begin) == state ) {
		BG_LOGI("%s: instrumentation already %s\n",
				reason, state ? "ON" : "OFF");
		return;
	}
	BG_(clo_trace_begin) = state;
#if 1
	BG_LOGI("Try to discard translations safely.\n");
	VG_(discard_translations_safely)( (Addr)0x1000, ~(SizeT)0xfff, "packergrind");
	BG_LOGI("Finish discarding translations safely.\n");
#else
	VALGRIND_DISCARD_INS_CACHE(reason);
	if (state) 
		initFilterlist();
	else {
		//releaseFilterlist(&fl);
		releaseTraceMemSyslib();
		// releaseFilterlist(&dlibl);
		releaseTraceMemFile();
		releaseDexFileList();
	}
#endif

	BG_LOGI("%s: Switch instrumentation %s ... \n",
			reason, state ? "ON" : "OFF");

	if (VG_(clo_verbosity) > 1)
		VG_(message)(Vg_DebugMsg, "%s: instrumentation switched %s\n",
				reason, state ? "ON" : "OFF");
}
/*------------------------------------------------------------*/
/*--- Register event handlers                       ---*/
/*------------------------------------------------------------*/
static
void bg_pre_mem_read ( CorePart part, ThreadId tid, const HChar* s,
		Addr base, SizeT size ) {
	BG_LOGI("pre_read(%d): 0x%x %d %s\n", tid, base, size, s);
}
static
void bg_pre_mem_read_asciiz ( CorePart part, ThreadId tid, const HChar* s,
		Addr str ) {
	BG_LOGI("pre_read_asciiz(%d): 0x%x %s\n", tid, str, s);
}
static
void bg_pre_mem_write ( CorePart part, ThreadId tid, const HChar* s,
		Addr base, SizeT size ) {
	if (BG_(clo_trace_begin))
		BG_LOGI("pre_write(%d): 0x%x %d %s\n", tid, base, size, s);
}
static
void bg_post_mem_write ( CorePart part, ThreadId tid, Addr a, SizeT len) {
	BG_LOGI("post_write(%d): 0x%x %d\n", tid, a, len);
}

/* When some chunk of guest state is written, mark the corresponding
	 shadow area as valid.  This is used to initialise arbitrarily large
	 chunks of guest state, hence the _SIZE value, which has to be as
	 big as the biggest guest state.
	 */
static void bg_post_reg_write ( CorePart part, ThreadId tid,
		PtrdiffT offset, SizeT size)
{
	BG_LOGI("post_reg_write(%d): offset_%d size_%d\n", tid, offset, size);
}

static void bg_post_reg_write_clientcall ( ThreadId tid,
		PtrdiffT offset, SizeT size, Addr f)
{
	if (BG_(clo_trace_begin))
		BG_LOGI("post_reg_write_clientcall(%d): offset_%d size_%d a_0x%x\n", tid, offset, size, f);
	//bg_post_reg_write(/*dummy*/0, tid, offset, size);
}


/*------------------------------------------------------------*/
/*--- Register-memory event handlers                       ---*/
/*------------------------------------------------------------*/
static void bg_copy_mem_to_reg ( CorePart part, ThreadId tid, Addr a,
		PtrdiffT guest_state_offset, SizeT size ) {
	if (BG_(clo_trace_begin))
		BG_LOGI("mem_to_reg(%d): a_0x%x -> r_%d %d\n", tid, a, guest_state_offset, size);
}

static void bg_copy_reg_to_mem ( CorePart part, ThreadId tid, 
		PtrdiffT guest_state_offset, Addr a, SizeT size ) {
	if (BG_(clo_trace_begin))
		BG_LOGI("reg_to_mem(%d): r_%d -> a_0x%x %d\n", tid, guest_state_offset,a, size);
}

static void bg_new_mem_startup ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx, 
		ULong di_handle ) {
	BG_LOGI("new_mem_startup: a_0x%x %d\n", a, len);
}

static void bg_track_copy_mem_remap ( Addr src, Addr dst, SizeT len) {
	ThreadId tid = VG_(get_running_tid)();
	BG_LOGI("copy_mem_remap(%d): a_0x%x -> a_0x%x %d\n", tid, src, dst, len);
}

static void bg_track_die_mem_stack_signal (Addr a, SizeT len) {
	if (BG_(clo_trace_begin))
	{
		BG_LOGI("die_mem_stack_signal: a_0x%x %d\n", a, len);
	}
}

void bg_track_pre_deliver_signal(ThreadId tid, Int sigNo, Bool tt)
{
	BG_LOGI(">> pre_signal(TID %u, sig %d, alt_st %s)\n",
			tid, sigNo, tt ? "yes":"no");
	if(sigNo == 9 || sigNo == 15) {
		releaseDexFileList();
	}
}

void bg_track_post_deliver_signal(ThreadId tid, Int sigNo)
{
	BG_LOGI(">> pre_signal(TID %u, sig %d)\n",
			tid, sigNo);
	if(sigNo == 9 || sigNo == 15) {
		releaseDexFileList();
	}
}
static void bg_track_die_mem_brk (Addr a, SizeT len) {
	if (BG_(clo_trace_begin))
	{
		BG_LOGI("die_mem_brk: a_0x%x %d\n", a, len);
	}
}

static void bg_track_new_mem_mmap ( Addr a, SizeT len, Bool rr, Bool ww, Bool xx,
		ULong di_handle ) {
	if(BG_(clo_trace_begin) == False)
		return;
	ThreadId tid = VG_(get_running_tid)();
	BG_LOGI("new_mem_mmap(%d): a_0x%08x-0x%08x %c%c%c\n", tid, a, a+len-1,
			rr?'r':'-', ww?'w':'-', xx?'x':'-');
}

static void bg_track_change_mem_mprotect ( Addr a, SizeT len, Bool rr, Bool ww, 
		Bool xx) {
	if(BG_(clo_trace_begin) == False)
		return;
	ThreadId tid = VG_(get_running_tid)();
	BG_LOGI("change_mem_mprotect(%d): a_0x%08x-0x%08x %c%c%c\n", tid, a, a+len-1,
			rr?'r':'-', ww?'w':'-', xx?'x':'-');
}

static void bg_track_die_mem_munmap (Addr a, SizeT len) {
	if(BG_(clo_trace_begin) == False)
		return;
	ThreadId tid = VG_(get_running_tid)();
	BG_LOGI("die_mem_munmap(%d): a_0x%08x-0x%08x %d\n", tid, a, a+len-1);
}

	static
void bg_discard_superblock_info ( Addr orig_addr, VexGuestExtents vge )
{
	tl_assert(vge.n_used > 0);
	if (1)
		VG_(printf)( "discard_superblock_info: oa_0x%x, ba_%x, %llu, %d\n",
				(void*)orig_addr,
				(void*)vge.base[0], (ULong)vge.len[0],
				vge.n_used);

	// Get BB info, remove from table, free BB info.  Simple!
	// When created, the BB is keyed by the first instruction address,
	// (not orig_addr, but eventually redirected address). Thus, we
	// use the first instruction address in vge.
}

const HChar* SHUTDOWN_HOW[3] = {
	"SHUT_RD",
	"SHUT_WR",
	"SHUT_RDWR"
};
/* Address family has 42 types in total, now we only suports the 11 most popular types */
const HChar* ADDRESS_FAMILY[11] = {
	/* 0*/"AF_UNSPEC",
	/* 1*/"AF_UNIX/LOCAL",
	/* 2*/"AF_INET",
	/* 3*/"AF_AX25",
	/* 4*/"AF_IPX",
	/* 5*/"AF_APPLETALK",
	/* 6*/"AF_NETROM",
	/* 7*/"AF_BRIDGE",
	/* 8*/"AF_ATMPVC",
	/* 9*/"AF_X25",
	/*10*/"AF_INET6",
	/*11*/"AF_ROSE",     /* Amateur Radio X.25 PLP       */
	/*12*/"AF_UNKNOWN",
	/*13*/"AF_MAX",      /* For now.. */
	/*14*/"AF_UNKNOWN",
	/*15*/"AF_UNKNOWN",
	/*16*/"AF_UNKNOWN",
	/*17*/"AF_PACKET"    /* Forward compat hook          */
};
/* Protocol family also has 42 types, each of which has one corresponding addres type */
const char* PROTOCOL_FAMILY[11] = {
	/* 0*/"PF_UNSPEC",
	/* 1*/"PF_UNIX/LOCAL",
	/* 2*/"PF_INET",
	/* 3*/"PF_AX25",
	/* 4*/"PF_IPX",
	/* 5*/"PF_APPLETALK",
	/* 6*/"PF_NETROM",
	/* 7*/"PF_BRIDGE",
	/* 8*/"PF_ATMPVC",
	/* 9*/"PF_X25",
	/*10*/"PF_INET6"
		/*11*/"PF_ROSE",   
	/*12*/"PF_UNKNOWN",
	/*13*/"PF_MAX",   
	/*14*/"PF_UNKNOWN",
	/*15*/"PF_UNKNOWN",
	/*16*/"PF_UNKNOWN",
	/*17*/"PF_PACKET" 
};

/* Socket type */
const HChar* SOCKET_TYPE[11] = {
	/* 0*/"SOCK_UNKNOWN",
	/* 1*/"SOCK_STREAM",
	/* 2*/"SOCK_DGRAM",
	/* 3*/"SOCK_RAM",
	/* 4*/"SOCK_RDM",
	/* 5*/"SOCK_SEQPACKET",
	/* 6*/"SOCK_UNKNOWN",
	/* 7*/"SOCK_UNKNOWN",
	/* 8*/"SOCK_UNKNOWN",
	/* 9*/"SOCK_UNKNOWN",
	/*10*/"SOCK_PACKET",
};

/* dexFileParse flags */
const HChar* DEXFILEPARSE_FLAG[3] = { 
	"kDexParseDefault",					//     = 0,
	"kDexParseVerifyChecksum",	//     = 1,
	"kDexParseContinueOnError"  //     = (1 << 1),
};

HChar *inet_ntoa(struct in_addr in)
{ 
	static HChar b[18];
	register UChar *p = (UChar*)&in;
	VG_(snprintf)(b, sizeof(b), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return b;	
}

Int inet_aton(UChar *cp,	struct in_addr *ap)
{
	Int dots = 0;
	register UWord acc = 0, addr = 0;

	do {
		register char cc = *cp;

		switch (cc) {
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
				acc = acc * 10 + (cc - '0');
				break;

			case '.':
				if (++dots > 3) {
					return 0;
				}
				/* Fall through */

			case '\0':
				if (acc > 255) {
					return 0;
				}
				addr = addr << 8 | acc;
				acc = 0;
				break;

			default:
				return 0;
		}
	} while (*cp++) ;

	/* Normalize the address */
	if (dots < 3) {
		addr <<= 8 * (3 - dots) ;
	}

	/* Store it if requested */
	if (ap) {
		ap->s_addr = HTONL(addr);
	}

	return 1;    

}

HChar* mmap_proto2a(Int flag) {
	HChar pro[4] = {'\0'};
	pro[0] = (flag & PROT_READ) ? 'r' : '-';
	pro[1] = (flag & PROT_WRITE) ? 'w' : '-';
	pro[2] = (flag & PROT_EXEC) ? 'x' : '-';
	pro[3] = '\0';
	return pro;
}

static ULong	init_tv = 0;
#define DBG_SHOW_STRING 0
Bool BG_(handle_client_requests) ( ThreadId tid, UWord *arg, UWord *ret) {
	Int i;
	Addr bad_addr;
	switch (arg[0]) {
		case VG_USERREQ__WRAPPER_GETTIMEOFDAY:
			{
				ULong currt_tv;
				struct vki_timeval* tv = (struct vki_timeval*)arg[1];
				if(init_tv > 0) {
					currt_tv = tv->tv_sec * 1000000ULL + tv->tv_usec;
					currt_tv = (currt_tv - init_tv) / BG_(time_slow) + init_tv;
					tv->tv_sec  = currt_tv / 1000000;
					tv->tv_usec = currt_tv % 1000000;
				} else {
					init_tv = tv->tv_sec * 1000000ULL + tv->tv_usec;
				}
				BG_LOGI("[0]LIBCWRAP(%d): gettimeofday()\n", tid);
				break;
			}
		case VG_USERREQ__WRAPPER_SETITIMER:
			{
				UInt which = arg[1];
				struct vki_itimerval *new_value = (struct vki_itimerval *)arg[2];
				struct vki_itimerval *old_value = (struct vki_itimerval *)arg[3];
				if(new_value) {
					struct vki_timeval *nxt_tv    = &new_value->it_interval;
					struct vki_timeval *cur_tv		= &new_value->it_value;
					BG_LOGI("[0]LIBCWRAP(%d): setitimer() %lu %lu\n", tid, nxt_tv->tv_sec, nxt_tv->tv_usec);
				} else {
					BG_LOGI("[0]LIBCWRAP(%d): setitimer()\n", tid);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_TIMER_SETTIME:
			{
				UInt timerid = arg[1];
				UInt flags   = arg[2];
				struct vki_itimerspec *value = (struct vki_itimerspec *)arg[3];
				if(value) {
					struct  vki_timespec it_interval = value->it_interval;    /* timer period */
          struct  vki_timespec it_value    = value->it_value;       /* timer expiration */
					BG_LOGI("[0]LIBCWRAP(%d): timer_settime() %lu %lu\n", tid, it_value.tv_sec, it_value.tv_nsec);
				} else {
					BG_LOGI("[0]LIBCWRAP(%d): timer_settime()\n", tid);
				}
				break;
			}
#if MON_STR_OPERATIONS
		case VG_USERREQ__WRAPPER_MEMCMP:
			{
				Addr	dst	= (Addr)arg[1];
				Addr	src = (Addr)arg[2];
				SizeT	len	= (SizeT)arg[3];
				Char* pInfo = NULL;
				if( isInTraceMemMap(dst, &pInfo) ) {
					BG_LOGI("[0]LIBCWRAP(%d):memcpy/memove 0x%08x <-- 0x%08x %04d %s\n", 
							tid,  dst, src, len, pInfo);
				}

				break;
			}
		case VG_USERREQ__WRAPPER_STRSTR:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				BG_LOGI("[1]LIBCWRAP(%d):strstr 0x%8x(%s)  0x%8x(%s) res=0x%08x\n", tid, 
						(Int)arg[1], (HChar*)arg[1],	
						(Int)arg[2], (HChar*)arg[2], (UInt)arg[3]);
				break;
			}
		case VG_USERREQ__WRAPPER_MEMCHR:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				BG_LOGI("[1]LIBCWRAP(%d):memchr find 0x%x in 0x%08x(%s) len=%d res=0x%08x\n", tid, 
						arg[2], (UInt)arg[1], (HChar*)arg[1],	
						arg[3], arg[4]);
				break;
			}
		case VG_USERREQ__WRAPPER_STRNCMP:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				BG_LOGI("[1]LIBCWRAP(%d):strncmp compare 0x%08x(%s) in 0x%08x(%s) len=%d res=%d\n", tid, 
						(UInt)arg[1], (HChar*)arg[1],	
						(UInt)arg[2], (HChar*)arg[2],	
						arg[3], arg[4]);
				break;
			}
		case VG_USERREQ__WRAPPER_STRCMP:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				BG_LOGI("POSTREQ(%d):strcmp 0x%x(%s)  0x%x(%s)\n", tid, 
						(Int)arg[1], (HChar*)arg[1],	
						(Int)arg[2], (HChar*)arg[2]);
				break;
			}
#endif // MON_STR_OPERATIONS
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE:
			{
				HChar *path = (HChar*)arg[2];
				BG_LOGI("[0]LIBART[%d]:LoadNativeLibrary() 0x%08x(%s)\n",
						tid, (Addr)path, path);
				if(strlen(path) > 0) {
					if(VG_(memcmp)("/data/", path, 6) == 0 && pAppDexFileObj) {
					BG_(set_instrument_state)("Loaded_native_library", True);
					}
				}
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY:
			{
				HChar *path = (HChar*)arg[2];
				BG_LOGI("[1]LIBART[%d]:LoadNativeLibrary() 0x%08x(%s)\n", 
						tid, (Addr)path, path);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE:
			{
				HChar *descriptor = (HChar*)arg[1];
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader	 *pHeader			= pDexFileObj->header_;
				if(isFrameworkClass(descriptor))
					break;
				BG_LOGI("[0]LIBART[%d]:DefineClass() %s pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n", 
						tid, descriptor, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS:
			{
				HChar *descriptor = (HChar*)arg[1];
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader	 *pHeader			= pDexFileObj->header_;
				if(isFrameworkClass(descriptor))
					break;
				BG_LOGI("[1]LIBART[%d]:DefineClass() %s pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n", 
						tid, descriptor, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE_PRE:
			{
				struct MemMapPlus *pMemMapObj = (struct MemMapPlus*)arg[1];
				Addr	base = (Addr)arg[2];
				UInt  len	 = (UInt)arg[3];
				HChar *str = (HChar*)arg[4];
				BG_LOGI("[0]LIBART[%d]:DexFile() %s 0x%08x-0x%08x pMemMapObj=0x%08x\n", 
						tid, str, base, base+len, (Addr)pMemMapObj);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				Addr	base = (Addr)arg[2];
				UInt  len	 = (UInt)arg[3];
				HChar *str = (HChar*)arg[4];
				Addr	memmap = (Addr)arg[5];
				BG_LOGI("[1]LIBART[%d]:DexFile() pDexFileObj=0x%08x, pMemMapObj=0x%08x, memMap=0x%08x\n",
						tid, (Addr)pDexFileObj, (Addr)pMemMapObj, memmap);
				UInt *tt = (UInt*)arg[1];
				for(Int i = 0; i < 18; i++)
					VG_(printf)(" %x", tt[i]);
				VG_(printf)("\n");
				if(VG_(memcmp)("/data/", str, 6) == 0) {
					dumpDexFile((UChar*)pDexFileObj->begin_, pDexFileObj->size_);
					pAppDexFileObj = pDexFileObj;
				}
				//meetDexFilePlus(pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_, 2);
				// BG_LOGI("[1]LIBART[%d]:DexFile() pDexFileObj=0x%08x, pMemMapObj=0x%08x, mmap 0x%08x-0x%08x\n",
				//		tid, (Addr)pDexFileObj, (Addr)pMemMapObj,(Addr)pMemMapObj->begin_, (Addr)pMemMapObj->begin_ + pMemMapObj->size_);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILESETUP_PRE:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				const char*	abs_dex_location = (const char*)arg[2];
				int res = (int)arg[3];
				BG_LOGI("[0]LIBART[%d]:OatFile::Setup() OatFile=0x%08x Location=%s %s\n", tid, (Addr)pOatFileObj, pOatFileObj->location_.data, abs_dex_location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILESETUP:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				const char*	abs_dex_location = (const char*)arg[2];
				int res = (int)arg[3];
				BG_LOGI("[1]LIBART[%d]:OatFile::Setup() OatFile=0x%08x Location=%s\n", tid, (Addr)pOatFileObj, abs_dex_location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILEOPEN_PRE:
			{
				struct StdString* filename = (struct StdString*)arg[1];
				Addr	requested_base	= (Addr)arg[2];
				Addr	oat_file_begin	= (Addr)arg[3];
				char*	abs_dex_location	= (char*)arg[4];
				struct OatFile* pOatFileObj = (struct OatFile*)arg[5];
				//BG_LOGI("[0]LIBART[%d]:OatFile::Open() base=0x%08x OatFileBegin=0x%08x OatFile=0x%08x Location=%s\n",
				//		tid, requested_base, oat_file_begin, (Addr)pOatFileObj, abs_dex_location);
				BG_LOGI("[0]LIBART[%d]:OatFile::Open() pOatFileObj=0x%08x Location=%s", tid, (Addr)pOatFileObj, abs_dex_location);
				if(pOatFileObj) {
					BG_LOGI("\t0x%08x-0x%08x file=%s\n", pOatFileObj->begin_, pOatFileObj->end_, pOatFileObj->location_.data);
				} else {
					BG_LOGI("\n");
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILEOPEN:
			{
				struct StdString* filename = (struct StdString*)arg[1];
				Addr	requested_base	= (Addr)arg[2];
				Addr	oat_file_begin	= (Addr)arg[3];
				char*	abs_dex_location	= (char*)arg[4];
				struct OatFile* pOatFileObj = (struct OatFile*)arg[5];
				BG_LOGI("[1]LIBART[%d]:OatFile::Open() pOatFileObj=0x%08x Location=%s", tid, (Addr)pOatFileObj, abs_dex_location);
				if(pOatFileObj) {
					BG_LOGI("\t0x%08x-%08x file=%s\n", pOatFileObj->begin_, pOatFileObj->end_, pOatFileObj->location_.data);

					if (VG_(strstr)(pOatFileObj->location_.data, "boot.oat") != NULL)
					{
						oat_file_type = oatTypeBoot;
						parseOatMem(pOatFileObj->location_.data, True);
						// dumpOatMem(pOatFileObj->begin_, pOatFileObj->end_ - pOatFileObj->begin_ + 1);
					} else {
						oat_file_type = oatTypeBase;
						parseOatMem(pOatFileObj->location_.data, True);
					}
					/* if(VG_(memcmp)("/data/", pOatFileObj->location_.data, 6) == 0) {
						 Char dest[256];
						 VG_(sprintf)(dest, "/data/local/tmp/unpack/oat-0x%08x.odex", (Addr)pOatFileObj);
						 copyFile(pOatFileObj->location_.data, dest);
						 } */
				} else {
					BG_LOGI("\n");
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT_PRE:
			{
				char* dex_location = (char*)arg[1];
				char* oat_location = (char*)arg[2];
				void* class_linker = (void*)arg[3];
				BG_LOGI("[0]LIBART[%d]:ClassLinker::OpenDexFilesFromOat() %s %s %s\n", tid, dex_location, oat_location, (HChar*)class_linker);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT:
			{
				char* dex_location = (char*)arg[1];
				char* oat_location = (char*)arg[2];
				void* class_linker = (void*)arg[3];
				BG_LOGI("[1]LIBART[%d]:ClassLinker::OpenDexFilesFromOat() %s %s 0x%08x\n", tid, dex_location, oat_location, (Addr)class_linker);
				// BG_(set_instrumentsate)("OpenDexFilesFromOat()", True);
				// parseOatFile(NULL);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES_PRE:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				char*	 dex_location					= (char*)arg[2];
				BG_LOGI("[0]LIBART[%d]:Assistant::LoadDexFiles() pOatFileObj=0x%08x 0x%08x-0x%08x %s\n",
						tid, (Addr)pOatFileObj, pOatFileObj->begin_, pOatFileObj->end_, dex_location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				char*	 dex_location					= (char*)arg[2];
				BG_LOGI("[1]LIBART[%d]:Assistant::LoadDexFiles() pOatFileObj=0x%08x 0x%08x-0x%08x %s\n",
						tid, (Addr)pOatFileObj, pOatFileObj->begin_, pOatFileObj->end_, dex_location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE_PRE:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				char*  dex_location					= (char*)arg[2];
				BG_LOGI("[0]LIBART[%d]:OatFile::GetDexFile() pOatFileObj=0x%08x 0x%08x-0x%08x %s\n",
						tid, (Addr)pOatFileObj, pOatFileObj->begin_, pOatFileObj->end_, dex_location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE:
			{
				struct OatFile* pOatFileObj = (struct OatFile*)arg[1];
				char*  dex_location					= (char*)arg[2];
				struct OatDexFile *pOatDexFileObj = (struct OatDexFile*)arg[3];
				BG_LOGI("[1]LIBART[%d]:OatFile::GetDexFile() pOatDexFileObj=0x%08x\n", tid, (Addr)pOatDexFileObj);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE_PRE:
			{
				BG_LOGI("[0]LIBART[%d]:DexFile::openDexFileNative()\n", tid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE:
			{
				BG_LOGI("[1]LIBART[%d]:DexFile::openDexFileNative()\n", tid);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENDEXFILE_PRE:
			{
				struct OatDexFile	 *pOatDexFileObj = (struct OatDexFile*)arg[1];
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[3];
				struct OatFile		 *pOatFileObj = pOatDexFileObj->oat_file_;
				BG_LOGI("[0]LIBART[%d]:OatDexFile::OpenDexFile() pOatFileObj=0x%08x 0x%08x-0x%08x DexFilePointer=0x%08x", 
						tid, (Addr)pOatFileObj, pOatFileObj->begin_, pOatFileObj->end_, (Addr)pOatDexFileObj->dex_file_pointer_); // pOatDexFileObj->dex_file_location_.data);
				if(pDexFileObj) {
					BG_LOGI("\tpDexFileObj=0x%08x begin=0x%08x size=0x%08x\n", 
							pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_);
				} else {
					BG_LOGI("\tpDexFileObj=0x%08x\n", pDexFileObj);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_OPENDEXFILE:
			{
				struct OatDexFile	 *pOatDexFileObj = (struct OatDexFile*)arg[1];
				struct DexFilePlus *pDexFileObj = *((struct DexFilePlus**)arg[3]);
				struct OatFile		 *pOatFileObj = pOatDexFileObj->oat_file_;
				BG_LOGI("[1]LIBART[%d]:OatDexFile::OpenDexFile() pOatFileObj=0x%08x pOatDexFileObj=0x%08x %s", 
						tid, (Addr)pOatFileObj, (Addr)pOatDexFileObj, pOatDexFileObj->dex_file_location_.data);
				if(pDexFileObj) {
					BG_LOGI("\tpDexFileObj=0x%08x begin=0x%08x size=0x%08x\n", 
							pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_);
					/*if(VG_(memcmp)("/data/", pOatDexFileObj->dex_file_location_.data, 6) == 0) {
						dumpDexFile((UChar*)pDexFileObj->begin_, pDexFileObj->size_);
						pAppDexFileObj = pDexFileObj; // Open Dex file in OAT file
						addTraceMemMap(pDexFileObj->begin_, pDexFileObj->size_, 0, pOatDexFileObj->dex_file_location_.data);
						// addFilterList(&ttt, "test", 1000, 200);
					}*/
				} else {
					BG_LOGI("\tpDexFileObj=0x%08x\n", pDexFileObj);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY_PRE:
			{
				Addr base = (Addr)arg[1];
				UInt size = (UInt)arg[2];
				//char*		location = (char*)(*((int*)arg[3]+8));
				struct StdString*		location = (struct StdString*)arg[3];
				struct OatDexFile*	pOatDexFileObj = (struct OatDexFile*)arg[4];
				struct DexFilePlus*	pDexFileObj = (struct DexFilePlus*)arg[5];
				// struct OatFile*			pOatFileObj = pOatDexFileObj->oat_file_;
				BG_LOGI("[0]LIBART[%d]:DexFile::OpenMemory() 0x%08x-0x%08x pOatDexFileObj=0x%08x pDexFileObj=0x%08x 0x%08x %s\n",
						tid, base, base + size, (Addr)pOatDexFileObj, (Addr)pDexFileObj, (Addr)location, location->data);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY:
			{
				Addr base = (Addr)arg[1];
				UInt size = (UInt)arg[2];
				struct StdString*		location		= (struct StdString*)arg[3];
				struct OatDexFile*	pOatDexFileObj	= (struct OatDexFile*)arg[4];
				struct DexFilePlus*	pDexFileObj = *((struct DexFilePlus**)arg[5]);
				// struct OatFile*			pOatFileObj = pOatDexFileObj->oat_file_;
				BG_LOGI("[1]LIBART[%d]:DexFile::OpenMemory() 0x%08x-0x%08x pOatDexFileObj=0x%08x pDexFileObj=0x%08x %s\n",
						tid, base, base + size, (Addr)pOatDexFileObj, (Addr)pDexFileObj, location->data);
				if(pDexFileObj) {
					BG_LOGI("\tpDexFileObj=0x%08x begin=0x%08x size=0x%08x\n", 
							pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_);
					if(VG_(memcmp)("/data/", location->data, 6) == 0) {
						dumpDexFile((UChar*)pDexFileObj->begin_, pDexFileObj->size_);
						pAppDexFileObj = pDexFileObj; // Open Dex file directly
						addTraceMemMap(pDexFileObj->begin_, pDexFileObj->size_, 0, location);
					}
				}
				/*if(pMemMapObj) {
					BG_LOGI("\tmem_map: 0x%08x 0x%08x 0x%08x 0x%08x\n", 
					pMemMapObj->begin_, pMemMapObj->size_, pMemMapObj->base_begin_, pMemMapObj->base_size_);
				}*/
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE_PRE:
			{
				const char* location = (const char*)arg[2];
				BG_LOGI("[0]LIBART[%d]:DexFile::OpenFile() location=%s\n", tid, location);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE:
			{
				struct DexFilePlus *pDexFileObj = *((struct DexFilePlus**)arg[5]);
				const char* location = (const char*)arg[2];
				BG_LOGI("[1]LIBART[%d]:DexFile::OpenFile() pDexFileObj=0x%08x location=%s\n",
						tid, (Addr)pDexFileObj, location);
				/*if(VG_(memcmp)("/data/", location, 6) == 0) {
					dumpDexFile((UChar*)pDexFileObj->begin_, pDexFileObj->size_);
					pAppDexFileObj = pDexFileObj; // Open Dex file directly
					addTraceMemMap(pDexFileObj->begin_, pDexFileObj->size_, 0, location);
				}*/
				break;
			}
		case VG_USERREQ__WRAPPER_ART_REGISTERNATIVE:
			{
				struct ArtMethod *pAMth = (struct ArtMethod *)arg[1];
				HChar *codeInfo;
				if( BG_(clo_trace_begin) && pAMth) {
					codeInfo = VG_(describe_IP) ( arg[2], NULL );
					BG_LOGI("[1]LIBART[%d]:RegisterNative() pArtMethod=0x%08x nativeCode=0x%08x (%s)\n", 
							tid, (Addr)pAMth, (Addr)arg[2], codeInfo);
					MthCodeNode* mc = queryMthCodeNode((Addr)pAMth);
					if(mc) {
						HChar* clazz;
						HChar* mth;
						HChar* shorty;
						/* nativeCodeAddr store the address of DexFile object for JNI method */
						if(parseLoadedMethod((struct DexFilePlus*)mc->nativeCodeAddr, pAMth, &clazz, &mth, &shorty)) {
							BG_LOGI("\tJNI method: %s %s() %s\n", clazz, mth, shorty);
							add_method(clazz, mth, shorty, (Addr)arg[2]&~0x1, 0, pAMth->dex_method_index_, pAMth->access_flags_);
						}
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD:
			{
				// void* FindNativeMethod(ArtMethod* m, std::string& detail)
				struct ArtMethod *pAMth = (struct ArtMethod *)arg[2];
				struct StdString *library = (struct StdString*)arg[3];
				Addr codeAddr = (Addr)arg[4];
				BG_LOGI("[0]LIBART[%d]:FindNativeMethod() method=%s res=0x%08x\n", tid, library ? library->data : "NULL", codeAddr);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				struct ArtMethod *pAMth = (struct ArtMethod *)arg[4];
				BG_LOGI("[1]LIBART[%d]:GetMethodID() jclass=0x%08x %s %s jmethodId=0x%08x, accFlags=0x%08x, "
						"declaring_class=0x%08x, dex_method_index=%d, method_idex=%d\n",
						tid, cl, mth_name, sig, (Addr)pAMth,
						pAMth == NULL ? 0  : pAMth->access_flags_,
						pAMth == NULL ? -1 : pAMth->declaring_class_,
						pAMth == NULL ? -1 : pAMth->dex_method_index_,
						pAMth == NULL ? -1 : pAMth->method_index_);

				break;
			}
		case VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID:
			{
				Addr cl = (Addr)arg[1];
				HChar* mth_name = (HChar*)arg[2];
				HChar* sig = (HChar*)arg[3];
				Addr res = (Addr)arg[4];
				BG_LOGI("[1]LIBART[%d]:GetStaticMethodID() 0x%08x %s %s id=0x%08x\n",tid, cl, mth_name, sig, res);
				break;
			}
		case VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD_PRE:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				const Addr jclass = (Addr)arg[2];
				struct ArtMethod *pAMth = (struct ArtMethod *)arg[3];
				Addr dex_code_item_addr = 0; 
				if(pDexFileObj == pAppDexFileObj) {
					if( pAMth->dex_code_item_offset_ > 0 ) 
						dex_code_item_addr = pDexFileObj->begin_ + pAMth->dex_code_item_offset_;
					BG_LOGI("[0]LIBART[%d]:LoadMethod() pArtMethod=0x%08x dex_method_index=%d "
							"method_index=%d kclass=0x%08x pDexFileObj=0x%08x dexCodeItemOffset=0x%08x(0x%08x)\n",  
							tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
							(Addr)jclass, (Addr)pDexFileObj, pAMth->dex_code_item_offset_, dex_code_item_addr);
					if(pAMth->ptr_sized_fields_.entry_point_from_quick_compiled_code_ != NULL) { 
						BG_LOGI("[0]LIBART[%s]::LoadMethod() pArtMethod=0x%08x dex_method_index=%s "
								"method_index=%d dexCodeItemOffset=0x%08x\n",
								tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
								(Addr)pAMth->dex_code_item_offset_);
					}
					// printDexCode((struct DexCode*)dex_code_item_addr);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				const Addr jclass = (Addr)arg[2];
				struct ArtMethod *pAMth = (struct ArtMethod *)arg[3];
				Addr dex_code_item_addr = 0; 
				if(pDexFileObj == pAppDexFileObj) {
					if( pAMth->dex_code_item_offset_ > 0 ) 
						dex_code_item_addr = pDexFileObj->begin_ + pAMth->dex_code_item_offset_;
					BG_LOGI("[1]LIBART[%d]:LoadMethod() pArtMethod=0x%08x dex_method_index=%d "
							"method_index=%d kclass=0x%08x pDexFileObj=0x%08x dexCodeItemOffset=0x%08x(0x%08x)\n",  
							tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
							(Addr)jclass, (Addr)pDexFileObj, pAMth->dex_code_item_offset_, dex_code_item_addr);

					if(pAMth->ptr_sized_fields_.entry_point_from_quick_compiled_code_ != NULL) { 
						BG_LOGI("[1]LIBART[%s]::LoadMethod() pArtMethod=0x%08x dex_method_index=%s "
								"method_index=%d dexCodeItemOffset=0x%08x\n",
								tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
								(Addr)pAMth->dex_code_item_offset_);
					}
					// printDexCode((struct DexCode*)dex_code_item_addr);
				}
				if(pAMth) {
					if(pAMth->access_flags_ & ACC_NATIVE) {
						addMthCodeNode(NULL, (Addr)pAMth, (Addr)pDexFileObj, (SizeT)pAMth->dex_method_index_, pAMth->access_flags_, pAMth->dex_method_index_);
					} else {
						MthCodeNode* mc = queryMthCodeNode(dex_code_item_addr);
						if(mc) {
							mc->nativeCodeAddr = (Addr)pDexFileObj;
							mc->nativeCodeSize = (SizeT)pAMth;
						}
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE_PRE:
			{
				struct ArtMethod*	pAMth		= (struct ArtMethod*)arg[1];
				struct OatClass*	pOClazz	= (struct OatClass*)arg[2];
				UInt class_def_method_index	= arg[3];
				BG_LOGI("[0]LIBART[%d]:LinkCode() pArtMethod=0x%08x dex_method_index=%d "
						"method_index=%d pOatClass=0x%08x class_def_method_index=0x%08x\n",
						tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
						(Addr)pOClazz, class_def_method_index);
				break;
			}
		case VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE:
			{
				struct ArtMethod*	pAMth		= (struct ArtMethod*)arg[1];
				struct OatClass*	pOClazz	= (struct OatClass*)arg[2];
				UInt class_def_method_index	= arg[3];
				BG_LOGI("[1]LIBART[%d]:LinkCode() pArtMethod=0x%08x dex_method_index=%d "
						"method_index=%d pOatClass=0x%08x class_def_method_index=0x%08x\n",
						tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
						(Addr)pOClazz, class_def_method_index);
				break;
			}
		case VG_USERREQ__WRAPPER_ART_ENTERINTERPRETERFROMINVOKE_PRE:
			{
				struct ArtMethod* pAMth = (struct ArtMethod*)arg[1];
				if(pAMth->ptr_sized_fields_.entry_point_from_quick_compiled_code_ != NULL) { 
					BG_LOGI("[0]LIBART[%d]:EnterInterpreterFromInvoke() ArtMethod=0x%08x dex_method_index=%s "
							"method_index=%d dexCodeItemOffset=0x%08x\n",
							tid, (Addr)pAMth, pAMth->dex_method_index_, pAMth->method_index_,
							(Addr)pAMth->dex_code_item_offset_);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_EXECUTEGOTO_PRE:
		case VG_USERREQ__WRAPPER_ART_EXECUTEGOTO:
			{
				struct DexCode* pDexcode = (struct DexCode*)arg[2];
				Int e = (arg[0] ==  VG_USERREQ__WRAPPER_ART_EXECUTEGOTO ? 1 : 0);
				if(BG_(clo_trace_begin)) {
					BG_LOGI("[%d]LIBART[%d]:ExecuteGotoImpl() Thread=0x%08x CodeItem=0x%08x", e, tid, arg[1], arg[2], arg[3]);
					// printDexCode(pDexcode);
					MthCodeNode* mc = queryMthCodeNode((Addr)pDexcode);
					if(mc && (mc->nativeCodeAddr) > 0 && (mc->nativeCodeSize > 0)) {
						HChar* clazz;
						HChar* mth;
						HChar* shorty;
						/* nativeCodeAddr store the address of DexFile object for JNI method */
						if(parseLoadedMethod((struct DexFilePlus*)mc->nativeCodeAddr, (struct ArtMethod*)mc->nativeCodeSize, &clazz, &mth, &shorty)) {
							BG_LOGI("\tMethod: %s %s %s", clazz, mth, shorty);
						}
					}
					BG_LOGI("\n");
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_EXECUTESWITCH_PRE:
		case VG_USERREQ__WRAPPER_ART_EXECUTESWITCH:
			{
				struct DexCode* pDexcode = (struct DexCode*)arg[2];
				Int e = (arg[0] ==  VG_USERREQ__WRAPPER_ART_EXECUTEGOTO ? 1 : 0);
				if(BG_(clo_trace_begin)) {
					BG_LOGI("[%d]LIBART[%d]:ExecuteSwitchImpl() Thread=0x%08x CodeItem=0x%08x 0x%08x", e,	tid, arg[1], arg[2], arg[3]);
					// printDexCode(pDexcode);
					MthCodeNode* mc = queryMthCodeNode((Addr)pDexcode);
					if(mc && (mc->nativeCodeAddr) > 0 && (mc->nativeCodeSize > 0)) {
						HChar* clazz;
						HChar* mth;
						HChar* shorty;
						/* nativeCodeAddr store the address of DexFile object for JNI method */
						if(parseLoadedMethod((struct DexFilePlus*)mc->nativeCodeAddr, (struct ArtMethod*)mc->nativeCodeSize, &clazz, &mth, &shorty)) {
							BG_LOGI("\tMethod: %s %s %s", clazz, mth, shorty);
						}
					}
					BG_LOGI("\n");
				}
				break;
			}
		case VG_USERREQ__WRAPPER_ART_TEST_PRE:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				BG_LOGI("[0]LIBART[%d]:RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)std, (Addr)str, str);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_TEST:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				BG_LOGI("[1]LIBART[%d]:RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)std, (Addr)str, str);
				break;
			} 
		case VG_USERREQ__WRAPPER_OPEN:
			{
				HChar* path = (HChar*)arg[1];
				Int  fd = (Addr)arg[2];
				if(BG_(clo_trace_begin) == False) { 
					if(fds[tid][fd].type == FdAppDex)
					{
						// BG_(set_instrumentsate)("first.app.dex.open", True);
						BG_LOGI("%s\n", "Tracing starts...");
					}
				} else {
					BG_LOGI("POSTREQ(%d):open(%s) res=%d\n",
							tid, path, fd);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_FOPEN:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				HChar* path = (HChar*)arg[1];
				Addr  file = (Addr)arg[2];
				BG_LOGI("POSTREQ(%d):fopen(%s) res=%d\n",
						tid, path, file);
				break;
			}
#ifndef ONLY_DUMP
		case VG_USERREQ__WRAPPER_FSEEK:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr file = (Addr)arg[1];
				Int  res  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):fseek(%d) res=%d\n",
						tid, file, res);
				break;
			}
		case VG_USERREQ__WRAPPER_LSEEK:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int fd = (Int)arg[1];
				Int  res  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):lseek(%d) res=%d\n",
						tid, fd, res);
				break;
			}
		case VG_USERREQ__WRAPPER_FREAD:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr  file = (Addr)arg[1];
				HChar *buf = (HChar*)arg[2];
				Int   len  = (Int)arg[3];
#if DBG_SHOW_STRING
				BG_LOGI("POSTREQ(%d):fread(%d) a_0x%08x(%s) l_%d\n",
						tid, file, (Int)buf, buf, len);
#else
				BG_LOGI("POSTREQ(%d):fread(%d) a_0x%08x l_%d\n",
						tid, file, (Int)buf, len);
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_READ:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int fd = (Int)arg[1];
				HChar *buf = (HChar*)arg[2];
				Int   len  = (Int)arg[3];
#if DBG_SHOW_STRING
				BG_LOGI("POSTREQ(%d):read(%d) a_0x%08x(%s) l_%d\n",
						tid, fd, (Int)buf, buf, len);
#else
				BG_LOGI("POSTREQ(%d):read(%d) a_0x%08x l_%d\n",
						tid, fd, (Int)buf, len);
#endif
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_FWRITE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr  file = (Addr)arg[1];
				HChar *buf = (HChar*)arg[2];
				Int   len  = (Int)arg[3];
#if DBG_SHOW_STRING
				BG_LOGI("POSTREQ(%d):fwrite(%d) a_0x%08x(%s) l_%d\n",
						tid, file, (Int)buf, buf, len);
#else
				BG_LOGI("POSTREQ(%d):fwrite(%d) a_0x%08x l_%d\n",
						tid, file, (Int)buf, len);
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_WRITE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int fd = (Int)arg[1];
				HChar *buf = (HChar*)arg[2];
				Int   len  = (Int)arg[3];
#if DBG_SHOW_STRING
				BG_LOGI("POSTREQ(%d):write(%d) a_0x%08x(%s) l_%d\n",
						tid, fd, (Int)buf, buf, len);
#else
				BG_LOGI("POSTREQ(%d):write(%d) a_0x%08x l_%d\n",
						tid, fd, (Int)buf, len);
#endif
				break;
			}
		case VG_USERREQ__WRAPPER_CLOSE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int  fd = (Int)arg[1];
				BG_LOGI("POSTREQ(%d):close(%d)\n", tid, fd);
				break;
			}
		case VG_USERREQ__WRAPPER_FCLOSE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr  file = (Addr)arg[1];
				BG_LOGI("POSTREQ(%d):fclose(%d)\n", tid, file);
				break;
			}
		case VG_USERREQ__WRAPPER_SHUTDOWN:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int sk  = (Int)arg[1];
				Int how = (Int)arg[2];
				Int res = (Int)arg[3];
				tl_assert(how==0 | how==1 || how==2);
				BG_LOGI("POSTREQ(%d):shutdown sk=%d how=%s res=%d\n",
						tid, sk, SHUTDOWN_HOW[how], res);
				break;
			}
#ifndef ONLY_DUMP
		case VG_USERREQ__WRAPPER_MMAP:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int  fd = (Int)arg[1];
				Int  flags  = (Int)arg[2];
				Int  len  = (Int)arg[3];
				Int  offset = (Int)arg[4];
				Addr res  = (Addr)arg[5];
				BG_LOGI("POSTREQ(%d):mmap(%d) offset=%d -> 0x%08x l_%d(%x) %s\n",
						tid, fd, offset, res, len, len, mmap_proto2a(flags));
				if(fd > -1 && fd < FD_MAX) {
					switch(fds[tid][fd].type) {
						case FdSystemLib:
							break;
						case FdAppLib:
							break;
						case FdFrameworkJar:
							break;
						case FdFrameworkDex:
							break;
						case FdAppDex:
							BG_LOGI("Third party app's dex(%d) file is mmaped 0x%08x-0x%08x\n", 
									fd, res, res+len-1);
							dumpDexFile((UChar*)res, len);
							break;
						case FdDevice:
							break;
						default:
							BG_LOGE("Unknown type fd: %d\n", fd);
							break;
					}
				}
				break;
			}
		case VG_USERREQ__WRAPPER_MUNMAP:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):munmap 0x%08x l_%d(%x)\n",
						tid, addr, len, len);
				break;
			}
		case VG_USERREQ__WRAPPER_MPROTECT:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				Int  prot = (Int)arg[3];
				BG_LOGI("POSTREQ(%d):mprotect 0x%08x l_%d(0x%08x) %s\n",
						tid, addr, len, len, mmap_proto2a(prot));
				break;
			}
#endif // ONLY_DUMP
		case VG_USERREQ__WRAPPER_SIGPROCMASK:
			{
				Int how = (Int)arg[1];
				BG_LOGI("LIBCWRAP(%d) sigprocmak() how = %d\n",
						tid, how);
				break;
			}
		case VG_USERREQ__WRAPPER_SIGACTION:
			{
				Int signum = (Int)arg[1];
				BG_LOGI("LIBCWRAP(%d) sigaction() signum = %d\n",
						tid, signum);
				break;
			}
		case VG_USERREQ__WRAPPER_SIGNAL:
			{
				Int signum = (Int)arg[1];
				BG_LOGI("LIBCWRAP(%d) signal() signum = %d\n",
						tid, signum);
				break;
			}
		case VG_USERREQ__WRAPPER_SYSTEM:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int res = (Int)arg[2];
				UChar *cmd = (UChar*)arg[1];
				BG_LOGI("POSTREQ(%d):system cmd=%s res=%d\n", tid, cmd, res);
				break;
			}
		case VG_USERREQ__WRAPPER_EXIT_PRE:
			{
				Int status = (Int)arg[1];
				BG_LOGI("[0]LIBCWRAP(%d):exit() status=%d\n", tid, status);
				//releaseDexFileList();
				break;
			}
		default:
			return False;
	}
	return True;
}


/* Get the debug info of BB */
	static __inline__
Bool bg_get_debug_info( Addr instr_addr,
		const HChar **dir,
		const HChar **file,
		const HChar **fn_name,
		UInt *line_num,
		DebugInfo **pDebugInfo) 
{
	Bool found_file_line, found_fn, result = True;
	UInt line;

	// DBG_FEXE_PRINTF(6, "  + get_debug_info(%#lx)\n", instr_addr);

	if (pDebugInfo) {
		*pDebugInfo = VG_(find_DebugInfo)(instr_addr);

		// for generated code in anonymous space, pSegInfo is 0
	}

	found_file_line = VG_(get_filename_linenum)(instr_addr,
			file,
			dir,
			&line);
	found_fn = VG_(get_fnname)(instr_addr, fn_name);

	if (!found_file_line && !found_fn) {
		*file = "???";
		*fn_name = "???";
		if (line_num) *line_num=0;
		result = False;

	} else if ( found_file_line &&  found_fn) {
		if (line_num) *line_num=line;

	} else if ( found_file_line && !found_fn) {
		*fn_name = "???";
		if (line_num) *line_num=line;

	} else  /*(!found_file_line &&  found_fn)*/ {
		*file = "???";
		if (line_num) *line_num=0;
	}

	BG_LOGI("- get_debug_info(%#lx): seg '%s', fn %s\n",
			instr_addr,
			!pDebugInfo   ? "-" :
			(*pDebugInfo) ? VG_(DebugInfo_get_filename)(*pDebugInfo) :
			"(None)",
			*fn_name);

	return result;
}

/* Get the general info of the BB */
	static __inline__
void bg_get_bb_info(Addr addr)
{
	const HChar *fnname, *filename, *dirname;
	DebugInfo *di;
	UInt line_num;
	Bool res = False;

	BG_LOGI("+ get_bb_info (BB %#lx)\n", addr);

	res = bg_get_debug_info(addr, &dirname, &filename,
			&fnname, &line_num, &di);
	if(di)
		BG_LOGI("Obj %#lx name: %s\n", addr, fnname);
}
	static
IRSB* bg_instrument ( VgCallbackClosure* closure,
		IRSB* sbIn,
		const VexGuestLayout* layout, 
		const VexGuestExtents* vge,
		const VexArchInfo* archinfo_host,
		IRType gWordTy, IRType hWordTy )
{
	IRSB		*sbOut;
	IRStmt	*st;
	HChar		*obj_name;
	Addr		origAddr;

	Int i;
	return sbIn;
	VG_(printf)("Input:\n");
	ppIRSB(sbIn);

	sbOut = deepCopyIRSBExceptStmts(sbIn);
	i = 0;
	while (i < sbIn->stmts_used && sbIn->stmts[i]->tag != Ist_IMark) {
		addStmtToIRSB( sbOut, sbIn->stmts[i]);
		i++;
	}
	st = sbIn->stmts[i];
	origAddr = st->Ist.IMark.addr + st->Ist.IMark.delta;
	bg_get_bb_info(origAddr);
	return sbIn;
}

/*--------------- adjustment by N bytes ---------------*/

static void bg_pre_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs) {
	if(BG_(is_trace_syscall) == False)
		return;
#if 0
	if(syscallno== 78) {
		if(tid == 1 )
			last_ttt++;
		else
			last_ttt = 0;
	}
#endif
}
static void bg_post_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs, SysRes res) {
	if(BG_(is_trace_syscall) == False)
		return;
	switch ((int)syscallno) {
		// Should be defined by respective include/vki/vki-scnums-arch-os.h
#if 1
		case __NR_execve:
			BG_(syscall_execve)(tid, args, nArgs, res);
			break;
		case __NR_clone:
			BG_(syscall_clone)(tid, args, nArgs, res);
			break;
		case __NR_rt_sigaction:
		case __NR_sigaction:
			BG_(syscall_action)(tid, args, nArgs, res);
			break;
		case __NR_unlink:
		case __NR_unlinkat:
			//BG_(syscall_unlink)(tid, args, nArgs, res);
			break;
		case __NR_read:
			BG_(syscall_read)(tid, args, nArgs, res);
			break;
		case __NR_pread64:
			BG_(syscall_pread)(tid, args, nArgs, res);
			break;
		case __NR_readv:
			BG_(syscall_readv)(tid, args, nArgs, res);
			break;
		case __NR_preadv:
			BG_(syscall_preadv)(tid, args, nArgs, res);
			break;
		case __NR_write:
			BG_(syscall_write)(tid, args, nArgs, res);
			break;
		case __NR_writev:
			BG_(syscall_writev)(tid, args, nArgs, res);
			break;
		case __NR_pwritev:
			BG_(syscall_pwritev)(tid, args, nArgs, res);
			break;
		case __NR_close:
			BG_(syscall_close)(tid, args, nArgs, res);
			break;
		case __NR_mprotect:
			BG_(syscall_mprotect)(tid, args, nArgs, res);
			break;
		case __NR_msync:
			BG_(syscall_msync)(tid, args, nArgs, res);
			break;
		case __NR_munmap:
			BG_(syscall_munmap)(tid, args, nArgs, res);
			break;
		case __NR_setuid:
		case __NR_setuid32:
			BG_(syscall_setuid)(tid, args, nArgs, res);
			break;
		case __NR_setreuid:
		case __NR_setreuid32:
			BG_(syscall_setreuid)(tid, args, nArgs, res);
			break;
		case __NR_setgid:
		case __NR_setgid32:
			BG_(syscall_setgid)(tid, args, nArgs, res);
			break;
		case __NR_setregid:
		case __NR_setregid32:
			BG_(syscall_setregid)(tid, args, nArgs, res);
			break;
		case __NR_mmap2:
			BG_(syscall_mmap)(tid, args, nArgs, res);
			break;
		case __NR_open:
		case __NR_openat:
			BG_(syscall_open)(tid, args, nArgs, res);
			break;

		case __NR_lseek:
			//	BG_(syscall_lseek)(tid, args, nArgs, res);
			break;
#ifdef __NR_llseek
		case __NR_llseek:
			BG_(syscall_llseek)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_recv
		case __NR_recv:
			BG_(syscall_recv)(tid, args, nArgs, res);
			break;
#endif
#ifdef __NR_recvfrom
		case __NR_recvfrom:
			BG_(syscall_recvfrom)(tid, args, nArgs, res);
			break;
#endif
#endif
		case __NR_ptrace:
			BG_(syscall_ptrace)(tid, args, nArgs, res);
			break;
		default:
			break;
	}
}
#if 0
/* Valgrind core functions */
static int bg_isatty(void) {
	HChar buf[256], dev2[11];
	const HChar dev[] = "/dev/pts/";
	int i;
	VG_(readlink)("/proc/self/fd/2", buf, 255);
	for ( i=0; i<10; i++ )
	{
		VG_(sprintf)(dev2, "%s%d", dev, i);
		if ( VG_(strncmp)(buf, dev2, 10) == 0 ) return 1;
	}
	return 0;
}
static void hdl (int sig) {
	BG_LOGI("Received signal %d\n", sig);
	releaseDexFileList();
	tl_assert(0);
}
static void register_handler()
{
	struct vki_sigaction_toK_t act;
	//struct vki_sgaction act;
	act.sa_handler = hdl;
	act.sa_flags = 0;
	VG_(sigaction)(SIGUSR2, &act, NULL);
	VG_(sigaction)(SIGUSR1, &act, NULL);
}
#endif
static void bg_post_clo_init(void)
{
#if 0
	Int i;
	for( i=0; i< TI_MAX; i++ ) {
		ti[i] = 0;
		tv[i] = 0;
	}
	for( i=0; i< RI_MAX; i++ )
		ri[i] = 0; 
	for( i=0; i< STACK_SIZE; i++ )
		lvar_i[i] = 0;
#endif
	BG_(clo_trace_begin) = False;
}
static void bg_fini(Int exitcode)
{
	/*releaseFilterlist(&fl);
		releaseFilterlist(&dlibl);
		releaseDexFileList();
		dumpDexFile((UChar*)pAppDexFileObj->begin_, pAppDexFileObj->size_);*/
	VG_(memset)((UChar*)fds, 0, sizeof(struct fd_info) * TG_N_THREADS * FD_MAX);
	VG_(printf)("exitcode:%d\n", exitcode);
}

static void bg_pre_clo_init(void)
{
	VG_(details_name)            ("PackerGrind");
	VG_(details_version)         ("0.1.1");
	VG_(details_description)     ("Adaptive unpacking of Android Applications");
	VG_(details_copyright_author)("Copyright (C) 2002-2017, and GNU GPL'd, by Rewhy");
	VG_(details_bug_reports_to)  (VG_BUGS_TO);
	VG_(details_avg_translation_sizeB) ( 640 );


	VG_(memset)((UChar*)fds, 0, sizeof(struct fd_info) * TG_N_THREADS * FD_MAX);
	//VG_(details_avg_translation_sizeB) ( 275 );

	VG_(basic_tool_funcs)					(bg_post_clo_init,
			BG_(instrument),
			bg_fini);

	VG_(needs_command_line_options)(BG_(process_cmd_line_option),
			BG_(print_usage),
			BG_(print_debug_usage));
	//VG_(needs_superblock_discards)(bg_discard_superblock_info);
	VG_(needs_syscall_wrapper)		(bg_pre_syscall, 	bg_post_syscall);

	VG_(needs_var_info)						();

	initSoaapData();

	VG_(needs_libc_freeres)				();
	VG_(needs_malloc_replacement)	(BG_(malloc),
			BG_(__builtin_new),
			BG_(__builtin_vec_new),     
			BG_(memalign),
			BG_(calloc),
			BG_(free),
			BG_(__builtin_delete),
			BG_(__builtin_vec_delete),
			BG_(realloc),
			BG_(malloc_usable_size), 
			BG_MALLOC_REDZONE_SZB ); 
	VG_(needs_client_requests) (BG_(handle_client_requests));
	BG_(malloc_list) = VG_(HT_construct)( "BG_(malloc_list)" );
	// VG_(track_pre_deliver_signal) (&bg_track_pre_deliver_signal);
	// VG_(track_post_deliver_signal) (&bg_track_post_deliver_signal);
}

VG_DETERMINE_INTERFACE_VERSION(bg_pre_clo_init)
