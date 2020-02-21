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

#include "bevgrind.h"
#include "unistd-asm-arm.h"
#include "bg_debug.h"
#include "bg_translate.h"
#include "bg_wrappers.h"
#include "bg_oatdexparse.h"

Bool BG_(is_release_dex_files) = False;
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

#ifdef BAIDU_1503
struct DexFile* baidu_dexFile = NULL;
#endif
#ifdef	QIHOO_1603
Addr qihoo_addr=0; UInt qihoo_len = 4664;
#endif

Bool isFrameworkClass(HChar* desc) {
	if(VG_(memcmp)("Ljava", desc, 5) == 0)
		return True;
	if(VG_(memcmp)("Landroid", desc, 8) == 0)
		return True;
	if(VG_(memcmp)("Llibcore", desc, 8) == 0)
		return True;
	if(VG_(memcmp)("Lcom/lang/", desc, 10) == 0)
		return True;
	if(VG_(memcmp)("Ljava/lang/", desc, 10) == 0)
		return True;
	if(VG_(memcmp)("Lcom/google/", desc, 12) == 0)
		return True;
	if(VG_(memcmp)("Lcom/android/", desc, 13) == 0)
		return True;
	if(VG_(memcmp)("Ldalvik/system/", desc, 15) == 0)
		return True;
	return False;
}
/* Command parameters */
Char *BG_(package_name)				= NULL;
Bool BG_(is_instrument_load)	= False;
Bool BG_(is_instrument_store)	= False;
Bool BG_(is_trace_syscall)	  = False;
Bool BG_(is_parse_dex)				= False;
Bool BG_(is_full_trace)				= False;
UInt BG_(time_slower)					= 1;

/* End */

UInt	 packer_type = 0;
struct fd_info fds[TG_N_THREADS][FD_MAX];

Bool BG_(clo_trace_begin) = False;
Bool BG_(only_dump)	= False;
Int		th_status[TG_N_THREADS] = {-1};
Bool  th_is_loading[TG_N_THREADS] = {False};


static void BG_(print_usage)(void)
{
	VG_(printf)(
			"		--package-name=<package>	the name of traced package name (NULL)"
			"		--instrument-load=yes|no	Instrument load statements (no).\n"
			"		--instrument-store=yes|no	Instrument store statements (no).\n"
			"    --time-slow=<slower>     the times for making the timestamps slower (1)\n"
			"   --trace-syscall						Trace the syscall invocations (no).\n"
			"		--parse-dex=yes|no				Parse the dex files during running (no).\n"
			"		--full-trace=yes|no				Output all tracing logs (no).");
}
static void BG_(print_debug_usage)(void)
{
}
static Bool BG_(process_cmd_line_option)(const HChar* arg)
{
	if VG_STR_CLO(arg, "--package-name",		BG_(package_name))	{	VG_(printf)("Perform instrument-load trace.\n"); }
	else if VG_BOOL_CLO(arg, "--instrument-load",		BG_(is_instrument_load))	{	VG_(printf)("Perform instrument-load trace.\n"); }
	else if VG_BOOL_CLO(arg, "--instrument-store",	BG_(is_instrument_store)) { VG_(printf)("Perform instrument-store trace.\n"); }
	else if VG_BOOL_CLO(arg, "--trace-syscall",   	BG_(is_trace_syscall))		{}
	else if VG_BOOL_CLO(arg, "--parse-dex",					BG_(is_parse_dex))				{}
	else if VG_INT_CLO(arg, "--time_slow",					BG_(time_slower))					{}
	else if VG_BOOL_CLO(arg, "--full-trace",				BG_(is_full_trace))				{
		BG_(is_instrument_store) = True;
		BG_(is_instrument_load) = True;
		BG_(is_trace_syscall) = True;
		//BG_(is_parse_dex) = True;
		VG_(printf)("Perform full trace.\n");
	}
	else 
		return VG_(replacement_malloc_process_cmd_line_option)(arg);

	return True;
}

void BG_(set_instrumentsate)(const HChar *reason, Bool state) {
	if( BG_(clo_trace_begin) == state ) {
		BG_LOGI("%s: instrumentation already %s\n",
				reason, state ? "ON" : "OFF");
		return;
	}
	BG_(clo_trace_begin) = state;
	if(BG_(is_instrument_store) || BG_(is_instrument_load)) {
#if 1
		BG_LOGI("Try to discard translations safely.\n");
		VG_(discard_translations_safely)( (Addr)0x1000, ~(SizeT)0xfff, "bevgrind");
		BG_LOGI("Finish discarding translations safely.\n");
#else
		VALGRIND_DISCARD_INS_CACHE(reason);
#endif
	}
	if (state) 
		initFilterlist();
	else {
		releaseFilterlist(&fl);
		releaseFilterlist(&dlibl);
		releaseDexFileList();
	}

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
	BG_LOGI(">> post_signal(TID %u, sig %d)\n",
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

static UInt last_ttt = 0;
static ULong last_ts;
static ULong first_ts;

//#define MAKE_SLOW		10.0
#define DBG_SHOW_STRING 0

Bool BG_(handle_client_requests) ( ThreadId tid, UWord *arg, UWord *ret) {
	Int i;
	Addr bad_addr;
	switch (arg[0]) {
		case VG_USERREQ__WRAPPER_GETTIMEOFDAY:
			{
#ifdef	IJIAMI_1603
				if (BG_(time_slower) == 1) {
					BG_(time_slower) = 40;
				}
#endif
				struct vki_timeval* tv = (struct vki_timeval*)arg[1];
				if(first_ts == 0)
					first_ts = tv->tv_sec * 1000000ULL + tv->tv_usec;
				if(BG_(clo_trace_begin) == False || BG_(time_slower) == 1) 
					break;
				if(tid != 1)
					break;
				ULong	 current_ts = tv->tv_sec * 1000000ULL + tv->tv_usec;
				if( BG_(time_slower) != 0 ) {
					current_ts = ((current_ts - first_ts) / (Double)BG_(time_slower)) + first_ts;
					tv->tv_sec  = (current_ts) / 1000000;
					tv->tv_usec = (current_ts) % 1000000;
					/*BG_LOGI("[0]LIBCWRAP(%d):gettimeofday res=%u.%u (%llu)\n", 
							tid, tv->tv_sec, tv->tv_usec, last_ts);*/
				}
				last_ts = current_ts;
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
#if 0
		case VG_USERREQ__WRAPPER_STRCMP:
			{
				if(BG_(is_full_trace) == False)
					break;
				if(BG_(clo_trace_begin) == False) 
					break;
#if DBG_SHOW_STRING
				BG_LOGI("POSTREQ(%d):strcmp 0x%x(%s)  0x%x(%s)\n", tid, 
						(Int)arg[1], (HChar*)arg[1],	
						(Int)arg[2], (HChar*)arg[2]);
#else
				BG_LOGI("POSTREQ(%d):strcmp 0x%x  0x%x\n", tid, 
						(Int)arg[1],
						(Int)arg[2]);
#endif
				break;
			}
#endif
		case VG_USERREQ__CHECK_MEM_TAINTED:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				break;// Preformance
				HChar* fun = (HChar*)arg[1];
				HChar* src = (HChar*)arg[2];
				Int len = (Int)arg[3];
				BG_LOGI("POSTREQ(%d):%s 0x%08x(%s) %d\n", tid,
						fun, (Addr)src, src, len);
				break;
			}
		case VG_USERREQ__COPY_MEM_TAINT:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				break;// Preformance
				HChar* fun = (HChar*)arg[1];
				HChar* src = (HChar*)arg[2];
				HChar* dst = (HChar*)arg[3];
				HChar* info;
				Int len = (Int)arg[4];
				if (len <= 0)
					break;
				if( len >= 52 ) {
#if DBG_SHOW_STRING
					BG_LOGI("POSTREQ(%d):%s 0x%08x(%s) -> 0x%08x(%s) %d\n", tid,
							fun, (Int)src, src,	
							(Int)dst, dst, len);
#else
					BG_LOGI("POSTREQ(%d):%s 0x%08x -> 0x%08x %d\n", tid,
							fun, (Int)src,
							(Int)dst, len);
#endif
					if( isInFilterList(dlibl, src, &info) ) {
						addFilterList(&dlibl, info, dst, len);
						//dumpMemBlock( src, len );
					}
				}
				break;
			}
#ifdef TRACE_DVM_PLATFORM 
		case VG_USERREQ__WRAPPER_DEXFILEPARSE_PRE:
			{
				//DexFile* dexFileParse(const u1* data, size_t length, int flags)
				if(BG_(clo_trace_begin) == False) 
					break;
				Addr begin_addr = (Addr)arg[1];
				Int  len = (Int)arg[2];
				Int  flag= (Int)arg[3];
				struct DexFile *pf = (struct DexFile*)arg[4];
				BG_LOGI("[0]DVMWRAP(%d):dexFileParse() file: 0x%08x-0x%08x flag: %s pDexFile=0x%08x\n", 
						tid, begin_addr, begin_addr+len, DEXFILEPARSE_FLAG[flag], (Addr)pf);
				//dumpDexFile(begin_addr, len);
				dumpRawData1(begin_addr, len, (Addr)arg[4]);
				break;
			}
		case VG_USERREQ__WRAPPER_DEXFILEPARSE:
			{
				//if(BG_(clo_trace_begin) == False) 
				//	break;
				Addr begin_addr = (Addr)arg[1];
				Int  len = (Int)arg[2];
				Int  flag= (Int)arg[3];
				struct DexFile *pf = (struct DexFile*)arg[4];
				BG_LOGI("[1]DVMWRAP(%d):dexFileParse() file: 0x%08x-0x%08x flag: %s pDexFile=0x%08x\n", 
						tid, begin_addr, begin_addr+len, DEXFILEPARSE_FLAG[flag], (Addr)pf);
				if(pf) {
					struct DexHeader* pdh = pf->pHeader;
					processDexFile(pf);
					addFilterList(&dlibl, "Dexfile.memory.range", begin_addr, len);
					addFilterList(&dlibl, "DexFile.struct", (Addr)pf, sizeof(struct DexFile));
					addDexFileList(pf);  //add pdf to recorded dex file list
					//meetDexFile(pf, begin_addr, len, 2);  // for new dex file pf, create clone memory to store data if not
				}
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEFINECLASS_PRE:
			{ //ClassObject* dvmDefineClass(DvmDex* pDvmDex, const char* descriptor, Object* classLoader)
				if(BG_(clo_trace_begin) == False) 
					break;
				struct DvmDex*  pdd		= (struct DvmDex*)arg[1];
				const  HChar*	  des   = (const HChar*)arg[2];
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				HChar *info;
				if( isInDexFileList(pdf) == NULL) {
					BG_LOGI("[0]DVMWRAP(%d):dvmDefineClass() des=%s, pDexFile=0x%08x  is not in DexFile List\n", 
							tid, des, (Addr)pdf);
					break;
				}
				BG_LOGI("[0]DVMWRAP(%d):dvmDefineClass() des=%s, pDexFile=0x%08x map: 0x%08x-0x%08x pHeader=0x%08x(0x%08x) pOptHeader=0x%08x\n", 
						tid, des, (Addr)pdf, mm.addr, mm.addr+mm.length, (Addr)pdh, (Addr)pdf->pHeader, (Addr)pdf->pOptHeader);
				if(isInDexFileList(pdf) == False) {
					BG_LOGI("[0]DVMWRAP(%d):dvmDefineClass() des=%s, pDexFile=0x%08x  is not in DexFile List\n", 
							tid, des, (Addr)pdf);
					processDexFile(pdf);
					addFilterList(&dlibl, "Dexfile.memory.map", mm.addr, mm.length);
					if (pdh)
						addFilterList(&dlibl, "Dexfile.range", pdf->baseAddr, pdh->fileSize);
					//Addr addr = isInFilterList(dlibl, (Addr)pdh, &info);
					if( mm.addr+0x28 == pdf->baseAddr || mm.addr == pdf->baseAddr ) {
						//dumpDexFile(mm.addr, mm.length);
						addDexFileList(pdf);
					} else {
						VG_(printf)("DEX file memory map is not match baseAddr.\n");
					}
				}
				if(isFrameworkClass(des))
					break;
				BG_LOGI("[0]DVMWRAP(%d):dvmDefineClass() des=%s, pDexFile=0x%08x  meet dex file\n", 
						tid, des, (Addr)pdf);
				//meetDexFile(pdf, mm.addr, mm.length, 2);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEFINECLASS:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct DvmDex*  pdd		= (struct DvmDex*)arg[1];
				const  HChar*	  des   = (const HChar*)arg[2];
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				struct ClassObject* poj	= (struct ClassObject*)arg[4];
				if(isInDexFileList(pdf) == NULL)
					break;
				if(poj) {
					BG_LOGI("[1]DVMWRAP(%d):dvmDefineClass() pDexFile=0x%08x class: %s\n", 
							tid, (Addr)pdf, poj->descriptor);
#ifdef BAIDU_1503
					if(VG_(strcmp)("Laaaaaaaa/bbbbbbbb;", poj->descriptor) == 0) {
						baidu_dexFile = pdf;
						BG_LOGI("Meet the dex file of BAIDU\n");
					}
#endif
					//added by ws
					// if(!isFrameworkClass(poj->descriptor)) {
					// 	copyOneClass(pdf, des);
					//}
					//copyOneClass(pdf, des);
				} else {
					BG_LOGI("[1]DVMWRAP(%d):dvmDefineClass() des=%s, pDexFile=0x%08x map: 0x%08x-0x%08x pHeader=0x%08x(0x%08x) pOptHeader=0x%08x %s res=NULL\n", 
							tid, des, (Addr)pdf, mm.addr, mm.addr+mm.length, (Addr)pdh, (Addr)pdf->pHeader, (Addr)pdf->pOptHeader, des);
					break;
				}
				if(isFrameworkClass(des))
					break;
				if( isInDexFileList(pdf) == False ) 
				{
					processDexFile(pdf);
					addFilterList(&dlibl, "Dexfile.memory.map", mm.addr, mm.length);
					if (pdh)
						addFilterList(&dlibl, "Dexfile.range", pdf->baseAddr, pdh->fileSize);
				}
#ifdef BANGCLE_1603
				if(VG_(strcmp)("Lcom/bangcle/everisk/utils/a;", des) == 0){
					BG_LOGI("Try to dump dex files for Bangcle: \n");
					releaseDexFileList();
				}
#endif 
#ifdef	IJIAMI_1603
				if(poj) {
					if(!isFrameworkClass(poj->descriptor)){
						getClassMethods(pdf, poj);
					}
				}
#endif
				break;
			}
#if 0
		case VG_USERREQ__WRAPPER_DVMINVOKEMTH_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[0]DVMWRAP(%d):dvmInvokeMethod() pDexFile=0x%08x map: 0x%08x-0x%08x pHeader=0x%08x(0x%08x) pOptHeader=0x%08x\n", 
						tid, (Addr)pdf, mm.addr, mm.addr+mm.length, (Addr)pdh, (Addr)pdf->pHeader, (Addr)pdf->pOptHeader);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMINVOKEMTH:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[1]DVMWRAP(%d):dvmInvokeMethod() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_DVMCALLMETHOD_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[0]DVMWRAP(%d):dvmCallMethod() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMCALLMETHOD:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[1]DVMWRAP(%d):dvmCallMethod() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMCALLJNIMTH_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[3];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[0]DVMWRAP(%d):dvmCallJNIMethod() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				if( isInDexFileList(pdf) == NULL)
					break;
				if(pOj->descriptor[9]=='o' && pOj->descriptor[10]=='s')
					break;
				//BG_LOGI("[0]DVMWRAP(%d):dvmCallJNIMethod() pDexFile=0x%08x map: 0x%08x-0x%08x pHeader=0x%08x(0x%08x) pOptHeader=0x%08x\n", 
				//		tid, (Addr)pdf, mm.addr, mm.addr+mm.length, (Addr)pdh, (Addr)pdf->pHeader, (Addr)pdf->pOptHeader);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMCALLJNIMTH:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[3];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[1]DVMWRAP(%d):dvmCallJNIMethod() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				if( isInDexFileList(pdf) == NULL)
					break;
				if(pOj->descriptor[9]=='o' && pOj->descriptor[10]=='s')
					break;
//#ifdef BAIDU_1503
				if(VG_(strcmp)("Lcom/baidu/protect/A;", pOj->descriptor)==0 && VG_(strcmp)("d", mth->name)==0) {
					BG_LOGI("Try to dump the complete DEX file for Baidu packer. baidu_pdf = 0x%08x, pdf = 0x%08x\n", 
							(Addr)baidu_dexFile, (Addr)pdf);
					meetDexFile(baidu_dexFile, 0, 0, 2); 
				}
//#endif
				break;
			}
		case VG_USERREQ__WRAPPER_DVMFINDCLASSBYNAME:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct ClassObject *pOj = (struct ClassObject *)arg[1];
				struct DvmDex* pdd		= pOj->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[x]DVMWRAP(%d):dvmFindClassByName() pDexFile=0x%08x (0x%08x)%s\n", 
						tid, (Addr)pdf, (Addr)pOj->descriptor, pOj->descriptor);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMINTERPRET_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				if( isInDexFileList(pdf) == NULL)
					break;
				if(isFrameworkClass(pOj->descriptor))
					break;
				BG_LOGI("[0]DVMWRAP(%d):dvmInterpret() pDexFile=0x%08x map: 0x%08x-0x%08x pHeader=0x%08x(0x%08x) pOptHeader=0x%08x\n", 
						tid, (Addr)pdf, mm.addr, mm.addr+mm.length, (Addr)pdh, (Addr)pdf->pHeader, (Addr)pdf->pOptHeader);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMINTERPRET:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Method* mth		= (struct Method*)arg[1];
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				if( isInDexFileList(pdf) == NULL)
					break;
				BG_LOGI("[1]DVMWRAP(%d):dvmInterpret() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				if(isFrameworkClass(pOj->descriptor))
					break;
#ifdef BANGCLE_1503
				if(pOj->descriptor[1]=='n' && pOj->descriptor[2]=='n' && pOj->descriptor[3]=='e' && pOj->descriptor[4]=='o'
						&& mth->name[1]=='c' && mth->name[2]=='l' && mth->name[3]=='i' && mth->name[4]=='n' && mth->name[5]=='i') {
					BG_LOGI("Try to dump dex files for Bangcle: \n");
					releaseDexFileList();
				}
#endif 
				break;
			}
		case VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[0]DVMWRAP(%d):dvmInterpretPortable() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[1]DVMWRAP(%d):dvmInterpretPortable() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMMTERPSTD_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[0]DVMWRAP(%d):dvmMterpStd() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMMTERPSTD:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[1]DVMWRAP(%d):dvmMterpStd() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMMTERPSTDRUN_PRE:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				struct DexHeader* pdh = pdd->pHeader;
				struct MemMapping mm	= pdd->memMap;
				BG_LOGI("[0]DVMWRAP(%d):dvmMterpStdRun() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);
				if( isInDexFileList(pdf) == False) {
					if( mm.addr+0x28 == pdf->baseAddr || mm.addr == pdf->baseAddr ) {
						//dumpDexFile(mm.addr, mm.length);
						//addDexFileList(pdf);
					} else {
						VG_(printf)("DEX file memory map is not match baseAddr.\n");
					}
				}
				BG_LOGI("[0]DVMWRAP(%d):dvmMterpStdRun() end\n");
				break;
			}
		case VG_USERREQ__WRAPPER_DVMMTERPSTDRUN:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				struct Thread *self = (struct Thread*)arg[1];
				struct Method *mth  = self->interpSave.method;
				struct ClassObject *pOj = mth->clazz;
				struct DvmDex* pdd		= mth->clazz->pDvmDex;
				struct DexFile* pdf		= pdd->pDexFile;
				BG_LOGI("[1]DVMWRAP(%d):dvmMterpStdRun() pDexFile=0x%08x mth: %s %s(%s) insn: 0x%08x-0x%08x\n", 
						tid, (Addr)pdf, pOj->descriptor, mth->name, mth->shorty, mth->insns, mth->insns+mth->insSize);

				if(isFrameworkClass(pOj->descriptor))
					break;
				copyMthCode(pdf, mth);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMLOADNATIVE_PRE:
			{   //bool dvmLoadNativeCode(const char* pathName, Object* classLoader, char** detail)
				HChar* fileName = (HChar*)arg[1];
				BG_LOGI("[0]DVMWRAP(%d):dvmLoadNativeCode() %s\n", 
						tid, fileName);
				th_is_loading[tid] = True;
				if(VG_(strstr)(fileName, "data") > 0)
				{	// QIHOO:		libjiagu.so/libprotectClass.so
					// ALI:			libmobisec.so
					// BANGCLE:	libsecexe.so/libsecmain.so
					// IJIAMI		libexecmain.so/libexec.so
					if((VG_(strstr)(fileName, "libexecmain.so") > 0)
							|| (VG_(strstr)(fileName, "libexec.so") > 0)) {
						packer_type = 4;
					}
					BG_(set_instrumentsate)("load.third.party.library", True);
					BG_LOGI("%s\n", "Tracing starts...");
				}
				break;
			}
		case VG_USERREQ__WRAPPER_DVMLOADNATIVE:
			{
				HChar* fileName = (HChar*)arg[1];
				BG_LOGI("[1]DVMWRAP(%d):dvmLoadNativeCode() %s\n", 
						tid, fileName);
				th_is_loading[tid] = False;
				/*if(True)
				{
					BG_(set_instrumentsate)("first.app.dex.open", True);
					BG_LOGI("%s\n", "Tracing starts...");
				}*/

#ifdef	QIHOO_1603
				if(VG_(strstr)(fileName, "libjiagu.so") > 0 && qihoo_addr > 0) {
					BG_LOGI("[1]DVMWRAP(%d):dvmLoadNativeCode() Dump qihoo_dex_file\n", tid);
					dumpDexFile(qihoo_addr, qihoo_len);
				}
#endif
#ifdef	APK_PROTECT
				if(VG_(strstr)(fileName, "libAPKProtect.so")) {
					releaseDexFileList();
					BG_LOGI("Will crash!!!!\n");
					tl_assert(0);
				}
				break;
#endif
				break;
			}
#if 0
		case VG_USERREQ__WRAPPER_DVMCONOPT_PRE:
			{
				Int fd			= (Int)arg[1];
				Int offset	= (Int)arg[2];
				Int len			= (Int)arg[3];
				HChar *fname= (HChar*)arg[4];
				BG_LOGI("[0]DVMWRAP(%d):dvmContinueOptimiztion(%d) %s len=%d offset_0x%08x\n", 
						tid, fd, fname, offset);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMCONOPT:
			{
				Int fd			= (Int)arg[1];
				Int offset	= (Int)arg[2];
				Int len			= (Int)arg[3];
				HChar *fname= (HChar*)arg[4];
				BG_LOGI("[1]DVMWRAP(%d):dvmContinueOptimiztion(%d) %s len = %d offset_0x%08x\n", 
						tid, fd, fname, len, offset);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY_PRE:
			{
				BG_LOGI("[0]DVMWRAP(%d):dvmRawDexFileOpenArrary() \n", 
						tid);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY:
			{
				BG_LOGI("[1]DVMWRAP(%d):dvmRawDexFileOpenArrary() \n", 
						tid);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN_PRE:
			{
				BG_LOGI("[0]DVMWRAP(%d):dvmRawDexFileOpen() \n", 
						tid);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN:
			{
				BG_LOGI("[1]DVMWRAP(%d):dvmRawDexFileOpen() \n", 
						tid);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMPREPAREDEX_PRE:
			{
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("[0]DVMWRAP(%d):dvmPrepareDexInMemory() a_0x%08x l_%d(0x%08x)\n", 
						tid, addr, len, len);
				//dumpDexFile(addr, len);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMPREPAREDEX:
			{
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("[1]DVMWRAP(%d):dvmPrepareDexInMemory() a_0x%08x l_%d(0x%08x)\n", 
						tid, addr, len, len);
				//dumpDexFile(addr, len);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD_PRE:
			{
				Int fd = (Int)arg[1];
				BG_LOGI("[0]DVMWRAP(%d):dvmDexFileOpenFromFd(%d) %s\n", 
						tid, fd, fds[tid][fd].name);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD:
			{
				Int fd = (Int)arg[1];
				BG_LOGI("[1]DVMWRAP(%d):dvmDexFileOpenFromFd(%d) %s\n", 
						tid, fd, fds[tid][fd].name);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL_PRE:
			{
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("[0]DVMWRAP(%d):dvmDexFileOpenPartial() a_0x%08x l_%d(0x%08x)\n", 
						tid, addr, len, len);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL:
			{
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("[1]DVMWRAP(%d):dvmDexFileOpenPartial() a_0x%08x l_%d(0x%08x)\n", 
						tid, addr, len, len);
				//dumpDexFile(addr, len);
				break;
			}
		case VG_USERREQ__WRAPPER_DVMCHANGESTATUS:
			{
				if(BG_(clo_trace_begin) == False) 
					break;
				Int newStatus = (Int)arg[2];
				Int oldStatus = (Int)arg[3];
				BG_LOGI("[1]DVMWRAP(%d):dvmChangeStatus() from %d to %d\n", 
						tid, oldStatus, newStatus);
				th_status[tid] = newStatus;
				break;
			}
#endif
#endif // TRACE_DVM_PLATFORM
#ifdef	TRACE_ART_PLATFORM
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE:
			{
				HChar *path = (HChar*)arg[2];
				BG_LOGI("[0]LIBART(%d):LoadNativeLibary() 0x%8x(%s)\n",
						tid, (Addr)path, path);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY:
			{
				HChar *path = (HChar*)arg[2];
				BG_LOGI("[1]LIBART(%d):LoadNativeLibary() 0x%8x(%s)\n", 
						tid, (Addr)path, path);
				/*	for(Int i = 0; i < 4; i++)
						VG_(printf)(" 0x%08x", test[i]);
						VG_(printf)(" %s\n", (HChar*)test[2]);*/
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEFINECLASS:
			{
				HChar *descriptor = (HChar*)arg[1];
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[2];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				struct DexHeader	 *pHeader			= pDexFileObj->header_;
				//struct DexClassDef *pDexClass		= (struct DexClassDef)arg[3];
				if(isFrameworkClass(descriptor))
					break;
				BG_LOGI("[1]LIBART(%d):DefineClass() %s pDexFileObj=0x%08x pMemMapObj=0x%08x 0x%08x-0x%08x 0x%08x %d\n", 
						tid, descriptor, (Addr)pDexFileObj, (Addr)pMemMapObj, pDexFileObj->begin_,
						(Addr)pDexFileObj->begin_ + pDexFileObj->size_, (Addr)pHeader, pHeader->fileSize);
				//if(isInDexFileList(pDexFileObj) == False) {
				meetDeFilePlus(pDexFileObj, pDexFileObj->begin_, pDexFileObj->size_, 2);
#ifdef BANGCLE_ART_1603
				if(VG_(strcmp)("Lcom/bangcle/everisk/utils/e;", descriptor) == 0)
					releaseDexFileList();
#endif
				//}
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEXFILE_PRE:
			{
				struct MemMapPlus *pMemMapObj = (struct MemMapPlus*)arg[1];
				Addr	base = (Addr)arg[2];
				UInt  len	 = (UInt)arg[3];
				HChar *str = (HChar*)arg[4];
				BG_LOGI("[0]LIBART(%d):DexFile() %s 0x%08x-0x%08x pMemMapObj=0x%08x\n", 
						tid, str, base, base+len, (Addr)pMemMapObj);
				if(VG_(memcmp)("/data/", str, 6) == 0)
					dumpDexFile((UChar*)base, len);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_DEXFILE:
			{
				struct DexFilePlus *pDexFileObj = (struct DexFilePlus*)arg[1];
				struct MemMapPlus  *pMemMapObj  = pDexFileObj->mem_map_;
				Addr	base = (Addr)arg[2];
				UInt  len	 = (UInt)arg[3];
				HChar *str = (HChar*)arg[4];
				Addr	memmap = (Addr)arg[5];
				BG_LOGI("[1]LIBART(%d):DexFile() pDexFileObj=0x%08x, pMemMapObj=0x%08x, memMap=0x%08x\n",
						tid, (Addr)pDexFileObj, (Addr)pMemMapObj, memmap);
				UInt *tt = (UInt*)arg[1];
				for(Int i = 0; i < 18; i++)
					VG_(printf)(" %x", tt[i]);
				VG_(printf)("\n");
				// BG_LOGI("[1]LIBART(%d):DexFile() pDexFileObj=0x%08x, pMemMapObj=0x%08x, mmap 0x%08x-0x%08x\n",
				//		tid, (Addr)pDexFileObj, (Addr)pMemMapObj,(Addr)pMemMapObj->begin_, (Addr)pMemMapObj->begin_ + pMemMapObj->size_);
				break;
			} 
#endif
#if 0
		case VG_USERREQ__WRAPPER_ART_TEST_PRE:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				BG_LOGI("[0]LIBART(%d):RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)std, (Addr)str, str);
				break;
			} 
		case VG_USERREQ__WRAPPER_ART_TEST:
			{
				Addr	this = (Addr)arg[1];
				HChar *std = (HChar*)arg[2];
				HChar *str = (HChar*)arg[3];
				BG_LOGI("[1]LIBART(%d):RewhyTest() 0x%8x 0x%08x %s\n", 
						tid, (Addr)sErrortd, (Addr)str, str);
				break;
			} 
		case VG_USERREQ__WRAPPER_SOCKET:
			{
				Int namespace = (Int)arg[1];
				Int style			= (Int)arg[2];
				Int protocol	= (Int)arg[3];
				Int sk        = (Int)arg[4];
				BG_LOGI("POSTREQ(%d):socket %d(%s) %d(%s) %d(%s) res_sk=%d\n", 
						tid, namespace, ADDRESS_FAMILY[namespace],
						style, SOCKET_TYPE[style],
						protocol, PROTOCOL_FAMILY[protocol],
						sk);
				break;
			}
		case VG_USERREQ__WRAPPER_BIND:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				BG_LOGI("POSTREQ(%d):bind sk=%d, family=%d, addr=%s\n",
						tid, sk, sa->sa_family, addr);
				break;
			}
		case VG_USERREQ__WRAPPER_CONNECT_PRE:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					BG_LOGI("PREVREQ(%d):connect sk=%d, AF_INET, addr=%s:%d\n",
							tid, sk, addr, NTOHS(sa->sa_port));
					inet_aton("10.10.0.1", &sa->addr);
					addr = inet_ntoa(sa->addr);
					BG_EXE_LOGI("PREVREQ(%d):connect target address modified to %s\n",
							tid, addr);
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					BG_LOGI("PREVREQ(%d):connect sk=%d, AF_UNIX, addr=%s\n",
							tid, sk, addr);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_CONNECT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				HChar *addr;
				Int* res = (Int*)arg[3];
				if (sa->sa_family == AF_INET) {
					addr = inet_ntoa(sa->addr);
					BG_LOGI("POSTREQ(%d):connect sk=%d, AF_INET, addr=%s:%d, res=%d (taint)\n",
							tid, sk, addr, NTOHS(sa->sa_port), *res);
				}
				else {
					addr = ((struct sockaddr*)sa)->sa_data;
					BG_LOGI("POSTREQ(%d):connect sk=%d, AF_UNIX, addr=%s, res=%d\n",
							tid, sk, addr, *res);
				}
				if(*res < 0) {
					*res = 0;
					BG_EXE_LOGI("POSTREQ(%d):connect res modified to %d\n", tid, *res);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_LISTEN:
			{
				Int sk = (Int)arg[1];
				Int bl = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):listen sk=%d, backlog=%d\n", tid, sk, bl);
				break;
			}
		case VG_USERREQ__WRAPPER_ACCEPT:
			{
				Int sk = (Int)arg[1];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[2];
				Int rk = (Int)arg[3];
				HChar *addr;
				if (sa->sa_family == AF_INET)
					addr = inet_ntoa(sa->addr);
				else
					addr = ((struct sockaddr*)sa)->sa_data;
				BG_LOGI("POSTREQ(%d):accept sk=%d, family=%d, addr=%s, res=%d\n", 
						tid, sk, sa->sa_family, addr, rk);
				break;
			}
		case VG_USERREQ__WRAPPER_SEND:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];

				BG_LOGI("POSTREQ(%d):send sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);
				break;
			}
		case VG_USERREQ__WRAPPER_SENDTO:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int *rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						BG_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						BG_LOGI("POSTREQ(%d):sendto sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, buf, *rlen);
					}
				} else {
					BG_LOGI("POSTREQ(%d):sendto sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, buf, *rlen);
				}

				break;
			}
		case VG_USERREQ__WRAPPER_RECV_PRE:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *bufsize = (Int*)arg[4];

				BG_LOGI("PREVREQ(%d):recv sk=%d, 0x%08x, size=%d\n", 
						tid, sk, (Int)buf, *bufsize);
				break;
			}
		case VG_USERREQ__WRAPPER_RECV:
			{
				Int sk = arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				Int *res = (Int*)arg[4];

				BG_LOGI("POSTREQ(%d):recv sk=%d, 0x%08x(%s), len=%d\n", 
						tid, sk, (Int)buf, buf, *res);

				break;
			}
		case VG_USERREQ__WRAPPER_RECVFROM_PRE:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int* rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						BG_LOGI("PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						BG_LOGI("PREVREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					BG_LOGI("PREVREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_RECVFROM:
			{
				Int sk = (Int)arg[1];
				HChar* buf = (HChar*)arg[2];
				UShort flags = (UShort)arg[3];
				struct sockaddr_in* sa = (struct sockaddr_in*)arg[4];
				Int* rlen = (Int*)arg[5];
				HChar *addr;
				if(sa) {
					if (sa->sa_family == AF_INET) {
						addr = inet_ntoa(sa->addr);
						BG_LOGI("POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_INET, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
					else {
						addr = ((struct sockaddr*)sa)->sa_data;
						BG_LOGI("POSTREQ(%d):recvfrom sk=%d, addr=%s:%d, AF_UNIX, 0x%08x(%s), len=%d\n", 
								tid, sk, addr, NTOHS(sa->sa_port), (Int)buf, (HChar*)buf, *rlen);
					}
				} else {
					BG_LOGI("POSTREQ(%d):recvfrom sk=%d , AF_UNIX, 0x%08x(%s), len=%d\n", 
							tid, sk,  (Int)buf, (HChar*)buf, *rlen);
				}
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_OPEN:
			{
				HChar* path = (HChar*)arg[1];
				Int  fd = (Addr)arg[2];
				if(BG_(clo_trace_begin) == False) { 
					/*if(fds[tid][fd].type == FdAppDex)
						{
						BG_(set_instrumentsate)("first.app.dex.open", True);
						BG_LOGI("%s\n", "Tracing starts...");
						}*/
				} else {
					if(BG_(is_full_trace))
						BG_LOGI("POSTREQ(%d):open(%s) res=%d\n", tid, path, fd);
				}
				break;
			}
		case VG_USERREQ__WRAPPER_FOPEN:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				HChar* path = (HChar*)arg[1];
				Addr  file = (Addr)arg[2];
				BG_LOGI("POSTREQ(%d):fopen(%s) res=%d\n",
						tid, path, file);
				break;
			}
		case VG_USERREQ__WRAPPER_FSEEK:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Addr file = (Addr)arg[1];
				Int  res  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):fseek(%d) res=%d\n",
						tid, file, res);
				break;
			}
		case VG_USERREQ__WRAPPER_LSEEK:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Int fd = (Int)arg[1];
				Int  res  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):lseek(%d) res=%d\n",
						tid, fd, res);
				break;
			}
		case VG_USERREQ__WRAPPER_FREAD:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
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
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
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
		case VG_USERREQ__WRAPPER_FWRITE:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
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
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
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
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Int  fd = (Int)arg[1];
				BG_LOGI("POSTREQ(%d):close(%d)\n", tid, fd);
				break;
			}
		case VG_USERREQ__WRAPPER_FCLOSE:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Addr  file = (Addr)arg[1];
				BG_LOGI("POSTREQ(%d):fclose(%d)\n", tid, file);
				break;
			}
		case VG_USERREQ__WRAPPER_SHUTDOWN:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Int sk  = (Int)arg[1];
				Int how = (Int)arg[2];
				Int res = (Int)arg[3];
				tl_assert(how==0 | how==1 || how==2);
				BG_LOGI("POSTREQ(%d):shutdown sk=%d how=%s res=%d\n",
						tid, sk, SHUTDOWN_HOW[how], res);
				break;
			}
		case VG_USERREQ__WRAPPER_MMAP:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
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
							if( BG_(is_parse_dex)) 
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
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				BG_LOGI("POSTREQ(%d):munmap 0x%08x l_%d(%x)\n",
						tid, addr, len, len);
				break;
			}
		case VG_USERREQ__WRAPPER_MPROTECT:
			{
				if(BG_(clo_trace_begin) == False || BG_(is_full_trace) == False) 
					break;
				break;
				Addr addr = (Addr)arg[1];
				Int  len  = (Int)arg[2];
				Int  prot = (Int)arg[3];
				BG_LOGI("POSTREQ(%d):mprotect 0x%08x l_%d(0x%08x) %s\n",
						tid, addr, len, len, mmap_proto2a(prot));
				break;
			}
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
#if 0
		case VG_USERREQ__WRAPPER_MADVISE_PRE:
			{
				Addr addr = (Addr)arg[1];
				UInt len	= (UInt)arg[2];
				Int	 dev	= (Int)arg[3];
				BG_LOGI("[0]LIBCWRAP(%d):madvise() addr=0x%08x len=%d dev=%x\n", 
						tid, addr, len, dev);
				break;
			}
		case VG_USERREQ__WRAPPER_MADVISE:
			{
				Addr addr = (Addr)arg[1];
				UInt len	= (UInt)arg[2];
				Int	 dev	= (Int)arg[3];
				Int	 res	= (Int)arg[4];
				BG_LOGI("[1]LIBCWRAP(%d):madvise() addr=0x%08x len=%d dev=%x res=%d\n", 
						tid, addr, len, dev, res);
				break;
			}
#endif
		case VG_USERREQ__WRAPPER_PTRACE:
			{
				Int pid = (Int)arg[1];
				Addr addr = (Addr)arg[2];
				Int data = (Int)arg[3];
				Int res = (Int)arg[4];
				BG_LOGI("[1]LIBCWRAP(%d):ptrace() tid=%d pid=%d addr=0x%08x data=%d res=%d\n", 
						tid, pid, addr, data, res);
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

static void bg_new_mem_stack ( Addr a, SizeT len )
{  
	BG_LOGI("new mem stack 0x%x %d\n", (Int)a, len );
}  

static void bg_die_mem_stack ( Addr a, SizeT len )
{  
	BG_LOGI("die mem stack 0x%x %d\n", (Int)(-VG_STACK_REDZONE_SZB + a), len );
}  

static void bg_ban_mem_stack ( Addr a, SizeT len )
{
	BG_LOGI("ban mem stack 0x%x %d\n", (Int)a, len );
}

static void halt( Double s) {
	Double j = 0;
	Double i = 0;
	for(i = 0.1; i < s; i += 0.1) {
		j = i * i;
	}
}
/*--- Syscall event handlers ---*/
static void bg_pre_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs) {
#ifdef IJIAMI_1603
	/*if(syscallno== 78) {
		if(tid == 1 )
			last_ttt++;
		else
			last_ttt = 0;
	}*/
#endif
	if (tid != 1) 
		return;
	switch ((int)syscallno) {
		case __NR_ptrace:
			BG_(syscall_ptrace_pre)(tid, args, nArgs);
			break;
		case __NR_exit:
			BG_(syscall_exit)(tid, args, nArgs);
			break;
		default:
			break;
	}
}
static void bg_post_syscall(ThreadId tid, UInt syscallno, UWord *args, UInt nArgs, SysRes res) {
	if (tid != 1) 
		return;
	if(BG_(is_full_trace) == False) {
		if( syscallno == __NR_open || syscallno == __NR_openat) 
			BG_(syscall_open)(tid, args, nArgs, res);
		return;
	}
	switch ((int)syscallno) {
		// Should be defined by respective include/vki/vki-scnums-arch-os.h
		case __NR_clone:
			BG_(syscall_clone)(tid, args, nArgs, res);
			break;
		case __NR_rt_sigaction:
		case __NR_sigaction:
			BG_(syscall_action)(tid, args, nArgs, res);
			break;
		case __NR_unlink:
		case __NR_unlinkat:
			BG_(syscall_unlink)(tid, args, nArgs, res);
			break;
		case __NR_execve:
			BG_(syscall_execve)(tid, args, nArgs, res);
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

#if 0
		case __NR_ptrace:
			BG_(syscall_ptrace)(tid, args, nArgs, res);
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
	Int i;
	for( i=0; i< TI_MAX; i++ ) {
		ti[i] = 0;
		tv[i] = 0;
	}
	for( i=0; i< RI_MAX; i++ )
		ri[i] = 0; 
	/*for( i=0; i< STACK_SIZE; i++ )
		lvar_i[i] = 0;
		lvar_s.size = 0;*/
	BG_(clo_trace_begin) = False;
}
static void bg_fini(Int exitcode)
{
	BG_(clo_trace_begin) = False;
	VG_(printf)("exitcode:%d\n", exitcode);
	if(BG_(is_release_dex_files) == True)
		return
	releaseFilterlist(&fl);
	releaseFilterlist(&dlibl);
	releaseDexFileList();
	VG_(memset)((UChar*)fds, 0, sizeof(struct fd_info) * TG_N_THREADS * FD_MAX);
	BG_(is_release_dex_files) = False;
}

static void bg_pre_clo_init(void)
{
	VG_(details_name)            ("Bevgrind");
	VG_(details_version)         ("0.3.0");
	VG_(details_description)     ("Application behaviors tracking");
	VG_(details_copyright_author)(
			"Copyright (C) 2002-2016, and GNU GPL'd, by Rewhy");
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
	VG_(needs_syscall_wrapper)		(bg_pre_syscall, 
			bg_post_syscall);

	VG_(needs_var_info)						();

	init_soaap_data();

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
	VG_(track_pre_deliver_signal) (&bg_track_pre_deliver_signal);
	VG_(track_post_deliver_signal) (&bg_track_post_deliver_signal);
#if 0
	VG_(track_new_mem_startup)		 ( bg_new_mem_startup );
	VG_(track_copy_mem_remap)      ( bg_track_copy_mem_remap ); 
	VG_(track_new_mem_mmap)				 ( bg_track_new_mem_mmap );
	VG_(track_change_mem_mprotect) ( bg_track_change_mem_mprotect );
	VG_(track_die_mem_munmap)      ( bg_track_die_mem_munmap );

	VG_(track_pre_mem_read)				 ( bg_pre_mem_read );
	VG_(track_pre_mem_read_asciiz) ( bg_pre_mem_read_asciiz );
	VG_(track_pre_mem_write)			 ( bg_pre_mem_write );
	VG_(track_post_mem_write)			 ( bg_post_mem_write );

	VG_(track_die_mem_stack_signal)( bg_track_die_mem_stack_signal );
	VG_(track_die_mem_brk)				 ( bg_track_die_mem_brk );

	VG_(track_new_mem_stack)			 ( bg_new_mem_stack );
	VG_(track_die_mem_stack)       ( bg_die_mem_stack );
	VG_(track_ban_mem_stack)       ( bg_ban_mem_stack );

	VG_(track_post_reg_write)                  ( bg_post_reg_write );
	VG_(track_post_reg_write_clientcall_return)( bg_post_reg_write_clientcall );

	VG_(track_copy_mem_to_reg)		 ( bg_copy_mem_to_reg );
	VG_(track_copy_reg_to_mem)		 ( bg_copy_reg_to_mem );
#endif
}

VG_DETERMINE_INTERFACE_VERSION(bg_pre_clo_init)

/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
