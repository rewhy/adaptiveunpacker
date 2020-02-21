// pg_mthtrace.c

#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcassert.h"
#include "pub_core_threadstate.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)
#include "pub_tool_debuginfo.h"     // VG_(get_fnname_w_offset), VG_(get_fnname)

#include "pg_debug.h"
#include "pg_mthtrace.h"
#include "pg_translate.h"
#include "pg_framework.h"
#include "pg_oatparse.h"


UChar pformat3[256];
#define ART_INVOKE(fmt, x...) \
	VG_(snprintf)(pformat3, sizeof(pformat3),	"[CALL]: %s", fmt); \
VG_(printf)(pformat3, ##x);

#define ART_RETURN(fmt, x...) \
	VG_(snprintf)(pformat3, sizeof(pformat3), "[RETU]: %s", fmt); \
VG_(printf)(pformat3, ##x);

#define ART_LOGI(fmt, x...) \
	VG_(snprintf)(pformat3, sizeof(pformat3), "[I]: %s", fmt); \
VG_(printf)(pformat3, ##x);

#define ART_LOGW(fmt, x...) \
	do{ \
		VG_(snprintf)(pformat3, sizeof(pformat3), "[W]: %s", fmt); \
		VG_(printf)(pformat3, ##x); \
	} while(0)

Int    do_start_method_index = -1;
HChar* do_start_clazz = NULL;
HChar* do_start_method_name = NULL;
HChar* do_start_method_shorty = NULL;

Int    do_stop_method_index = -1;
HChar* do_stop_clazz = NULL;
HChar* do_stop_method_name = NULL;
HChar* do_main_activity = NULL;

Int    do_main_oncreate_index = -1;

static VgHashTable*	do_oatmth_list = NULL; // Used to store the native code offset of methods when pasing OAT file
void addMthCodeNode(struct DexFile *pDex, Addr dexCodeAddr, Addr nativeCodeAddr, SizeT nativeCodeSize, Int accessFlags, Int idx)
{
	if(dexCodeAddr == 0) return; // JNI method
	// BG_LOGI("[0]addMthCodeNode: pDex=0x%08x 0x%08x 0x%08x 0x%08x\n", (Addr)pDex, dexCodeAddr, nativeCodeAddr, nativeCodeSize);
	
	if((nativeCodeAddr > 0) && (nativeCodeSize > 0) && pDex) { // Compiled method
		HChar *clazz, *mth, *shorty;
		if(getMethodSignature(pDex, idx, &clazz, &mth, &shorty)) {
			add_method(clazz, mth, shorty, nativeCodeAddr, nativeCodeSize, idx, accessFlags);
		}
		return;
	}
	
	/* The method to be interpreted */
	if(do_oatmth_list == NULL) {
		do_oatmth_list = VG_(HT_construct)( "do_oatmth_list" );
	}
	tl_assert(do_oatmth_list != NULL);
	MthCodeNode* mc = VG_(malloc)("method.code.node", sizeof(MthCodeNode));
	if(mc == NULL) return;

	mc->dexCodeAddr = dexCodeAddr;
	mc->nativeCodeAddr = nativeCodeAddr;
	mc->nativeCodeSize = nativeCodeSize ;
	VG_(HT_add_node)(do_oatmth_list, mc);
}

MthCodeNode* queryMthCodeNode(Addr dexCodeAddr) 
{
	if((dexCodeAddr == 0) || (do_oatmth_list == NULL)) return NULL;
	MthCodeNode* mc = VG_(HT_lookup)( do_oatmth_list, dexCodeAddr);
	// BG_LOGI("[1]queryMthCodeNode: 0x%08x rex=0x%08x\n", dexCodeAddr, (Addr)mc);
	return mc;
}

/************************************************************/

/***** For Tracking the method with native instructins *****/

static VgHashTable*	do_frame_mth_list = NULL;

static INLINE
MthNode* query_method_list(Addr codeAddr) {
	if(do_frame_mth_list == NULL)
		return NULL;
	MthNode *mNode = VG_(HT_lookup)( do_frame_mth_list, codeAddr);
	return mNode;
}



static Int t = 0;
void* add_method(HChar *clazz, HChar* mth, HChar* shorty, Addr codeAddr, SizeT codeSize, Int index, Int accessFlags)
{ 
	MthNode* mth_node = NULL;//, *mth_node1 = NULL;
	Addr		 code_addr = codeAddr;
	/*if(accessFlags & ACC_NATIVE) {
		return NULL;
		}*/
	/* Check method*/
	//if(mth[0] == '-') return;


	mth_node = (MthNode *)VG_(malloc)("method.node", sizeof(MthNode));

	if(do_frame_mth_list == NULL) {
		do_frame_mth_list = VG_(HT_construct)( "do_frame_mth_list" );
	}

	if(mth_node) {
		VG_(memset)((Addr)mth_node, 0, sizeof(MthNode));
#if 0
		VG_(strcpy)(mth_node->clazz, clazz);
		VG_(strcpy)(mth_node->method, mth);
		VG_(strcpy)(mth_node->shorty, shorty);
#endif
		mth_node->clazz				= (HChar*)clazz;
		mth_node->method			= (HChar*)mth;
		mth_node->shorty			= (HChar*)shorty;
		mth_node->codeAddr		= code_addr;
		mth_node->codeSize		= codeSize;
		mth_node->mthKey			= index;
		mth_node->accessFlags = accessFlags;

		VG_(HT_add_node)(do_frame_mth_list, mth_node);
		/* VG_(printf)("Add Method(%04d): %d 0x%08x-0x%08x %s %s() %s isNative=%c\n",
				t, index, codeAddr, codeAddr+codeSize-1, clazz, 
				mth, shorty, accessFlags & ACC_NATIVE ? 'T' : 'F');*/
	}
	return (void*)mth_node;
}



#if 0
MthNode* query_method_node(Addr codeAddr, Int index)
{
	MthNode *mth_node = VG_(HT_lookup)( do_frame_mth_list, codeAddr);
	return mth_node;
}

	static INLINE
Bool query_method(Addr codeAddr, HChar **clazz, HChar **mth, HChar **shorty, Int *accFlags)
{
	if(do_frame_mth_list == NULL)
		return False;
	//DT_LOGI("Query Addr: 0x%08x\n", codeAddr);
	MthNode *mth_node = VG_(HT_lookup)( do_frame_mth_list, codeAddr );
	if(mth_node) {
		if(clazz)
			*clazz		= mth_node->clazz;
		if(mth)
			*mth			= mth_node->method;
		if(shorty)
			*shorty		= mth_node->shorty;
		if(accFlags)
			*accFlags = mth_node->accessFlags;
		return True;
	}
	return False;
}
	static INLINE
void remove_method(Addr codeAddr)
{
	MthNode *mth_node = VG_(HT_remove)( do_frame_mth_list, codeAddr);
	if( NULL == mth_node )
		return;
	VG_(free)( mth_node );
	mth_node = NULL;
}
#endif

static MthStack	mthStack[TG_N_THREADS];

	static INLINE
Int mth_push_stack(ThreadId tid, Addr addr, MthNode* mth)
{
	MthStack* ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size < MAX_STACK_SIZE) {
			ms->addr[ms->size] = addr;
			ms->mth[ms->size]  = (Addr)mth;
			ms->size++;
		}
		return ms->size;
	}
	return -1;
}

static INLINE
Int mth_pop_stack(ThreadId tid) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > 0)
			ms->size--;
		return ms->size;
	}
	return -1;
}

static INLINE
Bool mth_top_stack(ThreadId tid, Addr *addr, MthNode **mth) {
	MthStack *ms = NULL;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		if(ms->size > 0) {
			*addr = ms->addr[ms->size-1];
			if(mth)
				*mth  = (MthNode*)ms->mth[ms->size-1];
			return True;
		}
	}
	return False;
}

static INLINE
MthNode* mth_lookup_stack(ThreadId tid, Addr a) {
	MthStack *ms = NULL;
	Addr addr;
	if(tid < TG_N_THREADS) {
		ms = &mthStack[tid];
		for(Int i = ms->size; i > 0; i--) {
			addr = ms->addr[i-1];
			if(a&~0x1 == addr&~0x1)
				return (MthNode*)ms->mth[i-1];
		}
	}
	return NULL;
}

static INLINE
Int mth_stack_size(ThreadId tid) {
	return mthStack[tid].size;
}





/* Dirty function inserted into the beginning of a IRSB */
void invoke_superblock(MthNode* mNode, VexGuestLayout *layout)
{
	ThreadId			tid	= VG_(get_running_tid)();
	ThreadState*	tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	UWord r0, r1, r2, r3, r4, sp, lr, pc; Int tt;
	Addr last_lr;
# if defined(VGPV_arm_linux_android)
	r0 = arch_state->guest_R0;
	r1 = arch_state->guest_R1;
	r2 = arch_state->guest_R2;
	r3 = arch_state->guest_R3;
	r4 = arch_state->guest_R4;
	sp = arch_state->guest_R13;
	lr = arch_state->guest_R14;
	pc = arch_state->guest_R15T;
# endif
	struct ArtMethod *pAMth = (struct ArtMethod *)r0;
	Bool isStatic = (mNode->accessFlags & ACC_STATIC) ? True : False;
	tt = mth_push_stack(tid, lr, mNode);
#if DBG_PARAMETER_PARSE
	ART_INVOKE("%d 0x%08x %05d 0x%08x pc=0x%08x lr=0x%08x last_lr=0x%08x %s %s() %s stack =%d sp=0x%08x isStatic=%s\n", 
			tid, (Addr)mNode, mNode->mthKey, mNode->codeAddr, pc, lr, last_lr, mNode->clazz, mNode->method, 
			mNode->shorty, tt, sp, isStatic ? "True" : "False");
#else
	ART_INVOKE("%d %05d %s %s() %s flag=%d\n", 
			tid, mNode->mthKey, mNode->clazz, mNode->method, mNode->shorty, pAMth->access_flags_);//, isStatic ? "True" : "False");
#endif
	/* Parse the parameters of the method to be invoked*/
	check_mth_invoke(mNode, tid);
}


/* Dirty function inserted into the end of a IRSB */
void return_superblock(Addr a,  VexGuestLayout *layout)
{ 
	ThreadId tid = VG_(get_running_tid)();
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	Addr addr; MthNode *mNode = NULL;
	UWord sp;
# if defined(VGPV_arm_linux_android)
	sp = arch_state->guest_R13;
# endif
	Bool isStatic = False;//(mNode->accessFlags & ACC_STATIC) ? True : False;
	if(mth_top_stack(tid, &addr, &mNode)) {
		if((addr&0xfffffffe) == (a&0xfffffffe)) {
			/*ART_RETURN("%d %05d pc=0x%08x %s %s() %s source=%d sp=0x%08x\n", tid, mNode->mthKey, 
				a, mNode->clazz, mNode->method, mNode->shorty, 
				mNode->type, sp);*/
			isStatic = (mNode->accessFlags & ACC_STATIC) ? True : False;
			ART_RETURN("%d %05d %s %s() %s isSource=%s\n", 
					tid, mNode->mthKey, mNode->clazz, mNode->method, 
					mNode->shorty,
					mNode->type & TYPE_SOURCE ? "True" : "Flase");
			mth_pop_stack(tid);
			/* Parse the results of the returning method */
			check_mth_return(mNode, tid);
		}
	}
}  


static INLINE Bool is_framework_bb(Addr *a) {
	DebugInfo*	d  = VG_(find_DebugInfo)(a);
	if(d) {
		if(VG_(DebugInfo_is_oat)(d)) {
			return True;
		}
	}
	return False;
}


void trackJavaMethod(const BGEnv* mce, 
		const VexGuestLayout* guestlayout,
		const VexGuestExtents* vge) {
	MthNode*	mNode = NULL;
	IRDirty*	di		= NULL;
	Bool			isEntry = False;

	// For tracking method invocations: just insert dirty function 
	// at the beginning of compiled Java method
	if( is_framework_bb(vge->base[0]) ) {
		// OAT_LOGI("Try to track Java method at 0x%08x\n", vge->base[0] & 0xfffffffe);
		mNode = query_method_list(vge->base[0] & 0xfffffffe);
		if(mNode) {
			// OAT_LOGI("Insert method tracking dirty function at 0x%08x.\n", vge->base[0]);
			di = unsafeIRDirty_0_N(
					0, "invoke_superblock",
					VG_(fnptr_to_fnentry)( &invoke_superblock ),
					mkIRExprVec_2(mkIRExpr_HWord((Addr)mNode),
						mkIRExpr_HWord((Addr)guestlayout)));
			insertStmt('C', mce, IRStmt_Dirty(di));
			isEntry = True;
		}
	}

	// For tracking method returns
	di = unsafeIRDirty_0_N(
			0, "return_superblock",
			VG_(fnptr_to_fnentry)( &return_superblock ),
			mkIRExprVec_2(mkIRExpr_HWord(vge->base[0] & ~0x1),
				mkIRExpr_HWord((Addr)guestlayout)));

	insertStmt('C', mce, IRStmt_Dirty(di));
	return;
}

