//pg_mthtrace.h
#ifndef _PG_MTH_TRACE_H
#define _PG_MTH_TRACE_H

#include "pub_tool_basics.h"
#include "pub_core_threadstate.h"
#include "pub_tool_machine.h"     // VG_(fnptr_to_fnentry)

#include "pg_dexparse.h"
#include "pg_translate.h"

/* For storing method list */
#define MAX_MTH_NUM			65535

#define DBG_PARAMETER_PARSE	0

typedef 
struct _Mth_Pool {
	struct _Mth_Pool *next;
	Addr		codeAddr;
	Addr		pAMth;
	SizeT		codeSize;
#if 0
	HChar		clazz[256];
	HChar		method[128];
	HChar		shorty[32];
#else
	HChar*	clazz;
	HChar*	method;
	HChar*	shorty;
#endif
	UInt		mthKey;
	Int			accessFlags;
	UChar		type;
	UChar   taintTag;
} MthNode;

/*#define MAX_METHOD_NUM	1024
typedef
struct _Mth_List {
	struct _Mth_List *next;
	Addr	codeAddr;
	Addr	mthNodes[MAX_METHOD_NUM];
	Int	 num;
} MthList;*/

#define MAX_STACK_SIZE	1024
typedef 
struct _Mth_stack {
	Addr	addr[MAX_STACK_SIZE];
	Addr  stack[MAX_STACK_SIZE];
	Addr	mth[MAX_STACK_SIZE];
	UChar	taintTag[MAX_STACK_SIZE];
	UInt	size;
} MthStack;

typedef 
struct _Method_Code_Node {
	struct _Hash_Node	*next;
	Addr	dexCodeAddr;
	Addr	nativeCodeAddr;
	SizeT nativeCodeSize;
} MthCodeNode;


//void addMthCodeNode(Addr dexCodeAddr, Addr nativeCodeAddr, SizeT nativeCodeSize);
void addMthCodeNode(struct DexFile *pDex, Addr dexCodeAddr, Addr nativeCodeAddr, SizeT nativeCodeSize, Int accessFlags, Int idx);
MthCodeNode* queryMthCodeNode(Addr dexCodeAddr) ;

void* add_method(HChar *clazz, HChar* mth, HChar* shorty, Addr codeAddr, SizeT codeSize, Int index, Int accessFlags);
void trackJavaMethod(const BGEnv* mce, const VexGuestLayout* guestlayout,	const VexGuestExtents* vge);
// MthNode* query_method_node(Addr codeAddr, Int index);
#endif // _PG_MTH_TRACE_H
