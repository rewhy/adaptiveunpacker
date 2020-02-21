// pg_memtrace.h
#ifndef PG_MEM_TRACE_H
#define PG_MEM_TRACE_H

#include "pub_tool_xarray.h"

#include "pg_translate.h"

struct myStringArray{
	char m[STACK_SIZE][MAX_LEN];
	int size;
};

struct FunList {
	char name[MAX_LEN];
	struct FunList *next;
};

struct LibList {
	char name[MAX_LEN];
	struct Funlist *flist;
	struct LibList *next;
};

struct FilterList {
	HChar			info[255];
	Addr			begin;
	Addr      end;
	struct FilterList* next;
};

void initSoaapData();
Bool addFilterFun(const HChar* soname, const HChar* fnname);

void addTraceMemMap(Addr addr, Int size, Int prot, HChar *info);
Bool getTraceMemMapInfo(Addr addr, Int prot, HChar **pinfo);
void delTraceMemMap(Addr addr, Int size);

//void dumpFilterList(struct FilterList *pfl);
//void delFilterList(struct FilterList** ppfl, const HChar *info, Addr avma, SizeT size );
//void addFilterList(struct FilterList** ppfl, const HChar* info, Addr avma, SizeT size );
void initFilterList();
//void releaseFilterlist(struct FilterList** ppfl);
//Addr isInFilterList(struct FilterList* pfl, Addr a, HChar** pInfo);
Bool isInstrumentNeeded( VgCallbackClosure* closure );

void releaseTraceMemSyslib(void);
void releaseTraceMemFile(void);
void releaseTraceMemMap(void);
Bool isInTraceMemSyslib(Addr a, HChar** pInfo);
Bool isInTraceMemFile(Addr a, HChar** pInfo);
Bool isInTraceMemMap(Addr a, HChar** pInfo);

#endif // PG_MEM_TRACE_H
