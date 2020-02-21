#ifndef _PG_FRAMEWORK_H
#define _PG_FRAMEWORK_H

#include "pg_mthtrace.h"
#include "runtime/rt_object.h"


HChar *get_classobject_name(ClassMirror *clazz);

typedef 
struct _Mth_Pool	
MthNode;

Int check_mth_return(MthNode* mNode, ThreadId tid);
Int check_mth_invoke(MthNode* mNode, ThreadId tid);

#endif //_PG_FRAMEWORK_H
