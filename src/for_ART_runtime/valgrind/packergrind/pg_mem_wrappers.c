// dt_mem_wrappers.c
//
#include "pub_tool_basics.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_mallocfree.h"
#include "pub_tool_replacemalloc.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_xarray.h"

#include "packergrind.h"
#include "pg_debug.h"
#include "pg_wrappers.h"
#include "pg_translate.h"

#define DBG_MEM_FUNC	0

extern Bool BG_(clo_trace_begin);
VgHashTable *BG_(malloc_list)  = NULL;   // HP_Chunks

void dumpMemBlock( Addr addr, SizeT size ) {
	Int i, j;
	UChar *t = (UChar*)addr;
	VG_(printf)("Memory block data: \n");
	if (size > 64)
		j = 64;
	else
		j = size;
	for(i = 0; i < j; i++) {
		VG_(printf)("0x%02x ", t[i]);
		if ((i + 1) % 32 == 0 )
			VG_(printf)("\n");
	}
	VG_(printf)("\n");
}


static
void* record_block( ThreadId tid, void* p, SizeT req_szB, SizeT slop_szB )
{
   // Make new HP_Chunk node, add to malloc_list
   HP_Chunk* hc = VG_(malloc)("dt.malloc_wrapper.rb.1", sizeof(HP_Chunk));
   hc->req_szB  = req_szB;
   hc->slop_szB = slop_szB;
   hc->data     = (Addr)p;
   VG_(HT_add_node)(BG_(malloc_list), hc);
	 //BG_LOGI("Add mem block: 0x%08x-0x%08x %d\n", (Addr)p, (Addr)p+req_szB, req_szB);
   return p;
}

static __inline__
void* alloc_and_record_block ( ThreadId tid, SizeT req_szB, SizeT req_alignB,
                               Bool is_zeroed )
{
   SizeT actual_szB, slop_szB;
   void* p;

   if ((SSizeT)req_szB < 0) return NULL;

   // Allocate and zero if necessary.
   p = VG_(cli_malloc)( req_alignB, req_szB );
   if (!p) {
      return NULL;
   }
   if (is_zeroed) VG_(memset)(p, 0, req_szB);
   actual_szB = VG_(cli_malloc_usable_size)(p);
   tl_assert(actual_szB >= req_szB);
   slop_szB = actual_szB - req_szB;

   // Record block.
   record_block(tid, p, req_szB, slop_szB);
#if 0
	 if (req_szB == 4668)
		 return (void*)0x1;
#endif
   return p;
}

static __inline__
void unrecord_block ( void* p )
{
   // Remove HP_Chunk from malloc_list
   HP_Chunk* hc = VG_(HT_remove)(BG_(malloc_list), (UWord)p);
   if (NULL == hc) {
      return;   // must have been a bogus free()
   }

	 if( BG_(clo_trace_begin) ) {
#ifndef M_PERFORMANCE
#ifndef ONLY_DUMP
			 //BG_LOGI("Del mem block: 0x%08x-0x%08x %d\n", hc->data, hc->data+hc->req_szB, hc->req_szB);
			 //if( hc->req_szB > 32 )
				// delFilterList(&dlibl, "Free.mem.block", hc->data, hc->req_szB);
#endif
#endif// M_PERFORMANCE
			 /*if( hc->req_szB == 4668 )
				 dumpMemBlock(hc->data, hc->req_szB);*/
	 }
   // Actually free the chunk, and the heap block (if necessary)
   VG_(free)( hc ); 
	 hc = NULL;
}

static __inline__
void* realloc_block ( ThreadId tid, void* p_old, SizeT new_req_szB )
{
   HP_Chunk* hc;
   void*     p_new;
   SizeT     old_req_szB, old_slop_szB, new_slop_szB, new_actual_szB;

   // Remove the old block
   hc = VG_(HT_remove)(BG_(malloc_list), (UWord)p_old);
   if (hc == NULL) {
      return NULL;   // must have been a bogus realloc()
   }

   old_req_szB  = hc->req_szB;
   old_slop_szB = hc->slop_szB;

   // Actually do the allocation, if necessary.
   if (new_req_szB <= old_req_szB + old_slop_szB) {
      // New size is smaller or same;  block not moved.
      p_new = p_old;
      new_slop_szB = old_slop_szB + (old_req_szB - new_req_szB);

   } else {
      // New size is bigger;  make new block, copy shared contents, free old.
      p_new = VG_(cli_malloc)(VG_(clo_alignment), new_req_szB);
      if (!p_new) {
         // Nb: if realloc fails, NULL is returned but the old block is not
         // touched.  What an awful function.
         return NULL;
      }
      VG_(memcpy)(p_new, p_old, old_req_szB);

      VG_(cli_free)(p_old);
      new_actual_szB = VG_(cli_malloc_usable_size)(p_new);
      tl_assert(new_actual_szB >= new_req_szB);
      new_slop_szB = new_actual_szB - new_req_szB;
   }

   if (p_new) {
      // Update HP_Chunk.
      hc->data     = (Addr)p_new;
      hc->req_szB  = new_req_szB;
      hc->slop_szB = new_slop_szB;
   }

   // Now insert the new hc (with a possibly new 'data' field) into
   // malloc_list.  If this realloc() did not increase the memory size, we
   // will have removed and then re-added hc unnecessarily.  But that's ok
   // because shrinking a block with realloc() is (presumably) much rarer
   // than growing it, and this way simplifies the growing case.
   VG_(HT_add_node)(BG_(malloc_list), hc);
   return p_new;
}


void* BG_(malloc) ( ThreadId tid, SizeT szB )
{
	void* res = alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/True );
#if DBG_MEM_FUNC
		BG_LOGI("malloc: 0x%x %d\n", res, szB);
#endif
	return res;
}

void* BG_(__builtin_new) ( ThreadId tid, SizeT szB )
{
	void* res = alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/True );
#if DBG_MEM_FUNC
		BG_LOGI("new: 0x%x %d\n", res, szB);
#endif
	return res;
}

void* BG_(__builtin_vec_new) ( ThreadId tid, SizeT szB )
{
	void* res = alloc_and_record_block( tid, szB, VG_(clo_alignment), /*is_zeroed*/True );
	return res;
}

void* BG_(calloc) ( ThreadId tid, SizeT m, SizeT szB )
{
	void* res = alloc_and_record_block( tid, m*szB, VG_(clo_alignment), /*is_zeroed*/True );
	return res;
}

void* BG_(memalign) ( ThreadId tid, SizeT alignB, SizeT szB )
{
	void* res = alloc_and_record_block( tid, szB, alignB, True );
	return res;
}

void BG_(free) ( ThreadId tid __attribute__((unused)), void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void BG_(__builtin_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void BG_(__builtin_vec_delete) ( ThreadId tid, void* p )
{
   unrecord_block(p);
   VG_(cli_free)(p);
}

void* BG_(realloc) ( ThreadId tid, void* p_old, SizeT new_szB )
{
	void* res = realloc_block(tid, p_old, new_szB);
	return res;
}

SizeT BG_(malloc_usable_size) ( ThreadId tid, void* p )
{                                                            
   HP_Chunk* hc = VG_(HT_lookup)( BG_(malloc_list), (UWord)p );
	 SizeT res =  ( hc ? hc->req_szB + hc->slop_szB : 0 );
	 return res;
}                                                            

//--------------------------------------------------------------------//
//--- end                                                          ---//
//--------------------------------------------------------------------//
