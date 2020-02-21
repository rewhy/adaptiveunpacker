#ifndef _BG_OAT_PLUS_H
#define	_BG_OAT_PLUS_H


#include "bg_oatdexparse.h"

/* Memory used by one classobject is decided by its
 * data members and virtual functions.
 */
// size = 12 bytes
struct StdString {
	/*0x00*/ UInt		unknown;
	/*0x04*/ UInt		len;
	/*0x08*/ HChar*	data;
};

// size = 36 bytes
struct MemMapPlus {
	/*0x00*/ struct StdString name_;
	/*0x0c*/ UChar* begin_;
	/*0x10*/ UInt	  size_;
	/*0x14*/ void*  base_begin_;
	/*0x18*/ UInt		base_size;
	/*0x1c*/ Int		prot_;
	/*0x20*/ Bool   reuse_;
};

// size = 40 bytes
struct OatDexFilePlus {
};

// size = 72 bytes
struct DexFilePlus {
#if 0 // Because they are static fields
	/*0x00*/ UChar*	kDexMagic;
	/*0x04*/ UChar*	kDexMagicVersion;
	/*0x08*/ UInt		kDexEndianConstant = 0x12345678;
	/*0x0c*/ HChar*	kClassDex;
	/*0x10*/ UInt		kDexNoIndex = 0xffffffff;
	/*0x14*/ UShort	kDexNoIndex16 = 0xffff;
	/*0x16*/ HChar	kMultiDexSeparator = ':';
#endif
	/*0x00*/ void*  close_dex_fun_;
	/*0x04*/ UChar*	begin_;
	/*0x08*/ UInt		size_;
	/*0x0c*/ struct StdString location_;
	/*0x18*/ UInt		location_checksum_;
	/*0x1c*/ struct MemMapPlus *mem_map_;
	/*0x20*/ struct DexHeader	*header_;
	/*0x24*/ struct StringId	*string_ids_;
	/*0x28*/ struct TypeId		*type_ids_;
	/*0x2c*/ struct FieldId		*field_ids_;
	/*0x30*/ struct MethodId	*method_ids_;
	/*0x34*/ struct ProtoId		*proto_ids_;
	/*0x38*/ struct ClassDef	*class_defs_;
	/*0x3b*/ UInt		find_class_def_misses_;
	/*0x40*/ void		*class_def_index_; 
	/*0x44*/ struct OatDexFilePlus *oat_dex_file_;
};
#endif
