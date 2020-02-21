#ifndef _BG_OAT_PARSE_H
#define	_BG_OAT_PARSE_H

#include "packergrind.h"
#include "pg_dexparse.h"
#include "pg_framework.h"

/* Memory used by one classobject is decided by its
 * data members and virtual functions.
 */

// size = 36 bytes
struct MemMapPlus {
	/*0x00*/ struct StdString name_;
	/*0x0c*/ UChar* begin_;
	/*0x10*/ UInt	  size_;
	/*0x14*/ void*  base_begin_;
	/*0x18*/ UInt		base_size_;
	/*0x1c*/ Int		prot_;
	/*0x20*/ Bool   reuse_;
};


/* Oat file related structres */
struct OatSec {
	UInt oatdata_offset;
	UInt oatdata_size;
	UInt oatexec_offset;
	UInt oatexec_size;
	UInt oatlastword_offset;
	UInt oatlastword_size;
};

struct OatHeader {
	UChar  magic[4];
	UChar  version[4];
	UInt  adler32Checksum;
	UInt  instructionSet;
	UInt  instructionSetFeatures;
	UInt  dexFileCount;
	UInt  executableOffset;
	UInt  interpreterToInterpreterBridgeOffset;
	UInt  interpreterToCompiledCodeBridgeOffset;
	UInt  jniDlsymLookupOffset;
	UInt  quickGenericJniTrampolineOffset;
	UInt  quickImtConflictTrampolineOffset;
	UInt  quickResolutionTrampolineOffset;
	UInt  quickToInterpreterBridgeOffset;				
	UInt  imagePatchDelta;											// The image relocated address delta
	UInt  imageFileLocationOatChecksum;					// Adler-32 checksum of boot.oat's header
	UInt  imageFileLocationOatDataBegin;				// The virtual address of boot.oat's oatdata section
	UInt  keyValueStoreSize;										// The length of key_value_store
};

enum {
	oatTypeUnknown = 0,
	oatTypeBoot = 1,
	oatTypeBase = 2
};

typedef enum {
	kOatClassAllCompiled = 0, 
	kOatClassSomeCompiled = 1,
	kOatClassNoneCompiled = 2,
	kOatClassMax = 3
} OatClassType;

typedef enum {
	kNone,
	kArm,
	kArm64,
	kThumb2,
	kX86,
	kX86_64,
	kMips,
	kMips64
} InstructionSet;

struct OatQuickMethodHeader {
	UInt mappingTableOffset;
	UInt vmapTableOffset;
	UInt gcMapOffset;
	UInt frameSizeInBytes;
	UInt coreSpillMask;
	UInt fpSpillMask;
	UInt codeSize;
};

/* TBD: CodeItem parsing refer to DumpCodeInfo in file oatdump.c */
struct CodeItem {
	UShort registersSize;
	UShort insSize;
	UShort outsSize;
	UShort triesSize;
	UInt	 debugInfoOff;
	UInt	 insnsSizeInCodeUnits;
	UShort insns[1];
};

struct OatClassOffset {
	UInt offset;
};

struct OatClassHeader {
	unsigned short status; // State of class during compilation
	unsigned short type;   // Type of class
	//	UInt	 bitmapSize;				 // Size of compiled methods bitmap (present only wehen type==1)
};

enum {
	TYPE_NONE		= 0x00,
	TYPE_SOURCE	= 0x01,
	TYPE_SINK		= 0x02
};

// According to oat_file.h
struct OatFile;

// 8 bytes
struct OatMethod {
	unsigned char*	begin_;
	unsigned int		code_offset_;
};

// 20 bytes
struct OatClass {
	struct OatFile* oat_file_;
	void*						status_;
	OatClassType		type_;
	unsigned int*		bitmap_;
	void*						methods_pointer_;
};


// 152 bytes
struct OatFile {
	// The image will embed this to link its associated oat file.
	struct StdString	location_; // 12 bytes
	
	// Pointer to OatHeader
	unsigned char*		begin_;

	// Pointer to end of oat region for bounds checking.
	unsigned char*		end_;

	// Pointer to the .bss section, if present, otherwise null.
	unsigned char*		bss_begin_;

	// Pointer to the end of the .bss section, if present, otherwise null.
	unsigned char*		bss_end_;

	// Was this oat_file loaded executable?
	Bool							is_executable_;

	// Backing memory map for oat file during when opened by ElfWriter during initial compilation.
	void*							mem_map_;

	// Backing memory map for oat file during cross compilation.
	void*							elf_file_;

	// Dlopen handle dring runtime.
	void*							dlopen_handle_;

	// Dummy memory map objects corresponding to the regions mapped by dlopen.
	struct StdVector	dlopen_mmaps_;

	// Owning storage for the OatDexFile objects.
	struct StdVector	oat_dex_files_storage_;


	// Map each location and canonical location (if different) retrieved from the oat file to its OatDexFile.
	UChar							oat_dex_files_[12];

	UChar							second_lock_[48];
	UChar							secondary_oat_dex_files_[12];
	struct StdList		string_cache;
};

// size = 40 bytes
struct OatDexFile {
	struct OatFile*		oat_file_;
	struct StdString	dex_file_location_;
	struct StdString	canonical_dex_file_location_;
	unsigned int			dex_file_location_checksum_;
	unsigned char*		dex_file_pointer_;
	unsigned int*			oat_class_offsets_pointer_;
};

/* size = 40 bytes from art_method.h */
struct ArtMethod {
	/*0x00*/	void* declaring_class_;
	/*0x04*/	void* dex_cache_resolved_methods_;
	/*0x08*/	void* dex_cache_resolved_types_;
	/*0x0c*/	UInt	access_flags_;
	/*0x10*/	UInt	dex_code_item_offset_;			/* offset to the CodeItem */
	/*0x14*/	UInt	dex_method_index_;					/* index into method_ids of the dex file */
	/*0x18*/	UInt	method_index_;							/* Entry within a dispatch table for this methods */
	struct PtrSizedFields {
		/*0x1c*/	void* entry_point_from_interpreter_;
		/*0x20*/	void* entry_point_from_jni_;
		/*0x24*/	void* entry_point_from_quick_compiled_code_;
	}ptr_sized_fields_;
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

void dumpOatMem(UChar* buf, UInt size);
Bool oatDexParse(struct DexFilePlus*, Addr, UInt, Addr, UInt);
#endif
