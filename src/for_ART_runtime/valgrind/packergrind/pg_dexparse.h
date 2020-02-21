#ifndef _PG_DEX_PARSE_H
#define _PG_DEX_PARSE_H

#include "pub_tool_basics.h"

#include "packergrind.h"
#include "pg_oatparse.h"
#include "pg_framework.h"

#ifndef INLINE
#define INLINE			inline __attribute__((always_inline))
#endif

#ifdef M_PERFORMANCE
#define	OAT_LOGD(fmt, x...) do{}while(0);
#else
#ifdef ONLY_DUMP
#define	OAT_LOGD(fmt, x...) do{}while(0);
#else
#define	OAT_LOGD(fmt, x...) VG_(printf)(fmt, ##x)
#endif
#endif // M_PERFORMANCE

#define	OAT_LOGI(fmt, x...) VG_(printf)(fmt, ##x)
//#define	OAT_LOGI(fmt, x...) do{}while(0)
#define	OAT_LOGE(fmt, x...) VG_(printf)(fmt, ##x)
/* Oat dex file related structures */
#define NO_INDEX 0xffffffff


typedef	UChar			u1;
typedef UShort		u2;
typedef UInt			u4;
typedef ULong			u8;

typedef Char			s1;
typedef Short			s2;
typedef Int				s4;
typedef Long			s8;

#define DEX_MAGIC						"dex\n"
#define DEX_MAGIC_VERS			"035\0"

#define DEX_OPT_MAGIC				"dey\n"
#define DEX_OPT_MAGIC_VERS	"036\0"

#define	DEX_DEP_MAGIC				"deps"


// #define	TRACE_DEX_FILE_DATA	0

/*
 * Single-thread single-string cache. This structure holds a pointer to
 * a string which is semi-automatically manipulated by some of the
 * method prototype functions. Functions which use in this struct
 * generally return a string that is valid until the next
 * time the same DexStringCache is used.
 */
struct DexStringCache {
	HChar* value;          /* the latest value */
	Int allocatedSize; /* size of the allocated buffer, if allocated */
	HChar buffer[120];     /* buffer used to hold small-enough results */
};  

struct DexFileInfo {
	HChar		name[255];	/* name of the dex file */
	ThreadId	tid;				/* Id of the thread which loaded this file */
	Int			fd;					/* fd of the opened file */
	Addr		begin;			/* The beginning address of mapped memory */
	UInt		len;				/* Length of the file in memory */
};

/*
 * Flag for use with createAccessFlagStr().
 */
enum AccessFor {
	kAccessForClass = 0, kAccessForMethod = 1, kAccessForField = 2,
	kAccessForMAX
};

/*
 *  * 160-bit SHA-1 digest.
 *   */
enum { kSHA1DigestLen = 20,
	kSHA1DigestOutputLen = kSHA1DigestLen*2 +1 };

/* annotation constants */
enum {
	kDexVisibilityBuild         = 0x00,     /* annotation visibility */
	kDexVisibilityRuntime       = 0x01,
	kDexVisibilitySystem        = 0x02,

	kDexAnnotationByte          = 0x00,
	kDexAnnotationShort         = 0x02,
	kDexAnnotationChar          = 0x03,
	kDexAnnotationInt           = 0x04,
	kDexAnnotationLong          = 0x06,
	kDexAnnotationFloat         = 0x10,
	kDexAnnotationDouble        = 0x11,
	kDexAnnotationString        = 0x17,
	kDexAnnotationType          = 0x18,
	kDexAnnotationField         = 0x19,
	kDexAnnotationMethod        = 0x1a,
	kDexAnnotationEnum          = 0x1b,
	kDexAnnotationArray         = 0x1c,
	kDexAnnotationAnnotation    = 0x1d,
	kDexAnnotationNull          = 0x1e,
	kDexAnnotationBoolean       = 0x1f,

	kDexAnnotationValueTypeMask = 0x1f,     /* low 5 bits */
	kDexAnnotationValueArgShift = 5,
};

/* map item type codes */
enum {
	kDexTypeHeaderItem               = 0x0000,
	kDexTypeStringIdItem             = 0x0001,
	kDexTypeTypeIdItem               = 0x0002,
	kDexTypeProtoIdItem              = 0x0003,
	kDexTypeFieldIdItem              = 0x0004,
	kDexTypeMethodIdItem             = 0x0005,
	kDexTypeClassDefItem             = 0x0006,
	kDexTypeMapList                  = 0x1000,
	kDexTypeTypeList                 = 0x1001,
	kDexTypeAnnotationSetRefList     = 0x1002,
	kDexTypeAnnotationSetItem        = 0x1003,
	kDexTypeClassDataItem            = 0x2000,
	kDexTypeCodeItem                 = 0x2001,
	kDexTypeStringDataItem           = 0x2002,
	kDexTypeDebugInfoItem            = 0x2003,
	kDexTypeAnnotationItem           = 0x2004,
	kDexTypeEncodedArrayItem         = 0x2005,
	kDexTypeAnnotationsDirectoryItem = 0x2006,
};

/* auxillary data section chunk codes */
enum {
	kDexChunkClassLookup            = 0x434c4b50,   /* CLKP */
	kDexChunkRegisterMaps           = 0x524d4150,   /* RMAP */

	kDexChunkEnd                    = 0x41454e44,   /* AEND */
};

/* debug info opcodes and constants */
enum {
	DBG_END_SEQUENCE         = 0x00,
	DBG_ADVANCE_PC           = 0x01,
	DBG_ADVANCE_LINE         = 0x02,
	DBG_START_LOCAL          = 0x03,
	DBG_START_LOCAL_EXTENDED = 0x04,
	DBG_END_LOCAL            = 0x05,
	DBG_RESTART_LOCAL        = 0x06,
	DBG_SET_PROLOGUE_END     = 0x07,
	DBG_SET_EPILOGUE_BEGIN   = 0x08,
	DBG_SET_FILE             = 0x09,
	DBG_FIRST_SPECIAL        = 0x0a,
	DBG_LINE_BASE            = -4,
	DBG_LINE_RANGE           = 15,
};

/* general constants */
enum {
	kDexEndianConstant = 0x12345678,    /* the endianness indicator */
	kDexNoIndex = 0xffffffff,           /* not a valid index value */
};

/*
 * access flags and masks; the "standard" ones are all <= 0x4000
 *
 * Note: There are related declarations in vm/oo/Object.h in the ClassFlags
 * enum.
 */
enum {
	ACC_PUBLIC       = 0x00000001,       // class, field, method, ic
	ACC_PRIVATE      = 0x00000002,       // field, method, ic
	ACC_PROTECTED    = 0x00000004,       // field, method, ic
	ACC_STATIC       = 0x00000008,       // field, method, ic
	ACC_FINAL        = 0x00000010,       // class, field, method, ic
	ACC_SYNCHRONIZED = 0x00000020,       // method (only allowed on natives)
	ACC_SUPER        = 0x00000020,       // class (not used in Dalvik)
	ACC_VOLATILE     = 0x00000040,       // field
	ACC_BRIDGE       = 0x00000040,       // method (1.5)
	ACC_TRANSIENT    = 0x00000080,       // field
	ACC_VARARGS      = 0x00000080,       // method (1.5)
	ACC_NATIVE       = 0x00000100,       // method
	ACC_INTERFACE    = 0x00000200,       // class, ic
	ACC_ABSTRACT     = 0x00000400,       // class, method, ic
	ACC_STRICT       = 0x00000800,       // method
	ACC_SYNTHETIC    = 0x00001000,       // field, method, ic
	ACC_ANNOTATION   = 0x00002000,       // class, ic (1.5)
	ACC_ENUM         = 0x00004000,       // class, field, ic (1.5)
	ACC_CONSTRUCTOR  = 0x00010000,       // method (Dalvik only)
	ACC_DECLARED_SYNCHRONIZED =
		0x00020000,       // method (Dalvik only)
	ACC_CLASS_MASK =
		(ACC_PUBLIC | ACC_FINAL | ACC_INTERFACE | ACC_ABSTRACT
		 | ACC_SYNTHETIC | ACC_ANNOTATION | ACC_ENUM),
	ACC_INNER_CLASS_MASK =
		(ACC_CLASS_MASK | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC),
	ACC_FIELD_MASK =
		(ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
		 | ACC_VOLATILE | ACC_TRANSIENT | ACC_SYNTHETIC | ACC_ENUM),
	ACC_METHOD_MASK =
		(ACC_PUBLIC | ACC_PRIVATE | ACC_PROTECTED | ACC_STATIC | ACC_FINAL
		 | ACC_SYNCHRONIZED | ACC_BRIDGE | ACC_VARARGS | ACC_NATIVE
		 | ACC_ABSTRACT | ACC_STRICT | ACC_SYNTHETIC | ACC_CONSTRUCTOR
		 | ACC_DECLARED_SYNCHRONIZED),
};


/*
 * Direct-mapped "header_item" struct.
 */
struct DexHeader { /* 112 bytes */
	/* 00 */UChar  magic[8];           /* includes version number */
	/* 08 */UInt  checksum;           /* adler32 checksum */
	/* 0c */UChar  signature[kSHA1DigestLen]; /* SHA-1 hash */
	/* 20 */UInt  fileSize;           /* length of entire file */
	/* 24 */UInt  headerSize;         /* offset to start of next section */
	/* 28 */UInt  endianTag;
	/* 2c */UInt  linkSize;
	/* 30 */UInt  linkOff;
	/* 34 */UInt  mapOff;
	/* 38 */UInt  stringIdsSize;
	/* 3c */UInt  stringIdsOff;
	/* 40 */UInt  typeIdsSize;
	/* 44 */UInt  typeIdsOff;
	/* 48 */UInt  protoIdsSize;
	/* 4c */UInt  protoIdsOff;
	/* 50 */UInt  fieldIdsSize;
	/* 54 */UInt  fieldIdsOff;
	/* 58 */UInt  methodIdsSize;
	/* 5c */UInt  methodIdsOff;
	/* 60 */UInt  classDefsSize;
	/* 64 */UInt  classDefsOff;
	/* 68 */UInt  dataSize;
	/* 6c */UInt  dataOff;
};

#if 0
struct DexHeader {
	UChar	magic[8];
	UInt  checksum;
	UChar signature[20];
	UInt  fileSize;
	UInt  headerSize;
	UInt  endianTag;
	UInt  linkSize;
	UInt  linkOff;
	UInt  mapOff;
	UInt  stringIdsSize;
	UInt  stringIdsOff;
	UInt  typeIdsSize;
	UInt  typeIdsOff;
	UInt  protoIdsSize;
	UInt  protoIdsOff;
	UInt  fieldIdsSize;
	UInt  fieldIdsOff;
	UInt  methodIdsSize;
	UInt  methodIdsOff;
	UInt  classDefsSize;
	UInt  classDefsOff;
	UInt  dataSize;
	UInt  dataOff;
};
#endif


/*
 * Direct-mapped "map_item".
 */
struct DexMapItem {
	UShort type;              /* type code (see kDexType* above) */
	UShort unused;
	UInt	 size;              /* count of items of the indicated type */
	UInt	 offset;            /* file offset to the start of data */
};

/*
 * Direct-mapped "map_list".
 */
struct DexMapList {
	UInt  size;			               /* #of entries in list */
	struct DexMapItem list[1];     /* entries */
};

/*
 * Direct-mapped "class_def_item".
 */
// 32bytes
struct DexClassDef {
	/*0x00*/ UInt  classIdx;           /* index into typeIds for this class */
	/*0x04*/ UInt  accessFlags;
	/*0x08*/ UInt  superclassIdx;      /* index into typeIds for superclass */
	/*0x0c*/ UInt  interfacesOff;      /* file offset to DexTypeList */
	/*0x10*/ UInt  sourceFileIdx;      /* index into stringIds for source file name */
	/*0x14*/ UInt  annotationsOff;     /* file offset to annotations_directory_item */
	/*0x18*/ UInt  classDataOff;       /* file offset to class_data_item */
	/*0x1c*/ UInt  staticValuesOff;    /* file offset to DexEncodedArray */
};

#if 0
struct DexClassDef {
	UInt  classIdx;
	UInt  accessFlags;
	UInt  superClassIdx;
	UInt  interfaceOff;
	UInt  sourceFileIdx;
	UInt  annotationsOff;
	UInt  classDataOff;
	UInt  staticValuesOff;
};
#endif

struct DexMethodId {
	UShort  classIdx;
	UShort  protoIdx;
	UInt		nameIdx;
};

/*
 * Direct-mapped "proto_id_item".
 */
struct DexProtoId {
	UInt  shortyIdx;          /* index into stringIds for shorty descriptor */
	UInt  returnTypeIdx;      /* index into typeIds list for return type */
	UInt  parametersOff;      /* file offset to type_list for parameter types */
};

struct DexFieldId {
	UShort classIdx;
	UShort typeIdx;
	UInt   nameIdx;
};

struct DexStringId {
	UInt stringDataOff;
};

struct DexTypeId {
	UInt descriptorIdx;
};

struct DexTypeItem {
	UShort typeIdx;				// index into type_ids section
};

struct DexTypeList {
	UInt size;						// size of the list, in entries
	struct DexTypeItem list[1];	// elements of the list
};

/*
 * Direct-mapped "code_item".
 *
 * The "catches" table is used when throwing an exception,
 * "debugInfo" is used when displaying an exception stack trace or
 * debugging. An offset of zero indicates that there are no entries.
 */
struct DexCode {
	UShort  registersSize;
	UShort  insSize;
	UShort  outsSize;
	UShort  triesSize;
	UInt	  debugInfoOff;       /* file offset to debug info stream */
	UInt	  insnsSize;          /* size of the insns array, in u2 units */
	UShort  insns[1];
	/* followed by optional u2 padding */
	/* followed by try_item[triesSize] */
	/* followed by uleb128 handlersSize */
	/* followed by catch_handler_item[handlersSize] */
};

/*
 * Direct-mapped "try_item".
 */
struct DexTry {
	UInt	  startAddr;          /* start address, in 16-bit code units */
	UShort  insnCount;          /* instruction count, in 16-bit code units */
	UShort  handlerOff;         /* offset in encoded handler data to handlers */
};

/*
 * Link table.  Currently undefined.
 */
struct DexLink {
	UChar  bleargh;
};


/*
 * Direct-mapped "annotations_directory_item".
 */
struct DexAnnotationsDirectoryItem {
	UInt  classAnnotationsOff;  /* offset to DexAnnotationSetItem */
	UInt  fieldsSize;           /* count of DexFieldAnnotationsItem */
	UInt  methodsSize;          /* count of DexMethodAnnotationsItem */
	UInt  parametersSize;       /* count of DexParameterAnnotationsItem */
	/* followed by DexFieldAnnotationsItem[fieldsSize] */
	/* followed by DexMethodAnnotationsItem[methodsSize] */
	/* followed by DexParameterAnnotationsItem[parametersSize] */
};

/*
 * Direct-mapped "field_annotations_item".
 */
struct DexFieldAnnotationsItem {
	UInt  fieldIdx;
	UInt  annotationsOff;             /* offset to DexAnnotationSetItem */
};

/*
 * Direct-mapped "method_annotations_item".
 */
struct DexMethodAnnotationsItem {
	UInt  methodIdx;
	UInt  annotationsOff;             /* offset to DexAnnotationSetItem */
};

/*
 * Direct-mapped "parameter_annotations_item".
 */
struct DexParameterAnnotationsItem {
	UInt  methodIdx;
	UInt  annotationsOff;             /* offset to DexAnotationSetRefList */
};

/*
 * Direct-mapped "annotation_set_ref_item".
 */
struct DexAnnotationSetRefItem {
	UInt  annotationsOff;             /* offset to DexAnnotationSetItem */
};

/*
 * Direct-mapped "annotation_set_ref_list".
 */
struct DexAnnotationSetRefList {
	UInt  size;
	struct DexAnnotationSetRefItem list[1];
};

/*
 * Direct-mapped "annotation_set_item".
 */
struct DexAnnotationSetItem {
	UInt  size;
	UInt  entries[1];                 /* offset to DexAnnotationItem */
};

/*
 * Direct-mapped "annotation_item".
 *
 * NOTE: this structure is byte-aligned.
 */
struct DexAnnotationItem {
	UChar  visibility;
	UChar  annotation[1];              /* data in encoded_annotation format */
};

/*
 * Direct-mapped "encoded_array".
 *
 * NOTE: this structure is byte-aligned.
 */
struct DexEncodedArray {
	UChar  array[1];                   /* data in encoded_array format */
};


/*
 * Lookup table for classes.  It provides a mapping from class name to
 * class definition.  Used by dexFindClass().
 *
 * We calculate this at DEX optimization time and embed it in the file so we
 * don't need the same hash table in every VM.  This is slightly slower than
 * a hash table with direct pointers to the items, but because it's shared
 * there's less of a penalty for using a fairly sparse table.
 */
struct DexClassLookup {
	Int     size;                       // total size, including "size"
	Int     numEntries;                 // size of table[]; always power of 2
	struct {
		UInt  classDescriptorHash;    // class descriptor hash code
		Int   classDescriptorOffset;  // in bytes, from start of DEX
		Int		classDefOffset;         // in bytes, from start of DEX
	} table[1];
};


/*
*/
#define	DEXHEAD						0x1
#define	DEXOPTDATA				0x2
#define DEXCLASS					0x4
#define	DEXMETHOD					0x8

struct MonitorDexFile {
	struct DexFile* pDexFile;
	struct DexFile* pDexFileClone;
	Addr						cloneMem;
	Addr						baseAddr;
	Addr						endAddr;
	Addr						lastAddr;
	UInt						cloneLen;
	UInt						offset;
	UInt						state;
	struct DexFileList* next;
};

/*
 * Header added by DEX optimization pass.  Values are always written in
 * local byte and structure padding.  The first field (magic + version)
 * is guaranteed to be present and directly readable for all expected
 * compiler configurations; the rest is version-dependent.
 *
 * Try to keep this simple and fixed-size.
 */
struct DexOptHeader {
	UChar  magic[8];           /* includes version number */

	UInt  dexOffset;          /* file offset of DEX header */
	UInt  dexLength;
	UInt  depsOffset;         /* offset of optimized DEX dependency table */
	UInt  depsLength;
	UInt  optOffset;          /* file offset of optimized data tables */
	UInt  optLength;

	UInt  flags;              /* some info flags */
	UInt  checksum;           /* adler32 checksum covering deps/opt */

	/* pad for 64-bit alignment if necessary */
};

/* Dex class related structures */

/* expanded form of a class_data_item header */
struct DexClassDataHeader {
	UInt staticFieldsSize;
	UInt instanceFieldsSize;
	UInt directMethodsSize;
	UInt virtualMethodsSize;
};

/* expanded form of encoded_field */
struct DexField {
	UInt fieldIdx;    /* index to a field_id_item */
	UInt accessFlags;
};  


/* expanded form of encoded_method */
struct DexMethod {
	UInt methodIdx;    /* index to a method_id_item */
	UInt accessFlags;
	UInt codeOff;      /* file offset to a code_item */
};  

/* expanded form of class_data_item. Note: If a particular item is
 * absent (e.g., no static fields), then the corresponding pointer
 * is set to NULL. */
struct DexClassData {
	struct DexClassDataHeader header;
	struct DexField*          staticFields;
	struct DexField*          instanceFields;
	struct DexMethod*         directMethods;
	struct DexMethod*         virtualMethods;
}; 

/*
 * Structure representing a DEX file.
 *
 * Code should regard DexFile as opaque, using the API calls provided here
 * to access specific structures.
 */
struct DexFile { // 52 bytes
	/* directly-mapped "opt" header */
	const struct DexOptHeader* pOptHeader;

	/* pointers to directly-mapped structs and arrays in base DEX */
	const struct DexHeader*			  pHeader;
	const struct DexStringId*			pStringIds;
	const struct DexTypeId*				pTypeIds;
	const struct DexFieldId*			pFieldIds;
	const struct DexMethodId*			pMethodIds;
	const struct DexProtoId*			pProtoIds;
	const struct DexClassDef*			pClassDefs;
	const struct DexLink*					pLinkData;

	/*
	 * These are mapped out of the "auxillary" section, and may not be
	 * included in the file.
	 */
	const struct DexClassLookup* pClassLookup;
	Addr         pRegisterMapPool;       // RegisterMapClassPool

	/* points to start of DEX file data */
	const UChar*       baseAddr;

	/* track memory overhead for auxillary structures */
	UInt               overhead;

	/* additional app-specific data structures associated with the DEX */
	//void*               auxData;
};

#if 0
struct DexProtoId {
	/* index into the stringID list of the short-form descriptor of this
	 * prototype. The string must comform to the syntax for ShortyDescriptor,
	 * defined above. and much correspond to the return type and paramethers 
	 * of this item.
	 */
	UInt shortyId; // index into string_ids array for shorty descriptor
	/* index info the TypeIds list for the return type of this descriptor
	*/
	UShort returnTypeId; // index into type_ids array for return type
	UShort pad_; // padding = 0
	/* offset from the start of the file to the list of parameter types of this prototype.
	 * or 0 if this prototype has no parameters. This offset, if non-zero, should be in 
	 * the data section, and the data threre thould be in the format specified by "type list" below.
	 * Additionally, there should be no reference to the type void in the list;
	 */
	UInt parametersOff; // file offset to type_list for parameter types
};
#endif


UInt uleb128_value(UChar* pStream);

UInt len_uleb128(unsigned long n);

void getUnsignedLebValue(UChar* dex, UChar* stringData, UInt offset);

UInt getTypeDescForClass(UChar* dex, struct DexStringId* strIdList,
		struct DexTypeId* typeIdList, struct DexClassDef* classDefItem,
		UChar* stringData);

void getTypeDesc(UChar* dex, struct DexStringId *strIdList,
		struct DexTypeId* typeIdList, UInt offset_poInter,
		UChar* stringData);

void getProtoDesc(UChar* dex, struct DexStringId *strIdList,
		struct DexTypeId* typeIdList,
		struct DexProtoId* protoIdList, UInt offset_poInter,
		UChar* returnType, UChar* shorty, UChar* params);

void getClassFileName(UChar* dex, struct DexStringId *strIdList,
		struct DexClassDef *classDefItem, UChar *stringData);

UChar* parseAccessFlags(UInt flags);

void getStringValue(UChar* dex, struct DexStringId *strIdList,
		UInt offset_poInter,UChar* stringData);

/* return the DexMapList of the file, if any */
INLINE const struct DexMapList* dexGetMap(const struct DexFile* pDexFile) {
	Int mapOff = pDexFile->pHeader->mapOff;
	if (mapOff == 0) {
		return NULL;
	} else {
		return (const struct DexMapList*) (pDexFile->baseAddr + mapOff);
	}
}

/* return the const char* string data referred to by the given string_id */
INLINE const HChar* dexGetStringData(const struct DexFile* pDexFile,
		const struct DexStringId* pStringId) {
	const UChar* ptr = pDexFile->baseAddr + pStringId->stringDataOff;

	/* Skip the uleb128 length. */
	while (*(ptr++) > 0x7f) /* empty */ ;
	return (const Char*) ptr;
}

/* return the StringId with the specified index */
INLINE const struct DexStringId* dexGetStringId(const struct DexFile* pDexFile, UInt idx) {
	tl_assert(idx < pDexFile->pHeader->stringIdsSize);
	return &pDexFile->pStringIds[idx];
}

/* return the UTF-8 encoded string with the specified string_id index */
INLINE const HChar* dexStringById(const struct DexFile* pDexFile, UInt idx) {
	const struct DexStringId* pStringId = dexGetStringId(pDexFile, idx);
	return dexGetStringData(pDexFile, pStringId);
}

/* Return the UTF-8 encoded string with the specified string_id index,
 * also filling in the UTF-16 size (number of 16-bit code points).
 */
const HChar* dexStringAndSizeById(const struct DexFile* pDexFile, UInt idx,
		UInt* utf16Size);

/* return the TypeId with the specified index */
INLINE const struct DexTypeId* dexGetTypeId(const struct DexFile* pDexFile, UInt idx) {
	tl_assert(idx < pDexFile->pHeader->typeIdsSize);
	return &pDexFile->pTypeIds[idx];
}

/*
 * Get the descriptor string associated with a given type index.
 * The caller should not free() the returned string.
 */
INLINE const char* dexStringByTypeIdx(const struct DexFile* pDexFile, UInt idx) {
	const struct DexTypeId* typeId = dexGetTypeId(pDexFile, idx);
	return dexStringById(pDexFile, typeId->descriptorIdx);
}

/* return the DexMethodId with the specified index */
INLINE const struct DexMethodId* dexGetMethodId(const struct DexFile* pDexFile, UInt idx) {
	// tl_assert(idx < pDexFile->pHeader->methodIdsSize);
	if (idx < pDexFile->pHeader->methodIdsSize) {
		return NULL;
	}
	return &pDexFile->pMethodIds[idx];
}

/* return the FieldId with the specified index */
INLINE const struct DexFieldId* dexGetFieldId(const struct DexFile* pDexFile, UInt idx) {
	tl_assert(idx < pDexFile->pHeader->fieldIdsSize);
	return &pDexFile->pFieldIds[idx];
}
/* return the ProtoId with the specified index */
INLINE const struct DexProtoId* dexGetProtoId(const struct DexFile* pDexFile, UInt idx) {
	tl_assert(idx < pDexFile->pHeader->protoIdsSize);
	return &pDexFile->pProtoIds[idx];
}

/*
 * Get the parameter list from a ProtoId. The returns NULL if the ProtoId
 * does not have a parameter list.
 */
INLINE const struct DexTypeList* dexGetProtoParameters(
		const struct DexFile *pDexFile, const struct DexProtoId* pProtoId) {
	if (pProtoId->parametersOff == 0) {
		return NULL;
	}
	return (const struct DexTypeList*)(pDexFile->baseAddr + pProtoId->parametersOff);
}

/* return the ClassDef with the specified index */
INLINE const struct DexClassDef* dexGetClassDef(const struct DexFile* pDexFile, UInt idx) {
	tl_assert(idx < pDexFile->pHeader->classDefsSize);
	return &pDexFile->pClassDefs[idx];
}

/* given a ClassDef pointer, recover its index */
INLINE UInt dexGetIndexForClassDef(const struct DexFile* pDexFile,
		const struct DexClassDef* pClassDef)
{
	tl_assert(pClassDef >= pDexFile->pClassDefs &&
			pClassDef < pDexFile->pClassDefs + pDexFile->pHeader->classDefsSize);
	return pClassDef - pDexFile->pClassDefs;
}

/* get the interface list for a DexClass */
INLINE const struct DexTypeList* dexGetInterfacesList(const struct DexFile* pDexFile,
		const struct DexClassDef* pClassDef)
{
	if (pClassDef->interfacesOff == 0)
		return NULL;
	return (const struct DexTypeList*)
		(pDexFile->baseAddr + pClassDef->interfacesOff);
}

/* return the Nth entry in a DexTypeList. */
INLINE const struct DexTypeItem* dexGetTypeItem(const struct DexTypeList* pList,
		UInt idx)
{
	tl_assert(idx < pList->size);
	return &pList->list[idx];
}
/* return the type_idx for the Nth entry in a TypeList */
INLINE UInt dexTypeListGetIdx(const struct DexTypeList* pList, UInt idx) {
	const struct DexTypeItem* pItem = dexGetTypeItem(pList, idx);
	return pItem->typeIdx;
}


INLINE const struct DexEncodedArray* dexGetStaticValuesList(
		const struct DexFile* pDexFile, const struct DexClassDef* pClassDef)
{
	if (pClassDef->staticValuesOff == 0)
		return NULL;
	return (const struct DexEncodedArray*)
		(pDexFile->baseAddr + pClassDef->staticValuesOff);
}

/* get the annotations directory item for a DexClass */
INLINE const struct DexAnnotationsDirectoryItem* dexGetAnnotationsDirectoryItem(
		const struct DexFile* pDexFile, const struct DexClassDef* pClassDef)
{
	if (pClassDef->annotationsOff == 0)
		return NULL;
	return (const struct DexAnnotationsDirectoryItem*)
		(pDexFile->baseAddr + pClassDef->annotationsOff);
}

/* get the source file string */
INLINE const UChar* dexGetSourceFile(
		const struct DexFile* pDexFile, const struct DexClassDef* pClassDef)
{
	if (pClassDef->sourceFileIdx == 0xffffffff)
		return NULL;
	return dexStringById(pDexFile, pClassDef->sourceFileIdx);
}

/* get the size, in bytes, of a DexCode */
UInt dexGetDexCodeSize(const struct DexCode* pCode);

/* Get the list of "tries" for the given DexCode. */
INLINE const struct DexTry* dexGetTries(const struct DexCode* pCode) {
	const UShort* insnsEnd = &pCode->insns[pCode->insnsSize];
	/* Round to four bytes. */
	if ((((UInt) insnsEnd) & 3) != 0) {
		insnsEnd++;
	}
	return (const struct DexTry*) insnsEnd;
}

/* Get the base of the encoded data for the given DexCode. */
INLINE const UChar* dexGetCatchHandlerData(const struct DexCode* pCode) {
	const struct DexTry* pTries = dexGetTries(pCode);
	return (const UChar*) &pTries[pCode->triesSize];
}

/* get a pointer to the start of the debugging data */
INLINE const UChar* dexGetDebugInfoStream(const struct DexFile* pDexFile,
		const struct DexCode* pCode)
{
	if (pCode->debugInfoOff == 0) {
		return NULL;
	} else {
		return pDexFile->baseAddr + pCode->debugInfoOff;
	}
}

/* DexClassDef convenience - get class descriptor */
INLINE const UChar* dexGetClassDescriptor(const struct DexFile* pDexFile,
		const struct DexClassDef* pClassDef)
{
	return dexStringByTypeIdx(pDexFile, pClassDef->classIdx);
}

/* DexClassDef convenience - get superclass descriptor */
INLINE const UChar* dexGetSuperClassDescriptor(const struct DexFile* pDexFile,
		const struct DexClassDef* pClassDef)
{
	if (pClassDef->superclassIdx == 0)
		return NULL;
	return dexStringByTypeIdx(pDexFile, pClassDef->superclassIdx);
}

/* DexClassDef convenience - get class_data_item pointer */
INLINE const UChar* dexGetClassData(const struct DexFile* pDexFile,
		const struct DexClassDef* pClassDef)
{
	if (pClassDef->classDataOff == 0)
		return NULL;
	return (const UChar*) (pDexFile->baseAddr + pClassDef->classDataOff);
}

/* return the Nth annotation offset from a DexAnnotationSetItem */
INLINE UInt dexGetAnnotationOff(
		const struct DexAnnotationSetItem* pAnnoSet, UInt idx)
{
	tl_assert(idx < pAnnoSet->size);
	return pAnnoSet->entries[idx];
}

/* Get an annotation set at a particular offset. */
INLINE const struct DexAnnotationItem* dexGetAnnotationItem(
		const struct DexFile* pDexFile, const struct DexAnnotationSetItem* pAnnoSet, UInt idx)
{
	UInt offset = dexGetAnnotationOff(pAnnoSet, idx);
	if (offset == 0) {
		return NULL;
	}
	return (const struct DexAnnotationItem*) (pDexFile->baseAddr + offset);
}

/* get the class' annotation set */
INLINE const struct DexAnnotationSetItem* dexGetClassAnnotationSet(
		const struct DexFile* pDexFile, const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	return dexGetAnnotationSetItem(pDexFile, pAnnoDir->classAnnotationsOff);
}

/* get the class' field annotation list */
INLINE const struct DexFieldAnnotationsItem* dexGetFieldAnnotations(
		const struct DexFile* pDexFile, const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	if (pAnnoDir->fieldsSize == 0)
		return NULL;

	/* Skip past the header to the start of the field annotations. */
	return (const struct DexFieldAnnotationsItem*) &pAnnoDir[1];
}

/* get field annotation list size */
INLINE Int dexGetFieldAnnotationsSize(const struct DexFile* pDexFile,
		const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	return pAnnoDir->fieldsSize;
}

/* return a pointer to the field's annotation set */
INLINE const struct DexAnnotationSetItem* dexGetFieldAnnotationSetItem(
		const struct DexFile* pDexFile, const struct DexFieldAnnotationsItem* pItem)
{
	return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

/* get the class' method annotation list */
INLINE const struct DexMethodAnnotationsItem* dexGetMethodAnnotations(
		const struct DexFile* pDexFile, const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	if (pAnnoDir->methodsSize == 0)
		return NULL;
	/*
	 * Skip past the header and field annotations to the start of the
	 * method annotations.
	 */
	const UChar* addr = (const UChar*) &pAnnoDir[1];
	addr += pAnnoDir->fieldsSize * sizeof (struct DexFieldAnnotationsItem);
	return (const struct DexMethodAnnotationsItem*) addr;
}

/* get method annotation list size */
INLINE Int dexGetMethodAnnotationsSize(const struct DexFile* pDexFile,
		const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	return pAnnoDir->methodsSize;
}

/* return a pointer to the method's annotation set */
INLINE const struct DexAnnotationSetItem* dexGetMethodAnnotationSetItem(
		const struct DexFile* pDexFile, const struct DexMethodAnnotationsItem* pItem)
{
	return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

/* get the class' parameter annotation list */
INLINE const struct DexParameterAnnotationsItem* dexGetParameterAnnotations(
		const struct DexFile* pDexFile, const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	if (pAnnoDir->parametersSize == 0)
		return NULL;
	/*
	 * Skip past the header, field annotations, and method annotations
	 * to the start of the parameter annotations.
	 */
	const UChar* addr = (const UChar*) &pAnnoDir[1];
	addr += pAnnoDir->fieldsSize * sizeof (struct DexFieldAnnotationsItem);
	addr += pAnnoDir->methodsSize * sizeof (struct DexMethodAnnotationsItem);
	return (const struct DexParameterAnnotationsItem*) addr;
}

/* get method annotation list size */
INLINE Int dexGetParameterAnnotationsSize(const struct DexFile* pDexFile,
		const struct DexAnnotationsDirectoryItem* pAnnoDir)
{
	(void) pDexFile;
	return pAnnoDir->parametersSize;
}

/* return the parameter annotation ref list */
INLINE const struct DexAnnotationSetRefList* dexGetParameterAnnotationSetRefList(
		const struct DexFile* pDexFile, const struct DexParameterAnnotationsItem* pItem)
{
	if (pItem->annotationsOff == 0) {
		return NULL;
	}
	return (const struct DexAnnotationSetRefList*) (pDexFile->baseAddr + pItem->annotationsOff);
}

/* get method annotation list size */
INLINE Int dexGetParameterAnnotationSetRefSize(const struct DexFile* pDexFile,
		const struct DexParameterAnnotationsItem* pItem)
{
	if (pItem->annotationsOff == 0) {
		return 0;
	}
	return dexGetParameterAnnotationSetRefList(pDexFile, pItem)->size;
}

/* return the Nth entry from an annotation set ref list */
INLINE const struct DexAnnotationSetRefItem* dexGetParameterAnnotationSetRef(
		const struct DexAnnotationSetRefList* pList, UInt idx)
{
	tl_assert(idx < pList->size);
	return &pList->list[idx];
}

/* given a DexAnnotationSetRefItem, return the DexAnnotationSetItem */
INLINE const struct DexAnnotationSetItem* dexGetSetRefItemItem(
		const struct DexFile* pDexFile, const struct DexAnnotationSetRefItem* pItem)
{
	return dexGetAnnotationSetItem(pDexFile, pItem->annotationsOff);
}

UInt getCodeOffset(UShort type, UChar* bitmap, UInt* offsets, UInt mid, UInt *nid);


void dexHeaderParse( struct DexHeader* dh); 
void processDexFile(struct DexFile* pDexFile);
void dumpDexFile(UChar* addr, Int len);
void dumpDexMem(UChar* buf, UInt size);
void copyFile(Char* from, Char* dest);
void DexMemParse(UChar* addr, Int len);


/*-------------------  for dvm related wrappers -------------------------------------*/
#define CLASS_FIELD_SLOTS   4

#define	ACC_NATIVE		0X0100


/*
 * Internal struct for managing DexFile.
 */
struct DexOrJar {
	char*       fileName;
	Bool        isDex;
	Bool        okayToFree;
	//RawDexFile* pRawDexFile;
	void*			  pRawDexFile;
	//JarFile*    pJarFile;
	void*			  pJarFile;
	u1*         pDexMemory; // malloc()ed memory, if any
};

struct Object;
struct Method;
struct ClassObject;

/* From RegisterMap.h */
struct RegisterMap {
	/* header */
	u1      format;         /* enum RegisterMapFormat; MUST be first entry */
	u1      regWidth;       /* bytes per register line, 1+ */
	u1      numEntries[2];  /* number of entries */

	/* raw data starts here; need not be aligned */
	u1      data[1];
};  

/* From Common.h */
union JValue {
#if defined(HAVE_LITTLE_ENDIAN)
	u1      z;
	s1      b;
	u2      c;
	s2      s;
	s4      i;
	s8      j;
	Float   f;
	Double  d;
	struct Object* l;
#endif
#if defined(HAVE_BIG_ENDIAN)
	struct {
		u1    _z[3];
		u1    z;
	};
	struct {
		s1    _b[3];
		s1    b;
	};
	struct {
		u2    _c;
		u2    c;
	};
	struct {
		s2    _s;
		s2    s;
	};
	s4      i;
	s8      j;
	float   f;
	double  d;
	void*   l;
#endif
};

/*  
 * Enumeration of all the primitive types.
 */ 
enum PrimitiveType {
	PRIM_NOT        = 0,       /* value is a reference type, not a primitive type */
	PRIM_VOID       = 1,
	PRIM_BOOLEAN    = 2,
	PRIM_BYTE       = 3,
	PRIM_SHORT      = 4,
	PRIM_CHAR       = 5,
	PRIM_INT        = 6,
	PRIM_LONG       = 7,
	PRIM_FLOAT      = 8,
	PRIM_DOUBLE     = 9,
}; 

/* current state of the class, increasing as we progress */
enum ClassStatus {
	CLASS_ERROR         = -1,

	CLASS_NOTREADY      = 0,
	CLASS_IDX           = 1,    /* loaded, DEX idx in super or ifaces */
	CLASS_LOADED        = 2,    /* DEX idx values resolved */
	CLASS_RESOLVED      = 3,    /* part of linking */
	CLASS_VERIFYING     = 4,    /* in the process of being verified */
	CLASS_VERIFIED      = 5,    /* logically part of linking; done pre-init */
	CLASS_INITIALIZING  = 6,    /* class init in progress */
	CLASS_INITIALIZED   = 7,    /* ready to go */
};

struct Object {
	void* clazz;
	UInt  lock;
};

struct InitiatingLoaderList {
	/* a list of initiating loader Objects; grown and initialized on demand */
	struct Object**  initiatingLoaders;
	/* count of loaders in the above list */
	Int						  initiatingLoaderCount;
};

struct InterfaceEntry {
	struct ClassObject*    clazz;
	Int*            methodIndexArray;
};

struct Field {
	// ClassObject*    clazz;          /* class in which the field is declared */
	void*		  				clazz;
	const HChar*     name;
	const HChar*     signature;      /* e.g. "I", "[C", "Landroid/os/Debug;" */
	UInt             accessFlags;
};

struct StaticField{
	struct Field				field;
	union JValue        value;          /* initially set from DEX for primitives */
};

struct InstField {
	struct Field		field;
	Int             byteOffset;
};

/*
 * Method prototype structure, which refers to a protoIdx in a
 * particular DexFile.
 */
struct DexProto {
	const struct DexFile* dexFile;     /* file the idx refers to */
	UInt  protoIdx;                /* index into proto_ids table of dexFile */
};

struct ClassObject{
	struct Object			object;
	UInt							instanceData[CLASS_FIELD_SLOTS];
	const HChar*			descriptor;
	HChar*						descriptorAlloc;
	UInt              accessFlags;

	UInt              serialNumber;

	struct DvmDex*		pDvmDex;

	enum ClassStatus  status;
	struct ClassObject*    verifyErrorClass;

	UInt              initThreadId;
	Int							objectSize;
	struct ClassObject*    elementClass;
	Int								arrayDim;
	enum PrimitiveType	   primitiveType;
	struct ClassObject*    super;
	struct Object*         classLoader;
	struct InitiatingLoaderList initiatingLoaderList;
	Int								interfaceCount;
	struct ClassObject**   interfaces;
	Int								directMethodCount;
	struct Method*    directMethods;
	Int								virtualMethodCount;
	struct Method*    virtualMethods;
	Int								vtableCount;
	struct Method**		vtable;
	Int								iftableCount;
	struct InterfaceEntry*		iftable;
	Int								ifviPoolCount;
	Int*							ifviPool;
	Int								ifieldCount;
	Int								ifieldRefCount; // number of fields that are object refs
	struct InstField* ifields;
	UInt							refOffsets;
	const HChar*	    sourceFile;
	Int				        sfieldCount;
	struct StaticField sfields[0]; /* MUST be last item */
};

struct Method {
	struct ClassObject*			clazz;

	/* access flags; low 16 bits are defined by spec (could be u2?) */
	u4		          accessFlags;
	u2			        methodIndex;

	u2              registersSize;  /* ins + locals */
	u2              outsSize;
	u2              insSize;
	const char*     name;
	struct DexProto prototype;
	const char*     shorty;
	const u2*       insns;          /* instructions, in memory-mapped .dex */
	int             jniArgInfo;
	//DalvikBridgeFunc nativeFunc;
	void*						nativeFunc; /* Function point */
	Bool fastJni;
	Bool noRef;
	Bool shouldTrace;
	const struct RegisterMap* registerMap;
	Bool            inProfile;
};


/*  
 * Use this to keep track of mapped segments.
 */ 
struct MemMapping {
	void*   addr;           /* start of data */
	Int  length;         /* length of data */

	void*   baseAddr;       /* page-aligned base address */
	Int  baseLength;     /* length of mapping */
};


/*
 * Some additional VM data structures that are associated with the DEX file.
 */
struct DvmDex {
	/* pointer to the DexFile we're associated with */
	struct DexFile*     pDexFile;

	/* clone of pDexFile->pHeader (it's used frequently enough) */
	const  struct DexHeader*    pHeader;
	/* interned strings; parallel to "stringIds" */
	//struct StringObject** pResStrings;
	void** pResStrings;

	/* resolved classes; parallel to "typeIds" */
	struct ClassObject** pResClasses;

	/* resolved methods; parallel to "methodIds" */
	struct Method**     pResMethods;

	/* resolved instance fields; parallel to "fieldIds" */
	/* (this holds both InstField and StaticField) */
	struct Field**      pResFields;

	/* interface method lookup cache */
	//struct AtomicCache* pInterfaceCache;
	void* pInterfaceCache;

	/* shared memory region with file contents */
	Bool                isMappedReadOnly;
	struct MemMapping   memMap;

	//jobject dex_object; 
	void*								dex_object; // jobject is type _jobject* in native layer
	/* lock ensuring mutual exclusion during updates */
	//pthread_mutex_t     modLock;
	//typedef struct pthread_mutex_t_ * pthread_mutex_t; in pthread.h
	void*								pthread_mutex_t;
}; 
/*---------------------------- End --------------------------------------------------*/
/*---------------------------- For intetpreting -------------------------------------*/
#define WITH_JIT	True
#define MAX_SPILL_JIT_IA 10
/*
 * Interpreter control struction.  Packed into a long long to enable
 * atomic updates. 
 */
union InterpBreak {
	volatile Long   all;
	struct {
		UChar		   subMode;
		UChar			 breakFlags;
		UChar			 unused;   /* for future expansion */
#ifndef DVM_NO_ASM_INTERP
		void*			 curHandlerTable;
#else
		UInt		   unused1;
#endif
	} ctl;
};


struct InterpSaveState {
	const UShort*					  pc;         // Dalvik PC
	UInt*										curFrame;   // Dalvik frame pointer
	const  struct Method*		method;    // Method being executed
	struct  DvmDex*         methodClassDex;
	union JValue						retval;
	void*										bailPtr;
	int											unused;        // Keep struct size constant
	struct InterpSaveState* prev;  // To follow nested activations

};

struct Thread {
	struct InterpSaveState	interpSave;
	UInt threadId;
	union InterpBreak interpBreak;
	int suspendCount;
	int dbgSuspendCount;

	UChar*         cardTable;

	/* current limit of stack; flexes for StackOverflowError */
	const UChar*   interpStackEnd;

	/* FP of bottom-most (currently executing) stack frame on interp stack */
	void*       XcurFrame;
	/* current exception, or NULL if nothing pending */
	//Object*     exception;
	void*			  exception;

	Bool        debugIsMethodEntry;
	/* interpreter stack size; our stacks are fixed-length */
	int         interpStackSize;
	Bool        stackOverflowed;
#if 0 // just use adoving fields
	/* thread handle, as reported by pthread_self() */
	pthread_t   handle;
	/* Assembly interpreter handler tables */
#ifndef DVM_NO_ASM_INTERP
	void*       mainHandlerTable;   // Table of actual instruction handler
	void*       altHandlerTable;    // Table of breakout handlers
#else
	void*       unused0;            // Consume space to keep offsets
	void*       unused1;            //   the same between builds with
#endif
	int         singleStepCount;

#ifdef WITH_JIT
	struct JitToInterpEntries jitToInterpEntries;
	/*
	 *      * Whether the current top VM frame is in the interpreter or JIT cache:
	 *           *   NULL    : in the interpreter
	 *                *   non-NULL: entry address of the JIT'ed code (the actual value doesn't
	 *                     *             matter)
	 *                          */
	void*             inJitCodeCache;
	unsigned char*    pJitProfTable;
	int               jitThreshold;
	const void*       jitResumeNPC;     // Translation return point
	const u4*         jitResumeNSP;     // Native SP at return point
	const u2*         jitResumeDPC;     // Dalvik inst following single-step
	JitState    jitState;
	int         icRechainCount;
	const void* pProfileCountdown;
	const ClassObject* callsiteClass;
	const Method*     methodToCall;
#endif

	/* JNI local reference tracking */
	IndirectRefTable jniLocalRefTable;

#if defined(WITH_JIT)
#if defined(WITH_SELF_VERIFICATION)
	/* Buffer for register state during self verification */
	struct ShadowSpace* shadowSpace;
#endif
	int         currTraceRun;
	int         totalTraceLen;  // Number of Dalvik insts in trace
	const u2*   currTraceHead;  // Start of the trace we're building
	const u2*   currRunHead;    // Start of run we're building
	int         currRunLen;     // Length of run in 16-bit words
	const u2*   lastPC;         // Stage the PC for the threaded interpreter
	const Method*  traceMethod; // Starting method of current trace
	intptr_t    threshFilter[JIT_TRACE_THRESH_FILTER_SIZE];
	JitTraceRun trace[MAX_JIT_RUN_LEN];
#endif

	/*
	 *      * Thread's current status.  Can only be changed by the thread itself
	 *           * (i.e. don't mess with this from other threads).
	 *                */
	volatile ThreadStatus status;

	/* thread ID, only useful under Linux */
	pid_t       systemTid;

	/* start (high addr) of interp stack (subtract size to get malloc addr) */
	u1*         interpStackStart;

	/* the java/lang/Thread that we are associated with */
	Object*     threadObj;

	/* the JNIEnv pointer associated with this thread */
	JNIEnv*     jniEnv;

	/* internal reference tracking */
	ReferenceTable  internalLocalRefTable;


	/* JNI native monitor reference tracking (initialized on first use) */
	ReferenceTable  jniMonitorRefTable;

	/* hack to make JNI_OnLoad work right */
	Object*     classLoaderOverride;

	/* mutex to guard the interrupted and the waitMonitor members */
	//pthread_mutex_t    waitMutex;
	void*    waitMutex;

	/* pointer to the monitor lock we're currently waiting on */
	/* guarded by waitMutex */
	/* TODO: consider changing this to Object* for better JDWP interaction */
	Monitor*    waitMonitor;

	/* thread "interrupted" status; stays raised until queried or thrown */
	/* guarded by waitMutex */
	bool        interrupted;

	/* links to the next thread in the wait set this thread is part of */
	struct Thread*     waitNext;

	/* object to sleep on while we are waiting for a monitor */
	pthread_cond_t     waitCond;

	/*
	 *      * Set to true when the thread is in the process of throwing an
	 *           * OutOfMemoryError.
	 *                */
	bool        throwingOOME;

	/* links to rest of thread list; grab global lock before traversing */
	struct Thread* prev;
	struct Thread* next;

	/* used by threadExitCheck when a thread exits without detaching */
	int         threadExitCheckCount;

	/* JDWP invoke-during-breakpoint support */
	DebugInvokeReq  invokeReq;

	/* base time for per-thread CPU timing (used by method profiling) */
	bool        cpuClockBaseSet;
	u8          cpuClockBase;

	/* previous stack trace sample and length (used by sampling profiler) */
	const Method** stackTraceSample;
	Int stackTraceSampleLength;

	/* memory allocation profiling state */
	AllocProfState allocProf;

#ifdef WITH_JNI_STACK_CHECK
	u4          stackCrc;
#endif

#if WITH_EXTRA_GC_CHECKS > 1
	/* PC, saved on every instruction; redundant with StackSaveArea */
	const u2*   currentPc2;
#endif

	/* Safepoint callback state */
	//pthread_mutex_t   callbackMutex;
	void*   callbackMutex;
	//SafePointCallback callback;
	void*   callback;
	void*             callbackArg;

#if defined(ARCH_IA32) && defined(WITH_JIT)
	u4 spillRegion[MAX_SPILL_JIT_IA];
#endif
#endif
};

Bool dumpRawData(UChar* buf, UInt size, Addr a, const char* type);

struct MonitorDexFile* addDexFileList( struct DexFile* pDexFile );
void delDexFileList( struct DexFile* pDexFile );
struct MonitorDexFile* isInDexFileList( struct DexFile* pDexFile );
void releaseDexFileList();

void printDexCode(const struct DexCode *pCode);

struct MonitorDexFile* createDexFileMem(const struct DexFile* pDexFile, Addr addr, UInt len);
Bool copyDexFileOptHeader(const struct DexFile* pDexFile);
Bool copyDexFileHead(const struct DexFile* pDexFile);
//Bool copyMethod(const struct DexFile* pDexFile, const struct DexFile* pDexFile1, const struct DexMethod* pDexMethod);
Bool copyDexClass(const struct DexFile* pDexFile, Int ids, HChar* desc);
Bool copyAllClasses(const struct DexFile* pDexFile);
Bool copyMthCode(const struct DexFile* pDexFile, const struct Method* pMethod);
struct MonitorDexFile* meetDexFile(const struct DexFile* pDexFile, Addr addr, UInt len, UInt state);
Bool copyOneClass(const struct DexFile* pDexFile, HChar* desc);
Bool getClassMethods(const struct DexFile *pDexFile, struct ClassObject *pClazz);
/*--------------------------------- End ---------------------------------------------*/

#ifdef TRACE_ART_PLATFORM
struct DexFilePlusNode {
	struct DexFilePlus	*pDexFilePlus;
	struct DexFIle			*pDexFile;
	struct DexFilePlusNode *next;
};
struct MonitorDexFile* meetDexFilePlus(const struct DexFilePlus* pDexFilePlus, Addr addr, UInt len, UInt state);
#endif

Bool parseLoadedMethod(const struct DexFilePlus* pDexPlus, const struct ArtMethod* pAMth, HChar** pClazz, HChar** pMth, HChar** pShorty);
Bool getMethodSignature(const struct DexFile *pDex, Int idx, HChar** psClass, HChar** psMth, HChar** psShorty);
struct DexFile* dexFileParse(UChar* dexBuf, UInt length);
#endif // _PG_DEX_PARSE_H
