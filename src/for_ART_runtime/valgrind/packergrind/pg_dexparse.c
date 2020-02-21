// oatparse.c

#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_mallocfree.h"

#include "pg_dexparse.h"
#include "pg_oatparse.h"

#ifdef TRACE_ART_PLATFORM
struct DexFilePlusNode *pDexFilePlusList = NULL;
#endif
/* -------------- Monitor Dex File List ----------------------------*/
static struct MonitorDexFile *dexFileList = NULL;
/* Used for dump the dex files */
static Int file_index = 0;

void copyFile(Char* from, Char* dest)
{
	tl_assert((from != NULL) && (dest != NULL));
	HChar	file_buf[1024];
	Int r_size = 0, fout = 0, fin = 0;
	OAT_LOGI("Try to copy file %s to %s\n", from, dest);
	fout = VG_(fd_open)(from, VKI_O_RDONLY|VKI_O_TRUNC, 0);
	if(fout <= 0) {
		OAT_LOGI("Failed to open source file!!!\n");
		return;
	}
	fin  = VG_(fd_open)(dest, VKI_O_WRONLY|VKI_O_CREAT, VKI_S_IRUSR|VKI_S_IWUSR);
	if(fin <= 0) {
		OAT_LOGI("Failed to open dest file!!!\n");
		VG_(close)(fout);
		return;
	}
	do {
		r_size = VG_(read)(fout, file_buf, 1024);
		OAT_LOGI("Try to copy %d bytes\n", r_size);
		if(r_size > 0) {
			VG_(write)(fin, file_buf, r_size);
		}
	} while(r_size == 1024);
	VG_(close)(fin);
	VG_(close)(fout);
}

Bool dumpRawData(UChar* buf, UInt size, Addr a, const char* type) {
	tl_assert(buf != NULL);
	Int fout;
	HChar fpath[255];
	VG_(sprintf)(fpath, "/data/local/tmp/unpack/0x%08x-0x%08x-%d.%s", (Addr)buf, a, file_index++, type);
	fout = VG_(fd_open)(fpath, VKI_O_WRONLY|VKI_O_TRUNC, 0);
	if (fout <= 0) {
		fout = VG_(fd_open)(fpath, VKI_O_CREAT|VKI_O_WRONLY, VKI_S_IRUSR|VKI_S_IWUSR);
		if( fout <= 0 ) {
			OAT_LOGI("Create Dex file error.\n");
			return;
		}
	} 
	OAT_LOGI("Try to dump %s file %s 0x%08x-0x%08x\n", 
			type, fpath, (Addr)buf, (Addr)buf+size);
	VG_(write)(fout, buf, size);
	VG_(close)(fout);
	return True;
}

void dumpDexMem(UChar* buf, UInt size) {
	dumpRawData(buf, size, 0, "dex");
}   

struct MonitorDexFile* addDexFileList( struct DexFile* pDexFile ) {
	struct MonitorDexFile* tfl = dexFileList;
	while(tfl) {
		if (pDexFile == tfl->pDexFile)
			return tfl;
		tfl = tfl->next;
	}
	tfl = (struct MonitorDexFile*)VG_(malloc)("New.MonitorDexFile.node", sizeof(struct MonitorDexFile));
	tl_assert(tfl);
	VG_(memset)((Addr)tfl, 0, sizeof(struct MonitorDexFile));
	tfl->pDexFile = pDexFile;
	tfl->next = dexFileList;
	dexFileList = tfl;
	return tfl;
}

void delDexFileList( struct DexFile* pDexFile ) {
	struct MonitorDexFile* tfl = dexFileList;
	struct MonitorDexFile* pfl = NULL;
	while(tfl) {
		if (pDexFile == tfl->pDexFile)
			break;
		pfl = tfl;
		tfl = tfl->next;
	}
	if(tfl == NULL)
		return;
	if(pfl) {
		pfl->next = tfl->next;
	} else {
		dexFileList = tfl->next;
	}
	VG_(free)(tfl);
}

/*
 * Compute the DEX file checksum for a memory-mapped DEX file.
 */
static UInt dexComputeChecksum(const struct DexHeader* pHeader)
{
	const UChar* start = (const UChar*) pHeader;
	UInt	adler = VG_(adler32)(0, NULL, 0);
	const UInt nonSum = sizeof(pHeader->magic) + sizeof(pHeader->checksum);

	return (UInt) VG_(adler32)(adler, start + nonSum, pHeader->fileSize - nonSum);
}

void releaseDexFileList() {
	struct MonitorDexFile* tfl = dexFileList;
	struct MonitorDexFile* pfl = NULL;
	struct DexHeader			*pHeader = NULL;
	UInt fileLen = 0;
	OAT_LOGI("Will release DexFile list.\n");
	while(tfl) {
		pfl = tfl;
		tfl = tfl->next;
		if(pfl->cloneMem)
		{
			pHeader = pfl->pDexFileClone->pHeader;
			fileLen = ((pfl->endAddr-(Addr)pHeader) & ~3) + 0x4;
			pHeader->fileSize = fileLen;
			pHeader->checksum = dexComputeChecksum(pHeader);
#ifndef M_PERFORMANCE
			dumpRawData((Addr)pHeader, fileLen, (Addr)pfl->pDexFile, "odex");
			//#ifndef ONLY_DUMP
			processDexFile(pfl->pDexFileClone);
			//#endif
			//dumpDexFile((Addr)pHeader, fileLen);
#endif
			VG_(free)(pfl->cloneMem);
		}
		if(pfl->pDexFileClone)
			VG_(free)(pfl->pDexFileClone);
		VG_(free)(pfl);
	}
#ifdef TRACE_ART_PLATFORM
	struct DexFilePlusNode *pNode = pDexFilePlusList, *pre;
	while(pNode) {
		pre = pNode;
		pNode = pNode->next;
		if(pre->pDexFile)
			VG_(free)(pre->pDexFile);
		VG_(free)(pre);
	}
	pDexFilePlusList = NULL;
#endif
}

struct MonitorDexFile* isInDexFileList( struct DexFile* pDexFile ) {
	struct MonitorDexFile* tfl = dexFileList;
	while(tfl) {
		if (pDexFile == tfl->pDexFile)
			return tfl;
		tfl = tfl->next;
	}
	return NULL;
}
/* -------------- End: Monitor Dex File List ----------------------------*/

static INLINE Bool isValidPoInter(const UChar* ptr, const UChar* start, const UChar* end)
{
	//return (ptr >= start) && (ptr <= end) && (((UInt)ptr & 0x7) == 0);
	return (ptr >= start) && (ptr <= end) && (((UInt)ptr & 0x3) == 0);
}

/*
 * Get 2 little-endian bytes.
 */ 
static INLINE UShort get2LE(UChar const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8);
}

/*
 * Get 4 little-endian bytes.
 */
static INLINE UInt get4LE(UChar const* pSrc)
{
	return pSrc[0] | (pSrc[1] << 8) | (pSrc[2] << 16) | (pSrc[3] << 24);
}

/*
 * Converts a single-HCharacter primitive type into its human-readable
 * equivalent.
 */
static const HChar* primitiveTypeLabel(HChar typeChar)
{
	switch (typeChar) {
		case 'B':   return "byte";
		case 'C':   return "HChar";
		case 'D':   return "double";
		case 'F':   return "float";
		case 'I':   return "int";
		case 'J':   return "long";
		case 'S':   return "short";
		case 'V':   return "void";
		case 'Z':   return "boolean";
		default:
								return "UNKNOWN";
	}
}

/*
 * Converts a type descriptor to human-readable "dotted" form.  For
 * example, "Ljava/lang/String;" becomes "java.lang.String", and
 * "[I" becomes "int[]".  Also converts '$' to '.', which means this
 * form can't be converted back to a descriptor.
 */
static HChar* descriptorToDot(const HChar* str)
{
	Int targetLen = strlen(str);
	Int offset = 0;
	Int arrayDepth = 0;
	HChar* newStr;

	/* strip leading [s; will be added to end */
	while (targetLen > 1 && str[offset] == '[') {
		offset++;
		targetLen--;
	}
	arrayDepth = offset;

	if (targetLen == 1) {
		/* primitive type */
		str = primitiveTypeLabel(str[offset]);
		offset = 0;
		targetLen = strlen(str);
	} else {
		/* account for leading 'L' and trailing ';' */
		if (targetLen >= 2 && str[offset] == 'L' &&
				str[offset+targetLen-1] == ';')
		{
			targetLen -= 2;
			offset++;
		}
	}

	newStr = (HChar*)VG_(malloc)("descriptor.to.dot.1", targetLen + arrayDepth * 2 +1);

	/* copy class name over */
	Int i;
	for (i = 0; i < targetLen; i++) {
		HChar ch = str[offset + i];
		newStr[i] = (ch == '/' || ch == '$') ? '.' : ch;
	}

	/* add the appropriate number of brackets for arrays */
	while (arrayDepth-- > 0) {
		newStr[i++] = '[';
		newStr[i++] = ']';
	}
	newStr[i] = '\0';
	assert(i == targetLen + arrayDepth * 2);

	return newStr;
}

/*
 * Converts the class name portion of a type descriptor to human-readable
 * "dotted" form.
 *
 * Returns a newly-allocated string.
 */
static HChar* descriptorClassToDot(const HChar* str)
{
	const HChar* lastSlash;
	HChar* newStr;
	HChar* cp;

	/* reduce to just the class name, trimming trailing ';' */
	lastSlash = strrchr(str, '/');
	if (lastSlash == NULL)
		lastSlash = str + 1;        /* start past 'L' */
	else
		lastSlash++;                /* start past '/' */

	newStr = VG_(strdup)("descriptor.class.to.dot", lastSlash);
	newStr[VG_(strlen)(lastSlash)-1] = '\0';
	for (cp = newStr; *cp != '\0'; cp++) {
		if (*cp == '$')
			*cp = '.';
	}

	return newStr;
}

/*
 * Reads an unsigned LEB128 value, updating the given pointer to point
 * just past the end of the read value. This function tolerates
 * non-zero high-order bits in the fifth encoded byte.
 */
INLINE Int readUnsignedLeb128(const UChar** pStream) {
	const UChar* ptr = *pStream;
	Int result = *(ptr++);

	if (result > 0x7f) {
		Int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur > 0x7f) {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur > 0x7f) {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur > 0x7f) {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}

	*pStream = ptr;
	return result;
}

/*
 * Reads a signed LEB128 value, updating the given pointer to point
 * just past the end of the read value. This function tolerates
 * non-zero high-order bits in the fifth encoded byte.
 */
INLINE Int readSignedLeb128(const UChar** pStream) {
	const UChar* ptr = *pStream;
	Int result = *(ptr++);

	if (result <= 0x7f) {
		result = (result << 25) >> 25;
	} else {
		Int cur = *(ptr++);
		result = (result & 0x7f) | ((cur & 0x7f) << 7);
		if (cur <= 0x7f) {
			result = (result << 18) >> 18;
		} else {
			cur = *(ptr++);
			result |= (cur & 0x7f) << 14;
			if (cur <= 0x7f) {
				result = (result << 11) >> 11;
			} else {
				cur = *(ptr++);
				result |= (cur & 0x7f) << 21;
				if (cur <= 0x7f) {
					result = (result << 4) >> 4;
				} else {
					/*
					 * Note: We don't check to see if cur is out of
					 * range here, meaning we tolerate garbage in the
					 * high four-order bits.
					 */
					cur = *(ptr++);
					result |= cur << 28;
				}
			}
		}
	}

	*pStream = ptr;
	return result;
}

/*
 * Writes a 32-bit value in unsigned ULEB128 format.
 *
 * Returns the updated pointer.
 */
INLINE UChar* writeUnsignedLeb128(UChar* ptr, UInt data)
{
	while (True) {
		UChar out = data & 0x7f;
		if (out != data) {
			*ptr++ = out | 0x80;
			data >>= 7;
		} else {
			*ptr++ = out;
			break;
		}
	}
	return ptr;
}

/*
 * Returns the number of bytes needed to encode "val" in ULEB128 form.
 */
INLINE Int unsignedLeb128Size(UInt data)
{
	Int count = 0;

	do {
		data >>= 7;
		count++;
	} while (data != 0);

	return count;
}


/*
 * Reads an unsigned LEB128 value, updating the given pointer to point
 * just past the end of the read value and also indicating whether the
 * value was syntactically valid. The only syntactically *invalid*
 * values are ones that are five bytes long where the final byte has
 * any but the low-order four bits set. Additionally, if the limit is
 * passed as non-NULL and bytes would need to be read past the limit,
 * then the read is considered invalid.
 */
Int readAndVerifyUnsignedLeb128(const UChar** pStream, const UChar* limit,
		Bool* okay) {
	const UChar* ptr = *pStream;
	Int result = readUnsignedLeb128(pStream);

	if (((limit != NULL) && (*pStream > limit))
			|| (((*pStream - ptr) == 5) && (ptr[4] > 0x0f))) {
		*okay = False;
	}

	return result;
}

/*
 * Reads a signed LEB128 value, updating the given pointer to point
 * just past the end of the read value and also indicating whether the
 * value was syntactically valid. The only syntactically *invalid*
 * values are ones that are five bytes long where the final byte has
 * any but the low-order four bits set. Additionally, if the limit is
 * passed as non-NULL and bytes would need to be read past the limit,
 * then the read is considered invalid.
 */
Int readAndVerifySignedLeb128(const UChar** pStream, const UChar* limit,
		Bool* okay) {
	const UChar* ptr = *pStream;
	Int result = readSignedLeb128(pStream);

	if (((limit != NULL) && (*pStream > limit))
			|| (((*pStream - ptr) == 5) && (ptr[4] > 0x0f))) {
		*okay = False;
	}

	return result;
}


/*
 * TBD: Compute the DEX file checksum for a memory-mapped DEX file.
 */

/*--------------------------------------------------------------------------------------------*/
/*-------------------- Dex class related functions -------------------------------------------*/
/*--------------------------------------------------------------------------------------------*/

/* Helper for verification which reads and verifies a given number
 * of uleb128 values. */
static Bool verifyUlebs(const UChar* pData, const UChar* pLimit, UInt count) {
	Bool okay = True;
	UInt i;

	while (okay && (count-- != 0)) {
		//TBD: readAndVerifyUnsignedLeb128(&pData, pLimit, &okay);
	}

	return okay;
}

/*
 * Get the DexCode for a DexMethod.  Returns NULL if the class is native
 * or abstract.
 */
INLINE const struct DexCode* dexGetCode(const struct DexFile* pDexFile,
		const struct DexMethod* pDexMethod)
{    
	if (pDexMethod->codeOff == 0)
		return NULL;
	return (const struct DexCode*) (pDexFile->baseAddr + pDexMethod->codeOff);
}		

/* Read the header of a class_data_item without verification. This
 * updates the given data pointer to poInt past the end of the read
 * data. */
INLINE void dexReadClassDataHeader(const UChar** pData,
		struct DexClassDataHeader *pHeader) {
	pHeader->staticFieldsSize   = readUnsignedLeb128(pData);
	pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
	pHeader->directMethodsSize  = readUnsignedLeb128(pData);
	pHeader->virtualMethodsSize = readUnsignedLeb128(pData); 
}

/* Read an encoded_field without verification. This updates the
 * given data pointer to poInt past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
INLINE void dexReadClassDataField(const UInt** pData, struct DexField* pField,
		UInt* lastIndex) {
	UInt index = *lastIndex + readUnsignedLeb128(pData);

	pField->accessFlags = readUnsignedLeb128(pData);
	pField->fieldIdx = index;
	*lastIndex = index;
}

/* Read an encoded_method without verification. This updates the
 * given data pointer to poInt past the end of the read data.
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 */
INLINE void dexReadClassDataMethod(const UChar** pData, struct DexMethod* pMethod,
		UInt* lastIndex) {
	UInt index = *lastIndex + readUnsignedLeb128(pData);

	pMethod->accessFlags = readUnsignedLeb128(pData);
	pMethod->codeOff = readUnsignedLeb128(pData);
	pMethod->methodIdx = index;
	*lastIndex = index;
}


/* Read and verify the header of a class_data_item. This updates the
 * given data poInter to poInt past the end of the read data and
 * returns an "okay" flag (that is, False == failure). */
Bool dexReadAndVerifyClassDataHeader(const UChar** pData, const UChar* pLimit,
		struct DexClassDataHeader *pHeader) {
	if (! verifyUlebs(*pData, pLimit, 4)) {
		return False;
	}

	dexReadClassDataHeader(pData, pHeader);
	return True;
}

/* Read and verify an encoded_field. This updates the
 * given data poInter to poInt past the end of the read data and
 * returns an "okay" flag (that is, False == failure).
 *
 * The lastIndex value should be set to 0 before the first field in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags or indices
 * are valid. */
Bool dexReadAndVerifyClassDataField(const UChar** pData, const UChar* pLimit,
		struct DexField* pField, UChar* lastIndex) {
	if (! verifyUlebs(*pData, pLimit, 2)) {
		return False;
	}

	dexReadClassDataField(pData, pField, lastIndex);
	return True;
}

/* Read and verify an encoded_method. This updates the
 * given data poInter to poInt past the end of the read data and
 * returns an "okay" flag (that is, False == failure).
 *
 * The lastIndex value should be set to 0 before the first method in
 * a list is read. It is updated as fields are read and used in the
 * decode process.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
Bool dexReadAndVerifyClassDataMethod(const UChar** pData, const UChar* pLimit,
		struct DexMethod* pMethod, UInt* lastIndex) {
	if (! verifyUlebs(*pData, pLimit, 3)) {
		return False;
	}

	dexReadClassDataMethod(pData, pMethod, lastIndex);
	return True;
}

/* Read, verify, and return an entire class_data_item. This updates
 * the given data poInter to poInt past the end of the read data. This
 * function allocates a single chunk of memory for the result, which
 * must subsequently be VG_(free)()d. This function returns NULL if there
 * was trouble parsing the data. If this function is passed NULL, it
 * returns an initialized empty DexClassData structure.
 *
 * The verification done by this function is of the raw data format
 * only; it does not verify that access flags, indices, or offsets
 * are valid. */
struct DexClassData* dexReadAndVerifyClassData(const UChar** pData, const UChar* pLimit) {
	struct DexClassDataHeader header;
	UInt lastIndex;

	if (*pData == NULL) {
		struct DexClassData* result = (struct DexClassData*) VG_(malloc)("Dex.Class.Data.1", sizeof(struct DexClassData));
		VG_(memset)((Addr)result, 0, sizeof(struct DexClassData));
		memset(result, 0, sizeof(*result));
		return result;
	}

	if (! dexReadAndVerifyClassDataHeader(pData, pLimit, &header)) {
		return NULL;
	}

	UInt resultSize = sizeof(struct DexClassData) +
		(header.staticFieldsSize		* sizeof(struct DexField)) +
		(header.instanceFieldsSize	* sizeof(struct DexField)) +
		(header.directMethodsSize		* sizeof(struct DexMethod)) +
		(header.virtualMethodsSize	* sizeof(struct DexMethod));

	struct DexClassData* result = (struct DexClassData*) VG_(malloc)("Dex.Class.Data.2", resultSize);
	VG_(memset)((Addr)result, 0, sizeof(struct DexClassData));
	UChar* ptr = ((UChar*) result) + sizeof(struct DexClassData);
	Bool okay = True;
	UInt i;

	if (result == NULL) {
		return NULL;
	}

	result->header = header;

	if (header.staticFieldsSize != 0) {
		result->staticFields = (struct DexField*) ptr;
		ptr += header.staticFieldsSize * sizeof(struct DexField);
	} else {
		result->staticFields = NULL;
	}

	if (header.instanceFieldsSize != 0) {
		result->instanceFields = (struct DexField*) ptr;
		ptr += header.instanceFieldsSize * sizeof(struct DexField);
	} else {
		result->instanceFields = NULL;
	}

	if (header.directMethodsSize != 0) {
		result->directMethods = (struct DexMethod*) ptr;
		ptr += header.directMethodsSize * sizeof(struct DexMethod);
	} else {
		result->directMethods = NULL;
	}

	if (header.virtualMethodsSize != 0) {
		result->virtualMethods = (struct DexMethod*) ptr;
	} else {
		result->virtualMethods = NULL;
	}

	lastIndex = 0;
	for (i = 0; okay && (i < header.staticFieldsSize); i++) {
		okay = dexReadAndVerifyClassDataField(pData, pLimit,
				&result->staticFields[i], &lastIndex);
	}

	lastIndex = 0;
	for (i = 0; okay && (i < header.instanceFieldsSize); i++) {
		okay = dexReadAndVerifyClassDataField(pData, pLimit,
				&result->instanceFields[i], &lastIndex);
	}

	lastIndex = 0;
	for (i = 0; okay && (i < header.directMethodsSize); i++) {
		okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
				&result->directMethods[i], &lastIndex);
	}

	lastIndex = 0;
	for (i = 0; okay && (i < header.virtualMethodsSize); i++) {
		okay = dexReadAndVerifyClassDataMethod(pData, pLimit,
				&result->virtualMethods[i], &lastIndex);
	}

	if (! okay) {
		VG_(free)(result);
		return NULL;
	}

	return result;
}

/*---------------------------------------------------------------------------------------------*/
/*----------------------------------- End -----------------------------------------------------*/
/*---------------------------------------------------------------------------------------------*/

/*---------------------------------------------------------------------------------------------*/
/*------------------------------ From DexProto.h ----------------------------------------------*/
/*---------------------------------------------------------------------------------------------*/

/*
 * ===========================================================================
 *      String Cache
 * ===========================================================================
 */

/*
 * Make sure that the given cache can hold a string of the given length,
 * including the final '\0' byte.
 */
void dexStringCacheAlloc(struct DexStringCache* pCache, Int length) {
	if (pCache->allocatedSize != 0) {
		if (pCache->allocatedSize >= length) {
			return;
		}
		VG_(free)((void*) pCache->value);
	}

	if (length <= sizeof(pCache->buffer)) {
		pCache->value = pCache->buffer;
		pCache->allocatedSize = 0;
	} else {
		pCache->value = (HChar*) VG_(malloc)("dex.string.cache.alloc", length);
		pCache->allocatedSize = length;
	}
}

/*
 * Initialize the given DexStringCache. Use this function before passing
 * one into any other function.
 */
void dexStringCacheInit(struct DexStringCache* pCache) {
	pCache->value = pCache->buffer;
	pCache->allocatedSize = 0;
	pCache->buffer[0] = '\0';
}

/*
 * Release the allocated contents of the given DexStringCache, if any.
 * Use this function after your last use of a DexStringCache.
 */
void dexStringCacheRelease(struct DexStringCache* pCache) {
	if (pCache->allocatedSize != 0) {
		VG_(free)((void*) pCache->value);
		pCache->value = pCache->buffer;
		pCache->allocatedSize = 0;
	}
}

/*
 * If the given DexStringCache doesn't already point at the given value,
 * make a copy of it into the cache. This always returns a writable
 * pointer to the contents (whether or not a copy had to be made). This
 * function is intended to be used after making a call that at least
 * sometimes doesn't populate a DexStringCache.
 */
HChar* dexStringCacheEnsureCopy(struct DexStringCache* pCache, const HChar* value) {
	if (value != pCache->value) {
		Int length = strlen(value) + 1;
		dexStringCacheAlloc(pCache, length);
		VG_(memcpy)(pCache->value, value, length);
	}
	return pCache->value;
}

/*
 * Abandon the given DexStringCache, and return a writable copy of the
 * given value (reusing the string cache's allocation if possible).
 * The return value must be free()d by the caller. Use this instead of
 * dexStringCacheRelease() if you want the buffer to survive past the
 * scope of the DexStringCache.
 */
HChar* dexStringCacheAbandon(struct DexStringCache* pCache, const HChar* value) {
	if ((value == pCache->value) && (pCache->allocatedSize != 0)) {
		HChar* result = pCache->value;
		pCache->allocatedSize = 0;
		pCache->value = pCache->buffer;
		return result;
	}
	HChar *res = (HChar*)VG_(strdup)("dexstring.cache.abandon.1", value);
	return res;
}
/*
 * Set the given DexProto to refer to the prototype of the given MethodId.
 */
INLINE void dexProtoSetFromMethodId(struct DexProto* pProto,
		const struct DexFile* pDexFile, const struct DexMethodId* pMethodId)
{
	pProto->dexFile = pDexFile;
	pProto->protoIdx = pMethodId->protoIdx;
}

/*
 * Return the DexProtoId from the given DexProto. The DexProto must
 * actually refer to a DexProtoId.
 */
static INLINE const struct DexProtoId* getProtoId(const struct DexProto* pProto) {
	return dexGetProtoId(pProto->dexFile, pProto->protoIdx);
}

/* (documented in header file) */
static INLINE const char* dexProtoGetShorty(const struct DexProto* pProto) {
	const  struct DexProtoId* protoId = getProtoId(pProto);
	return dexStringById(pProto->dexFile, protoId->shortyIdx);
}

/* (documented in header file) */
const HChar* dexProtoGetMethodDescriptor(const struct DexProto* pProto,
		struct DexStringCache* pCache) {
	const struct DexFile* dexFile = pProto->dexFile;
	const struct DexProtoId* protoId = getProtoId(pProto);
	const struct DexTypeList* typeList = dexGetProtoParameters(dexFile, protoId);
	Int length = 3; // parens and terminating '\0'
	UInt paramCount = (typeList == NULL) ? 0 : typeList->size;
	UInt i;

	for (i = 0; i < paramCount; i++) {
		UInt idx = dexTypeListGetIdx(typeList, i);
		length += VG_(strlen)(dexStringByTypeIdx(dexFile, idx));
	}

	length += VG_(strlen)(dexStringByTypeIdx(dexFile, protoId->returnTypeIdx));

	dexStringCacheAlloc(pCache, length);

	HChar *at = (HChar*) pCache->value;
	*(at++) = '(';

	for (i = 0; i < paramCount; i++) {
		UInt idx = dexTypeListGetIdx(typeList, i);
		const HChar* desc = dexStringByTypeIdx(dexFile, idx);
		VG_(strcpy)(at, desc);
		at += VG_(strlen)(desc);
	}

	*(at++) = ')';

	VG_(strcpy)(at, dexStringByTypeIdx(dexFile, protoId->returnTypeIdx));
	return pCache->value;
}

/*
 * Return the utf-8 encoded descriptor string from the proto of a MethodId.
 */
INLINE const HChar* dexGetDescriptorFromMethodId(const struct DexFile* pDexFile,
		const struct DexMethodId* pMethodId, struct DexStringCache* pCache)
{
	struct DexProto proto;

	dexProtoSetFromMethodId(&proto, pDexFile, pMethodId);
	return dexProtoGetMethodDescriptor(&proto, pCache);
}       

/* (documented in header file) */
INLINE HChar* dexProtoCopyMethodDescriptor(const struct DexProto* pProto) {
	struct DexStringCache cache;

	dexStringCacheInit(&cache);
	return dexStringCacheAbandon(&cache,
			dexProtoGetMethodDescriptor(pProto, &cache));
}

/*  
 * Get a copy of the utf-8 encoded method descriptor string from the
 * proto of a MethodId. The returned pointer must be free()ed by the
 * caller. 
 */     
INLINE HChar* dexCopyDescriptorFromMethodId(const struct DexFile* pDexFile,
		const struct DexMethodId* pMethodId)
{
	struct DexProto proto;

	dexProtoSetFromMethodId(&proto, pDexFile, pMethodId);
	return dexProtoCopyMethodDescriptor(&proto);
}   


/*------------------------------ End DexProto.h -----------------------------------------------*/


/*
 * Count the number of '1' bits in a word.
 */
static Int countOnes(UInt val)
{
	Int count = 0;

	val = val - ((val >> 1) & 0x55555555);
	val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
	count = (((val + (val >> 4)) & 0x0F0F0F0F) * 0x01010101) >> 24;

	return count;
}

/*
 * Create a new string with human-readable access flags.
 *
 * In the base language the access_flags fields are type u2; in Dalvik
 * they're UInt.
 */
static HChar* createAccessFlagStr(UInt flags, enum AccessFor forWhat)
{
#define NUM_FLAGS   18
	static const HChar* kAccessStrings[kAccessForMAX][NUM_FLAGS] = {
		{
			/* class, inner class */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"?",                /* 0x0040 */
			"?",                /* 0x0080 */
			"?",                /* 0x0100 */
			"INTERFACE",        /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"ANNOTATION",       /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"VERIFIED",         /* 0x10000 */
			"OPTIMIZED",        /* 0x20000 */
		},
		{
			/* method */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"SYNCHRONIZED",     /* 0x0020 */
			"BRIDGE",           /* 0x0040 */
			"VARARGS",          /* 0x0080 */
			"NATIVE",           /* 0x0100 */
			"?",                /* 0x0200 */
			"ABSTRACT",         /* 0x0400 */
			"STRICT",           /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"?",                /* 0x4000 */
			"MIRANDA",          /* 0x8000 */
			"CONSTRUCTOR",      /* 0x10000 */
			"DECLARED_SYNCHRONIZED", /* 0x20000 */
		},
		{
			/* field */
			"PUBLIC",           /* 0x0001 */
			"PRIVATE",          /* 0x0002 */
			"PROTECTED",        /* 0x0004 */
			"STATIC",           /* 0x0008 */
			"FINAL",            /* 0x0010 */
			"?",                /* 0x0020 */
			"VOLATILE",         /* 0x0040 */
			"TRANSIENT",        /* 0x0080 */
			"?",                /* 0x0100 */
			"?",                /* 0x0200 */
			"?",                /* 0x0400 */
			"?",                /* 0x0800 */
			"SYNTHETIC",        /* 0x1000 */
			"?",                /* 0x2000 */
			"ENUM",             /* 0x4000 */
			"?",                /* 0x8000 */
			"?",                /* 0x10000 */
			"?",                /* 0x20000 */
		},
	};
	const Int kLongest = 21;        /* strlen of longest string above */
	Int i, count;
	HChar* str;
	HChar* cp;

	/*
	 *      * Allocate enough storage to hold the expected number of strings,
	 *           * plus a space between each.  We over-allocate, using the longest
	 *                * string above as the base metric.
	 *                     */
	count = countOnes(flags);
	cp = str = (HChar*) VG_(malloc)("create.access.flag.1", count * (kLongest+1) +1);

	for (i = 0; i < NUM_FLAGS; i++) {
		if (flags & 0x01) {
			const HChar* accessStr = kAccessStrings[forWhat][i];
			Int len = VG_(strlen)(accessStr);
			if (cp != str)
				*cp++ = ' ';

			memcpy(cp, accessStr, len);
			cp += len;
		}
		flags >>= 1;
	}
	*cp = '\0';

	return str;
}



/*
 * Copy HCharacter data from "data" to "out", converting non-ASCII values
 * to OAT_LOGI format HChars or an ASCII filler ('.' or '?').
 *
 * The output buffer must be able to hold (2*len)+1 bytes.  The result is
 * NUL-terminated.
 */
static void asciify(HChar* out, const UChar* data, UInt len)
{
	while (len--) {
		if (*data < 0x20) {
			/* could do more here, but we don't need them yet */
			switch (*data) {
				case '\0':
					*out++ = '\\';
					*out++ = '0';
					break;
				case '\n':
					*out++ = '\\';
					*out++ = 'n';
					break;
				default:
					*out++ = '.';
					break;
			}
		} else if (*data >= 0x80) {
			*out++ = '?';
		} else {
			*out++ = *data;
		}
		data++;
	}
	*out = '\0';
}


/*
 * Dump a "code" struct.
 */
void printDexCode(const struct DexCode *pCode)
{
	if(pCode == NULL)
		return;
	OAT_LOGI("      code          -	0x%08x\n", (Addr)pCode);
	OAT_LOGI("      debugInfoOff  : 0x%08x\n", pCode->debugInfoOff);
	OAT_LOGI("      registers     : %d\n", pCode->registersSize);
	OAT_LOGI("      ins           : %d\n", pCode->insSize);
	OAT_LOGI("      outs          : %d\n", pCode->outsSize);
	OAT_LOGI("      insns size    : %d (0x%08x-0x%08x) 16-bit code units\n", 
			pCode->insnsSize, (Addr)pCode->insns, (Addr)pCode->insns+((pCode->insnsSize-1) * 2));
	if(pCode->insnsSize > 0 /*&& i < 0*/)
	{
		OAT_LOGI("			FOR DEBUG			:");
		for(Int i = 0; i < pCode->insnsSize; i++)
			VG_(printf)(" 0x%04x", pCode->insns[i]);
		VG_(printf)("\n");
	}
#if 0 // TODO
	//if (gOptions.disassemble)
	dumpBytecodes(pDexFile, pDexMethod);

	dumpCatches(pDexFile, pCode);
	/* both of these are encoded in debug info */
	dumpPositions(pDexFile, pCode, pDexMethod);
	dumpLocals(pDexFile, pCode, pDexMethod);
#endif
}
/* 2.4.2.4
 * Dump a method.
 */
void dumpMethod(struct DexFile* pDexFile, const struct DexMethod* pDexMethod, Int i)
{
	const struct DexMethodId* pMethodId;
	const HChar* backDescriptor;
	const HChar* name;
	HChar* typeDescriptor = NULL;
	HChar* accessStr = NULL;
#if 0
	if (gOptions.exportsOnly &&
			(pDexMethod->accessFlags & (ACC_PUBLIC | ACC_PROTECTED)) == 0)
	{
		return;
	}
#endif

	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	if(pMethodId == NULL)
		return;
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	typeDescriptor = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	backDescriptor = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	accessStr = createAccessFlagStr(pDexMethod->accessFlags,kAccessForMethod);

	OAT_LOGI("    #%d             : (in %s)\n", i, backDescriptor);
	OAT_LOGI("      name          : '%s'\n", name);
	OAT_LOGI("      type          : '%s'\n", typeDescriptor);
	OAT_LOGI("      access        : 0x%04x (%s)\n", pDexMethod->accessFlags, accessStr);
	OAT_LOGI("      method_id_idx : %d\n", pDexMethod->methodIdx);
	OAT_LOGI("      class_idx     : %d\n", pMethodId->classIdx);
	OAT_LOGI("      proto_idx     : %d\n", pMethodId->protoIdx);
	OAT_LOGI("      name_idx      : %d\n", pMethodId->nameIdx);

	if (pDexMethod->codeOff == 0) {
		OAT_LOGI("      code          : (none)\n");
	} else {
		struct DexCode* pCode = dexGetCode(pDexFile, pDexMethod);
#ifdef IJIAMI_1603
		if((Addr)pCode > pDexFile->baseAddr + pDexFile->pHeader->fileSize) {
			OAT_LOGI("Warning: DexCode 0x%08x is out of the memory range!!\n", (Addr)pCode);
			return;
		}
		if(pCode->debugInfoOff > pDexFile->baseAddr + pDexFile->pHeader->fileSize) {
			OAT_LOGI("Warning: Debug info of code 0x%08x is out of the memory range!!\n", (Addr)pCode);
			pCode->debugInfoOff = 0;
		}
#endif
		printDexCode(pCode);
	}

#if 0
	if (gOptions.disassemble)
		putHChar('\n');
#endif

bail:
	VG_(free)(typeDescriptor);
	VG_(free)(accessStr);
}

/* 2.4.2.3
 * Dump an instance field.
 */
void dumpIField(const struct DexFile* pDexFile, const struct DexField* pIField, Int i)
{
	dumpSField(pDexFile, pIField, i);
}

/* 2.4.2.2
 * Dump a static (class) field.
 */
void dumpSField(const struct DexFile* pDexFile, const struct DexField* pSField, Int i)
{   
	const struct DexFieldId* pFieldId;
	const HChar* backDescriptor;
	const HChar* name;
	const HChar* typeDescriptor; 
	HChar* accessStr;

#if 0
	if (gOptions.exportsOnly &&
			(pSField->accessFlags & (ACC_PUBLIC | ACC_PROTECTED)) == 0)
	{
		return;
	}
#endif

	pFieldId = dexGetFieldId(pDexFile, pSField->fieldIdx);
	name = dexStringById(pDexFile, pFieldId->nameIdx);
	typeDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->typeIdx);
	backDescriptor = dexStringByTypeIdx(pDexFile, pFieldId->classIdx);
	accessStr = createAccessFlagStr(pSField->accessFlags, kAccessForField);

	OAT_LOGI("    #%d              : (in %s)\n", i, backDescriptor);
	OAT_LOGI("      name          : '%s'\n", name);
	OAT_LOGI("      type          : '%s'\n", typeDescriptor);
	OAT_LOGI("      access        : 0x%04x (%s)\n",
			pSField->accessFlags, accessStr);
	VG_(free)(accessStr);
}

/* 2.4.2.1
 * Dump an interface that a class declares to implement.
 */
void dumpInterface(const struct DexFile* pDexFile, const struct DexTypeItem* pTypeItem,
		Int i)
{
	const UChar* interfaceName =
		dexStringByTypeIdx(pDexFile, pTypeItem->typeIdx);

	//if (gOptions.outputFormat == OUTPUT_PLAIN) {
	if (1) {
		OAT_LOGI("    #%d              : '%s'\n", i, interfaceName);
	} else {
		UChar* dotted = descriptorToDot(interfaceName);
		OAT_LOGI("<implements name=\"%s\">\n</implements>\n", dotted);
		VG_(free)(dotted);
	}
}

/* 2.4.2
 * Dump the class.
 *
 * Note "idx" is a DexClassDef index, not a DexTypeId index.
 *
 * If "*pLastPackage" is NULL or does not match the current class' package,
 * the value will be replaced with a newly-allocated string.
 */
void dumpClass(struct DexFile* pDexFile, Int idx, HChar** pLastPackage)
{
	const struct DexTypeList* pInterfaces = NULL;
	const struct DexClassDef* pClassDef = NULL;
	struct DexClassData* pClassData = NULL;

	const UChar* pEncodedData = NULL, *pEncodeStart = NULL;
	const HChar* fileName = NULL;
	const HChar* classDescriptor = NULL;
	const HChar* superclassDescriptor = NULL;

	Int i;
	Int encodeLen;
	pClassDef = dexGetClassDef(pDexFile, idx);
#if 0
	if (gOptions.exportsOnly && (pClassDef->accessFlags & ACC_PUBLIC) == 0) {
		//OAT_LOGI("<!-- omitting non-public class %s -->\n",
		//      classDescriptor);
		goto bail;
	}
#endif 
	pEncodedData = dexGetClassData(pDexFile, pClassDef);
	pEncodeStart = pEncodedData;
	pClassData = dexReadAndVerifyClassData(&pEncodedData, NULL);

	if (pClassData == NULL) {
		OAT_LOGI("Trouble reading class data (#%d)\n", idx);
		goto bail;
	}

	classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

	/*
	 * For the XML output, show the package name.  Ideally we'd gather
	 * up the classes, sort them, and dump them alphabetically so the
	 * package name wouldn't jump around, but that's not a great plan
	 * for something that needs to run on the device.
	 */
	if (!(classDescriptor[0] == 'L' &&
				classDescriptor[VG_(strlen)(classDescriptor)-1] == ';'))
	{
		/* arrays and primitives should not be defined explicitly */
		OAT_LOGE("Malformed class name '%s'\n", classDescriptor);
		/* keep going? */
	} else {
		HChar* mangle;
		HChar* lastSlash;
		HChar* cp;

		mangle = VG_(strdup)("clase.descriptor", classDescriptor + 1);
		mangle[VG_(strlen)(mangle)-1] = '\0';

		/* reduce to just the package name */
		lastSlash = VG_(strrchr)(mangle, '/');
		if (lastSlash != NULL) {
			*lastSlash = '\0';
		} else {
			*mangle = '\0';
		}

		for (cp = mangle; *cp != '\0'; cp++) {
			if (*cp == '/')
				*cp = '.';
		}

		if (*pLastPackage == NULL || VG_(strcmp)(mangle, *pLastPackage) != 0) {
			/* start of a new package */
			VG_(free)(*pLastPackage);
			*pLastPackage = mangle;
		} else {
			VG_(free)(mangle);
		}
	}


	if (pClassDef->superclassIdx == kDexNoIndex) {
		superclassDescriptor = NULL;
	} else {
		superclassDescriptor =
			dexStringByTypeIdx(pDexFile, pClassDef->superclassIdx);
	}

	//if (gOptions.outputFormat == OUTPUT_PLAIN) {
	if (1) {
		OAT_LOGI("\tClassDef          : 0x%08x\n", (Addr)pClassDef);
		OAT_LOGI("\tEncode  Data		  : 0x%08x-0x%08x\n",(Addr)pEncodeStart, (Addr)pEncodedData);
		OAT_LOGI("\tClass descriptor  : '%s'\n", classDescriptor);
		OAT_LOGI("\tAccess flags      : 0x%04x \n",
				pClassDef->accessFlags);

		if (superclassDescriptor != NULL)
			OAT_LOGI("\tSuperclass        : '%s'\n", superclassDescriptor);

		OAT_LOGI("\tInterfaces        -\n");
	} else {
		HChar* tmp;

		tmp = descriptorClassToDot(classDescriptor);
		OAT_LOGI("<class name=\"%s\"\n", tmp);
		VG_(free)(tmp);

		if (superclassDescriptor != NULL) {
			tmp = descriptorToDot(superclassDescriptor);
			OAT_LOGI(" extends=\"%s\"\n", tmp);
			VG_(free)(tmp);
		}
		OAT_LOGI(" abstract=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_ABSTRACT) != 0));
		OAT_LOGI(" static=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_STATIC) != 0));
		OAT_LOGI(" final=%s\n",
				quotedBool((pClassDef->accessFlags & ACC_FINAL) != 0));


		// "deprecated=" not knowable w/o parsing annotations
		OAT_LOGI(" visibility=%s\n",
				quotedVisibility(pClassDef->accessFlags));
		OAT_LOGI(">\n");
	}
	/* 2.4.2.1 Parse interfaces */
	pInterfaces = dexGetInterfacesList(pDexFile, pClassDef);
	if (pInterfaces != NULL) {
		for (i = 0; i < (Int) pInterfaces->size; i++)
			dumpInterface(pDexFile, dexGetTypeItem(pInterfaces, i), i);
	}
	/* 2.4.2.2 Parse static fields */
	OAT_LOGI("\tStatic fields     -\n");
	for (i = 0; i < (Int) pClassData->header.staticFieldsSize; i++) {
		dumpSField(pDexFile, &pClassData->staticFields[i], i);
	}
	/* 2.4.2.3 Parse instantces */
	OAT_LOGI("\tInstance fields   -\n");
	for (i = 0; i < (Int) pClassData->header.instanceFieldsSize; i++) {
		dumpIField(pDexFile, &pClassData->instanceFields[i], i);
	}

	/* 2.4.2.4 Parse Direct methods */
	OAT_LOGI("\tDirect methods    -\n");
	for (i = 0; i < (Int) pClassData->header.directMethodsSize; i++) {
		dumpMethod(pDexFile, &pClassData->directMethods[i], i);
	}

	/* 2.4.2.5 Parse virtual methods */
	OAT_LOGI("\tVirtual methods   -\n");
	for (i = 0; i < (Int) pClassData->header.virtualMethodsSize; i++) {
		dumpMethod(pDexFile, &pClassData->virtualMethods[i], i);
	}
	// TODO: Annotations.

	if (pClassDef->sourceFileIdx != kDexNoIndex)
		fileName = dexStringById(pDexFile, pClassDef->sourceFileIdx);
	else
		fileName = "unknown";

	OAT_LOGI("\tsource_file_idx   : %d (%s)\n",
			pClassDef->sourceFileIdx, fileName);
	OAT_LOGI("\n");

bail:
	VG_(free)(pClassData);
}

/* 2.4.1
 * Dump a class_def_item.
 */
void dumpClassDef(struct DexFile* pDexFile, Int idx)
{
	const struct DexClassDef* pClassDef;
	const UChar* pEncodedData;
	struct DexClassData* pClassData;

	pClassDef			= dexGetClassDef(pDexFile, idx);
	pEncodedData	= dexGetClassData(pDexFile, pClassDef);
	pClassData		= dexReadAndVerifyClassData(&pEncodedData, NULL);

	if (pClassData == NULL) {
		OAT_LOGE("Trouble reading class data\n");
		return;
	}

	OAT_LOGI("Class #%d header:\n", idx);
	OAT_LOGI("\tclass_idx           : %d\n", pClassDef->classIdx);
	OAT_LOGI("\taccess_flags        : %d (0x%04x)\n",
			pClassDef->accessFlags, pClassDef->accessFlags);
	OAT_LOGI("\tsuperclass_idx      : %d\n", pClassDef->superclassIdx);
	OAT_LOGI("\tInterfaces_off      : %d (0x%06x)\n",
			pClassDef->interfacesOff, pClassDef->interfacesOff);
	OAT_LOGI("\tsource_file_idx     : %d\n", pClassDef->sourceFileIdx);
	OAT_LOGI("\tannotations_off     : %d (0x%06x)\n",
			pClassDef->annotationsOff, pClassDef->annotationsOff);
	OAT_LOGI("\tclass_data_off      : %d (0x%06x)\n",
			pClassDef->classDataOff, pClassDef->classDataOff);
	OAT_LOGI("\tstatic_fields_size  : %d\n", pClassData->header.staticFieldsSize);
	OAT_LOGI("\tinstance_fields_size: %d\n",
			pClassData->header.instanceFieldsSize);
	OAT_LOGI("\tdirect_methods_size : %d\n", pClassData->header.directMethodsSize);
	OAT_LOGI("\tvirtual_methods_size: %d\n",
			pClassData->header.virtualMethodsSize);
	OAT_LOGI("\n");

	VG_(free)(pClassData);
}

/* 2.4 
 * Dump the class of the dex file
 */
void dumpClassData(const struct DexFile* pDexFile, const struct MonitorDexFile* pMDexFile) 
{
	HChar *package = NULL;
	Int i = 0;
	if( pDexFile->baseAddr != (Addr)pDexFile->pHeader) {
		OAT_LOGI("baseAddr and pHeader doesn't match!!\n");
		return;
	}
	for ( i = 0; i < (Int) pDexFile->pHeader->classDefsSize; i++) {
		//if (i > 20)
		//	break;
		dumpClassDef(pDexFile, i);				// 2.4.1
		dumpClass(pDexFile, i, &package);	// 2.4.2
	}

	/* free the last one allocated */
	if(package != NULL) {
		VG_(free)(package);
	}
}

/* 2.3
 * Dump the "table of contents" for the opt area.
 */
void dumpOptDirectory(const struct DexFile* pDexFile, const struct MonitorDexFile* pMDexFile)
{
	const struct DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	if (pOptHeader == NULL) {
		OAT_LOGE("No opt header found.\n");
		return;
	}

	OAT_LOGI("OPT section contents:\n");

	const UInt* pOpt = (const UInt*) ((UChar*) pOptHeader + pOptHeader->optOffset);

	if (*pOpt == 0) {
		OAT_LOGE("(1.0 format, only class lookup table is present)\n\n");
		return;
	}

	/*
	 * The "opt" section is in "chunk" format: a 32-bit identifier, a 32-bit
	 * length, then the data.  Chunks start on 64-bit boundaries.
	 */
	while (*pOpt != kDexChunkEnd) {
		const HChar* verboseStr;

		UInt size = *(pOpt+1);

		switch (*pOpt) {
			case kDexChunkClassLookup:
				verboseStr = "class lookup hash table";
				break;
			case kDexChunkRegisterMaps:
				verboseStr = "register maps";
				break;
			default:
				verboseStr = "(unknown chunk type)";
				break;
		}

		OAT_LOGI("\tChunk %08x (%c%c%c%c) - %s (%d bytes)\n", *pOpt,
				*pOpt >> 24, (HChar)(*pOpt >> 16), (HChar)(*pOpt >> 8), (HChar)*pOpt,
				verboseStr, size);

		size = (size + 8 + 7) & ~7;
		pOpt += size / sizeof(UInt);
	}
	OAT_LOGI("\n");
}

/* 2.2
 * Dump the file header.
 */
static Bool dumpFileHeader(const struct DexFile* pDexFile, const struct MonitorDexFile* pMDexFile)
{
	const struct DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	const struct DexHeader* pHeader = pDexFile->pHeader;
	HChar sanitized[sizeof(pHeader->magic)*2 +1];

	OAT_LOGI("DexFile								:\n");
	OAT_LOGI("\tDexOptHeader				: 0x%08x\n", (Addr)pDexFile->pOptHeader);
	OAT_LOGI("\tDexHeader						: 0x%08x\n", (Addr)pDexFile->pHeader);
	OAT_LOGI("\tDexStringId					: 0x%08x\n", (Addr)pDexFile->pStringIds);
	OAT_LOGI("\tDexTypeIds					: 0x%08x\n", (Addr)pDexFile->pTypeIds);
	OAT_LOGI("\tDexFieldId					: 0x%08x\n", (Addr)pDexFile->pFieldIds);
	OAT_LOGI("\tDexMethodId					: 0x%08x\n", (Addr)pDexFile->pMethodIds);
	OAT_LOGI("\tDexProtoId					: 0x%08x\n", (Addr)pDexFile->pProtoIds);
	OAT_LOGI("\tDexClassDef					: 0x%08x\n", (Addr)pDexFile->pClassDefs);
	OAT_LOGI("\tDexLink							: 0x%08x\n", (Addr)pDexFile->pLinkData);
	OAT_LOGI("\tDexClassLookup			: 0x%08x\n", (Addr)pDexFile->pClassLookup);
	OAT_LOGI("\tRegisterMapPoolAddr	: 0x%08x\n", (Addr)pDexFile->pRegisterMapPool);
	OAT_LOGI("\tbaseAddr						: 0x%08x\n", (Addr)pDexFile->baseAddr);
	OAT_LOGI("\toverhead						: 0x%08x\n", pDexFile->overhead);

	if ((Addr)pOptHeader + 0x28 == pDexFile->baseAddr) {
		tl_assert(sizeof(pHeader->magic) == sizeof(pOptHeader->magic));
		OAT_LOGI("Optimized DEX file header:\n");

		asciify(sanitized, pOptHeader->magic, sizeof(pOptHeader->magic));

		OAT_LOGI("\tmagic               : '%s'\n", sanitized);
		OAT_LOGI("\tdex_offset          : %d (0x%06x)\n",
				pOptHeader->dexOffset, pOptHeader->dexOffset);
		OAT_LOGI("\tdex_length          : %d\n", pOptHeader->dexLength);
		OAT_LOGI("\tdeps_offset         : %d (0x%06x)\n",
				pOptHeader->depsOffset, pOptHeader->depsOffset);
		OAT_LOGI("\tdeps_length         : %d\n", pOptHeader->depsLength);
		OAT_LOGI("\topt_offset          : %d (0x%06x)\n",
				pOptHeader->optOffset, pOptHeader->optOffset);
		OAT_LOGI("\topt_length          : %d\n", pOptHeader->optLength);
		OAT_LOGI("\tflags               : %08x\n", pOptHeader->flags);
		OAT_LOGI("\tchecksum            : %08x\n", pOptHeader->checksum);
	} else {
		OAT_LOGI("Optimized DEX file header is Invalid !!!!!\n");
	}
	OAT_LOGI("\n");

	if ((pHeader != NULL) && (pHeader == pDexFile->baseAddr)) {
		OAT_LOGI("DEX file header:\n");
		asciify(sanitized, pHeader->magic, sizeof(pHeader->magic));
		OAT_LOGI("\tmagic               : '%s'\n", sanitized);
		OAT_LOGI("\tchecksum            : %08x\n", pHeader->checksum);
		OAT_LOGI("\tsignature           : %02x%02x...%02x%02x\n",
				pHeader->signature[0], pHeader->signature[1],
				pHeader->signature[kSHA1DigestLen-2],
				pHeader->signature[kSHA1DigestLen-1]);
		OAT_LOGI("\tfile_size           : %d (0x%08x)\n", pHeader->fileSize, pHeader->fileSize);
		OAT_LOGI("\theader_size         : %d\n", pHeader->headerSize);
		OAT_LOGI("\tlink_size           : %d\n", pHeader->linkSize);
		OAT_LOGI("\tlink_off            : %d (0x%06x)\n",
				pHeader->linkOff, pHeader->linkOff);
		OAT_LOGI("\tstring_ids_size     : %d\n", pHeader->stringIdsSize);
		OAT_LOGI("\tstring_ids_off      : %d (0x%06x)\n",
				pHeader->stringIdsOff, pHeader->stringIdsOff);
		OAT_LOGI("\ttype_ids_size       : %d\n", pHeader->typeIdsSize);
		OAT_LOGI("\ttype_ids_off        : %d (0x%06x)\n",
				pHeader->typeIdsOff, pHeader->typeIdsOff);
		OAT_LOGI("\tproto_ids_size      : %d\n", pHeader->protoIdsSize);
		OAT_LOGI("\tproto_ids_off       : %d (0x%06x)\n",
				pHeader->protoIdsOff, pHeader->protoIdsOff);
		OAT_LOGI("\tfield_ids_size      : %d\n", pHeader->fieldIdsSize);
		OAT_LOGI("\tfield_ids_off       : %d (0x%06x)\n",
				pHeader->fieldIdsOff, pHeader->fieldIdsOff);
		OAT_LOGI("\tmethod_ids_size     : %d\n", pHeader->methodIdsSize);
		OAT_LOGI("\tmethod_ids_off      : %d (0x%06x)\n",
				pHeader->methodIdsOff, pHeader->methodIdsOff);
		OAT_LOGI("\tclass_defs_size     : %d\n", pHeader->classDefsSize);
		OAT_LOGI("\tclass_defs_off      : %d (0x%06x)\n",
				pHeader->classDefsOff, pHeader->classDefsOff);
		OAT_LOGI("\tdata_size           : %d\n", pHeader->dataSize);
		OAT_LOGI("\tdata_off            : %d (0x%06x)\n\n",
				pHeader->dataOff, pHeader->dataOff);
		return True;
	} else { 
		OAT_LOGI("DEX file header is Invalid !!!!!\n");
	}
	return False;
}

/* 2.1.1.1
 * Dump a map in the "differential" format.
 *
 * TODO: show a hex dump of the compressed data.  (We can show the
 * uncompressed data if we move the compression code to libdex; otherwise
 * it's too complex to merit a fast & fragile implementation here.)
 */
void dumpDifferentialCompressedMap(const UChar** pData)
{
	const UChar* data = *pData;
	const UChar* dataStart = data -1;      // format byte already removed
	UChar regWidth;
	UShort numEntries;

	/* standard header */
	regWidth = *data++;
	numEntries = *data++;
	numEntries |= (*data++) << 8;

	/* compressed data begins with the compressed data length */
	Int compressedLen = readUnsignedLeb128(&data);
	Int addrWidth = 1;
	if ((*data & 0x80) != 0)
		addrWidth++;

	Int origLen = 4 + (addrWidth + regWidth) * numEntries;
	Int compLen = (data - dataStart) + compressedLen;

	OAT_LOGI("        (differential compression %d -> %d [%d -> %d])\n",
			origLen, compLen,
			(addrWidth + regWidth) * numEntries, compressedLen);

	/* skip past end of entry */
	data += compressedLen;

	*pData = data;
}

/* 2.1.1
 * Dump register map contents of the current method.
 *
 * "*pData" should poInt to the start of the register map data.  Advances
 * "*pData" to the start of the next map.
 */
void dumpMethodMap(struct DexFile* pDexFile, const struct DexMethod* pDexMethod, Int idx,
		const UChar** pData)
{
	const UChar* data = *pData;
	const struct DexMethodId* pMethodId;
	const HChar* name;
	Int offset = data - (UChar*) pDexFile->pOptHeader;

	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	if(pMethodId == NULL)
		return;
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	OAT_LOGI("      #%d: 0x%08x %s\n", idx, offset, name);

	UChar format;
	Int addrWidth;

	format = *data++;
	if (format == 1) {              /* kRegMapFormatNone */
		/* no map */
		OAT_LOGI("        (no map)\n");
		addrWidth = 0;
	} else if (format == 2) {       /* kRegMapFormatCompact8 */
		addrWidth = 1;
	} else if (format == 3) {       /* kRegMapFormatCompact16 */
		addrWidth = 2;
	} else if (format == 4) {       /* kRegMapFormatDifferential */
		dumpDifferentialCompressedMap(&data); // 2.1.1.1
		goto bail;
	} else {
		OAT_LOGI("        (unknown format %d!)\n", format);
		/* don't know how to skip data; failure will cascade to end of class */
		goto bail;
	}

	if (addrWidth > 0) {
		UChar regWidth;
		UShort numEntries;
		Int idx, addr, byte;

		regWidth = *data++;
		numEntries = *data++;
		numEntries |= (*data++) << 8;

		for (idx = 0; idx < numEntries; idx++) {
			addr = *data++;
			if (addrWidth > 1)
				addr |= (*data++) << 8;

			OAT_LOGI("        %4x:", addr);
			for (byte = 0; byte < regWidth; byte++) {
				OAT_LOGI(" %02x", *data++);
			}
			OAT_LOGI("\n");
		}
	}

bail:
	//if (addrWidth >= 0)
	//    *pData = align32(data);
	*pData = data;
}

/* 2.1 (only present in optimized DEX files)
 * Dump the contents of the register map area.
 *
 * These are only present in optimized DEX files, and the structure is
 * not really exposed to other parts of the VM itself.  We're going to
 * dig through them here, but this is pretty fragile.  DO NOT rely on
 * this or derive other code from it.
 */
static void dumpRegisterMaps(const struct DexFile* pDexFile, const struct MonitorDexFile* pMDexFile)
{
	const UChar* pClassPool = (const UChar*)pDexFile->pRegisterMapPool;
	const UInt*  classOffsets;
	const UChar* ptr;
	UInt numClasses;
	Int baseFileOffset = (UChar*) pClassPool - (UChar*) pDexFile->pOptHeader;
	Int idx;
	/*
		 if (pDexFile->pRegisterMapPool == NULL) {
		 OAT_LOGI("No register maps found\n");
		 return;
		 }
		 */
	if(pClassPool == NULL) {
		OAT_LOGI("No registerMapPool\n");
		return;
	}
	if(pDexFile->pOptHeader == NULL) {
		OAT_LOGI("No registerMapPool\n");
		return;
	}
	ptr = pClassPool;
	numClasses = get4LE(ptr);

	ptr += sizeof(UInt);
	classOffsets = (const UInt*) ptr;

	OAT_LOGI("RMAP begins at offset 0x%07x\n", baseFileOffset);
	OAT_LOGI("Maps for %d classes\n", numClasses);
	for (idx = 0; idx < (Int) numClasses; idx++) {
		const struct DexClassDef* pClassDef;
		const HChar* classDescriptor;

		pClassDef = dexGetClassDef(pDexFile, idx);
		classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);

		OAT_LOGI("%4d: +%d (0x%08x) %s\n", idx, classOffsets[idx],
				baseFileOffset + classOffsets[idx], classDescriptor);

		if (classOffsets[idx] == 0)
			continue;

		/*
		 * What follows is a series of RegisterMap entries, one for every
		 * direct method, then one for every virtual method.
		 */
		struct DexClassData* pClassData;
		const  UChar* pEncodedData;
		const  UChar* data = (UChar*) pClassPool + classOffsets[idx];
		UShort methodCount;
		Int i;

		pEncodedData = dexGetClassData(pDexFile, pClassDef);
		pClassData   = dexReadAndVerifyClassData(&pEncodedData, NULL);
		if (pClassData == NULL) {
			OAT_LOGE("Trouble reading class data\n");
			continue;
		}

		methodCount  = *data++;
		methodCount |= (*data++) << 8;
		data += 2;      /* two pad bytes follow methodCount */
		if (methodCount != pClassData->header.directMethodsSize
				+ pClassData->header.virtualMethodsSize)
		{
			OAT_LOGE("NOTE: method count discrepancy (%d != %d + %d)\n",
					methodCount, pClassData->header.directMethodsSize,
					pClassData->header.virtualMethodsSize);
			/* this is bad, but keep going anyway */
		}

		OAT_LOGI("    direct methods: %d\n",
				pClassData->header.directMethodsSize);
		for (i = 0; i < (Int) pClassData->header.directMethodsSize; i++) {
			dumpMethodMap(pDexFile, &pClassData->directMethods[i], i, &data);
		}

		OAT_LOGI("    virtual methods: %d\n",
				pClassData->header.virtualMethodsSize);
		for (i = 0; i < (Int) pClassData->header.virtualMethodsSize; i++) {
			dumpMethodMap(pDexFile, &pClassData->virtualMethods[i], i, &data);
		}
		VG_(free)(pClassData);
	}
}

/* 2
 * Dump the requested sections of the file.
 */
void processDexFile(struct DexFile* pDexFile)
{
	if( !pDexFile ) {
		OAT_LOGI("Error DexFile\n");
		return;
	}
	dumpRegisterMaps(pDexFile, NULL); // 2.1
	dumpFileHeader(pDexFile, NULL);		// 2.2
	//dexHeaderParse(pDexFile->pHeader);
	dumpOptDirectory(pDexFile, NULL); // 2.3
	dumpClassData(pDexFile, NULL);		// 2.4
}

static
void dumpDexFileBasicPointers(struct DexFile* pDexFile) {
	tl_assert(pDexFile != 0);
	OAT_LOGI("DexFile								:\n");
	OAT_LOGI("\tDexOptHeader				: 0x%08x\n", (Addr)pDexFile->pOptHeader);
	OAT_LOGI("\tDexHeader						: 0x%08x\n", (Addr)pDexFile->pHeader);
	OAT_LOGI("\tDexStringId					: 0x%08x\n", (Addr)pDexFile->pStringIds);
	OAT_LOGI("\tDexTypeIds					: 0x%08x\n", (Addr)pDexFile->pTypeIds);
	OAT_LOGI("\tDexFieldId					: 0x%08x\n", (Addr)pDexFile->pFieldIds);
	OAT_LOGI("\tDexMethodId					: 0x%08x\n", (Addr)pDexFile->pMethodIds);
	OAT_LOGI("\tDexProtoId					: 0x%08x\n", (Addr)pDexFile->pProtoIds);
	OAT_LOGI("\tDexClassDef					: 0x%08x\n", (Addr)pDexFile->pClassDefs);
	OAT_LOGI("\tDexLink							: 0x%08x\n", (Addr)pDexFile->pLinkData);
	OAT_LOGI("\tDexClassLookup			: 0x%08x\n", (Addr)pDexFile->pClassLookup);
	OAT_LOGI("\tRegisterMapPoolAddr	: 0x%08x\n", (Addr)pDexFile->pRegisterMapPool);
	OAT_LOGI("\tbaseAddr						: 0x%08x\n", (Addr)pDexFile->baseAddr);
	OAT_LOGI("\toverhead						: 0x%08x\n", pDexFile->overhead);

}

/* 1.2
 * Set up the basic raw data poInters of a DexFile. This function isn't
 * meant for general use.
 */
void dexFileSetupBasicPoInters(struct DexFile* pDexFile, const UChar* data) {
	struct DexHeader *pHeader		= (struct DexHeader*) data;
	pDexFile->baseAddr		= data;
	pDexFile->pHeader			= pHeader;
	pDexFile->pStringIds	= (const struct DexStringId*)	(data + pHeader->stringIdsOff);
	pDexFile->pTypeIds		= (const struct DexTypeId*)		(data + pHeader->typeIdsOff);
	pDexFile->pFieldIds		= (const struct DexFieldId*)	(data + pHeader->fieldIdsOff);
	pDexFile->pMethodIds	= (const struct DexMethodId*)	(data + pHeader->methodIdsOff);
	pDexFile->pProtoIds		= (const struct DexProtoId*)	(data + pHeader->protoIdsOff);
	pDexFile->pClassDefs	= (const struct ClassDefine*) (data + pHeader->classDefsOff);
	pDexFile->pLinkData		= (const struct DexLink*)			(data + pHeader->linkOff);
}

/* 1.1
 * (documented in header file) 
 * */
Bool dexParseOptData(const UChar* data, UInt length, struct DexFile* pDexFile)
{
	const void* pOptStart = data + pDexFile->pOptHeader->optOffset;
	const void* pOptEnd		= data + length;
	const UInt* pOpt			= (const UInt*) pOptStart;
	UInt optLength				= (const UChar*) pOptEnd - (const UChar*) pOptStart;

	/*
	 * Make sure the opt data start is in range and aligned. This may
	 * seem like a superfluous check, but (a) if the file got
	 * truncated, it might turn out that pOpt >= pOptEnd; and (b)
	 * if the opt data header got corrupted, pOpt might not be
	 * properly aligned. This test will catch both of these cases.
	 */
	if (!isValidPoInter(pOpt, pOptStart, pOptEnd)) {
		OAT_LOGE("Bogus opt data start pointer(0x%08x 0x%08x 0x%08x)",
				pOpt, pOptStart, pOptEnd);
		return False;
	}

	/* Make sure that the opt data length is a whole number of words. */
	if ((optLength & 3) != 0) {
		OAT_LOGE("Unaligned opt data area end");
		return False;
	}

	/*
	 * Make sure that the opt data area is large enough to have at least
	 * one chunk header.
	 */
	if (optLength < 8) {
		OAT_LOGE("Undersized opt data area (%u)", optLength);
		return False;
	}

	/* Process chunks until we see the end marker. */
	while (*pOpt != kDexChunkEnd) {
		if (!isValidPoInter(pOpt + 2, pOptStart, pOptEnd)) {
			const UInt offset = ((const UChar*) pOpt) - data;
			OAT_LOGE("Bogus opt data content poInter at offset %u", offset);
			return False;
		}

		UInt size = *(pOpt + 1);
		const UChar* pOptData = (const UChar*) (pOpt + 2);

		/*
		 * The rounded size is 64-bit aligned and includes +8 for the
		 * type/size header (which was extracted immediately above).
		 */
		UInt roundedSize = (size + 8 + 7) & ~7;
		const UInt* pNextOpt = pOpt + (roundedSize / sizeof(UInt));

		if (!isValidPoInter(pNextOpt, pOptStart, pOptEnd)) {
			const UInt offset = ((const UChar*) pOpt) - data;
			OAT_LOGE("Opt data area problem for chunk of size %u at offset %u", size, offset);
			return False;
		}

		switch (*pOpt) {
			case kDexChunkClassLookup:
				pDexFile->pClassLookup = (const struct DexClassLookup*) pOptData;
				break;
			case kDexChunkRegisterMaps:
				OAT_LOGI("+++ found register maps, size=%u", size);
				pDexFile->pRegisterMapPool = pOptData;
				break;
			default:
				OAT_LOGI("Unknown chunk 0x%08x (%c%c%c%c), size=%d in opt data area",
						*pOpt,
						(HChar) ((*pOpt) >> 24), (HChar) ((*pOpt) >> 16),
						(HChar) ((*pOpt) >> 8),  (HChar)  (*pOpt),
						size);
				break;
		}

		pOpt = pNextOpt;
	}

	return True;
}

/* 1   
 * Parse an optimized or unoptimized .dex file sitting in memory.  This is
 * called after the byte-ordering and structure alignment has been fixed up.
 *       
 * On success, return a newly-allocated DexFile.
 */  
struct DexFile* dexFileParse(UChar* dexBuf, UInt length) {
	UInt j = 0;

	struct DexMethodId *method_id_list;
	struct DexFieldId	*field_id_list;
	struct DexStringId *string_id_list;
	struct DexTypeId   *type_id_list;
	struct DexProtoId  *proto_id_list;
	UInt  offset = 0;
	struct DexFile* pDexFile = NULL;

	pDexFile = (struct DexFile*) VG_(malloc)("Dex.file.parse.DexFile", sizeof(struct DexFile));
	VG_(memset)((Addr)pDexFile, 0, sizeof(struct DexFile));
	HChar *magic, *data = (HChar*)dexBuf;
	/*
	 * Peel off the optimized header.
	 */

	if (VG_(memcmp)(data, DEX_OPT_MAGIC, 4) == 0) {
		magic = data;
		if (VG_(memcmp)(magic+4, DEX_OPT_MAGIC_VERS, 4) != 0) {
			OAT_LOGI("bad opt version (0x%02x %02x %02x %02x)\n",
					magic[4], magic[5], magic[6], magic[7]);
			goto bail;
		}

		pDexFile->pOptHeader = (const struct DexOptHeader*) data;
		OAT_LOGI("Good opt header, DEX offset is %u, flags=0x%02x\n",
				pDexFile->pOptHeader->dexOffset, pDexFile->pOptHeader->flags);

		/* parse the optimized dex file tables */
		if (!dexParseOptData(data, length, pDexFile)) {
			goto bail;
		}

		/* ignore the opt header and appended data from here on out */
		data += pDexFile->pOptHeader->dexOffset;
		length -= pDexFile->pOptHeader->dexOffset;

		if (pDexFile->pOptHeader->dexLength > length) {
			OAT_LOGE("File truncated? stored len=%d, rem len=%d",
					pDexFile->pOptHeader->dexLength, (Int) length);
			goto bail;
		}
		length = pDexFile->pOptHeader->dexLength;
	} else {
		OAT_LOGI("No OPT MAGIC found.\n");
	}

	dexFileSetupBasicPoInters(pDexFile, data);
	struct DexHeader* dh = pDexFile->pHeader;

	/* Check magic number */
	if(VG_(memcmp)(dh->magic, DEX_MAGIC, 4) != 0) {
		OAT_LOGI("Error: unrecongnized magic number (%02x %02x %02x %02x).\n", 
				dh->magic[0], dh->magic[1], dh->magic[2], dh->magic[3]);
	}


	/* TBD: Verify the checksum(s) */
	/* TBD: Verify the SHA-1 digest. */


	if( dh->fileSize > length ) {
		OAT_LOGI("ERROR: stored file size (0x%08x) < expected (0x%08x)\n",
				(UInt)dh->fileSize, length);
		goto bail;
	}
	if (dh->classDefsSize == 0) {
		OAT_LOGI("ERROR: DEX file has no classes in it, failing");
		goto bail;
	}

	//dump(fd, dexOffset+dex_file_offset, dh.fileSize);

	return pDexFile;
bail:
	if(pDexFile != NULL) {
		VG_(free)(pDexFile);
		pDexFile = NULL;
	}
	OAT_LOGI("Failure.\n");
	return pDexFile;
}

void dexHeaderParse( struct DexHeader* dh) 
{
	if( !dh ) {
		OAT_LOGI("Error dex header\n");
		return;
	}
	OAT_LOGI("DEX Header:\n");
	OAT_LOGI("\tDEX magic							: ");
	for(Int j=0;j<8;j++) OAT_LOGI("%02x ", dh->magic[j]);
	OAT_LOGI("\n");
	OAT_LOGI("\tDEX version						: %s\n", &dh->magic[4]);
	OAT_LOGI("\tAdler32 checksum			: 0x%x\n", dh->checksum);
	OAT_LOGI("\tDex file size					: %d (0x%x)\n", dh->fileSize, dh->fileSize);
	OAT_LOGI("\tDex header size				: %d (0x%x)\n", dh->headerSize, dh->headerSize);
	OAT_LOGI("\tEndian Tag						: 0x%x\n", dh->endianTag);
	OAT_LOGI("\tLink size							: %d\n", dh->linkSize);
	OAT_LOGI("\tLink offset						: 0x%x\n", dh->linkOff);
	OAT_LOGI("\tMap list offset				: 0x%x\n", dh->mapOff);
	OAT_LOGI("\tNumber of strings in string ID list: %d\n", dh->stringIdsSize);
	OAT_LOGI("\tString ID list offset	: 0x%x\n", dh->stringIdsOff);
	OAT_LOGI("\tNumber of types in the type ID list: %d\n", dh->typeIdsSize);
	OAT_LOGI("\tType ID list offset		: 0x%x\n", dh->typeIdsOff);
	OAT_LOGI("\tNumber of items in the method prototype ID list: %d\n", dh->protoIdsSize);
	OAT_LOGI("\tMethod prototype ID list offset: 0x%x\n", dh->protoIdsOff);
	OAT_LOGI("\tNumber of item in the field ID list: %d\n", dh->fieldIdsSize);
	OAT_LOGI("\tField ID list offset	: 0x%x\n", dh->fieldIdsOff);
	OAT_LOGI("\tNumber of items in the method ID list: %d\n", dh->methodIdsSize);
	OAT_LOGI("\tMethod ID list offset	: 0x%x\n", dh->methodIdsOff);
	OAT_LOGI("\tNumber of items in the class definitions list: %d\n", dh->classDefsSize);
	OAT_LOGI("\tClass definitions list offset: 0x%x\n", dh->classDefsOff);
	OAT_LOGI("\tData section size			: %d bytes\n", dh->dataSize);
	OAT_LOGI("\tData section offset		: 0x%x\n", dh->dataOff);
	OAT_LOGI("\tNumber of classes in the archive: %d\n\n", dh->classDefsSize);
}


void dumpDexFile(UChar* addr, Int len) {
	struct DexFile* pDexFile = NULL;
#ifndef M_PERFORMANCE
#ifndef ONLY_DUMP
	dumpRawData(addr, len, 0, "dex");
#endif
#endif
	pDexFile = dexFileParse(addr, len);
	if( !pDexFile ) {
		OAT_LOGI("Error DexFile\n");
		return;
	}

	if (!isValidPoInter(pDexFile->pRegisterMapPool, pDexFile->baseAddr, addr+len)) {
		OAT_LOGE("Bogus pRegisterMapPool pointer(0x%08x 0x%08x 0x%08x)\n",
				pDexFile->pRegisterMapPool, pDexFile->baseAddr, addr+len);
	} else {
		dumpRegisterMaps(pDexFile, NULL); // 2.1
	}

	dumpFileHeader(pDexFile, NULL);		// 2.2

	if (!isValidPoInter(pDexFile->pOptHeader, addr, addr+len)) {
		OAT_LOGE("Bogus pOptHeader  pointer(0x%08x 0x%08x 0x%08x)\n",
				pDexFile->pOptHeader, pDexFile->baseAddr, addr+len);
	} else {
		dumpOptDirectory(pDexFile, NULL); // 2.3
	}
	dumpClassData(pDexFile, NULL);		// 2.4
}


void DexMemParse(UChar* addr, Int len) {
	struct DexFile* pDexFile = NULL;
	OAT_LOGD("Try to parse Dex file memaory map 0x%08x-0x%08x\n",
			addr, addr+len);
	pDexFile = dexFileParse(addr, len);
	if(pDexFile)
		processDexFile(pDexFile);
}


/*--- For propogate data from original Dex file to clone memory of Dex File ---*/
/*
	 Bool copyDexFileHead(const struct MonitorDexFile* pMDexFile) {
	 return True;
	 }
	 Bool copyDexFileClass(const struct MonitorDexFile* pMDexFile, Int idx) {
	 return True;
	 }
	 Bool copyDexFileMethod(const struct MonitorDexFile* pMDexFile, const struct DexMethod* pMethod) {
	 return True;
	 }
	 */
#define APPEND_MEM		0x4000000  // 1M
struct MonitorDexFile* createDexFileMem(const struct DexFile* pDexFile, Addr addr, UInt len) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if( pMDexFile == NULL)			
		pMDexFile = addDexFileList(pDexFile);
	tl_assert(pMDexFile);

	if( len > 16 * 1024 * 1024 ) {
		OAT_LOGI("The dex file memory is too large !!!!\n");
		return NULL;
	}
	if( len <  108 ) {
		OAT_LOGI("The dex file memory is too small !!!!\n");
		return NULL;
	}
	if(pMDexFile->cloneMem == NULL) {
		OAT_LOGD("Try to create clone memory for DexFile 0x%08x\n", (Addr)pDexFile);
		pMDexFile->cloneMem = (Addr)VG_(malloc)("Clone.dex.file.mem", len+APPEND_MEM);
		tl_assert(pMDexFile->cloneMem);
		VG_(memcpy)(pMDexFile->cloneMem, (UChar*)addr, len);
		OAT_LOGD("Clone memory 0x%08x-0x%08x to 0x%08x-0x%08x for DexFile 0x%08x\n", 
				addr, addr+len, pMDexFile->cloneMem, pMDexFile->cloneMem+len,(Addr)pDexFile);
		pMDexFile->cloneLen = len;
		pMDexFile->lastAddr = pMDexFile->cloneMem+len+APPEND_MEM;
		pMDexFile->endAddr  = pMDexFile->cloneMem+len;
		pMDexFile->pDexFileClone = (struct DexFile*)VG_(malloc)("Clone.DexFile.struct", sizeof(struct DexFile));
	} else {
		OAT_LOGD("Clone memory for DexFile 0x%08x has been created\n", (Addr)pDexFile);
		return pMDexFile;
	}
	tl_assert(pMDexFile->pDexFileClone);
	struct DexFile* pDexFileClone = pMDexFile->pDexFileClone;
	const UInt offset = (Addr)pMDexFile->cloneMem - addr;
	pMDexFile->offset = offset;
	if(pDexFile->pOptHeader) {
		pDexFileClone->pOptHeader				= (Addr)pDexFile->pOptHeader	+	offset;
		if(pDexFile->pRegisterMapPool)
			pDexFileClone->pRegisterMapPool = (Addr)pDexFile->pRegisterMapPool + offset;
		else
			pDexFileClone->pRegisterMapPool = NULL;
	} else {
		pDexFileClone->pOptHeader				= NULL; //(Addr)pDexFile->pOptHeader	+	offset;
		pDexFileClone->pRegisterMapPool = NULL; //(Addr)pDexFile->pRegisterMapPool + offset;
	}
	pDexFileClone->pHeader			= (Addr)pDexFile->pHeader			+ offset;
	pDexFileClone->pStringIds		= (Addr)pDexFile->pStringIds	+ offset;
	pDexFileClone->pTypeIds			= (Addr)pDexFile->pTypeIds		+ offset;
	pDexFileClone->pFieldIds		= (Addr)pDexFile->pFieldIds		+ offset;
	pDexFileClone->pMethodIds		= (Addr)pDexFile->pMethodIds	+ offset;
	pDexFileClone->pProtoIds		= (Addr)pDexFile->pProtoIds	  + offset;
	pDexFileClone->pClassDefs   = (Addr)pDexFile->pClassDefs	+ offset;
	pDexFileClone->pLinkData		= (Addr)pDexFile->pLinkData		+ offset;
	pDexFileClone->pClassLookup  = (Addr)pDexFile->pClassLookup+ offset;
	pDexFileClone->baseAddr			= (Addr)pDexFile->baseAddr		+ offset;
	pDexFileClone->overhead			= pDexFile->overhead;

	pMDexFile->baseAddr = 	pDexFileClone->baseAddr;

	OAT_LOGI("Clone DexFile 0x%08x is created for DexFile 0x%08x!\nbaseAddr=0x%08x endAddr=0x%08x\n", 
			(Addr)pDexFileClone, (Addr)pDexFile, pMDexFile->baseAddr, pMDexFile->endAddr);
	dumpFileHeader(pDexFileClone, NULL);
	return pMDexFile;
#else
	return NULL;
#endif
}
static INLINE Bool isCloneMemValid(const struct DexFile* pDexFile, const struct MonitorDexFile* pMDexFile) {
	if(pMDexFile == NULL) {
		OAT_LOGI("Error: The DexFile 0x%08x is not under monitoring!\n", (Addr)pDexFile);
		return False;
	}
	if(pMDexFile->cloneMem == NULL || pMDexFile->pDexFileClone == NULL) {
		OAT_LOGI("Error: The DexFile 0x%08x is not cloned!\n", (Addr)pDexFile);
		return False;
	}
	return True;
}
Bool copyDexFileOptHeader(const struct DexFile* pDexFile) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;

	const struct DexOptHeader* pOptHeader = pDexFile->pOptHeader;
	if( pOptHeader == NULL ) {
		OAT_LOGI("No DexOptHeader of DexFile 0x%08x found for coping.\n", (Addr)pDexFile);
		return False;
	}
	tl_assert(pMDexFile->baseAddr-(Addr)pMDexFile->cloneMem == (Addr)pOptHeader->dexOffset);
	if(pOptHeader->dexLength > pMDexFile->cloneLen) {
		OAT_LOGI("Warning: dexLength %d in OptDexHeader of DexFile 0x%08x is larger than length %d of clone memory!!!\n", 
				pOptHeader->dexLength,	(Addr)pDexFile, pMDexFile->cloneLen);
	}
	VG_(memcpy)((Addr)pMDexFile->pDexFileClone->pOptHeader, (Addr)pOptHeader, sizeof(struct DexOptHeader));
	OAT_LOGD("OptDexHeader of DexFile 0x%08x is copied to clone mem range 0x%08x\n", 
			(Addr)pDexFile, (Addr)pMDexFile->cloneMem);

	const UChar* pOptStart = (UChar*)pOptHeader+pOptHeader->optOffset;
	const UChar* pCloneOptStart = (UChar*)pMDexFile->pDexFileClone->pOptHeader + pOptHeader->optOffset;
	const UChar* pOptEnd   = (UChar*)pOptHeader+pOptHeader->dexLength;
	const UInt*	 pOpt			 = (const UInt*)pOptStart;
	const UInt	 optLength = pOptEnd - pOptStart;

	if (!isValidPoInter(pOpt, pOptStart, pOptEnd)) {
		OAT_LOGE("Bogus opt data start pointer(0x%08x 0x%08x 0x%08x)",
				pOpt, pOptStart, pOptEnd);
		return False;
	}
	/* Make sure that the opt data length is a whole number of words. */
	if ((optLength & 3) != 0) {
		OAT_LOGE("Unaligned opt data area end");
		return False;
	} 
	/*
	 * Make sure that the opt data area is large enough to have at least
	 * one chunk header.
	 */
	if (optLength < 8) {
		OAT_LOGE("Undersized opt data area (%u)", optLength);
		return False; 
	}
	VG_(memcpy)(pCloneOptStart, pOptStart, optLength);
	OAT_LOGD("OptData of DexFile 0x%08x is copied to clone mem range 0x%08x\n", 
			(Addr)pDexFile, (Addr)pMDexFile->cloneMem);
	pMDexFile->state |= DEXOPTDATA;
#endif
	return True;
}

Bool copyDexFileHead(const struct DexFile* pDexFile) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;
	tl_assert(pDexFile->pHeader == pDexFile->baseAddr);
	tl_assert(pDexFile->pHeader->headerSize == sizeof(struct DexHeader));
	VG_(memcpy)(pMDexFile->baseAddr, pDexFile->baseAddr, pDexFile->pHeader->headerSize);
	pMDexFile->state |= DEXHEAD;
	OAT_LOGD("DexHeader of DexFile 0x%08x is copied to clone mem range 0x%08x\n", 
			(Addr)pDexFile, (Addr)pMDexFile->cloneMem);
#endif
	return True;
}

/* During interpreting we just copy the instructions and the other parmeters we accquired just after method loadMethodFromDex */
Bool copyMthCode(const struct DexFile* pDexFile, const struct Method* pMethod) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	Bool isCloned = True;
	if(pMethod->insns == NULL)
	{
		return False;
	}
	if(pMDexFile == NULL) 
		isCloned = False;
	else if(pMDexFile->cloneMem==NULL)
		isCloned = False;
	if(isCloned == False)
	{
		OAT_LOGD("Meet new DexFile 0x%08x when copy method code.\n", (Addr)pDexFile);
		if(pMethod->clazz == NULL)
			return False;
		struct DvmDex* pdd		= pMethod->clazz->pDvmDex;
		if(pdd == NULL)
			return False;
		struct MemMapping* mm	= &pdd->memMap;
		pMDexFile = meetDexFile(pDexFile, mm->addr, mm->length, 1);
		if(pMDexFile == NULL)
			return False;
		//dumpDexFile(mm->addr, mm->length);
		OAT_LOGD("Created clone memory for  new DexFile 0x%08x\n", (Addr)pDexFile);
	}
	const struct DexFile*	pDexFileClone = pMDexFile->pDexFileClone;
	const struct DexCode* pDexCode = (struct DexCode*)((Addr)pMethod->insns - 0x10);
	const	UInt							offset = (Addr)pDexCode - (Addr)pDexFile->baseAddr;
	const struct DexCode* pDexCode1= (struct DexCode*)((Addr)pDexFileClone->baseAddr + offset);
	/*if ( (Addr)pDexCode1 - (Addr)pDexCode != pMDexFile->offset ) {
		OAT_LOGI("Warning: the offset of DexCode mis-match 0x%08x 0x%08x offset=0x%08x (0x%08x)!!\n",	
		(Addr)pDexCode, (Addr)pDexCode1, (Addr)pDexCode1-(Addr)pDexCode, pMDexFile->offset);
		processDexFile(pDexFile);
		processDexFile(pDexFileClone);
		return False;
		}*/
	if (!isValidPoInter(pDexCode1, pMDexFile->baseAddr, pMDexFile->endAddr)) {
		OAT_LOGI("Warning: thd offset of DexCode (0x%08x) is out of the clone memory!!\n",
				(Addr)pDexCode1);
		//processDexFile(pDexFile);
		//processDexFile(pDexFileClone);
		return False;
	}
	if (!isValidPoInter(pDexCode1->insns, pMDexFile->baseAddr, pMDexFile->endAddr)) {
		OAT_LOGI("Warning: thd offset of insns (0x%08x) is out of the clone memory!!\n",
				(Addr)pDexCode1->insns);
		//processDexFile(pDexFile);
		//processDexFile(pDexFileClone);
		return False;
	}

	OAT_LOGD("Try to copy method insn form 0x%08x to pDexCode1->insns 0x%08x size %d (%d).\n", 
			(Addr)pDexCode->insns, pDexCode1->insns, pDexCode->insnsSize, pDexCode1->insnsSize);
	VG_(memcpy)((Addr)pDexCode1, (Addr)pDexCode, sizeof(struct DexCode));
	VG_(memcpy)(pDexCode1->insns, pDexCode->insns, pDexCode1->insnsSize * sizeof(UShort));
#endif
	return True;
}

/* Copy DexCodeItem */
static	Bool copyMethod(struct MonitorDexFile* pMDexFile, 
		const struct DexFile* pDexFile, const struct DexFile* pDexFileClone, 
		const struct DexMethod* pDexMethod) {
#ifdef	TRACE_DEX_FILE_DATA
	struct DexFile* pDexFile1;
	if(pDexFileClone == NULL) {
		struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
		if(isCloneMemValid(pDexFile, pMDexFile) == False)
			return False;
		pDexFile1 = pMDexFile->pDexFileClone;
	} else {
		pDexFile1 = pDexFileClone;
	}
	if( pDexMethod->codeOff == NULL) {
		OAT_LOGD("Warning: DexCode of DexMethod 0x%08x is invalid.\n", 
				pDexMethod->codeOff, (Addr)pDexMethod);
		return False;
	}
	const struct DexCode* pDexCode = (struct DexCode*)(pDexFile->baseAddr + pDexMethod->codeOff);
	struct DexCode* pDexCode1= (struct DexCode*)(pDexFile1->baseAddr + pDexMethod->codeOff);
	OAT_LOGD("Try to copy DexCode off 0x%0x (0x%0x) of DexFile 0x%08x\n", pDexMethod->codeOff, 
			pDexCode->insnsSize, (Addr)pDexFile);
#ifndef M_PERFORMANCE
#ifndef ONLY_DUMP
	dumpMethod(pDexFile, pDexMethod, -1);
#endif
#endif
	VG_(memcpy)((Addr)pDexCode1, (Addr)pDexCode, sizeof(struct DexCode));
	if(pDexFile1->baseAddr + pDexCode1->debugInfoOff > pMDexFile->endAddr) {
		OAT_LOGI("Warning: Debug info is out of the memory range!!\n");
		pDexCode1->debugInfoOff = 0;
	}
	UInt len = pDexCode->insnsSize*sizeof(UShort);
	if(pDexCode->insnsSize > 0) {
		// Adapt to ALI
		if((Addr)pDexCode1->insns > pMDexFile->endAddr) {
			if((Addr)pDexCode1->insns+len < pMDexFile->lastAddr) {
				pMDexFile->endAddr = (Addr)pDexCode1->insns + len;
			} else {
				OAT_LOGI("Error:DexCode is not in allocated memory\n"); 
				return False;
			}
		}
		OAT_LOGD("Try to copy ins 0x%08x DexFile 0x%08x to ins 0x%08x\n", 
				pDexCode->insns, (Addr)pDexFile, pDexCode1->insns);
		VG_(memcpy)((Addr)pDexCode1->insns, (Addr)pDexCode->insns, pDexCode->insnsSize * sizeof(UShort));
	}
#endif
	return True;
}

Bool copyDexClass(const struct DexFile* pDexFile, Int idx, HChar* desc) {
#ifdef	TRACE_DEX_FILE_DATA
	const struct DexClassDef*		pClassDef		= dexGetClassDef(pDexFile, idx);
	if(desc) {
		const HChar* classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);
		if(VG_(strcmp)(classDescriptor, desc) != 0)
			return False;
		OAT_LOGD("\nTry to copy class %s of DexFile 0x%0x\n", desc, (Addr)pDexFile);
	} else
		OAT_LOGD("\nTry to copy class %d of DexFile 0x%0x\n", idx, (Addr)pDexFile);

	HChar *package = NULL;
	//OAT_LOGI("Source class:\n");
	//dumpClassDef(pDexFile, idx);				// 2.4.1
	//dumpClass(pDexFile, idx, &package);
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	const struct DexFile*	pDexFileClone = pMDexFile->pDexFileClone;
	struct DexClassDef*		pClassDef1	= dexGetClassDef(pDexFileClone, idx);

	/* Clone DexClassDef */
#if 0
	if(pClassDef->classDataOff > pMDexFile->cloneLen)
	{
		OAT_LOGI("Error: ClassDataOff 0x%x is larger than clone memory 0x%d.\n",
				pClassDef->classDataOff, pMDexFile->cloneLen);
	}
#endif

	UInt len = 0;
	Int  i   = 0;

	OAT_LOGD("Try to copy DexClassDef in class %d of DexFile 0x%08x 0x%08x/0x%08x\n", 
			idx, (Addr)pDexFile, (Addr)pClassDef1, (Addr)pClassDef);
	VG_(memcpy)((UChar*)pClassDef1, (UChar*)pClassDef, sizeof(struct DexClassDef));

	/* Clone interface */
	const struct DexTypeList* pInterfaces		= dexGetInterfacesList(pDexFile, pClassDef);
	OAT_LOGD("Try to copy interface in class %d of DexFile 0x%08x\n", idx, (Addr)pDexFile);
	if(pInterfaces != NULL && pInterfaces->size > 0) {
		len = sizeof(struct DexTypeItem) * pInterfaces->size + sizeof(UInt);
		if(pClassDef1->interfacesOff > (pMDexFile->endAddr - pMDexFile->baseAddr))
		{
			pClassDef1->interfacesOff = (pMDexFile->endAddr - pMDexFile->baseAddr);
			OAT_LOGI("Warning: Class interfaces off 0x%x is larger than clone memory 0x%x new 0x%x.\n",
					pClassDef->interfacesOff, pMDexFile->cloneLen, pClassDef1->classDataOff);
			pMDexFile->endAddr += len;
		}
		const struct DexTypeList* pInterfaces1	= dexGetInterfacesList(pDexFileClone, pClassDef1);
		OAT_LOGD("Try to copy interface in class %d of DexFile 0x%0x\n", idx, (Addr)pDexFile);
		//pInterfaces1->size = pInterfaces->size;
		len = sizeof(struct DexTypeItem) * pInterfaces->size + sizeof(UInt);
		VG_(memcpy)((Addr)pInterfaces1, (Addr)pInterfaces, len);
		OAT_LOGD("%d interfaces in class %d of DexFile 0x%0x have been copied\n", 
				pInterfaces->size, idx, (Addr)pDexFile);
	}
	/* Clone Class Data */
	OAT_LOGD("Try to copy ClassData in class %d of DexFile 0x%0x\n", idx, (Addr)pDexFile);
	const UChar*								pEncodeData	= dexGetClassData(pDexFile,  pClassDef);
	const UChar*								pData				= pEncodeData;
	const struct DexClassData*	pClassData	= dexReadAndVerifyClassData(&pData, NULL);
	len	= (Addr)pData - (Addr)pEncodeData;
	if (pClassData == NULL) {
		OAT_LOGI("Trouble reading class data (#%d) for coping\n", idx);
		return False;
	}

	if((UInt)pClassDef1->classDataOff > (pMDexFile->endAddr - pMDexFile->baseAddr))
	{
		pClassDef1->classDataOff = (pMDexFile->endAddr - pMDexFile->baseAddr);
		OAT_LOGI("Warning: Class data off 0x%x is larger than clone memory 0x%x new 0x%x.\n",
				pClassDef->classDataOff, pMDexFile->cloneLen, pClassDef1->classDataOff);
		pMDexFile->endAddr += len;
	}

	OAT_LOGD("Origi baseAddr 0x%08x classDataOff 0x%08x\n", (Addr)pDexFile->baseAddr, pClassDef->classDataOff); 
	OAT_LOGD("Clone baseAddr 0x%08x classDataOff 0x%08x\n", (Addr)pDexFileClone->baseAddr, pClassDef1->classDataOff);

	const UChar*								pEncodeData1= dexGetClassData(pDexFileClone, pClassDef1);
	OAT_LOGD("Try to copy Encodedata from 0x%08x to 0x%08x len=%d basaddr 0x%08x\n", 
			(Addr)pEncodeData, (Addr)pEncodeData1, len, pDexFileClone->baseAddr);
	VG_(memcpy)(pEncodeData1, pEncodeData, len);

	/* Clone Method */
	OAT_LOGD("Try to copy %d directMethods in class %d of DexFile 0x%0x\n", 
			(Int)pClassData->header.directMethodsSize, idx, (Addr)pDexFile);
	for(i = 0; i < (Int)pClassData->header.directMethodsSize; i++) {
		copyMethod(pMDexFile, pDexFile, pDexFileClone, &pClassData->directMethods[i]);
	}
	OAT_LOGD("Try to copy %d virtualMethods in class %d of DexFile 0x%0x\n", 
			(Int)pClassData->header.virtualMethodsSize, idx, (Addr)pDexFile);
	for(i = 0; i < (Int)pClassData->header.virtualMethodsSize; i++) {
		copyMethod(pMDexFile, pDexFile, pDexFileClone, &pClassData->virtualMethods[i]);
	}

	/* Release pClassData */
	if(pClassData) {
		VG_(free)(pClassData);
	}
	//OAT_LOGI("Dest class:\n");
	//dumpClassDef(pDexFileClone, idx);
	//dumpClass(pDexFileClone, idx, &package);
#endif
	return True;
}

Bool copyAllClasses(const struct DexFile* pDexFile) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;
	Int i = 0;
	OAT_LOGD("Try to copy all classes of DexFile 0x%08x\n", (Addr)pDexFile);
	for(i = 0; i < (Int)pDexFile->pHeader->classDefsSize; i++) {
		if(copyDexClass(pDexFile, i, NULL) == False) {
			OAT_LOGI("Copy class %d of DexFile 0x%08x error.\n", i, (Addr)pDexFile);
			return False;
		}
	}
	OAT_LOGD("Copied  %d classes of DexFile 0x%08x.\n", i, (Addr)pDexFile);
#endif
	return True;
}

struct MonitorDexFile* meetDexFile(const struct DexFile* pDexFile, Addr addr, UInt len, UInt state)
{
#ifdef	TRACE_DEX_FILE_DATA
	if(pDexFile == NULL)
		return NULL;
	/* state 1: Just create clone memory and copy dex data */
	OAT_LOGD("Meet DexFile 0x%08x at 0x%08x-0x%08x\n", (Addr)pDexFile, addr, addr+len);
#if 0
	if(!(pDexFile->baseAddr >= addr) || !((pDexFile->pHeader->fileSize+pDexFile->baseAddr) <= (addr+len)))
	{
		OAT_LOGI("Size of DexFile 0x%08x is larger then mapped memory 0x%08x-0x%08x\n",
				(Addr)pDexFile, addr, addr+len);
		return False;
	}
#endif
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	Bool isCloned = False;
	if(pMDexFile) {
		if(pMDexFile->cloneLen > 0) {
			isCloned = True;
		}
	}
	if(isCloned == False)	{
		OAT_LOGI("Find no clone dex file for DexFile 0x%08x\n",
				(Addr)pDexFile);
		if(addr == 0 || len < 108)
			return NULL;
		pMDexFile = createDexFileMem(pDexFile, addr, len);
		if(pMDexFile == NULL)
			return NULL;
	} else {
		OAT_LOGD("Clone memory 0x%08x-0x%08x for DexFile 0x%08x has been created.\n", 
				(Addr)pMDexFile->cloneMem, (Addr)pMDexFile->cloneMem+pMDexFile->cloneLen, (Addr)pDexFile);
	}

	if(state == 1) {
		return pMDexFile;
	}
	/* state 2: copy class data */
	if(state == 2) {
		if( (pMDexFile->state & DEXCLASS) == 0) {
			OAT_LOGD("Try to copy classes of DexFile 0x%08x.\n", (Addr)pDexFile);
			//processDexFile(pDexFile);
			if(copyAllClasses(pDexFile)){
				;//pMDexFile->state |= DEXCLASS;
				return pMDexFile;
			} else {
				return NULL;
			}
		} else {
			OAT_LOGD("Class of DexFile 0x%08x has been copied.\n", (Addr)pDexFile);
			return pMDexFile;
		}
	}
#endif
	return NULL;
}

Bool copyOneClass(const struct DexFile* pDexFile, HChar* desc) {
#ifdef	TRACE_DEX_FILE_DATA
	if(pDexFile == NULL)
		return False;
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;
	Int i = 0;
	OAT_LOGD("Try to copy one class %s of DexFile 0x%08x\n", 
			desc,(Addr)pDexFile);

	for(i = 0; i < (Int)pDexFile->pHeader->classDefsSize; i++) {
		if(copyDexClass(pDexFile, i, desc) == True) {
			OAT_LOGD("Copy one class %s of DexFile 0x%08x successfully.\n", desc, (Addr)pDexFile);
			return True;
		}
	}
	OAT_LOGI("Cope one class %s of DexFile 0x%08x falture.\n", desc, (Addr)pDexFile);
#endif
	return False;
}

/* The following codes are for collecting DexCode of apps packed by IJIAMI_1603.
 * Because the insns address of Method is different the insns address of DexCode.
 * It modify the insns addresses of the all created Methods just before the dvmDefineClass
 * returns.
 */
static struct Method* getMethod(struct Method* mth, Int count, 
		const HChar* name, const HChar* shorty) {
	for(Int i = 0; i < count; i++) {
		if(VG_(strcmp)(name, mth[i].name) == 0 && VG_(strcmp)(shorty, mth[i].shorty)==0)
			return &mth[i];
	}
	return NULL;
}

static Bool getMethodCode(struct DexFile *pDexFile, struct DexMethod* pDexMethod, struct Method *mths, Int count)
{
	const struct DexMethodId* pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	if(pMethodId == NULL)
		return;
	const HChar*			 name			 = dexStringById(pDexFile, pMethodId->nameIdx);
	struct DexProto    proto;
	dexProtoSetFromMethodId(&proto, pDexFile, pMethodId);
	const HChar*			 shorty		 = dexProtoGetShorty(&proto);
	const struct Method *pMethod = getMethod(mths, count, name, shorty);
	if( pMethod == NULL ) {
		OAT_LOGI("Error: Found no method %s(%s)\n", name, shorty);
		return False;
	}
	const struct DexCode* pDexCode = (struct DexCode*)(pDexFile->baseAddr + pDexMethod->codeOff);
	if(pDexCode->insnsSize > 0) {
		OAT_LOGD("Copy insn of method %s(%s) from 0x%08x to 0x%08x size=%d\n", name, shorty,
				(Addr)pMethod->insns, (Addr)pDexCode->insns, pDexCode->insnsSize);
		VG_(memcpy)(pDexCode->insns, pMethod->insns, pDexCode->insnsSize * sizeof(UShort));
	}
	return True;
}

Bool getClassMethods(const struct DexFile *pDexFile, struct ClassObject *pClazz) {
#ifdef	TRACE_DEX_FILE_DATA
	if((pDexFile == NULL) || (pClazz == NULL))
		return False;
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;

	Int i = 0;
	const struct DexFile*	pDexFileClone = pMDexFile->pDexFileClone;
	struct DexClassDef*		pClassDef		= NULL;
	HChar* classDescriptor =  NULL ;
	OAT_LOGD("Try to get method code of class %s in DexFile 0x%08x\n", 
			pClazz->descriptor,(Addr)pDexFileClone);


	for(i = 0; i < (Int)pDexFileClone->pHeader->classDefsSize; i++) {
		pClassDef		= dexGetClassDef(pDexFileClone, i);
		classDescriptor = dexStringByTypeIdx(pDexFileClone, pClassDef->classIdx);
		if(VG_(strcmp)(classDescriptor, pClazz->descriptor) == 0)
			break;
	}
	if( i == (Int)pDexFileClone->pHeader->classDefsSize ) {
		OAT_LOGI("Warning: Found no class %s in DexFile 0x%08x.\n", 
				pClazz->descriptor, (Addr)pDexFileClone);
		return False;
	} else {
		OAT_LOGD("Found class %s with id %d in DexFile 0x%08x.\n", 
				pClazz->descriptor, i, (Addr)pDexFileClone);
	}

	const UChar*								pEncodeData	= dexGetClassData(pDexFileClone,  pClassDef);
	const struct DexClassData*	pClassData	= dexReadAndVerifyClassData(&pEncodeData, NULL);
	tl_assert(pClassData != NULL);

	if( pClazz->directMethodCount != pClassData->header.directMethodsSize ) {
		OAT_LOGI("Warning: number of direct methods mis-match!!!\n");
		return False;
	}
	if( pClazz->virtualMethodCount != pClassData->header.virtualMethodsSize ) {
		OAT_LOGI("Warning: number of virtual methods mis-match!!!\n");
		return False;
	}

	for(i = 0; i < (Int)pClassData->header.directMethodsSize; i++) {
		if(getMethodCode(pDexFileClone, &pClassData->directMethods[i], pClazz->directMethods, pClazz->directMethodCount) == False)
			return False;
	}
	for(i = 0; i < (Int)pClassData->header.virtualMethodsSize; i++) {
		if(getMethodCode(pDexFileClone, &pClassData->virtualMethods[i], pClazz->virtualMethods, pClazz->virtualMethodCount) == False)
			return False;
	}
	if(pClassData)
		VG_(free)(pClassData);

#endif
	return False;
}

#ifdef TRACE_ART_PLATFORM
static struct DexFile *DexFilePlus2DexFile(struct DexFilePlus *pDexFilePlus) {
	struct DexFilePlusNode *pNode = pDexFilePlusList;
	while(pNode) {
		if(pNode->pDexFilePlus == pDexFilePlus)
			break;
		pNode = pNode->next;
	}
	if(pNode)
		return pNode->pDexFile;

	pNode = (struct DexFilePlusNode*)VG_(malloc)("new.DexFilePlus.node", sizeof(struct DexFilePlusNode));
	VG_(memset)((Addr)pNode, 0, sizeof(struct DexFilePlusNode));
	struct DexFile *pDexFile = (struct DexFile*)VG_(malloc)("new.dexfile", sizeof(struct DexFile));
	VG_(memset)((Addr)pDexFile, 0, sizeof(struct DexFile));
	pDexFile->pHeader = pDexFilePlus->header_;
	pDexFile->pStringIds = pDexFilePlus->string_ids_;
	pDexFile->pTypeIds   = pDexFilePlus->type_ids_;
	pDexFile->pFieldIds  = pDexFilePlus->field_ids_;
	pDexFile->pMethodIds = pDexFilePlus->method_ids_;
	pDexFile->pProtoIds  = pDexFilePlus->proto_ids_;
	pDexFile->pClassDefs = pDexFilePlus->class_defs_;
	pDexFile->baseAddr   = pDexFilePlus->begin_;

	pNode->pDexFilePlus  = pDexFilePlus;
	pNode->pDexFile			 = pDexFile;
	pNode->next = pDexFilePlusList;
	return pDexFile;
}
struct MonitorDexFile* meetDexFilePlus(const struct DexFilePlus* pDexFilePlus, Addr addr, UInt len, UInt state)
{
	struct DexFile *pDexFile = DexFilePlus2DexFile(pDexFilePlus);
	tl_assert(pDexFile);
	return meetDexFile(pDexFile, addr, len, state);
}


/* Process the methodd during execution for both DVM and ART */

/* parse the loaded method to list for tracking */
Bool parseLoadedMethod(const struct DexFilePlus* pDexPlus, const struct ArtMethod* pAMth, HChar** psClass, HChar** psMth, HChar** psShorty)
{
	struct DexMethodId *pMethodId = NULL;
	HChar* className = NULL;
	HChar* mthName   = NULL;
	HChar* shorty    = NULL;
	struct DexProto proto;
	struct DexFile* pDex = DexFilePlus2DexFile(pDexPlus); 
	if(!pDex || !pAMth) 
		return False;
	if((pAMth->dex_code_item_offset_ == 0)) { // JNI method or method to be intepreted
		if(pAMth->access_flags_ & ACC_NATIVE == 0) { // Not JNI method
			return False;
		}
	}
	// VG_(printf)("test: 1 pDexPlus=0x%08x dex_method_index=%d\n", (Addr)pDex, pAMth->dex_method_index_);
	pMethodId = dexGetMethodId(pDex, pAMth->dex_method_index_);
	className = NULL;
	mthName   = NULL;
	shorty    = NULL;
	if(pMethodId == NULL)
		return False;
	
	// VG_(printf)("test: 2 0x%08x %d %d %d\n", (Addr)pMethodId, pMethodId->classIdx, pMethodId->protoIdx, pMethodId->nameIdx);

	className = dexStringByTypeIdx(pDex, pMethodId->classIdx);
	mthName		= dexStringById(pDex, pMethodId->nameIdx);
	dexProtoSetFromMethodId(&proto, pDex, pMethodId);
	shorty		= dexProtoGetShorty(&proto);
	*psClass = className;
	*psMth   = mthName;
	*psShorty= shorty;
	return True;
}

Bool getMethodSignature(const struct DexFile *pDex, Int idx, HChar** psClass, HChar** psMth, HChar** psShorty)
{
	struct DexMethodId* pMethodId = dexGetMethodId(pDex, idx);
	struct DexProto proto;
	if(pMethodId == NULL)
		return False;
	OAT_LOGI("[0] DexMethodId: 0x%08x 0x%08x 0x%08x\n",
			pMethodId->classIdx,
			pMethodId->nameIdx,
			pMethodId->protoIdx);
	*psClass = dexStringByTypeIdx(pDex, pMethodId->classIdx);
	*psMth   = dexStringById(pDex, pMethodId->nameIdx);
	dexProtoSetFromMethodId(&proto, pDex, pMethodId);
	*psShorty= dexProtoGetShorty(&proto);
	OAT_LOGI("[1] DexMethodId: 0x%08x 0x%08x 0x%08x\n",
			(Addr)*psClass, (Addr)*psMth, (Addr)*psShorty);
	return True;
}
#endif

