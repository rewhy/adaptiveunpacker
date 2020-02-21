// oatparse.c

#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_mallocfree.h"

#include "bevgrind.h"
#include "bg_oatdexparse.h"

extern Bool BG_(is_parse_dex);
extern Bool BG_(is_full_trace);
extern UInt	 packer_type;

#ifdef TRACE_ART_PLATFORM
#include "bg_oatparse.c"
#endif
/* -------------- Monitor Dex File List ----------------------------*/
static struct MonitorDexFile *dexFileList = NULL;
/* Used for dump the dex files */
static Int file_index = 0;
Bool dumpRawData(UChar* buf, UInt size, Addr a) {
	tl_assert(buf != NULL);
	Int fout;
	HChar fpath[255];
	VG_(sprintf)(fpath, "/data/local/tmp/dex/0x%08x-0x%08x-%d.dex", (Addr)buf, a, file_index++);
	fout = VG_(fd_open)(fpath, VKI_O_WRONLY|VKI_O_TRUNC, 0);
	if (fout <= 0) {
		fout = VG_(fd_open)(fpath, VKI_O_CREAT|VKI_O_WRONLY, VKI_S_IRUSR|VKI_S_IWUSR);
		if( fout <= 0 ) {
			OAT_LOGI("Create Dex file error.\n");
			return;
		}
	} 
	OAT_LOGI("Try to dump dex file %s 0x%08x-0x%08x\n", 
			fpath, (Addr)buf, (Addr)buf+size);
	VG_(write)(fout, buf, size);
	VG_(close)(fout);
	return True;
}

Bool dumpRawData1(UChar* buf, UInt size, Addr a) {
	tl_assert(buf != NULL);
	Int fout;
	HChar fpath[255];
	VG_(sprintf)(fpath, "/data/local/tmp/dex/0x%08x-%d.dex", a, file_index++);
	fout = VG_(fd_open)(fpath, VKI_O_WRONLY|VKI_O_TRUNC, 0);
	if (fout < 0) {
		fout = VG_(fd_open)(fpath, VKI_O_CREAT|VKI_O_WRONLY, VKI_S_IRUSR|VKI_S_IWUSR);
		if( fout < 0 ) {
			OAT_LOGI("Create Dex file error %d.\n", fout);
			return;
		}
	} 
	OAT_LOGI("Try to dump dex file %s \n", fpath);
	VG_(write)(fout, buf, size);
	VG_(close)(fout);
	return True;
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
	tfl->pid = VG_(getpid)();
	dexFileList = tfl;
	OAT_LOGI("Added new dex file 0x%08x\n", (Addr)pDexFile);
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

static struct DexFile* dexFileParse(UChar* dexBuf, UInt length);

void releaseDexFileList() {
	struct MonitorDexFile* tfl = dexFileList;
	struct MonitorDexFile* pfl = dexFileList;
	struct DexHeader			*pHeader = NULL;
	UInt fileLen = 0;
	if(tfl) {
		if(tfl->pid != VG_(getpid)())
			return;
	}
	VG_(printf)("Will release DexFile list.\n");
	//added by ws
	Int i = 0;
	while(tfl) {
		pfl = tfl;
		tfl = tfl->next;
		if(pfl->cloneMem)
		{
			pHeader = pfl->pDexFileClone->pHeader;
			fileLen = ((pfl->endAddr-(Addr)pHeader) & ~3) + 0x4;
			pHeader->fileSize = fileLen;
			pHeader->checksum = dexComputeChecksum(pHeader);
			OAT_LOGI("release DexFile : %d 0x%08x 0x%08x.\n", 
					i++, pfl->pDexFile, (Addr)pfl->pDexFileClone);
			//BG_(is_parse_dex) = False; //
			if(packer_type == 4 && i == 1) {
				processDexFile(pfl->pDexFileClone);
				//dumpClassData(pfl->pDexFileClone, NULL);		// 2.4
				u4 length = 0;
				u1* temp_mem = reassembleAndDumpDexClone(pfl->pDexFileClone, &length);
				//dumpDexFile((Addr)temp_mem, length);

				dumpRawData1((Addr)temp_mem, length, (Addr)pfl->pDexFile);
				VG_(free)(temp_mem);

				//struct DexFile* dexFile = dexFileParse(temp_mem, length);
			} else {
				dumpRawData1((Addr)pHeader, fileLen, (Addr)pfl->pDexFile);
				processDexFile(pfl->pDexFileClone);
				//dumpDexFile((Addr)pHeader, fileLen);
			}
			VG_(free)(pfl->cloneMem);
		}
		if(pfl->pDexFileClone)
			VG_(free)(pfl->pDexFileClone);
		VG_(free)(pfl);
		dexFileList = tfl;
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
	dexFileList = NULL;
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
 * Converts a single-HCharacter primitive type Into its human-readable
 * equivalent.
 */
static const HChar* primitiveTypeLabel(HChar typeChar)
{
	switch (typeChar) {
		case 'B':   return "byte";
		case 'C':   return "HChar";
		case 'D':   return "double";
		case 'F':   return "float";
		case 'I':   return "Int";
		case 'J':   return "long";
		case 'S':   return "short";
		case 'V':   return "void";
		case 'Z':   return "Boolean";
		default:
								return "UNKNOWN";
	}
}

/*
 * Converts a type descriptor to human-readable "dotted" form.  For
 * example, "Ljava/lang/String;" becomes "java.lang.String", and
 * "[I" becomes "Int[]".  Also converts '$' to '.', which means this
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
 * Reads an unsigned LEB128 value, updating the given poInter to poInt
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
 * Reads a signed LEB128 value, updating the given poInter to poInt
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
 * Returns the updated poInter.
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
 * Reads an unsigned LEB128 value, updating the given poInter to poInt
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
 * Reads a signed LEB128 value, updating the given poInter to poInt
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
 * updates the given data poInter to poInt past the end of the read
 * data. */
INLINE void dexReadClassDataHeader(const UChar** pData,
		struct DexClassDataHeader *pHeader) {
	pHeader->staticFieldsSize   = readUnsignedLeb128(pData);
	pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
	pHeader->directMethodsSize  = readUnsignedLeb128(pData);
	pHeader->virtualMethodsSize = readUnsignedLeb128(pData); 
}

/* Read an encoded_field without verification. This updates the
 * given data poInter to poInt past the end of the read data.
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
 * given data poInter to poInt past the end of the read data.
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
 * one Into any other function.
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
 * If the given DexStringCache doesn't already poInt at the given value,
 * make a copy of it Into the cache. This always returns a writable
 * poInter to the contents (whether or not a copy had to be made). This
 * function is Intended to be used after making a call that at least
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
 * proto of a MethodId. The returned poInter must be free()ed by the
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
			"IntERFACE",        /* 0x0200 */
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
 * Dump the catches table associated with the code.
 */
/*
	 void dumpCatches(DexFile* pDexFile, const DexCode* pCode) {
	 u4 triesSize = pCode->triesSize;

	 if (triesSize == 0) {
	 printf("      catches       : (none)\n");    
	 return;
	 }
	 printf("      catches       : %d\n", triesSize);
	 const DexTry* pTries = dexGetTries(pCode); 
	 u4 i;

	 for (i = 0; i < triesSize; i++) {
	 const DexTry* pTry = &pTries[i];
	 u4 start = pTry->startAddr;
	 u4 end = start + pTry->insnCount;
	 DexCatchIterator iterator;
	 printf("        0x%04x - 0x%04x\n", start, end);
	 dexCatchIteratorInit(&iterator, pCode, pTry->handlerOff);

	 for (;;) {
	 DexCatchHandler* handler = dexCatchIteratorNext(&iterator);
	 const char* descriptor;
	 if (handler == NULL) {
	 break;
	 }
	 descriptor = (handler->typeIdx == kDexNoIndex) ? "<any>" : dexStringByTypeIdx(pDexFile, handler->typeIdx);
	 printf("          %s -> 0x%04x\n", descriptor,  handler->address);
	 }
	 }
	 }*/

/*
 * Dump a "code" struct.
 */
	static 
void dumpCode(const struct DexCode *pCode, Int i)
{
	OAT_LOGI("      code          -	0x%08x\n", (Addr)pCode);
	OAT_LOGI("      registers     : %d\n", pCode->registersSize);
	OAT_LOGI("      ins           : %d\n", pCode->insSize);
	OAT_LOGI("      outs          : %d\n", pCode->outsSize);
	OAT_LOGI("      tries         : %d\n", pCode->triesSize);
	OAT_LOGI("      debugInfoOff  : 0x%08x\n", pCode->debugInfoOff);
	OAT_LOGI("      insns         : %d\n", pCode->insnsSize);
	OAT_LOGI("      insns size    : %d (0x%08x-0x%08x) 16-bit code units\n", 
			pCode->insnsSize, (Addr)pCode->insns, (Addr)pCode->insns+((pCode->insnsSize-1) * 2));
#if 0 // output Dalvik code
	if(pCode->insnsSize > 0 /*&& i < 0*/)
	{
		OAT_LOGI("			FOR DEBUG			:");
#if OAT_DEBUG
		for(Int i = 0; i < pCode->insnsSize; i++)
			VG_(printf)(" 0x%04x", pCode->insns[i]);
		VG_(printf)("\n");
#endif
	}
#endif
	//added by ws
	//dumpCatches(pDexFile, pCode);
	/* both of these are encoded in debug info */
	//dumpPositions(pDexFile, pCode, pDexMethod);
	//dumpLocals(pDexFile, pCode, pDexMethod);

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
	if (pDexMethod == NULL) {
		OAT_LOGI(" method == NULL and return\n");
		return;	
	}
#if 0
	if (gOptions.exportsOnly &&
			(pDexMethod->accessFlags & (ACC_PUBLIC | ACC_PROTECTED)) == 0)
	{
		return;
	}
#endif

	pMethodId = dexGetMethodId(pDexFile, pDexMethod->methodIdx);
	name = dexStringById(pDexFile, pMethodId->nameIdx);
	typeDescriptor = dexCopyDescriptorFromMethodId(pDexFile, pMethodId);

	backDescriptor = dexStringByTypeIdx(pDexFile, pMethodId->classIdx);

	accessStr = createAccessFlagStr(pDexMethod->accessFlags,
			kAccessForMethod);

	OAT_LOGI("    #%d             : (in %s)\n", i, backDescriptor);
	OAT_LOGI("      name          : '%s'\n", name);
	OAT_LOGI("      type          : '%s'\n", typeDescriptor);
	OAT_LOGI("      access        : 0x%04x (%s)\n",
			pDexMethod->accessFlags, accessStr);
	OAT_LOGI("      code off      : %d (0x%04x)\n", pDexMethod->codeOff, pDexMethod->codeOff);

	if (pDexMethod->codeOff == 0) {
		OAT_LOGI("      code          : (none)\n");
	} else {
		struct DexCode* pCode = dexGetCode(pDexFile, pDexMethod);
#ifdef IJIAMI_1603
		if((Addr)pCode >= ((Addr)pDexFile->pHeader + pDexFile->pHeader->fileSize)) {
			OAT_LOGI("Warning: DexCode 0x%08x is out of the memory range!!\n", (Addr)pCode);
			return;
		}
		if(pCode->debugInfoOff > pDexFile->pHeader->fileSize) {
			OAT_LOGI("Warning: Debug info of code 0x%08x is out of the memory range!!\n", (Addr)pCode);
			pCode->debugInfoOff = 0;
		}
#endif
		dumpCode(pCode, i);
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
 * Dump an Interface that a class declares to implement.
 */
void dumpInterface(const struct DexFile* pDexFile, const struct DexTypeItem* pTypeItem,
		Int i)
{
	const UChar* InterfaceName =
		dexStringByTypeIdx(pDexFile, pTypeItem->typeIdx);

	//if (gOptions.outputFormat == OUTPUT_PLAIN) {
	if (1) {
		OAT_LOGI("    #%d              : '%s'\n", i, InterfaceName);
	} else {
		UChar* dotted = descriptorToDot(InterfaceName);
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
	if (pEncodedData == NULL) {
		OAT_LOGI("Trouble reading class data (#%d)\n", idx);
		goto bail;
	}
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
	/* 2.4.2.1 Parse Interfaces */
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
	OAT_LOGI("start to dump class def.\n");
	const struct DexClassDef* pClassDef;
	const UChar* pEncodedData;
	struct DexClassData* pClassData;

	pClassDef			= dexGetClassDef(pDexFile, idx);
	OAT_LOGI("start to dump class def,  got ClassDef,  pDexFile->baseAddr: %08x,  pClassDef->classDataOff: %d.\n", pDexFile->baseAddr, pClassDef->classDataOff);
	pEncodedData	= dexGetClassData(pDexFile, pClassDef);
	OAT_LOGI("start to dump class def,  got encoded class data.\n");
	pClassData		= dexReadAndVerifyClassData(&pEncodedData, NULL);
	OAT_LOGI("start to dump class def,  read and parsed to get class data.\n");
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
	OAT_LOGI("start to dump class data.\n");
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
#if 0
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
#endif
/* 2
 * Dump the requested sections of the file.
 */
void processDexFile(struct DexFile* pDexFile)
{
	if( !pDexFile ) {
		OAT_LOGI("Error DexFile\n");
		return;
	}
	OAT_LOGI("processDexFile-- dump the requested sections of the file 0x%08x\n", (Addr)pDexFile);
	//dumpRegisterMaps(pDexFile, NULL); // 2.1
	dumpFileHeader(pDexFile, NULL);		// 2.2
	//dexHeaderParse(pDexFile->pHeader);
	if(BG_(is_parse_dex)) {
		dumpOptDirectory(pDexFile, NULL); // 2.3
		dumpClassData(pDexFile, NULL);		// 2.4
	}
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
		OAT_LOGE("Bogus opt data start poInter(0x%08x 0x%08x 0x%08x)",
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
static struct DexFile* dexFileParse(UChar* dexBuf, UInt length) {
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


	if( dh->fileSize != length ) {
		OAT_LOGI("ERROR: stored file size (0x%08x) != expected (0x%08x)",
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
//#ifndef M_PERFORMANCE
#if 0
	dumpRawData(addr, len, 0);
	struct DexFile* dexFile = dexFileParse(addr, len);
	u4 length = 0;
	u1* temp_mem = reassembleAndDumpDexClone(dexFile, &length);    
	dumpRawData1((Addr)temp_mem, length, dexFile);
	VG_(free)(temp_mem);
#endif
	pDexFile = dexFileParse(addr, len);
	if( !pDexFile ) {
		OAT_LOGI("Error DexFile\n");
		return;
	}

	if (!isValidPoInter(pDexFile->pRegisterMapPool, pDexFile->baseAddr, addr+len)) {
		OAT_LOGE("Bogus pRegisterMapPool poInter(0x%08x 0x%08x 0x%08x)\n",
				pDexFile->pRegisterMapPool, pDexFile->baseAddr, addr+len);
	} else {
		dumpRegisterMaps(pDexFile, NULL); // 2.1
	}

	dumpFileHeader(pDexFile, NULL);		// 2.2

	if (!isValidPoInter(pDexFile->pOptHeader, addr, addr+len)) {
		OAT_LOGE("Bogus pOptHeader  poInter(0x%08x 0x%08x 0x%08x)\n",
				pDexFile->pOptHeader, pDexFile->baseAddr, addr+len);
	} else {
		dumpOptDirectory(pDexFile, NULL); // 2.3
	}
	dumpClassData(pDexFile, NULL);		// 2.4
}
void DexMemParse(UChar* addr, Int len) {
	struct DexFile* pDexFile = NULL;
	OAT_LOGD("Try to parse DEX file memaory map 0x%08x-0x%08x\n",
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

static INLINE Bool isMemAvailable(Addr base, UInt len, Addr begAddr, Addr endAddr) {
	if ((base >= begAddr) && (base < endAddr) && (base+len <= endAddr))
		return True;
	else
		return False;
}
#define APPEND_MEM		0x4000000  // 64M
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
		OAT_LOGE("Bogus opt data start poInter(0x%08x 0x%08x 0x%08x)",
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

	//dumpCode(pDexCode, -1);
	//dumpCode(pDexCode1, -1);
#endif
	return True;
}

/* Copy DexCodeItem */
static Bool copyMethod(struct MonitorDexFile* pMDexFile, 
		const struct DexFile* pDexFile, const struct DexFile* pDexFileClone, 
		const struct DexMethod* pDexMethod, struct DexMethod* pDexMethod1) {
	OAT_LOGI("start to copy method 0--pDexFile=0x%08x------pDexMethod=0x%08x 0x%08x\n", 
			(Addr)pDexFile, (Addr)pDexMethod, (Addr)pDexMethod1);
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
	OAT_LOGI("start to copy method 1--pDexFile=0x%08x 0x%08x------pDexMethod=0x%08x 0x%08x\n", 
			(Addr)pDexFile, (Addr)pDexFile1, (Addr)pDexMethod, (Addr)pDexMethod1);
	//const struct DexCode* pDexCode = (struct DexCode*)(pDexFile->baseAddr + pDexMethod->codeOff);
	//const struct DexCode* pDexCode1= (struct DexCode*)(pDexFile1->baseAddr + pDexMethod1->codeOff);
	const struct DexCode* pDexCode = dexGetCode(pDexFile, pDexMethod);
	struct DexCode* pDexCode1= dexGetCode(pDexFile1, pDexMethod1);


	//  OAT_LOGI("dump method code before copy\n");
	//OAT_LOGI("pDexMethod--------------\n");
	//   dumpMethod(pDexFile, pDexMethod, -1);

	if (pDexCode == NULL) {
		OAT_LOGI("Warning: DexCode of DexMethod  is invalid.\n");
		pDexMethod1->codeOff = 0;
		return False;
	}

	if(BG_(is_full_trace)) {
		dumpMethod(pDexFile, pDexMethod, -1);
	}
	// OAT_LOGI("start to copy method---------------------2\n");
	//added by ws

	UInt codeSize = getDexCodeSize(pDexCode, NULL);
	if(isMemAvailable(pDexCode1, codeSize, pMDexFile->baseAddr, pMDexFile->endAddr) == False) {
		pDexCode1 = NULL;
	}

	OAT_LOGI("Try to copy DexCode off 0x%0x  of DexFile 0x%08x to DexCode1 off 0x%0x  of DexFile 0x%08x size=%d\n", 
			pDexMethod->codeOff, (Addr)pDexFile, pDexMethod1->codeOff, (Addr) pDexFile1, codeSize);

	UInt end_offset = pMDexFile->endAddr - pMDexFile->baseAddr; 

	if (!(pDexMethod1->codeOff  + codeSize > end_offset)) {
		UInt codeSize1 = (pDexCode1 == NULL ? 0 : getDexCodeSize(pDexCode1, pMDexFile));
		if ( codeSize1 < 0 || codeSize1 > 65535) {
			codeSize1 = 0;
		}
		if(isMemAvailable(pDexCode1, codeSize1, pMDexFile->baseAddr, pMDexFile->endAddr)) {
			if (codeSize <= codeSize1) {
				OAT_LOGI("Try to copy DexCode codeAddr: 0x%08x/0x%08x codeSize: %d , codeSize1: %d\n", (Addr)pDexCode, (Addr)pDexCode1, codeSize, codeSize1);
				VG_(memset)((Addr)pDexCode1, 0, codeSize1);
				VG_(memcpy)((Addr)pDexCode1, (Addr)pDexCode, codeSize);
				return True;
			}
		} else {
			codeSize1 = 0;
		}
	} 

	// 4-bytes align
	while (end_offset & 3) {
		end_offset++;
	}
	UInt save_offset = end_offset;

	end_offset += codeSize;
	// 4-bytes align
	while (end_offset & 3) {
		end_offset++;
	}
	if (pDexCode != NULL) {
		if (pMDexFile->baseAddr + end_offset > pMDexFile->lastAddr) {
			OAT_LOGI("Error: copy DexCode, the allocated clone memory is not enough\n"); 
			return 0;
		} else {
			VG_(memcpy)((Addr)pMDexFile->baseAddr + save_offset, (Addr)pDexCode, codeSize);
			pMDexFile->endAddr =  pMDexFile->baseAddr + end_offset;
			pDexMethod1->codeOff = save_offset;
		}   
	}  
	pDexCode1= dexGetCode(pDexFile1, pDexMethod1);
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
				OAT_LOGD("Error:DexCode is not in allocated memory\n"); 
				return False;
			}
		}
		OAT_LOGI("Try to copy ins 0x%08x DexFile 0x%08x to ins 0x%08x\n", 
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
		OAT_LOGI("\nTry to copy class %s of DexFile 0x%0x\n", desc, (Addr)pDexFile);
	} else {
		OAT_LOGI("\nTry to copy class %d of DexFile 0x%0x\n", idx, (Addr)pDexFile);
	}

	HChar *package = NULL;
	if (BG_(is_parse_dex)) {
		OAT_LOGI("Source class:\n");
		dumpClassDef(pDexFile, idx);				// 2.4.1
		dumpClass(pDexFile, idx, &package);
	}

	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	const struct DexFile*	pDexFileClone = pMDexFile->pDexFileClone;
	struct DexClassDef*     pClassDef1   = dexGetClassDef(pDexFileClone, idx);

	/* Clone DexClassDef */
#if 1
	if(pClassDef->classDataOff > pMDexFile->cloneLen)
	{
		OAT_LOGI("Error: ClassDataOff 0x%x is larger than clone memory 0x%d.\n",
				pClassDef->classDataOff, pMDexFile->cloneLen);
	}
#endif

	UInt len = 0;
	Int  i   = 0;

	OAT_LOGI("Try to copy DexClassDef in class %d of DexFile 0x%08x 0x%08x/0x%08x\n", 
			idx, (Addr)pDexFile, (Addr)pClassDef1, (Addr)pClassDef);
	VG_(memcpy)((UChar*)pClassDef1, (UChar*)pClassDef, sizeof(struct DexClassDef));

	/* Clone interface */
	const struct DexTypeList* pInterfaces		= dexGetInterfacesList(pDexFile, pClassDef);
	OAT_LOGI("Try to copy interface (0x%08x) in class %d of DexFile 0x%08x\n", (Addr)pInterfaces, idx, (Addr)pDexFile);
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
		OAT_LOGI("Try to copy interface in class %d of DexFile 0x%0x\n", idx, (Addr)pDexFile);
		//pInterfaces1->size = pInterfaces->size;
		len = sizeof(struct DexTypeItem) * pInterfaces->size + sizeof(UInt);
		VG_(memcpy)((Addr)pInterfaces1, (Addr)pInterfaces, len);
		OAT_LOGI("%d interfaces in class %d of DexFile 0x%0x have been copied\n", 
				pInterfaces->size, idx, (Addr)pDexFile);
	}
	/* Clone Class Data */
	OAT_LOGI("Try to clone class data.\n");
	const UChar* pEncodeData = dexGetClassData(pDexFile,  pClassDef);
	const UChar* pData = pEncodeData;
	const struct DexClassData* pClassData = ReadClassData(&pData);
	len = (Addr)pData - (Addr)pEncodeData;

	if (pClassData == NULL) {
		OAT_LOGI("Trouble reading class data (#%d) for coping\n", idx);
		return False;
	}

	UInt len1 = 0;
	UChar*pData1 = NULL;
	struct DexClassData* pClassData1 = NULL;
	const UChar* pEncodeData1= dexGetClassData(pDexFileClone, pClassDef1);
	if(isMemAvailable(pEncodeData1, len, pMDexFile->baseAddr, pMDexFile->endAddr)) {
		pData1 = pEncodeData1;
		pClassData1	= ReadClassData(&pData1);
		len1 = (Addr)pData1 - (Addr)pEncodeData1;
	} else {
		OAT_LOGI("Get clone encode data addr 0x%08x pDexFileClone = 0x%08x.\n", (Addr)pEncodeData1, (Addr)pDexFileClone);
	}

	OAT_LOGI("Try to copy ClassData in class %d of DexFile 0x%0x (size: %d)  to DexFile 0x%0x (size: %d)\n", 
			idx, (Addr)pDexFile, len, pDexFileClone, len1);
	UInt target_off = 0;
	UInt chg_space = 0;

	//if (len + chg_space < len1 && !(pClassDef1->classDataOff  + len > (pMDexFile->endAddr - pMDexFile->baseAddr))) {
	if ((len + chg_space <= len1) && isMemAvailable(pClassDef1->classDataOff,  len,  
				pMDexFile->baseAddr, pMDexFile->endAddr)) { 
		/* The dest memory is available for stroing the encode data */
		VG_(memset)(pEncodeData1, 0, len1);
		VG_(memcpy)(pEncodeData1, pEncodeData, len);
		target_off = pClassDef1->classDataOff;
	} else {
		if (pMDexFile->endAddr + len + chg_space > pMDexFile->lastAddr) {
			/* The cloned memory is not enough to store the encode data */
			OAT_LOGI("Error: copy class data, the allocated clone memory is not enough\n"); 
			return False;
		} else {
			/* Append the code to the end of the clone dex file */
			VG_(memcpy)((Addr)pMDexFile->endAddr, (Addr)pEncodeData, len);
			target_off = pMDexFile->endAddr - pMDexFile->baseAddr;
			pClassDef1->classDataOff = target_off;
			pMDexFile->endAddr =  pMDexFile->endAddr + len + chg_space;
		}   
	}

	if (target_off == 0 || target_off > (pMDexFile->endAddr - pMDexFile->baseAddr)) {
		OAT_LOGI("Error: copy class data the first time\n"); 
		return False;
	}

	if(pClassData1) {
		VG_(free)(pClassData1);
	}

	pEncodeData1= dexGetClassData(pDexFileClone, pClassDef1);
	pData1 = pEncodeData1;
	pClassData1 = ReadClassData(&pData1);


	/* Clone Method */
	OAT_LOGI("Try to copy %d directMethods in class %d of DexFile 0x%0x\n", 
			(Int)pClassData->header.directMethodsSize, idx, (Addr)pDexFile);
	for(i = 0; i < (Int)pClassData->header.directMethodsSize; i++) {
		copyMethod(pMDexFile, pDexFile, pDexFileClone, &pClassData->directMethods[i], &pClassData1->directMethods[i]);
	}
	OAT_LOGI("Try to copy %d virtualMethods in class %d of DexFile 0x%0x\n", 
			(Int)pClassData->header.virtualMethodsSize, idx, (Addr)pDexFile);
	for(i = 0; i < (Int)pClassData->header.virtualMethodsSize; i++) {
		copyMethod(pMDexFile, pDexFile, pDexFileClone, &pClassData->virtualMethods[i], &pClassData1->virtualMethods[i]);
	}


	/* clone class data again*/
	Int length = 0;
	const UChar* tempEncodeData = EncodeClassData(pClassData1, &length);
	VG_(memcpy)((Addr) pMDexFile->baseAddr + target_off, tempEncodeData, length);


	/* Release pClassData */
	OAT_LOGI("Release pClassData and tempEncodeData\n");
	if(pClassData) {
		VG_(free)(pClassData);
	}

	if(tempEncodeData) {
		VG_(free)(tempEncodeData);
	}
	if (BG_(is_parse_dex)) {
		OAT_LOGI("Dest class:\n");
		dumpClassDef(pDexFileClone, idx);
		dumpClass(pDexFileClone, idx, &package);
	}
#endif
	return True;
}


Bool copyAllClasses(const struct DexFile* pDexFile) {
#ifdef	TRACE_DEX_FILE_DATA
	struct MonitorDexFile* pMDexFile = isInDexFileList(pDexFile);
	if(isCloneMemValid(pDexFile, pMDexFile) == False)
		return False;
	Int i = 0;
	OAT_LOGI("Try to copy all classes of DexFile 0x%08x\n", (Addr)pDexFile);
	for(i = 0; i < (Int)pDexFile->pHeader->classDefsSize; i++) {
		const struct DexClassDef* pClassDef = dexGetClassDef(pDexFile, i);
		const HChar* classDescriptor = dexStringByTypeIdx(pDexFile, pClassDef->classIdx);
		if(isFrameworkClass(classDescriptor)) continue;
		if(copyDexClass(pDexFile, i, NULL) == False) {
			OAT_LOGI("Copy class %d of DexFile 0x%08x error.\n", i, (Addr)pDexFile);
			//return False;
		}
	}
	OAT_LOGI("Copied  %d classes of DexFile 0x%08x.\n", i, (Addr)pDexFile);
#endif
	return True;
}


struct MonitorDexFile* meetDexFile(const struct DexFile* pDexFile, Addr addr, UInt len, UInt state) {
#ifdef	TRACE_DEX_FILE_DATA
	if(pDexFile == NULL)
		return NULL;
	/* state 1: Just create clone memory and copy dex data */
	OAT_LOGI("Meet DexFile 0x%08x at 0x%08x-0x%08x\n", (Addr)pDexFile, addr, addr+len);
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
	OAT_LOGI("Meet DexFile 0x%08x at 0x%08x-0x%08x, isCloned: %d\n", (Addr)pDexFile, addr, addr+len, isCloned);
	if(isCloned == False)	{
		OAT_LOGI("Find no clone dex file for DexFile 0x%08x\n",
				(Addr)pDexFile);
		if(addr == 0 || len < 108)
			return NULL;
		pMDexFile = createDexFileMem(pDexFile, addr, len);
		if(pMDexFile == NULL)
			return NULL;
	} else {
		OAT_LOGI("Clone memory 0x%08x-0x%08x for DexFile 0x%08x has been created.\n", 
				(Addr)pMDexFile->cloneMem, (Addr)pMDexFile->cloneMem+pMDexFile->cloneLen, (Addr)pDexFile);
		if(packer_type == 4)
			return pMDexFile;
	}

	if(state == 1) {
		return pMDexFile;
	}
	/* state 2: copy class data */
	if(state == 2) {
		if( (pMDexFile->state & DEXCLASS) == 0) {
			OAT_LOGI("Try to copy classes of DexFile 0x%08x.\n", (Addr)pDexFile);
			//processDexFile(pDexFile);
			if(copyAllClasses(pDexFile)){
				//pMDexFile->state |= DEXCLASS;
				return pMDexFile;
			} else {
				return NULL;
			}
		} else {
			OAT_LOGI("Class of DexFile 0x%08x has been copied.\n", (Addr)pDexFile);
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
	OAT_LOGI("Try to copy one class %s of DexFile 0x%08x\n", 
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
	if((pDexCode->insnsSize) > 0 && (pMethod->insns != NULL)) {
		OAT_LOGD("Copy insn of method %s(%s) from 0x%08x to 0x%08x size=%d\n", name, shorty,
				(Addr)pMethod->insns, (Addr)pDexCode->insns, pDexCode->insnsSize);
		VG_(memcpy)(pDexCode->insns, pMethod->insns, pDexCode->insnsSize * sizeof(UShort));
	} 
	else {
		OAT_LOGI("Error: Get codes (0x%08x->0x%08x %d) of %s error\n", 
				(Addr)pDexCode->insns, (Addr)pMethod->insns, pDexCode->insnsSize, name);
		return False;
	}
	dumpCode(pDexCode, -1);
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
	const UChar*								pStartAddr  = pEncodeData;
	const struct DexClassData*	pClassData	= dexReadAndVerifyClassData(&pEncodeData, NULL);
	if (((Addr)pStartAddr < pMDexFile->baseAddr) || ((Addr)pStartAddr >= pMDexFile->endAddr)) {
		OAT_LOGI("Warning: thd address of EncodeData (0x%08x/0x%08x) is out of the clone memory (0x%08x-0x%08x)!!\n", 
				(Addr)pStartAddr, (Addr)pEncodeData, (Addr)pMDexFile->baseAddr, (Addr)pMDexFile->endAddr);
	}
	tl_assert(pClassData != NULL);

	if( pClazz->directMethodCount != pClassData->header.directMethodsSize ) {
		OAT_LOGI("Warning: number of direct methods mis-match!!!\n");
		return False;
	}
	if( pClazz->virtualMethodCount != pClassData->header.virtualMethodsSize ) {
		OAT_LOGI("Warning: number of virtual methods mis-match!!!\n");
		return False;
	}

	// OAT_LOGD("Try to get methods %d %d\n", (Int)pClassData->header.directMethodsSize, (Int)pClassData->header.virtualMethodsSize);
	for(i = 0; i < (Int)pClassData->header.directMethodsSize; i++) {
		if(getMethodCode(pDexFileClone, &pClassData->directMethods[i], pClazz->directMethods, pClazz->directMethodCount) == False) {
			return False;
		}
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
#endif


/********************************Begin   Dex File Reassemble **********************************************/


#define LOGI 1

/*   The operations for class data items */

/*
 *  Read header info for class data items from uleb128 format value
 */
void ReadClassDataHeader(const u1** pData,
		struct DexClassDataHeader *pHeader) {
	pHeader->staticFieldsSize = readUnsignedLeb128(pData);
	pHeader->instanceFieldsSize = readUnsignedLeb128(pData);
	pHeader->directMethodsSize = readUnsignedLeb128(pData);
	pHeader->virtualMethodsSize = readUnsignedLeb128(pData);
}



void ReadClassDataField(const u1** pData, struct DexField* pField) {
	pField->fieldIdx = readUnsignedLeb128(pData);
	pField->accessFlags = readUnsignedLeb128(pData);
}

void ReadClassDataMethod(const u1** pData, struct DexMethod* pMethod) {
	pMethod->methodIdx = readUnsignedLeb128(pData);
	pMethod->accessFlags = readUnsignedLeb128(pData);
	pMethod->codeOff = readUnsignedLeb128(pData);
}


void writeLeb128(u1 ** ptr, u4 data) {
	while (True) {
		u1 out = data & 0x7f;
		if (out != data) {
			*(*ptr)++ = out | 0x80;
			data >>= 7;
		} else {
			*(*ptr)++ = out;
			break;
		}
	}
}



struct DexClassData* ReadClassData(const u1** pData) {
	struct DexClassDataHeader header;
	if (*pData == NULL) {
		return NULL;
	}
	ReadClassDataHeader(pData, &header);
	u4 resultSize = sizeof(struct DexClassData) + 
		(header.staticFieldsSize * sizeof(struct DexField)) + 
		(header.instanceFieldsSize * sizeof(struct DexField)) + 
		(header.directMethodsSize * sizeof(struct DexMethod)) + 
		(header.virtualMethodsSize * sizeof(struct DexMethod));
	struct DexClassData* result = (struct DexClassData*) VG_(malloc)("New.assemble.dexclassdata", resultSize);
	tl_assert(result);
	VG_(memset)((Addr)result, 0, resultSize);

	u1* ptr = ((u1*) result) + sizeof(struct DexClassData); 
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
	if(header.staticFieldsSize > 0) {
		for (u4 i = 0; i < header.staticFieldsSize; i++) {
			ReadClassDataField(pData, &result->staticFields[i]);
		}
	}
	if(header.instanceFieldsSize > 0) {
		for (u4 i = 0; i < header.instanceFieldsSize; i++) {
			ReadClassDataField(pData, &result->instanceFields[i]);
		}
	}
	if(header.directMethodsSize > 0) {
		for (u4 i = 0; i < header.directMethodsSize; i++) {
			ReadClassDataMethod(pData, &result->directMethods[i]);
		}
	}
	if(header.virtualMethodsSize > 0) {
		for (u4 i = 0; i < header.virtualMethodsSize; i++) {
			ReadClassDataMethod(pData, &result->virtualMethods[i]);
		}
	}
	return result;
}

u1* EncodeClassData(struct DexClassData *pData, Int* len_back) {
	Int len=0;
	len+=unsignedLeb128Size(pData->header.staticFieldsSize);
	len+=unsignedLeb128Size(pData->header.instanceFieldsSize);
	len+=unsignedLeb128Size(pData->header.directMethodsSize);
	len+=unsignedLeb128Size(pData->header.virtualMethodsSize);

	if (pData->staticFields) {
		for (u4 i = 0; i < pData->header.staticFieldsSize; i++) {
			len+=unsignedLeb128Size(pData->staticFields[i].fieldIdx);
			len+=unsignedLeb128Size(pData->staticFields[i].accessFlags);
		}
	}
	if (pData->instanceFields) {
		for (u4 i = 0; i < pData->header.instanceFieldsSize; i++) {
			len+=unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
			len+=unsignedLeb128Size(pData->instanceFields[i].accessFlags);
		}
	}
	if (pData->directMethods) {
		for (u4 i=0; i<pData->header.directMethodsSize; i++) {
			len+=unsignedLeb128Size(pData->directMethods[i].methodIdx);
			len+=unsignedLeb128Size(pData->directMethods[i].accessFlags);
			len+=unsignedLeb128Size(pData->directMethods[i].codeOff);
		}
	}
	if (pData->virtualMethods) {
		for (u4 i=0; i<pData->header.virtualMethodsSize; i++) {
			len+=unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
			len+=unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
			len+=unsignedLeb128Size(pData->virtualMethods[i].codeOff);
		}
	}

	u1* store = (u1*) VG_(malloc)("New.assemble.u1", len);
	tl_assert(store);
	VG_(memset)((Addr)store, 0, len);
	//  u1* store = (u1 *) malloc(len);
	if (!store) {
		return NULL;
	}
	u1 *result = store;

	writeLeb128(&store,pData->header.staticFieldsSize);
	writeLeb128(&store,pData->header.instanceFieldsSize);
	writeLeb128(&store,pData->header.directMethodsSize);
	writeLeb128(&store,pData->header.virtualMethodsSize);

	if (pData->staticFields) {
		for (u4 i = 0; i < pData->header.staticFieldsSize; i++) {
			writeLeb128(&store,pData->staticFields[i].fieldIdx);
			writeLeb128(&store,pData->staticFields[i].accessFlags);
		}
	}
	if (pData->instanceFields) {
		for (u4 i = 0; i < pData->header.instanceFieldsSize; i++) {
			writeLeb128(&store,pData->instanceFields[i].fieldIdx);
			writeLeb128(&store,pData->instanceFields[i].accessFlags);
		}
	}
	if (pData->directMethods) {
		for (u4 i=0; i<pData->header.directMethodsSize; i++) {
			writeLeb128(&store,pData->directMethods[i].methodIdx);
			writeLeb128(&store,pData->directMethods[i].accessFlags);
			writeLeb128(&store,pData->directMethods[i].codeOff);
		}
	}
	if (pData->virtualMethods) {
		for (u4 i=0; i<pData->header.virtualMethodsSize; i++) {
			writeLeb128(&store,pData->virtualMethods[i].methodIdx);
			writeLeb128(&store,pData->virtualMethods[i].accessFlags);
			writeLeb128(&store,pData->virtualMethods[i].codeOff);
		}
	}
	VG_(free)((void*)pData); 
	*len_back = len;
	return result;
}


/* Helper for verifyClassDataItem(), which checks a list of fields. */
Bool verifyFields(struct DexFileData* dexData, u4 size,
		struct DexField* fields, Bool expectStatic) {
	u4 i;

	for (i = 0; i < size; i++) {
		struct DexField* field = &fields[i];
		u4 accessFlags = field->accessFlags;
		Bool isStatic = (accessFlags & ACC_STATIC) != 0;

		if (field->fieldIdx >= dexData->fieldIds->size) {
			OAT_LOGD("GOT IT: field out of range @ %d\n", i);
			return False;
		}

		if (isStatic != expectStatic) {
			OAT_LOGD("GOT IT: Field in wrong list @ %d\n", i);
			return False;
		}

		if ((accessFlags & ~ACC_FIELD_MASK) != 0) {
			// The VM specification says that unknown flags should be ignored.
			OAT_LOGD("GOT IT: Bogus field access flags %x @ %d\n", accessFlags, i);
			field->accessFlags &= ACC_FIELD_MASK;
		}
	}
	return True;
}

u1* codeitem_end(const u1** pData)
{
	Addr start = *pData;
	u4 num_of_list = readUnsignedLeb128(pData);
	for (;num_of_list>0;num_of_list--) {
		Int num_of_handlers=readSignedLeb128(pData);
		Int num=num_of_handlers;
		if (num_of_handlers<=0) {
			num=-num_of_handlers;
		}
		for (; num > 0; num--) {
			readUnsignedLeb128(pData);
			readUnsignedLeb128(pData);
			if((Addr)(*pData) - start > 1024) {
				return NULL;
			}
		}
		if (num_of_handlers<=0) {
			readUnsignedLeb128(pData);
		}
		if((Addr)(*pData) - start > 1024) {
			return NULL;
		}
	}
	return (u1*)(*pData);
}


Int getDexCodeSize(struct DexCode* code, struct MonitorDexFile *pMDexFile) {

	u1 *item=(u1 *) code;
	Int code_item_len = 0;
	if ((Addr)code & 0x3 != 0)
		OAT_LOGI("GOT IT: DexCode addresss error\n");
	if (code->triesSize) {
		const u1 * handler_data = dexGetCatchHandlerData(code);
		if(pMDexFile) {
			if(isMemAvailable(handler_data, 4, pMDexFile->baseAddr, pMDexFile->endAddr) == False) {
				OAT_LOGI("GOT IT: Memory is not available\n");
				return 0;
			}
		}
		const u1** phandler=(const u1**)&handler_data;
		u1 * tail=codeitem_end(phandler);
		if (tail == NULL) {
			OAT_LOGI("OGT IT: Read encode data error\n");
			code_item_len = 16 + code->insnsSize * 2;
		}	else {
			code_item_len = (Int)(tail-item);
		}
	} else {
		code_item_len = 16 + code->insnsSize * 2;
	}

	return code_item_len;

}


/* Helper for verifyClassDataItem(), which checks a list of methods. */
Bool verifyMethods(struct DexFileData* dexData, u4 size,
		struct DexMethod* methods, Bool expectDirect) {
	u4 i;

	for (i = 0; i < size; i++) {
		struct DexMethod* method = &methods[i];

		if (method->methodIdx >= dexData->methodIds->size) {
			OAT_LOGD("GOT IT: Method out of range @ %d\n", i);
			return False;
		}

		u4 accessFlags = method->accessFlags;
		Bool isDirect =
			(accessFlags & (ACC_STATIC | ACC_PRIVATE | ACC_CONSTRUCTOR)) != 0;
		Bool expectCode = (accessFlags & (ACC_NATIVE | ACC_ABSTRACT)) == 0;
		Bool isSynchronized = (accessFlags & ACC_SYNCHRONIZED) != 0;
		Bool allowSynchronized = (accessFlags & ACC_NATIVE) != 0;

		if (isDirect != expectDirect) {
			OAT_LOGD("dvmInterpet: Method in wrong list @ %d\n", i);
			return False;
		}

		if (isSynchronized && !allowSynchronized) {
			OAT_LOGD("GOT IT: Bogus method access flags (synchronization) %x @ %d\n", accessFlags, i);
			return False;
		}

		if ((accessFlags & ~ACC_METHOD_MASK) != 0) {
			// The VM specification says that unknown flags should be ignored.
			OAT_LOGD("GOT IT: Bogus method access flags %x @ %d\n", accessFlags, i);
			method->accessFlags &= ACC_METHOD_MASK;
		}

		if (expectCode) {
			if (method->codeOff == 0) {
				OAT_LOGD("GOT IT: Unexpected zero code_off for access_flags %x\n",
						accessFlags);
				return False;
			}
		} else if (method->codeOff != 0) {
			OAT_LOGD("GOT IT: Unexpected non-zero code_off %#x for access_flags %x\n",
					method->codeOff, accessFlags);
			return False;
		}
	}
	return True;
}

Bool verifyClassDataItem(struct DexFileData* dexData, struct DexClassData* classData) {
	Bool okay;
	okay = verifyFields(dexData, classData->header.staticFieldsSize,
			classData->staticFields, True);
	if (!okay) {
#ifdef LOGI
		OAT_LOGD("GOT IT: verify static fields , verify error\n");
#endif
		return False;
	}
	okay = verifyFields(dexData, classData->header.instanceFieldsSize,
			classData->instanceFields, False);
	if (!okay) {
#ifdef LOGI
		OAT_LOGD("GOT IT: verify instance fields , verify error\n");
#endif
		return False;
	}
	okay = verifyMethods(dexData, classData->header.directMethodsSize,
			classData->directMethods, True);
	if (!okay) {
#ifdef LOGI
		OAT_LOGD("GOT IT: verify direct methods , verify error\n");
#endif
		return False;
	}
	okay = verifyMethods(dexData, classData->header.virtualMethodsSize,
			classData->virtualMethods, False);

	if (!okay) {
#ifdef LOGI
		OAT_LOGD("GOT IT: verify virtual methods , verify error\n");
#endif
		return False;
	}
	return True;
}

void readEncodedValue(const u1** ptr, struct DexFileData* dexData) {
	//encoded value
	u1 var_arg_type = *(*ptr);
	(*ptr)++;
	u1 var_arg = var_arg_type >> 5;
	// ALOGI("GOI IT: read encode value: %x", var_arg_type);  
	u1 var_type = var_arg_type & 0x1f;
	switch(var_type) {
		case VALUE_BYTE:
			{
				(*ptr)++;
				break;
			}
		case VALUE_SHORT:
		case VALUE_CHAR:
		case VALUE_INT:
		case VALUE_LONG:
		case VALUE_FLOAT:
		case VALUE_DOUBLE:
		case VALUE_STRING:
		case VALUE_TYPE:
		case VALUE_FIELD:
		case VALUE_METHOD:
		case VALUE_ENUM:
			{
				(*ptr) += var_arg + 1;
				break;
			}
		case VALUE_ARRAY:
			{
				if (var_arg != 0) {
#ifdef LOGI
					OAT_LOGD("GOI IT: calculate the length of annotations error\n");  
#endif
				}
				//skip encoded array size
				Int encode_arr_size = readUnsignedLeb128(ptr);	
				for(Int i = 0; i < encode_arr_size; i++) {
					readEncodedValue(ptr, dexData);
				}
				break;
			}
		case VALUE_ANNOTATION:
			{
				if (var_arg != 0) {
#ifdef LOGI
					OAT_LOGD("GOI IT: calculate the length of annotations error\n");  
#endif
				}
				readEncodedAnnotation(ptr, dexData);
				break;
			}
		case VALUE_NULL:
			{
				if (var_arg != 0) {
#ifdef LOGI
					OAT_LOGD("GOI IT: calculate the length of annotations error\n"); 
#endif
				}
				//do nothing
				break;
			}
		case VALUE_BOOLEAN:
			{
				//do nothing
				break;
			}
	}
}


void readEncodedAnnotation(const u1** ptr, struct DexFileData* dexData) {
	u4 type_idx = readUnsignedLeb128(ptr); //skip typeIdx
	if (type_idx >= dexData->typeIds->size) {
#ifdef LOGI
		OAT_LOGD("GOI IT: calculate the length of annotations error, type ids exceed\n");
#endif
	}
	u4 anno_ele_size = readUnsignedLeb128(ptr);
	for (u4 i = 0; i < anno_ele_size; i++) {
		u4 name_idx = readUnsignedLeb128(ptr); //skip nameIde
		if (name_idx >= dexData->stringIds->size) {
#ifdef LOGI
			OAT_LOGD("GOI IT: calculate the length of annotations error, name ids exceed\n");  
#endif
		}
		readEncodedValue(ptr,  dexData);
	}   
}

/*
 * collect encode array data for initial values of static fields in classes
 * 
 */
Int collectDexEncodedArray(struct DexFile* dexFile, struct DexFileData* dexData, u4 clzDefIndex) 
{
	tl_assert(dexData!=NULL);
	if (dexData->encodeArrayData == NULL) {
		dexData->encodeArrayData = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dexData->encodeArrayData);
		VG_(memset)((Addr)dexData->encodeArrayData, 0, sizeof(struct DexDataSet));
	}

	dexData->encodeArrayData->isWordAlign = False;

	if (dexData->classDefs == NULL) {
		OAT_LOGI("GOT IT: collect class data items, class defs == NULL\n");
		return -1;
	}
	if (clzDefIndex >= dexData->classDefs->size) {
		OAT_LOGD("GOT IT: collect class data items, class defs index exceed\n");
		return -1;
	}

	struct DexClassDef* clzDef = (struct DexClassDef*)dexGetClassDef(dexFile, clzDefIndex);
	tl_assert(clzDef!=NULL);
	u4 off = clzDef->staticValuesOff;
	if(off == 0) {
		//OAT_LOGD("GOT IT: collect encode array for classes, offset == 0\n");
		return -1; 
	}

	// search for reused encode items
	for (u4 i = 0; i < dexData->encodeArrayData->size; i++) {
		if (dexData->encodeArrayData->items[i].read_off == off) {
			return i;
		}
	} 

	//calculate the length of encode array data
	struct DexEncodedArray* encodeArray = (struct DexEncodedArray*)(dexFile->baseAddr + off);
	const u1* ptr = (const u1*) encodeArray;
	const u1* save_ptr = ptr;
	u4 encode_val_size = readUnsignedLeb128(&ptr);
	for (u4 i = 0; i < encode_val_size; i++) {
		readEncodedValue(&ptr,  dexData);
	}   

	u4 size = ptr - save_ptr;

	//DexDataItem* temp = new DexDataItem();
	struct DexDataItem* temp = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
	tl_assert(temp);
	VG_(memset)((Addr)temp, 0, sizeof(struct DexDataItem)); 

	temp->read_off = off;
	temp->refer = clzDefIndex;
	// temp->isIDDS = false;
	temp->length = size;

	if (dexData->encodeArrayData->size >= MAX_ITEM_SIZE) {
		OAT_LOGD("GOT IT: collect encodeArrayData, exceed  size 80000,  < %d\n", dexData->encodeArrayData->size);
		return -1;
	} else {
		dexData->encodeArrayData->items[dexData->encodeArrayData->size++] = *temp;
	}
	VG_(free)(temp); 
	return dexData->encodeArrayData->size - 1;
}
/*
 * For each string Id, collect string data item, and return its index
 *  
 */
Int collectDexStringData(struct DexFile* dexFile, struct DexFileData* dexData, u4 strIdIndex) {

	struct DexDataSet* dataSet = dexData->stringData; 
	if (dataSet == NULL) {
		// dataSet = new DexDataSet();
		dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet));
		dexData->stringData = dataSet;
	}

	dataSet->isWordAlign = False;
	if (dexData->stringIds == NULL || strIdIndex >= dexData->stringIds->size) {
		OAT_LOGI("GOT IT: collect string data item, string Ids == NULL or index exceed\n");
		return -1;
	}
	struct DexStringId* stringId = (struct DexStringId*) (dexData->stringIds->items[strIdIndex].data);
	u4 off = stringId->stringDataOff;
	if(off == 0) {
		OAT_LOGI("GOT IT: collect string data offset = 0\n");
		return -1; 
	}
	// calculate the length of string data items
	const u1* ptr = dexFile->baseAddr + off; 
	const u1* temp_ptr = ptr;
	Int length = 1; 
	//add the uleb128 length
	while (*(temp_ptr++) > 0x7f) {
		length++;
	}
	//OAT_LOGI("GOT IT: collect string data: %s\n", temp_ptr); 
	const char* temp_ptr1 = (const char*) temp_ptr;
	while((*temp_ptr1++) != '\0') {
		length++;                                                                                                      
	}
	length++;     

	struct DexDataItem* temp = NULL;
	temp = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
	tl_assert(temp);
	VG_(memset)((Addr)temp, 0, sizeof(struct DexDataItem));     

	temp->read_off = off;
	temp->refer = strIdIndex;
	temp->length = length;
	// temp->isIDDS = False;

	if (dexData->stringData->size >= MAX_ITEM_SIZE) {    
		OAT_LOGI("GOT IT: collect string data items, exceed  size 80000,  < %d\n", dexData->stringData->size);
		return -1;
	} else {
		dexData->stringData->items[dexData->stringData->size++] = *temp;
	}  

	VG_(free)(temp); 
	return dexData->stringData->size -1;
}


/*
 * For each protoId or classDef, collect type list, and return its index
 *
 */
Int collectDexTypeListData(struct DexFile* dexFile, struct DexFileData* dexData, Bool isProto, u4 index) {

	struct DexDataSet* dataSet = dexData->typeListData; 
	if (dexData->typeListData == NULL) {
		dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet));
		dexData->typeListData = dataSet;
	}

	dataSet->isWordAlign = True;

	u4 off = 0;
	struct DexTypeList *list = NULL;
	if (isProto) {
		if (dexData->protoIds == NULL || index >= dexData->protoIds->size) {
			OAT_LOGD("GOT IT: collect type list item ,  proto Ids == NULL or index exceed\n");
			return -1;
		}
		struct DexProtoId* protoId = (struct DexProtoId*) dexGetProtoId(dexFile, index);
		off = protoId->parametersOff;
		if (off != 0) {
			list = (struct DexTypeList *)dexGetProtoParameters(dexFile, protoId); 
		} 
	} else {
		if (dexData->classDefs == NULL || index >= dexData->classDefs->size) {
			OAT_LOGD("GOT IT: collect type list item,  class defs == NULL or index exceed\n");
			return -1;
		}
		struct DexClassDef* classdef = (struct DexClassDef*)dexGetClassDef(dexFile, index);
		off = classdef->interfacesOff;
		if (off != 0) {
			list = (struct DexTypeList*)dexGetInterfacesList(dexFile, classdef);
		}  
	}

	if (list == NULL) {
		//OAT_LOGD("GOT IT: collect type list item for Proto ? %d, offset == 0 and return -1\n", isProto);
		return -1;
	}

	// search for reused type list
	for (u4 i = 0; i < dexData->typeListData->size; i++) {
		//OAT_LOGD("GOT IT: collect type list, search for i : %d", i);
		if (dexData->typeListData->items[i].read_off == off) {
			return i;
		}
	} 

	// DexDataItem* temp = new DexDataItem();

	struct DexDataItem* temp = NULL;
	temp = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
	tl_assert(temp);
	VG_(memset)((Addr)temp, 0, sizeof(struct DexDataItem));     

	temp->read_off = off;
	temp->refer = index;
	//temp->isIDDS = False;
	temp->length = sizeof(struct DexTypeItem) * list->size + 4;
	if (dexData->typeListData->size >= MAX_ITEM_SIZE) {
		OAT_LOGD("GOT IT: collect type list items, exceed  size 80000,  < %d\n", dexData->typeListData->size);
		return -1;
	} else {
		dexData->typeListData->items[dexData->typeListData->size++] = *temp;
	}

	VG_(free)(temp); 
	return dexData->typeListData->size -1;
}


/*
 *  collect class data items and return its index
 * it also collect code items for each class data item
 *
 */
Int collectDexClassData(struct DexFile* dexFile, struct DexFileData* dexData, u4 clzDefIndex) { 
	OAT_LOGI("GOT IT: start to collect class data, for clz def : %d\n", clzDefIndex);
	tl_assert(dexData);
	if (dexData->classData == NULL) {

		dexData->classData = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert( dexData->classData);
		VG_(memset)((Addr) dexData->classData, 0, sizeof(struct DexDataSet));
	}
	dexData->classData->isWordAlign = False;
	if (dexData->classDefs == NULL || clzDefIndex >= dexData->classDefs->size) {
		OAT_LOGI("GOT IT: collect class data items, class defs == NULL or index exceed\n");
		return -1;
	}
	struct DexClassDef* clzDef = (struct DexClassDef*)dexGetClassDef(dexFile, clzDefIndex);
	u4 off = clzDef->classDataOff;
	if(off == 0) {
		OAT_LOGI("GOT IT: collect class data items, offset == 0\n");
		return -1; 
	}

	//calculate the length of class data items and obtain class data item
	Int dataItem_length = 0;
	const u1* pEncodedData = dexGetClassData(dexFile, clzDef);
	struct DexClassData* pData = NULL;
	if(isMemAvailable(pEncodedData, 0, dexFile->baseAddr, dexFile->baseAddr+APPEND_MEM-14))  {
		pData = ReadClassData(&pEncodedData);
	}	else  {
		OAT_LOGI("Error: Encoded data is not in clone memory...\n");
		return -1;
	}

	if (pData == NULL) {
		OAT_LOGI("GOT IT: collect class data null\n");
		return -1;
	}


	struct DexDataItem* temp = NULL;
	temp = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
	tl_assert(temp);
	VG_(memset)((Addr)temp, 0, sizeof(struct DexDataItem));  

	temp->read_off = off;
	temp->refer = clzDefIndex;
	temp->data = pData;

	dataItem_length+= unsignedLeb128Size(pData->header.staticFieldsSize);
	dataItem_length+= unsignedLeb128Size(pData->header.instanceFieldsSize);
	dataItem_length+= unsignedLeb128Size(pData->header.directMethodsSize);
	dataItem_length+= unsignedLeb128Size(pData->header.virtualMethodsSize);
	if (pData->staticFields) {
		for (u4 i = 0; i < pData->header.staticFieldsSize; i++) {
			dataItem_length +=unsignedLeb128Size(pData->staticFields[i].fieldIdx);
			dataItem_length +=unsignedLeb128Size(pData->staticFields[i].accessFlags);
		}
	}
	if (pData->instanceFields) {
		for (u4 i = 0; i < pData->header.instanceFieldsSize; i++) {
			dataItem_length += unsignedLeb128Size(pData->instanceFields[i].fieldIdx);
			dataItem_length += unsignedLeb128Size(pData->instanceFields[i].accessFlags);
		}
	}
	if (pData->directMethods) {
		for (u4 i=0; i<pData->header.directMethodsSize; i++) {
			dataItem_length += unsignedLeb128Size(pData->directMethods[i].methodIdx);
			dataItem_length += unsignedLeb128Size(pData->directMethods[i].accessFlags);
			dataItem_length += unsignedLeb128Size(pData->directMethods[i].codeOff);
		}
	}
	if (pData->virtualMethods) {
		for (u4 i=0; i<pData->header.virtualMethodsSize; i++) {
			dataItem_length += unsignedLeb128Size(pData->virtualMethods[i].methodIdx);
			dataItem_length += unsignedLeb128Size(pData->virtualMethods[i].accessFlags);
			dataItem_length += unsignedLeb128Size(pData->virtualMethods[i].codeOff);
		}
	}

	Bool okay = verifyClassDataItem(dexData, pData);
	if (!okay) {
		OAT_LOGI("GOT IT: collect class data , verify error\n");
		return -1;
	}

	temp->length = dataItem_length;
	if (dexData->classData->size >= MAX_ITEM_SIZE) {
		OAT_LOGI("GOT IT: collect class datas, exceed  size 80000,  < %d\n", dexData->classData->size);
		return -1;
	} else {
		u4 save_index = dexData->classData->size;
		OAT_LOGI("GOT IT: try to save index = %d\n", save_index);
		dexData->classData->items[dexData->classData->size++] = *temp;
		VG_(free)(temp); 

		if (pData->header.directMethodsSize + pData->header.virtualMethodsSize <= 0) {
			OAT_LOGI("GOT IT: collect class datas,  method size == 0, no need to collect method code\n");
		} else {
			u4 refer_method = 0;

			/*
				 struct MethodCodeRefer* codeRefer = (struct MethodCodeRefer*)VG_(malloc)("New.assemble.codeRefer", sizeof(struct MethodCodeRefer));
				 tl_assert(codeRefer);
				 VG_(memset)((Addr)codeRefer, 0, sizeof(struct MethodCodeRefer));


				 codeRefer->refer_code_num = pData->header.directMethodsSize + pData->header.virtualMethodsSize;
			//  codeRefer->refer_code = new Int[codeRefer->refer_code_num];
			codeRefer->refer_code = (Int*)VG_(malloc)("New.assemble.code", sizeof(Int));
			tl_assert(codeRefer->refer_code);
			//  VG_(memset)((Addr)codeRefer->refer_code, 0, sizeof(struct DexDataItem)); 


			dexData->classData->items[save_index].refer_data = codeRefer;
			*/
			dexData->classData->items[save_index].refer_code_num = pData->header.directMethodsSize + pData->header.virtualMethodsSize;

			OAT_LOGI("GOT IT: start to collect code for class data : %d, num of methods: %d\n", save_index, dexData->classData->items[save_index].refer_code_num);
			if (dexData->classData->items[save_index].refer_code_num >= 200) {
				OAT_LOGI("GOT IT: collect class datas,  method size >= 200, return\n"); 
				return -1;
			}
			/*
				 dexData->classData->items[save_index].refer_code = (Int*)VG_(malloc)("New.assemble.code", sizeof(Int));
				 tl_assert(dexData->classData->items[save_index].refer_code);*/
			//dexData->classData->items[save_index].refer_code

			if (pData->directMethods) {
				for (u4 i=0; i<pData->header.directMethodsSize; i++) {
					//collect code items for direct methods
					Int index = collectDexCodeData(dexFile, dexData, refer_method++, save_index); 
					dexData->classData->items[save_index].refer_code[refer_method - 1] = index;
				}
			}

			if (pData->virtualMethods) {
				for (u4 i=0; i<pData->header.virtualMethodsSize; i++) {	
					//collect code items for virtual methods
					Int index = collectDexCodeData(dexFile, dexData, refer_method++, save_index); 
					dexData->classData->items[save_index].refer_code[refer_method - 1] = index;
				}
			}
		}
	} 

	return dexData->classData->size - 1;
}


/*
 * collect code items for class data items' methods
 *
 */
Int collectDexCodeData(struct DexFile* dexFile, struct DexFileData* dexData, u4 refer_method, u4 refer_class) 
{ 
	//  ALOGI("GOT IT: start to collect code data");
	if (dexData->codeData == NULL) {
		//  dexData->codeData = new DexDataSet();
		dexData->codeData = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dexData->codeData);
		VG_(memset)((Addr)dexData->codeData, 0, sizeof(struct DexDataSet));
	}

	dexData->codeData->isWordAlign = True;

	if (dexData->classData == NULL || refer_class >= dexData->classData->size) {
		OAT_LOGI("GOT IT: collect code data, class data == NULL or refer class index exceed\n");
		return -1;
	}

	struct DexClassData* pData = (struct DexClassData*) dexData->classData->items[refer_class].data;
	struct DexMethod* method = NULL;

	if (refer_method < pData->header.directMethodsSize) {
		method = &pData->directMethods[refer_method];  
	} else if (refer_method - pData->header.directMethodsSize < pData->header.virtualMethodsSize) {
		method = &pData->virtualMethods[refer_method - pData->header.directMethodsSize];
	} else {
		OAT_LOGI("GOT IT: code, refer_method index out of scope\n");
		return -1;
	}

	struct DexDataItem* temp = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
	tl_assert(temp);
	VG_(memset)((Addr)temp, 0, sizeof(struct DexDataItem));  

	u4 off = method->codeOff;
	if(off == 0) {
		//OAT_LOGD("GOT IT: code, collect code data, offset == 0\n");
		return -1; 
	}

	struct DexCode* code = (struct DexCode*) dexGetCode(dexFile, method);
	// u4 codeSize = dexGetDexCodeSize(code);
	u4 codeSize = getDexCodeSize(code, NULL);
	temp->length = codeSize;
	temp->data = code;

	//temp->isIDDS = false;
	if (dexData->codeData->size >= MAX_ITEM_SIZE) {
		OAT_LOGI("GOT IT: collect code datas, exceed  size 80000,  < %d\n", dexData->codeData->size);
		return -1;
	} else {
		dexData->codeData->items[dexData->codeData->size++] = *temp;
	}  

	VG_(free)(temp); 
	return dexData->codeData->size -1;
}




void collectDexFileData(struct DexFile * dexFile, struct DexFileData* dexData) {
	UInt itemsize = 0;
	// directly set the dex header
	if (dexData->header == NULL) {
		dexData->header = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
		tl_assert(dexData->header);
		VG_(memset)((Addr)dexData->header, 0, sizeof(struct DexDataItem));  
		dexData->header->data = (struct DexHeader*) dexFile->pHeader;
		// dexData->header->isIDDS = True;
		dexData->header->length = sizeof(struct DexHeader);
	}

	OAT_LOGI("GOT IT: collect string ids %d\n", dexFile->pHeader->stringIdsSize);
	// collect string ids and their corrsponding string data items
	if (dexData->stringIds == NULL) {

		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet));

		dexData->stringIds = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->stringIdsSize;
		for (u4 i = 0; i < dataSet->size; i++) {
			dataSet->items[i].data = (struct DexStringId*)dexGetStringId(dexFile, i);
			dataSet->items[i].length = sizeof(struct DexStringId);
			Int index = collectDexStringData(dexFile, dexData, i);
			dataSet->items[i].refer = index;
		}
	}

	OAT_LOGI("GOT IT: collect type ids %d\n", dexFile->pHeader->typeIdsSize);
	// collect type Ids
	if (dexData->typeIds == NULL) {
		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet)); 

		dexData->typeIds = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->typeIdsSize;

		for (u4 i = 0; i < dataSet->size; i++) {
			dataSet->items[i].data = (struct DexTypeId*)dexGetTypeId(dexFile, i);
			dataSet->items[i].length = sizeof(struct DexTypeId);
		}
	} 

	OAT_LOGI("GOT IT: collect field ids %d\n", dexFile->pHeader->fieldIdsSize);
	// collect field Ids
	if (dexData->fieldIds == NULL) {
		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet)); 

		dexData->fieldIds = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->fieldIdsSize;

		for (u4 i = 0; i < dataSet->size; i++) {
			dataSet->items[i].data = (struct DexFieldId*)dexGetFieldId(dexFile, i);
			dataSet->items[i].length = sizeof(struct DexFieldId);
		}
	} 

	// collect method Ids
	OAT_LOGI("GOT IT: collect method ids %d\n", dexFile->pHeader->methodIdsSize);
	if (dexData->methodIds == NULL) {
		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet)); 

		dexData->methodIds = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->methodIdsSize;
		for (u4 i = 0; i < dataSet->size; i++) {
			dataSet->items[i].data = (struct DexMethodId*)dexGetMethodId(dexFile, i);
			dataSet->items[i].length = sizeof(struct DexMethodId);
		}
	} 

	// collect proto Ids and its corrsponding type lists
	OAT_LOGI("GOT IT: collect proto ids %d\n", dexFile->pHeader->protoIdsSize);
	if (dexData->protoIds == NULL) {
		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet)); 

		dexData->protoIds = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->protoIdsSize;
		for (u4 i = 0; i < dataSet->size; i++) {
			dataSet->items[i].data = (struct DexProtoId*) dexGetProtoId(dexFile, i);

			dataSet->items[i].length = sizeof(struct DexProtoId);
			Int index = collectDexTypeListData(dexFile, dexData, True, i);
			dataSet->items[i].refer = index;
		}
	} 

	OAT_LOGI("GOT IT: collect class defs %d\n", dexFile->pHeader->classDefsSize);
	/* collect class defs and its corrsponding type lists, class data items, annotation directory items, and ...*/
	if (dexData->classDefs == NULL) {

		struct DexDataSet* dataSet = (struct DexDataSet*)VG_(malloc)("New.assemble.dataset", sizeof(struct DexDataSet));
		tl_assert(dataSet);
		VG_(memset)((Addr)dataSet, 0, sizeof(struct DexDataSet)); 

		dexData->classDefs = dataSet;
		dataSet->isWordAlign = True;
		dataSet->size = dexFile->pHeader->classDefsSize;
		OAT_LOGI("GOT IT: collect class defs, end to allocate, size: %d\n", dataSet->size);
		for (u4 i = 0; i < dataSet->size; i++) {
			// OAT_LOGI("GOT IT: collect class defs, dump the original class def\n");
			//  dumpClassDef(dexFile, i);
			struct DexClassDef* pClassDef = (struct DexClassDef*)dexGetClassDef(dexFile, i);
			dataSet->items[i].data = pClassDef; 

			dataSet->items[i].length = sizeof(struct DexClassDef);
			/*
				 struct ClassDefRefer* clzDefRefer = (struct ClassDefRefer*)VG_(malloc)("New.assemble.classRefer", sizeof(struct ClassDefRefer));
				 tl_assert(clzDefRefer);
				 VG_(memset)((Addr)clzDefRefer, 0, sizeof(struct ClassDefRefer)); 

				 OAT_LOGI("GOT IT: collect class defs, %d, end to allocate class refer\n", i);

			//default value
			clzDefRefer->refer_typeList = -1;
			clzDefRefer->refer_clzDataItem = -1;
			clzDefRefer->refer_annoDir = -1;
			clzDefRefer->refer_encodeArray = -1;

			dataSet->items[i].refer_data = clzDefRefer;



			Int index = collectDexTypeListData(dexFile, dexData, False, i);
			clzDefRefer->refer_typeList = index;

			index = collectDexEncodedArray(dexFile, dexData, i);
			clzDefRefer->refer_encodeArray = index;    

			index = collectDexClassData(dexFile, dexData, i);
			clzDefRefer->refer_clzDataItem = index;*/
			dataSet->items[i].refer_typeList = -1;
			dataSet->items[i].refer_clzDataItem = -1;
			dataSet->items[i].refer_annoDir = -1;
			dataSet->items[i].refer_encodeArray = -1;

			Int index = collectDexTypeListData(dexFile, dexData, False, i);
			dataSet->items[i].refer_typeList = index;

			index = collectDexEncodedArray(dexFile, dexData, i);
			dataSet->items[i].refer_encodeArray = index;    

			OAT_LOGI("Try to collect dex class index=%d\n", i);
			index = collectDexClassData(dexFile, dexData, i);
			OAT_LOGI("Collected dex class index=%d\n", index);
			dataSet->items[i].refer_clzDataItem = index;
		}   
	} 
	OAT_LOGI("GOT IT: collect class defs, end\n");

	/* we do not collect mapList and calculate its values instead */
}


/*
 * try to write collect dex data to memory and calculate each items offset including header and mapList
 * return False if error
 * 
 */
Bool tryWriteDexData(struct DexFileData* dexData, struct DexFile* dexFile, u4* realLength) {

	u4 total_pointer = 0;
	u4 itemSize = 0;

	/*  try to write the dex header */
	if (dexData->header == NULL) {
		OAT_LOGI("GOT IT: try -- header == NULL and return\n");
		return False;
	}

	// OAT_LOGI("GOT IT: try -- Header,  write offset: %08x\n", total_pointer);
	dexData->header->write_off = total_pointer;
	total_pointer += dexData->header->length;
	while (total_pointer & 3) {
		total_pointer++;
	}
	itemSize++;

	/* try to write the string_ids */
	//  OAT_LOGI("GOT IT: try -- StringId, realsize: %d, write offset: %08x\n", dexData->stringIds->size, total_pointer);
	dexData->stringIds->write_off = total_pointer;
	// assert(dexData->stringIds->size == size);
	for (u4 j = 0; j < dexData->stringIds->size; j++) {
		dexData->stringIds->items[j].write_off = total_pointer;
		total_pointer += dexData->stringIds->items[j].length;
		if (dexData->stringIds->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	}
	itemSize++;

	/* try to write the type_ids */
	//  OAT_LOGI("GOT IT: try -- TypeId, realsize: %d, write offset: %08x\n", dexData->typeIds->size, total_pointer);
	dexData->typeIds->write_off = total_pointer;
	for (u4 j = 0; j < dexData->typeIds->size; j++) {
		dexData->typeIds->items[j].write_off = total_pointer;
		total_pointer += dexData->typeIds->items[j].length;
		if (dexData->typeIds->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	}
	itemSize++;

	/* try to write the proto_ids */
	// OAT_LOGI("GOT IT: try -- ProtoId, realsize: %d, write offset: %08x\n", dexData->protoIds->size, total_pointer); 
	dexData->protoIds->write_off = total_pointer;
	for (u4 j = 0; j < dexData->protoIds->size; j++) {
		dexData->protoIds->items[j].write_off = total_pointer;
		total_pointer += dexData->protoIds->items[j].length;
		if (dexData->protoIds->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	} 
	itemSize++;

	/* try to write field_ids */
	// OAT_LOGI("GOT IT: try --  FieldId, realsize: %d, write offset: %08x\n", dexData->fieldIds->size, total_pointer);
	dexData->fieldIds->write_off = total_pointer;
	for (u4 j = 0; j < dexData->fieldIds->size; j++) {
		dexData->fieldIds->items[j].write_off = total_pointer;
		total_pointer += dexData->fieldIds->items[j].length;
		if (dexData->fieldIds->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	}  
	itemSize++;

	/* try to write method_ids */
	// OAT_LOGD("GOT IT: try -- MethodId, realsize: %d,  write offset: %08x\n", dexData->methodIds->size, total_pointer);
	dexData->methodIds->write_off = total_pointer;
	for (u4 j = 0; j < dexData->methodIds->size; j++) {
		dexData->methodIds->items[j].write_off = total_pointer;
		total_pointer += dexData->methodIds->items[j].length;
		if (dexData->methodIds->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	}  
	itemSize++;


	/* try to writhe class_Defs */
	// OAT_LOGI("GOT IT: try -- ClassDef, realsize: %d, write offset: %08x\n", dexData->classDefs->size, total_pointer); 
	dexData->classDefs->write_off = total_pointer;
	for (u4 j = 0; j < dexData->classDefs->size; j++) {
		dexData->classDefs->items[j].write_off = total_pointer;
		total_pointer += dexData->classDefs->items[j].length;
		if (dexData->classDefs->isWordAlign) {
			while (total_pointer & 3) {
				total_pointer++;
			}
		}
	}  
	itemSize++;

	/*  try to write type list data  */
	if (dexData->typeListData == NULL) {
		OAT_LOGI("GOT IT: try -- TypeList data == NULL\n");
	} else {
		//  OAT_LOGI("GOT IT: try -- TypeList, Realsize: %d, write offset: %08x\n", dexData->typeListData->size, total_pointer);
		dexData->typeListData->write_off = total_pointer;
		//assert(dexData->typeListData->size == size);
		for (u4 j = 0; j < dexData->typeListData->size; j++) {
			dexData->typeListData->items[j].write_off = total_pointer;
			total_pointer += dexData->typeListData->items[j].length;
			if (dexData->typeListData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}  
		itemSize++;
	}

	/* try to write annotation set ref list data */
	if (dexData->annoSetRefListData == NULL) {
		OAT_LOGI("GOT IT: try -- annoSetRefListData, no data to try write and fill\n");
	} else {
		//  OAT_LOGI("GOT IT: try -- annoSetRefListData, realsize: %d,  write offset: %08x\n", dexData->annoSetRefListData->size, total_pointer); 
		dexData->annoSetRefListData->write_off = total_pointer;
		for (u4 j = 0; j < dexData->annoSetRefListData->size; j++) {
			dexData->annoSetRefListData->items[j].write_off = total_pointer;

			total_pointer += dexData->annoSetRefListData->items[j].length;
			if (dexData->annoSetRefListData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}
		itemSize++;
	}

	/* try to write annotation set data */
	if (dexData->annoSetData == NULL) {
		OAT_LOGI("GOT IT: try --  annoSetRefListData, no data to try write and fill\n");
	} else {
		//   OAT_LOGI("GOT IT: try --  AnnotationSet, realsize: %d,  write offset: %08x\n", dexData->annoSetData->size,  total_pointer);
		dexData->annoSetData->write_off = total_pointer;
		for (u4 j = 0; j < dexData->annoSetData->size; j++) {
			dexData->annoSetData->items[j].write_off = total_pointer;

			total_pointer += dexData->annoSetData->items[j].length;
			if (dexData->annoSetData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}
		itemSize++;
	} 

	/* try to write the class data */
	if (dexData->classData == NULL) {
		OAT_LOGI("GOT IT: try -- classData, no data to try write and break\n");
	} else {
		//   OAT_LOGI("GOT IT: try -- ClassData, realsize: %d, write offset: %08x\n", dexData->classData->size, total_pointer); 
		dexData->classData->write_off = total_pointer;
		//assert(dexData->classData->size == size);
		for (u4 j = 0; j < dexData->classData->size; j++) {
			dexData->classData->items[j].write_off = total_pointer;
			//OAT_LOGD("GOT IT: try --  ClassData [%d], write offset: %0x", j, total_pointer);
			total_pointer += dexData->classData->items[j].length;
			if (dexData->classData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}
		itemSize++;
	}

	// spare 100 bytes to avoid the change of class data items may need more space
	total_pointer += 100;

	while(total_pointer & 3) {
		total_pointer++;
	}

	/* try to write code data */
	if (dexData->codeData == NULL) {
		OAT_LOGI("GOT IT: try -- codeData, no data to try write and break\n");
	} else {
		//  OAT_LOGI("GOT IT: try -- codeData, realsize: %d, write offset: %08x\n", dexData->codeData->size, total_pointer); 
		dexData->codeData->write_off = total_pointer;
		//assert(dexData->codeData->size == size);
		for (u4 j = 0; j < dexData->codeData->size; j++) {
			dexData->codeData->items[j].write_off = total_pointer;
			total_pointer += dexData->codeData->items[j].length;
			if (dexData->codeData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		} 
		itemSize++;
	}

	/* try to write string data */
	if (dexData->stringData == NULL) {
		OAT_LOGI("GOT IT: try -- stringData, no data to try write and break\n");
	} else {
		//   OAT_LOGI("GOT IT: try -- stringData, realsize: %d, write offset: %08x\n", dexData->stringData->size, total_pointer); 
		dexData->stringData->write_off = total_pointer;
		//assert(dexData->stringData->size == size);
		for (u4 j = 0; j < dexData->stringData->size; j++) {
			dexData->stringData->items[j].write_off = total_pointer;
			total_pointer += dexData->stringData->items[j].length;
			if (dexData->stringData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}  
		itemSize++;
	}

	/* try to write debug info data */
	if (dexData->debugInfoData == NULL) {
		OAT_LOGI("GOT IT: try -- debugInfoData, no data to try write and fill\n");
	} else {
		OAT_LOGI("GOT IT: try -- debugInfoData, realsize: %d, write offset: 0x%08x\n", dexData->debugInfoData->size, total_pointer);
		dexData->debugInfoData->write_off = total_pointer;
		//assert(dexData->debugInfoData->size == size);
		for (u4 j = 0; j < dexData->debugInfoData->size; j++) {
			dexData->debugInfoData->items[j].write_off = total_pointer;
			total_pointer += dexData->debugInfoData->items[j].length;
			if (dexData->debugInfoData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}   
		itemSize++;
	}

	/* try to write  annotation item data */
	if (dexData->annoData == NULL) {
		OAT_LOGD("GOT IT: try -- Annotation, no data to try write and fill\n");
	} else {
		OAT_LOGD("GOT IT: try -- Annotation,  realsize: %d,  write offset: 0x%08x\n", dexData->annoData->size, total_pointer); 
		dexData->annoData->write_off = total_pointer;
		//assert(dexData->annoData->size == size);
		for (u4 j = 0; j < dexData->annoData->size; j++) {
			dexData->annoData->items[j].write_off = total_pointer;
			//OAT_LOGD("GOT IT: try -- %d, Annotation, , write off: 0x%x", j, total_pointer);
			total_pointer += dexData->annoData->items[j].length;
			if (dexData->annoData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}
		itemSize++;
	}

	/* try to write encoded array data */
	if (dexData->encodeArrayData == NULL) {
		OAT_LOGI("GOT IT: try -- EncodedArray, no data to try write and file\n");
	} else {
		OAT_LOGI("GOT IT: try -- EncodedArray, realsize: %d, write offset: 0x%08x\n", dexData->encodeArrayData->size, total_pointer); 
		dexData->encodeArrayData->write_off = total_pointer;
		for (u4 j = 0; j < dexData->encodeArrayData->size; j++) {
			dexData->encodeArrayData->items[j].write_off = total_pointer;
			total_pointer += dexData->encodeArrayData->items[j].length;
			if (dexData->encodeArrayData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}
		itemSize++;
	}


	/* try to write annotation directory item data */
	if (dexData->annosDirectoryData == NULL) {
		OAT_LOGI("GOT IT: try -- AnnotationsDirectory, no data to try write and fill\n");
	} else {
		//   OAT_LOGI("GOT IT: try -- AnnotationsDirectory, realsize: %d, write offset: %08x\n", dexData->annosDirectoryData->size, total_pointer); 
		dexData->annosDirectoryData->write_off = total_pointer;
		for (u4 j = 0; j < dexData->annosDirectoryData->size; j++) {
			dexData->annosDirectoryData->items[j].write_off = total_pointer;
			//OAT_LOGD("GOT IT: try -- %d, AnnotationsDirectory %d, length: %d, write_off: 0x%x", i, j, dexData->annosDirectoryData->items[j].length, total_pointer);
			total_pointer += dexData->annosDirectoryData->items[j].length; 
			if (dexData->annosDirectoryData->isWordAlign) {
				while (total_pointer & 3) {
					total_pointer++;
				}
			}
		}  
		itemSize++;
	}

	while (total_pointer & 3) {
		total_pointer++;
	}

	/* try to write the mapList */
	if (dexData->mapList == NULL) {
		//  OAT_LOGI("GOT IT: try -- MapList, no data to write and will space space here, write offset: %08x\n", total_pointer);
		//dexData->mapList = new DexDataItem();

		dexData->mapList = (struct DexDataItem*)VG_(malloc)("New.assemble.dataItem", sizeof(struct DexDataItem));
		tl_assert(dexData->mapList);
		VG_(memset)((Addr)dexData->mapList, 0, sizeof(struct DexDataItem));  

		dexData->mapList->write_off = total_pointer;
		// dexData->mapList->isIDDS = False;
		itemSize++;
		dexData->mapList->length = itemSize * sizeof(struct DexMapItem) + 4;
		total_pointer += dexData->mapList->length;
		while (total_pointer & 3) {
			total_pointer++;
		}
	} else {
		OAT_LOGI("GOT IT: try -- MapList, has data to write and error\n");
		return False;
	}

	// OAT_LOGI("GOT IT: try -- others, from offset : %08x, to %08x, numofItem: %d, length: %08x\n", total_pointer, dexData->memMap.length, itemSize, total_pointer);

	*realLength = total_pointer;
	return True;
}


/*
 * write collected dex data to memory ( each item to its calculated offset, alter the offset to CDDS if necessary,
 *  and dump to file at last
 * 
 */
Bool writeDexData(struct DexFileData* dexData, struct DexFile* dexFile, u4 length) {
	//  OAT_LOGI("GOT IT: write -- dex data start - length: %d\n", length);

	/* write the header and update its content including offset to xx_ids, fileSize,... 
	 * And leave magic number, checksum and signature to the end of the write process*/
	//   OAT_LOGI("GOT IT: write -- header - from offset: %d\n", dexData->header->write_off);


	//memcpy(dexData->memMap.dexAddr + dexData->header->write_off, dexData->header->data, dexData->header->length);
	VG_(memcpy)(dexData->memMap.dexAddr + dexData->header->write_off, dexData->header->data, dexData->header->length);

	struct DexHeader* pHeader = (struct DexHeader*) (dexData->memMap.dexAddr + dexData->header->write_off);
	pHeader->fileSize = length;
	pHeader->headerSize = sizeof(struct DexHeader);
	pHeader->mapOff = dexData->mapList->write_off;

	pHeader->stringIdsOff = dexData->stringIds->write_off;
	pHeader->stringIdsSize = dexData->stringIds->size;

	pHeader->typeIdsSize = dexData->typeIds->size;
	pHeader->typeIdsOff = dexData->typeIds->write_off;

	pHeader->protoIdsSize = dexData->protoIds->size;
	pHeader->protoIdsOff = dexData->protoIds->write_off;

	pHeader->fieldIdsSize = dexData->fieldIds->size;
	pHeader->fieldIdsOff = dexData->fieldIds->write_off;

	pHeader->methodIdsSize = dexData->methodIds->size;
	pHeader->methodIdsOff = dexData->methodIds->write_off;

	pHeader->classDefsSize = dexData->classDefs->size;
	pHeader->classDefsOff = dexData->classDefs->write_off;

	/* writhe string ids and its data items  */
	//  OAT_LOGI("GOT IT: write -- string ids  - from offset: %d\n", dexData->stringIds->items[0].write_off);
	for (u4 i = 0; i < dexData->stringIds->size; i++) {
		struct DexDataItem* strId = &dexData->stringIds->items[i];
		// memcpy(dexData->memMap.dexAddr + strId->write_off, strId->data, strId->length);
		VG_(memcpy)(dexData->memMap.dexAddr + strId->write_off, strId->data, strId->length);
		// write string data items;
		if (strId->refer == -1) {
			continue;
		}
		if (strId->refer >= (Int) dexData->stringData->size) {
			OAT_LOGI("GOT IT: write -- string id - refer string dta index exceed size\n");
			return False;
		}
		struct DexDataItem* str_data = &dexData->stringData->items[strId->refer];
		if (str_data->write_off == 0 || str_data->read_off == 0) {
			OAT_LOGI("GOT IT: write -- string id - string data, offset error\n");
			return False;
		}
		//memcpy(dexData->memMap.dexAddr + str_data->write_off, dexFile->baseAddr + str_data->read_off, str_data->length);
		VG_(memcpy)(dexData->memMap.dexAddr + str_data->write_off, dexFile->baseAddr + str_data->read_off, str_data->length);
		// adjust string id refer offset
		struct DexStringId *temp = (struct DexStringId*) (dexData->memMap.dexAddr + strId->write_off);
		temp->stringDataOff = str_data->write_off;
	}

	/*  write type ids  */
	//  OAT_LOGI("GOT IT: write -- type ids  - from offset: %d\n", dexData->typeIds->items[0].write_off);
	for (u4 i = 0; i < dexData->typeIds->size; i++) {
		struct DexDataItem* typeId = &dexData->typeIds->items[i];
		//memcpy(dexData->memMap.dexAddr + typeId->write_off, typeId->data, typeId->length);
		VG_(memcpy)(dexData->memMap.dexAddr + typeId->write_off, typeId->data, typeId->length);
	}

	/* write proto Ids and its corresponding type list data */
	// OAT_LOGI("GOT IT: write -- proto ids   from offset: %d\n", dexData->protoIds->items[0].write_off);
	for (u4 i = 0; i < dexData->protoIds->size; i++) {
		struct DexDataItem* proId = &dexData->protoIds->items[i];
		//memcpy(dexData->memMap.dexAddr + proId->write_off, proId->data, proId->length);

		VG_(memcpy)(dexData->memMap.dexAddr + proId->write_off, proId->data, proId->length);

		struct DexProtoId *temp = (struct DexProtoId*) (dexData->memMap.dexAddr + proId->write_off);
		// write type list items;
		if (proId->refer == -1) {
			//OAT_LOGD("GOT IT: write -- proto id - refer type list index -1\n");
			temp->parametersOff = 0;
			continue;
		}
		struct DexDataItem* typelist_data = &dexData->typeListData->items[proId->refer];
		if (proId->refer >= (Int) dexData->typeListData->size) {
			OAT_LOGI("GOT IT: write -- proto id - refer type list index exceed size\n");
			return False;
		}

		if (typelist_data->write_off == 0 || typelist_data->read_off == 0) {
			OAT_LOGI("GOT IT: write -- proto id - typelist_data, write offset or read off error,proId->refer: %d\n", proId->refer);
			return False;
		}
		// memcpy(dexData->memMap.dexAddr + typelist_data->write_off, dexFile->baseAddr + typelist_data->read_off, typelist_data->length);
		VG_(memcpy)(dexData->memMap.dexAddr + typelist_data->write_off, dexFile->baseAddr + typelist_data->read_off, typelist_data->length);
		// adjust proto id refer offset
		temp->parametersOff = typelist_data->write_off;
	}


	/*  write field ids */
	// OAT_LOGI("GOT IT: write -- field ids   from offset: %d\n", dexData->fieldIds->items[0].write_off);
	for (u4 i = 0; i < dexData->fieldIds->size; i++) {
		struct DexDataItem* fieldId = &dexData->fieldIds->items[i];
		// memcpy(dexData->memMap.dexAddr + fieldId->write_off, fieldId->data, fieldId->length);
		VG_(memcpy)(dexData->memMap.dexAddr + fieldId->write_off, fieldId->data, fieldId->length);
	}

	/* write method ids */
	//  OAT_LOGI("GOT IT: write -- method ids   from offset: %d\n", dexData->methodIds->items[0].write_off);
	for (u4 i = 0; i < dexData->methodIds->size; i++) {
		struct DexDataItem* methodId = &dexData->methodIds->items[i];
		//memcpy(dexData->memMap.dexAddr + methodId->write_off, methodId->data, methodId->length);
		VG_(memcpy)(dexData->memMap.dexAddr + methodId->write_off, methodId->data, methodId->length);
	}

	/* write class defs and its corresponding data, including typeList, class data items, encoded array, annotations */

	//  OAT_LOGI("GOT IT: write -- class defs, size: %d, from offset: %08x\n", dexData->classDefs->size, dexData->classDefs->items[0].write_off);
	//  OAT_LOGI("GOT IT: write -- type list datas   size: %d\n", dexData->typeListData->size);
	//  OAT_LOGI("GOT IT: write -- class data items   size: %d\n", dexData->classData->size);

	// be careful about the class data items since their length can vary after change of their values, so we cannot
	// use the write offset calculated for each item, we should adjust the write offest just afte their written
	u4 w_off_clz_data = dexData->classData->write_off;
	u4 num_clz_written = 0;
	u4 num_clzDef_written = 0;

	for (u4 i = 0; i < dexData->classDefs->size; i++) {
		struct DexDataItem* clzDefItem = &dexData->classDefs->items[i];
		//struct DexClassDef* data = (struct DexClassDef*) (clzDefItem->data);

		//memcpy(dexData->memMap.dexAddr + clzDefItem->write_off, clzDefItem->data, clzDefItem->length);
		VG_(memcpy)(dexData->memMap.dexAddr + clzDefItem->write_off, clzDefItem->data, clzDefItem->length);
		// OAT_LOGD("GOT IT: write -- class defs %d, after write memcpy\n", i);
		num_clzDef_written++;
		struct DexClassDef* classDef = (struct DexClassDef*) (dexData->memMap.dexAddr + clzDefItem->write_off);
		// OAT_LOGD("GOT IT: write -- class defs %d, after write memcpy,  got class def\n", i);
		//if (clzDefItem->isIDDS) {
		/*
			 if (clzDefItem->refer_data == NULL) {
			 OAT_LOGI("GOI IT: write -- clzDef, the refer_data == NULL\n");
			 return;
			 }*/

		//struct ClassDefRefer* clzDefRefer = (struct ClassDefRefer*)(clzDefItem->refer_data);

		// write type lists;
		if (clzDefItem->refer_typeList != -1) {
			if (clzDefItem->refer_typeList >= (Int) dexData->typeListData->size) {
				OAT_LOGI("GOT IT: write -- clzDef - typelist_data, refer  exceed size\n"); 
				return False;
			}
			struct DexDataItem* typelist_data = &dexData->typeListData->items[clzDefItem->refer_typeList];
			if (typelist_data->write_off == 0 || typelist_data->read_off == 0) {
				OAT_LOGI("GOT IT: write -- clzDef - typelist_data, offset error, refer_typeList: %d\n", clzDefItem->refer_typeList);
				return False;
			} else {
				//memcpy(dexData->memMap.dexAddr + typelist_data->write_off, dexFile->baseAddr + typelist_data->read_off, typelist_data->length);
				VG_(memcpy)(dexData->memMap.dexAddr + typelist_data->write_off, dexFile->baseAddr + typelist_data->read_off, typelist_data->length);
				// adjust class def refer offset
				classDef->interfacesOff = typelist_data->write_off;
			}
			//OAT_LOGD("GOT IT: write -- clzDef - typelist, offset: %x", typelist_data->write_off);
		} else {
			classDef->interfacesOff = 0; 
		} 

		// OAT_LOGD("GOT IT: write -- class defs %d, after write type lists,  annotation refer: %d\n", i, clzDefRefer->refer_annoDir);

		// skip annotation and debug info
		classDef->annotationsOff = 0;



		//OAT_LOGD("GOT IT: write -- class defs %d, start to write encode data,  refer: %d", i, clzDefRefer->refer_encodeArray);

		//write encode array data for static values
		if (clzDefItem->refer_encodeArray != -1) {
			if (clzDefItem->refer_encodeArray >= (Int) dexData->encodeArrayData->size) {
#ifdef LOGI
				OAT_LOGD("GOT IT: write -- clzDef - encode array, refer  exceed size\n"); 
#endif
				return False;
			}    
			struct DexDataItem* encode_data = &dexData->encodeArrayData->items[clzDefItem->refer_encodeArray];
			if (encode_data->write_off == 0 || encode_data->read_off == 0) {
#ifdef LOGI
				OAT_LOGD("GOT IT: write -- clzDef - encode arry data, offset error\n");
#endif
				return False;
			} else {
				//memcpy(dexData->memMap.dexAddr + encode_data->write_off, dexFile->baseAddr + encode_data->read_off, encode_data->length);
				VG_(memcpy)(dexData->memMap.dexAddr + encode_data->write_off, dexFile->baseAddr + encode_data->read_off, encode_data->length);
				// adjust class def refer offset
				classDef->staticValuesOff = encode_data->write_off;
			}
		} else {
			// adjust class def refer offset
			classDef->staticValuesOff = 0;
		}

		//  OAT_LOGI("GOT IT: write -- class defs %d, start to write class data item,  refer: %d\n", i, clzDefItem->refer_clzDataItem);

		// write class data items, including code items for each method
		if (clzDefItem->refer_clzDataItem == -1) {
			classDef->classDataOff =  0;
#ifdef LOGI
			OAT_LOGI("GOT IT: write -- clzDef - clz_data,  classDef->classDataOff =  0\n");
#endif
			continue;
		}

		if (clzDefItem->refer_clzDataItem >= (Int) dexData->classData->size) {
#ifdef LOGI
			OAT_LOGD("GOT IT: write -- clzDef - class_data, refer  exceed size\n"); 
#endif
			return False;
		}

		struct DexDataItem* clz_data = &dexData->classData->items[clzDefItem->refer_clzDataItem];

		//  OAT_LOGI("GOT IT: write -- class defs %d, write class data item,  writeoff: %d, readoff: %d, num of methods: %d\n", i, clz_data->write_off, clz_data->read_off, clz_data->refer_code_num);
		if (clz_data->write_off == 0 || clz_data->read_off == 0) {
			//classDef->classDataOff =  0; 
#ifdef LOGI
			OAT_LOGI("GOT IT: write -- clzDef - clz_data, offset error\n");
#endif
			return False;
		} else {
			struct DexClassData* pData = (struct DexClassData*) (clz_data->data);
			if (pData == NULL) {
#ifdef LOGI
				OAT_LOGD("GOT IT: write -- clzDef - clz_data, pData == NULL\n");
#endif
				classDef->classDataOff = 0;
				continue;
			}

			struct DexDataItem* codeItem = NULL; 
			if (clz_data->refer_code_num <= 0) {
				if (pData->directMethods || pData->virtualMethods) {
#ifdef LOGI
					OAT_LOGI("GOT IT: write -- clz data items - code data, error, no refercode index array, but class has methods\n");
#endif
					return False;
				} else {
#ifdef LOGI
					OAT_LOGD("GOT IT: write -- clz data items - no code data to write, go to write class data\n");
#endif
				}
			} else {
				//struct MethodCodeRefer* codeRefer = (struct MethodCodeRefer*)(clz_data->refer_data);
				//OAT_LOGD("GOT IT: write -- class defs %d, write class data item,  got code Refer: %d", i, (Int) codeRefer);

				if (!pData->directMethods && !pData->virtualMethods) {
#ifdef LOGI
					OAT_LOGI("GOT IT: write -- clz data items - code data, error, has refer code, but class do not have  methods\n");
#endif
					return False;
				}
				//  OAT_LOGD("GOT IT: write -- class defs %d, write class data item,  start to write method code", i);
				u4 refer_index = 0;
				if (pData->directMethods) {
					//OAT_LOGD("GOT IT: write -- class defs %d, start write method code AFTER\n", i);
					for (u4 j = 0; j < pData->header.directMethodsSize; j++) {
						Int cur_code = clz_data->refer_code[refer_index++];
						if (cur_code == -1) {
							pData->directMethods[j].codeOff = 0;
						} else {
							codeItem = &dexData->codeData->items[cur_code];
							if (codeItem->write_off == 0) {
#ifdef LOGI
								OAT_LOGI("GOT IT: write -- clz data items - code data, offset error\n");
#endif
								return False;
							} else {
								if (codeItem->data == NULL) {
									pData->directMethods[j].codeOff = 0;
								} else {
									//memcpy(dexData->memMap.dexAddr + codeItem->write_off, (u1*) codeItem->data, codeItem->length);
									VG_(memcpy)(dexData->memMap.dexAddr + codeItem->write_off, (u1*) codeItem->data, codeItem->length);
									//adjust debug info to 0
									struct DexCode* code = (struct DexCode*) (dexData->memMap.dexAddr + codeItem->write_off);
									code->debugInfoOff = 0;
									// adjust class data itmes refer offset
									pData->directMethods[j].codeOff = codeItem->write_off;
								}
							}
						}
					}  
				}


				if (pData->virtualMethods) {
					for (u4 j=0; j<pData->header.virtualMethodsSize; j++) {
						Int cur_code = clz_data->refer_code[refer_index++];
						if (cur_code == -1) {
							pData->virtualMethods[j].codeOff = 0;
						} else {
							codeItem = &dexData->codeData->items[cur_code];
							if (codeItem->write_off == 0) {
#ifdef LOGI
								OAT_LOGI("GOT IT: write -- clz data items - code data, offset error\n");
#endif
								return False;
							} else {
								if (codeItem->data == NULL) {
									pData->virtualMethods[j].codeOff = 0;
								} else {
									//memcpy(dexData->memMap.dexAddr + codeItem->write_off, (u1*) codeItem->data, codeItem->length);
									VG_(memcpy)(dexData->memMap.dexAddr + codeItem->write_off, (u1*) codeItem->data, codeItem->length);
									//adjust debug info to 0
									struct DexCode* code = (struct DexCode*) (dexData->memMap.dexAddr + codeItem->write_off);
									code->debugInfoOff = 0;
									// adjust class data itmes refer offset
									pData->virtualMethods[j].codeOff = codeItem->write_off;
								}
							}
						}
					}
				}
			}


			Bool okay = verifyClassDataItem(dexData, pData);
			if (!okay) {
#ifdef LOGI
				OAT_LOGI("GOT IT: write class data , before write verify error\n");
#endif
				return False;
			} 

			Int clz_data_size = 0;
			u1* result = EncodeClassData(pData, &clz_data_size);
#ifdef LOGI
			//  OAT_LOGI("GOT IT: write -- class defs %d, write class data items to offset: 0x%x, datasize: %d\n", i, w_off_clz_data, clz_data_size);
#endif
			//memcpy(dexData->memMap.dexAddr + w_off_clz_data, result, clz_data_size);
			VG_(memcpy)(dexData->memMap.dexAddr + w_off_clz_data, result, clz_data_size);
			num_clz_written++;

			//adjust class def refer offset
			classDef->classDataOff =  w_off_clz_data;
			clz_data->write_off = w_off_clz_data;
			clz_data->length = clz_data_size;
			// free(result);
			//    OAT_LOGI("GOT IT: write -- class defs %d, free encoded class data\n", i); 
			VG_(free)(result);
			w_off_clz_data += clz_data_size;
		}
#ifdef LOGI
		//  OAT_LOGI("GOT IT: write -- class defs %d, after write class data items and method code\n", i);
#endif
	}


	// check wether the last class data item overlap with the mapList data
	if (w_off_clz_data > dexData->mapList->write_off) {
#ifdef LOGI
		OAT_LOGI("GOT IT, write class data overlap with the mapList being written and error\n");
#endif
		return False;
	}

	// write mapList and ajust the offset of non-considerred items
	Int itemSize = (dexData->mapList->length - 4) / sizeof(struct DexMapItem);

	// OAT_LOGI("GOT IT: start to write -- mapList, itemSize: %d, length: %d, mapList->data : %08x\n", itemSize, dexData->mapList->length);
	//memcpy(dexData->memMap.dexAddr + dexData->mapList->write_off, dexData->mapList->data, dexData->mapList->length);
	// VG_(memcpy)(dexData->memMap.dexAddr + dexData->mapList->write_off, dexData->mapList->data, dexData->mapList->length);
	struct DexMapList* mapList = (struct DexMapList*) (dexData->memMap.dexAddr + dexData->mapList->write_off);
	mapList->size = itemSize;

	//  OAT_LOGI("GOT IT: after write -- mapList and start to ajust each item\n");

	Int i = 0;
	if (dexData->header != NULL) {
		mapList->list[i].type = kDexTypeHeaderItem;
		mapList->list[i].size = 1;
		mapList->list[i].offset = dexData->header->write_off; 
		i++;
	}


	if (dexData->stringIds != NULL) {
		mapList->list[i].type = kDexTypeStringIdItem;
		mapList->list[i].size = dexData->stringIds->size;
		mapList->list[i].offset = dexData->stringIds->write_off; 
		i++;
	}


	if (dexData->typeIds != NULL) {
		mapList->list[i].type = kDexTypeTypeIdItem;
		mapList->list[i].offset = dexData->typeIds->write_off;
		mapList->list[i].size = dexData->typeIds->size;
		i++;
	}


	if (dexData->protoIds != NULL) {
		mapList->list[i].type = kDexTypeProtoIdItem;
		mapList->list[i].offset = dexData->protoIds->write_off;
		mapList->list[i].size = dexData->protoIds->size;
		i++;
	}


	if (dexData->fieldIds != NULL) {
		mapList->list[i].type = kDexTypeFieldIdItem;
		mapList->list[i].offset = dexData->fieldIds->write_off;	
		mapList->list[i].size= dexData->fieldIds->size;
		i++;
	}


	if (dexData->methodIds != NULL) {
		mapList->list[i].type = kDexTypeMethodIdItem;
		mapList->list[i].offset = dexData->methodIds->write_off;
		mapList->list[i].size = dexData->methodIds->size;
		i++;
	}


	if (dexData->classDefs != NULL) {
		mapList->list[i].type = kDexTypeClassDefItem;
		mapList->list[i].offset = dexData->classDefs->write_off;
		mapList->list[i].size = dexData->classDefs->size;
		i++;
	}


	if (dexData->typeListData != NULL) {
		mapList->list[i].type = kDexTypeTypeList;
		mapList->list[i].offset = dexData->typeListData->write_off;
		mapList->list[i].size = dexData->typeListData->size;
		i++;
	}


	if (dexData->annoSetRefListData != NULL) {
		mapList->list[i].type = kDexTypeAnnotationSetRefList;
		mapList->list[i].offset = dexData->annoSetRefListData->write_off;
		mapList->list[i].size = dexData->annoSetRefListData->size;
		i++;
	}


	if (dexData->annoSetData != NULL) {
		mapList->list[i].type = kDexTypeAnnotationSetItem;
		mapList->list[i].offset = dexData->annoSetData->write_off;
		mapList->list[i].size = dexData->annoSetData->size;
		i++;
	}


	if (dexData->classData != NULL) {
		mapList->list[i].type = kDexTypeClassDataItem;
		mapList->list[i].offset = dexData->classData->write_off;
		mapList->list[i].size = dexData->classData->size; 
		i++;
	}


	if (dexData->codeData != NULL) {
		mapList->list[i].type = kDexTypeCodeItem;
		mapList->list[i].offset = dexData->codeData->write_off;
		mapList->list[i].size = dexData->codeData->size;
		i++;
	}


	if (dexData->stringData != NULL) {
		mapList->list[i].type = kDexTypeStringDataItem;
		mapList->list[i].offset = dexData->stringData->write_off;
		mapList->list[i].size = dexData->stringData->size;
		i++;
	}


	if (dexData->debugInfoData != NULL) {
		mapList->list[i].type = kDexTypeDebugInfoItem;
		mapList->list[i].offset = dexData->debugInfoData->write_off;
		mapList->list[i].size = dexData->debugInfoData->size;
		i++;
	}


	if (dexData->annoData != NULL) {
		mapList->list[i].type = kDexTypeAnnotationItem;
		mapList->list[i].offset = dexData->annoData->write_off;
		mapList->list[i].size = dexData->annoData->size;
		i++;
	}


	if (dexData->encodeArrayData != NULL) {
		mapList->list[i].type = kDexTypeEncodedArrayItem;
		mapList->list[i].offset = dexData->encodeArrayData->write_off;
		mapList->list[i].size = dexData->encodeArrayData->size;
		i++;
	}


	if (dexData->annosDirectoryData != NULL) {
		mapList->list[i].type = kDexTypeAnnotationsDirectoryItem;
		mapList->list[i].offset = dexData->annosDirectoryData->write_off;
		mapList->list[i].size = dexData->annosDirectoryData->size;
		i++;
	}


	if (dexData->mapList != NULL) {
		mapList->list[i].type =  kDexTypeMapList;
		mapList->list[i].offset = dexData->mapList->write_off;
		mapList->list[i].size = 1;
		i++;
	}


	if (i > itemSize) {
#ifdef LOGI
		OAT_LOGI("GOT IT, write mapList, size > calculated item size and error\n");
#endif
		return False;
	}

	/* write the magic number , signature, and checksum of dex file header  */
	u1 DEX_FILE_MAGIC[8] = {0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00};
	//memcpy(pHeader->magic, DEX_FILE_MAGIC, 8);
	VG_(memcpy)(pHeader->magic, DEX_FILE_MAGIC, 8);

	/* recalculate the signature of dex file, be careful that the length may change after write the class data items */
	// u1 sha1Digest[kSHA1DigestLen];
	// const Int nonSum = sizeof(pHeader->magic) + sizeof(pHeader->checksum) + kSHA1DigestLen;
	//dexComputeSHA1Digest(dexData->memMap.dexAddr + nonSum, length - nonSum, sha1Digest);
	//memcpy(pHeader->signature, sha1Digest, kSHA1DigestLen);
	// VG_(memcpy)(pHeader->signature, sha1Digest, kSHA1DigestLen);
	/* recalculate the checksum of dex file */
#ifdef LOGI
	u4 save_checksum = pHeader->checksum;
#endif
	pHeader->checksum = dexComputeChecksum(pHeader);
#ifdef LOGI
	OAT_LOGI("GOT IT: write -- header checksum- need change to from %08x to  %08x,,  headerSize: %d\n", save_checksum, pHeader->checksum, pHeader->headerSize); 
#endif
	return True;
	}


	void clearDexData(struct DexFileData* dexData) {

		//   OAT_LOGI("GOT IT: set the dexData memMap start address to NULL\n");
		/*******clear mem map******/
		if (dexData->memMap.startAddr != NULL) {
			//free(dexData->memMap.startAddr);
			// leave for caller to free
			dexData->memMap.startAddr = NULL;
		}

		//  OAT_LOGI("GOT IT: clear dexData header\n");
		/*******clear header*******/
		if (dexData->header != NULL) {
			if (dexData->header->data != NULL) {
				// VG_(free)(dexData->header->data);
				dexData->header->data = NULL;
			}
			VG_(free)(dexData->header);
			dexData->header = NULL;
		}

		//   OAT_LOGI("GOT IT: clear dexData string ids\n");
		/********clear stringIds ******/
		if (dexData->stringIds != NULL) {
			//  OAT_LOGI("GOT IT: clear each string id item\n");
			for (u4 i = 0; i < dexData->stringIds->size; i++) {
				if (dexData->stringIds->items[i].data != NULL) {
					//free(dexData->stringIds->items[i].data);
					//VG_(free)(dexData->stringIds->items[i].data);
					dexData->stringIds->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->stringIds);
			dexData->stringIds = NULL;
		}

		//  OAT_LOGI("GOT IT: clear dexData type ids\n");
		/********clear typeIds *******/
		if (dexData->typeIds != NULL) {
			for (u4 i = 0; i < dexData->typeIds->size; i++) {
				if (dexData->typeIds->items[i].data != NULL) {
					//VG_(free)(dexData->typeIds->items[i].data);
					dexData->typeIds->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->typeIds);
			dexData->typeIds = NULL;
		}   

		//  OAT_LOGI("GOT IT: clear dexData field ids\n");
		/********clear fieldIds *********/    
		if (dexData->fieldIds != NULL) {
			for (u4 i = 0; i < dexData->fieldIds->size; i++) {
				if (dexData->fieldIds->items[i].data != NULL) {
					//VG_(free)(dexData->fieldIds->items[i].data);
					dexData->fieldIds->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->fieldIds);
			dexData->fieldIds = NULL;
		}   

		//  OAT_LOGI("GOT IT: clear dexData method ids\n");
		/******** clear methodIds *******/
		if (dexData->methodIds != NULL) {
			for (u4 i = 0; i < dexData->methodIds->size; i++) {
				if (dexData->methodIds->items[i].data != NULL) {
					//VG_(free)(dexData->methodIds->items[i].data);
					dexData->methodIds->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->methodIds);
			dexData->methodIds = NULL;
		}  

		//  OAT_LOGI("GOT IT: clear dexData proto ids\n");
		/******* clear protoIds ********/
		if (dexData->protoIds != NULL) {
			for (u4 i = 0; i < dexData->protoIds->size; i++) {
				if (dexData->protoIds->items[i].data != NULL) {
					//VG_(free)(dexData->protoIds->items[i].data);
					dexData->protoIds->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->protoIds);
			dexData->protoIds = NULL;
		} 

		//  OAT_LOGI("GOT IT: clear dexData class defs\n");
		/******* clear classDefs ********/
		if (dexData->classDefs != NULL) {
			for (u4 i = 0; i < dexData->classDefs->size; i++) {
				if (dexData->classDefs->items[i].data != NULL) {
					//VG_(free)(dexData->classDefs->items[i].data);
					dexData->classDefs->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->classDefs);
			dexData->classDefs = NULL;
		}  

		/******* clear mapList ********/
		if (dexData->mapList != NULL) {
			if (dexData->mapList->data != NULL) {
				VG_(free)(dexData->mapList->data);
				dexData->mapList->data = NULL;
			}
			//OAT_LOGI("GOT IT: clear dexData map list itself \n");
			//VG_(free)(dexData->mapList);    // TBD
			dexData->mapList = NULL;
			// OAT_LOGI("GOT IT: clear dexData map list itself  end\n");
		}      

		//  OAT_LOGI("GOT IT: clear dexData typeList data\n");
		/********clear typeListData ******/
		if (dexData->typeListData != NULL) {
			for (u4 i = 0; i < dexData->typeListData->size; i++) {
				if (dexData->typeListData->items[i].data != NULL) {
					//VG_(free)(dexData->typeListData->items[i].data);
					dexData->typeListData->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->typeListData);
			dexData->typeListData = NULL;
		}  

		/*
		 * skip annoSetRefListData, annoSetData, debugInfoData, annoData, annosDirectoryData 
		 */////////////////////

		//  OAT_LOGI("GOT IT: clear dexData class data\n");
		/*********clear classData ********/
		if (dexData->classData != NULL) { 
			for (u4 i = 0; i < dexData->classData->size; i++) {
				if (dexData->classData->items[i].data != NULL) {
					//VG_(free)(dexData->classData->items[i].data);
					dexData->classData->items[i].data = NULL;
				}
			}

			VG_(free)(dexData->classData);
			dexData->classData = NULL;
		}  

		//  OAT_LOGI("GOT IT: clear dexData code data\n");
		/*********clear codeData ********/
		if (dexData->codeData != NULL) {
			for (u4 i = 0; i < dexData->codeData->size; i++) {
				if (dexData->codeData->items[i].data != NULL) {
					//VG_(free)(dexData->codeData->items[i].data);
					dexData->codeData->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->codeData);
			dexData->codeData = NULL;
		}  

		//  OAT_LOGI("GOT IT: clear dexData string data\n");
		/*********clear stringData ********/
		if (dexData->stringData != NULL) {
			for (u4 i = 0; i < dexData->stringData->size; i++) {
				if (dexData->stringData->items[i].data != NULL) {
					//VG_(free)(dexData->stringData->items[i].data);
					dexData->stringData->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->stringData);
			dexData->stringData = NULL;
		}   

		//   OAT_LOGI("GOT IT: clear dexData encodeArray data\n");

		/**********clear encodeArrayData ****/
		if (dexData->encodeArrayData != NULL) {
			for (u4 i = 0; i < dexData->encodeArrayData->size; i++) {
				if (dexData->encodeArrayData->items[i].data != NULL) {
					//VG_(free)(dexData->encodeArrayData->items[i].data);
					dexData->encodeArrayData->items[i].data = NULL;
				}
			}
			VG_(free)(dexData->encodeArrayData);
			dexData->encodeArrayData = NULL;
		}            

		//   OAT_LOGI("GOT IT: clear dexData itself\n");
		/********* clear dexData itself *****/
		if (dexData != NULL) {
			VG_(free)(dexData);
			dexData = NULL;
		}
		// OAT_LOGI("GOT IT: clear dexData end\n");

	}


	/**
	 * the main entrypoInt for dex reassembling
	 *
	 */
	u1* reassembleAndDumpDexClone(struct DexFile* pDexFile, u4* len) {

		struct DexFile* dexFile= pDexFile;

		OAT_LOGI("start to reassemble dex from dex file.\n");

		struct DexFileData* dexData = (struct DexFileData*)VG_(malloc)("New.assemble.dexfiledata", sizeof(struct DexFileData));
		tl_assert(dexData);
		VG_(memset)((Addr)dexData, 0, sizeof(struct DexFileData));

		OAT_LOGI("start to collect dex file data from dex file 0x%08x.\n", (Addr)pDexFile);

		collectDexFileData(dexFile, dexData);

		OAT_LOGI("start to try write these data to obtain their offset.\n");
		/* try to calculate the offset of each data items */
		u4 length = 0;
		Bool res = tryWriteDexData(dexData, dexFile, &length);
		if (!res) {        
			OAT_LOGI("GOT IT: error when collecting structs and return\n");
			return NULL;
		}

		// OAT_LOGI("start to allocate memory to store these data, length: %d.\n", length);
		/* allocate a memory to store these data at first*/

		//void* mptr = malloc(length);
		void* mptr = (void *) VG_(malloc)("New.assemble.normal", length);
		tl_assert(mptr);
		if (mptr == NULL) {
			OAT_LOGD("GOT IT: malloc for dex failure!\n");
			return NULL;
		}

		//memset(dexData->memMap.startAddr, 0, dexData->memMap.length);
		VG_(memset)((Addr)mptr, 0, length);  
		//  OAT_LOGI("after allocate memory to store these data, length: %d.\n", length);
		// cannot create opt header
		u4 optHeaderSize = 0;

		dexData->memMap.startAddr = (u1*) mptr;
		dexData->memMap.dexAddr = dexData->memMap.startAddr + optHeaderSize;
		dexData->memMap.length = length;
		dexData->memMap.dexLength = length - optHeaderSize;

		OAT_LOGI("start to write dex data lengh = %d\n", length);
		/* write the data to the memory according their offset */
		if (!writeDexData(dexData, dexFile, length)) {
			OAT_LOGI("GOT IT: error when writting dex data\n");
			return NULL;
		}


		OAT_LOGI("start to clear dex data\n");

		/* clear the memory allocated */
		if (dexData != NULL) {
			clearDexData(dexData);
		}
		OAT_LOGI("after clearing dex data\n");
		*len = length;
		return (u1*) mptr;
	}


	/********************************End    Dex File Reassemble ***********************************************/

