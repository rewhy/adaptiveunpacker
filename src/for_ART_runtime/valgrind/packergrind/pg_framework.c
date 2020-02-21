// dt_framework.c
//
#include "pub_tool_basics.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_guest.h"
#include "pub_core_threadstate.h"

#include "pg_debug.h"
#include "runtime/rt_object.h"
#include "pg_oatparse.h"
#include "pg_dexparse.h"
#include "pg_mthtrace.h"
#include "pg_framework.h"

#define UNKNOWN_CLASS_NAME		"???"
#define TMP_STR_SIZE		1024

#define	T	"\e[31mY"
#define	F	"N"


HChar tmp_string_str[TMP_STR_SIZE];
HChar tmp_class_name[TMP_STR_SIZE];

static int enc_unicode_to_utf8_one(ULong unic, UChar *pOutput, Int outSize)  
{  
	tl_assert(pOutput != NULL);  
	tl_assert(outSize >= 6);  

	if ( unic <= 0x0000007F )  
	{  
		// * U-00000000 - U-0000007F:  0xxxxxxx  
		*pOutput     = (unic & 0x7F);  
		return 1;  
	}  
	else if ( unic >= 0x00000080 && unic <= 0x000007FF )  
	{  
		// * U-00000080 - U-000007FF:  110xxxxx 10xxxxxx  
		*(pOutput+1) = (unic & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 6) & 0x1F) | 0xC0;  
		return 2;  
	}  
	else if ( unic >= 0x00000800 && unic <= 0x0000FFFF )  
	{  
		// * U-00000800 - U-0000FFFF:  1110xxxx 10xxxxxx 10xxxxxx  
		*(pOutput+2) = (unic & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >>  6) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 12) & 0x0F) | 0xE0;  
		return 3;  
	}  
	else if ( unic >= 0x00010000 && unic <= 0x001FFFFF )  
	{  
		// * U-00010000 - U-001FFFFF:  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+3) = (unic & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 12) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 18) & 0x07) | 0xF0;  
		return 4;  
	}  
	else if ( unic >= 0x00200000 && unic <= 0x03FFFFFF )  
	{  
		// * U-00200000 - U-03FFFFFF:  111110xx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+4) = (unic & 0x3F) | 0x80;  
		*(pOutput+3) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >> 12) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 18) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 24) & 0x03) | 0xF8;  
		return 5;  
	}  
	else if ( unic >= 0x04000000 && unic <= 0x7FFFFFFF )  
	{  
		// * U-04000000 - U-7FFFFFFF:  1111110x 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx 10xxxxxx  
		*(pOutput+5) = (unic & 0x3F) | 0x80;  
		*(pOutput+4) = ((unic >>  6) & 0x3F) | 0x80;  
		*(pOutput+3) = ((unic >> 12) & 0x3F) | 0x80;  
		*(pOutput+2) = ((unic >> 18) & 0x3F) | 0x80;  
		*(pOutput+1) = ((unic >> 24) & 0x3F) | 0x80;  
		*pOutput     = ((unic >> 30) & 0x01) | 0xFC;  
		return 6;  
	}  

	return 0;  
}

HChar *get_classobject_name(ClassMirror *clazz) {
	if(!clazz) {
		//VG_(printf)("Object@0x%08x NULL.\n", (Addr)clazz);
		return UNKNOWN_CLASS_NAME;
	}
#if DBG_PARAMETER_PARSE
	VG_(printf)("Object@0x%08x type index: %d ClassDef index: %d\n",
			(Addr)clazz, clazz->dex_type_idx_, clazz->dex_class_def_idx_);
#endif
	StringMirror *strMi = clazz->name_;
	if(!strMi) {
		return UNKNOWN_CLASS_NAME;
	}
	Int size = 0, i = 0;
	UShort *value = NULL;
#if DBG_PARAMETER_PARSE
	VG_(printf)("Object@0x%08x flags: 0x%08x len=%d\n", (Addr)clazz, clazz->access_flags_ >> 16, strMi->count_);
#endif
	if(strMi->count_ > 0) {
		size = TMP_STR_SIZE-1 < strMi->count_ ? TMP_STR_SIZE-1 : strMi->count_;
		value = strMi->value_;
		for(i=0; i < size; i++) {
			tmp_class_name[i] = (UChar)value[i];
		}
		tmp_class_name[i] = '\0';
		return tmp_class_name;
	}
	return UNKNOWN_CLASS_NAME;
}
	static
HChar* get_stringobj_str(Addr addr)
{
	StringMirror *strObj = (StringMirror *)addr;
	Int size = 0, i = 0, j = 0;
	UShort *value = NULL;
	ClassMirror *clazz = strObj->object_.klass_;
	HChar *t = get_classobject_name(clazz);
#if 0
	TNT_LOGI("%s@%08x \n", t, (Addr)clazz);
#endif
	if(strObj && strObj->count_ > 0) {
		size = TMP_STR_SIZE-1 < strObj->count_ ? TMP_STR_SIZE-1 : strObj->count_;
		value = strObj->value_;
		for(i=0; i < size; i++) {
			//tmp_string_str[i] = (UChar)value[i];
			j += enc_unicode_to_utf8_one(value[i], tmp_string_str+j, TMP_STR_SIZE-j);
		}
		tmp_string_str[i] = '\0';
		return tmp_string_str;
	}
	return NULL;
}
UShort* get_string_content(Addr addr)
{
	StringMirror *strObj = (StringMirror *)addr;
	if(strObj && strObj->count_ > 0) {
		return strObj->value_;
	}
	return NULL;
}
/*
 * From: art/compiler/dex/quick/arm/arm_lir.h
 * Runtime register usage conventions.
 *
 * r0-r3: Argument registers in both Dalvik and C/C++ conventions.
 *        However, for Dalvik->Dalvik calls we'll pass the target's Method*
 *        pointer in r0 as a hidden arg0. Otherwise used as codegen scratch
 *        registers.
 * r0-r1: As in C/C++ r0 is 32-bit return register and r0/r1 is 64-bit
 * r4   : If ARM_R4_SUSPEND_FLAG is set then reserved as a suspend check/debugger
 *        assist flag, otherwise a callee save promotion target.
 * r5   : Callee save (promotion target)
 * r6   : Callee save (promotion target)
 * r7   : Callee save (promotion target)
 * r8   : Callee save (promotion target)
 * r9   : (rARM_SELF) is reserved (pointer to thread-local storage)
 * r10  : Callee save (promotion target)
 * r11  : Callee save (promotion target)
 * r12  : Scratch, may be trashed by linkage stubs
 * r13  : (sp) is reserved
 * r14  : (lr) is reserved
 * r15  : (pc) is reserved
 *
 * 5 core temps that codegen can use (r0, r1, r2, r3, r12)
 * 7 core registers that can be used for promotion
 *
 * Floating pointer registers
 * s0-s31
 * d0-d15, where d0={s0,s1}, d1={s2,s3}, ... , d15={s30,s31}
 *
 * s16-s31 (d8-d15) preserved across C calls
 * s0-s15 (d0-d7) trashed across C calls
 *
 * s0-s15/d0-d7 used as codegen temp/scratch
 * s16-s31/d8-d31 can be used for promotion.
 *
 * Calling convention
 *     o On a call to a Dalvik method, pass target's Method* in r0
 *     o r1-r3 will be used for up to the first 3 words of arguments
 *     o Arguments past the first 3 words will be placed in appropriate
 *       out slots by the caller.
 *     o If a 64-bit argument would span the register/memory argument
 *       boundary, it will instead be fully passed in the frame.
 *     o Maintain a 16-byte stack alignment
 *
 *  Stack frame diagram (stack grows down, higher addresses at top):
 *
 * +------------------------+
 * | IN[ins-1]              |  {Note: resides in caller's frame}
 * |       .                |
 * | IN[0]                  |
 * | caller's Method*       |
 * +========================+  {Note: start of callee's frame}
 * | spill region           |  {variable sized - will include lr if non-leaf.}
 * +------------------------+
 * | ...filler word...      |  {Note: used as 2nd word of V[locals-1] if long]
 * +------------------------+
 * | V[locals-1]            |
 * | V[locals-2]            |
 * |      .                 |
 * |      .                 |
 * | V[1]                   |
 * | V[0]                   |
 * +------------------------+
 * |  0 to 3 words padding  |
 * +------------------------+
 * | OUT[outs-1]            |
 * | OUT[outs-2]            |
 * |       .                |
 * | OUT[0]                 |
 * | cur_method*            | <<== sp w/ 16-byte alignment
* +========================+
*/

/*
 * L:		jobject
 * V:		void
 * Z:		bool
 * B:		Byte
 * C:		Char
 * D:		Double
 * F:		Float
 * I:		Int
 * J:		Long
 * S:		Shorty
 */

static 
UInt process_array_arg(HChar *clazz, Addr addr) {
	tl_assert(clazz[0] == '[');
	ArrayMirror *array = (ArrayMirror *)addr;
	UInt j = 0, size = 0;
	HChar *cv = NULL;
	Int		*iv = NULL;
	Long	*jv = NULL;
	Int len = array->length_ > 2 ? 2 : array->length_;
	switch(clazz[1]) {
		case 'B':
		case 'C':
			cv = (HChar*)array->first_element_;
			size = 1;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%02x ", cv[j]);
			VG_(printf)("\n");
			break;
		case 'Z':
			size = 1;
			break;
		case 'S':
			size = 2;
			break;
		case 'I':
			iv = (Int*)array->first_element_;
			size = 4;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%d ", iv[j]);
			VG_(printf)("\n");
			break;
		case 'J':
			jv = (Long*)array->first_element_;
			size = 8;
			VG_(printf)("\t%s: ", clazz);
			for( j = 0; j < len; j++)
				VG_(printf)("%lld ", jv[j]);
			VG_(printf)("\n");
			break;
		case 'L':
			size = 4;
			break;
		case 'F':
			size = 4;
			break;
		case 'D':
			size = 8;
			break;
		case 'V':
		default:
			break;
	}
	return array->length_ * size;
}

/*----------------- For check parameters --------------*/

Int check_mth_invoke(MthNode *mNode, ThreadId tid)
{
	if(mNode == NULL || mNode->shorty == NULL) {
		TNT_LOGI("%s shorty is NULL!!!!\n", mNode->method);
		return;
	}
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	struct ArtMethod *pAMth = NULL;
	ClassMirror		*clazz = NULL;
	UInt	objSize = 0, clazzSize = 0;
	Addr	objAddr = 0;
	HChar *tmp = UNKNOWN_CLASS_NAME;//, *tmp1 = NULL;
	HChar type = '\0';
	Word *r;
	Float	*s;
	HChar *content;
	Int tt, i = 0, j = 0, f = 0, len = 0;
	UInt    *psp;
	Addr		sp;
	Bool		bres;
	HChar		cres;
	Short		sres;
	Int			ires;
	Long		jres;
	Float		fres, fres1;
	Double	dres, dres1;
# if defined(VGPV_arm_linux_android)
	r = (Word*)&arch_state->guest_R0;
	s = (Float*)&arch_state->guest_D0;
	sp		= r[13]+16;
	psp   = (UInt*)(r[13]);
#endif
#if DBG_PARAMETER_PARSE
	VG_(printf)("r0=%08x r1=%08x r2=%08x r3=%08x sp=%08x lr=%08x pc=%08x\n",
			r[0], r[1], r[2], r[3], r[13], r[14], r[15]);
	VG_(printf)("s0=%f s1=%f s2=%f s3=%f\n",
			s[0], s[1], s[2], s[3]);
	VG_(printf)("0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x 0x%08x\n",
			psp[0], psp[1], psp[2], psp[3], psp[4], psp[5], psp[6], psp[7], psp[8], psp[9], psp[10]);
#endif 
	/* Check parameters */
	i = 1;
	if(mNode->accessFlags & ACC_STATIC) { // Static method
		j = 1;
	} else {
		j = 2;
		clazz = (ClassMirror*)r[1];
		if(clazz) {
			clazz = clazz->object_.klass_;
			if(clazz) 
				tmp = get_classobject_name(clazz);
			else
				tmp = "???";
		}
		content = NULL;
		if(VG_(strcmp)("java.lang.String", tmp) == 0) {
			content = get_stringobj_str((StringMirror *)r[1]);
		}
		TNT_LOGI("[00] \'class\' %s@0x%08x ", tmp, r[1]);
		if(content)
			VG_(printf)("(c:%s)\n", content);
		else
			VG_(printf)("\n");
	}
#if DBG_PARAMETER_PARSE
	pAMth = (struct ArtMethod *)r[0];
	VG_(printf)("key=%d flags=0x%08x (0x%08x) dex_method_index=%d method_index=%d\n", mNode->mthKey,
			pAMth->access_flags_, mNode->accessFlags, pAMth->dex_method_index_, pAMth->method_index_);
#endif
	while(i < VG_(strlen)(mNode->shorty)) {
		type = mNode->shorty[i];
		switch(type) {
			case 'L':
				clazzSize = 0;
				objSize   = 0;
				if(j < 4) {
					if(r[j] > 0)
						clazz = (ClassMirror *)(r[j]);
					else
						clazz = NULL;
					j += 1;
				}	else {
					clazz = (ClassMirror*)(*((Addr*)sp));
					sp += sizeof(Addr);
				}
				objAddr = (Addr)clazz;
				if((Addr)clazz & (0xffff << 16))
					clazz = clazz->object_.klass_;
				else 
					clazz = NULL;
				if(clazz) {
					tmp = get_classobject_name(clazz);
					clazzSize = clazz->class_size_;
					objSize		= clazz->object_size_;;
				}	else {
					tmp = "???";
				}
				content = NULL;
				if(tmp[0] == '[') {
					len = process_array_arg(tmp, objAddr);
				} else if(VG_(strcmp)("java.lang.String", tmp) == 0) {
					content = get_stringobj_str((StringMirror *)objAddr);
				}
				TNT_LOGI("[%02d] \'class\' %s@0x%08x %d(%d) ", 
						i, tmp, objAddr, clazzSize, objSize);
				if(content)
					VG_(printf)("(c:%s)\n", content);
				else
					VG_(printf)("\n");
				break;
			case 'Z': // Bool
				if( j < 4) {
					bres = (Bool)r[j];
					j += 1;
				} else {
					bres = (Bool)(*(Int*)sp);
					sp += sizeof(Int);
				}
				TNT_LOGI("[%02d] \'Bool\' %d\n", i, bres);
				break;
			case 'C':
				if( j < 4) {
					cres = (HChar)r[j];
					j += 1;
				} else {
					cres = (HChar)(*(Int*)sp);
					sp += sizeof(Int);
				}
				TNT_LOGI("[%02d] \'char\' %c\n", i, cres);
				break;
			case 'S':
				if( j < 4) {
					sres = (Short)r[j];
					j += 1;
				} else {
					sres = (Short)(*(Int*)sp);
					sp += sizeof(Int);
				}
				TNT_LOGI("[%02d] \'Short\' %d\n", i, sres);
				break;
			case 'I':
				if( j < 4) {
					ires = (Int)r[j];
					j += 1;
				} else {
					ires = *(Int*)sp;
					sp += sizeof(Int);
				}
				TNT_LOGI("[%02d] \'Int\' 0x%x\n", i, ires);
				break;
			case 'J':
				if( j < 3) {
					jres = (Long)r[j+1] << 32;
					jres |= r[j];
					j += 2;
				} else {
					jres = *(Long*)sp;
					sp += sizeof(Long);
				}
				TNT_LOGI("[%02d] \'Long\' 0x%llx\n", i, jres);
				break;
			case 'F':
#if 0
				if( j < 4) {
					fres = *((Float*)&r[j]);
					j += 1;
				} else {
					sp += sizeof(Float);
					fres = *(Float*)sp;
				}
#else
				fres = s[f];
				f += 1;
				if( j >= 4 ) {
					fres1 = *((Float*)sp);
					sp += sizeof(Float);
				}
#endif
				TNT_LOGI("[%02d] \'Float\' %f (%f).\n", i, fres, fres1);
				break;
			case 'D':
#if 0
				if( j < 3) {
					dres = *((Double*)&r[j]);
					j += 2;
				} else {
					jres = (*(Long*)sp);
					sp += sizeof(Double);
					dres = (Double)jres;
				}
#else
				dres = *((Double*)&s[f]);
				f += 2;
				if( j >= 4 ) {
					dres1 = *((Double*)sp);
					sp += sizeof(Double);
				}
#endif
				TNT_LOGI("[%02d] \'Double\' %f (%f).\n", i, dres, dres1);
				break;
			case 'V':
				tl_assert(0);
				break;
			default:
				TNT_LOGI("[%02d] unknown \'C\'\n",
						i, type);
				break;
		}
		i++;
	};
}

Int check_mth_return(MthNode *mNode, ThreadId tid)
{
	if(mNode == NULL || mNode->shorty == NULL) {
		TNT_LOGI("%s shorty is NULL!!!!\n", mNode->method);
		return;
	}
	if(mNode->shorty[0] == 'V') {
		return;
	}
	ThreadState *tst	= VG_(get_ThreadState) ( tid );
	VexGuestArchState *arch_state = &tst->arch.vex;
	HChar type = '\0';
	UWord *r;
	Float *s;
	Addr		sp;
	UInt	len = 0;
	ClassMirror		*clazz = NULL;
	HChar *tmp = NULL, *content = NULL;
	Bool		bres;
	HChar		cres;
	Short		sres;
	Int			ires;
	Long		jres;
	Float		fres, fres1;
	Double	dres, dres1;
# if defined(VGPV_arm_linux_android)
	r	= (UWord*)&arch_state->guest_R0;
	s = (Float*)&arch_state->guest_D0;
	sp		= r[13];
#endif
#if DBG_PARAMETER_PARSE
	TNT_LOGI("r0=0x%08x r1=0x%08x s0=%f s1=%f sp=0x%08x\n", 
			r[0], r[1], s[0], s[1], sp);
#endif

	/* Check parameters */
	type = mNode->shorty[0];
	switch(type) {
		case 'L':
			if((r[0] == 0x0) 
					|| ((r[0] & 0xff000000) == 0x0)
					|| ((r[0] & 0xff000000) == 0xff000000)) {
				TNT_LOGI("[99] Unknown res@0x%08x\n", r[0]);
				break;
			}
			clazz = (ClassMirror *)r[0];
			if((Addr)clazz) {
				clazz = clazz->object_.klass_;
			} else {
				clazz = NULL;
			}
			if(clazz) {
				tmp =  get_classobject_name(clazz);	
			} else {
				tmp = "????";
			}

			if(tmp[0] == '[') {
				len = process_array_arg(tmp, r[0]);
			} else if(VG_(strcmp)("java.lang.String", tmp) == 0) {
				content = get_stringobj_str((StringMirror *)r[0]);
			}
			TNT_LOGI("[99] \'class\' %s@0x%08x ",	tmp, r[0]);
			if(content)
				VG_(printf)("(c:%s)\n", content);
			else
				VG_(printf)("\n");
			break;
		case 'Z': // Bool
			bres = (Bool)r[0];
			TNT_LOGI("[99] \'Bool\' %d\n", bres);
			break;
		case 'C':
			cres = (HChar)r[0];
			TNT_LOGI("[99] \'char\' %c\n", cres);
			break;
		case 'S':
			sres = (Short)r[0];
			TNT_LOGI("[99] \'Short\' %d\n", sres);
			break;
		case 'I':
			ires = (Int)r[0];
			TNT_LOGI("[99] \'Int\' 0x%x\n", ires);
			break;
		case 'J':
			jres = (Long)r[1] << 32;
			jres |= r[0];
			TNT_LOGI("[99] \'Long\' 0x%llx\n", jres);
			break;
		case 'F':
			fres = *(Float*)r;
			fres1= *(Float*)s;
			TNT_LOGI("[99] \'Float\' %f (%f)\n", fres1, fres);
			break;
		case 'D':
			dres = *(Double*)r;
			dres1= *(Double*)s;
			TNT_LOGI("[99] \'Double\' %f (%f)\n", dres1, dres);
			break;
		case 'V':
		default:
			break;
	}
	return 0;
}
