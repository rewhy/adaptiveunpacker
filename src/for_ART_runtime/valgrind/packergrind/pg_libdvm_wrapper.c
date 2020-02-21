//pg_libdvm_wrapper.c

/*--------------- DVM related wrappers ---------------------*/
#define  BG_Z_LIBDVM_SONAME  libdvmZdsoZa              // libdvm.so*
#define LIBDVM_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBDVM_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBDVM_SONAME,f)(args)

static Bool is_so_loading = False;
//void dvmCallJNIMethod(const u4* args, JValue* pResult,
//     const Method* method, Thread* self);
void dvmCallJNIMethod_wrapper(const uint32_t* args, void* pResult, const void* method,	void* self)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMCALLJNIMTH_PRE, uint32_t*, args, void*, pResult, void*, method,
			void*, self);
	CALL_FN_v_WWWW(fn, args, pResult, method, self);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMCALLJNIMTH, uint32_t*, args, void*, pResult, void*, method,
			void*, self);
}
//
//_Z16dvmCallJNIMethodPKjP6JValuePK6MethodP6Thread
LIBDVM_FUNC(void, _Z16dvmCallJNIMethodPKjP6JValuePK6MethodP6Thread,
		const uint32_t* args, void* pResult, const void* method, void* self)
{
	dvmCallJNIMethod_wrapper(args, pResult, method, self);
}

/*
 * Convert argc/argv into a function call.  This is platform-specific.
 */
// extern "C" void dvmPlatformInvoke(void* pEnv, ClassObject* clazz, int argInfo,
//     int argc, const u4* argv, const char* signature, void* func, JValue* pResult);
// In dvmCallJNIMethod(), dvmPlatformInvoke is used to call the native method(signature in Method.insns).
//
#if 0
void dvmPlatformInvoke(void* pEnv, void* clazz, int argInfo, int argc, const unsigned int* argv,
		const char* signature, void* func, void* pResult)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMPLATFORMINVOKE_PRE, void*, clazz, void*, func, int, argc,
			void*, argv);
	CALL_FN_v_8W(fn, pEnv, clazz, argInfo, argc, argv, signature, func, pResult);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMFLATFORMINVOKE, void*, clazz, void*, func, int, argc,
			void*, argv);
}
//  dvmPlatformInvoke
LIBDVM_FUNC(void, dvmPlatformInvoke,
		void* pEnv, void* clazz, int argInfo, int argc, const unsigned int* argv,
		const char* signature, void* func, void* pResult )
{
	dvmPlatformInvoke(pEnv, clazz, argInfo, argc, argv, signature, func, pResult);
}
#endif
// ClassObject* dvmDefineClass(DvmDex* pDvmDex, const char* descriptor,
//	    Object* classLoader)

void* dvmDefineClass_wrapper(void* pDvmDex, const char* descriptor, void* classLoader)
{
	OrigFn fn;
	void* res;
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMDEFINECLASS_PRE, void*, pDvmDex, const char*, descriptor, void*, classLoader);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, pDvmDex, descriptor, classLoader);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMDEFINECLASS, void*, pDvmDex, const char*, descriptor, void*, classLoader,
			void*, res);
	return res;
}
//_Z14dvmDefineClassP6DvmDexPKcP6Object
LIBDVM_FUNC(void*, _Z14dvmDefineClassP6DvmDexPKcP6Object,
		void* pDvmDex, const char* descriptor, void* classLoader)
{
	return dvmDefineClass_wrapper(pDvmDex, descriptor, classLoader);
}
// bool dvmLoadNativeCode(const char* pathName, Object* classLoader,  
//         char** detail)
Bool dvmLoadNativeCode_wrapper(const char* pathName, void* classLoader, char** detail)
{
	OrigFn fn;
	Bool res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMLOADNATIVE_PRE, const char*, pathName);
	is_so_loading = True;
	CALL_FN_W_WWW(res, fn, pathName, classLoader, detail);
	is_so_loading = False;
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMLOADNATIVE, const char*, pathName);
	return res;
}
//_Z17dvmLoadNativeCodePKcP6ObjectPPc
LIBDVM_FUNC(Bool, _Z17dvmLoadNativeCodePKcP6ObjectPPc,
		const char* pathName, void* classLoader, char** detail)
{
	return dvmLoadNativeCode_wrapper(pathName, classLoader, detail);
}


/*
 * Resolve a native method and invoke it.
 *
 * This is executed as if it were a native bridge or function.  If the
 * resolution succeeds, method->insns is replaced, and we don't go through
 * here again unless the method is unregistered.
 *
 * Initializes method's class if necessary.
 *
 * An exception is thrown on resolution failure.
 *
 * (This should not be taking "const Method*", because it modifies the
 * structure, but the declaration needs to match the DalvikBridgeFunc
 * type definition.)
 */
// void dvmResolveNativeMethod(const u4* args, JValue* pResult,
//		     const Method* method, Thread* self)

// _Z22dvmResolveNativeMethodPKjP6JValuePK6MethodP6Thread
//
//

/*-------------------- For tracing method invocation -----------------------------*/

//ClassObject* callPrep(Thread* self, const Method* method, Object* obj,
//     bool checkAccess)
/* This can cause: java.lang.RuntimeException: too many PopLocalFrame calls
 * But I still don't know the reason.
 */
#if 0
void* callPrep_wrapper(void* self, const void* method, void* obj, Bool checkAccess)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, self, method, obj, checkAccess);
	if(res) {
		DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CALLPREP, void*, self, const void*, method, Bool, checkAccess);
	}
	return res;
}
//_Z8callPrepP6ThreadPK6MethodP6Objectb
LIBDVM_FUNC(Bool, _Z8callPrepP6ThreadPK6MethodP6Objectb,
		void* self, const void* method, void* obj, Bool checkAccess)
{
	return callPrep_wrapper(self, method, obj, checkAccess);
}
#endif

/* void dvmCallMethod(Thread* self, const Method* method, Object* obj,
 *      JValue* pResult, ...); 
 * it also calls dvmCallMethodV(), so we just need to wrap dvmCallMethodV().
 */

//void dvmCallMethodV(Thread* self, const Method* method, Object* obj,
//     bool fromJni, JValue* pResult, va_list args);
void dvmCallMethod_wrapper(void* self, const void* method, void* obj, 
		Bool fromJni, void* pResults, void* args)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMCALLMETHOD_PRE, const void*, method);
	CALL_FN_v_6W(fn, self, method, obj, fromJni, pResults, args);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMCALLMETHOD, const void*, method);
}
//_Z14dvmCallMethodVP6ThreadPK6MethodP6ObjectbP6JValueSt9__va_list
LIBDVM_FUNC(void, _Z14dvmCallMethodVP6ThreadPK6MethodP6ObjectbP6JValueSt9__va_list,
		void* self, void* method, void* obj, Bool fromJni, void* pResults, void* args)
{
	dvmCallMethod_wrapper(self, method, obj, fromJni, pResults, args);
}
// void dvmCallMethodA(Thread* self, const Method* method, Object* obj,
//     bool fromJni, JValue* pResult, const jvalue* args);
//_Z14dvmCallMethodAP6ThreadPK6MethodP6ObjectbP6JValuePK6jvalue
LIBDVM_FUNC(void, _Z14dvmCallMethodAP6ThreadPK6MethodP6ObjectbP6JValuePK6jvalue,
		void* self, void* method, void* obj, Bool fromJni, void* pResults, void *arg)
{
	dvmCallMethod_wrapper(self, method, obj, fromJni, pResults, arg);
}

//ClassObject* dvmFindClassByName(StringObject* nameObj, Object* loader,
//     bool doInit)
void* dvmFindClassByName_wrapper(void* nameObj, void* loader, Bool doInit) 
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	//DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMFINDCLASSBYNAME_PRE, void*, nameObj, void*, loader, Bool doInit);
	CALL_FN_W_WWW(res, fn, nameObj, loader, doInit);
	if(res)
		DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMFINDCLASSBYNAME, void*, res, void*, loader, Bool, doInit);
	return res;
}
// _Z18dvmFindClassByNameP12StringObjectP6Objectb
LIBDVM_FUNC(void*, _Z18dvmFindClassByNameP12StringObjectP6Objectb,
		void* nameObj, void* loader, Bool doInit)
{
	return dvmFindClassByName_wrapper(nameObj, loader, doInit);
}

/*
 * JNI reflection support: convert Method to reflection object.
 *
 * The returned object will be either a java.lang.reflect.Method or
 * .Constructor, depending on whether "method" is a constructor.
 *
 * This is also used for certain "system" annotations.
 *
 * Caller must call dvmReleaseTrackedAlloc().
 */
// Object* dvmCreateReflectObjForMethod(const ClassObject* clazz, Method* method)

// bool dvmInitClass(ClassObject* clazz)



//Object* dvmInvokeMethod(Object* invokeObj, const Method* meth,
//    ArrayObject* argList, ArrayObject* params, ClassObject* returnType,
//    bool noAccessCheck);
void* dvmInvokeMethod_wrapper(void* invokeObj, const void* meth, 
		void* arglist, void* params, void* returnType, Bool noAccessCheck)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DVMINVOKEMTH_PRE, const void*, meth, void*, invokeObj);
	CALL_FN_W_6W(res, fn, invokeObj, meth, arglist, params, returnType, noAccessCheck);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DVMINVOKEMTH, const void*, meth, void*, invokeObj);
	return res;
}
//_Z15dvmInvokeMethodP6ObjectPK6MethodP11ArrayObjectS5_P11ClassObjectb
LIBDVM_FUNC(void*, _Z15dvmInvokeMethodP6ObjectPK6MethodP11ArrayObjectS5_P11ClassObjectb,
		void* invokeObj, const void* meth, void* arglist, void* params, void* returnType,
		Bool noAccessCheck) 
{
	return dvmInvokeMethod_wrapper(invokeObj, meth, arglist, params, returnType, 
			noAccessCheck);
}

// void dvmInterpret(Thread* self, const Method* method, JValue* pResult)
void dvmInterpret_wrapper(void* self, const void* method, void* pResult) 
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMINTERPRET_PRE, const void*, method);
	CALL_FN_v_WWW(fn, self, method, pResult );
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DVMINTERPRET, const void*, method, void*, pResult);
}
// _Z12dvmInterpretP6ThreadPK6MethodP6JValue
LIBDVM_FUNC(void, _Z12dvmInterpretP6ThreadPK6MethodP6JValue,
		void* self, const void* method, void* pResult)
{
	dvmInterpret_wrapper(self, method, pResult);
}

// extern void dvmMterpStd(Thread* self);
void dvmMterpStd_wrapper(void* self) 
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMMTERPSTD_PRE, void*, self);
	CALL_FN_v_W(fn, self);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMMTERPSTD, void*, self);
}
// _Z11dvmMterpStdP6Thread
LIBDVM_FUNC(void, _Z11dvmMterpStdP6Thread,
		void *self) 
{
	dvmMterpStd_wrapper(self);
}

// void dvmMterpStdRun(Thread* self);
// dvmMterpStdRun
void dvmMterpStdRun_wrapper(void* self) 
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMMTERPSTDRUN_PRE, void*, self);
	CALL_FN_v_W(fn, self);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMMTERPSTDRUN, void*, self);
}
// _Z11dvmMterpStdP6Thread
LIBDVM_FUNC(void, dvmMterpStdRun, void *self) 
{
	dvmMterpStdRun_wrapper(self);
}

// extern void dvmInterpretPortable(Thread* self);
void dvmInterpretPortable_wrapper(void* self) 
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE_PRE, void*, self);
	CALL_FN_v_W(fn, self);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_DVMINTERPRETPORTABLE, void*, self);
}
// _Z20dvmInterpretPortableP6Thread
LIBDVM_FUNC(void, _Z20dvmInterpretPortableP6Thread,
		void *self) 
{
	dvmInterpretPortable_wrapper(self);
}

/* All JNI methods must start by changing their thread status to
 * THREAD_RUNNING, and finish by changing it back to THREAD_NATIVE before
 * returning to native code.  The switch to "running" triggers a thread
 * suspension check. (in Jni.cpp)
 */
// ThreadStatus dvmChangeStatus(Thread* self, ThreadStatus newStatus)
ThreadStatus dvmChangeStatus_wrapper(void* self, ThreadStatus newStatus)
{
	OrigFn fn;
	ThreadStatus res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, self, newStatus);
#if TRACE_SO_LOAD_STATUS_ONLY
	if( is_so_loading )
#endif
		DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMCHANGESTATUS, void*, self, 
				ThreadStatus, newStatus, ThreadStatus, res);
	return res;
}
// _Z15dvmChangeStatusP6Thread12ThreadStatus
LIBDVM_FUNC(ThreadStatus, _Z15dvmChangeStatusP6Thread12ThreadStatus,
		void* self, ThreadStatus newStatus)
{
	return dvmChangeStatus_wrapper(self, newStatus);
}

/*------------------------- For tracing loading DEX file -----------------------------------*/

/*
 * Given an open optimized DEX file, map it into read-only shared memory and
 * parse the contents.
 *  
 * Returns nonzero on error.
 */ 
// int dvmDexFileOpenFromFd(int fd, DvmDex** ppDvmDex)
int dvmDexFileOpenFromFd(int fd, void **ppDvmDex)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD_PRE, int, fd, void**, ppDvmDex, 
			int, res);
	CALL_FN_W_WW(res, fn, fd, ppDvmDex);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMDEXFILEOPENFROMFD, int, fd, void**, ppDvmDex, 
			int, res);
	return res;
}
// _Z20dvmDexFileOpenFromFdiPP6DvmDex
LIBDVM_FUNC(int, _Z20dvmDexFileOpenFromFdiPP6DvmDex,
		int fd, void** ppDvmDex)
{
	return dvmDexFileOpenFromFd(fd, ppDvmDex);
}

/* In method dvmDexFileOpenPartial(), method dexFileParse() is invorked actiually,
 * as a result, this method has no need to be wrapped.
 */
//int dvmDexFileOpenPartial(const void* addr, int len, DvmDex** ppDvmDex)
int dvmDexFileOpenPartial_wrapper(const void* addr, int len, void** ppDvmDex) 
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL_PRE, const void*, addr, int, len);
	CALL_FN_W_WWW(res, fn, addr, len, ppDvmDex);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMDEXFILEOPENPARTIAL, const void*, addr, int, len, 
			int, res);
	return res;
}
//_Z21dvmDexFileOpenPartialPKviPP6DvmDex
LIBDVM_FUNC(int, _Z21dvmDexFileOpenPartialPKviPP6DvmDex,
		const void* addr, int len, void** ppDvmDex) {
	return dvmDexFileOpenPartial_wrapper(addr, len, ppDvmDex);
}

/*
 * Open a raw ".dex" file, optimize it, and load it.
 *
 * On success, returns 0 and sets "*ppDexFile" to a newly-allocated DexFile.
 * On failure, returns a meaningful error code [currently just -1].
 */
// int dvmRawDexFileOpen(const char* fileName, const char* odexOutputName,
//		     RawDexFile** ppDexFile, bool isBootstrap);
int dvmRawDexFileOpen_wrapper(const char* fileName, const char* odexOutputName,
		void** ppDexFile, Bool isBootstrap)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN_PRE, const char*, fileName, const char*, odexOutputName, 
			void**, ppDexFile, Bool, isBootstrap);
	CALL_FN_W_WWWW(res, fn, fileName, odexOutputName, ppDexFile, isBootstrap);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPEN, const char*, fileName, const char*, odexOutputName, 
			void**, ppDexFile, Bool, isBootstrap);
	return res;
}
// _Z17dvmRawDexFileOpenPKcS0_PP10RawDexFileb
LIBDVM_FUNC(int, _Z17dvmRawDexFileOpenPKcS0_PP10RawDexFileb,
		const char* fileName, const char* odexOutputName, void** ppDexfile, Bool isBootstrap)
{
	return dvmRawDexFileOpen_wrapper( fileName, odexOutputName, ppDexfile, isBootstrap);
}


/*
 * Open a raw ".dex" file based on the given chunk of memory, and load
 * it. The bytes are assumed to be owned by the caller for the
 * purposes of memory management and further assumed to not be touched
 * by the caller while the raw dex file remains open. The bytes *may*
 * be modified as the result of issuing this call.
 *
 * On success, returns 0 and sets "*ppDexFile" to a newly-allocated DexFile.
 * On failure, returns a meaningful error code [currently just -1].
 */
// int dvmRawDexFileOpenArray(u1* pBytes, u4 length, RawDexFile** ppDexFile);
int dvmRawDexFileOpenArrary(unsigned char* pBytes, int length, void** ppDexFile)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY_PRE, unsigned char*, pBytes, int, length, void**, ppDexFile);
	CALL_FN_W_WWW(res, fn, pBytes, length, ppDexFile);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMRAWDEXFILEOPENARRARY, unsigned char*, pBytes, int, length, void**, ppDexFile);
	return res;
}
// _Z22dvmRawDexFileOpenArrayPhjPP10RawDexFile
LIBDVM_FUNC( int, _Z22dvmRawDexFileOpenArrayPhjPP10RawDexFile,
		unsigned char* pBytes, int length, void** ppDexFile) 
{
	return dvmRawDexFileOpenArrary( pBytes, length, ppDexFile );
}

//Bool dvmContinueOptimization(int fd, off_t dexOffset, long dexLength,
//    const char* fileName, u4 modWhen, u4 crc, Bool isBootstrap)
Bool dvmContinueOptimization_wrapper(int fd, off_t dexOffset, long dexLong,
		const char* fileName, uint32_t modWhen, uint32_t crc, Bool isBootStrap)
{
	OrigFn fn;
	Bool res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMCONOPT_PRE, int, fd, int, dexOffset, int, dexLong, 
			const char*, fileName);
	CALL_FN_W_7W(res, fn, fd, dexOffset, dexLong, fileName, modWhen, crc, isBootStrap);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DVMCONOPT, int, fd, int, dexOffset, int, dexLong, 
			const char*, fileName);
	return res;
}
//_Z23dvmContinueOptimizationillPKcjjb
LIBDVM_FUNC(Bool, _Z23dvmContinueOptimizationillPKcjjb,
		int fd, off_t dexOffset, long dexLong, const char* fileName,
		uint32_t modWhen, uint32_t crc, Bool isBootStrap)
{
	return dvmContinueOptimization_wrapper(fd, dexOffset, dexLong, fileName,
			modWhen, crc, isBootStrap);
}

/*
 * Prepare an in-memory DEX file.
 *
 * The data was presented to the VM as a byte array rather than a file.
 * We want to do the same basic set of operations, but we can just leave
 * them in memory instead of writing them out to a cached optimized DEX file.
 */
//bool dvmPrepareDexInMemory(u1* addr, size_t len, DvmDex** ppDvmDex)
Bool dvmPrepareDexInMemory_wrapper(unsigned char *addr, size_t len, void** ppDvmDex)
{
	OrigFn fn;
	Bool res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMPREPAREDEX_PRE, const void*, addr, int, len, void**, ppDvmDex);
	CALL_FN_W_WWW(res, fn, addr, len, ppDvmDex);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DVMPREPAREDEX, const void*, addr, int, len, void**, ppDvmDex);
	return res;
}
//_Z21dvmPrepareDexInMemoryPhjPP6DvmDex
LIBDVM_FUNC(Bool, _Z21dvmPrepareDexInMemoryPhjPP6DvmDex,
		unsigned char *addr, size_t len, void** ppDvmDex) {
	return dvmPrepareDexInMemory_wrapper( addr, len, ppDvmDex );
}

// DexFile* dexFileParse(const u1* data, size_t length, int flags)
/* It only create DexFile struction and set its parameters, does not check whether parameters are valid */
void* dexFileParse_wrapper(const unsigned char* data, size_t len, int flags)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DEXFILEPARSE_PRE, int, data, int, len, int, flags);
	CALL_FN_W_WWW(res, fn, data, len, flags);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_DEXFILEPARSE, int, data, int, len, int, flags, void*, res);
	return res;
}
LIBDVM_FUNC(void*, _Z12dexFileParsePKhji, 
		const unsigned char* data, size_t len, int flags)
{
	return dexFileParse_wrapper(data, len, flags);
}

/*---------------------- END -------------------------------*/
