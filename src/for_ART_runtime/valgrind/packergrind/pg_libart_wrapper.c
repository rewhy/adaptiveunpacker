//pg_libart_wrapper.c

#define  BG_Z_LIBART_SONAME  libartZdsoZa              // libart.so*
#define LIBART_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBART_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBART_SONAME,f)(args)

#if 1
#define  BG_Z_LIBANDROID_RUNTINE_SONAME  libandroid_runtimeZdsoZa              // libandroid_runtime.so*
#define LIBANDROID_RUNTIME_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBANDROID_RUNTIME_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBANDROID_RUNTIME_SONAME,f)(args)
#endif

#if 1
// bool JavaVMExt::LoadNativeLibrary(JNIEnv* env, const std::string& path, jobject class_loader,
//                                 std::string* error_msg);
Bool JavaVMExt_LoadNativeLibrary(void *this, void *env, char* path, void* class_loader, char* error_msg)
{
	OrigFn fn;
	Bool res = 0;
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY_PRE, void*, this, char*, (char*)(*((unsigned int*)path+2)), void*, class_loader);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_5W(res, fn, this, env, path, class_loader, error_msg);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_LOADNATIVELIBRARY, void*, this, char*, path, void*, class_loader);
	return res;
}
// _ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectPS9
LIBART_FUNC(Bool, _ZN3art9JavaVMExt17LoadNativeLibraryEP7_JNIEnvRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEP8_jobjectPS9_,
		void *this, void *env, char* path, void* class_loader, char* error_msg)
{
	return JavaVMExt_LoadNativeLibrary(this, env, path, class_loader, error_msg);
}

// std::unique_ptr<const DexFile> DexFile::OpenMemory(const uint8_t* base,
//                                                    size_t size,
//                                                    const std::string& location,
//                                                    uint32_t location_checksum,
//                                                    MemMap* mem_map,
//                                                    const OatDexFile* oat_dex_file,
//                                                    std::string* error_msg) {
// DexFile::DexFile(const uint8_t* base, size_t size,
//                 const std::string& location,
//                  uint32_t location_checksum,
//                  MemMap* mem_map,
//                 const OatDexFile* oat_dex_file)
// 
void* dexfile_dexfile(void *base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	OrigFn fn;
	void* res = NULL;
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE_PRE, void*, mem_map, char*, base, int, size, char*, (char*)(*((unsigned int*)location+2)));
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_6W(res, fn, base, size, location, checksum, mem_map, oat_dex_file);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILEDEXFILE, void*, res, char*, base, int, size, char*, (char*)(*((unsigned int*)location+2)),
			void*, mem_map);
	return res;
}
// _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE
LIBART_FUNC(void*, _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE,
		void* base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	return dexfile_dexfile(base, size, location, checksum, mem_map, oat_dex_file);
}

#if 0 // Will cause crash
// From oat_file.h
// const OatDexFile* GetOatDexFile(const char* dex_location,
//		const uint32_t* const dex_location_checksum,
//		bool exception_if_not_found = true) const
void* oatfile_getoatdexfile(void* this_oatfile, char* dex_location, void* dex_location_checksum, int exception_if_not_found)
{
	OrigFn fn;
	void* res_oatdexfile = NULL;
	// DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE_PRE, void*, this_oatfile, char*, dex_location);
	CALL_FN_W_WWWW(res_oatdexfile, fn, this_oatfile, dex_location, dex_location_checksum, exception_if_not_found);
	// DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OATFILE_GETOATDEXFILE, void*, this_oatfile, char*, dex_location, void*, res_oatdexfile);
	return res_oatdexfile;
}

LIBART_FUNC(void*, _ZNK3art7OatFile13GetOatDexFileEPKcPKjb,
		void* this_oatfile, char* dex_location, void* dex_location_checksum, int exception_if_not_found)
{
	return oatfile_getoatdexfile(this_oatfile, dex_location, dex_location_checksum, exception_if_not_found);
}
#endif

// std::unique_ptr<const DexFile> OpenDexFile(std::string* error_msg) const;
void* oatfile_oatdexfile_opendexfile(void* unknown, void *this_oat_dex_file, void* error_msg)
{
	OrigFn fn;
	void* res_dex_file = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OPENDEXFILE_PRE, void*, this_oat_dex_file, void*, error_msg, void*, res_dex_file);
	CALL_FN_W_WWW(res_dex_file, fn, unknown, this_oat_dex_file, error_msg);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OPENDEXFILE, void*, this_oat_dex_file, void*, error_msg, void*, res_dex_file);
	return res_dex_file;
}
// _ZNK3art10OatDexFile11OpenDexFileEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE
LIBART_FUNC(void*, _ZNK3art10OatDexFile11OpenDexFileEPNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEE,
		void* unknown, void* this, void* error_msg)

{
	return oatfile_oatdexfile_opendexfile(unknown, this, error_msg);
}

// Opens a .dex file at the given address, optionally backed by a MemMap
/*static std::unique_ptr<const DexFile> OpenMemory(const uint8_t* dex_file,
		size_t size,
		const std::string& location,
		uint32_t location_checksum,
		MemMap* mem_map,
		const OatDexFile* oat_dex_file, // NULL
		std::string* error_msg);*/
void* dexfile_openmemory(void* this, void* dexfile, int size, void* location, int location_checksum, void* mem_map, void* oat_dex_file, void* error_msg)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY_PRE, void*, dexfile, int, size, void*, location, void*, oat_dex_file, void*, res);
	CALL_FN_W_8W(res, fn, this, dexfile, size, location, location_checksum, mem_map, oat_dex_file, error_msg);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILEOPENMEMORY, void*, dexfile, int, size, void*, location, void*, oat_dex_file, void*, res);
	return res;
}
// _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_
LIBART_FUNC(void*, _ZN3art7DexFile10OpenMemoryEPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileEPS9_,
		void* this, void* dexfile, int size, void* location, int location_checksum, void* mem_map, void* oat_dex_file, void* error_msg)
{
	return dexfile_openmemory(this, dexfile, size, location, location_checksum, mem_map, oat_dex_file, error_msg);
}

// From class_linker.h
/* std::vector<std::unique_ptr<const DexFile>>  OpenDexFilesFromOat(
      const char* dex_location, const char* oat_location,
      std::vector<std::string>* error_msgs)
      LOCKS_EXCLUDED(dex_lock_, Locks::mutator_lock_); */
void* classlinker_opendexfilesfromoat(void* unknown, void* this, char* dex_location, char* oat_location, void* error_msg)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT_PRE, char*, dex_location, char*, oat_location, void*, this);
	CALL_FN_W_5W(res, fn, unknown, this, dex_location, oat_location, error_msg);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_CLASSLINKER_OPENDEXFILESFROMOAT, char*, dex_location, char*, oat_location, void*, this);
	return res;
}
LIBART_FUNC(void*, _ZN3art11ClassLinker19OpenDexFilesFromOatEPKcS2_PNSt3__16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE,
		void* unknown, void* this, char* dex_location, char* oat_location, void* error_msg)
{
	return classlinker_opendexfilesfromoat(unknown, this, dex_location, oat_location, error_msg);
}

// mirror::Class* ClassLinker::DefineClass(Thread* self, const char* descriptor, size_t hash,
//       Handle<mirror::ClassLoader> class_loader,
//       const DexFile& dex_file,
//       const DexFile::ClassDef& dex_class_def);
void* ClassLinker_DefineClass(void* this, void* thread,void* descriptor, int hash, void* class_loader, void* dex_file, void* dex_class_def)
{
	OrigFn fn;
	void* res = NULL;
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_DEFINECLASS_PRE, char*, descriptor, void*, dex_file, void*, dex_class_def);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_7W(res, fn, this, thread, descriptor, hash, class_loader, dex_file, dex_class_def);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_DEFINECLASS, char*, descriptor, void*, dex_file, void*, dex_class_def);
	return res;
}
// _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE
LIBART_FUNC(void*,  _ZN3art11ClassLinker11DefineClassEPNS_6ThreadEPKcjNS_6HandleINS_6mirror11ClassLoaderEEERKNS_7DexFileERKNS9_8ClassDefE,
		void* this, void *thread, void* descriptor, int hash, void* class_loader, void* dex_file, void* dex_class_def)
{
	return ClassLinker_DefineClass(this, thread, descriptor, hash, class_loader, dex_file, dex_class_def);
}


#if 0
int JavaVMExt_RewhyTestSTD(void *this, void *std, void *str)
{
	OrigFn fn;
	int res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_TEST_PRE, void*, this, void*, std, void*, str);
	CALL_FN_W_WWW(res, fn, this, std, str);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_TEST, void*, this, void*, std, void*, str);
	return res;
}
LIBART_FUNC(int, _ZN3art9JavaVMExt12RewhyTestSTDERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEEPKc,
		void* this, void* std, void* str)
{
	return JavaVMExt_RewhyTestSTD(this, std, str);
}
#endif
//  void ArtMethod::RegisterNative(const void* native_method, bool is_fast)
void ArtMethod_RegisterNative(const void* this, const void* native_method, Int is_fast){
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_WWW(fn, this, native_method, is_fast);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_REGISTERNATIVE, void*, this, void*, native_method, Int, is_fast);
}
LIBART_FUNC(void, _ZN3art9ArtMethod14RegisterNativeEPKvb,
		const void *this, const void *native_method, Int is_fast)
{
	ArtMethod_RegisterNative(this, native_method, is_fast);
}

// void ArtMethod::Invoke(Thread* self, uint32_t* args, uint32_t args_size, JValue* result,const char* shorty)
// _ZN3art9ArtMethod6InvokeEPNS_6ThreadEPjjPNS_6JValueEPKc


// JValue ExecuteSwitchImpl(Thread* self, const DexFile::CodeItem* code_item, ShadowFrame& shadow_frame, JValue result_register)
//_ZN3art11interpreter17ExecuteSwitchImplILb1ELb1EEENS_6JValueEPNS_6ThreadEPKNS_7DexFile8CodeItemERNS_11ShadowFrameES2_>
//
//
Int interpreter_executeSwitchImpl(void* this, void* self, void* code_item, void* shadow_frame, void* result_register)
{
	OrigFn fn;
	Int	res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_EXECUTESWITCH_PRE, void*, self, void*, code_item, void*, shadow_frame);
	CALL_FN_W_5W(res, fn, this, self, code_item, shadow_frame, result_register);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_EXECUTESWITCH, void*, self, void*, code_item, void*, shadow_frame);
	return res;
}
LIBART_FUNC(Int, _ZN3art11interpreter17ExecuteSwitchImplILb1ELb1EEENS_6JValueEPNS_6ThreadEPKNS_7DexFile8CodeItemERNS_11ShadowFrameES2_,
		void* this, void* self, void* code_item, void* shadow_frame, void* result_register)
{
	return interpreter_executeSwitchImpl(this, self, code_item, shadow_frame, result_register);
}

#if 0
Int interpreter_executeSwitchGoto(void* this, void* self, void* code_item, void* shadow_frame, void* result_register)
{
	OrigFn fn;
	Int	res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_EXECUTEGOTO_PRE, void*, self, void*, code_item, void*, shadow_frame);
	CALL_FN_W_5W(res, fn, this, self, code_item, shadow_frame, result_register);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_EXECUTEGOTO, void*, self, void*, code_item, void*, shadow_frame);
	return res;
}
LIBART_FUNC(Int, _ZN3art11interpreter15ExecuteGotoImplILb0ELb0EEENS_6JValueEPNS_6ThreadEPKNS_7DexFile8CodeItemERNS_11ShadowFrameES2_,
		void* this, void* self, void* code_item, void* shadow_frame, void* result_register)
{
	return interpreter_executeSwitchGoto(this, self, code_item, shadow_frame, result_register);
}
#endif

// void* FindNativeMethod(ArtMethod* m, std::string& detail)
void* Library_FindNativeMethod(const void* this, const void* artMethod, void* std_string) {
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, this, artMethod, std_string);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_FINDNATIVEMETHOD, void*, this, void*, artMethod, void*, std_string, void*, res);
	return res;
}
// _ZN3art9Libraries16FindNativeMethodEPNS_9ArtMethodERNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE
LIBART_FUNC(void*,  _ZN3art9Libraries16FindNativeMethodEPNS_9ArtMethodERNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE,
		const void *this, const void* artMethod, void* std_string) 
{
	return Library_FindNativeMethod(this, artMethod, std_string);
}
#if 0
// static jmethodID GetMethodID(JNIEnv* env, jclass java_class, const char* name, const char* sig)
int jni_GetMethodID(void* env, void* java_class, const char* name, const char* sig)
{
	OrigFn fn;
	int res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, env, java_class, name, sig);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_JNIGETMETHODID, void*, java_class, char*, name, char*, sig, int, res);
	return res;
}
LIBART_FUNC(int, _ZN3art3JNI11GetMethodIDEP7_JNIEnvP7_jclassPKcS6_,
		void* env, void* java_class, char* name, char* sig)
{
	return jni_GetMethodID(env, java_class, name, sig);
}

//
// static jmethodID GetStaticMethodID(JNIEnv* env, jclass java_class, const char* name, const char* sig)
int jni_GetStaticMethodID(void* env, void* java_class, const char* name, const char* sig)
{
	OrigFn fn;
	int res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, env, java_class, name, sig);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_JNIGETSTATICMETHODID, void*, java_class, char*, name, char*, sig, int, res);
	return res;
}
LIBART_FUNC(int, _ZN3art3JNI17GetStaticMethodIDEP7_JNIEnvP7_jclassPKcS6_,
		void* env, void* java_class, char* name, char* sig)
{
	return jni_GetMethodID(env, java_class, name, sig);
}
#endif

// void ClassLinker::LoadMethod(Thread* self, const DexFile& dex_file, const ClassDataItemIterator& it, Handle<mirror::Class> klass, ArtMethod* dst)
void ClassLinker_LoadMethod(void* this, void* thread, void* dex_file, void* it, void* klass, void* dst)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD_PRE, void*, dex_file, void*, klass, void*, dst);
	CALL_FN_v_6W(fn, this, thread, dex_file, it, klass, dst);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LOADMETHOD, void*, dex_file, void*, klass, void*, dst);
}
LIBART_FUNC(void, _ZN3art11ClassLinker10LoadMethodEPNS_6ThreadERKNS_7DexFileERKNS_21ClassDataItemIteratorENS_6HandleINS_6mirror5ClassEEEPNS_9ArtMethodE,
		void* this, void* thread, void* dexfile, void* it, void* klass, void* dst)
{
	ClassLinker_LoadMethod(this, thread, dexfile, it, klass, dst);
}

// void ClassLinker::LinkCode(ArtMethod* method, const OatFile::OatClass* oat_class, uint32_t class_def_method_index)
void ClassLinker_LinkCode(void* this, void* method, void* oat_class, UInt class_def_method_index)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE_PRE, void*, method, void*, oat_class, UInt, class_def_method_index);
	CALL_FN_v_WWWW(fn, this, method, oat_class, class_def_method_index);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CLASSLINKER_LINKCODE, void*, method, void*, oat_class, UInt, class_def_method_index);
}
LIBART_FUNC(void, _ZN3art11ClassLinker8LinkCodeEPNS_9ArtMethodEPKNS_7OatFile8OatClassEj,
		void* this, void* method, void* oat_class, UInt class_def_method_index)
{
	ClassLinker_LinkCode(this, method, oat_class, class_def_method_index);
}

// static std::unique_ptr<const DexFile> DexFile::OpenFile(int fd, const char* location, bool verify, std::string* error_msg)
void* dexfile_openfile(void* unknown, int fd, const char* location, int verify, void* error_msg) 
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE_PRE, int, fd, char*, location, int, verify);
	CALL_FN_W_5W(res, fn, unknown, fd, location, verify, error_msg);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILEOPENFILE, int, fd, char*, location, int, verify, void*, error_msg, int, res);
	return res;
}
LIBART_FUNC(int, _ZN3art7DexFile8OpenFileEiPKcbPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE,
		void* unknown, int fd, const char* location, int verify, void* error_msg)
{
	return dexfile_openfile(unknown, fd, location, verify, error_msg);
}

// bool OatFile::Setup(const char* abs_dex_location, std::string* error_msg)
int oatfile_setup(void* oatfile, const char* abs_dex_location, void* error_msg)
{
	OrigFn fn;
	int res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OATFILESETUP_PRE, void*, oatfile, const char*, abs_dex_location, int, res);
	CALL_FN_W_WWW(res, fn, oatfile, abs_dex_location, error_msg);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ART_OATFILESETUP, void*, oatfile, const char*, abs_dex_location, int, res);
	return res;
}
//_ZN3art7OatFile5SetupEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE
LIBART_FUNC(int, _ZN3art7OatFile5SetupEPKcPNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEE,
		void* oatfile, const char* abs_dex_location, void* error_msg)
{
	return oatfile_setup(oatfile, abs_dex_location, error_msg);
}

// OatFile* OatFile::Open(const std::string& filename, const std::string& location, uint8_t* requested_base, uint8_t* oat_file_begin,
//			bool executable, const char* abs_dex_location, std::string* error_msg);
void* oatfile_open(void* filename, void* location, void* base, void* oat_file_begin, int executable, void* abs_dex_location, void* error_msg)
{
	OrigFn fn;
	void* res = NULL;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_OATFILEOPEN_PRE, void*, filename, void*, base,  void*, oat_file_begin, void*, abs_dex_location, void*, res);
	CALL_FN_W_7W(res, fn, filename, location, base, oat_file_begin, executable, abs_dex_location, error_msg);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_OATFILEOPEN, void*, filename, void*, base,  void*, oat_file_begin, void*, abs_dex_location, void*, res);
	return res;
}

// _ZN3art7OatFile4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_PhSA_bPKcPS7_
LIBART_FUNC(void*, _ZN3art7OatFile4OpenERKNSt3__112basic_stringIcNS1_11char_traitsIcEENS1_9allocatorIcEEEES9_PhSA_bPKcPS7_,
		void* filename, void* location, void* base, void* oat_file_begin, int executable, void* abd_dex_location, void* error_msg)
{
	return oatfile_open(filename, location, base, oat_file_begin, executable, abd_dex_location, error_msg);
}

// From oat_file_assistant.h

// static std::vector<std::unique_ptr<const DexFile>> LoadDexFiles(const OatFile& oat_file, const char* dex_location);
void* oatfileassistant_loaddexfiles(void* this, void* oat_file, char* dex_location)
{
	OrigFn fn;
	void* res = NULL;
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES_PRE, void*, oat_file, vod*, dex_location);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, this, oat_file, dex_location);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_ASSISTANT_LOADDEXFILES, void*, oat_file, void*, dex_location);
	return res;
}
LIBART_FUNC(void*, _ZN3art16OatFileAssistant12LoadDexFilesERKNS_7OatFileEPKc,
		void* this, void* oat_file, char* dex_location)
{
	return oatfileassistant_loaddexfiles(this, oat_file, dex_location);
}

// From interpreter.h
// extern void EnterInterpreterFromInvoke(Thread* self, ArtMethod* method,
//					mirror::Object* receiver, uint32_t* args, JValue* result)
//  SHARED_LOCKS_REQUIRED(Locks::mutator_lock_);
void interpreter_enterinterpreterfrominvoke(void* self, void* method, void* receiver, void* args, void* result)
{
	OrigFn fn;
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_ART_ENTERINTERPRETERFROMINVOKE_PRE, void*, method, void*, self);
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_v_5W(fn, self, method, receiver, args, result);
}
LIBART_FUNC(void,  _ZN3art11interpreter26EnterInterpreterFromInvokeEPNS_6ThreadEPNS_9ArtMethodEPNS_6mirror6ObjectEPjPNS_6JValueE,
		void* self, void* method, void* receiver, void* args, void* result)
{
	interpreter_enterinterpreterfrominvoke(self, method, receiver, args, result);
}

// From dalvik_system_DexFile.cc
// static jclass DexFile_defineClassNative(JNIEnv* env, jclass, jstring javaName, jobject javaLoader,
//                                          jobject cookie)
//
// _ZN3artL25DexFile_defineClassNativeEP7_JNIEnvP7_jclassP8_jstringP8_jobjectS7_

// static jobject DexFile_openDexFileNative(
//    JNIEnv* env, jclass, jstring javaSourceName, jstring javaOutputName, jint) {
//    ScopedUtfChars sourceName(env, javaSourceName);
UInt dexfile_opendexfilenative(void* env, void* jclass, void* jSourceName, void* jOutputName, int n)
{
	OrigFn fn;
	UInt res = 0;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE_PRE, void*, env, void*, jclass, void*, jOutputName, int, n);
	CALL_FN_W_5W(res, fn, env, jclass, jSourceName, jOutputName, n);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_OPENDEXFILENATIVE, void*, env, void*, jclass, void*, jOutputName, int, n);
	return res;
}
#if 1
LIBART_FUNC(UInt,  _ZN3artL25DexFile_openDexFileNativeEP7_JNIEnvP7_jclassP8_jstringS5_i,
		void* env, void* jclass, void* jSourceName, void* jOutputName, int n)
{
	return dexfile_opendexfilenative(env, jclass, jSourceName, jOutputName, n);
}
#endif

// From AndroidRuntime.cpp
// void AndroidRuntime::start(const char* className, const Vector<String8>& options, bool zygote)
// _ZN7android14AndroidRuntime5startEPKcRKNS_6VectorINS_7String8EEEb
#endif
