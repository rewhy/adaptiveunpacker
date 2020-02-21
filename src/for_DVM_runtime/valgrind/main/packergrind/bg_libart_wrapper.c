//bg_libart_wrapper.c

#define  BG_Z_LIBART_SONAME  libartZdsoZa              // libart.so*
#define LIBART_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBART_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBART_SONAME,f)(args)


/* std::string layout: 
 * UInt xxx
 * UInt len
 * char *pStr
 */


#if 1
// bool JavaVMExt::LoadNativeLibrary(JNIEnv* env, const std::string& path, jobject class_loader,
//                                 std::string* error_msg);
Bool JavaVMExt_LoadNativeLibrary(void *this, void *env, char* path, void* class_loader, char* error_msg)
{
	OrigFn fn;
	Bool res;
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
void* DexFile_DexFile(void *this, void *base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	OrigFn fn;
	void* res;
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_ART_DEXFILE_PRE, void*, mem_map, char*, base, int, size, char*, (char*)(*((unsigned int*)location+2)));
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_7W(res, fn, this, base, size, location, checksum, mem_map, oat_dex_file);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_ART_DEXFILE, void*, this, char*, base, int, size, char*, (char*)(*((unsigned int*)location+2)),
			void*, mem_map);
	return res;
}
// _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE
LIBART_FUNC(void*, _ZN3art7DexFileC2EPKhjRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPNS_6MemMapEPKNS_10OatDexFileE,
		void* this, void* base, int size, void* location, int checksum, void* mem_map, void* oat_dex_file)
{
	return DexFile_DexFile(this, base, size, location, checksum, mem_map, oat_dex_file);
}

// mirror::Class* ClassLinker::DefineClass(Thread* self, const char* descriptor, size_t hash,
//       Handle<mirror::ClassLoader> class_loader,
//       const DexFile& dex_file,
//       const DexFile::ClassDef& dex_class_def);
void* ClassLinker_DefineClass(void* this, void* thread,void* descriptor, int hash, void* class_loader, void* dex_file, void* dex_class_def)
{
	OrigFn fn;
	void* res;
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
	int res;
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
#endif
