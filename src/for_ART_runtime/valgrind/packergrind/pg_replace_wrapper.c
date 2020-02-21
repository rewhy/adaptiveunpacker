#include "pub_tool_basics.h"
#include "pub_tool_poolalloc.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_redir.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_clreq.h"

#include <stdio.h>
#include "packergrind.h"


/*--------------------------------------------------------------------*/
/*--- Function wrapper (taint source/sink)                         ---*/
/*--------------------------------------------------------------------*/

/*--- Stuff for wrapped functions																	 ---*/
#ifdef LIBC_FUNC
#undef LIBC_FUNC
#endif

#define LIBC_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBC_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(VG_Z_LIBC_SONAME,f)(args)

#ifdef LIBDL_FUNC
#undef LIBDL_FUNC
#endif

#define  BG_Z_LIBDL_SONAME  libdlZdsoZa              // libdl.so*
#define LIBDL_FUNC(ret_ty, f, args...) \
	ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBDL_SONAME,f)(args); \
ret_ty I_WRAP_SONAME_FNNAME_ZU(BG_Z_LIBDL_SONAME,f)(args)

#define CALL_FN_v_8W(fnptr, arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8)   \
	do { volatile unsigned long _junk;                             \
		CALL_FN_W_8W(_junk,fnptr,arg1,arg2,arg3,arg4,arg5,arg6,arg7,arg8); } while (0)

#define TRACE_SO_LOAD_STATUS_ONLY 1


#if TRACE_DVM_PLATFORM
#include "pg_libdvm_wrapper.c"
#endif

#if TRACE_ART_PLATFORM
#include "pg_libart_wrapper.c"
#endif

#if 0
int sigprocmask_wrapper(int how, void *set, void *oldset)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	//CALL_FN_W_WWW(res, fn, how, set, oldset);
	res = -1;
	//DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_SIGPROCMASK, int, how, void*, set, void*, oldset, int, res);
	return res;
}
LIBC_FUNC(int, sigprocmask, int how, void *set, void *oldset)
{
	return sigprocmask_wrapper(how, set, oldset);
}

int signal_wrapper(int signum, int handler)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, signum, handler);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_SIGNAL, int, signum, int, handler, int, res);
	return res;
}
LIBC_FUNC(int, signal, int signum, int handler)
{
	return signal_wrapper(signum, handler);
}
/* String related functions */
int sigaction_wrapper(int signum, void* act, void* oldact)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, signum, act, oldact);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_SIGACTION, int, signum, void*, act, void*, oldact, int, res);
	return res;
}
LIBC_FUNC(int, sigaction, 
		int signum, void* act, void* oldact)
{
	return sigaction_wrapper(signum, act, oldact);
}
// char* strstr(const char* haystack, const char *needle)
char* strstr_wrapper(const char *ls, const char *ss)
{
	OrigFn fn;
	char* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, ls, ss);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_STRSTR, char*, ls, char*, ss, char*, res);
	return res;
}
LIBC_FUNC(char*, strstr, const char* ls, const char* ss)
{
	return strstr_wrapper(ls, ss);
}
#ifndef M_PERFORMANCE
// void *memchr(const void *s, int c, size_t n);
void *memchr_wrapper(const void *s, int c, int n)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, s, c, n);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_MEMCHR, void*, s, int, c, int, n, void*, res);
	return res;
}
LIBC_FUNC(void*, memchr, const void* s, int c, int n)
{
	return memchr_wrapper(s, c, n);
}
//int strncmp(char *string1, char *string2, int n);
int strncmp_wrapper(char *s1, char *s2, int n)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, s1, s2, n);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_STRNCMP, char*, s1, char*, s2, int, n, int, res);
	return res;
}
LIBC_FUNC(int, strncmp, const void* s1, char* s2, int n)
{
	return strncmp_wrapper(s1, s2, n);
}
#endif

#endif
/* Socket related operation wrappers */
//  int socket (int namespace, int style, int protocol)
int socket_wrapper(int namespace, int style, int protocol)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, namespace, style, protocol);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_SOCKET, int, namespace, int, style, int, protocol, 
			int, res);
	return res;
}
LIBC_FUNC(int, socket,
		int namespace, int style, int protocol)
{
	return socket_wrapper(namespace, style, protocol);
}

// int bind (int socket, struct sockaddr *addr, socklen_t length)
int bind_wrapper(int socket, struct sockaddr *addr, socklen_t length)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, socket, addr, length);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_BIND, int, socket, struct sockaddr *, addr);
	return res;
}
LIBC_FUNC(int, bind,
		int socket, struct sockaddr *addr, socklen_t length)
{
	return bind_wrapper(socket, addr, length);
}
// int shutdown (int socket, int how)
// int connect(int sockfd, const struct sockaddr *serv_addr, socklen_t addrlen)
int connect_wrapper(int socket, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CONNECT_PRE, int, socket, struct sockaddr *, serv_addr, int*, &res);
	CALL_FN_W_WWW(res, fn, socket, serv_addr, addrlen);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_CONNECT, int, socket, struct sockaddr *, serv_addr, int*, &res);
	return res;
}
LIBC_FUNC(int, connect, 
		int socket, const struct sockaddr *serv_addr, socklen_t addrlen)
{
	return connect_wrapper(socket, serv_addr, addrlen);
}

// int listen(int s, int backlog)
int listen_wrapper(int s, int backlog) 
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_LISTEN, int, s, int, backlog);
	CALL_FN_W_WW(res, fn, s, backlog);
	return res;
}
LIBC_FUNC(int, listen,
		int s, int backlog)
{
	return listen_wrapper(s, backlog);
}

// int accept(int s, struct sockaddr *addr, socklen_t *addrlen)
int accept_wrapper(int s, struct sockaddr *addr, socklen_t *addrlen)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, s, addr, addrlen);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_ACCEPT, int, s, struct sockaddr*, addr, int, res);
	return res;
}
LIBC_FUNC(int, accept,
		int s, struct sockaddr *addr, socklen_t *addrlen)
{
	return accept_wrapper(s, addr, addrlen);
}

// int send(int s, const void *buf, int len, unsigned int flags)
int send_wrapper(int s, const void *buf, int len, unsigned int flags) 
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, s, buf, len, flags);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_SEND, int, s, void*, buf, unsigned int, flags, int*, &res);
	return res;
} 
LIBC_FUNC(int, send,
		int s, const void *buf, int len, unsigned int flags)
{ 
	return send_wrapper(s, buf, len, flags);
}

// int sendto(int s, const void *buf, int len, int flags, const struct sockaddr *to, socklen_t tolen)
int sendto_wrapper(int s, const void *buf, int len, unsigned int flags, const struct sockaddr *to, int tolen)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_6W(res, fn, s, buf, len, flags, to, tolen);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_SENDTO, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, to, int*, &res); 
	return res;
} 
LIBC_FUNC(int, sendto,
		int s, const void *buf, int len, unsigned int flags, const struct sockaddr *to, int tolen)
{ 
	return sendto_wrapper(s, buf, len, flags, to, tolen);
}

// int recv(int s, void *buf, int len, unsigned int flags)
int recv_wrapper(int s, void *buf, int len, unsigned int flags)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_RECV_PRE,	int, s, void*, buf, unsigned int, flags, int*, &len);
	CALL_FN_W_WWWW(res, fn, s, buf, len, flags);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_RECV,	int, s, void*, buf, unsigned int, flags, int*, &res);
	return res;
} 
LIBC_FUNC(int, recv,
		int s, void *buf, int len, unsigned int flags)
{ 
	return recv_wrapper(s, buf, len, flags);
} 

// ssize_t recvfrom (int socket, void *buffer, size_t size, int flags, struct sockaddr *addr, socklen_t *length-ptr)
// int recvfrom(int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *len)
int recvfrom_wrapper(int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *slen)
{ 
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_RECVFROM_PRE, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, from, int*, &len);
	CALL_FN_W_6W(res, fn, s, buf, len, flags, from, slen);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_RECVFROM, int, s, void*, buf, unsigned int, flags,
			struct sockaddr*, from, int*, &res);
	//printf("post: recvfrom: 0x%08x(%s), res=%d\n", (int)buf, (char*)buf, res);
	return res;
} 
LIBC_FUNC(int, recvfrom, 
		int s, void *buf, int len, int flags, struct sockaddr *from, socklen_t *slen)
{ 
	return recvfrom_wrapper(s, buf, len, flags, from, slen);
} 

// int shutdown(int s, int how)
int shutdown_wrapper(int s, int how) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, s, how);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_SHUTDOWN, int, s, int, how, int, res);
	return res;
}
LIBC_FUNC(int, shutdown, int s, int how) {
	return shutdown_wrapper(s, how);
}

//int system(const char *command )
int system_wrapper(const char *command) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, command);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_SYSTEM, void*, command, int, res);
	return res;
}
LIBC_FUNC(int, system, const void *command) {
	return system_wrapper(command);
}
// int gettimeofday(struct  timeval*tv,struct  timezone *tz )
int gettimeofday_wrapper(void* tv, void* tz) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, tv, tz);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_GETTIMEOFDAY, void*, tv, void*, tz);
	return res;
}
LIBC_FUNC(int, gettimeofday, void *tv, void *tz) {
	return gettimeofday_wrapper(tv, tz);
}

// int setitimer(int which, const struct itimerval *new_value, struct itimerval *old_value)
int setitimer_wrapper(int which, void *new_value, void *old_value) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, which, new_value, old_value);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_SETITIMER, int, which, void*, new_value, void*, old_value);
	return res;
}
LIBC_FUNC(int, setitimer, int which, void *new_value, void *old_value) {
	return setitimer_wrapper(which, new_value, old_value);
}

// int timer_settime(int timerid, int flags, void* value, void* ovalue)
int timer_settime_wrapper(int timerid, int flags, void* value, void* ovalue)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, timerid, flags, value, ovalue);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_TIMER_SETTIME, int, timerid, int, flags, void*, value);
	return res;
}
LIBC_FUNC(int, timer_settime, int timerid, int flags, void* value, void* ovalue)
{
	return timer_settime_wrapper(timerid, flags, value, ovalue);
}

/*-------------------- File related operations -----------------------*/
// void *dlopen(const char *filename, int flags)

void* dlopen_wrapper(const char *file, int flags)
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, file, flags);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_DLOPEN, const char*, file, int, flags, void*, res);
	return res;
}

LIBDL_FUNC(void*, dlopen,
		const char *file, int flags)
{
	return open_wrapper(file, flags);
}
// int open(const char *file, int mode /*, int permissions */);
int open_wrapper(const char *file, int mode)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, file, mode);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_OPEN, const char*, file, int, res);
	return res;
}
LIBC_FUNC(int, open,
		const char *file, int mode)
{
	return open_wrapper(file, mode);
}
// FILE *fopen(const char *path, const char *mode)
FILE *fopen_wrapper(const char *path, const char *mode)
{
	OrigFn fn;
	FILE *res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, path, mode);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_FOPEN, const char*, path, void*, res);
	return res;
}
LIBC_FUNC(FILE *, fopen,
		const char *path, const char *mode)
{
	return fopen_wrapper(path, mode);
}
//
// int fseek(FILE *stream, long offset, int whence);
int fseek_wrapper(FILE *stream, long offset, int whence)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, stream, offset, whence);
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_FSEEK, int, res, FILE *, stream);
	return res;
}
LIBC_FUNC(int, fseek,
		FILE *stream, long offset, int whence)
{
	return fseek_wrapper(stream, offset, whence);
}
#if 0
//int read(int  handle,  void  *buffer,  int  nbyte)
int read_wrapper(int handle, void *buffer, int nbyte)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, handle, buffer, nbyte);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_READ,
			int, handle, void *, buffer, int, res);
	return res;
}
LIBC_FUNC(int, read,
		int handle, void *buffer, int nbyte)
{
	return read_wrapper(handle, buffer, nbyte);
}
// int write(int  handle,  void  *buffer,  int  nbyte)
int write_wrapper(int handle, void *buffer, int nbyte)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, handle, buffer, nbyte);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_WRITE,
			int, handle, unsigned int, (unsigned int)buffer, int, res);
	return res;
} 
// size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream)
Int	fread_wrapper(void *ptr, Int size, Int nmemb, FILE *stream)
{
	OrigFn fn;
	Int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, ptr, size, nmemb, stream);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_FREAD, 
			FILE*, stream, void *, ptr, Int, res);
	return res;
}
LIBC_FUNC(Int, fread,
		void *ptr, Int size, Int nmemb, FILE *stream)
{
	return fread_wrapper(ptr, size, nmemb, stream);
}
LIBC_FUNC(int, write,
		int handle, void *buffer, int nbyte)
{ 
	return write_wrapper(handle, buffer, nbyte);
}

// size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream)
Int fwrite_wrapper(const void *ptr, Int size, Int nmemb, FILE *stream)
{
	OrigFn fn;
	Int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWWW(res, fn, ptr, size, nmemb, stream);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_FWRITE, 
			unsigned int, (unsigned int)ptr, Int, size, Int, nmemb, FILE*, stream);
	return res;
}
LIBC_FUNC(Int, fwrite,
		const void *ptr, Int size, Int nmemb, FILE *stream)
{
	return fwrite_wrapper(ptr, size, nmemb, stream);
}
#endif

#if 0
// int close(int  handle)
int close_wrapper(int handle)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, handle);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_CLOSE, int, handle);
	return res;
}
LIBC_FUNC(int, close,
		int handle)
{
	return close_wrapper(handle);
}
#endif
// int fclose(FILE *fp);
int fclose_wrapper(FILE *fp)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, fp);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_FCLOSE, FILE*, fp);
	return res;
}
LIBC_FUNC(int, fclose,
		FILE *fp)
{
	return fclose_wrapper(fp);
}

#if 0
//  int setreuid(uid_t ruid, uid_t euid)
int setreuid_wrapper(int ruid, int euid)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, ruid, euid);
	//DO_CREQ_v_W(VG_USERREQ__WRAPPER_FCLOSE, FILE*, fp);
	return res;
}
LIBC_FUNC(int, setreuid,
		int ruid, int euid)
{
	return setreuid_wrapper(ruid, euid);
}
//  int setregid(uid_t ruid, uid_t euid)
int setregid_wrapper(int ruid, int euid)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, ruid, euid);
	//DO_CREQ_v_W(VG_USERREQ__WRAPPER_FCLOSE, FILE*, fp);
	return res;
}
LIBC_FUNC(int, setregid,
		int ruid, int euid)
{
	return setreuid_wrapper(ruid, euid);
}
// int madvise(void *addr, size_t length, int advice);
int madvise_wrapper(void *addr, int length, int advice) 
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_MADVISE_PRE,
			int, addr, int, length, int, advice);
	CALL_FN_W_WWW(res, fn, addr, length, advice);
	DO_CREQ_v_WWWW(VG_USERREQ__WRAPPER_MADVISE,
			int, addr, int, length, int, advice, int, res);
	return res;
}
LIBC_FUNC(int, madvise, void *addr, int length, int advice)
{
	return madvise_wrapper(addr, length, advice);
}
// void exit(int status)
void exit_wrapper(int status)
{
	OrigFn fn;
	VALGRIND_GET_ORIG_FN(fn);
	DO_CREQ_v_W(VG_USERREQ__WRAPPER_EXIT_PRE, int, status);
	CALL_FN_v_W(fn, status);
}
LIBC_FUNC(void, exit, int status)
{
	exit_wrapper(status);
}
// 
// void * mmap (void *address, size_t length, int protect, int flags, int filedes, off_t offset)
void * mmap_wrapper(void *address, size_t length, int protect, int flags, int filedes, int offset )
{
	OrigFn fn;
	void* res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_6W(res, fn, address, length, protect, flags, filedes, offset);
	DO_CREQ_v_WWWWW(VG_USERREQ__WRAPPER_MMAP, 
			int, filedes, int, flags, int, length, int, offset, int, res);
	return res;
}
LIBC_FUNC(void*, mmap,
		void *address, size_t length, int protect, int flags, int filedes, int offset)
{
	return mmap_wrapper(address, length, protect, flags, filedes, offset);
}
//int munmap(void *addr, size_t len); 
int munmap_wrapper(void *addr, int length)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WW(res, fn, addr, length);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_MUNMAP,	void*, addr, int, length, int, res);
	return res;
}
LIBC_FUNC(int, munmap,
		void *addr, int length)
{
	return munmap_wrapper(addr, length);
}
// int mprotect(const void *addr, size_t len, int prot);
int mprotect_wrapper(void *addr, size_t len, int prot)
{
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_WWW(res, fn, addr, len, prot);
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_MPROTECT,	void*, addr, size_t, len, int, prot);
	return res;
}
LIBC_FUNC(int, mprotect,
		void* addr, size_t len, int prot)
{
	return mprotect_wrapper(addr, len, prot);
}
#endif

#if 0
/* wrapper for uninstrumentation */

// int pthread_mutex_lock(pthread_mutex_t *mutex);
int pthread_mutex_lock_wrapper(pthread_mutex_t *mutex) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, mutex);
	return res;
}
LIBC_FUNC(int, pthread_mutex_loack,	pthread_mutex_t* mutex) {
	return pthread_mutex_lock_wrapper(mutex);
}
//int pthread_mutex_trylock(pthread_mutex_t *mutex);
//int pthread_mutex_unlock(pthread_mutex_t *mutex);
int pthread_mutex_unlock_wrapper(pthread_mutex_t *mutex) {
	OrigFn fn;
	int res;
	VALGRIND_GET_ORIG_FN(fn);
	CALL_FN_W_W(res, fn, mutex);
	return res;
}
LIBC_FUNC(int, pthread_mutex_unloack,	pthread_mutex_t* mutex) {
	return pthread_mutex_unlock_wrapper(mutex);
}
#endif
//long ptrace(enum __ptrace_request request, pid_t pid,
//		                    void *addr, void *data);
long ptrace_wrapper(int request, int pid, int addr, int data) {
	OrigFn fn;
	long res;
	VALGRIND_GET_ORIG_FN(fn);
	res = -1;
	//CALL_FN_W_WWWW(res, fn, request, pid, addr, data);
	return res;
}
LIBC_FUNC(long, ptrace,	int r, int p, int a, int d) {
	return ptrace_wrapper(r, p, a, d);
	//return 0;
}
/* ---------------------------------------------------------------------
	 We have our own versions of these functions for two reasons:
	 (a) it allows us to do overlap checking
	 (b) some of the normal versions are hyper-optimised, which fools
	 Memcheck and cause spurious value warnings.  Our versions are
	 simpler.
	 (c) the glibc SSE-variants can read past the end of the input data
	 ranges. This can cause false-positive Memcheck / Helgrind / DRD
	 reports.

	 Note that overenthusiastic use of PLT bypassing by the glibc people also
	 means that we need to patch multiple versions of some of the functions to
	 our own implementations.

	 THEY RUN ON THE SIMD CPU!
	 ------------------------------------------------------------------ */

/* Assignment of behavioural equivalence class tags: 2NNNP is intended
	 to be reserved for str/mem intercepts.  Current usage:

	 20010 STRRCHR
	 20020 STRCHR
	 20030 STRCAT
	 20040 STRNCAT
	 20050 STRLCAT
	 20060 STRNLEN
	 20070 STRLEN
	 20080 STRCPY
	 20090 STRNCPY
	 20100 STRLCPY
	 20110 STRNCMP
	 20120 STRCASECMP
	 20130 STRNCASECMP
	 20140 STRCASECMP_L
	 20150 STRNCASECMP_L
	 20160 STRCMP
	 20170 MEMCHR

	 20180 MEMCPY    if there's a conflict between memcpy and
	 20181 MEMMOVE   memmove, prefer memmove

	 20190 MEMCMP
	 20200 STPCPY
	 20210 MEMSET
	 2022P unused (was previously MEMMOVE)
	 20230 BCOPY
	 20240 GLIBC25___MEMMOVE_CHK
	 20250 GLIBC232_STRCHRNUL
	 20260 GLIBC232_RAWMEMCHR
	 20270 GLIBC25___STRCPY_CHK
	 20280 GLIBC25___STPCPY_CHK
	 20290 GLIBC25_MEMPCPY
	 20300 GLIBC26___MEMCPY_CHK
	 20310 STRSTR
	 20320 STRPBRK
	 20330 STRCSPN
	 20340 STRSPN
	 20350 STRCASESTR
	 20360 MEMRCHR
	 20370 WCSLEN
	 20380 WCSCMP
	 20390 WCSCPY
	 20400 WCSCHR
	 20410 WCSRCHR
	 20420 STPNCPY
	 */

#if defined(VGO_solaris)
/*
	 Detour functions in the libc and the runtime linker. If a function isn't
	 much optimized (and no overlap checking is necessary) then redir the
	 function only in the libc. This way we can keep stacktraces in the tests
	 consistent.
	 */
#endif

#ifndef M_PERFORMANCE
#ifndef ONLY_DUMP

/* Figure out if [dst .. dst+dstlen-1] overlaps with
	 [src .. src+srclen-1].
	 We assume that the address ranges do not wrap around
	 (which is safe since on Linux addresses >= 0xC0000000
	 are not accessible and the program will segfault in this
	 circumstance, presumably).
	 */
	static inline
Bool is_overlap ( void* dst, const void* src, SizeT dstlen, SizeT srclen )
{
	Addr loS, hiS, loD, hiD;

	if (dstlen == 0 || srclen == 0)
		return False;

	loS = (Addr)src;
	loD = (Addr)dst;
	hiS = loS + srclen - 1;
	hiD = loD + dstlen - 1;

	/* So figure out if [loS .. hiS] overlaps with [loD .. hiD]. */
	if (loS < loD) {
		return !(hiS < loD);
	}
	else if (loD < loS) {
		return !(hiD < loS);
	}
	else {
		/* They start at same place.  Since we know neither of them has
			 zero length, they must overlap. */
		return True;
	}
}


/* Call here to exit if we can't continue.  On Android we can't call
	 _exit for some reason, so we have to blunt-instrument it. */
	__attribute__ ((__noreturn__))
static inline void my_exit ( int x )
{
#  if defined(VGPV_arm_linux_android) || defined(VGPV_mips32_linux_android) \
	|| defined(VGPV_arm64_linux_android)
	__asm__ __volatile__(".word 0xFFFFFFFF");
	while (1) {}
#  elif defined(VGPV_x86_linux_android)
	__asm__ __volatile__("ud2");
	while (1) {}
#  else
	extern __attribute__ ((__noreturn__)) void _exit(int status);
	_exit(x);
#  endif
}


//#define RECORD_OVERLAP_ERROR(s, src, dst, len) do { \
//	VG_(printf)("%s: 0x%x 0x%x %d\n", s, src, dst, len); \
//} while (0)
// This is a macro rather than a function because we don't want to have an
// extra function in the stack trace.
#ifndef RECORD_OVERLAP_ERROR
#define RECORD_OVERLAP_ERROR(s, src, dst, len) do { } while (0)
#endif
#ifndef VALGRIND_CHECK_VALUE_IS_DEFINED
#define VALGRIND_CHECK_VALUE_IS_DEFINED(__lvalue) 1
#endif


/*---------------------- memcpy ----------------------*/

#define MEMMOVE_OR_MEMCPY(becTag, soname, fnname, do_ol_check)  \
	void* VG_REPLACE_FUNCTION_EZZ(becTag,soname,fnname) \
( void *dst, const void *src, SizeT len ); \
void* VG_REPLACE_FUNCTION_EZZ(becTag,soname,fnname) \
( void *dst, const void *src, SizeT len ) \
{ \
	DO_CREQ_v_WWW(VG_USERREQ__WRAPPER_MEMCMP, void*, dst, void*, src, SizeT, len ); \
	if (do_ol_check && is_overlap(dst, src, len, len)) \
	RECORD_OVERLAP_ERROR("memcpy", dst, src, len); \
	\
	const Addr WS = sizeof(UWord); /* 8 or 4 */ \
	const Addr WM = WS - 1;        /* 7 or 3 */ \
	\
	if (len > 0) { \
		if (dst < src || !is_overlap(dst, src, len, len)) { \
			\
			/* Copying backwards. */ \
			SizeT n = len; \
			Addr  d = (Addr)dst; \
			Addr  s = (Addr)src; \
			\
			if (((s^d) & WM) == 0) { \
				/* s and d have same UWord alignment. */ \
				/* Pull up to a UWord boundary. */ \
				while ((s & WM) != 0 && n >= 1) \
				{ *(UChar*)d = *(UChar*)s; s += 1; d += 1; n -= 1; } \
				/* Copy UWords. */ \
				while (n >= WS) \
				{ *(UWord*)d = *(UWord*)s; s += WS; d += WS; n -= WS; } \
				if (n == 0) {\
					return dst;} \
			} \
			if (((s|d) & 1) == 0) { \
				/* Both are 16-aligned; copy what we can thusly. */ \
				while (n >= 2) \
				{ *(UShort*)d = *(UShort*)s; s += 2; d += 2; n -= 2; } \
			} \
			/* Copy leftovers, or everything if misaligned. */ \
			while (n >= 1) \
			{ *(UChar*)d = *(UChar*)s; s += 1; d += 1; n -= 1; } \
			\
		} else if (dst > src) { \
			\
			SizeT n = len; \
			Addr  d = ((Addr)dst) + n; \
			Addr  s = ((Addr)src) + n; \
			\
			/* Copying forwards. */ \
			if (((s^d) & WM) == 0) { \
				/* s and d have same UWord alignment. */ \
				/* Back down to a UWord boundary. */ \
				while ((s & WM) != 0 && n >= 1) \
				{ s -= 1; d -= 1; *(UChar*)d = *(UChar*)s; n -= 1; } \
				/* Copy UWords. */ \
				while (n >= WS) \
				{ s -= WS; d -= WS; *(UWord*)d = *(UWord*)s; n -= WS; } \
				if (n == 0) {\
					return dst; }\
			} \
			if (((s|d) & 1) == 0) { \
				/* Both are 16-aligned; copy what we can thusly. */ \
				while (n >= 2) \
				{ s -= 2; d -= 2; *(UShort*)d = *(UShort*)s; n -= 2; } \
			} \
			/* Copy leftovers, or everything if misaligned. */ \
			while (n >= 1) \
			{ s -= 1; d -= 1; *(UChar*)d = *(UChar*)s; n -= 1; } \
			\
		} \
	} \
	\
	return dst; \
}

#define MEMMOVE(soname, fnname)  \
	MEMMOVE_OR_MEMCPY(20181, soname, fnname, 0)

#define MEMCPY(soname, fnname) \
	MEMMOVE_OR_MEMCPY(20180, soname, fnname, 1)

#if defined(VGO_linux)
/* For older memcpy we have to use memmove-like semantics and skip
	 the overlap check; sigh; see #275284. */
	MEMMOVE(VG_Z_LIBC_SONAME, memcpyZAGLIBCZu2Zd2Zd5) /* memcpy@GLIBC_2.2.5 */
	MEMCPY(VG_Z_LIBC_SONAME,  memcpyZAZAGLIBCZu2Zd14) /* memcpy@@GLIBC_2.14 */
	MEMCPY(VG_Z_LIBC_SONAME,  memcpy) /* fallback case */
	MEMCPY(VG_Z_LIBC_SONAME,    __GI_memcpy)
	MEMCPY(VG_Z_LIBC_SONAME,    __memcpy_sse2)
	MEMCPY(VG_Z_LD_SO_1,      memcpy) /* ld.so.1 */
MEMCPY(VG_Z_LD64_SO_1,    memcpy) /* ld64.so.1 */
	/* icc9 blats these around all over the place.  Not only in the main
		 executable but various .so's.  They are highly tuned and read
		 memory beyond the source boundary (although work correctly and
		 never go across page boundaries), so give errors when run
		 natively, at least for misaligned source arg.  Just intercepting
		 in the exe only until we understand more about the problem.  See
		 http://bugs.kde.org/show_bug.cgi?id=139776
		 */
MEMCPY(NONE, ZuintelZufastZumemcpy)

#elif defined(VGO_darwin)
# if DARWIN_VERS <= DARWIN_10_6
MEMCPY(VG_Z_LIBC_SONAME,  memcpy)
# endif
	MEMCPY(VG_Z_LIBC_SONAME,  memcpyZDVARIANTZDsse3x) /* memcpy$VARIANT$sse3x */
MEMCPY(VG_Z_LIBC_SONAME,  memcpyZDVARIANTZDsse42) /* memcpy$VARIANT$sse42 */

#elif defined(VGO_solaris)
	MEMCPY(VG_Z_LIBC_SONAME,  memcpy)
MEMCPY(VG_Z_LD_SO_1,      memcpy)

#endif
	/*---------------------- strcmp ----------------------*/

#define STRCMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20160,soname,fnname) \
	( const char* s1, const char* s2 ); \
	int VG_REPLACE_FUNCTION_EZU(20160,soname,fnname) \
	( const char* s1, const char* s2 ) \
{ \
	const char* s1_org = s1; \
	const char* s2_org = s2; \
	register UChar c1; \
	register UChar c2; \
	while (True) { \
		c1 = *(const UChar *)s1; \
		c2 = *(const UChar *)s2; \
		if (c1 != c2) break; \
		if (c1 == 0) break; \
		s1++; s2++; \
	} \
	DO_CREQ_v_WW(VG_USERREQ__WRAPPER_STRCMP, const char*, s1_org, const char*, s2_org);\
	if ((UChar)c1 < (UChar)c2) return -1; \
	if ((UChar)c1 > (UChar)c2) return 1; \
	return 0; \
}

#if defined(VGO_linux)
	STRCMP(VG_Z_LIBC_SONAME,          strcmp)
	STRCMP(VG_Z_LIBC_SONAME,          __GI_strcmp)
	STRCMP(VG_Z_LIBC_SONAME,          __strcmp_sse2)
	STRCMP(VG_Z_LIBC_SONAME,          __strcmp_sse42)
	STRCMP(VG_Z_LD_LINUX_X86_64_SO_2, strcmp)
STRCMP(VG_Z_LD64_SO_1,            strcmp)
# if defined(VGPV_arm_linux_android) || defined(VGPV_x86_linux_android) \
		|| defined(VGPV_mips32_linux_android)
	STRCMP(NONE, __dl_strcmp); /* in /system/bin/linker */
# endif

#elif defined(VGO_darwin)
STRCMP(VG_Z_LIBC_SONAME, strcmp)
# if DARWIN_VERS >= DARWIN_10_9
STRCMP(libsystemZuplatformZddylib, _platform_strcmp)
# endif

#elif defined(VGO_solaris)
	STRCMP(VG_Z_LIBC_SONAME,          strcmp)
STRCMP(VG_Z_LD_SO_1,              strcmp)

#endif
#if 0
	/*---------------------- strrchr ----------------------*/

#define STRRCHR(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20010,soname,fnname)( const char* s, int c ); \
	char* VG_REPLACE_FUNCTION_EZU(20010,soname,fnname)( const char* s, int c ) \
{ \
	HChar ch = (HChar)c;   \
	const HChar* p = s;       \
	const HChar* last = NULL; \
	while (True) { \
		if (*p == ch) last = p; \
		if (*p == 0) { \
			return CONST_CAST(HChar *,last); }   \
		p++; \
	} \
}

// Apparently rindex() is the same thing as strrchr()
#if defined(VGO_linux)
	STRRCHR(VG_Z_LIBC_SONAME,   strrchr)
	STRRCHR(VG_Z_LIBC_SONAME,   rindex)
	STRRCHR(VG_Z_LIBC_SONAME,   __GI_strrchr)
	STRRCHR(VG_Z_LIBC_SONAME,   __strrchr_sse2)
	STRRCHR(VG_Z_LIBC_SONAME,   __strrchr_sse2_no_bsf)
	STRRCHR(VG_Z_LIBC_SONAME,   __strrchr_sse42)
STRRCHR(VG_Z_LD_LINUX_SO_2, rindex)
#if defined(VGPV_arm_linux_android) || defined(VGPV_x86_linux_android) \
		|| defined(VGPV_mips32_linux_android)
	STRRCHR(NONE, __dl_strrchr); /* in /system/bin/linker */
#endif

#elif defined(VGO_darwin)
	//STRRCHR(VG_Z_LIBC_SONAME,   strrchr)
	//STRRCHR(VG_Z_LIBC_SONAME,   rindex)
	//STRRCHR(VG_Z_DYLD,          strrchr)
	//STRRCHR(VG_Z_DYLD,          rindex)
STRRCHR(VG_Z_LIBC_SONAME, strrchr)
# if DARWIN_VERS >= DARWIN_10_9
STRRCHR(libsystemZucZddylib, strrchr)
# endif

#elif defined(VGO_solaris)
	STRRCHR(VG_Z_LIBC_SONAME,   strrchr)
	STRRCHR(VG_Z_LIBC_SONAME,   rindex)
STRRCHR(VG_Z_LD_SO_1,       strrchr)

#endif


	/*---------------------- strchr ----------------------*/

#define STRCHR(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20020,soname,fnname) ( const char* s, int c ); \
	char* VG_REPLACE_FUNCTION_EZU(20020,soname,fnname) ( const char* s, int c ) \
{ \
	HChar  ch = (HChar)c ; \
	const HChar* p  = s;   \
	while (True) { \
		if (*p == ch) { \
			return CONST_CAST(HChar *,p);}  \
		if (*p == 0) { \
			return NULL; }\
		p++; \
	} \
}

// Apparently index() is the same thing as strchr()
#if defined(VGO_linux)
	STRCHR(VG_Z_LIBC_SONAME,          strchr)
	STRCHR(VG_Z_LIBC_SONAME,          __GI_strchr)
	STRCHR(VG_Z_LIBC_SONAME,          __strchr_sse2)
	STRCHR(VG_Z_LIBC_SONAME,          __strchr_sse2_no_bsf)
STRCHR(VG_Z_LIBC_SONAME,          index)
# if !defined(VGP_x86_linux)
	STRCHR(VG_Z_LD_LINUX_SO_2,        strchr)
	STRCHR(VG_Z_LD_LINUX_SO_2,        index)
	STRCHR(VG_Z_LD_LINUX_X86_64_SO_2, strchr)
STRCHR(VG_Z_LD_LINUX_X86_64_SO_2, index)
# endif

#elif defined(VGO_darwin)
STRCHR(VG_Z_LIBC_SONAME, strchr)
# if DARWIN_VERS == DARWIN_10_9
STRCHR(libsystemZuplatformZddylib, _platform_strchr)
# endif
# if DARWIN_VERS >= DARWIN_10_10
	/* _platform_strchr$VARIANT$Generic */
STRCHR(libsystemZuplatformZddylib, _platform_strchr$VARIANT$Generic)
	/* _platform_strchr$VARIANT$Haswell */
STRCHR(libsystemZuplatformZddylib, _platform_strchr$VARIANT$Haswell)
# endif

#elif defined(VGO_solaris)
	STRCHR(VG_Z_LIBC_SONAME,          strchr)
	STRCHR(VG_Z_LIBC_SONAME,          index)
STRCHR(VG_Z_LD_SO_1,              strchr)

#endif


	/*---------------------- strcat ----------------------*/

#define STRCAT(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20030,soname,fnname) \
	( char* dst, const char* src ); \
	char* VG_REPLACE_FUNCTION_EZU(20030,soname,fnname) \
	( char* dst, const char* src ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	HChar* dst_from = dst; \
	while (*dst) dst++; \
	dst_from = dst; \
	while (*src) *dst++ = *src++; \
	*dst = 0; \
	\
	/* This is a bit redundant, I think;  any overlap and the strcat will */ \
	/* go forever... or until a seg fault occurs. */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1,  \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("strcat", dst_orig, src_orig, 0); \
	\
	return dst_orig; \
}

#if defined(VGO_linux)
	STRCAT(VG_Z_LIBC_SONAME, strcat)
STRCAT(VG_Z_LIBC_SONAME, __GI_strcat)

#elif defined(VGO_darwin)
//STRCAT(VG_Z_LIBC_SONAME, strcat)

#elif defined(VGO_solaris)
	STRCAT(VG_Z_LIBC_SONAME, strcat)
STRCAT(VG_Z_LD_SO_1,     strcat)

#endif


	/*---------------------- strncat ----------------------*/

#define STRNCAT(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20040,soname,fnname) \
	( char* dst, const char* src, SizeT n ); \
	char* VG_REPLACE_FUNCTION_EZU(20040,soname,fnname) \
	( char* dst, const char* src, SizeT n ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	HChar* dst_from = dst; \
	SizeT m = 0; \
	\
	while (*dst) dst++; \
	dst_from = dst; \
	while (m < n && *src) { m++; *dst++ = *src++; } /* concat <= n chars */ \
	*dst = 0;                                       /* always add null   */ \
	\
	/* This checks for overlap after copying, unavoidable without */ \
	/* pre-counting lengths... should be ok */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1, \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("strncat", dst_orig, src_orig, n); \
	\
	return dst_orig; \
}

#if defined(VGO_linux)
STRNCAT(VG_Z_LIBC_SONAME, strncat)

#elif defined(VGO_darwin)
	//STRNCAT(VG_Z_LIBC_SONAME, strncat)
	//STRNCAT(VG_Z_DYLD,        strncat)

#elif defined(VGO_solaris)
STRNCAT(VG_Z_LIBC_SONAME, strncat)

#endif


	/*---------------------- strlcat ----------------------*/

	/* Append src to dst. n is the size of dst's buffer. dst is guaranteed
		 to be nul-terminated after the copy, unless n <= strlen(dst_orig).
		 Returns min(n, strlen(dst_orig)) + strlen(src_orig).
		 Truncation occurred if retval >= n.
		 */
#define STRLCAT(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20050,soname,fnname) \
	( char* dst, const char* src, SizeT n ); \
	SizeT VG_REPLACE_FUNCTION_EZU(20050,soname,fnname) \
	( char* dst, const char* src, SizeT n ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	SizeT m = 0; \
	\
	while (m < n && *dst) { m++; dst++; } \
	if (m < n) { \
		/* Fill as far as dst_orig[n-2], then nul-terminate. */ \
		while (m < n-1 && *src) { m++; *dst++ = *src++; } \
		*dst = 0; \
	} else { \
		/* No space to copy anything to dst. m == n */ \
	} \
	/* Finish counting min(n, strlen(dst_orig)) + strlen(src_orig) */ \
	while (*src) { m++; src++; } \
	/* This checks for overlap after copying, unavoidable without */ \
	/* pre-counting lengths... should be ok */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1,  \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("strlcat", dst_orig, src_orig, n); \
	\
	return m; \
}

#if defined(VGO_linux)

#elif defined(VGO_darwin)
	//STRLCAT(VG_Z_LIBC_SONAME, strlcat)
	//STRLCAT(VG_Z_DYLD,        strlcat)
STRLCAT(VG_Z_LIBC_SONAME, strlcat)

#elif defined(VGO_solaris)
STRLCAT(VG_Z_LIBC_SONAME, strlcat)

#endif


	/*---------------------- strnlen ----------------------*/

#define STRNLEN(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20060,soname,fnname) \
	( const char* str, SizeT n ); \
	SizeT VG_REPLACE_FUNCTION_EZU(20060,soname,fnname) \
	( const char* str, SizeT n ) \
{ \
	SizeT i = 0; \
	while (i < n && str[i] != 0) i++; \
	return i; \
}

#if defined(VGO_linux)
	STRNLEN(VG_Z_LIBC_SONAME, strnlen)
STRNLEN(VG_Z_LIBC_SONAME, __GI_strnlen)

#elif defined(VGO_darwin)
# if DARWIN_VERS == DARWIN_10_9
STRNLEN(libsystemZucZddylib, strnlen)
# endif

#elif defined(VGO_solaris)
STRNLEN(VG_Z_LIBC_SONAME, strnlen)

#endif


	/*---------------------- strlen ----------------------*/

	// Note that this replacement often doesn't get used because gcc inlines
	// calls to strlen() with its own built-in version.  This can be very
	// confusing if you aren't expecting it.  Other small functions in
	// this file may also be inline by gcc.

#define STRLEN(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20070,soname,fnname) \
	( const char* str ); \
	SizeT VG_REPLACE_FUNCTION_EZU(20070,soname,fnname) \
	( const char* str )  \
{ \
	SizeT i = 0; \
	while (str[i] != 0) i++; \
	return i; \
}

#if defined(VGO_linux)
	STRLEN(VG_Z_LIBC_SONAME,          strlen)
	STRLEN(VG_Z_LIBC_SONAME,          __GI_strlen)
	STRLEN(VG_Z_LIBC_SONAME,          __strlen_sse2)
	STRLEN(VG_Z_LIBC_SONAME,          __strlen_sse2_no_bsf)
	STRLEN(VG_Z_LIBC_SONAME,          __strlen_sse42)
	STRLEN(VG_Z_LD_LINUX_SO_2,        strlen)
STRLEN(VG_Z_LD_LINUX_X86_64_SO_2, strlen)
# if defined(VGPV_arm_linux_android) \
		|| defined(VGPV_x86_linux_android) \
	|| defined(VGPV_mips32_linux_android)
	STRLEN(NONE, __dl_strlen); /* in /system/bin/linker */
# endif

#elif defined(VGO_darwin)
STRLEN(VG_Z_LIBC_SONAME, strlen)
# if DARWIN_VERS >= DARWIN_10_9
STRLEN(libsystemZucZddylib, strlen)
# endif

#elif defined(VGO_solaris)
	STRLEN(VG_Z_LIBC_SONAME,          strlen)
STRLEN(VG_Z_LD_SO_1,              strlen)

#endif


	/*---------------------- strcpy ----------------------*/

#define STRCPY(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20080,soname,fnname) \
	( char* dst, const char* src ); \
	char* VG_REPLACE_FUNCTION_EZU(20080,soname,fnname) \
	( char* dst, const char* src ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	\
	while (*src) *dst++ = *src++; \
	*dst = 0; \
	\
	/* This checks for overlap after copying, unavoidable without */ \
	/* pre-counting length... should be ok */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1, \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("strcpy", dst_orig, src_orig, 0); \
	\
	return dst_orig; \
}

#if defined(VGO_linux)
	STRCPY(VG_Z_LIBC_SONAME, strcpy)
STRCPY(VG_Z_LIBC_SONAME, __GI_strcpy)

#elif defined(VGO_darwin)
STRCPY(VG_Z_LIBC_SONAME, strcpy)
# if DARWIN_VERS == DARWIN_10_9
STRCPY(libsystemZucZddylib, strcpy)
# endif

#elif defined(VGO_solaris)
	STRCPY(VG_Z_LIBC_SONAME, strcpy)
STRCPY(VG_Z_LD_SO_1,     strcpy)

#endif


	/*---------------------- strncpy ----------------------*/

#define STRNCPY(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20090,soname,fnname) \
	( char* dst, const char* src, SizeT n ); \
	char* VG_REPLACE_FUNCTION_EZU(20090,soname,fnname) \
	( char* dst, const char* src, SizeT n ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	SizeT m = 0; \
	\
	while (m   < n && *src) { m++; *dst++ = *src++; } \
	/* Check for overlap after copying; all n bytes of dst are relevant, */ \
	/* but only m+1 bytes of src if terminator was found */ \
	if (is_overlap(dst_orig, src_orig, n, (m < n) ? m+1 : n)) \
	RECORD_OVERLAP_ERROR("strncpy", dst, src, n); \
	while (m++ < n) *dst++ = 0;         /* must pad remainder with nulls */ \
	\
	return dst_orig; \
}

#if defined(VGO_linux)
	STRNCPY(VG_Z_LIBC_SONAME, strncpy)
	STRNCPY(VG_Z_LIBC_SONAME, __GI_strncpy)
	STRNCPY(VG_Z_LIBC_SONAME, __strncpy_sse2)
STRNCPY(VG_Z_LIBC_SONAME, __strncpy_sse2_unaligned)

#elif defined(VGO_darwin)
STRNCPY(VG_Z_LIBC_SONAME, strncpy)
# if DARWIN_VERS >= DARWIN_10_9
STRNCPY(libsystemZucZddylib, strncpy)
# endif

#elif defined(VGO_solaris)
	STRNCPY(VG_Z_LIBC_SONAME, strncpy)
STRNCPY(VG_Z_LD_SO_1,     strncpy)

#endif


	/*---------------------- strlcpy ----------------------*/

	/* Copy up to n-1 bytes from src to dst. Then nul-terminate dst if n > 0.
		 Returns strlen(src). Does not zero-fill the remainder of dst. */
#define STRLCPY(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20100,soname,fnname) \
	( char* dst, const char* src, SizeT n ); \
	SizeT VG_REPLACE_FUNCTION_EZU(20100,soname,fnname) \
	( char* dst, const char* src, SizeT n ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	SizeT m = 0; \
	\
	STRLCPY_CHECK_FOR_DSTSIZE_ZERO \
	\
	while (m < n-1 && *src) { m++; *dst++ = *src++; } \
	/* m non-nul bytes have now been copied, and m <= n-1. */ \
	/* Check for overlap after copying; all n bytes of dst are relevant, */ \
	/* but only m+1 bytes of src if terminator was found */ \
	if (is_overlap(dst_orig, src_orig, n, (m < n) ? m+1 : n)) \
	RECORD_OVERLAP_ERROR("strlcpy", dst, src, n); \
	/* Nul-terminate dst. */ \
	if (n > 0) *dst = 0; \
	/* Finish counting strlen(src). */ \
	while (*src) src++; \
	return src - src_orig; \
}

#if defined(VGO_linux)

#if defined(VGPV_arm_linux_android) || defined(VGPV_x86_linux_android) \
		|| defined(VGPV_mips32_linux_android)
#define STRLCPY_CHECK_FOR_DSTSIZE_ZERO
	STRLCPY(VG_Z_LIBC_SONAME, strlcpy);
#endif

#elif defined(VGO_darwin)
#define STRLCPY_CHECK_FOR_DSTSIZE_ZERO
	//STRLCPY(VG_Z_LIBC_SONAME, strlcpy)
	//STRLCPY(VG_Z_DYLD,        strlcpy)
STRLCPY(VG_Z_LIBC_SONAME, strlcpy)

#elif defined(VGO_solaris)
	/* special case for n == 0 which is undocumented but heavily used */
#define STRLCPY_CHECK_FOR_DSTSIZE_ZERO \
		if (n == 0) { \
			while (*src) src++; \
			return src - src_orig; \
		}

STRLCPY(VG_Z_LIBC_SONAME, strlcpy)

#endif


	/*---------------------- strncmp ----------------------*/

#define STRNCMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20110,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax ); \
	int VG_REPLACE_FUNCTION_EZU(20110,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax ) \
{ \
	SizeT n = 0; \
	SizeT l = 0; \
	while (s1[l] != 0) l++; \
	l = 0; \
	while (s2[l] != 0) l++; \
	while (True) { \
		if (n >= nmax) return 0; \
		if (*s1 == 0 && *s2 == 0) return 0; \
		if (*s1 == 0) return -1; \
		if (*s2 == 0) return 1; \
		\
		if (*(const UChar*)s1 < *(const UChar*)s2) return -1; \
		if (*(const UChar*)s1 > *(const UChar*)s2) return 1; \
		\
		s1++; s2++; n++; \
	} \
}

#if defined(VGO_linux)
	//STRNCMP(VG_Z_LIBC_SONAME, strncmp)
	STRNCMP(VG_Z_LIBC_SONAME, __GI_strncmp)
	STRNCMP(VG_Z_LIBC_SONAME, __strncmp_sse2)
STRNCMP(VG_Z_LIBC_SONAME, __strncmp_sse42)

#elif defined(VGO_darwin)
STRNCMP(VG_Z_LIBC_SONAME,        strncmp)
# if DARWIN_VERS >= DARWIN_10_9
STRNCMP(libsystemZuplatformZddylib, _platform_strncmp)
# endif

#elif defined(VGO_solaris)
STRNCMP(VG_Z_LIBC_SONAME, strncmp)

#endif


	/*---------------------- strcasecmp ----------------------*/

#define STRCASECMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20120,soname,fnname) \
	( const char* s1, const char* s2 ); \
	int VG_REPLACE_FUNCTION_EZU(20120,soname,fnname) \
	( const char* s1, const char* s2 ) \
{ \
	extern int tolower(int); \
	const char* s1_org = s1; \
	const char* s2_org = s2; \
	register UChar c1; \
	register UChar c2; \
	while (True) { \
		c1 = tolower(*(const UChar *)s1); \
		c2 = tolower(*(const UChar *)s2); \
		if (c1 != c2) break; \
		if (c1 == 0) break; \
		s1++; s2++; \
	} \
	if ((UChar)c1 < (UChar)c2) return -1; \
	if ((UChar)c1 > (UChar)c2) return 1; \
	return 0; \
}

#if defined(VGO_linux)
# if !defined(VGPV_arm_linux_android) \
		&& !defined(VGPV_x86_linux_android) \
	&& !defined(VGPV_mips32_linux_android) \
	&& !defined(VGPV_arm64_linux_android)
	STRCASECMP(VG_Z_LIBC_SONAME, strcasecmp)
STRCASECMP(VG_Z_LIBC_SONAME, __GI_strcasecmp)
# endif

#elif defined(VGO_darwin)
//STRCASECMP(VG_Z_LIBC_SONAME, strcasecmp)

#elif defined(VGO_solaris)
STRCASECMP(VG_Z_LIBC_SONAME, strcasecmp)

#endif


	/*---------------------- strncasecmp ----------------------*/

#define STRNCASECMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20130,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax ); \
	int VG_REPLACE_FUNCTION_EZU(20130,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax ) \
{ \
	extern int tolower(int); \
	SizeT n = 0; \
	SizeT l = 0; \
	while (s1[l] != 0) l++; \
	l = 0; \
	while (s2[l] != 0)  l++; \
	while (True) { \
		if (n >= nmax) return 0; \
		if (*s1 == 0 && *s2 == 0) return 0; \
		if (*s1 == 0) return -1; \
		if (*s2 == 0) return 1; \
		\
		if (tolower(*(const UChar *)s1) \
				< tolower(*(const UChar*)s2)) return -1; \
		if (tolower(*(const UChar *)s1) \
				> tolower(*(const UChar *)s2)) return 1; \
		\
		s1++; s2++; n++; \
	} \
}

#if defined(VGO_linux)
# if !defined(VGPV_arm_linux_android) \
		&& !defined(VGPV_x86_linux_android) \
	&& !defined(VGPV_mips32_linux_android) \
	&& !defined(VGPV_arm64_linux_android)
	STRNCASECMP(VG_Z_LIBC_SONAME, strncasecmp)
STRNCASECMP(VG_Z_LIBC_SONAME, __GI_strncasecmp)
# endif

#elif defined(VGO_darwin)
//STRNCASECMP(VG_Z_LIBC_SONAME, strncasecmp)
//STRNCASECMP(VG_Z_DYLD,        strncasecmp)

#elif defined(VGO_solaris)
STRNCASECMP(VG_Z_LIBC_SONAME, strncasecmp)

#endif


	/*---------------------- strcasecmp_l ----------------------*/

#define STRCASECMP_L(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20140,soname,fnname) \
	( const char* s1, const char* s2, void* locale ); \
	int VG_REPLACE_FUNCTION_EZU(20140,soname,fnname) \
	( const char* s1, const char* s2, void* locale ) \
{ \
	extern int tolower_l(int, void*) __attribute__((weak)); \
	register UChar c1; \
	register UChar c2; \
	while (True) { \
		c1 = tolower_l(*(const UChar *)s1, locale); \
		c2 = tolower_l(*(const UChar *)s2, locale); \
		if (c1 != c2) break; \
		if (c1 == 0) break; \
		s1++; s2++; \
	} \
	if ((UChar)c1 < (UChar)c2) return -1; \
	if ((UChar)c1 > (UChar)c2) return 1; \
	return 0; \
}

#if defined(VGO_linux)
	STRCASECMP_L(VG_Z_LIBC_SONAME, strcasecmp_l)
	STRCASECMP_L(VG_Z_LIBC_SONAME, __GI_strcasecmp_l)
STRCASECMP_L(VG_Z_LIBC_SONAME, __GI___strcasecmp_l)

#elif defined(VGO_darwin)
//STRCASECMP_L(VG_Z_LIBC_SONAME, strcasecmp_l)

#elif defined(VGO_solaris)

#endif


	/*---------------------- strncasecmp_l ----------------------*/

#define STRNCASECMP_L(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20150,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax, void* locale ); \
	int VG_REPLACE_FUNCTION_EZU(20150,soname,fnname) \
	( const char* s1, const char* s2, SizeT nmax, void* locale ) \
{ \
	extern int tolower_l(int, void*) __attribute__((weak));    \
	SizeT n = 0; \
	while (True) { \
		if (n >= nmax) return 0; \
		if (*s1 == 0 && *s2 == 0) return 0; \
		if (*s1 == 0) return -1; \
		if (*s2 == 0) return 1; \
		\
		if (tolower_l(*(const UChar *)s1, locale) \
				< tolower_l(*(const UChar *)s2, locale)) return -1; \
		if (tolower_l(*(const UChar *)s1, locale) \
				> tolower_l(*(const UChar *)s2, locale)) return 1; \
		\
		s1++; s2++; n++; \
	} \
}

#if defined(VGO_linux)
	STRNCASECMP_L(VG_Z_LIBC_SONAME, strncasecmp_l)
	STRNCASECMP_L(VG_Z_LIBC_SONAME, __GI_strncasecmp_l)
STRNCASECMP_L(VG_Z_LIBC_SONAME, __GI___strncasecmp_l)

#elif defined(VGO_darwin)
//STRNCASECMP_L(VG_Z_LIBC_SONAME, strncasecmp_l)
//STRNCASECMP_L(VG_Z_DYLD,        strncasecmp_l)

#elif defined(VGO_solaris)

#endif




	/*---------------------- memchr ----------------------*/

#define MEMCHR(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20170,soname,fnname) \
	(const void *s, int c, SizeT n); \
	void* VG_REPLACE_FUNCTION_EZU(20170,soname,fnname) \
	(const void *s, int c, SizeT n) \
{ \
	SizeT i; \
	UChar c0 = (UChar)c; \
	const UChar* p = s; \
	for (i = 0; i < n; i++) \
	if (p[i] == c0) {\
		return CONST_CAST(void *,&p[i]); }\
	return NULL; \
}

#if defined(VGO_linux)
//MEMCHR(VG_Z_LIBC_SONAME, memchr)
MEMCHR(VG_Z_LIBC_SONAME, __GI_memchr)

#elif defined(VGO_darwin)
# if DARWIN_VERS == DARWIN_10_9
	MEMCHR(VG_Z_DYLD,                   memchr)
MEMCHR(libsystemZuplatformZddylib, _platform_memchr)
# endif
# if DARWIN_VERS >= DARWIN_10_10
MEMCHR(VG_Z_DYLD,                   memchr)
	/* _platform_memchr$VARIANT$Generic */
MEMCHR(libsystemZuplatformZddylib, _platform_memchr$VARIANT$Generic)
	/* _platform_memchr$VARIANT$Haswell */
MEMCHR(libsystemZuplatformZddylib, _platform_memchr$VARIANT$Haswell)
# endif

#elif defined(VGO_solaris)
MEMCHR(VG_Z_LIBC_SONAME, memchr)

#endif


	/*---------------------- memrchr ----------------------*/

#define MEMRCHR(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20360,soname,fnname) \
	(const void *s, int c, SizeT n); \
	void* VG_REPLACE_FUNCTION_EZU(20360,soname,fnname) \
	(const void *s, int c, SizeT n) \
{ \
	SizeT i; \
	UChar c0 = (UChar)c; \
	const UChar* p = s; \
	for (i = 0; i < n; i++) \
	if (p[n-1-i] == c0) { \
		return CONST_CAST(void *,&p[n-1-i]); }\
	return NULL; \
}

#if defined(VGO_linux)
MEMRCHR(VG_Z_LIBC_SONAME, memrchr)

#elif defined(VGO_darwin)
	//MEMRCHR(VG_Z_LIBC_SONAME, memrchr)
	//MEMRCHR(VG_Z_DYLD,        memrchr)

#elif defined(VGO_solaris)

#endif



	/*---------------------- memcmp ----------------------*/

#define MEMCMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20190,soname,fnname)       \
	( const void *s1V, const void *s2V, SizeT n ); \
	int VG_REPLACE_FUNCTION_EZU(20190,soname,fnname)       \
	( const void *s1V, const void *s2V, SizeT n )  \
{ \
	const SizeT WS = sizeof(UWord); /* 8 or 4 */ \
	const SizeT WM = WS - 1;        /* 7 or 3 */ \
	Addr s1A = (Addr)s1V; \
	Addr s2A = (Addr)s2V; \
	if (((s1A | s2A) & WM) == 0) { \
		/* Both areas are word aligned.  Skip over the */ \
		/* equal prefix as fast as possible. */ \
		while (n >= WS) { \
			UWord w1 = *(UWord*)s1A; \
			UWord w2 = *(UWord*)s2A; \
			if (w1 != w2) break; \
			s1A += WS; \
			s2A += WS; \
			n -= WS; \
		} \
	} \
	\
	const UChar* s1 = (const UChar*) s1A; \
	const UChar* s2 = (const UChar*) s2A; \
	\
	while (n != 0) { \
		UChar a0 = s1[0]; \
		UChar b0 = s2[0]; \
		s1 += 1; \
		s2 += 1; \
		int res = ((int)a0) - ((int)b0); \
		if (res != 0) \
		return res; \
		n -= 1; \
	} \
	return 0; \
}

#if defined(VGO_linux)
	MEMCMP(VG_Z_LIBC_SONAME, memcmp)
	MEMCMP(VG_Z_LIBC_SONAME, __GI_memcmp)
	MEMCMP(VG_Z_LIBC_SONAME, __memcmp_sse2)
	MEMCMP(VG_Z_LIBC_SONAME, __memcmp_sse4_1)
	MEMCMP(VG_Z_LIBC_SONAME, bcmp)
MEMCMP(VG_Z_LD_SO_1,     bcmp)

#elif defined(VGO_darwin)
# if DARWIN_VERS >= DARWIN_10_9
MEMCMP(libsystemZuplatformZddylib, _platform_memcmp)
# endif

#elif defined(VGO_solaris)
	MEMCMP(VG_Z_LIBC_SONAME, memcmp)
	MEMCMP(VG_Z_LIBC_SONAME, bcmp)
MEMCMP(VG_Z_LD_SO_1,     memcmp)

#endif


	/*---------------------- stpcpy ----------------------*/

	/* Copy SRC to DEST, returning the address of the terminating '\0' in
		 DEST. (minor variant of strcpy) */
#define STPCPY(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20200,soname,fnname) \
	( char* dst, const char* src ); \
	char* VG_REPLACE_FUNCTION_EZU(20200,soname,fnname) \
	( char* dst, const char* src ) \
{  UInt len = 0;\
	const HChar* src_orig = src; \
	HChar* dst_orig = dst; \
	\
	while (*src) {*dst++ = *src++; len++;}\
	*dst = 0; \
	\
	/* This checks for overlap after copying, unavoidable without */ \
	/* pre-counting length... should be ok */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1,  \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("stpcpy", dst_orig, src_orig, 0); \
	\
	return dst; \
}

#if defined(VGO_linux)
	STPCPY(VG_Z_LIBC_SONAME,          stpcpy)
	STPCPY(VG_Z_LIBC_SONAME,          __GI_stpcpy)
	STPCPY(VG_Z_LIBC_SONAME,          __stpcpy_sse2)
	STPCPY(VG_Z_LIBC_SONAME,          __stpcpy_sse2_unaligned)
	STPCPY(VG_Z_LD_LINUX_SO_2,        stpcpy)
STPCPY(VG_Z_LD_LINUX_X86_64_SO_2, stpcpy)

#elif defined(VGO_darwin)
	//STPCPY(VG_Z_LIBC_SONAME,          stpcpy)
	//STPCPY(VG_Z_DYLD,                 stpcpy)

#elif defined(VGO_solaris)
STPCPY(VG_Z_LIBC_SONAME,          stpcpy)

#endif


	/*---------------------- stpncpy ----------------------*/

#define STPNCPY(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20420,soname,fnname) \
	( char* dst, const char* src, SizeT n ); \
	char* VG_REPLACE_FUNCTION_EZU(20420,soname,fnname) \
	( char* dst, const char* src, SizeT n ) \
{ \
	const HChar* src_orig = src; \
	HChar* dst_str  = dst; \
	SizeT m = 0; \
	\
	while (m < n && *src) { m++; *dst++ = *src++; } \
	/* Check for overlap after copying; all n bytes of dst are relevant, */ \
	/* but only m+1 bytes of src if terminator was found */ \
	if (is_overlap(dst_str, src_orig, n, (m < n) ? m+1 : n)) \
	RECORD_OVERLAP_ERROR("stpncpy", dst, src, n); \
	dst_str = dst; \
	while (m++ < n) *dst++ = 0;         /* must pad remainder with nulls */ \
	\
	return dst_str; \
}

#if defined(VGO_linux)
STPNCPY(VG_Z_LIBC_SONAME, stpncpy)
#endif


	/*---------------------- memset ----------------------*/

	/* Why are we bothering to intercept this?  It seems entirely
		 pointless. */

#define MEMSET(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20210,soname,fnname) \
	(void *s, Int c, SizeT n); \
	void* VG_REPLACE_FUNCTION_EZU(20210,soname,fnname) \
	(void *s, Int c, SizeT n) \
{ \
	if (sizeof(void*) == 8) { \
		Addr  a  = (Addr)s;   \
		ULong c8 = (c & 0xFF); \
		c8 = (c8 << 8) | c8; \
		c8 = (c8 << 16) | c8; \
		c8 = (c8 << 32) | c8; \
		while ((a & 7) != 0 && n >= 1) \
		{ *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
		while (n >= 8) \
		{ *(ULong*)a = c8; a += 8; n -= 8; } \
		while (n >= 1) \
		{ *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
		return s; \
	} else { \
		Addr a  = (Addr)s;   \
		UInt c4 = (c & 0xFF); \
		c4 = (c4 << 8) | c4; \
		c4 = (c4 << 16) | c4; \
		while ((a & 3) != 0 && n >= 1) \
		{ *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
		while (n >= 4) \
		{ *(UInt*)a = c4; a += 4; n -= 4; } \
		while (n >= 1) \
		{ *(UChar*)a = (UChar)c; a += 1; n -= 1; } \
		return s; \
	} \
}

#if defined(VGO_linux)
MEMSET(VG_Z_LIBC_SONAME, memset)

#elif defined(VGO_darwin)
	//MEMSET(VG_Z_LIBC_SONAME, memset)
	//MEMSET(VG_Z_DYLD,        memset)
MEMSET(VG_Z_LIBC_SONAME, memset)

#elif defined(VGO_solaris)
MEMSET(VG_Z_LIBC_SONAME, memset)

#endif


	/*---------------------- memmove ----------------------*/

	/* memmove -- use the MEMMOVE defn above. */

#if defined(VGO_linux)
	MEMMOVE(VG_Z_LIBC_SONAME, memmove)
MEMMOVE(VG_Z_LIBC_SONAME, __GI_memmove)
	/* See bug #349828 Override for ld64.so.1 like memcpy, because for some
		 arches MEMCPY_OK_FOR_FORWARD_MEMMOVE is set, which might cause memmove
		 to call memcpy.  */
MEMMOVE(VG_Z_LD64_SO_1, memmove)

#elif defined(VGO_darwin)
# if DARWIN_VERS <= DARWIN_10_6
MEMMOVE(VG_Z_LIBC_SONAME, memmove)
# endif
	MEMMOVE(VG_Z_LIBC_SONAME,  memmoveZDVARIANTZDsse3x) /* memmove$VARIANT$sse3x */
MEMMOVE(VG_Z_LIBC_SONAME,  memmoveZDVARIANTZDsse42) /* memmove$VARIANT$sse42 */
# if DARWIN_VERS >= DARWIN_10_9
	/* _platform_memmove$VARIANT$Ivybridge */
MEMMOVE(libsystemZuplatformZddylib, ZuplatformZumemmoveZDVARIANTZDIvybridge)
# endif

#elif defined(VGO_solaris)
	MEMMOVE(VG_Z_LIBC_SONAME, memmove)
MEMMOVE(VG_Z_LD_SO_1,     memmove)

#endif


	/*---------------------- bcopy ----------------------*/

#define BCOPY(soname, fnname) \
		void VG_REPLACE_FUNCTION_EZU(20230,soname,fnname) \
	(const void *srcV, void *dstV, SizeT n); \
	void VG_REPLACE_FUNCTION_EZU(20230,soname,fnname) \
	(const void *srcV, void *dstV, SizeT n) \
{ \
	SizeT i; \
	HChar* dst = dstV; \
	const HChar* src = srcV; \
	if (dst < src) { \
		for (i = 0; i < n; i++) \
		dst[i] = src[i]; \
	} \
	else  \
	if (dst > src) { \
		for (i = 0; i < n; i++) \
		dst[n-i-1] = src[n-i-1]; \
	} \
}

#if defined(VGO_linux)
BCOPY(VG_Z_LIBC_SONAME, bcopy)

#elif defined(VGO_darwin)
	//BCOPY(VG_Z_LIBC_SONAME, bcopy)
	//BCOPY(VG_Z_DYLD,        bcopy)

#elif defined(VGO_darwin)
BCOPY(VG_Z_LIBC_SONAME, bcopy)

#endif


	/*-------------------- memmove_chk --------------------*/

	/* glibc 2.5 variant of memmove which checks the dest is big enough.
		 There is no specific part of glibc that this is copied from. */
#define GLIBC25___MEMMOVE_CHK(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20240,soname,fnname) \
	(void *dstV, const void *srcV, SizeT n, SizeT destlen); \
	void* VG_REPLACE_FUNCTION_EZU(20240,soname,fnname) \
	(void *dstV, const void *srcV, SizeT n, SizeT destlen) \
{ \
	SizeT i; \
	HChar* dst = dstV;        \
	const HChar* src = srcV; \
	if (destlen < n) \
	goto badness; \
	if (dst < src) { \
		for (i = 0; i < n; i++) \
		dst[i] = src[i]; \
	} \
	else  \
	if (dst > src) { \
		for (i = 0; i < n; i++) \
		dst[n-i-1] = src[n-i-1]; \
	} \
	return dst; \
	badness: \
	VALGRIND_PRINTF_BACKTRACE( \
			"*** memmove_chk: buffer overflow detected ***: " \
			"program terminated\n"); \
	my_exit(1); \
	/*NOTREACHED*/ \
	return NULL; \
}

#if defined(VGO_linux)
GLIBC25___MEMMOVE_CHK(VG_Z_LIBC_SONAME, __memmove_chk)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*-------------------- strchrnul --------------------*/

	/* Find the first occurrence of C in S or the final NUL byte.  */
#define GLIBC232_STRCHRNUL(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20250,soname,fnname) \
	(const char* s, int c_in); \
	char* VG_REPLACE_FUNCTION_EZU(20250,soname,fnname) \
	(const char* s, int c_in) \
{ \
	HChar c = (HChar) c_in; \
	const HChar* char_ptr = s; \
	while (1) { \
		if (*char_ptr == 0) return CONST_CAST(HChar *,char_ptr);  \
		if (*char_ptr == c) return CONST_CAST(HChar *,char_ptr);  \
		char_ptr++; \
	} \
}

#if defined(VGO_linux)
GLIBC232_STRCHRNUL(VG_Z_LIBC_SONAME, strchrnul)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*---------------------- rawmemchr ----------------------*/

	/* Find the first occurrence of C in S.  */
#define GLIBC232_RAWMEMCHR(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20260,soname,fnname) \
	(const void* s, int c_in); \
	void* VG_REPLACE_FUNCTION_EZU(20260,soname,fnname) \
	(const void* s, int c_in) \
{ \
	UChar c = (UChar) c_in; \
	const UChar* char_ptr = s; \
	while (1) { \
		if (*char_ptr == c) return CONST_CAST(void *,char_ptr); \
		char_ptr++; \
	} \
}

#if defined (VGO_linux)
	GLIBC232_RAWMEMCHR(VG_Z_LIBC_SONAME, rawmemchr)
GLIBC232_RAWMEMCHR(VG_Z_LIBC_SONAME, __GI___rawmemchr)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*---------------------- strcpy_chk ----------------------*/

	/* glibc variant of strcpy that checks the dest is big enough.
		 Copied from glibc-2.5/debug/test-strcpy_chk.c. */
#define GLIBC25___STRCPY_CHK(soname,fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20270,soname,fnname) \
	(char* dst, const char* src, SizeT len); \
	char* VG_REPLACE_FUNCTION_EZU(20270,soname,fnname) \
	(char* dst, const char* src, SizeT len) \
{ \
	const HChar* src_orig = src; \
	const HChar* dst_orig = dst; \
	const SizeT  len_orig = len; \
	HChar* ret = dst; \
	if (! len) \
	goto badness; \
	while ((*dst++ = *src++) != '\0') \
	if (--len == 0) \
	goto badness; \
	return ret; \
	badness: \
	VALGRIND_PRINTF_BACKTRACE( \
			"*** strcpy_chk: buffer overflow detected ***: " \
			"program terminated\n"); \
	my_exit(1); \
	/*NOTREACHED*/ \
	return NULL; \
}

#if defined(VGO_linux)
GLIBC25___STRCPY_CHK(VG_Z_LIBC_SONAME, __strcpy_chk)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*---------------------- stpcpy_chk ----------------------*/

	/* glibc variant of stpcpy that checks the dest is big enough.
		 Copied from glibc-2.5/debug/test-stpcpy_chk.c. */
#define GLIBC25___STPCPY_CHK(soname,fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20280,soname,fnname) \
	(char* dst, const char* src, SizeT len); \
	char* VG_REPLACE_FUNCTION_EZU(20280,soname,fnname) \
	(char* dst, const char* src, SizeT len) \
{ \
	const HChar* src_orig = src; \
	const HChar* dst_orig = dst; \
	const SizeT  len_orig = len; \
	if (! len) \
	goto badness; \
	while ((*dst++ = *src++) != '\0') \
	if (--len == 0) \
	goto badness; \
	return dst - 1; \
	badness: \
	VALGRIND_PRINTF_BACKTRACE( \
			"*** stpcpy_chk: buffer overflow detected ***: " \
			"program terminated\n"); \
	my_exit(1); \
	/*NOTREACHED*/ \
	return NULL; \
}

#if defined(VGO_linux)
GLIBC25___STPCPY_CHK(VG_Z_LIBC_SONAME, __stpcpy_chk)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*---------------------- mempcpy ----------------------*/

	/* mempcpy */
#define GLIBC25_MEMPCPY(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20290,soname,fnname) \
	( void *dst, const void *src, SizeT len ); \
	void* VG_REPLACE_FUNCTION_EZU(20290,soname,fnname) \
	( void *dst, const void *src, SizeT len ) \
{ \
	SizeT len_saved = len; \
	\
	if (len == 0) \
	return dst; \
	\
	if (is_overlap(dst, src, len, len)) \
	RECORD_OVERLAP_ERROR("mempcpy", dst, src, len); \
	\
	if ( dst > src ) { \
		register HChar *d = (char *)dst + len - 1; \
		register const HChar *s = (const char *)src + len - 1; \
		while ( len-- ) { \
			*d-- = *s--; \
		} \
	} else if ( dst < src ) { \
		register HChar *d = dst; \
		register const HChar *s = src; \
		while ( len-- ) { \
			*d++ = *s++; \
		} \
	} \
	return (void*)( ((char*)dst) + len_saved ); \
}

#if defined(VGO_linux)
	GLIBC25_MEMPCPY(VG_Z_LIBC_SONAME, mempcpy)
	GLIBC25_MEMPCPY(VG_Z_LIBC_SONAME, __GI_mempcpy)
	GLIBC25_MEMPCPY(VG_Z_LD_SO_1,     mempcpy) /* ld.so.1 */
	GLIBC25_MEMPCPY(VG_Z_LD_LINUX_SO_3, mempcpy) /* ld-linux.so.3 */
GLIBC25_MEMPCPY(VG_Z_LD_LINUX_X86_64_SO_2, mempcpy) /* ld-linux-x86-64.so.2 */

#elif defined(VGO_darwin)
//GLIBC25_MEMPCPY(VG_Z_LIBC_SONAME, mempcpy)

#elif defined(VGO_solaris)

#endif


	/*-------------------- memcpy_chk --------------------*/

#define GLIBC26___MEMCPY_CHK(soname, fnname) \
		void* VG_REPLACE_FUNCTION_EZU(20300,soname,fnname) \
	(void* dst, const void* src, SizeT len, SizeT dstlen ); \
	void* VG_REPLACE_FUNCTION_EZU(20300,soname,fnname) \
	(void* dst, const void* src, SizeT len, SizeT dstlen ) \
{ \
	register HChar *d; \
	register const HChar *s; \
	SizeT len_saved = len; \		
	\
	if (dstlen < len) goto badness; \
	\
	if (len == 0) \
	return dst; \
	\
	if (is_overlap(dst, src, len, len)) \
	RECORD_OVERLAP_ERROR("__memcpy_chk", dst, src, len); \
	\
	if ( dst > src ) { \
		d = (HChar *)dst + len - 1; \
		s = (const HChar *)src + len - 1; \
		while ( len-- ) { \
			*d-- = *s--; \
		} \
	} else if ( dst < src ) { \
		d = (HChar *)dst; \
		s = (const HChar *)src; \
		while ( len-- ) { \
			*d++ = *s++; \
		} \
	} \
	return dst; \
	badness: \
	VALGRIND_PRINTF_BACKTRACE( \
			"*** memcpy_chk: buffer overflow detected ***: " \
			"program terminated\n"); \
	my_exit(1); \
	/*NOTREACHED*/ \
	return NULL; \
}

#if defined(VGO_linux)
GLIBC26___MEMCPY_CHK(VG_Z_LIBC_SONAME, __memcpy_chk)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)

#endif


	/*---------------------- strstr ----------------------*/
// char* strstr(char *str1, const char *str2)
#define STRSTR(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20310,soname,fnname) \
	(const char* haystack, const char* needle); \
	char* VG_REPLACE_FUNCTION_EZU(20310,soname,fnname) \
	(const char* haystack, const char* needle) \
{ \
	const HChar* h = haystack; \
	const HChar* n = needle; \
	\
	/* find the length of n, not including terminating zero */ \
	UWord nlen = 0, hlen = 0; \
	while (h[hlen]) hlen++; \
	while (n[nlen]) nlen++;\
	/* if n is the empty string, match immediately. */ \
	if (nlen == 0) return CONST_CAST(HChar *,h); \
	/* assert(nlen >= 1); */ \
	HChar n0 = n[0]; \
	\
	while (1) { \
		const HChar hh = *h; \
		if (hh == 0) return NULL; \
		if (hh != n0) { h++; continue; } \
		\
		UWord i; \
		for (i = 0; i < nlen; i++) { \
			if (n[i] != h[i]) \
			break; \
		} \
		/* assert(i >= 0 && i <= nlen); */ \
		if (i == nlen) {\
			DO_CREQ_v_WW(VG_USERREQ__WRAPPER_STRSTR, char*, haystack, char*, needle);\
			return CONST_CAST(HChar *,h);          \
		}\
		h++; \
	} \
}

#if defined(VGO_linux)
//	STRSTR(VG_Z_LIBC_SONAME,          strstr)
	STRSTR(VG_Z_LIBC_SONAME,          __strstr_sse2)
STRSTR(VG_Z_LIBC_SONAME,          __strstr_sse42)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
STRSTR(VG_Z_LIBC_SONAME,          strstr)

#endif


	/*---------------------- strpbrk ----------------------*/

#define STRPBRK(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20320,soname,fnname) \
	(const char* sV, const char* acceptV); \
	char* VG_REPLACE_FUNCTION_EZU(20320,soname,fnname) \
	(const char* sV, const char* acceptV) \
{ \
	const HChar* s = sV; \
	const HChar* accept = acceptV; \
	\
	/*  find the length of 'accept', not including terminating zero */ \
	UWord nacc = 0; \
	while (accept[nacc]) nacc++; \
	\
	/* if n is the empty string, fail immediately. */ \
	if (nacc == 0) return NULL; \
	\
	/* assert(nacc >= 1); */ \
	while (1) { \
		UWord i; \
		HChar sc = *s; \
		if (sc == 0) \
		break; \
		for (i = 0; i < nacc; i++) { \
			if (sc == accept[i]) \
			return CONST_CAST(HChar *,s);       \
		} \
		s++; \
	} \
	\
	return NULL; \
}

#if defined(VGO_linux)
STRPBRK(VG_Z_LIBC_SONAME,          strpbrk)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
STRPBRK(VG_Z_LIBC_SONAME,          strpbrk)

#endif


	/*---------------------- strcspn ----------------------*/

#define STRCSPN(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20330,soname,fnname) \
	(const char* sV, const char* rejectV); \
	SizeT VG_REPLACE_FUNCTION_EZU(20330,soname,fnname) \
	(const char* sV, const char* rejectV) \
{ \
	const HChar* s = sV; \
	const HChar* reject = rejectV; \
	\
	/* find the length of 'reject', not including terminating zero */ \
	UWord nrej = 0; \
	while (reject[nrej]) nrej++; \
	\
	UWord len = 0; \
	while (1) { \
		UWord i; \
		HChar sc = *s; \
		if (sc == 0) \
		break; \
		for (i = 0; i < nrej; i++) { \
			if (sc == reject[i]) \
			break; \
		} \
		/* assert(i >= 0 && i <= nrej); */ \
		if (i < nrej) \
		break; \
		s++; \
		len++; \
	} \
	\
	return len; \
}

#if defined(VGO_linux)
STRCSPN(VG_Z_LIBC_SONAME,          strcspn)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
STRCSPN(VG_Z_LIBC_SONAME,          strcspn)

#endif


	/*---------------------- strspn ----------------------*/

#define STRSPN(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20340,soname,fnname) \
	(const char* sV, const char* acceptV); \
	SizeT VG_REPLACE_FUNCTION_EZU(20340,soname,fnname) \
	(const char* sV, const char* acceptV) \
{ \
	const UChar* s = (const UChar *)sV;        \
	const UChar* accept = (const UChar *)acceptV;     \
	\
	/* find the length of 'accept', not including terminating zero */ \
	UWord nacc = 0; \
	while (accept[nacc]) nacc++; \
	if (nacc == 0) return 0; \
	\
	UWord len = 0; \
	while (1) { \
		UWord i; \
		HChar sc = *s; \
		if (sc == 0) \
		break; \
		for (i = 0; i < nacc; i++) { \
			if (sc == accept[i]) \
			break; \
		} \
		/* assert(i >= 0 && i <= nacc); */ \
		if (i == nacc) \
		break; \
		s++; \
		len++; \
	} \
	\
	return len; \
}

#if defined(VGO_linux)
STRSPN(VG_Z_LIBC_SONAME,          strspn)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
STRSPN(VG_Z_LIBC_SONAME,          strspn)

#endif


	/*---------------------- strcasestr ----------------------*/

#define STRCASESTR(soname, fnname) \
		char* VG_REPLACE_FUNCTION_EZU(20350,soname,fnname) \
	(const char* haystack, const char* needle); \
	char* VG_REPLACE_FUNCTION_EZU(20350,soname,fnname) \
	(const char* haystack, const char* needle) \
{ \
	extern int tolower(int); \
	const HChar* h = haystack; \
	const HChar* n = needle;   \
	\
	/* find the length of n, not including terminating zero */ \
	UWord nlen = 0; \
	while (n[nlen]) nlen++; \
	\
	/* if n is the empty string, match immediately. */ \
	if (nlen == 0) return CONST_CAST(HChar *,h);       \
	\
	/* assert(nlen >= 1); */ \
	UChar n0 = tolower(n[0]);                 \
	\
	while (1) { \
		UChar hh = tolower(*h);    \
		if (hh == 0) return NULL; \
		if (hh != n0) { h++; continue; } \
		\
		UWord i; \
		for (i = 0; i < nlen; i++) { \
			if (tolower(n[i]) != tolower(h[i]))  \
			break; \
		} \
		/* assert(i >= 0 && i <= nlen); */ \
		if (i == nlen) \
		return CONST_CAST(HChar *,h);    \
		\
		h++; \
	} \
}

#if defined(VGO_linux)
# if !defined(VGPV_arm_linux_android) \
		&& !defined(VGPV_x86_linux_android) \
	&& !defined(VGPV_mips32_linux_android) \
	&& !defined(VGPV_arm64_linux_android)
STRCASESTR(VG_Z_LIBC_SONAME,      strcasestr)
# endif

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
STRCASESTR(VG_Z_LIBC_SONAME,      strcasestr)

#endif


	/*---------------------- wcslen ----------------------*/

	// This is a wchar_t equivalent to strlen.  Unfortunately
	// we don't have wchar_t available here, but it looks like
	// a 32 bit int on Linux.  I don't know if that is also
	// valid on MacOSX.

#define WCSLEN(soname, fnname) \
		SizeT VG_REPLACE_FUNCTION_EZU(20370,soname,fnname) \
	( const UInt* str ); \
	SizeT VG_REPLACE_FUNCTION_EZU(20370,soname,fnname) \
	( const UInt* str )  \
{ \
	SizeT i = 0; \
	while (str[i] != 0) i++; \
	return i; \
}

#if defined(VGO_linux)
WCSLEN(VG_Z_LIBC_SONAME,          wcslen)

#elif defined(VGO_darwin)

#elif defined(VGO_solaris)
WCSLEN(VG_Z_LIBC_SONAME,          wcslen)

#endif

	/*---------------------- wcscmp ----------------------*/

	// This is a wchar_t equivalent to strcmp.  We don't
	// have wchar_t available here, but in the GNU C Library
	// wchar_t is always 32 bits wide and wcscmp uses signed
	// comparison, not unsigned as in strcmp function.

#define WCSCMP(soname, fnname) \
		int VG_REPLACE_FUNCTION_EZU(20380,soname,fnname) \
	( const Int* s1, const Int* s2 ); \
	int VG_REPLACE_FUNCTION_EZU(20380,soname,fnname) \
	( const Int* s1, const Int* s2 ) \
{ \
	register Int c1; \
	register Int c2; \
	while (True) { \
		c1 = *s1; \
		c2 = *s2; \
		if (c1 != c2) break; \
		if (c1 == 0) break; \
		s1++; s2++; \
	} \
	if (c1 < c2) return -1; \
	if (c1 > c2) return 1; \
	return 0; \
}

#if defined(VGO_linux)
WCSCMP(VG_Z_LIBC_SONAME,          wcscmp)
#endif

	/*---------------------- wcscpy ----------------------*/

	// This is a wchar_t equivalent to strcpy.  We don't
	// have wchar_t available here, but in the GNU C Library
	// wchar_t is always 32 bits wide.

#define WCSCPY(soname, fnname) \
		Int* VG_REPLACE_FUNCTION_EZU(20390,soname,fnname) \
	( Int* dst, const Int* src ); \
	Int* VG_REPLACE_FUNCTION_EZU(20390,soname,fnname) \
	( Int* dst, const Int* src ) \
{ \
	const Int* src_orig = src; \
	const Int* dst_orig = dst; \
	const Int  s = sizeof(Int);\
	Int len = 0; \
	\
	while (*src) {*dst++ = *src++; len += s;} \
	*dst = 0; \
	\
	/* This checks for overlap after copying, unavoidable without */ \
	/* pre-counting length... should be ok */ \
	if (is_overlap(dst_orig,  \
				src_orig,  \
				(Addr)dst-(Addr)dst_orig+1, \
				(Addr)src-(Addr)src_orig+1)) \
	RECORD_OVERLAP_ERROR("wcscpy", dst_orig, src_orig, 0); \
	\
	return dst_orig; \
}

#if defined(VGO_linux)
WCSCPY(VG_Z_LIBC_SONAME, wcscpy)
#endif


	/*---------------------- wcschr ----------------------*/

	// This is a wchar_t equivalent to strchr.  We don't
	// have wchar_t available here, but in the GNU C Library
	// wchar_t is always 32 bits wide.

#define WCSCHR(soname, fnname) \
		Int* VG_REPLACE_FUNCTION_EZU(20400,soname,fnname) ( const Int* s, Int c ); \
	Int* VG_REPLACE_FUNCTION_EZU(20400,soname,fnname) ( const Int* s, Int c ) \
{ \
	const Int* p = s; \
	while (True) { \
		if (*p == c) return CONST_CAST(Int *,p);  \
		if (*p == 0) return NULL; \
		p++; \
	} \
}

#if defined(VGO_linux)
WCSCHR(VG_Z_LIBC_SONAME,          wcschr)
#endif
	/*---------------------- wcsrchr ----------------------*/

	// This is a wchar_t equivalent to strrchr.  We don't
	// have wchar_t available here, but in the GNU C Library
	// wchar_t is always 32 bits wide.

#define WCSRCHR(soname, fnname) \
		Int* VG_REPLACE_FUNCTION_EZU(20410,soname,fnname)( const Int* s, Int c ); \
	Int* VG_REPLACE_FUNCTION_EZU(20410,soname,fnname)( const Int* s, Int c ) \
{ \
	const Int* p = s; \
	const Int* last = NULL; \
	while (True) { \
		if (*p == c) last = p; \
		if (*p == 0) return CONST_CAST(Int *,last);  \
		p++; \
	} \
}

#if defined(VGO_linux)
WCSRCHR(VG_Z_LIBC_SONAME, wcsrchr)
#endif

	/*------------------------------------------------------------*/
	/*--- Improve definedness checking of process environment  ---*/
	/*------------------------------------------------------------*/

#if defined(VGO_linux)

	/* If these wind up getting generated via a macro, so that multiple
		 versions of each function exist (as above), use the _EZU variants
		 to assign equivalance class tags. */

	/*---------------------- putenv ----------------------*/

	int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, putenv) (char* string);
int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, putenv) (char* string)
{
	OrigFn fn;
	Word result;
	const HChar* p = string;
	VALGRIND_GET_ORIG_FN(fn);
	/* Now by walking over the string we magically produce
		 traces when hitting undefined memory. */
	if (p)
		while (*p++)
			__asm__ __volatile__("" ::: "memory");
	CALL_FN_W_W(result, fn, string);
	return result;
}


/*---------------------- unsetenv ----------------------*/

int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, unsetenv) (const char* name);
int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, unsetenv) (const char* name)
{
	OrigFn fn;
	Word result;
	const HChar* p = name;
	VALGRIND_GET_ORIG_FN(fn);
	/* Now by walking over the string we magically produce
		 traces when hitting undefined memory. */
	if (p)
		while (*p++)
			__asm__ __volatile__("" ::: "memory");
	CALL_FN_W_W(result, fn, name);
	return result;
}


/*---------------------- setenv ----------------------*/

/* setenv */
int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, setenv)
	(const char* name, const char* value, int overwrite);
	int VG_WRAP_FUNCTION_ZU(VG_Z_LIBC_SONAME, setenv)
(const char* name, const char* value, int overwrite)
{
	OrigFn fn;
	Word result;
	const HChar* p;
	VALGRIND_GET_ORIG_FN(fn);
	/* Now by walking over the string we magically produce
		 traces when hitting undefined memory. */
	if (name)
		for (p = name; *p; p++)
			__asm__ __volatile__("" ::: "memory");
	if (value)
		for (p = value; *p; p++)
			__asm__ __volatile__("" ::: "memory");
	(void) VALGRIND_CHECK_VALUE_IS_DEFINED (overwrite);
	CALL_FN_W_WWW(result, fn, name, value, overwrite);
	return result;
}
#endif /* defined(VGO_linux) */

#endif // ONLY_DUMP
#endif // M_PERFORMANCE
#endif
/*--------------------------------------------------------------------*/
/*--- end                                                          ---*/
/*--------------------------------------------------------------------*/
