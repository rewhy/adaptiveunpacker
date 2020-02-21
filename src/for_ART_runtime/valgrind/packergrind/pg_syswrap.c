// pg_syswrap.c
#include "pub_tool_basics.h"
#include "pub_tool_vki.h"
#include "pub_tool_vkiscnums.h"
#include "pub_tool_hashtable.h"
#include "pub_tool_tooliface.h"
#include "pub_tool_libcbase.h"
#include "pub_tool_libcassert.h"
#include "pub_tool_libcprint.h"
#include "pub_tool_libcproc.h"
#include "pub_tool_libcfile.h"
#include "pub_tool_machine.h"
#include "pub_tool_aspacemgr.h"
#include "pub_tool_threadstate.h"
#include "pub_tool_stacktrace.h"   // for VG_(get_and_pp_StackTrace)
#include "pub_tool_debuginfo.h"	   // VG_(describe_IP), VG_(get_fnname)

#include "valgrind.h"

#include "packergrind.h"
#include "pg_debug.h"
#include "pg_wrappers.h"
#include "pg_translate.h"

extern Bool BG_(clo_trace_begin);

	static 
Bool identifyFdType(ThreadId tid, Int fd, HChar *path) 
{
	Int len = VG_(strlen)(path);

	if( (len > 8) && (VG_(memcmp)(path, "/system/", 8) == 0) ) {
		fds[tid][fd].type = FdSystemLib;
	} else if(VG_(memcmp)(path, "/proc/", 6) == 0) {
		fds[tid][fd].type = FdProcMap;
	} else if( (VG_(memcmp)(path, "/dev/", 5) == 0)
			|| (VG_(memcmp)(path, "/sys/devices/", 13) == 0)) {
		fds[tid][fd].type = FdDevice;
	}	else {
		if( VG_(memcmp)((HChar*)&path[len-3], ".so", 3) == 0) {
			fds[tid][fd].type = FdAppLib;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".apk", 4) == 0) {
			fds[tid][fd].type = FdAppApk;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".jar", 4) == 0) {
			fds[tid][fd].type = FdAppJar;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".dex", 4) == 0) {
			if( len > 40 && VG_(memcmp)(path, "/data/dalvik-cache/system@framework@", 36) == 0) {
				fds[tid][fd].type = FdFrameworkDex;
			} else {
				fds[tid][fd].type = FdAppDex;
			}
		}
	}
#if 0
	if( (len > 15 && (VG_(memcmp)(path, "/system/lib/", 12) == 0))
			|| (len > 22 && (VG_(memcmp)(path, "/system/vendor/lib/", 19) == 0))) {
		fds[tid][fd].type = FdSystemLib; 
	} else if(len > 22 && VG_(memcmp)( path, "/system/framework/", 18) == 0) {
		if(VG_(memcmp)((HChar*)&path[len-4], ".jar", 4) == 0) {
			fds[tid][fd].type = FdFrameworkJar;
		}
	}	else if( len > 40 && VG_(memcmp)(path, "/data/dalvik-cache/system@framework@", 36) == 0) {
		if( VG_(memcmp)((HChar*)&path[len-4], ".dex", 4) == 0) {
			fds[tid][fd].type = FdFrameworkDex;
		}
	} else if( len > 10 && VG_(memcmp)(path, "/data/", 6) == 0 ) {
		if( VG_(memcmp)((HChar*)&path[len-4], ".dex", 4) == 0){
			fds[tid][fd].type = FdAppDex;
		} else if( VG_(memcmp)((HChar*)&path[len-3], ".so", 3) == 0) {
			fds[tid][fd].type = FdAppLib;
		} else if( VG_(memcmp)((HChar*)&path[len-4], ".apk", 4) == 0) {
			fds[tid][fd].type = FdAppApk;
		}
	} else if( (VG_(memcmp)(path, "/dev/", 5) == 0)
			|| (VG_(memcmp)(path, "/sys/devices/", 13) == 0)) {
		fds[tid][fd].type = FdDevice;
	}
#endif
	VG_(strcpy)(fds[tid][fd].name, path);
#ifdef DBG_SYSCALL
	BG_LOGI("IDENTIFY: %d %d %s\n",
			fd, fds[tid][fd].type, path);
#endif
	if(fds[tid][fd].type > 0) {
		return True;
	} else {
		fds[tid][fd].type = FdUnknown;
		return False;
	}
}

static
INLINE Bool isThirdFd( Int tid, Int fd) {
	if (fd <= 0)
		return False;
	if ( (fds[tid][fd].type == FdAppDex)
			/*|| (fds[tid][fd].type == FdAppLib)*/
			|| (fds[tid][fd].type == FdAppJar)
			|| (fds[tid][fd].type == FdProcMap)
			|| (fds[tid][fd].type == FdUnknown) ) {
		return True;
	}
	return False;
}


	static
void resolve_filename(UWord fd, HChar *path, Int max)
{
	HChar src[FD_MAX_PATH];
	Int len = 0;

	// TODO: Cache resolved fds by also catching open()s and close()s
	VG_(sprintf)(src, "/proc/%d/fd/%d", VG_(getpid)(), (int)fd);
	len = VG_(readlink)(src, path, max);

	// Just give emptiness on error.
	if (len == -1) len = 0;
	path[len] = '\0';
}

void BG_(syscall_lseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	// off_t lseek(int fd, off_t offset, int whence);
	Int   fd      = args[0];
	ULong offset  = args[1];
	UInt  whence  = args[2];

	if (fd >= FD_MAX || fd <= 0)
		return;

	Int retval = sr_Res(res);

#ifdef DBG_SYSCALL
	VG_(printf)("syscall _lseek %d %d ", tid, fd);
	VG_(printf)("offset: 0x%x whence: 0x%x ", (UInt)offset, whence);
	VG_(printf)("retval: 0x%x read_offset: 0x%x\n", retval, fds[tid][fd].offset);
#endif
	if( whence == 0/*SEEK_SET*/ )
		fds[tid][fd].offset = 0 + (UInt)offset;
	else if( whence == 1/*SEEK_CUR*/ )
		fds[tid][fd].offset += (UInt)offset;
	if( whence == 2/*SEEK_END*/ )
		fds[tid][fd].offset = retval;
	else {
		VG_(printf)("whence %x\n", whence);
		tl_assert(0);
	}

}

// int  _llseek(int fildes, ulong offset_high, ulong offset_low, loff_t *result,, uint whence);
void BG_(syscall_llseek)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	ULong offset_high  = args[1];
	ULong offset_low   = args[2];
	UInt  result       = args[3];
	UInt  whence       = args[4];
	ULong offset;

	if (fd >= FD_MAX || fd <= 0)
		return;
	Int retval = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("syscall _llseek %d %d ", tid, fd);
	VG_(printf)("0x%x 0x%x 0x%x 0x%x\n", (UInt)offset_high, (UInt)offset_low, result, whence);
	VG_(printf)("0x%x\n", retval);
#endif
	offset = (offset_high<<32) | offset_low;
	if( whence == 0)
		fds[tid][fd].offset = 0 + (UInt)offset;
	else if (whence == 1) 
		fds[tid][fd].offset += (UInt)offset;
	else {
		VG_(printf)("whence %x\n", whence);
		tl_assert(0);
	}
}

// ssize_t  read(int fildes, void *buf, size_t nbyte);
void BG_(syscall_read)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	UInt  curr_offset  = fds[tid][fd].offset;
	Int   curr_len     = sr_Res(res);					// Data length

	BG_(check_fd_access)(tid, fd, FD_READ);
	if (curr_len == 0) return;

	if (fd < 0 || fd >= FD_MAX )
		return;
	fds[tid][fd].offset += curr_len;
	if (BG_(clo_trace_begin) == False)
		return;


	if ( isThirdFd(tid, fd) ) {
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, fds[tid][fd].name, (Addr)data, curr_len);
#endif //M_PERFORMANCE
	} else {
		return;
	}
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) read(%d) offset:0x%x 0x%08x-0x%08x %d %s\n", 
			tid, fd, fds[tid][fd].offset, (Int)data, (Int)data+curr_len-1, curr_len, fds[tid][fd].name);
	if( fds[tid][fd].type == FdProcMap )
		BG_LOGI("Data: %s\n", data);
#endif
}

// ssize_t pread(int fildes, void *buf, size_t nbyte, size_t offset);
void BG_(syscall_pread)(ThreadId tid, UWord* args, UInt nArgs,
		SysRes res) {
	Int   fd           = args[0];
	HChar *data        = (HChar *)args[1];
	UInt  curr_offset  = (Int)args[3];
	Int   curr_len     = sr_Res(res);

	if (curr_len == 0) return;

	if (fd < 0 || fd >= FD_MAX )
		return;

	if (BG_(clo_trace_begin) == False)
		return;
	//if (fds[tid][fd].type == FdAppLib ) {
	if ( isThirdFd(tid, fd)  && curr_len > 0) {
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, fds[tid][fd].name, (Addr)data, curr_len);
#endif //M_PERFORMANCE
	} else {
		return;
	}
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) pread(%d) 0x%x %d\n", 
			tid, fd, (Int)data, curr_len);
#endif
}

// ssize_t readv(int fd, const struct iovec *iov, int iovcnt);
void BG_(syscall_readv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int	re			= sr_Res(res);
	if (BG_(clo_trace_begin) == False)
		return;
	if ( isThirdFd(tid, fd) && re > 0 ) {
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, fds[tid][fd].name, (Addr)iov->iov_base, iov->iov_len);
#endif // M_PERFORMANCE
	} else {
		return;
	}
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) readv(%d) 0x%x %d\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t preadv(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void BG_(syscall_preadv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int   offset  = args[3];
	int		re			= sr_Res(res);
	if (BG_(clo_trace_begin) == False)
		return;
	if ( isThirdFd(tid, fd) && re > 0) {
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, fds[tid][fd].name, (Addr)iov->iov_base, iov->iov_len);
#endif// M_PERFORMANCE
	} else {
		return;
	}
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) preadv(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t writev(int fd, const struct iovec *iov, int iovcnt);
void BG_(syscall_writev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	Int	re			= sr_Res(res);
	if (BG_(clo_trace_begin) == False || re < 0)
		return;
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) writev(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, (Int)iov->iov_base, iov->iov_len);
#endif
}
// ssize_t pwritev(int fd, const struct iovec *iov, int iovcnt, off_t offset);
void BG_(syscall_pwritev)(ThreadId tid, UWord* args, UInt nArgs, SysRes res)
{
	Int fd					= args[0];
	struct iovec *iov = (struct iovec*)args[1];
	Int iovcnt			= args[2];
	int		  offset  = args[3];
	int			re			= sr_Res(res);
	if (BG_(clo_trace_begin) == False || re < 0)
		return;
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) pwritev(%d) offset=0x%x 0x%x %d\n", 
			tid, fd, offset, (Int)iov->iov_base, iov->iov_len);
#endif
}
// void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
void BG_(syscall_mmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int begin_addr = sr_Res(res);
	Int size  = (Int)args[1];
	Int prot = (Int)args[2];
	Int flags = (Int)args[3];
	Int  fd = (Int)args[4];
	UInt offset = (Int)args[5];
	if( begin_addr <= 0 || prot == PROT_NONE )
		return;
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) mmap(%d) off_0x%08x -> 0x%08x-0x%08x %d %c%c%c 0x%x\n", 
			tid, fd, offset, begin_addr, begin_addr+size, size, 
			(prot & PROT_READ) ? 'r' : '-',
			(prot & PROT_WRITE) ? 'w' : '-',
			(prot & PROT_EXEC) ? 'x' : '-',
			flags);
#endif
	if ( isThirdFd(tid, fd) ) {
		if(fds[tid][fd].type == FdAppDex) {
			BG_LOGI("Third party app's dex(%d) file is mmaped 0x%08x-0x%08x\n", 
					fd, begin_addr, begin_addr+size-1);
			//DexMemParse((UChar*)begin_addr, size);
		}
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, fds[tid][fd].name, begin_addr, size);
#endif // M_PERFORMANCE
		if(prot & PROT_EXEC)/* Executable */
			addTraceMemMap(begin_addr, size, prot, fds[tid][fd].name);
	}
	if (BG_(clo_trace_begin) == False)
		return;
	if(prot & PROT_EXEC) { /* Executable */
		if(fd <= 0) {
			addTraceMemMap(begin_addr, size, prot, "anonymous.memory.map");
		}
	}
#ifndef ONLY_DUMP
	if(fd <= 0) {
#ifndef M_PERFORMANCE
		// addFilterList(&dlibl, "/anonymously/memory/segment", begin_addr, size);
#endif // M_PERFORMANCE
	}
#endif
}

// int mprotect(void *addr, size_t len, int prot);
void BG_(syscall_mprotect) ( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	Int  prot = (Int)args[2];
	Int  re  = sr_Res(res);
	if (BG_(clo_trace_begin) == False)
		return;
	if( prot == PROT_NONE )
		return;
#ifdef DBG_SYSCALL
	/*if( re >= 0)
		BG_LOGI("SYSCALL(%d) mprotect() 0x%08x-0x%08x %c%c%c\n",
		tid, begin_addr, begin_addr+size,
		(prot & PROT_READ) ? 'r' : '-',
		(prot & PROT_WRITE) ? 'w' : '-',
		(prot & PROT_EXEC) ? 'x' : '-');*/
#endif
	//return;
	if(prot & PROT_EXEC) { /* Executable */
		addTraceMemMap(begin_addr, size, prot, "mprotect.to.executable");
	} else {
		delTraceMemMap(begin_addr, size);
	}
}

// int msync(void *addr, size_t length, int flags);
void BG_(syscall_msync)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  length		  = (Int)args[1];
	Int	 flags			= (Int)args[2];
	Int  re				= sr_Res(res);
#ifdef DBG_SYSCALL
	if(re == 0) {
		BG_LOGI("SYSCALL(%d) msync() 0x%08x-0x%08x %d\n",
				tid, begin_addr, begin_addr+length, flags);
	}
#endif
}

// int munmap(void *addr, size_t len); 
void BG_(syscall_munmap)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Addr begin_addr = (Addr)args[0];
	Int  size = (Int)args[1];
	if (BG_(clo_trace_begin) == False)
		return;
	if( begin_addr > 0) {
#ifdef DBG_SYSCALL
		BG_LOGI("SYSCALL(%d) munmap() 0x%08x-0x%08x\n", 
				tid, begin_addr, begin_addr+size);
#endif
		//delFilterList(&dml, "munmap", begin_addr, size);
		//delFilterList(&dlibl, "munmap", begin_addr, size);
		delTraceMemMap(begin_addr, size);
	}
}

// int ptrace(int request, pid_t pid, caddr_t addr, int data); 
void BG_(syscall_ptrace)( ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int request = (Int)args[0];
	Int pid = (Int)args[1];
	Int data = (Int)args[3];
	BG_LOGI("SYSCALL(%d) ptrace() req=0x%x pid=%d data=%d\n", 
			tid, request, pid, data);
#ifdef DBG_SYSCALL
#endif
}

//  int open (const char *filename, int flags[, mode_t mode])
void BG_(syscall_open)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	HChar fdpath[FD_MAX_PATH];
	Int fd = sr_Res(res);
	if (fd > -1 && fd < FD_MAX) {
		resolve_filename(fd, fdpath, FD_MAX_PATH-1);
		identifyFdType(tid, fd, fdpath);
		fds[tid][fd].offset = 0;
#ifdef DBG_SYSCALL
		if(fd > 0)
			BG_LOGI("SYSCALL(%d) open(%d) 0x%08x(%s) flag=0x%08x\n", tid, fd, fdpath, (HChar*)fdpath, args[1]);
#endif
	}
}

void BG_(syscall_close)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	//   int close (int filedes)
	Int fd = args[0];
	if (fd > -1 && fd < FD_MAX)
	{
		if( fds[tid][fd].type > 0) {
			fds[tid][fd].type = 0;
			fds[tid][fd].offset = 0;
		}
	}
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) close(%d) %s\n", tid, fd, fds[tid][fd].name);
#endif
}

void BG_(syscall_write)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t write(int fd, const void *buf, size_t nbytes);
	Int fd = args[0];
	HChar *data        = (HChar *)args[1];		// Memery buffer
	Int   curr_len     = sr_Res(res);					// Data length

	BG_(check_fd_access)(tid, fd, FD_WRITE);
#ifdef DBG_SYSCALL
	BG_LOGI("SYSCALL(%d) write(%d) 0x%x %d\n", 
			tid, fd, (Int)data, curr_len);
#endif
}

void BG_(get_fnname)(ThreadId tid, const HChar** buf) {
	UInt pc = VG_(get_IP)(tid);
	VG_(get_fnname)(pc, buf);
}

void BG_(check_fd_access)(ThreadId tid, UInt fd, Int fd_request) {
}

void BG_(syscall_recv)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recv(int sockfd, void *buf, size_t len, int flags)
	Int msglen  = sr_Res(res);
	Int sk = (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) recv(%d)  0x%x(%s) %d\n", 
			tid, sk, (Int)data, (HChar*)data, msglen);
#endif
}

void BG_(syscall_recvfrom)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	// ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
	//                 struct sockaddr *src_addr, socklen_t *addrlen)
	// TODO: #include <arpa/inet.h> inet_ntop to pretty print IP address
	Int msglen  = sr_Res(res);
	Int sk = (Int)args[0];
	HChar *data = (HChar *)args[1];
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) recvfrom(%d) 0x%x(%s) %d\n", 
			tid, sk, (Int)data, (HChar*)data, msglen);
#endif
	//VG_(printf)("syscall recvfrom %d 0x%x 0x%02x\n", tid, msglen, data[0]);
}

// int execve(const char *filename, char *const argv[], char *const envp[])
void BG_(syscall_execve)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UChar *cmd = (HChar *)args[0];
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) execv 0x%x(%s)\n", 
			tid, (Int)cmd, (HChar*)cmd);
#endif
}

// int unlink(const char *path)
void BG_(syscall_unlink)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	UChar *path = (HChar *)args[0];
	Int r = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) unlink 0x%x(%s) %s\n", 
			tid, (Int)path, (HChar*)path, r==0 ? "Successfull" : "Failure");
#endif
}

// int setuid(uid_t uid)
void BG_(syscall_setuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int uid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) setuid() uid=%d res=%d\n", 
			tid, uid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void BG_(syscall_setreuid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int ruid = (Int)args[0];
	Int euid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) setreuid() ruid=%d euid=%d res=%d\n", 
			tid, ruid, euid, re);
#endif
}
// int setgid(uid_t uid)
void BG_(syscall_setgid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int gid = (Int)args[0];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) setgid() gid=%d res=%d\n", 
			tid, gid, re);
#endif
}
// int setreuid(uid_t ruid, uid_t euid)
void BG_(syscall_setregid)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int rgid = (Int)args[0];
	Int egid = (Int)args[1];
	Int re = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) setregid() rgid=%d egid=%d res=%d\n", 
			tid, rgid, egid, re);
#endif
}
void BG_(syscall_action)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	Int sigNum = (Int)args[0];
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) sigaction() for sigNo=%d\n", 
			tid, sigNum);
#endif
}
// long clone(unsigned long flags, void *child_stack,
//                  void *ptid, void *ctid,
//                                   struct pt_regs *regs);
void BG_(syscall_clone)(ThreadId tid, UWord* args, UInt nArgs, SysRes res) {
	ULong flag	= (ULong)args[0];
	Addr ptid		= (Int)args[2];
	Addr ctid		= (Int)args[3];
	ULong r   = sr_Res(res);
#ifdef DBG_SYSCALL
	VG_(printf)("SYSCALL(%d) clone flag=0x%lx ptid=0x%08x, ctid=0x%08x, res=0x%lx\n", 
			tid, flag, ptid, ctid, r);
#endif
}
