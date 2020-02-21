#ifndef _BG_DEBUG_H
#define _BG_DEBUG_H

/*----------------------------------------------------*/
/*----- Debug output helpers for client wrapper  -----*/
/*----------------------------------------------------*/
#define BG_DEBUG		1
#define DBG_MEM			1
#define DBG_SYSCALL	1

#define INS_LOAD		1
#define INS_STORE		1

//#define DBG_TAINT_SET 1
#define DBG_OAT_PARSE		0

#define DBG_ART_METHOD

#define DBG_INSTRUMENT	1
#define DBT_TAINT_INFO	1

#define DBG_CURRENT_LINE	VG_(printf)("[L][%-12s:%-4d] [%-24s]\n", __FILE__, __LINE__, __func__)

#ifdef	DEBUG_CLIENT_REQUEST
#define DBG_REQUEST_INFO(fmt, x...)	\
	do {															\
		VG_(printf)(fmt, ##x);					\
	} while(0)
#else
#define DBG_REQUEST_INFO(fmt, x...)	\
	do { } while(0)
#endif // DEBUG_CLIENT_REQUEST


#define MON_STR_OPERATIONS	0
/*-------------------- End ---------------------------*/

/*----------------------------------------------------*/
/*----- Debug output helpers for force execution -----*/
/*----------------------------------------------------*/
UChar pformat[256];
#define BG_IP_INFO(fmt, x...)	\
do { \
	UInt  lr = VG_(get_LR)( tid ); \
		const HChar *fnname = VG_(describe_IP) ( lr, NULL ); \
		VG_(snprintf)(pformat, sizeof(pformat), \
				"%s | %s", fnname, fmt); \
		VG_(printf)(pformat, ##x); \
} while(0);

#ifdef BG_DEBUG
#define	BG_LOGI(fmt, x...) \
	do {\
		VG_(printf)(fmt, ##x);	\
	} while(0)

#define	BG_LOGE(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[E][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)

#define	BG_EXE_LOGI(fmt, x...) \
	do {\
		VG_(snprintf)(pformat, sizeof(pformat), \
				"[F][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat, ##x);	\
	} while(0)

#define BG_ASSERT(aaa) \
	tl_assert(aaa)

#else // BG_DEBUG

#define BG_LOGI(fmt, x...) ;
#define BG_LOGE(fmt, x...) ;
#define BG_ASSERT(aaa) \
	tl_assert(aaa)
#define	BG_EXE_LOGI(fmt, x...) ;

#endif // BG_DEBUG

#ifdef DBG_MEM
UChar pformat1[256];
#define DBG_MEM_INFO(fmt, x...) \
	do {\
		VG_(snprintf)(pformat1, sizeof(pformat1), \
				"[I][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat1, ##x);	\
	} while(0)
#else
#define DBG_MEM_INFO(fmt, x...) ;
#endif // DBG_MEM

#ifdef DBG_SYSCALL
UChar pformat2[256];
#define DBG_CALL_INFO(fmt, x...) \
	do {\
		VG_(snprintf)(pformat2, sizeof(pformat2), \
				"[I][%-12s:%-4d] [%-24s] %s",			\
				__FILE__, __LINE__, __func__, fmt);	\
		VG_(printf)(pformat2, ##x);	\
	} while(0)
#else
#define DBG_CALL_INFO(fmt, x...) ;
#endif // DBG_SYSCALL

UChar pformat4[256];
#define TNT_LOGI(fmt, x...) \
     VG_(snprintf)(pformat4, sizeof(pformat4), "\t%s", fmt); \
     VG_(printf)(pformat4, ##x);


/*------------------------  End  --------------------------*/
#endif // _BG_DEBUG_H
