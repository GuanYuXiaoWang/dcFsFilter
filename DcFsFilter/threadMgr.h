#ifndef THREADMGR_H
#define THREADMGR_H

#include <fltKernel.h>

#define THREAD_TBL_TAG 'BTDT'
#define PROC_TBL_TAG 'BTCP'

#define STACK_BACK_TRACE_ENUM_DRIVER
// #define STACK_BACK_TRACE_RTLWALKFRAMECHAIN
// #define STACK_BACK_TRACE_RTLCAPTURESTACKBACKTRACE
#define CHARACTERISTIC_VALUE_COUNT					1
#define CHARACTERISTIC_VALUE_SIZE					16
#define MAX_FRAME_CAPTURE_NUM						100
#define TMXPFLT_THREAD								{0x48, 0x8b, 0x4f, 0x40, 0xe8, 0x1f, 0xb8, 0x00, 0x00, 0x48, 0x8b, 0xcf, 0xe8, 0xdb, 0xa5, 0x01}

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY						InLoadOrderLinks;
	LIST_ENTRY						InMemoryOrderLinks;
	LIST_ENTRY						InInitializationOrderLinks;
	PVOID							DllBase;
	PVOID							EntryPoint;
	ULONG							SizeOfImage;
	UNICODE_STRING					FullDllName;
	UNICODE_STRING					BaseDllName;
	ULONG							Flags;
	USHORT							LoadCount;
	USHORT							TlsIndex;
	union
	{
		LIST_ENTRY					HashLinks;
		struct
		{
			PVOID					SectionPointer;
			ULONG					CheckSum;
		};
	};
	union
	{
		struct
		{
			ULONG					TimeDateStamp;
		};
		struct
		{
			PVOID					LoadedImports;
		};
	};
	struct _ACTIVATION_CONTEXT *	EntryPointActivationContext;
	PVOID							PatchInformation;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY, *LPLDR_DATA_TABLE_ENTRY;

typedef struct _THREAD_INFO
{
	ULONG		ulTid;
	LIST_ENTRY	List;
} THREAD_INFO, *PTHREAD_INFO, *LPTHREAD_INFO;


BOOLEAN InitThreadMgr(PDRIVER_OBJECT DeviceObject);

BOOLEAN UnInitThreadMgr();

BOOLEAN InitOffset();

BOOLEAN IsIn(__in ULONG ulTid);

BOOLEAN Enum();

VOID GetLock();

VOID FreeLock();

BOOLEAN Insert(__in ULONG ulTid);

BOOLEAN Delete(__in ULONG ulTid);

LPTHREAD_INFO Get(__in ULONG ulTid);

BOOLEAN Clear();

BOOLEAN IsInControlSysNameList(
	__in ULONG		ulTid,
	__in PETHREAD	pEThread
	);

extern PFLT_FILTER gFilterHandle;

#endif