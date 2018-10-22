#ifndef REGMGR_H
#define REGMGR_H

#include <fltKernel.h>

#define KEY_VALUE_LENGTH 32//三种类型最大长度：受控进程名，受控文件类型，过滤掉的文件类型

typedef struct tagREG_KEY_INFO
{
	LIST_ENTRY listEntry;
	WCHAR keyValue[KEY_VALUE_LENGTH];
	USHORT length;
}REG_KEY_INFO, *PREG_KEY_INFO;

extern NPAGED_LOOKASIDE_LIST  g_RegKeyLookasideList;

#ifdef __cplusplus
extern "C" {
#endif

void InitReg();
NTSTATUS InitListByKeyInfo(__in HANDLE KeyHandle,
	__in PUNICODE_STRING ValueName,
	__in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	__inout PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation,
	__in ULONG Length,
	__inout PLIST_ENTRY ListEntry);

NTSTATUS InitDogKeyInfo(__in HANDLE KeyHandle, 
	__in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
	__inout PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation,
	__in ULONG Length);

void UnInitReg();

NTSTATUS FilterDeleteList(__in PLIST_ENTRY pListEntry);
BOOLEAN  IsControlProcess(__in PUCHAR pProcessName);
BOOLEAN IsControlProcessEx(__in PWCHAR pProcessName);
BOOLEAN IsControlFileType(__in PWCHAR pFileExt, __in USHORT Length);
BOOLEAN IsFilterFileType(__in PWCHAR pFileExt, __in USHORT Length);
BOOLEAN IsControlSys(__in PWCHAR pFileExt, __in USHORT Length);

#ifdef __cplusplus
}
#endif
#endif