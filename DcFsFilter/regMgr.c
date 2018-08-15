#include "regMgr.h"
#include <wdm.h>


#define DRIVER_LOAD_REG_PATH L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\services\\DcFsFilter"
#define CONTROL_PROCESS_NAME L"ControlProcessName"
#define CONTROL_FILE_TYPE L"ControlFileType"
#define FILTER_FILE_TYPE L"FilterFileType"

NPAGED_LOOKASIDE_LIST  g_RegKeyLookasideList;

LIST_ENTRY   g_ControlProcessList;
LIST_ENTRY   g_ControlFileTypeList;
LIST_ENTRY	g_FilterFileTypeList;

ERESOURCE g_ControlProcessResource;
ERESOURCE g_ControlFileTypeResource;
ERESOURCE g_FilterFileTypeResource;

void InitReg()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ob = {0};
	HANDLE hKey = NULL;
	UNICODE_STRING strRegPath;
	UNICODE_STRING strCPN;
	UNICODE_STRING strCFT;
	UNICODE_STRING strFFT;
	USHORT length = sizeof(KEY_VALUE_PARTIAL_INFORMATION) + 1024;
	PKEY_VALUE_PARTIAL_INFORMATION pKeyInfo = NULL;

	ExInitializeNPagedLookasideList(&g_RegKeyLookasideList, NULL, NULL, 0, sizeof(REG_KEY_INFO), 'rkll', 0);
	InitializeListHead(&g_ControlProcessList);
	InitializeListHead(&g_ControlFileTypeList);
	InitializeListHead(&g_FilterFileTypeList);

	ExInitializeResourceLite(&g_ControlProcessResource);
	ExInitializeResourceLite(&g_ControlFileTypeResource);
	ExInitializeResourceLite(&g_FilterFileTypeResource);

	//读注册表
	__try
	{
		RtlInitUnicodeString(&strRegPath, DRIVER_LOAD_REG_PATH);
		RtlInitUnicodeString(&strCPN, CONTROL_PROCESS_NAME);
		RtlInitUnicodeString(&strCFT, CONTROL_FILE_TYPE);
		RtlInitUnicodeString(&strFFT, FILTER_FILE_TYPE);

		pKeyInfo = ExAllocatePoolWithTag(NonPagedPool, length, 'keyv');
		if (NULL == pKeyInfo)
		{
			__leave;
		}

		InitializeObjectAttributes(&ob, &strRegPath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = ZwOpenKey(&hKey, KEY_ALL_ACCESS, &ob);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		RtlZeroMemory(pKeyInfo, length);
		ntStatus = InitListByKeyInfo(hKey, &strCPN, KeyValuePartialInformation, pKeyInfo, length, &g_ControlProcessList);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("init list(%S) info failed(0x%x), line=%d...\n", strCPN.Buffer, ntStatus, __LINE__);
		}
		RtlZeroMemory(pKeyInfo, length);
		ntStatus = InitListByKeyInfo(hKey, &strCFT, KeyValuePartialInformation, pKeyInfo, length, &g_ControlFileTypeList);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("init list(%S) info failed(0x%x), line=%d...\n", strCFT.Buffer, ntStatus, __LINE__);
		}
		RtlZeroMemory(pKeyInfo, length);
		ntStatus = InitListByKeyInfo(hKey, &strFFT, KeyValuePartialInformation, pKeyInfo, length, &g_FilterFileTypeList);
		if (!NT_SUCCESS(ntStatus))
		{
			DbgPrint("init list(%S) info failed(0x%x), line=%d...\n", strFFT.Buffer, ntStatus, __LINE__);
		}
	}
	__finally
	{
		if (NULL != pKeyInfo)
		{
			ExFreePoolWithTag(pKeyInfo, 'keyv');
		}
		if (NULL != hKey)
		{
			ZwClose(hKey);
		}
	}
}

void UnInitReg()
{
	FilterDeleteList(&g_ControlProcessList);
	FilterDeleteList(&g_ControlFileTypeList);
	FilterDeleteList(&g_FilterFileTypeList);
	ExDeleteNPagedLookasideList(&g_RegKeyLookasideList);
	ExDeleteResourceLite(&g_ControlProcessResource);
	ExDeleteResourceLite(&g_ControlFileTypeResource);
	ExDeleteResourceLite(&g_FilterFileTypeResource);
}

NTSTATUS InitListByKeyInfo(__in HANDLE KeyHandle, 
	__in PUNICODE_STRING ValueName, 
	__in KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass, 
	__inout PKEY_VALUE_PARTIAL_INFORMATION KeyValueInformation,
	__in ULONG Length,
	__inout PLIST_ENTRY ListEntry)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	USHORT nIndex = 0;
	USHORT nFind = 0;
	PREG_KEY_INFO pItem = NULL;
	WCHAR * pTmp = NULL;
	ULONG ulRet = 0;

	__try
	{
		ntStatus = ZwQueryValueKey(KeyHandle, ValueName, KeyValueInformationClass, KeyValueInformation, Length, &ulRet);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		pTmp = (WCHAR*)KeyValueInformation->Data;
		if (KeyValueInformation->DataLength > sizeof(WCHAR))
		{
			while (nIndex < KeyValueInformation->DataLength / sizeof(WCHAR))//1.exe|2.exe|....最后一个进程名后没有|
			{
				if (L'|' == pTmp[nIndex] && nIndex > 0)
				{
					pItem = ExAllocateFromNPagedLookasideList(&g_RegKeyLookasideList);
					if (NULL == pItem)
					{
						break;
					}
					RtlZeroMemory(pItem, sizeof(REG_KEY_INFO));
					pItem->length = (nIndex - (nFind > 0 ? nFind + 1 : nFind)) * sizeof(WCHAR);
					if (pItem->length <= sizeof(WCHAR))//空的情况,像||这样
					{
						ExFreeToNPagedLookasideList(&g_RegKeyLookasideList, pItem);
						continue;
					}
					RtlCopyMemory(pItem->keyValue, pTmp + (nFind > 0 ? nFind + 1 : 0), pItem->length);
					InsertTailList(ListEntry, &pItem->listEntry);
					nFind = nIndex;
				}

				nIndex++;
			}
			//最后一个进程或只有一个进程的情况
			if (0 == nFind)
			{
				if (nIndex > 1)
				{
					pItem = ExAllocateFromNPagedLookasideList(&g_RegKeyLookasideList);
					if (NULL != pItem)
					{
						RtlZeroMemory(pItem, sizeof(REG_KEY_INFO));
						pItem->length = nIndex *sizeof(WCHAR);
						RtlCopyMemory(pItem->keyValue, pTmp, pItem->length);
						InsertTailList(ListEntry, &pItem->listEntry);
					}
				}
			}
			else
			{
				pItem = ExAllocateFromNPagedLookasideList(&g_RegKeyLookasideList);
				if (NULL != pItem)
				{
					RtlZeroMemory(pItem, sizeof(REG_KEY_INFO));
					pItem->length = (nIndex - nFind - 1) *sizeof(WCHAR);
					RtlCopyMemory(pItem->keyValue, pTmp + nFind + 1, pItem->length);
					InsertTailList(ListEntry, &pItem->listEntry);
				}
			}
		}
	}
	__finally
	{

	}
	return ntStatus;
}

NTSTATUS FilterDeleteList(__in PLIST_ENTRY pListEntry)
{
	NTSTATUS status = STATUS_SUCCESS;
	PREG_KEY_INFO pItem = NULL;
	LIST_ENTRY * listEntry = NULL;

	while (!IsListEmpty(pListEntry))
	{
		listEntry = RemoveHeadList(pListEntry);
		pItem = CONTAINING_RECORD(listEntry, REG_KEY_INFO, listEntry);
		if (pItem)
		{
			ExFreeToNPagedLookasideList(&g_RegKeyLookasideList, pItem);
			pItem = NULL;
		}
	}

	return status;
}

BOOLEAN IsControlProcess(__in PUCHAR pProcessName)
{
	BOOLEAN bFind = FALSE;
	LIST_ENTRY* listEntry = NULL;
	PREG_KEY_INFO pItem = NULL;
	BOOLEAN bAcquireResource = FALSE;
	UNICODE_STRING strControlProcess;
	ANSI_STRING strProcess;
	if (IsListEmpty(&g_ControlProcessList))
	{
		return FALSE;
	}

	RtlInitAnsiString(&strProcess, pProcessName);
	RtlAnsiStringToUnicodeString(&strControlProcess, &strProcess, TRUE);
	bAcquireResource = ExAcquireResourceShared(&g_ControlProcessResource, TRUE);
	for (listEntry = g_ControlProcessList.Flink; listEntry != &g_ControlProcessList; listEntry = listEntry->Flink)
	{
		pItem = CONTAINING_RECORD(listEntry, REG_KEY_INFO, listEntry);
		if (pItem && 0 == wcsicmp(strControlProcess.Buffer, pItem->keyValue))
		{
			bFind = TRUE;
			break;
		}
	}
	if (bAcquireResource)
	{
		ExReleaseResourceLite(&g_ControlProcessResource);
	}
	RtlFreeUnicodeString(&strControlProcess);
	return bFind;
}

BOOLEAN IsControlFileType(__in PWCHAR pFileExt, __in USHORT Length)
{
	BOOLEAN bFind = FALSE;
	LIST_ENTRY* listEntry = NULL;
	PREG_KEY_INFO pItem = NULL;
	UNICODE_STRING strControlFileType;
	BOOLEAN bAcquireResource = FALSE;
	if (IsListEmpty(&g_ControlFileTypeList))
	{
		return TRUE;
	}
	RtlInitUnicodeString(&strControlFileType, pFileExt);

	bAcquireResource = ExAcquireResourceShared(&g_ControlFileTypeResource, TRUE);
	for (listEntry = g_ControlFileTypeList.Flink; listEntry != &g_ControlFileTypeList; listEntry = listEntry->Flink)
	{
		pItem = CONTAINING_RECORD(listEntry, REG_KEY_INFO, listEntry);
		if (pItem && 0 == wcsicmp(strControlFileType.Buffer, pItem->keyValue))
		{
			bFind = TRUE;
			break;
		}
	}
	if (bAcquireResource)
	{
		ExReleaseResourceLite(&g_ControlFileTypeResource);
	}
	return bFind;
}

BOOLEAN IsFilterFileType(__in PWCHAR pFileExt, __in USHORT Length)
{
	BOOLEAN bFind = FALSE;
	LIST_ENTRY* listEntry = NULL;
	PREG_KEY_INFO pItem = NULL;
	UNICODE_STRING strFilterFileType;
	BOOLEAN bAcquireResource = FALSE;
	if (IsListEmpty(&g_FilterFileTypeList))
	{
		return FALSE;
	}
	RtlInitUnicodeString(&strFilterFileType, pFileExt);

	bAcquireResource = ExAcquireResourceShared(&g_FilterFileTypeResource, TRUE);
	for (listEntry = g_FilterFileTypeList.Flink; listEntry != &g_FilterFileTypeList; listEntry = listEntry->Flink)
	{
		pItem = CONTAINING_RECORD(listEntry, REG_KEY_INFO, listEntry);
		if (pItem && 0 == wcsicmp(strFilterFileType.Buffer, pItem->keyValue))
		{
			bFind = TRUE;
			break;
		}
	}
	if (bAcquireResource)
	{
		ExReleaseResourceLite(&g_FilterFileTypeResource);
	}

	return bFind;
}
