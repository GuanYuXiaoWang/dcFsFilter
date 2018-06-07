#include "volumeContext.h"
#include "defaultStruct.h"

/*参考：维基ntfs
记录每个设备的元文件：这些都是系统重要的数据（过滤时要排除系统文件，非$ROOT外）
1.$MFT
2.$MFTMirr
3.$LogFile
4.$Volume
5.$AttrDe
6.$ROOT:记录卷目录所有文件和文件索引
7.$Bitmap
8.$Boot
9.$BadClus
10.$Secure
11.$UpCase
12.$Extended*和$Extend*（$Extended metadata directory、$Extend\$Reparse、$Extend\UsnJrnl、$Extend\Quota、$Extend\ObjId）
*/
VOID initMetadataFileList(WSTRING * pString, int nCount)
{
	WCHAR * pName = NULL;
	ULONG length = 0;
	int i = 0;
	WCHAR * pwsz[METADATA_FILE_COUNT] = {L"\\$Mft", L"\\$Directory", L"\\$LogFile", L"$Volume",  L"$AttrDe",
										L"\\$EXTEND\\$", L"$Bitmap", L"$Boot", L"$BadClus", L"$Secure",
										L"$UpCase", L"$Extend"};
	for (i; i < nCount; i++)
	{
		pString[i].ulLength = (wcslen(pwsz[i]) + 1) * sizeof(WCHAR);
		pString[i].pwszName = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, pString[i].ulLength, VOLUME_CONTEXT_POOL_TAG);
		if (NULL == pString[i].pwszName)
		{
			DbgPrint("ExAllocatePoolWithTag failed, line=%d, file=%s\n", __LINE__, __FILE__);
			continue;
		}
		memset(pString[i].pwszName, 0, pString[i].ulLength);
		memcpy(pString[i].pwszName, pwsz[i], wcslen(pwsz[i]) * sizeof(WCHAR));
	}
}

VOID unInitMetadataFileList(WSTRING * pString, int nCount)
{
	int i = 0;
	if (NULL == pString)
	{
		return;
	}
	for (i; i < nCount; i++)
	{
		if (NULL != pString[i].pwszName)
		{
			ExFreePoolWithTag(pString[i].pwszName, VOLUME_CONTEXT_POOL_TAG);
			pString[i].pwszName = NULL;
		}
	}
}
NTSTATUS setVolumeContext(ULONG ulSectorSize, PUNICODE_STRING pDevName, PFLT_VOLUME pFltVolume)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOLUMECONTEXT pVolumeContext = NULL;
	
	__try
	{
		if (NULL == pDevName || 0 == ulSectorSize || NULL == pFltVolume)
		{
			__leave;
		}
	
		do 
		{
			status = FltAllocateContext(gFilterHandle, FLT_VOLUME_CONTEXT, sizeof(VOLUMECONTEXT), NonPagedPool, (PFLT_CONTEXT *)&pVolumeContext);
		} while (STATUS_INSUFFICIENT_RESOURCES == status);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		pVolumeContext->ulSectorSize = max(ulSectorSize, MIN_SECTOR_SIZE);
		pVolumeContext->strDeviceName.ulLength = pDevName->Length + 1;
		pVolumeContext->strDeviceName.pwszName = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, pDevName->Length + 1, VOLUME_CONTEXT_POOL_TAG);
		if (NULL == pVolumeContext->strDeviceName.pwszName)
		{
			__leave;
		}
		memset(pVolumeContext->strDeviceName.pwszName, 0, pVolumeContext->strDeviceName.ulLength);
		memcpy(pVolumeContext->strDeviceName.pwszName, pDevName->Buffer, pDevName->Length);
		pVolumeContext->strMetaDataList = (PWSTRING)ExAllocatePoolWithTag(NonPagedPool, sizeof(WSTRING)* METADATA_FILE_COUNT, VOLUME_CONTEXT_POOL_TAG);
		if (NULL == pVolumeContext->strMetaDataList)
		{
			__leave;
		}
		initMetadataFileList(pVolumeContext->strMetaDataList, METADATA_FILE_COUNT);
		status = FltSetVolumeContext(pFltVolume, FLT_SET_CONTEXT_KEEP_IF_EXISTS, pVolumeContext, NULL);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		FltReleaseContext((PFLT_CONTEXT)pVolumeContext);
		status = STATUS_SUCCESS;
		pVolumeContext = NULL;
	}
	__finally
	{
		if (!NT_SUCCESS(status) && pVolumeContext)
		{
			if (pVolumeContext->strMetaDataList)
			{
				unInitMetadataFileList(pVolumeContext->strMetaDataList, METADATA_FILE_COUNT);
			}
			
			if (pVolumeContext->strDeviceName.pwszName)
			{
				ExFreePoolWithTag(pVolumeContext->strDeviceName.pwszName, VOLUME_CONTEXT_POOL_TAG);
			}
			FltReleaseContext((PFLT_CONTEXT)pVolumeContext);
			pVolumeContext = NULL;
		}
	}

	return status;
}

VOID volumeCleanup(__in PFLT_CONTEXT Context, __in FLT_CONTEXT_TYPE ContextType)
{
	PVOLUMECONTEXT pVolumeContext = (PVOLUMECONTEXT)Context;
	UNREFERENCED_PARAMETER(ContextType);

	PAGED_CODE();

	__try
	{
		if (pVolumeContext)
		{
			unInitMetadataFileList(pVolumeContext->strMetaDataList, METADATA_FILE_COUNT);
			if (pVolumeContext->strDeviceName.pwszName)
			{
				ExFreePoolWithTag(pVolumeContext->strDeviceName.pwszName, VOLUME_CONTEXT_POOL_TAG);
			}
			FltDeleteContext(pVolumeContext);
		}
	}
	__finally
	{

	}
}
