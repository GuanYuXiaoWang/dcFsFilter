#include "fsData.h"
#include "fatstruc.h"
#include "defaultStruct.h"
#include <ntifs.h>
#include <wdm.h>
#include "fsCreate.h"
#include "fsInformation.h"
#include "fsFlush.h"
#include "fsRead.h"
#include "fsWrite.h"
#include "fsCleanup.h"
#include "fsClose.h"
#include "Crypto.h"
#include "head.h"
#include "EncFile.h"
#include "regMgr.h"
#include "fsControl.h"
#include "threadMgr.h"
#include <ntstrsafe.h>

NPAGED_LOOKASIDE_LIST  g_IrpContextLookasideList;
NPAGED_LOOKASIDE_LIST  g_FcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_EResourceLookasideList;
NPAGED_LOOKASIDE_LIST  g_CcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_IoContextLookasideList;
DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS = {0};
NPAGED_LOOKASIDE_LIST g_NTFSFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_FastMutexInFCBLookasideList;

BOOLEAN g_bUnloading = FALSE;
BOOLEAN g_bAllModuleInitOk = FALSE;
BOOLEAN g_bSafeDataReady = FALSE;
PAGED_LOOKASIDE_LIST g_EncryptFileListLookasideList;
ERESOURCE g_FcbResource;
LIST_ENTRY g_FcbEncryptFileList;

ULONG g_OsMajorVersion = 0;
ULONG g_OsMinorVersion = 0;
ULONG g_SectorSize = 512;

CACHE_MANAGER_CALLBACKS g_CacheManagerCallbacks = {0};

LARGE_INTEGER  Li0 = { 0, 0 };
LARGE_INTEGER  Li1 = { 1, 0 };

KSPIN_LOCK g_GeneralSpinLock;
EXPLORER_PROCESS_FILE g_LastProcessInfo = { 0 };

#define SURPORT_NAME_LENGTH 64

NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

BOOLEAN IsFilterProcess(IN PFLT_CALLBACK_DATA Data, IN PNTSTATUS pStatus, IN PULONG pProcType)
{
	PFLT_FILE_NAME_INFORMATION FileInfo = NULL;
	HANDLE ProcessId = NULL;
	BOOLEAN bFilter = FALSE;
	WCHAR szExName[32] = { 0 };
	USHORT length = 0;
	WCHAR szProcessName[MAX_PATH] = { 0 };
	UNICODE_STRING strProcessName;
	

	UNREFERENCED_PARAMETER(pProcType);

	if (!CheckEnv(MINIFILTER_ENV_TYPE_SAFE_DATA))
	{
		return FALSE;
	}
	//先判断文件是否为加密文件，再判断访问进程是否为受控进程(可以不区分先后)
	__try
	{
		*pStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileInfo);
		if (!NT_SUCCESS(*pStatus))
		{
			__leave;
		}
		ProcessId = PsGetCurrentProcessId();
		if (NULL == ProcessId)
		{
			*pStatus = STATUS_UNSUCCESSFUL;
			__leave;
		}
		/*
		RtlInitUnicodeString(&strProcessName, szProcessName);
		strProcessName.Length = (MAX_PATH - 1)* sizeof(WCHAR);
		strProcessName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		*pStatus = FsGetProcessName(ProcessId, &strProcessName);
		if (!NT_SUCCESS(*pStatus))
		{
			__leave;
		}
		if (!IsControlProcessEx(strProcessName.Buffer))
		{
			__leave;
		}
		*/
		if (0 == ProcessId)
		{
			__leave;
		}
		if (!IsControlProcessByProcessId(ProcessId, pProcType))
		{
			__leave;
		}
		
		//判断文件后缀名
		if (!FsGetFileExtFromFileName(&FileInfo->Name, szExName, &length))
		{
			__leave;
		}
		//排除特定类型的文件，如dll/lib/exe/等（读配置文件或注册表）
		if (IsFilterFileType(szExName, length))
		{
			__leave;
		}

		//过滤包含特定类型的文件??
		if (!IsControlFileType(szExName, length))
		{
			__leave;
		}
		KdPrint(("PID=%d,FileName=%S,Extension=%S....\n", ProcessId, FileInfo->Name.Buffer ? FileInfo->Name.Buffer : L"none", FileInfo->Extension.Buffer ? FileInfo->Extension.Buffer : L"none"));
		bFilter = TRUE;
		*pStatus = STATUS_SUCCESS;
	}
	__finally
	{
		if (FileInfo != NULL)
		{
			FltReleaseFileNameInformation(FileInfo);
		}
	}

	return bFilter;
}

BOOLEAN IsControlProcessByProcessId(__in HANDLE ProcessID, __inout ULONG * ProcessType)
{
	PEPROCESS Process = NULL;
	PUCHAR ProcessName = NULL;
	BOOLEAN bControl = FALSE;
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;

	if (4 == ProcessID)
	{
#ifndef REAL_ENCRYPTE
 		if (!IsIn(PsGetCurrentThreadId()))
 		{
 			bControl = FALSE;
 		}		
#endif
	}
	else
	{
		ntStatus = PsLookupProcessByProcessId(ProcessID, &Process);
		if (!NT_SUCCESS(ntStatus))
		{
			return FALSE;
		}

		ProcessName = PsGetProcessImageFileName(Process);//ImageFileName有长度限制，最大支持16个字节，EPROCESS反汇编可以看出
		if (!MmIsAddressValid(ProcessName))//Process为0x6e地址时，无法获取进程信息，这个地址是？？
		{
			Process = NULL;
			return FALSE;
		}
		if (ProcessType)
		{
			*ProcessType = (0 == _stricmp(ProcessName, "explorer.exe") ? PROCESS_ACCESS_EXPLORER : 0);
		}
		if (!IsControlProcess(ProcessName))
		{
			return FALSE;
		}
		bControl = TRUE;
	}

	if (Process != NULL)
	{
		ObDereferenceObject(Process);
	}

	return bControl;
}

BOOLEAN IsFltFileLock()
{
	return TRUE;
}
//应用层HOOK explorer的复制、移动等行为，把操作的文件对象发给驱动，这样比较彻底一点
//1.从explorer操作规律看，拷贝或移动进行中的行为都先访问被操作文件，然后操作目标文件（多文件排队处理）
//2.记录最后一次打开的文件，下一次操作的文件根据最后一次操作的文件进行判断是否加密？？会不会存在漏洞？？
BOOLEAN IsNeedEncrypted()
{
	if (NULL == g_LastProcessInfo.Fcb)
	{
		return FALSE;
	}
	return TRUE;
}

VOID FsSetExplorerInfo(__in  PFILE_OBJECT FileObject, __in PDEFFCB Fcb)
{
	g_LastProcessInfo.FileOBject = FileObject;
	g_LastProcessInfo.Fcb = Fcb;
	g_LastProcessInfo.ProcessId = PsGetCurrentProcessId();
}

VOID InitData()
{
	RtlZeroMemory(szVcbPlacer, sizeof(UCHAR)* 300);
	UNICODE_STRING RoutineString = { 0 };
	ExInitializeNPagedLookasideList(&g_IrpContextLookasideList, NULL, NULL, 0, sizeof(DEF_IRP_CONTEXT), 'IRC', 0);
	ExInitializeNPagedLookasideList(&g_IoContextLookasideList, NULL, NULL, 0, sizeof(DEF_IO_CONTEXT), 'IOC', 0);
	ExInitializeNPagedLookasideList(&g_FcbLookasideList, NULL, NULL, 0, sizeof(DEFFCB), 'FCB', 0);
	ExInitializeNPagedLookasideList(&g_CcbLookasideList, NULL, NULL, 0, sizeof(DEF_CCB), 'CCB', 0);
	ExInitializeNPagedLookasideList(&g_EResourceLookasideList, NULL, NULL, 0, sizeof(ERESOURCE), 'Res', 0);
	ExInitializePagedLookasideList(&g_EncryptFileListLookasideList, NULL, NULL, 0, sizeof(ENCRYPT_FILE_FCB), 'efl', 0);
	ExInitializeNPagedLookasideList(&g_NTFSFCBLookasideList, NULL, NULL, 0, sizeof(NTFS_FCB), 'ntfb', 0);
	ExInitializeNPagedLookasideList(&g_FastMutexInFCBLookasideList, NULL, NULL, 0, sizeof(FAST_MUTEX), 'fsmt', 0);
	ExInitializeNPagedLookasideList(&g_Npaged64KBList, NULL, NULL, 0, SIZEOF_64KBList, BUF_64KB_TAG, 0);
	ExInitializeNPagedLookasideList(&g_Npaged4KBList, NULL, NULL, 0, SIZEOF_4KBList, BUF_4KB_TAG, 0);

	g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx = (fltCheckOplockEx)FltGetRoutineAddress("FltCheckOplockEx");
	g_DYNAMIC_FUNCTION_POINTERS.OplockBreakH = (fltOplockBreakH)FltGetRoutineAddress("FltOplockBreakH");
	g_DYNAMIC_FUNCTION_POINTERS.QueryDirectoryFile = (fltQueryDirectoryFile)FltGetRoutineAddress("FltQueryDirectoryFile");
	g_DYNAMIC_FUNCTION_POINTERS.OplockFsctrlEx = (fltOplockFsctrlEx)FltGetRoutineAddress("FltOplockFsctrlEx");
	g_DYNAMIC_FUNCTION_POINTERS.QueryEaFile = (fltQueryEaFile)FltGetRoutineAddress("FltQueryEaFile");
	g_DYNAMIC_FUNCTION_POINTERS.SetEaFile = (fltSetEaFile)FltGetRoutineAddress("FltSetEaFile");
	g_DYNAMIC_FUNCTION_POINTERS.OplockIsSharedRequest = (fltOplockIsSharedRequest)FltGetRoutineAddress("FltOplockIsSharedRequest");

	RtlInitUnicodeString(&RoutineString, L"MmDoesFileHaveUserWritableReferences");
	g_DYNAMIC_FUNCTION_POINTERS.pMmDoesFileHaveUserWritableReferences = (fMmDoesFileHaveUserWritableReferences)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"FsRtlChangeBackingFileObject");
	g_DYNAMIC_FUNCTION_POINTERS.pFsRtlChangeBackingFileObject = (fsRtlChangeBackingFileObject)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"FsRtlCheckLockForOplockRequest");
	g_DYNAMIC_FUNCTION_POINTERS.pFsRtlCheckLockForOplockRequest = (fsRtlCheckLockForOplockRequest)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"RtlGetVersion");
	g_DYNAMIC_FUNCTION_POINTERS.pGetVersion = (fsGetVersion)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"ZwQueryInformationProcess");
	g_DYNAMIC_FUNCTION_POINTERS.QueryInformationProcess = (fsQueryInformationProcess)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"FsRtlAreThereCurrentOrInProgressFileLocks");
	g_DYNAMIC_FUNCTION_POINTERS.RtlAreThereCurrentOrInProgressFileLocks = (fsRtlAreThereCurrentOrInProgressFileLocks)MmGetSystemRoutineAddress(&RoutineString);

	g_CacheManagerCallbacks.AcquireForLazyWrite = &FsAcquireFcbForLazyWrite;
	g_CacheManagerCallbacks.ReleaseFromLazyWrite = &FsReleaseFcbFromLazyWrite;
	g_CacheManagerCallbacks.AcquireForReadAhead = &FsAcquireFcbForReadAhead;
	g_CacheManagerCallbacks.ReleaseFromReadAhead = &FsReleaseFcbFromReadAhead;

	InitializeListHead(&g_FcbEncryptFileList);
	KeInitializeSpinLock(&g_GeneralSpinLock);
	ExInitializeResourceLite(&g_FcbResource);
	InitReg();
}

VOID UnInitData()
{
	ClearFcbList();
	ExDeleteNPagedLookasideList(&g_FcbLookasideList);
	ExDeleteNPagedLookasideList(&g_CcbLookasideList);
	ExDeleteNPagedLookasideList(&g_EResourceLookasideList);
	ExDeleteNPagedLookasideList(&g_IrpContextLookasideList);
	ExDeleteNPagedLookasideList(&g_IoContextLookasideList);
	ExDeleteResourceLite(&g_FcbResource);
	UnInitReg();
}

PERESOURCE FsdAllocateResource()
{
	PERESOURCE Resource = NULL;

	Resource = (PERESOURCE)ExAllocateFromNPagedLookasideList(&g_EResourceLookasideList);

	ExInitializeResourceLite(Resource);

	return Resource;
}

BOOLEAN FsIsIrpTopLevel(IN PFLT_CALLBACK_DATA Data)
{
	if (NULL == IoGetTopLevelIrp())
	{
		IoSetTopLevelIrp((PIRP)Data);
		return TRUE;
	}

	return FALSE;
}

PDEF_IRP_CONTEXT FsCreateIrpContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN bWait)
{
	PDEF_IRP_CONTEXT pIrpContext = NULL;
	PFILE_OBJECT pFileObject = FltObjects->FileObject;

	pIrpContext = ExAllocateFromNPagedLookasideList(&g_IrpContextLookasideList);
	if (NULL != pIrpContext)
	{
		RtlZeroMemory(pIrpContext, sizeof(DEF_IRP_CONTEXT));
		pIrpContext->NodeTypeCode = LAYER_NTC_FCB;
		pIrpContext->NodeByteSize = sizeof(DEF_IRP_CONTEXT);
		pIrpContext->OriginatingData = Data;
		pIrpContext->ResourceThread = ExGetCurrentResourceThread();
		if (bWait)
		{
			SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
		}
		if (FlagOn(pFileObject->Flags, FO_WRITE_THROUGH))
		{
			SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);
		}
		pIrpContext->MajorFunction = Data->Iopb->MajorFunction;
		pIrpContext->MinorFunction = Data->Iopb->MinorFunction;

		RtlCopyMemory(&pIrpContext->FltObjects, FltObjects, FltObjects->Size);
		if ((PFLT_CALLBACK_DATA)IoGetTopLevelIrp() != Data)
		{
			SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL);
		}
		pIrpContext->FileObject = pFileObject;
	}

	return pIrpContext;
}
//延迟写
BOOLEAN FsAcquireFcbForLazyWrite(IN PVOID Fcb, IN BOOLEAN Wait)
{
	//BOOLEAN bAcquireFile = TRUE;
	ULONG uIndex = (ULONG)Fcb & 1;
	DEFFCB * pFcb = (DEFFCB*)Fcb;

	PAGED_CODE();

	if (NULL == Fcb)
	{
		return FALSE;
	}
	if (NULL == pFcb->Header.Resource || !ExAcquireResourceSharedLite(pFcb->Header.Resource, Wait))
	{
		return FALSE;
	}
	pFcb->LazyWriteThread[uIndex] = PsGetCurrentThread();
	if (IoGetTopLevelIrp() == NULL)
	{
		IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
	}
	return TRUE;
}

VOID FsReleaseFcbFromLazyWrite(IN PVOID Fcb)
{
	ULONG uIndex = (ULONG)Fcb & 1;
	DEFFCB * pFcb = (DEFFCB*)Fcb;
	
	PAGED_CODE();

	if (NULL == pFcb)
	{
		return;
	}
	if ((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP == IoGetTopLevelIrp())
	{
		IoSetTopLevelIrp(NULL);
	}
	pFcb->LazyWriteThread[uIndex] = NULL;
	if (pFcb->Header.Resource)
	{
		ExReleaseResourceLite(pFcb->Header.Resource);
	}
}

//预读
BOOLEAN FsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait)
{
	DEFFCB * pFcb = (DEFFCB*)Fcb;
	
	PAGED_CODE();

	if (NULL == pFcb || NULL == pFcb->Header.Resource || !ExAcquireResourceSharedLite(pFcb->Header.Resource, Wait))
	{
		return FALSE;
	}
	if (IoGetTopLevelIrp() == NULL)
	{
		IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
	}

	return TRUE;
}

VOID FsReleaseFcbFromReadAhead(IN PVOID Fcb)
{
	DEFFCB * pFcb = (DEFFCB*)Fcb;

	PAGED_CODE();

	IoSetTopLevelIrp(NULL);

	if (NULL == pFcb)
	{
		return;
	}
	if (pFcb->Header.Resource)
	{
		ExReleaseResourceLite(pFcb->Header.Resource);
	}
}

BOOLEAN IsMyFakeFcb(PFILE_OBJECT FileObject)
{
	DEFFCB * Fcb;
	if (FileObject == NULL || FileObject->FsContext == NULL)
	{
		//no file open
		return FALSE;
	}
	Fcb = FileObject->FsContext;

	if (Fcb->Header.NodeTypeCode == LAYER_NTC_FCB &&
		Fcb->Header.NodeByteSize == sizeof(DEFFCB))
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN IsTopLevelIRP(IN PFLT_CALLBACK_DATA Data)
{
	if (NULL == IoGetTopLevelIrp())
	{
		IoSetTopLevelIrp((PIRP)Data);
		return TRUE;
	}

	return FALSE;
}

BOOLEAN GetVersion()
{
	NTSTATUS status = STATUS_SUCCESS;
	RTL_OSVERSIONINFOW versionInfo = {0};
	if (g_DYNAMIC_FUNCTION_POINTERS.pGetVersion)
	{
		status = g_DYNAMIC_FUNCTION_POINTERS.pGetVersion(&versionInfo);
		g_OsMajorVersion = versionInfo.dwMajorVersion;
		g_OsMinorVersion = versionInfo.dwMinorVersion;
		return NT_SUCCESS(status) ? TRUE : FALSE;
	}

	return PsGetVersion(&g_OsMajorVersion, &g_OsMinorVersion, NULL, NULL);
}

BOOLEAN IsWin7OrLater()
{
	if (0 == g_OsMajorVersion)
	{
		GetVersion();
	}
	if (g_OsMajorVersion >= 6 && g_OsMinorVersion >=1)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN IsVistaOrLater()
{
	if (0 == g_OsMajorVersion)
	{
		GetVersion();
	}
	if (g_OsMajorVersion >= 6)
	{
		return TRUE;
	}
	return FALSE;
}

BOOLEAN InsertFcbList(PDEFFCB *Fcb)
 {
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	BOOLEAN bRet = FALSE;
	__try
	{
		pFileFcb = ExAllocateFromPagedLookasideList(&g_EncryptFileListLookasideList);
		if (NULL == pFileFcb)
		{
			__leave;
		}
		RtlZeroMemory(pFileFcb, sizeof(ENCRYPT_FILE_FCB));
		pFileFcb->Fcb = *Fcb;
		pFileFcb->uType = LAYER_NTC_FCB;
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FcbResource, TRUE);
		bAcquireResource = TRUE;
		InsertTailList(&g_FcbEncryptFileList, &pFileFcb->listEntry);
		bRet = TRUE;
	}
	__finally
	{
		if (bAcquireResource)
		{
			ExReleaseResourceLite(&g_FcbResource);
			FsRtlExitFileSystem();
		}
	}
	return bRet;
}

BOOLEAN RemoveFcbList(WCHAR * pwszFile)
{
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	BOOLEAN bRet = FALSE;
	PLIST_ENTRY pListEntry;
	PENCRYPT_FILE_FCB pContext = NULL;
	
	if (NULL == pwszFile || wcslen(pwszFile) <= 0)
	{
		return TRUE;
	}

	__try
	{
		if (IsListEmpty(&g_FcbEncryptFileList))
		{
			bRet = TRUE;
			__leave;
		}
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FcbResource, TRUE);
		bAcquireResource = TRUE;
		for (pListEntry = g_FcbEncryptFileList.Flink; pListEntry != &g_FcbEncryptFileList; pListEntry = pListEntry->Flink)
		{
			pContext = CONTAINING_RECORD(pListEntry, ENCRYPT_FILE_FCB, listEntry);
			if (pContext && pContext->Fcb && 0 == wcsicmp(pwszFile, pContext->Fcb->wszFile))
			{
				RemoveEntryList(&pContext->listEntry);
				ExFreeToPagedLookasideList(&g_EncryptFileListLookasideList, pContext);
				bRet = TRUE;
				break;
			}
		}
	}
	__finally
	{
		if (bAcquireResource)
		{
			ExReleaseResourceLite(&g_FcbResource);
			FsRtlExitFileSystem();
		}
	}
	return bRet;
}

VOID ClearFcbList()
{
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	PLIST_ENTRY pListEntry;
	PENCRYPT_FILE_FCB pContext = NULL;
	__try
	{
		FsRtlEnterFileSystem();
		for (pListEntry = g_FcbEncryptFileList.Flink; pListEntry != &g_FcbEncryptFileList; pListEntry = pListEntry->Flink)
		{
			pContext = CONTAINING_RECORD(pListEntry, ENCRYPT_FILE_FCB, listEntry);
			RemoveEntryList(&pContext->listEntry);
			FsFreeFcb(pContext->Fcb, NULL);
			ExFreeToPagedLookasideList(&g_EncryptFileListLookasideList, pContext);
		}
	}
	__finally
	{
		if (bAcquireResource)
		{
			ExReleaseResourceLite(&g_FcbResource);
			FsRtlExitFileSystem();
		}
	}
}

BOOLEAN FindFcb(IN PFLT_CALLBACK_DATA Data, IN WCHAR * pwszFile, IN PDEFFCB * pFcb)
{
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	BOOLEAN bRet = FALSE;
	PLIST_ENTRY pListEntry;
	PENCRYPT_FILE_FCB pContext = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PFLT_FILE_NAME_INFORMATION NameInfo = NULL;
	WCHAR * pTempFile = NULL;
	ULONG FileLength = 0;

	FsRtlEnterFileSystem();
	__try
	{
		if (NULL == pFcb)
		{
			__leave;
		}

		if (NULL != Data)
		{
			status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &NameInfo);
			if (!NT_SUCCESS(status) && (NULL == pwszFile || wcslen(pwszFile) <= 1))
			{
				__leave;
			}
		}

		if (NULL != NameInfo && NameInfo->Name.Buffer)
		{
			FileLength = NameInfo->Name.Length + sizeof(WCHAR);
		}
		else
		{
			FileLength = (pwszFile != NULL ? (wcslen(pwszFile) + 1) * sizeof(WCHAR) : 0);
		}
		if (0 == FileLength)
		{
			__leave;
		}

		pTempFile = ExAllocatePoolWithTag(NonPagedPool, FileLength, 'fnff');
		if (NULL == pTempFile)
		{
			__leave;
		}
		RtlZeroMemory(pTempFile, FileLength);

		if (NULL != NameInfo && NameInfo->Name.Buffer)
		{
			RtlCopyMemory(pTempFile, NameInfo->Name.Buffer, FileLength - sizeof(WCHAR));
		}
		else
			RtlCopyMemory(pTempFile, pwszFile, FileLength - sizeof(WCHAR));

		bAcquireResource = ExAcquireResourceExclusiveLite(&g_FcbResource, TRUE);
		if (IsListEmpty(&g_FcbEncryptFileList))
		{
			bRet = FALSE;
			__leave;
		}
		for (pListEntry = g_FcbEncryptFileList.Flink; pListEntry != &g_FcbEncryptFileList; pListEntry = pListEntry->Flink)
		{
			pContext = CONTAINING_RECORD(pListEntry, ENCRYPT_FILE_FCB, listEntry);
			if (pContext && pContext->Fcb && 0 == wcsicmp(pTempFile, pContext->Fcb->wszFile))
			{
				*pFcb = pContext->Fcb;
				bRet = TRUE;
				KdPrint(("Find Fcb:%S...\n", pTempFile));
				break;
			}
		}
	}
	__finally
	{
		if (bAcquireResource)
		{
			ExReleaseResourceLite(&g_FcbResource);
		}
		if (NULL != NameInfo)
		{
			FltReleaseFileNameInformation(NameInfo);
		}
		if (NULL != pTempFile)
		{
			ExFreePoolWithTag(pTempFile, 'fnff');
		}
	}
	FsRtlExitFileSystem();
	return bRet;
}

BOOLEAN UpdateFcbList(WCHAR * pwszFile, PDEFFCB * pFcb)
{
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	BOOLEAN bRet = FALSE;
	PENCRYPT_FILE_FCB pContext = NULL;

	if (NULL == pFcb || NULL == pwszFile || wcslen(pwszFile) <= 0)
	{
		return FALSE;
	}

	RemoveFcbList(pwszFile);
	return InsertFcbList(pFcb);
}
//分配独占的权限
BOOLEAN FsAcquireExclusiveFcb(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb)
{
RetryFcbExclusive:
	if (ExAcquireResourceExclusiveLite(Fcb->Header.Resource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)))
	{
		if ((Fcb->OutstandingAsyncWrites != 0) &&
			((IrpContext->MajorFunction != IRP_MJ_WRITE) ||
			!FlagOn(IrpContext->OriginatingData->Iopb->IrpFlags, IRP_NOCACHE) ||
			(ExGetSharedWaiterCount(Fcb->Header.Resource) != 0) ||
			(ExGetExclusiveWaiterCount(Fcb->Header.Resource) != 0)))
		{
			KeWaitForSingleObject(Fcb->OutstandingAsyncEvent,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			FsReleaseFcb(IrpContext, Fcb);

			goto RetryFcbExclusive;
		}
		__try
		{
			FsVerifyOperationIsLegal(IrpContext);
		}
		__finally
		{
			if (AbnormalTermination())
			{
				FsReleaseFcb(IrpContext, Fcb);
			}
		}
		return TRUE;
	}

	return FALSE;
}

BOOLEAN FsAcquireSharedFcbWaitForEx(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb)
{
RetryFcbSharedWaitEx:
	if (ExAcquireSharedWaitForExclusive(Fcb->Header.Resource, FALSE))
	{

		if ((Fcb->OutstandingAsyncWrites != 0) &&
			(IrpContext->MajorFunction != IRP_MJ_WRITE)) {

			KeWaitForSingleObject(Fcb->OutstandingAsyncEvent, //同步
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			FsReleaseFcb(IrpContext, Fcb);

			goto RetryFcbSharedWaitEx;
		}

		__try 
		{
			FsVerifyOperationIsLegal(IrpContext);
		}
		__finally 
		{
			if (AbnormalTermination()) {

				FsReleaseFcb(IrpContext, Fcb);
			}
		}

		return TRUE;
	}

	return FALSE;
}

BOOLEAN FsAcquireSharedFcb(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb)
{
RetryFcbShared:
	if (ExAcquireResourceSharedLite(Fcb->Header.Resource, BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT)))
	{
		if ((Fcb->OutstandingAsyncWrites != 0) &&
			((IrpContext->MajorFunction != IRP_MJ_WRITE) ||
			!FlagOn(IrpContext->OriginatingData->Iopb->IrpFlags, IRP_NOCACHE) ||
			(ExGetSharedWaiterCount(Fcb->Header.Resource) != 0) ||
			(ExGetExclusiveWaiterCount(Fcb->Header.Resource) != 0))) {

			KeWaitForSingleObject(Fcb->OutstandingAsyncEvent,
				Executive,
				KernelMode,
				FALSE,
				(PLARGE_INTEGER)NULL);

			FsReleaseFcb(IrpContext, Fcb);
			goto RetryFcbShared;
		}

		__try 
		{
			FsVerifyOperationIsLegal(IrpContext);
		}
		__finally
		{
			if (AbnormalTermination()) 
			{
				FsReleaseFcb(IrpContext, Fcb);
			}
		}
		return TRUE;
	}

	return FALSE;
}

VOID FsVerifyOperationIsLegal(IN PDEF_IRP_CONTEXT IrpContext)
{
	PFLT_CALLBACK_DATA Data;
	PFILE_OBJECT FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb;

	Data = IrpContext->OriginatingData;
	if (NULL == Data)
	{
		return;
	}

	FileObject = Data->Iopb->TargetFileObject;
	if (NULL == FileObject)
	{
		return;
	}

	if (FlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE))
	{
		Iopb = Data->Iopb;
		if (NULL == Iopb)
		{
			return;
		}
		if (FlagOn(Iopb->IrpFlags, IRP_PAGING_IO) || 
			Iopb->MajorFunction == IRP_MJ_CLOSE ||
			Iopb->MajorFunction == IRP_MJ_SET_INFORMATION ||
			Iopb->MajorFunction == IRP_MJ_QUERY_INFORMATION ||
			(((Iopb->MajorFunction == IRP_MJ_READ) || (Iopb->MajorFunction == IRP_MJ_WRITE)) &&
			FlagOn(Iopb->MajorFunction, IRP_MN_COMPLETE)))
		{
			NOTHING;
		}
		else
		{
			FsRaiseStatus(IrpContext, STATUS_FILE_CLOSED);
		}
	}
}

VOID FsRaiseStatus(PDEF_IRP_CONTEXT IrpContext, NTSTATUS Status)
{
	if (IrpContext != NULL)
	{
		IrpContext->ExceptionStatus = Status;
	}
	ExRaiseStatus(Status);
}

//FltQueueDeferredIoWorkItem 过滤驱动提供的工作队列
VOID FsPrePostIrp(IN PFLT_CALLBACK_DATA Data, IN PVOID Context)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PDEF_IRP_CONTEXT pIrpContext = (PDEF_IRP_CONTEXT)Context;
	if (NULL == Data)
	{
		return;
	}
	if (pIrpContext->pIoContext != NULL && FlagOn(pIrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT))
	{
		ClearFlag(pIrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT);
		pIrpContext->pIoContext = NULL;
	}

	if (ARGUMENT_PRESENT(Data))
	{
		if (IRP_MJ_READ == pIrpContext->MajorFunction || IRP_MJ_WRITE == pIrpContext->MajorFunction)
		{
			//锁定用户buffer
			if (!FlagOn(pIrpContext->MinorFunction, IRP_MN_MDL))
			{
				Status = FltLockUserBuffer(Data);
			}
		}
		else if (IRP_MJ_DIRECTORY_CONTROL == pIrpContext->MajorFunction && IRP_MN_QUERY_DIRECTORY == pIrpContext->MinorFunction)
		{
			Status = FltLockUserBuffer(Data);
		}
		else if (IRP_MJ_QUERY_EA == pIrpContext->MajorFunction || IRP_MJ_SET_EA == pIrpContext->MajorFunction)
		{
			Status = FltLockUserBuffer(Data);
		}

		//原来的时候这里是标记irp pending
		if (!NT_SUCCESS(Status))
		{
			FsRaiseStatus(pIrpContext, Status);
		}
	}
}

VOID FsOplockComplete(IN PFLT_CALLBACK_DATA Data, IN PVOID Context)
{
	PAGED_CODE();

	if (STATUS_SUCCESS == Data->IoStatus.Status)
	{
		FsAddToWorkQueue(Data, Context);
	}
	else
	{
		FsCompleteRequest((PDEF_IRP_CONTEXT *)&Context, &Data, Data->IoStatus.Status, FALSE);
	}
}

VOID FsAddToWorkQueue(IN PFLT_CALLBACK_DATA Data, IN PDEF_IRP_CONTEXT IrpContext)
{
	PFLT_IO_PARAMETER_BLOCK CONST Iopb = IrpContext->OriginatingData->Iopb;
	IrpContext->WorkItem = IoAllocateWorkItem(Iopb->TargetFileObject->DeviceObject);
	IoQueueWorkItem(IrpContext->WorkItem, FsDispatchWorkItem, DelayedWorkQueue, (PVOID)IrpContext);
}

VOID FsCompleteRequest(IN OUT PDEF_IRP_CONTEXT * IrpContext OPTIONAL, IN OUT PFLT_CALLBACK_DATA *Data OPTIONAL, IN NTSTATUS Status, IN BOOLEAN Pending)
{
	if (ARGUMENT_PRESENT(IrpContext) && ARGUMENT_PRESENT(*IrpContext))
	{
		(*IrpContext)->ExceptionStatus = Status;
		if ((*IrpContext)->WorkItem != NULL)
		{
			IoFreeWorkItem((*IrpContext)->WorkItem);
			(*IrpContext)->WorkItem = NULL;
		}
		//延迟的设置可以删除irp上下文了然后删除上下文
		if (FlagOn((*IrpContext)->Flags, IRP_CONTEXT_FLAG_IN_FSP))
		{
			Pending = TRUE;
		}
		if (Pending)
		{
			ClearFlag((*IrpContext)->Flags, IRP_CONTEXT_FLAG_DONT_DELETE);//延迟请求不删除上下文
		}
		if ((*IrpContext)->AllocateMdl != NULL)
		{
			IoFreeMdl((*IrpContext)->AllocateMdl);
			(*IrpContext)->AllocateMdl = NULL;
		}
		FsDeleteIrpContext(IrpContext);
	}
	if (ARGUMENT_PRESENT(Data) && ARGUMENT_PRESENT(*Data))
	{
		if (NT_ERROR(Status) && FlagOn((*Data)->Iopb->IrpFlags, IRP_INPUT_OPERATION))
		{
			(*Data)->IoStatus.Information = 0;
		}
		(*Data)->IoStatus.Status = Status;
		if (Pending)
		{
			FltCompletePendedPreOperation(*Data, FLT_PREOP_COMPLETE, NULL);
		}
	}
}

VOID FsDispatchWorkItem(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context)
{
	PFLT_CALLBACK_DATA Data;
	PDEF_IRP_CONTEXT IrpContext;
	PFLT_IO_PARAMETER_BLOCK Iopb;
	BOOLEAN Retry;
	NTSTATUS ExceptionCode;

	UNREFERENCED_PARAMETER(DeviceObject);

	IrpContext = (PDEF_IRP_CONTEXT)Context;
	Data = IrpContext->OriginatingData;

	if (Data != NULL)
	{
		Iopb = Data->Iopb;
	}
	SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP);

	KdPrint(("DispatchWorkItem,function=0x%x......\n", IrpContext->MajorFunction));

	while (TRUE)
	{
		FsRtlEnterFileSystem();
		Retry = FALSE;

		if (FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL))
		{
			IoSetTopLevelIrp((PIRP)FSRTL_FSP_TOP_LEVEL_IRP);
		}
		else
		{
			IoSetTopLevelIrp((PIRP)Data);
		}
		__try
		{
			IrpContext->ExceptionStatus = 0;
			if (NULL != Data)
			{
				switch (IrpContext->MajorFunction)
				{
				case IRP_MJ_CREATE:
					FsCommonCreate(Data, NULL, IrpContext);
					break;
				case IRP_MJ_CLOSE:
					
					break;
				case IRP_MJ_READ:
					FsCommonRead(Data, NULL, IrpContext);
					break;
				case IRP_MJ_WRITE:
					FsCommonWrite(Data, NULL, IrpContext);
					break;
				case IRP_MJ_QUERY_INFORMATION:
					FsCommonQueryInformation(Data, NULL, IrpContext);
					break;
				case IRP_MJ_SET_INFORMATION:
					FsCommonSetInformation(Data, NULL, IrpContext);
					break;
				case IRP_MJ_SET_EA:

					break;
				case IRP_MJ_QUERY_EA:

					break;
				case IRP_MJ_FLUSH_BUFFERS:
					FsCommonFlush(Data, NULL, IrpContext);
					break;
				case IRP_MJ_CLEANUP:
					FsCommonCleanup(Data, NULL, IrpContext);
					break;
				case IRP_MJ_LOCK_CONTROL:
					FsCommonLockControl(Data, NULL, IrpContext);
					break;
				case IRP_MJ_QUERY_SECURITY:

					break;
				case IRP_MJ_SET_SECURITY:

					break;
				case IRP_MJ_FILE_SYSTEM_CONTROL:
					FsCommonFileSystemControl(Data, NULL, IrpContext);
					break;
				

				default:
					FsCompleteRequest(&IrpContext, &Data, STATUS_INVALID_DEVICE_REQUEST, TRUE);
					break;
				}
			}
			else
			{
				FsCompleteRequest(&IrpContext, NULL, STATUS_SUCCESS, TRUE);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			ExceptionCode = GetExceptionCode();
			if (STATUS_CANT_WAIT == ExceptionCode)
			{
				Retry = TRUE;
			}
			else
			{
				FsRaiseStatus(NULL, ExceptionCode);
			}
		}
		
		IoSetTopLevelIrp(NULL);
		FsRtlExitFileSystem();
		if (!Retry)
		{
			break;
		}
	}
}

NTSTATUS FsPostRequest(IN OUT PFLT_CALLBACK_DATA Data, IN PDEF_IRP_CONTEXT IrpContext)
{
	FsPrePostIrp(Data, IrpContext);
	FsAddToWorkQueue(Data, IrpContext);
	return STATUS_PENDING;
}

VOID FsDeleteIrpContext(IN OUT PDEF_IRP_CONTEXT * IrpContext)
{
	if (!FlagOn((*IrpContext)->Flags, IRP_CONTEXT_STACK_IO_CONTEXT) && 
		(*IrpContext)->pIoContext != NULL)
	{
		ExFreeToNPagedLookasideList(&g_IoContextLookasideList, (*IrpContext)->pIoContext);
		(*IrpContext)->pIoContext = NULL;
	}
	if (*IrpContext != NULL)
	{
		ExFreeToNPagedLookasideList(&g_IrpContextLookasideList, *IrpContext);
		*IrpContext = NULL;
	}
}

PDEF_CCB FsCreateCcb()
{
	PDEF_CCB Ccb = NULL;
	Ccb = (PDEF_CCB)ExAllocateFromNPagedLookasideList(&g_CcbLookasideList);
	if (NULL != Ccb)
	{
		RtlZeroMemory(Ccb, sizeof(DEF_CCB));
		Ccb->FileAccess = FILE_PASS_ACCESS;
	}
	return Ccb;
}

PERESOURCE FsAllocateResource()
{
	PERESOURCE Resource = NULL;

	Resource = (PERESOURCE)ExAllocateFromNPagedLookasideList(&g_EResourceLookasideList);
	if (NULL != Resource)
	{
		ExInitializeResourceLite(Resource);
	}
	return Resource;
}

void FsFreeResource(PERESOURCE Resource)
{
	if (NULL != Resource)
	{
		ExDeleteResourceLite(Resource);
		ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Resource);
		Resource = NULL;
	}
}

VOID NetFileSetCacheProperty(IN PFILE_OBJECT FileObject, IN ACCESS_MASK DesiredAccess)
{
	PDEFFCB Fcb = FileObject->FsContext;
	PDEF_CCB Ccb = FileObject->FsContext2;
	CREATE_ACCESS_TYPE CreateAccess = CREATE_ACCESS_INVALID;

	if (CACHE_DISABLE == Fcb->CacheType)
	{
		return;
	}
	if (FlagOn(DesiredAccess, FILE_READ_DATA) && !FlagOn(DesiredAccess, FILE_WRITE_DATA) ||
		(FlagOn(DesiredAccess, FILE_APPEND_DATA)))
	{
		CreateAccess = CREATE_ACCESS_READ;
		if (CcIsFileCached(FileObject) && Fcb->CacheType == CACHE_READWRITE)
		{
			Fcb->CacheType = CACHE_READ;
		}
	}
	else if (!FlagOn(DesiredAccess, FILE_READ_DATA) && FlagOn(DesiredAccess, FILE_WRITE_DATA) || (FlagOn(DesiredAccess, FILE_APPEND_DATA)))
	{
		CreateAccess = CREATE_ACCESS_WRITE;
		Fcb->CacheType = CACHE_READ;
	}
	else if (FlagOn(DesiredAccess, FILE_READ_DATA) && FlagOn(DesiredAccess, FILE_WRITE_DATA) || (FlagOn(DesiredAccess, FILE_APPEND_DATA)))
	{
		CreateAccess = CREATE_ACCESS_READWRITE;
	}
}

//获得文件信息
NTSTATUS FsGetFileStandardInfo(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObject, __inout PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	FILE_STANDARD_INFORMATION FileInfo = {0};

	status = FltQueryInformationFile(FltObject->Instance, IrpContext->createInfo.pStreamObject, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
	if (NT_SUCCESS(status))
	{
		//这里是实际大小
		IrpContext->createInfo.FileSize = FileInfo.EndOfFile;
		IrpContext->createInfo.FileAllocationSize = FileInfo.AllocationSize;
		IrpContext->createInfo.Directory = FileInfo.Directory;
		IrpContext->createInfo.DeletePending = FileInfo.DeletePending;
		IrpContext->createInfo.NumberOfLinks = FileInfo.NumberOfLinks;
	}

	return status;
}


NTSTATUS FsGetFileHeaderInfo(__in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = NULL;
	LARGE_INTEGER ByteOffset = {0};
	FILE_BASIC_INFORMATION FileInfo = {0};
	UCHAR * pFileHeader = NULL;
	ULONG FileType = 0;
	ByteOffset.QuadPart = 0;

	IrpContext->createInfo.bEnFile = FALSE;
	IrpContext->createInfo.bWriteHeader = FALSE;

	FileObject = IrpContext->createInfo.pStreamObject;
	pFileHeader = FltAllocatePoolAlignedWithTag(FltObjects->Instance, PagedPool, ENCRYPT_HEAD_LENGTH, 'fhl');
	if (NULL == pFileHeader)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (IrpContext->createInfo.FileSize.QuadPart >= ENCRYPT_HEAD_LENGTH)
	{
		RtlZeroMemory(pFileHeader, ENCRYPT_HEAD_LENGTH);
		
		ntStatus = FltReadFile(FltObjects->Instance, FileObject, &ByteOffset, ENCRYPT_HEAD_LENGTH, pFileHeader,
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
			NULL, NULL, NULL);
		if (NT_SUCCESS(ntStatus))
		{
			if (IsEncryptedFileHead(pFileHeader, &FileType, IrpContext->createInfo.FileHeader))
			{
				RtlCopyMemory(IrpContext->createInfo.OrgFileHeader, pFileHeader, ENCRYPT_HEAD_LENGTH);

				IrpContext->createInfo.bEnFile = TRUE;
				IrpContext->createInfo.bWriteHeader = TRUE;
				//IrpContext->createInfo.bDecrementHeader = TRUE;
			}
		}
		else if (IrpContext->createInfo.bNetWork)//wps、office等访问局域网共享文件，create文件时，如果DesiredAccess缺少READ_CONTROL和SYNCHRONIZE，就无法读文件
		{
			//重新创建获取文件头信息
			OBJECT_ATTRIBUTES ob = { 0 };
			IO_STATUS_BLOCK IoStatus = { 0 };
			HANDLE hFile = NULL;
			PFILE_OBJECT pFileObject = NULL;
			InitializeObjectAttributes(&ob, &IrpContext->createInfo.nameInfo->Name, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
			ntStatus = FltCreateFile(FltObjects->Filter, FltObjects->Instance,
				&hFile,
				FILE_GENERIC_READ,
				&ob,
				&IoStatus,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				0, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0, 0
				);
			if (NT_SUCCESS(ntStatus))
			{
				ntStatus = ObReferenceObjectByHandle(hFile, 0, *IoFileObjectType, KernelMode, &pFileObject, NULL);
				if (NT_SUCCESS(ntStatus))
				{
					ntStatus = FltReadFile(FltObjects->Instance, pFileObject, &ByteOffset, ENCRYPT_HEAD_LENGTH, pFileHeader,
						FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET | FLTFL_IO_OPERATION_NON_CACHED,
						NULL, NULL, NULL);
					if (NT_SUCCESS(ntStatus))
					{
						if (IsEncryptedFileHead(pFileHeader, &FileType, IrpContext->createInfo.FileHeader))
						{
							RtlCopyMemory(IrpContext->createInfo.OrgFileHeader, pFileHeader, ENCRYPT_HEAD_LENGTH);

							IrpContext->createInfo.bEnFile = TRUE;
							IrpContext->createInfo.bWriteHeader = TRUE;
						}
					}
					ObDereferenceObject(pFileObject);
				}
				FltClose(hFile);
			}
		}
	}
	
	//获取文件的访问权限
	if (NT_SUCCESS(ntStatus))
	{
		ntStatus = FltQueryInformationFile(FltObjects->Instance, FileObject, &FileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);
		if (NT_SUCCESS(ntStatus))
		{
			if (FlagOn(FileInfo.FileAttributes, FILE_ATTRIBUTE_READONLY))
			{
				IrpContext->createInfo.FileAccess = FILE_READ_ACCESS;
			}
			else
			{
				IrpContext->createInfo.FileAccess = FileInfo.FileAttributes;
			}
			RtlCopyMemory(&IrpContext->createInfo.BaseInfo, &FileInfo, sizeof(FILE_BASIC_INFORMATION));
		}
	}

	if (NULL != pFileHeader)
	{
		FltFreePoolAlignedWithTag(FltObjects->Instance, pFileHeader, 'fhl');
		pFileHeader = NULL;
	}
	return ntStatus;
}

NTSTATUS FsCreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ob;
	PFILE_OBJECT FileObject;
	ULONG ClusterSize = 0;
	LARGE_INTEGER Temp;
	ULONG Options = 0;

	__try
	{
		FileObject = FltObjects->FileObject;
		Fcb = FsCreateFcb();
		if (NULL == Fcb)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		Ccb = FsCreateCcb();
		if (NULL == Ccb)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		
		//todo::如果解密，需减去加密头的长度
 		if (IrpContext->createInfo.bDecrementHeader)
 		{
 			IrpContext->createInfo.FileSize.QuadPart -= ENCRYPT_HEAD_LENGTH;
 			IrpContext->createInfo.FileAllocationSize.QuadPart -= ENCRYPT_HEAD_LENGTH;
 		}
		
		Fcb->Header.FileSize.QuadPart = IrpContext->createInfo.FileSize.QuadPart;
		Fcb->Header.ValidDataLength.QuadPart = IrpContext->createInfo.FileSize.QuadPart;
		if (IrpContext->createInfo.FileSize.QuadPart > IrpContext->createInfo.FileAllocationSize.QuadPart)
		{
			ClusterSize = IrpContext->ulSectorSize * IrpContext->uSectorsPerAllocationUnit;
			Temp.QuadPart = Fcb->Header.FileSize.QuadPart;
			Temp.QuadPart += ClusterSize;
			Temp.HighPart += (ULONG)((LONGLONG)ClusterSize >> 32);

			if (0 == Temp.LowPart)
			{
				Temp.LowPart -= 1;
			}
			Fcb->Header.AllocationSize.LowPart = ((ULONG)Fcb->Header.FileSize.LowPart + (ClusterSize - 1)) & (~(ClusterSize - 1));
			Fcb->Header.AllocationSize.HighPart = Temp.HighPart;
		}
		else
		{
			Fcb->Header.AllocationSize.QuadPart = IrpContext->createInfo.FileAllocationSize.QuadPart;
		}

		if (IrpContext->createInfo.bRealSize)
		{
			if (IrpContext->createInfo.RealSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
			{
				IrpContext->createInfo.RealSize.QuadPart = IrpContext->createInfo.FileSize.QuadPart;
			}
			else
			{
				Fcb->Header.FileSize.QuadPart = IrpContext->createInfo.RealSize.QuadPart;
				Fcb->Header.ValidDataLength.QuadPart = IrpContext->createInfo.RealSize.QuadPart;
				Fcb->ValidDataToDisk.QuadPart = IrpContext->createInfo.FileSize.QuadPart;
			}
		}
		Fcb->LastAccessTime = IrpContext->createInfo.BaseInfo.LastAccessTime.QuadPart;
		Fcb->CreationTime = IrpContext->createInfo.BaseInfo.CreationTime.QuadPart;
		Fcb->CurrentLastAccess = IrpContext->createInfo.BaseInfo.ChangeTime.QuadPart;
		Fcb->Attribute = IrpContext->createInfo.BaseInfo.FileAttributes;
		Fcb->LastWriteTime = IrpContext->createInfo.BaseInfo.LastWriteTime.QuadPart;
		Fcb->LinkCount = IrpContext->createInfo.NumberOfLinks;
		Fcb->DeletePending = IrpContext->createInfo.DeletePending;
		Fcb->Directory = IrpContext->createInfo.Directory;
		Fcb->ProcessID = PsGetCurrentProcessId();
		Fcb->ThreadID = PsGetCurrentThreadId();

		FltInitializeOplock(&Fcb->Oplock);
		Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
		if (IrpContext->createInfo.bWriteHeader)
		{
			SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
		}
		if (IrpContext->createInfo.bNetWork)
		{
			//???
			//SetFlag(Fcb->FcbState,SCB_STATE_DISABLE_LOCAL_BUFFERING);
			//Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
		}
		//todo::受控进程只要打开了受控的文件，退出时就加密？？
		Fcb->bEnFile = IrpContext->createInfo.bEnFile;
		Fcb->bWriteHead = IrpContext->createInfo.bWriteHeader;
		Fcb->CacheType = CACHE_ALLOW;
		Fcb->ProcessAcessType = IrpContext->createInfo.uProcType;

		if (Fcb->bEnFile)
		{
			if (FlagOn(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED))
			{
				RtlCopyMemory(Fcb->szFileHead, IrpContext->createInfo.FileHeader, ENCRYPT_HEAD_LENGTH);
				RtlCopyMemory(Fcb->szOrgFileHead, IrpContext->createInfo.OrgFileHeader, ENCRYPT_HEAD_LENGTH);
			}
			Fcb->FileHeaderLength = ENCRYPT_HEAD_LENGTH;
		}
		else
		{
			SetFlag(Fcb->ProcessAcessType, FILE_ACCESS_PROCESS_RW);
		}
		
		if (IsFltFileLock())
		{
			Fcb->FileLock = FltAllocateFileLock(NULL, NULL);
			if (Fcb->FileLock)
			{
				FltInitializeFileLock(Fcb->FileLock);
			}
		}
		else
		{
			Fcb->FileLock = FsRtlAllocateFileLock(NULL, NULL);
			if (Fcb->FileLock)
			{
				FsRtlInitializeFileLock(Fcb->FileLock, NULL, NULL);
			}
		}
		
		if (IrpContext->createInfo.nameInfo->Name.Length < FILE_PATH_LENGTH_MAX)
		{
			RtlCopyMemory(Fcb->wszFile, IrpContext->createInfo.nameInfo->Name.Buffer, IrpContext->createInfo.nameInfo->Name.Length);
		}
		else
			RtlCopyMemory(Fcb->wszFile, IrpContext->createInfo.nameInfo->Name.Buffer, FILE_PATH_LENGTH_MAX);

		Fcb->bRecycleBinFile = IsRecycleBinFile(IrpContext->createInfo.nameInfo->Name.Buffer, IrpContext->createInfo.nameInfo->Name.Length);

		if (!IrpContext->createInfo.bNetWork && !Fcb->bRecycleBinFile)
		{
			Options = FILE_NON_DIRECTORY_FILE;
#ifdef USE_CACHE_READWRITE
			SetFlag(Options, FILE_WRITE_THROUGH);//直接写入
#endif
			UNICODE_STRING unicodeString;
			IO_STATUS_BLOCK IoStatus;

			RtlInitUnicodeString(&unicodeString, Fcb->wszFile);
			InitializeObjectAttributes(&ob, &unicodeString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
			status = FltCreateFile(FltObjects->Filter, FltObjects->Instance, &Fcb->CcFileHandle, FILE_SPECIAL_ACCESS, &ob, &IoStatus,
				NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OPEN, Options, NULL, 0, 0);
			if (!NT_SUCCESS(status))
			{
				try_return(status);
			}
			status = ObReferenceObjectByHandle(Fcb->CcFileHandle, 0, *IoFileObjectType, KernelMode, &Fcb->CcFileObject, NULL);
			if (!NT_SUCCESS(status))
			{
				FltClose(Fcb->CcFileHandle);
				Fcb->CcFileHandle = NULL;
				try_return(status);
			}
		}
		else
		{
			Fcb->CcFileObject = IrpContext->createInfo.pStreamObject;
			Fcb->CcFileHandle = IrpContext->createInfo.hStreamHanle;
		}
		Fcb->FileAllOpenInfo[Fcb->FileAllOpenCount].FileObject = IrpContext->createInfo.pStreamObject;
		Fcb->FileAllOpenInfo[Fcb->FileAllOpenCount].FileHandle = IrpContext->createInfo.hStreamHanle;
		Fcb->FileAllOpenCount += 1;

		if (InsertFcbList(&Fcb))
		{
			Ccb->StreamFileInfo.hStreamHandle = IrpContext->createInfo.hStreamHanle;
			Ccb->StreamFileInfo.StreamObject = IrpContext->createInfo.pStreamObject;
			Ccb->StreamFileInfo.pFO_Resource = FsAllocateResource();
			Ccb->ProcType = IrpContext->createInfo.uProcType;

			if (IrpContext->createInfo.bNetWork)
			{
				SetFlag(Ccb->CcbState, CCB_FLAG_NETWORK_FILE);
			}
			Ccb->FileAccess = IrpContext->createInfo.FileAccess;
			ExInitializeFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);
		}
		else
		{
			try_return(status = STATUS_INSUFFICIENT_RESOURCES);
		}
		
		IrpContext->createInfo.pFcb = Fcb;
		IrpContext->createInfo.pCcb = Ccb;

		try_return(status = STATUS_SUCCESS);
try_exit:NOTHING;

	}
	__finally
	{
		if (AbnormalTermination() || !NT_SUCCESS(status))
		{
			FltUninitializeOplock(&Fcb->Oplock);
			if (Fcb != NULL)
			{
				if (Fcb->FileLock)
				{
					if (IsFltFileLock())
					{
						FltUninitializeFileLock(Fcb->FileLock);
						FltFreeFileLock(Fcb->FileLock);
					}
					else
					{
						FsRtlUninitializeFileLock(Fcb->FileLock);
						FsRtlFreeFileLock(Fcb->FileLock);
					}
					Fcb->FileLock = NULL;
				}

				FsFreeFcb(Fcb, IrpContext);
				FileObject->FsContext = NULL;
			}
			if (Ccb != NULL)
			{
				FsFreeCcb(Ccb);
				FileObject->FsContext2 = NULL;
			}
		}
	}
	return status;
}

PDEFFCB FsCreateFcb()
{
	PDEFFCB Fcb = NULL;
	Fcb = (PDEFFCB)ExAllocateFromNPagedLookasideList(&g_FcbLookasideList);
	if (Fcb)
	{
		RtlZeroMemory(Fcb, sizeof(DEFFCB));
		Fcb->Header.NodeTypeCode = LAYER_NTC_FCB;
		Fcb->Header.NodeByteSize = sizeof(DEFFCB);
		Fcb->Header.PagingIoResource = FsAllocateResource();
		Fcb->Resource = FsAllocateResource();
		Fcb->Header.Resource = FsAllocateResource();
		
		if (NULL == Fcb->Header.PagingIoResource || NULL == Fcb->Resource || NULL == Fcb->Header.Resource)
		{
			FsFreeResource(Fcb->Header.PagingIoResource);
			FsFreeResource(Fcb->Resource);
			FsFreeResource(Fcb->Header.Resource);
			if (Fcb->NtfsFcb)
			{
				ExFreeToNPagedLookasideList(&g_NTFSFCBLookasideList, Fcb->NtfsFcb);
			}
			ExFreeToNPagedLookasideList(&g_FcbLookasideList, Fcb);
			return NULL;
		}
		Fcb->NtfsFcb = ExAllocateFromNPagedLookasideList(&g_NTFSFCBLookasideList);
		if (Fcb->NtfsFcb)
		{
			Fcb->NtfsFcb->Resource = Fcb->Resource;
			Fcb->NtfsFcb->PageioResource = Fcb->Header.PagingIoResource;
		}
		Fcb->Header.FastMutex = ExAllocateFromNPagedLookasideList(&g_FastMutexInFCBLookasideList);
		ExInitializeFastMutex(Fcb->Header.FastMutex);
		ExInitializeFastMutex(&Fcb->AdvancedFcbHeaderMutex);
		FsRtlSetupAdvancedHeader(&Fcb->Header, &Fcb->AdvancedFcbHeaderMutex);
	
		Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
		Fcb->Header.AllocationSize.QuadPart = -1;
		Fcb->Header.FileSize.QuadPart = 0;
		Fcb->Header.ValidDataLength.QuadPart = 0;
		Fcb->Vcb = szVcbPlacer;
	}
	return Fcb;
}

BOOLEAN FsFreeFcb(__in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	FILE_BASIC_INFORMATION fileInfo = { 0 };
	BOOLEAN bSetBasicInfo = FALSE;
	RemoveFcbList(Fcb->wszFile);
	if (NULL != Fcb->CcFileObject)
	{
		if (!BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
		{
			if (BooleanFlagOn(Fcb->FcbState, FCB_STATE_FILE_CHANGED))
			{
				Status = FsCloseGetFileBasicInfo(Fcb->CcFileObject, IrpContext, &fileInfo);
				if (NT_SUCCESS(Status))
				{
					bSetBasicInfo = TRUE;
				}
				ObDereferenceObject(Fcb->CcFileObject);
				Status = FltClose(Fcb->CcFileHandle);
				if (bSetBasicInfo)
				{
					Status = FsCloseSetFileBasicInfo(Fcb->CcFileObject, IrpContext, &fileInfo);
				}
			}
			else
			{
				ObDereferenceObject(Fcb->CcFileObject);
				Status = FltClose(Fcb->CcFileHandle);
			}
		}
		else
		{
			ObDereferenceObject(Fcb->CcFileObject);
			FltClose(Fcb->CcFileHandle);
		}
		
		Fcb->CcFileObject = NULL;
		Fcb->CcFileHandle = NULL;
	}
	FsFreeResource(Fcb->Header.PagingIoResource);
	FsFreeResource(Fcb->Header.Resource);
	FsFreeResource(Fcb->Resource);
	if (Fcb->Header.FastMutex)
	{
		ExFreeToNPagedLookasideList(&g_FastMutexInFCBLookasideList, Fcb->Header.FastMutex);
		Fcb->Header.FastMutex = NULL;
	}
	if (Fcb->OutstandingAsyncEvent != NULL)
	{
		ExFreePool(Fcb->OutstandingAsyncEvent);
		Fcb->OutstandingAsyncEvent = NULL;
	}
	if (FlagOn(Fcb->Header.Flags, FSRTL_FLAG_ADVANCED_HEADER))
	{
		FsRtlTeardownPerStreamContexts(&Fcb->Header);
	}
	if (Fcb->Oplock && NULL != &Fcb->Oplock)
	{
		FltUninitializeOplock(&Fcb->Oplock);
	}
	
	if (Fcb->FileLock)
	{
		if (IsFltFileLock())
		{
			FltUninitializeFileLock(Fcb->FileLock);
		}
		else
		{
			FsRtlUninitializeFileLock(Fcb->FileLock);
		}
		Fcb->FileLock = NULL;
	}
	
	if (Fcb->NtfsFcb)
	{
		ExFreeToNPagedLookasideList(&g_NTFSFCBLookasideList, Fcb->NtfsFcb);
		Fcb->NtfsFcb = NULL;
	}
	ExFreeToNPagedLookasideList(&g_FcbLookasideList, Fcb);
	Fcb = NULL;
	return TRUE;
}

NTSTATUS FsOverWriteFile(__in PFILE_OBJECT FileObject, __in PDEFFCB Fcb, __in LARGE_INTEGER AllocationSize)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOLEAN bAcquiredPagingResource = FALSE;
	__try
	{
		if (MmCanFileBeTruncated(&Fcb->SectionObjectPointers, &Li0))
		{
			//清除缓存数据
			SetFlag(Fcb->FcbState, FCB_STATE_NOTIFY_RESIZE_STREAM);
			if (!CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE))
			{
				KdPrint(("error:CcPurgeCacheSection failed...\n"));
			}
			ClearFlag(Fcb->FcbState, FCB_STATE_NOTIFY_RESIZE_STREAM);

			//更新缓存中文件大小
			if (ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE))
			{
				bAcquiredPagingResource = TRUE;
			}
			Fcb->Header.FileSize.QuadPart = 0;
			Fcb->Header.ValidDataLength.QuadPart = 0;
			Fcb->Header.AllocationSize.QuadPart = AllocationSize.QuadPart;

			CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
			
			if (bAcquiredPagingResource)
			{
				ExReleaseResourceLite(Fcb->Header.PagingIoResource);
				bAcquiredPagingResource = FALSE;
			}
			Status = STATUS_SUCCESS;
		}
		else
		{
			Status = STATUS_USER_MAPPED_FILE;
		}
	}
	__finally
	{
		if (bAcquiredPagingResource)
		{
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
		}
	}
	return Status;
}

NTSTATUS FsCloseGetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __inout PFILE_BASIC_INFORMATION FileInfo)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_CALLBACK_DATA NewData = NULL;

	__try
	{
		Status = FltAllocateCallbackData(IrpContext->FltObjects.Instance, FileObject, &NewData);
		if (NT_SUCCESS(Status))
		{
			NewData->Iopb->MajorFunction = IRP_MJ_QUERY_INFORMATION;
			NewData->Iopb->MinorFunction = 0;
			NewData->Iopb->Parameters.QueryFileInformation.InfoBuffer = FileInfo;
			NewData->Iopb->Parameters.QueryFileInformation.FileInformationClass = FileBasicInformation;
			NewData->Iopb->Parameters.QueryFileInformation.Length = sizeof(FILE_BASIC_INFORMATION);
			NewData->Iopb->TargetFileObject = FileObject;

			FltPerformSynchronousIo(NewData);
			Status = NewData->IoStatus.Status;
		}
	}
	__finally
	{
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FsCloseGetFileBasicInfo failed(0x%x)....\n", Status));
		}
		if (NULL != NewData)
		{
			FltFreeCallbackData(NewData);
		}
	}

	return Status;
}

NTSTATUS FsCloseSetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_BASIC_INFORMATION FileInfo)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_CALLBACK_DATA NewData = NULL;

	__try
	{
		Status = FltAllocateCallbackData(IrpContext->FltObjects.Instance, FileObject, &NewData);
		if (NT_SUCCESS(Status))
		{
			NewData->Iopb->MajorFunction = IRP_MJ_SET_INFORMATION;
			NewData->Iopb->MinorFunction = 0;
			NewData->Iopb->Parameters.SetFileInformation.FileInformationClass = FileBasicInformation;
			NewData->Iopb->Parameters.SetFileInformation.Length = sizeof(FILE_BASIC_INFORMATION);
			NewData->Iopb->Parameters.SetFileInformation.InfoBuffer = FileInfo;
			NewData->Iopb->Parameters.SetFileInformation.AdvanceOnly = FALSE;
			NewData->Iopb->Parameters.SetFileInformation.ParentOfTarget = NULL;
			NewData->Iopb->TargetFileObject = FileObject;
			FltPerformSynchronousIo(NewData);
			Status = NewData->IoStatus.Status;
		}
	}
	__finally
	{
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FsCloseSetFileBasicInfo failed(0x%x)....\n",Status));
		}
		if (NewData != NULL)
		{
			FltFreeCallbackData(NewData);
		}
	}

	return Status;
}

BOOLEAN CanFsWait(__in PFLT_CALLBACK_DATA Data)
{
	return FltIsOperationSynchronous(Data);
}

FLT_PREOP_CALLBACK_STATUS FsCompleteMdl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	PFILE_OBJECT FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	PAGED_CODE();

	if (FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}

	switch (Iopb->MajorFunction)
	{
	case IRP_MJ_READ:
		CcMdlReadComplete(FileObject, Iopb->Parameters.Read.MdlAddress);
		break;
	case IRP_MJ_WRITE:
		CcMdlWriteComplete(FileObject, &Iopb->Parameters.Write.ByteOffset, Iopb->Parameters.Write.MdlAddress);
		break;

	default:
		//FsBugCheck();
		break;
	}

	Iopb->Parameters.Read.MdlAddress = NULL;
	Data->IoStatus.Status = STATUS_SUCCESS;
	FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);

	return FLT_PREOP_COMPLETE;
}

VOID FsProcessException(IN OUT PDEF_IRP_CONTEXT *IrpContext OPTIONAL, IN OUT PFLT_CALLBACK_DATA *Data OPTIONAL, IN NTSTATUS Status)
{
	BOOLEAN bPending = FALSE;
	__try
	{
		if (ARGUMENT_PRESENT(IrpContext) && ARGUMENT_PRESENT(*IrpContext))
		{
			(*IrpContext)->ExceptionStatus = Status;
			
			if ((*IrpContext)->WorkItem != NULL)
			{
				IoFreeWorkItem((*IrpContext)->WorkItem);
				(*IrpContext)->WorkItem = NULL;
			}
			//延迟的设置可以删除irp上下文了然后删除上下文
			if ((*IrpContext)->AllocateMdl != NULL)
			{
				IoFreeMdl((*IrpContext)->AllocateMdl);
				(*IrpContext)->AllocateMdl = NULL;
			}
			if (FlagOn((*IrpContext)->Flags, IRP_CONTEXT_FLAG_IN_FSP))
			{
				bPending = TRUE;
			}
			if (bPending)
			{
				ClearFlag((*IrpContext)->Flags, IRP_CONTEXT_FLAG_DONT_DELETE);
			}
			FsDeleteIrpContext(IrpContext);
		}
		if (ARGUMENT_PRESENT(Data) && ARGUMENT_PRESENT(*Data))
		{
			if (NT_ERROR(Status) && FlagOn((*Data)->Iopb->IrpFlags, IRP_INPUT_OPERATION))
			{
				(*Data)->IoStatus.Information = 0;
			}
			(*Data)->IoStatus.Status = Status;
			if (bPending)
			{
				FltCompletePendedPreOperation(*Data, FLT_PREOP_COMPLETE, NULL);
			}
		}
	}
	__finally
	{
		if (ARGUMENT_PRESENT(Data) && ARGUMENT_PRESENT(*Data))
		{
			(*Data)->IoStatus.Status = Status;
		}
	}
}

PVOID FsMapUserBuffer(__inout PFLT_CALLBACK_DATA Data, __inout PULONG RetLength)
{
	NTSTATUS Status;
	PMDL pMdl = NULL;
	PVOID pBuffer = NULL;

	PMDL *ppMdl = NULL;
	PVOID * ppBuffer = NULL;
	PULONG Length = NULL;
	LOCK_OPERATION DesiredAccess;

	PVOID pSystemBuffer = NULL;
	PFLT_IO_PARAMETER_BLOCK pIopb = Data->Iopb;

	PAGED_CODE();

	Status = FltDecodeParameters(Data, &ppMdl, &ppBuffer, &Length, &DesiredAccess);
	if (!NT_SUCCESS(Status))
	{
		FsRaiseStatus(NULL, Status);
	}
	pMdl = *ppMdl;
	pBuffer = *ppBuffer;
	if (RetLength != NULL)
	{
		*RetLength = *Length;
	}

	if (NULL == pMdl)
	{
		KdPrint(("[%s]buffer=0x%x, Length=%d...\n", __FUNCTION__, pBuffer, *Length));
		return pBuffer;
	}
	pSystemBuffer = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (NULL == pSystemBuffer)
	{
		FsRaiseStatus(NULL, STATUS_INSUFFICIENT_RESOURCES);
	}
	if (RetLength != NULL)
	{
		*RetLength = *Length;
	}
	KdPrint(("[%s]buffer=0x%x, SystemBuffer=0x%x, Length=%d...\n", __FUNCTION__, pBuffer, pSystemBuffer, *Length));
	
	return pSystemBuffer;
}

BOOLEAN MyFltCheckLockForReadAccess(IN PFILE_LOCK FileLock, IN PFLT_CALLBACK_DATA Data)
{
	BOOLEAN Result;

	PFLT_IO_PARAMETER_BLOCK  Iopb;

	LARGE_INTEGER  StartingByte;
	LARGE_INTEGER  Length;
	ULONG          Key;
	PFILE_OBJECT   FileObject;
	PVOID          ProcessId;
	LARGE_INTEGER  BeyondLastByte;

	if (FileLock->LockInformation == NULL)
	{
		return TRUE;
	}

	Iopb = Data->Iopb;

	StartingByte = Iopb->Parameters.Read.ByteOffset;
	Length.QuadPart = (ULONGLONG)Iopb->Parameters.Read.Length;

	BeyondLastByte.QuadPart = (ULONGLONG)StartingByte.QuadPart + Length.LowPart;

	Key = Iopb->Parameters.Read.Key;
	FileObject = Iopb->TargetFileObject;
	ProcessId = FltGetRequestorProcess(Data);

	Result = FsRtlFastCheckLockForRead(FileLock,
		&StartingByte,
		&Length,
		Key,
		FileObject,
		ProcessId);

	return Result;
}


//重新得到文件的分配大小
VOID FsLookupFileAllocationSize(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb, IN PDEF_CCB Ccb)
{
	NTSTATUS Status;
	FILE_STANDARD_INFORMATION FileInfo = { 0 };
	PFLT_CALLBACK_DATA NewData;
	PFLT_RELATED_OBJECTS FltObjects = &IrpContext->FltObjects;
	ULONG ClusterSize;
	LARGE_INTEGER TempLi;
	PVOLUMECONTEXT volCtx = NULL;


	Status = FltAllocateCallbackData(FltObjects->Instance, Ccb->StreamFileInfo.StreamObject, &NewData);
	if (NT_SUCCESS(Status))
	{
		NewData->Iopb->MajorFunction = IRP_MJ_QUERY_INFORMATION;
		NewData->Iopb->Parameters.QueryFileInformation.FileInformationClass = FileStandardInformation;
		NewData->Iopb->Parameters.QueryFileInformation.InfoBuffer = &FileInfo;
		NewData->Iopb->Parameters.QueryFileInformation.Length = sizeof(FILE_STANDARD_INFORMATION);

		FltPerformSynchronousIo(NewData);
		Status = NewData->IoStatus.Status;
	}
	if (NT_SUCCESS(Status))
	{
		Fcb->Header.AllocationSize.QuadPart = FileInfo.AllocationSize.QuadPart - Fcb->FileHeaderLength;
		if (Fcb->Header.FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
		{
			Status = FltGetVolumeContext(FltObjects->Filter,
				FltObjects->Volume,
				&volCtx);
			if (!NT_SUCCESS(Status))
			{
				FsRaiseStatus(IrpContext, Status);
			}

			ClusterSize = volCtx->ulSectorSize * volCtx->uSectorsPerAllocationUnit; //簇大小

			if (volCtx != NULL)
			{
				FltReleaseContext(volCtx);
				volCtx = NULL;
			}

			TempLi.QuadPart = Fcb->Header.FileSize.QuadPart;//占用大小
			TempLi.QuadPart += ClusterSize;
			TempLi.HighPart += (ULONG)((LONGLONG)ClusterSize >> 32);

			if (TempLi.LowPart == 0) //不需要进位 
			{
				TempLi.HighPart -= 1;
			}

			Fcb->Header.AllocationSize.LowPart = ((ULONG)Fcb->Header.FileSize.LowPart + (ClusterSize - 1)) & (~(ClusterSize - 1));

			Fcb->Header.AllocationSize.HighPart = TempLi.HighPart;
		}
		if (NewData != NULL)
		{
			FltFreeCallbackData(NewData);
		}
	}
	else
	{
		if (NULL != NewData)
		{
			FltFreeCallbackData(NewData);
		}
		FsRaiseStatus(IrpContext, Status);
	}
	if (Fcb->Header.FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
	{
		FsPopUpFileCorrupt(IrpContext, Fcb);
		FsRaiseStatus(IrpContext, STATUS_FILE_CORRUPT_ERROR);
	}
}

VOID FsPopUpFileCorrupt(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb)
{
	PKTHREAD Thread;
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, Fcb->wszFile);
	if (IoIsSystemThread(IrpContext->OriginatingData->Thread))
	{
		Thread = NULL;
	}
	else
	{
		Thread = IrpContext->OriginatingData->Thread;
	}
	IoRaiseInformationalHardError(STATUS_FILE_CORRUPT_ERROR, &unicodeString, Thread);
}

VOID FsFreeCcb(IN PDEF_CCB Ccb)
{
	if (NULL != Ccb)
	{
		if (Ccb->StreamFileInfo.pFO_Resource)
		{
			ExDeleteResourceLite(Ccb->StreamFileInfo.pFO_Resource);
			ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Ccb->StreamFileInfo.pFO_Resource);
		}	

		ExFreeToNPagedLookasideList(&g_CcbLookasideList, Ccb);
	}
	Ccb = NULL;
}

FLT_PREOP_CALLBACK_STATUS FsPrePassThroughIrp(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	//哪些IRP要特殊处理？？
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);


	return FltStatus;
}

BOOLEAN IsTest(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PUCHAR FunctionName)
{
	NTSTATUS status;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	HANDLE hProcessId = NULL;
	PEPROCESS Process = NULL;
	WCHAR szExName[8] = { 0 };
	BOOLEAN bTrue = FALSE;
	ULONG length = 0;
	WCHAR * pwszName = NULL;
	WCHAR wszName[5] = {L".xls"};
	WCHAR szProcessName[MAX_PATH] = { 0 };
	UNICODE_STRING strProcessName;
	HANDLE ProcessId = NULL;
	//过早使用FltGetFileNameInformation会带来下层ntfs驱动兼容问题
	__try
	{
		ProcessId = PsGetCurrentProcessId();
		RtlInitUnicodeString(&strProcessName, szProcessName);
		strProcessName.Length = MAX_PATH * sizeof(WCHAR);
		strProcessName.MaximumLength = MAX_PATH * sizeof(WCHAR);
		status = FsGetProcessName(ProcessId, &strProcessName);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}

		if (FileObject && (NULL != FileObject->FileName.Buffer))
		{
			length = FileObject->FileName.Length + sizeof(WCHAR);
			pwszName = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, length, 'aaaa');
			RtlZeroMemory(pwszName, length);
			RtlCopyMemory(pwszName, FileObject->FileName.Buffer, FileObject->FileName.Length);
			if (NULL == wcsstr(pwszName, wszName))
			{
				__leave;
			}
		}
		KdPrint(("-------Test:File:%S. Process:%S ...\n", pwszName, strProcessName.Buffer));
		if (0 == wcsicmp(L"NTRtScan.exe", strProcessName.Buffer) ||
			0 == wcsicmp(L"coreServiceShell.exe", strProcessName.Buffer))
		{
			bTrue = TRUE;
			KdPrint(("processName=%S, funtionName=%s, File Name=%S...\n", strProcessName.Buffer, FunctionName, pwszName));
		}
	}
	__finally
	{
		if (NULL != Process)
		{
			ObDereferenceObject(Process);
		}
		if (pwszName)
		{
			ExFreePoolWithTag(pwszName, 'aaaa');
		}
	}

	return bTrue;
}

BOOLEAN FsGetFileExtFromFileName(__in PUNICODE_STRING FilePath, __inout WCHAR * FileExt, __inout USHORT* nLength)
{
	PWCHAR pFileName = NULL;
	ULONG   nIndex = 0;
	PWCHAR pTemp = FileExt;

	if (FilePath == NULL)
		return FALSE;

	if (!FilePath->Buffer || FilePath->Length == 0)
		return FALSE;

	if (FilePath->Length == sizeof(WCHAR) && FilePath->Buffer[0] == L'\\')
		return FALSE;

	pFileName = FilePath->Buffer;
	nIndex = FilePath->Length / sizeof(WCHAR)-1;

	while (nIndex >= 0)
	{
		if (pFileName[nIndex] == L'.' || pFileName[nIndex] == L'\\')
		{
			break;
		}
		nIndex--;
	};

	if (nIndex <= 0)
		return FALSE;

	if (pFileName[nIndex] == L'\\')
		return TRUE;
	if (pFileName[nIndex] == L'.' && nIndex>0 && pFileName[nIndex - 1] == L'*')
		return FALSE;
	nIndex++;

	if (FilePath->Length / sizeof(WCHAR)-nIndex > 32)
		return FALSE;

	while ((USHORT)nIndex < FilePath->Length / sizeof(WCHAR) && pFileName[nIndex] != 0)
	{
		*pTemp = pFileName[nIndex++];
		pTemp++;
	};
	*pTemp = 0;
	*nLength = (pTemp - FileExt)*sizeof(WCHAR);
	return TRUE;
}

NTSTATUS FsWriteFileHeader(__in PFLT_INSTANCE Instance, __in PFILE_OBJECT FileObject, __inout PVOID HeadBuf)
{
	NTSTATUS Status;
	PVOID pHeader = NULL;
	LARGE_INTEGER ByteOffset;
	ByteOffset.QuadPart = 0;
	__try
	{
		pHeader = FltAllocatePoolAlignedWithTag(Instance, PagedPool, ENCRYPT_HEAD_LENGTH, 'fsfh');
		if (NULL == pHeader)
		{
			return STATUS_INSUFFICIENT_RESOURCES;
		}
		RtlZeroMemory(pHeader, ENCRYPT_HEAD_LENGTH);
		CreateFileHead(pHeader);
		if (NULL != HeadBuf)
		{
			RtlCopyMemory(HeadBuf, pHeader, ENCRYPT_HEAD_LENGTH);
		}
		EncryptFileHead(pHeader);
		
		Status = FltWriteFile(Instance,
			FileObject,
			&ByteOffset,
			ENCRYPT_HEAD_LENGTH,
			pHeader,
			/*FLTFL_IO_OPERATION_NON_CACHED | */FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			NULL, NULL, NULL);
	}
	__finally
	{
		if (NULL != pHeader)
		{
			FltFreePoolAlignedWithTag(Instance, pHeader, 'fsfh');
		}
		if (AbnormalTermination())
		{
			Status = STATUS_INSUFFICIENT_RESOURCES;
		}
	}
	return Status;
}

//设置文件的大小
NTSTATUS FsExtendingValidDataSetFile(__in PCFLT_RELATED_OBJECTS FltObjects, PDEFFCB Fcb, PDEF_CCB Ccb)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	FILE_VALID_DATA_LENGTH_INFORMATION fvi = {0};
	ULONG RetryCount = 0;

	fvi.ValidDataLength.QuadPart = Fcb->Header.FileSize.QuadPart + Fcb->FileHeaderLength;

	while (RetryCount <= 3) //失败了重复3次
	{
		Status = FltSetInformationFile(
			FltObjects->Instance,
			Fcb->CcFileObject,
			&fvi,
			sizeof(FILE_VALID_DATA_LENGTH_INFORMATION),
			FileValidDataLengthInformation
			);
		if (NT_SUCCESS(Status) || Status == STATUS_INVALID_PARAMETER)
		{
			Status = STATUS_SUCCESS;
			break;

		}
		RetryCount++;
	}
	return Status;
}

BOOLEAN FsZeroData(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb, IN PFILE_OBJECT FileObject, IN LONGLONG StartingZero, IN LONGLONG ByteCount, IN ULONG SectorSize)
{
	LARGE_INTEGER ZeroStart = { 0, 0 };
	LARGE_INTEGER BeyondZeroEnd = { 0, 0 };

	BOOLEAN Finished;

	PAGED_CODE();

	ZeroStart.QuadPart = ((ULONGLONG)StartingZero + (SectorSize - 1)) & ~((ULONGLONG)SectorSize - 1);

	//
	//  Detect overflow if we were asked to zero in the last sector of the file,
	//  which must be "zeroed" already (or we're in trouble).
	//

	if (StartingZero != 0 && ZeroStart.QuadPart == 0) {

		return TRUE;
	}

	//
	//  Note that BeyondZeroEnd can take the value 4gb.
	//

	BeyondZeroEnd.QuadPart = ((ULONGLONG)StartingZero + ByteCount + (SectorSize - 1))
		& (~((LONGLONG)SectorSize - 1));

	//
	//  If we were called to just zero part of a sector we are in trouble.
	//

	if (ZeroStart.QuadPart == BeyondZeroEnd.QuadPart) {

		return TRUE;
	}

	Finished = CcZeroData(FileObject,
		&ZeroStart,
		&BeyondZeroEnd,
		BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT));

	return Finished;
}

BOOLEAN FsMyFltCheckLockForWriteAccess(__in PFILE_LOCK FileLock, __in PFLT_CALLBACK_DATA Data)
{
	BOOLEAN Result;

	PFLT_IO_PARAMETER_BLOCK  Iopb;

	LARGE_INTEGER   StartingByte;
	LARGE_INTEGER   Length;
	ULONG           Key;
	PFILE_OBJECT    FileObject;
	PVOID           ProcessId;
	LARGE_INTEGER   BeyondLastByte;

	if (FileLock->LockInformation == NULL)
	{
		return TRUE;
	}


	Iopb = Data->Iopb;

	StartingByte = Iopb->Parameters.Write.ByteOffset;
	Length.QuadPart = (ULONGLONG)Iopb->Parameters.Write.Length;

	BeyondLastByte.QuadPart = (ULONGLONG)StartingByte.QuadPart + Length.LowPart;


	Key = Iopb->Parameters.Write.Key;
	FileObject = Iopb->TargetFileObject;
	ProcessId = FltGetRequestorProcess(Data);

	Result = FsRtlFastCheckLockForWrite(FileLock,
		&StartingByte,
		&Length,
		Key,
		FileObject,
		ProcessId);

	return Result;
}

NTSTATUS FsSetFileInformation(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in PVOID FileInfoBuffer, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInfoClass)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_CALLBACK_DATA NewData = NULL;

	Status = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(Status))
	{
		NewData->Iopb->MajorFunction = IRP_MJ_SET_INFORMATION;
		NewData->Iopb->Parameters.SetFileInformation.FileInformationClass = FileInfoClass;
		NewData->Iopb->Parameters.SetFileInformation.Length = Length;
		NewData->Iopb->Parameters.SetFileInformation.InfoBuffer = FileInfoBuffer;
		NewData->Iopb->TargetFileObject = FileObject;


		SetFlag(NewData->Iopb->IrpFlags, IRP_SYNCHRONOUS_API);
		FltPerformSynchronousIo(NewData);
		Status = NewData->IoStatus.Status;
	}

	if (NewData != NULL)
	{
		FltFreeCallbackData(NewData);
	}
	return Status;
}

BOOLEAN CheckEnv(__in ULONG ulMinifilterEnvType)
{
	BOOLEAN bRet = FALSE;

	__try
	{
		KeEnterCriticalRegion();

		if (MINIFILTER_ENV_TYPE_NULL == ulMinifilterEnvType)
		{
			KdPrint(("MinifilterEnvType error"));
			__leave;
		}

		if (FlagOn(ulMinifilterEnvType, MINIFILTER_ENV_TYPE_RUNING))
		{
			if (g_bUnloading)
				__leave;
		}

		if (FlagOn(ulMinifilterEnvType, MINIFILTER_ENV_TYPE_ALL_MODULE_INIT))
		{
			if (!g_bAllModuleInitOk)
				__leave;
		}

		if (FlagOn(ulMinifilterEnvType, MINIFILTER_ENV_TYPE_FLT_FILTER))
		{
			if (!gFilterHandle)
				__leave;
		}

		if (FlagOn(ulMinifilterEnvType, MINIFILTER_ENV_TYPE_SAFE_DATA))
		{
			if (GetDogId())
			{
				bRet = TRUE;
				__leave;
			}
			if (!g_bSafeDataReady)
				__leave;
		}

		bRet = TRUE;
	}
	__finally
	{
		KeLeaveCriticalRegion();
	}

	return bRet;
}

BOOLEAN IsFilterFileByExt(__in WCHAR * pwszExtName, __in USHORT Length)
{
	//.dll|.exe|.sys|.lib|.log|.db|-journal|-wal|.xml|.cpp|.c|.h|.hpp|.acf|.idl|.pdb|.idb|.manifest|.obj|.rsp|.pch|.vmem|.vmsn|.ipdb|Cookies|.dmp|.cache|.dat|.chs|.db-shm|.db-wal|.cab|.P2P|.mem|.bin|.cupf|.suo|.fdb|.lck
	BOOLEAN bRet = FALSE;
	USHORT usLength = Length / sizeof(WCHAR);
	__try
	{
		
		switch (usLength)
		{
		case 0:
			bRet = TRUE;
			break;
		case 1:
			break;
		case 2:
			if (0 == _wcsnicmp(pwszExtName, L"pf", 2) ||
				0 == _wcsnicmp(pwszExtName, L"qm", 2) ||
				0 == _wcsnicmp(pwszExtName, L"so", 2) ||
				0 == _wcsnicmp(pwszExtName, L"rb", 2) ||
				0 == _wcsnicmp(pwszExtName, L"db", 2))
			{
				bRet = TRUE;
			}
			break;
		case 3:
			if ((0 == _wcsnicmp(pwszExtName, L"dll", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"exe", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"sys", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"lib", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"pdb", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"acf", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"idb", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"obj", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"rsp", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"pch", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"chs", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"bin", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"suo", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"fdb", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"lck", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"mem", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"dat", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"cab", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"dmp", 3)) || 
				(0 == _wcsnicmp(pwszExtName, L"tmp", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"mui", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"sdb", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"rbx", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"ttf", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"scr", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"plg", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"ini", 3)) ||
				(0 == _wcsnicmp(pwszExtName, L"p2p", 3)) )
			{
				bRet = TRUE;
			}
			break;
		case  4:
			break;

		default:
			break;
		}
	}
	__finally
	{

	}
	

	return bRet;
}

NTSTATUS FsGetFileObjectIdInfo(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __inout PDEFFCB Fcb)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	FILE_OBJECTID_BUFFER FileObjectIdInfo = { 0 };
	ULONG Length = sizeof(FILE_OBJECTID_BUFFER);
	PVOID pBuf = &FileObjectIdInfo;

// 	if (/*IsVistaOrLater()*/FALSE)
// 	{
// 		ntStatus = g_DYNAMIC_FUNCTION_POINTERS.QueryDirectoryFile(FltObjects->Instance, Fcb->CcFileObject, &FileObjectIdInfo, sizeof(FILE_OBJECTID_INFORMATION), FileObjectIdInformation, TRUE, &strFile, TRUE, &RetLength);
// 		if (NT_SUCCESS(ntStatus))
// 		{
// 			RtlCopyMemory(&Fcb->FileObjectIdInfo, &FileObjectIdInfo, sizeof(FILE_FS_OBJECTID_INFORMATION));
// 		}
// 
// 	}

	PFLT_CALLBACK_DATA NewData = NULL;
	ntStatus = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(ntStatus))
	{
		NewData->Iopb->MajorFunction = IRP_MJ_FILE_SYSTEM_CONTROL;
		NewData->Iopb->MinorFunction = IRP_MN_USER_FS_REQUEST;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer = pBuf;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength = Length;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode = FSCTL_GET_OBJECT_ID;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength = 0;

		NewData->Iopb->Parameters.FileSystemControl.Common.FsControlCode = FSCTL_GET_OBJECT_ID;
		NewData->Iopb->Parameters.FileSystemControl.Common.InputBufferLength = 0;
		NewData->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength = Length;

		NewData->Iopb->Parameters.FileSystemControl.Direct.FsControlCode = FSCTL_GET_OBJECT_ID;
		NewData->Iopb->Parameters.FileSystemControl.Direct.InputBufferLength = 0;
		NewData->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer = pBuf;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputBufferLength = Length;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputMdlAddress = NULL;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputBuffer = pBuf;
			
		NewData->Iopb->Parameters.FileSystemControl.Neither.FsControlCode = FSCTL_GET_OBJECT_ID;
		NewData->Iopb->Parameters.FileSystemControl.Neither.InputBufferLength = 0;
		NewData->Iopb->Parameters.FileSystemControl.Neither.InputBuffer = pBuf;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength = Length;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer = pBuf;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputMdlAddress = NULL;
			
		NewData->Iopb->TargetFileObject = FileObject;
		NewData->Iopb->IrpFlags = Data->Iopb->IrpFlags | IRP_SYNCHRONOUS_API;
		FltPerformSynchronousIo(NewData);
		ntStatus = NewData->IoStatus.Status;
		if (NT_SUCCESS(ntStatus))
		{
			RtlCopyMemory(Fcb->FileObjectIdInfo.ObjectId, FileObjectIdInfo.ObjectId, 16);
			RtlCopyMemory(Fcb->FileObjectIdInfo.ExtendedInfo, FileObjectIdInfo.ExtendedInfo, 48);
		}
		else
		{
			KdPrint(("Get Object Id failed(0x%x)....\n", ntStatus));
		}
	}
	if (NULL != NewData)
	{
		FltFreeCallbackData(NewData);
	}
	return ntStatus;
}

NTSTATUS FsGetFileSecurityInfo(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEFFCB Fcb)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG Length = 0;
	PFLT_CALLBACK_DATA NewData = NULL;
	ntStatus = FltAllocateCallbackData(FltObjects->Instance, Fcb->CcFileObject, &NewData);
	if (NT_SUCCESS(ntStatus))
	{
		NewData->Iopb->MajorFunction = IRP_MJ_QUERY_SECURITY;
		NewData->Iopb->MinorFunction = IRP_MN_NORMAL;

		NewData->Iopb->Parameters.QuerySecurity.Length = Data->Iopb->Parameters.QuerySecurity.Length;
		NewData->Iopb->Parameters.QuerySecurity.MdlAddress = Data->Iopb->Parameters.QuerySecurity.MdlAddress;
		NewData->Iopb->Parameters.QuerySecurity.SecurityBuffer = Data->Iopb->Parameters.QuerySecurity.SecurityBuffer;
		NewData->Iopb->Parameters.QuerySecurity.SecurityInformation = Data->Iopb->Parameters.QuerySecurity.SecurityInformation;

		NewData->Iopb->IrpFlags = IRP_SYNCHRONOUS_API;
		NewData->Iopb->TargetFileObject = Fcb->CcFileObject;
		FltPerformSynchronousIo(NewData);
		ntStatus = NewData->IoStatus.Status;
		Data->IoStatus.Information = NewData->IoStatus.Information;
		Data->IoStatus.Status = ntStatus;
	}
	if (NewData != NULL)
	{
		FltFreeCallbackData(NewData);
	}
	return ntStatus;
}

NTSTATUS FsFileInfoChangedNotify(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	PFILE_RENAME_INFORMATION FileRenameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	WCHAR * pFileName = NULL;
	WCHAR wszDosName[32] = { 0 };//磁盘路径，C:、D:等
	WCHAR wszNtName[SURPORT_NAME_LENGTH] = { 0 };
	UNICODE_STRING strDosName;
	UNICODE_STRING strNtName;
	UNICODE_STRING strFullPath;
	PFLT_FILE_NAME_INFORMATION FileInfo = NULL;
	BOOLEAN bFilter = FALSE;
	WCHAR szExName[32] = { 0 };
	WCHAR * NetDevice = L"\\Device\\Mup";
	USHORT length = 0;
	PDEFFCB pFcb = NULL;
	PVOLUMECONTEXT pVolCtx = NULL;
	BOOLEAN bNetWork = FALSE;
	
	ULONG NetVolumeLength = 0;

	if (!CheckEnv(MINIFILTER_ENV_TYPE_SAFE_DATA))
	{
		return FALSE;
	}
	if (FileDispositionInformation != FileInfoClass && FileRenameInformation != FileInfoClass)
	{
		return ntStatus;
	}
	//KdPrint(("FsFileInfoChangedNotify begin....\n"));
	
	__try
	{
		if (FileRenameInformation == FileInfoClass)
		{
			if (!IsControlProcessByProcessId(PsGetCurrentProcessId(), NULL))
			{
				__leave;
			}
	
			ntStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileInfo);
			if (!NT_SUCCESS(ntStatus))
			{
				__leave;
			}
			
			ntStatus = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
			if (!NT_SUCCESS(ntStatus))
			{
				__leave;
			}
			ExAcquireResourceExclusiveLite(pVolCtx->pEresurce, TRUE);
			if (pVolCtx->uDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
			{
				bNetWork = TRUE;
			}
			ExReleaseResourceLite(pVolCtx->pEresurce);
	
			if (!bNetWork)
			{
				RtlCopyMemory(wszDosName, FileRenameInfo->FileName, 6 * sizeof(WCHAR));
				RtlInitUnicodeString(&strDosName, wszDosName);
				strNtName.Buffer = wszNtName;
				strNtName.Length = SURPORT_NAME_LENGTH;
				strNtName.MaximumLength = SURPORT_NAME_LENGTH;
				if (!GetVolDevNameByQueryObj(&strDosName, &strNtName, &length))
				{
					__leave;
				}
				if (0 == length)
				{
					__leave;
				}
				strNtName.Length = length;
				length += FileRenameInfo->FileNameLength - 6 * sizeof(WCHAR);
			}
			else
			{
				if (FileInfo->Volume.Buffer && FileInfo->Volume.Length > 0)
				{
					NetVolumeLength = FileInfo->Volume.Length;
				}
				else
				{
					NetVolumeLength = wcslen(NetDevice) * sizeof(WCHAR);
				}
				length = FileRenameInfo->FileNameLength - 7 * sizeof(WCHAR) + NetVolumeLength;
			}
			
			pFileName = ExAllocatePoolWithTag(NonPagedPool, length + sizeof(WCHAR), 'refn');
			if (NULL == pFileName)
			{
				__leave;
			}
			RtlZeroMemory(pFileName, length + sizeof(WCHAR));
			if (!bNetWork)
			{
				RtlCopyMemory(pFileName, strNtName.Buffer, strNtName.Length);
				RtlCopyMemory(pFileName + (strNtName.Length / sizeof(WCHAR) - 1), FileRenameInfo->FileName + 6, FileRenameInfo->FileNameLength - 6 * sizeof(WCHAR));
			}
			else
			{
				//\??\UNC\192.....
				if (FileInfo->Volume.Buffer && FileInfo->Volume.Length > 0)
				{
					RtlCopyMemory(pFileName, FileInfo->Volume.Buffer, NetVolumeLength);
				}
				else
				{
					RtlCopyMemory(pFileName, NetDevice, NetVolumeLength);
				}
				RtlCopyMemory(pFileName + NetVolumeLength / sizeof(WCHAR), FileRenameInfo->FileName + 7, FileRenameInfo->FileNameLength - 7 * sizeof(WCHAR));
			}

			//KdPrint(("[%s]rename file:org=%S, dest=%S....\n", __FUNCTION__, FileInfo->Name.Buffer, pFileName));

			RtlInitUnicodeString(&strFullPath, pFileName);
			//判断文件后缀名
			length = 0;
			if (!FsGetFileExtFromFileName(&strFullPath, szExName, &length))
			{
				__leave;
			}
		}
		else
		{
			ntStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileInfo);
			if (!NT_SUCCESS(ntStatus))
			{
				__leave;
			}
			//判断文件后缀名
			if (!FsGetFileExtFromFileName(&FileInfo->Name, szExName, &length))
			{
				__leave;
			}
			pFileName = ExAllocatePoolWithTag(NonPagedPool, FileInfo->Name.Length + sizeof(WCHAR), 'refn');
			if (NULL == pFileName)
			{
				__leave;
			}
			RtlZeroMemory(pFileName, FileInfo->Name.Length + sizeof(WCHAR));
			RtlCopyMemory(pFileName, FileInfo->Name.Buffer, FileInfo->Name.Length);
			//KdPrint(("[%s]delete file:%S....\n", __FUNCTION__, pFileName));
		}
		//过滤包含特定类型的文件??
		if (!IsControlFileType(szExName, length))
		{
			__leave;
		}
		if (FindFcb(Data, pFileName, &pFcb))
		{
			SetFlag(pFcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			//如果文件正在被其他程序打开，create时是否有权限？
			if (FileDispositionInformation == FileInfoClass && 0 == pFcb->OpenCount)
			{
				FsFreeFcb(pFcb, NULL);
			}
		}
		else if (FileRenameInformation == FileInfoClass)
		{
			//受控进程把一个文件重命名为受控类型文件，对此文件进行加密
			KdPrint(("ReName file.....\n"));
			if (Network)
			{
				ntStatus = FsDelayEncrypteFile(FltObjects, strFullPath.Buffer, strFullPath.Length, bNetWork);
			}
			else 
				FsEncrypteFile(Data, FltObjects->Filter, FltObjects->Instance, NULL, 0, FALSE);
		}
	}
	__finally
	{
		if (NULL != pVolCtx)
		{
			FltReleaseContext(pVolCtx);
		}

		if (pFileName != NULL)
		{
			ExFreePoolWithTag(pFileName, 'refn');
		}

		if (FileInfo != NULL)
		{
			FltReleaseFileNameInformation(FileInfo);
		}
	}

	//KdPrint(("FsFileInfoChangedNotify end....\n"));
	return ntStatus;
}
//获取进程完整路径名
NTSTATUS FsGetProcessName(__in ULONG ProcessID, __inout PUNICODE_STRING ProcessImageName)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	HANDLE hProcess = NULL;
	PEPROCESS Eprocess = NULL;
	ULONG RetLength = 0;
	ULONG BufferLength = 0;
	PVOID Buffer = NULL;
	PUNICODE_STRING ImagePath = NULL;
	USHORT i = 0;
	PWCHAR pTmp = NULL;
	USHORT ProcessNameLength = 0;

	__try
	{
		if (4 == ProcessID || 0 == ProcessID)
		{
			//系统进程，暂不处理
			__leave;
		}
		if (NULL == g_DYNAMIC_FUNCTION_POINTERS.QueryInformationProcess)
		{
			__leave;
		}
		ntStatus = PsLookupProcessByProcessId((HANDLE)ProcessID, &Eprocess);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ntStatus = ObOpenObjectByPointer(Eprocess, OBJ_KERNEL_HANDLE, NULL, GENERIC_READ, *PsProcessType, KernelMode, &hProcess);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ntStatus = g_DYNAMIC_FUNCTION_POINTERS.QueryInformationProcess(hProcess, ProcessImageFileName, NULL, 0, &RetLength);
		if (STATUS_INFO_LENGTH_MISMATCH != ntStatus)
		{
			__leave;
		}

		if (RetLength > MAX_PATH || RetLength <= sizeof (UNICODE_STRING))
		{
			KdPrint(("QueryInformationProcess:Retlength > %d...\n", MAX_PATH));
			__leave;
		}
		BufferLength = RetLength - sizeof (UNICODE_STRING);
		Buffer = ExAllocatePoolWithTag(PagedPool, RetLength, 'proc');
		if (NULL == Buffer)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}
		ntStatus = g_DYNAMIC_FUNCTION_POINTERS.QueryInformationProcess(hProcess, ProcessImageFileName, Buffer, RetLength, &RetLength);
		if (NT_SUCCESS(ntStatus) && Buffer != NULL)
		{
			ImagePath = (PUNICODE_STRING)Buffer;
			//RtlCopyUnicodeString(ProcessImagePath, ImagePath);
			if (ImagePath->Length / sizeof(WCHAR) > MAX_PATH)
			{
				__leave;
			}
			//取进程名
			pTmp = ImagePath->Buffer + ImagePath->Length / sizeof(WCHAR);
			for (i = 0; i < ImagePath->Length / sizeof(WCHAR); i++)
			{
				if (L'\\' == pTmp[0])
				{
					RtlCopyMemory(ProcessImageName->Buffer, pTmp + 1, ProcessNameLength * sizeof(WCHAR));
					break;
				}
				pTmp -= 1;
				ProcessNameLength++;
			}
			ProcessImageName->Length = ProcessNameLength * sizeof(WCHAR);
		}
	}
	__finally
	{
		if (Eprocess != NULL)
		{
			ObDereferenceObject(Eprocess);
		}
		if (hProcess != NULL)
		{
			ZwClose(hProcess);
		}
		if (Buffer != NULL)
		{
			ExFreePoolWithTag(Buffer, 'proc');
		}
	}

	return ntStatus;
}

NTSTATUS FsGetCcFileInfo(__in PFLT_FILTER Filter, __in PFLT_INSTANCE Instance, __in PWCHAR FileName, __inout PHANDLE CcFileHandle, __inout  PVOID * CcFileObject, __in BOOLEAN NetWork)
{
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING unicodeString;
	IO_STATUS_BLOCK IoStatus;
	OBJECT_ATTRIBUTES ob;
	ULONG Options = FILE_NON_DIRECTORY_FILE;
	SetFlag(Options, FILE_WRITE_THROUGH);
	ACCESS_MASK DesiredAccess = FILE_SPECIAL_ACCESS;
	ULONG ShareAccess = 0;
	if (NetWork)
	{
		DesiredAccess = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES;
		SetFlag(DesiredAccess, READ_CONTROL);
		SetFlag(DesiredAccess, SYNCHRONIZE);
		SetFlag(ShareAccess, FILE_SHARE_READ);
		Options |= (FILE_SYNCHRONOUS_IO_NONALERT | GENERIC_ALL);
	}

	__try
	{
		RtlInitUnicodeString(&unicodeString, FileName);
		InitializeObjectAttributes(&ob, &unicodeString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		status = FltCreateFile(Filter, Instance, CcFileHandle, DesiredAccess, &ob, &IoStatus,
			NULL, FILE_ATTRIBUTE_NORMAL, ShareAccess, FILE_OPEN, Options, NULL, 0, 0);
		if (!NT_SUCCESS(status))
		{
			__leave;
		}
		
		status = ObReferenceObjectByHandle(*CcFileHandle, 0, *IoFileObjectType, KernelMode, CcFileObject, NULL);
		if (!NT_SUCCESS(status))
		{
			FltClose(*CcFileHandle);
			*CcFileHandle = NULL;
			__leave;
		}
	}
	__finally
	{
	}
	return status;
}

VOID FsFreeCcFileInfo(__in PHANDLE CcFileHandle, __in PVOID * CcFileObject)
{
	if (*CcFileObject != NULL)
	{
		ObDereferenceObject(*CcFileObject);
		FltClose(*CcFileHandle);
	}
	*CcFileObject = NULL;
	*CcFileHandle = NULL;
}

NTSTATUS FsEncrypteFile(__in PFLT_CALLBACK_DATA Data, __in PFLT_FILTER Filter, __in PFLT_INSTANCE Instance, __in  PWCHAR FilePath, __in ULONG FileLength, __in BOOLEAN Network)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	WCHAR * pFileName = NULL;
	PFLT_FILE_NAME_INFORMATION FileNameInfo = NULL;
	WCHAR szTmpName[5] = { L".tmp" };
	ULONG TmpNameLength = sizeof(szTmpName)-sizeof(WCHAR);
	ULONG LengthPathOrg = 0;
	ULONG LengthTmpPath = 0;//include '\0'

	OBJECT_ATTRIBUTES ob;
	HANDLE Handle = NULL;
	PFILE_OBJECT FileObject = NULL;
	HANDLE HandleTmp = NULL;
	PFILE_OBJECT FileObjectTmp = NULL;
	IO_STATUS_BLOCK IoStatus;
	UNICODE_STRING FileString = { 0 };
	
	LARGE_INTEGER ByteOffset = {0};
	LARGE_INTEGER OrgByteOffset = {0};
	FILE_STANDARD_INFORMATION FileInfo = { 0 };
	PUCHAR pBuffer = NULL;
	PUCHAR pHeader = NULL;
	ULONG RetReadLength = 0;

	__try
	{
		if (NULL == FilePath)
		{
			ntStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileNameInfo);
			if (!NT_SUCCESS(ntStatus))
			{
				__leave;
			}
			LengthPathOrg = FileNameInfo->Name.Length;
			LengthTmpPath = LengthPathOrg + TmpNameLength + sizeof(WCHAR);
			pFileName = ExAllocatePoolWithTag(NonPagedPool, LengthTmpPath, 'enfn');
			if (NULL == pFileName)
			{
				__leave;
			}
			RtlZeroMemory(pFileName, LengthTmpPath);
			RtlCopyMemory(pFileName, FileNameInfo->Name.Buffer, LengthPathOrg);
		}
		else
		{
			LengthPathOrg = FileLength;
			LengthTmpPath = LengthPathOrg + TmpNameLength + sizeof(WCHAR);
			pFileName = ExAllocatePoolWithTag(NonPagedPool, LengthTmpPath, 'enfn');
			if (NULL == pFileName)
			{
				__leave;
			}
			RtlZeroMemory(pFileName, LengthTmpPath);
			RtlCopyMemory(pFileName, FilePath, LengthPathOrg);
		}
		
		ntStatus = FsGetCcFileInfo(Filter, Instance, pFileName, &Handle, &FileObject, Network);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ntStatus = FltQueryInformationFile(Instance, FileObject, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}

		if (0 == FileInfo.EndOfFile.QuadPart)
		{
			ntStatus = FsWriteFileHeader(Instance, FileObject, NULL);
			__leave;
		}

		if (FileInfo.EndOfFile.QuadPart >= ENCRYPT_HEAD_LENGTH)
		{
			LARGE_INTEGER Offset = { 0 };
			ULONG EncrypteType = 0;
			PUCHAR DecrypteHeader = NULL;

			pHeader = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ENCRYPT_HEAD_LENGTH, 'fsfh');
			if (NULL == pHeader)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}
			RtlZeroMemory(pHeader, ENCRYPT_HEAD_LENGTH);
			DecrypteHeader = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ENCRYPT_HEAD_LENGTH, 'fsfh');
			if (NULL == DecrypteHeader)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}
			RtlZeroMemory(DecrypteHeader, ENCRYPT_HEAD_LENGTH);

			ntStatus = FltReadFile(Instance,
				FileObject,
				&Offset,
				ENCRYPT_HEAD_LENGTH,
				pHeader,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				NULL, NULL, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("[%s]FltReadFile failed(0x%x)...\n", __FUNCTION__, ntStatus));
				__leave;
			}
			if (IsEncryptedFileHead(pHeader, &EncrypteType, DecrypteHeader))
			{
				KdPrint(("[%s]IsEncryptedFileHead ,so return...\n", __FUNCTION__));
				FltFreePoolAlignedWithTag(Instance, DecrypteHeader, 'fsfh');
				__leave;
			}
			FltFreePoolAlignedWithTag(Instance, DecrypteHeader, 'fsfh');
		}

		RtlCopyMemory(pFileName + LengthPathOrg / sizeof(WCHAR), szTmpName, TmpNameLength);
		FileString.Buffer = pFileName;
		FileString.Length = LengthTmpPath - sizeof(WCHAR);
		FileString.MaximumLength = LengthTmpPath;

		InitializeObjectAttributes(&ob, &FileString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
		ntStatus = FltCreateFile(Filter,
			Instance,
			&HandleTmp,
			FILE_READ_DATA | FILE_WRITE_DATA | DELETE,
			&ob,
			&IoStatus,
			NULL,
			FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_TEMPORARY,
			FILE_SHARE_VALID_FLAGS,
			FILE_OVERWRITE_IF,
			FILE_DELETE_ON_CLOSE | FILE_NON_DIRECTORY_FILE,
			NULL,
			0,
			IO_IGNORE_SHARE_ACCESS_CHECK);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s]FltCreateFile failed(0x%x)....\n", __FUNCTION__, ntStatus));
			__leave;
		}
		ntStatus = ObReferenceObjectByHandle(HandleTmp, 0, *IoFileObjectType, KernelMode, &FileObjectTmp, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			FltClose(HandleTmp);
			__leave;
		}

		if (NULL == pHeader)
		{
			pHeader = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ENCRYPT_HEAD_LENGTH, 'fsfh');
			if (NULL == pHeader)
			{
				ntStatus = STATUS_INSUFFICIENT_RESOURCES;
				__leave;
			}
		}
		RtlZeroMemory(pHeader, ENCRYPT_HEAD_LENGTH);

		//从原文件中读取内容加密后写到tmp文件中，然后把tmp文件里的内容读出写到原文件
		ntStatus = FsWriteFileHeader(Instance, FileObjectTmp, pHeader);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		pBuffer = FltAllocatePoolAlignedWithTag(Instance, NonPagedPool, ENCRYPT_HEAD_LENGTH, 'fsfh');
		if (NULL == pBuffer)
		{
			ntStatus = STATUS_INSUFFICIENT_RESOURCES;
			__leave;
		}

		OrgByteOffset.QuadPart = 0;
		ByteOffset.QuadPart += ENCRYPT_HEAD_LENGTH;
		//这里是否该考虑写失败情况？
		while (OrgByteOffset.QuadPart < FileInfo.AllocationSize.QuadPart)
		{
			RtlZeroMemory(pBuffer, ENCRYPT_HEAD_LENGTH);
			ntStatus = FltReadFile(Instance,
				FileObject,
				&OrgByteOffset,
				ENCRYPT_HEAD_LENGTH,
				pBuffer,
				/*FLTFL_IO_OPERATION_NON_CACHED | */FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, //非缓存的打开
				&RetReadLength, NULL, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				break;
			}
			//todo::加密内容
			EncBuf(pBuffer, RetReadLength, pHeader);
			//
			ntStatus = FltWriteFile(Instance,
				FileObjectTmp,
				&ByteOffset,
				RetReadLength,
				pBuffer,
				/*FLTFL_IO_OPERATION_NON_CACHED | */FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, //非缓存的打开
				&RetReadLength, NULL, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				break;
			}
			OrgByteOffset.QuadPart += RetReadLength;
			ByteOffset.QuadPart += RetReadLength;
		}
		//设置文件的大小等等信息
		if (!NT_SUCCESS(ntStatus) && ntStatus != STATUS_END_OF_FILE)
		{
			CHAR szBuf[128] = { 0 };
			sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
			LogFile(Filter, Instance, szBuf, strlen(szBuf));
			__leave;
		}
		FILE_END_OF_FILE_INFORMATION FileEndInfo;
		FileEndInfo.EndOfFile.QuadPart = FileInfo.EndOfFile.QuadPart + ENCRYPT_HEAD_LENGTH;
		ntStatus = FltSetInformationFile(Instance,
			FileObjectTmp,
			&FileEndInfo,
			sizeof(FILE_END_OF_FILE_INFORMATION),
			FileEndOfFileInformation);
		if (!NT_SUCCESS(ntStatus))
		{
			CHAR szBuf[128] = { 0 };
			sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
			LogFile(Filter, Instance, szBuf, strlen(szBuf));
			__leave;
		}
		//把加密文件写回去
		ByteOffset.QuadPart = 0;
		while (ByteOffset.QuadPart < (FileInfo.AllocationSize.QuadPart + ENCRYPT_HEAD_LENGTH))
		{
			RtlZeroMemory(pBuffer, ENCRYPT_HEAD_LENGTH);
			ntStatus = FltReadFile(Instance,
				FileObjectTmp,
				&ByteOffset,
				ENCRYPT_HEAD_LENGTH,
				pBuffer,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, 
				&RetReadLength, NULL, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				CHAR szBuf[128] = { 0 };
				sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
				LogFile(Filter, Instance, szBuf, strlen(szBuf));
				break;
			}
			ntStatus = FltWriteFile(Instance,
				FileObject,
				&ByteOffset,
				RetReadLength,
				pBuffer,
				FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
				NULL, NULL, NULL);
			if (!NT_SUCCESS(ntStatus))
			{
				CHAR szBuf[128] = { 0 };
				sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
				LogFile(Filter, Instance, szBuf, strlen(szBuf));
				break;
			}
			ByteOffset.QuadPart += RetReadLength;
		}
		//设置文件的大小
		if (NT_SUCCESS(ntStatus) || STATUS_END_OF_FILE == ntStatus)
		{
			FILE_END_OF_FILE_INFORMATION FileEndInfo;
			FILE_ALLOCATION_INFORMATION FileAllocateInfo;
			LARGE_INTEGER TmpLI = { 0 };

			FileEndInfo.EndOfFile = FileInfo.EndOfFile;
			FileEndInfo.EndOfFile.QuadPart += ENCRYPT_HEAD_LENGTH;
			TmpLI.QuadPart = FileEndInfo.EndOfFile.QuadPart;
			ntStatus = FltSetInformationFile(Instance,
				FileObject,
				&FileEndInfo,
				sizeof(FILE_END_OF_FILE_INFORMATION),
				FileEndOfFileInformation);
			if (!NT_SUCCESS(ntStatus))
			{
				CHAR szBuf[128] = { 0 };
				sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
				LogFile(Filter, Instance, szBuf, strlen(szBuf));
				__leave;
			}
			FileAllocateInfo.AllocationSize.QuadPart = FileEndInfo.EndOfFile.QuadPart;
			ntStatus = FltSetInformationFile(Instance,
				FileObject,
				&FileAllocateInfo,
				sizeof(FILE_ALLOCATION_INFORMATION),
				FileAllocationInformation);
			if (!NT_SUCCESS(ntStatus))
			{
				CHAR szBuf[128] = { 0 };
				sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
				LogFile(Filter, Instance, szBuf, strlen(szBuf));
				__leave;
			}
		}		
		
	}
	__finally
	{
		if (NULL != pFileName)
		{
			ExFreePoolWithTag(pFileName, 'enfn');
			pFileName = NULL;
		}
		if (NULL != FileNameInfo)
		{
			FltReleaseFileNameInformation(FileNameInfo);
			FileNameInfo = NULL;
		}
		if (NULL != Handle)
		{
			FsFreeCcFileInfo(&Handle, &FileObject);
		}
		if (NULL != FileObjectTmp)
		{
			ObDereferenceObject(FileObjectTmp);
		}
		if (NULL != HandleTmp)
		{
			FltClose(HandleTmp);
		}

		if (NULL != pBuffer)
		{
			FltFreePoolAlignedWithTag(Instance, pBuffer, 'fsfh');
		}
		if (NULL != pHeader)
		{
			FltFreePoolAlignedWithTag(Instance, pHeader, 'fsfh');
		}
	}
	CHAR szBuf[128] = { 0 };
	sprintf(szBuf, "[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__);
	KdPrint(("[%s]failed(0x%x), line=%d...\n", __FUNCTION__, ntStatus, __LINE__));
	LogFile(Filter, Instance, szBuf, strlen(szBuf));
	return ntStatus;
}

VOID LogFile(__in PFLT_FILTER Filter, __in PFLT_INSTANCE Instance, __in PVOID Buffer, __in ULONG Length)
{
	return;
	NTSTATUS ntStatus;
	HANDLE HandleTmp = NULL;
	PFILE_OBJECT FileObjectTmp = NULL;
	FILE_STANDARD_INFORMATION FileInfo = { 0 };
	WCHAR szFile[128] = { L"\\Device\\Mup\\192.168.0.216\\DS Client\\1.log" };//\\Device\\HarddiskVolume1
	LARGE_INTEGER ByteOffset = { 0 };
	ULONG RetLength = 0;

	__try
	{
		ntStatus = FsGetCcFileInfo(Filter, Instance, szFile, &HandleTmp, &FileObjectTmp, TRUE);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s]FltCreateFile failed(0x%x)....\n", __FUNCTION__, ntStatus));
			__leave;
		}
		ntStatus = FltQueryInformationFile(Instance, FileObjectTmp, &FileInfo, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ByteOffset.QuadPart = FileInfo.EndOfFile.QuadPart;
		ntStatus = FltWriteFile(Instance,
			FileObjectTmp,
			&ByteOffset,
			Length,
			Buffer,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, //非缓存的打开
			&RetLength, NULL, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ByteOffset.QuadPart += RetLength;
		UCHAR sz[1] = { "\n" };
		ntStatus = FltWriteFile(Instance,
			FileObjectTmp,
			&ByteOffset,
			1,
			sz,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET, //非缓存的打开
			&RetLength, NULL, NULL);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		FILE_END_OF_FILE_INFORMATION FileEndInfo;
		FileEndInfo.EndOfFile.QuadPart = ByteOffset.QuadPart + RetLength;
		ntStatus = FltSetInformationFile(Instance,
			FileObjectTmp,
			&FileEndInfo,
			sizeof(FILE_END_OF_FILE_INFORMATION),
			FileEndOfFileInformation);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
	}
	__finally
	{
		if (NULL != FileObjectTmp)
		{
			ObDereferenceObject(FileObjectTmp);
		}
		if (NULL != HandleTmp)
		{
			FltClose(HandleTmp);
		}
	}

}
#define DELAY_ONE_MICROSECOND   (-10)
#define DELAY_ONE_MILLISECOND   (DELAY_ONE_MICROSECOND*1000)
void EncrypteFileThread(PVOID Context)
{
	NTSTATUS ntStatus;
	PDEFFCB Fcb = NULL;
	THREAD_PARAM * Param = (THREAD_PARAM *)Context;
	PEPROCESS  Process = NULL;
	int Counts = 0;
	if (NULL == Param)
	{
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	ntStatus = PsLookupProcessByProcessId(GetClientProcessId(), &Process);
	if (!NT_SUCCESS(ntStatus))
	{
		KdPrint(("[%s]PsLookupProcessByProcessId failed...\n", __FUNCTION__));
		PsTerminateSystemThread(STATUS_SUCCESS);
		return;
	}
	KeAttachProcess(Process);

	while (TRUE)
	{
		if (Counts > 3)
		{
			break;
		}
		Counts++;
		KeSleep(2000);
		if (FindFcb(NULL, Param->FilePath, &Fcb) && Fcb->OpenCount != 0)
		{

		}
		else
		{
			ntStatus = FsEncrypteFile(NULL, Param->Filter, Param->Instance, Param->FilePath, Param->Length - sizeof(WCHAR), Param->NetFile);
			if (NT_SUCCESS(ntStatus))
			{
				break;
			}
		}
	}
	KeDetachProcess();
	if (Process != NULL)
	{
		ObDereferenceObject(Process);
	}
	ExFreePoolWithTag(Param->FilePath, 'tpfp');
	ExFreePoolWithTag(Param, 'tpfp');

	PsTerminateSystemThread(STATUS_SUCCESS);
}

NTSTATUS FsDelayEncrypteFile(__in PCFLT_RELATED_OBJECTS FltObjects, __in PWCHAR FilePath, __in ULONG Length, __in BOOLEAN NetFile)
{
	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	HANDLE ThreadHandle = NULL;
	CLIENT_ID ID = { 0 };
	THREAD_PARAM * Param = NULL;
	OBJECT_ATTRIBUTES ob = { 0 };
	//PEPROCESS  Process = NULL;

	__try
	{
		Param = ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_PARAM), 'tpfp');
		if (NULL == Param)
		{
			__leave;
		}
		Param->Length = Length + sizeof(WCHAR);
		Param->FilePath = ExAllocatePoolWithTag(NonPagedPool, Param->Length, 'tpfp');
		if (NULL == Param->FilePath)
		{
			KdPrint(("[%s]ExAllocatePoolWithTag failed...\n", __FUNCTION__));
			__leave;
		}
		RtlZeroMemory(Param->FilePath, Length);
		RtlCopyMemory(Param->FilePath, FilePath, Length);
		Param->Filter = FltObjects->Filter;
		Param->Instance = FltObjects->Instance;
		Param->NetFile = NetFile;
		InitializeObjectAttributes(&ob, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
		ntStatus = PsCreateSystemThread(&ThreadHandle, THREAD_ALL_ACCESS, &ob, NULL, NULL, (PKSTART_ROUTINE)EncrypteFileThread, (PVOID)Param);
	}
	__finally
	{
		if (!NT_SUCCESS(ntStatus))
		{
			if (Param->FilePath)
			{
				ExFreePoolWithTag(Param->FilePath, 'tpfp');
			}
			if (Param)
			{
				ExFreePoolWithTag(Param, 'tpfp');
			}
		}
	}

	return ntStatus;
}

VOID KeSleep(LONG MilliSecond)
{
	LARGE_INTEGER Interval = { 0 };
	Interval.QuadPart = DELAY_ONE_MILLISECOND;
	Interval.QuadPart *= MilliSecond;
	KeDelayExecutionThread(KernelMode, 0, &Interval);
}

#define RECYCLE_BIN_FILE L"$Recycle.Bin"
BOOLEAN IsRecycleBinFile(__in PWCHAR  FilePath, __in USHORT Length)
{
	//\Device\HarddiskVolume1\$Recycle.Bin
	PWCHAR pTmp = NULL;
	USHORT Index = 0;
	USHORT Count = 0;
	while (Index < Length)
	{
		if ('\\' == *(FilePath + Index))
		{
			Count++;
		}
		if (3 == Count)
		{
			break;
		}
		Index++;
	}
	Count = wcslen(RECYCLE_BIN_FILE);
	pTmp = FilePath + Index + 1;
	if (Count + Index <= Length && 0 == wcsnicmp(pTmp, RECYCLE_BIN_FILE, Count))
	{
		return TRUE;
	}
	return FALSE;
}

