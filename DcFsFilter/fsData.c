#include "fsData.h"
#include "fatstruc.h"
#include "defaultStruct.h"
#include <ntifs.h>
#include <wdm.h>
#include "fsCreate.h"

NPAGED_LOOKASIDE_LIST  g_IrpContextLookasideList;
NPAGED_LOOKASIDE_LIST  g_FcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_EResourceLookasideList;
NPAGED_LOOKASIDE_LIST  g_CcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_IoContextLookasideList;
DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS = {0};
NPAGED_LOOKASIDE_LIST g_NTFSFCBLookasideList;
NPAGED_LOOKASIDE_LIST g_FastMutexInFCBLookasideList;

ULONG g_OsMajorVersion = 0;
ULONG g_OsMinorVersion = 0;

CACHE_MANAGER_CALLBACKS g_CacheManagerCallbacks = {0};

LARGE_INTEGER  Li0 = { 0, 0 };
LARGE_INTEGER  Li1 = { 1, 0 };

NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

BOOLEAN IsFilterProcess(IN PFLT_CALLBACK_DATA Data, IN PNTSTATUS pStatus, IN PULONG pProcType)
{
	PFLT_FILE_NAME_INFORMATION FileInfo = NULL;
	HANDLE ProcessId = NULL;
	PEPROCESS Process = NULL;
	PUCHAR ProcessName;
	BOOLEAN bFilter = FALSE;
	UNICODE_STRING unicodeString;
	RtlInitUnicodeString(&unicodeString, L"\\Device\\HarddiskVolume1\\1.docx");

	UNREFERENCED_PARAMETER(pProcType);

	//先判断文件是否为加密文件，再判断访问进程是否为受控进程(可以不区分先后)

	__try
	{
		*pStatus = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED, &FileInfo);
		if (!NT_SUCCESS(*pStatus))
		{
			__leave;
		}
		//DbgPrint("FileName=%S....\n", FileInfo->Name.Buffer ? FileInfo->Name.Buffer : L"none");
		//test
		if (0 != RtlCompareUnicodeString(&(FileInfo->Name), &unicodeString, TRUE))
		{
			__leave;
		}

		ProcessId = PsGetCurrentProcessId();
		if (NULL == ProcessId)
		{
			*pStatus = STATUS_UNSUCCESSFUL;
			__leave;
		}
		*pStatus = PsLookupProcessByProcessId(ProcessId, &Process);
		if (!NT_SUCCESS(*pStatus))
		{
			__leave;
		}
		ProcessName = PsGetProcessImageFileName(Process);
		//DbgPrint("ProcessName=%s....\n", ProcessName ? ProcessName : "none");
		if (0 == stricmp("wps.exe", ProcessName))
		{
			bFilter = TRUE;
		}
	}
	__finally
	{
		if (FileInfo != NULL)
		{
			FltReleaseFileNameInformation(FileInfo);
		}
		if (Process != NULL)
		{
			ObDereferenceObject(Process);
		}
	}

	return bFilter;
}


VOID InitData()
{
	RtlZeroMemory(szVcbPlacer, sizeof(UCHAR)* 300);
	UNICODE_STRING RoutineString = { 0 };
	ExInitializeNPagedLookasideList(&g_IrpContextLookasideList, NULL, NULL, 0, sizeof(DEF_IRP_CONTEXT), 'IRC', 0);
	ExInitializeNPagedLookasideList(&g_IoContextLookasideList, NULL, NULL, 0, sizeof(DEF_IO_CONTEXT), 'IOC', 0);
	ExInitializeNPagedLookasideList(&g_FcbLookasideList, NULL, NULL, 0, sizeof(DEFFCB), 'FCB', 0);
	ExInitializeNPagedLookasideList(&g_CcbLookasideList, NULL, NULL, 0, sizeof(CCB), 'CCB', 0);
	ExInitializeNPagedLookasideList(&g_EResourceLookasideList, NULL, NULL, 0, sizeof(ERESOURCE), 'Res', 0);
	ExInitializePagedLookasideList(&g_EncryptFileListLookasideList, NULL, NULL, 0, sizeof(ENCRYPT_FILE_FCB), 'efl', 0);
	ExInitializeNPagedLookasideList(&g_NTFSFCBLookasideList, NULL, NULL, 0, sizeof(NTFS_FCB), 'ntfb', 0);
	ExInitializeNPagedLookasideList(&g_FastMutexInFCBLookasideList, NULL, NULL, 0, sizeof(FAST_MUTEX), 'fsmt', 0);

	g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx = (fltCheckOplockEx)FltGetRoutineAddress("FltCheckOplockEx");
	g_DYNAMIC_FUNCTION_POINTERS.OplockBreakH = (fltOplockBreakH)FltGetRoutineAddress("FltOplockBreakH");

	RtlInitUnicodeString(&RoutineString, L"MmDoesFileHaveUserWritableReferences");
	g_DYNAMIC_FUNCTION_POINTERS.pMmDoesFileHaveUserWritableReferences = (fMmDoesFileHaveUserWritableReferences)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"FsRtlChangeBackingFileObject");
	g_DYNAMIC_FUNCTION_POINTERS.pFsRtlChangeBackingFileObject = (fsRtlChangeBackingFileObject)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"RtlGetVersion");
	g_DYNAMIC_FUNCTION_POINTERS.pGetVersion = (fsGetVersion)MmGetSystemRoutineAddress(&RoutineString);

	g_CacheManagerCallbacks.AcquireForLazyWrite = &FsAcquireFcbForLazyWrite;
	g_CacheManagerCallbacks.ReleaseFromLazyWrite = &FsReleaseFcbFromLazyWrite;
	g_CacheManagerCallbacks.AcquireForReadAhead = &FsAcquireFcbForReadAhead;
	g_CacheManagerCallbacks.ReleaseFromReadAhead = &FsReleaseFcbFromReadAhead;

	InitializeListHead(&g_FcbEncryptFileList);
}

VOID UnInitData()
{
	ExDeleteNPagedLookasideList(&g_FcbLookasideList);
	ExDeleteNPagedLookasideList(&g_CcbLookasideList);
	ExDeleteNPagedLookasideList(&g_EResourceLookasideList);
	ExDeleteNPagedLookasideList(&g_IrpContextLookasideList);
	ExDeleteNPagedLookasideList(&g_IoContextLookasideList);
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
		pIrpContext->ProcessId = PsGetCurrentThread();
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
	if (!ExAcquireResourceSharedLite(pFcb->Header.PagingIoResource, Wait))
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
	if (pFcb->Header.PagingIoResource)
	{
		ExReleaseResourceLite(pFcb->Header.PagingIoResource);
	}
}

//预读
BOOLEAN FsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait)
{
	DEFFCB * pFcb = (DEFFCB*)Fcb;
	
	PAGED_CODE();

	if (NULL == pFcb || !ExAcquireResourceSharedLite(pFcb->Header.Resource, Wait))
	{
		return FALSE;
	}
	IoSetTopLevelIrp((PIRP)FSRTL_CACHE_TOP_LEVEL_IRP);
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

BOOLEAN FindFcb(WCHAR * pwszFile, PDEFFCB * pFcb)
{
	BOOLEAN bAcquireResource = FALSE;
	PENCRYPT_FILE_FCB pFileFcb = NULL;
	BOOLEAN bRet = FALSE;
	PLIST_ENTRY pListEntry;
	PENCRYPT_FILE_FCB pContext = NULL;

	if (NULL == pFcb || NULL == pwszFile || wcslen(pwszFile) <= 0)
	{
		return FALSE;
	}

	__try
	{
		FsRtlEnterFileSystem();
		ExAcquireResourceExclusiveLite(&g_FcbResource, TRUE);
		bAcquireResource = TRUE;
		if (IsListEmpty(&g_FcbEncryptFileList))
		{
			bRet = FALSE;
			__leave;
		}
		for (pListEntry = g_FcbEncryptFileList.Flink; pListEntry != &g_FcbEncryptFileList; pListEntry = pListEntry->Flink)
		{
			pContext = CONTAINING_RECORD(pListEntry, ENCRYPT_FILE_FCB, listEntry);
			if (pContext && pContext->Fcb && 0 == wcsicmp(pwszFile, pContext->Fcb->wszFile))
			{
				*pFcb = pContext->Fcb;
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

					break;
				case IRP_MJ_WRITE:

					break;
				case IRP_MJ_QUERY_INFORMATION:

					break;
				case IRP_MJ_SET_INFORMATION:

					break;
				case IRP_MJ_SET_EA:

					break;
				case IRP_MJ_QUERY_EA:

					break;
				case IRP_MJ_FLUSH_BUFFERS:

					break;
				case IRP_MJ_CLEANUP:

					break;
				case IRP_MJ_LOCK_CONTROL:

					break;
				case IRP_MJ_QUERY_SECURITY:

					break;
				case IRP_MJ_SET_SECURITY:

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
				FsRaiseStatus(IrpContext, ExceptionCode);
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
NTSTATUS MyGetFileStandardInfo(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObject, __inout PDEF_IRP_CONTEXT IrpContext)
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


NTSTATUS FsCreatedFileHeaderInfo(__in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = NULL;
	LARGE_INTEGER ByteOffset = {0};
	FILE_BASIC_INFORMATION FileInfo = {0};
	ByteOffset.QuadPart = 0;

	FileObject = IrpContext->createInfo.pStreamObject;
	IrpContext->createInfo.pFileHeader = FltAllocatePoolAlignedWithTag(FltObjects->Instance, PagedPool, FILE_HEADER_LENGTH, 'fh');
	if (NULL == IrpContext->createInfo.pFileHeader)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	if (IrpContext->createInfo.FileSize.QuadPart >= FILE_HEADER_LENGTH)
	{
		RtlZeroMemory(IrpContext->createInfo.pFileHeader, FILE_HEADER_LENGTH);
		
		Status = FltReadFile(FltObjects->Instance, FileObject, &ByteOffset, FILE_HEADER_LENGTH, IrpContext->createInfo.pFileHeader,
			FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			NULL, NULL, NULL);
		if (NT_SUCCESS(Status))
		{
			/*
			if ((RtlCompareMemory(IrpContext->CreateInfo.pFileHeader->FileBegin, FileBegin, sizeof(FileBegin)) == sizeof(FileBegin))
				&& (RtlCompareMemory(IrpContext->CreateInfo.pFileHeader->Flag, Flag, sizeof(Flag)) == sizeof(Flag)))
			{
				IrpContext->CreateInfo.IsEnFile = TRUE;
				IrpContext->CreateInfo.DecrementHeader = TRUE;
				IrpContext->CreateInfo.IsWriteHeader = TRUE;
			}
			*/
		}
	}
	//获取文件的访问权限
	if (NT_SUCCESS(Status))
	{
		Status = FltQueryInformationFile(FltObjects->Instance, FileObject, &FileInfo, sizeof(FILE_BASIC_INFORMATION), FileBasicInformation, NULL);
		if (NT_SUCCESS(Status))
		{
			if (FlagOn(FileInfo.FileAttributes, FILE_ATTRIBUTE_READONLY))
			{
				IrpContext->createInfo.FileAccess = FILE_READ_ACCESS;
			}
			else
			{
				IrpContext->createInfo.FileAccess = FILE_WRITE_ACCESS;
			}
			RtlCopyMemory(&IrpContext->createInfo.BaseInfo, &FileInfo, sizeof(FILE_BASIC_INFORMATION));
		}
	}

	if (NULL != IrpContext->createInfo.pFileHeader)
	{
		FltFreePoolAlignedWithTag(FltObjects->Instance, IrpContext->createInfo.pFileHeader, 'fh');
		IrpContext->createInfo.pFileHeader = NULL;
	}
	return Status;
}

NTSTATUS FsCreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	NTSTATUS status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ob;
	IO_STATUS_BLOCK IoStatus;
	PFILE_OBJECT FileObject;
	BOOLEAN bAdvancedHeader = FALSE;
	ULONG ClusterSize = 0;
	LARGE_INTEGER Temp;
	ULONG Options = 0;
	UNICODE_STRING unicodeString;

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
		
		bAdvancedHeader = TRUE;
		//todo::如果解密，需减去加密头的长度
// 		if (IrpContext->createInfo.bDecrementHeader)
// 		{
// 			IrpContext->createInfo.FileSize.QuadPart -= FILE_HEADER_LENGTH;
// 			IrpContext->createInfo.FileAllocationSize.QuadPart -= FILE_HEADER_LENGTH;
// 		}
		
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
		Fcb->LastModificationTime = IrpContext->createInfo.BaseInfo.LastWriteTime.QuadPart;
		Fcb->LinkCount = IrpContext->createInfo.NumberOfLinks;
		Fcb->DeletePending = IrpContext->createInfo.DeletePending;
		Fcb->Directory = IrpContext->createInfo.Directory;
		Fcb->OpenCount = IrpContext->createInfo.pStreamObject ? 1 : 0;
		Fcb->OpenHandleCount = IrpContext->createInfo.hStreamHanle ? 1 : 0;

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
		Fcb->bEnFile = IrpContext->createInfo.bEnFile;
		if (Fcb->bEnFile && FlagOn(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED))
		{
			Fcb->FileHeaderLength = FILE_HEADER_LENGTH;
		}
		if (TRUE/*FLT_FILE_LOCK*/)
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
		
		Fcb->CacheType = CACHE_ALLOW;
		Fcb->FileType = IrpContext->createInfo.uProcType;
		
		if (IrpContext->createInfo.nameInfo->Name.Length < 128)
		{
			RtlCopyMemory(Fcb->wszFile, IrpContext->createInfo.nameInfo->Name.Buffer, IrpContext->createInfo.nameInfo->Name.Length);
		}
		else
			RtlCopyMemory(Fcb->wszFile, IrpContext->createInfo.nameInfo->Name.Buffer, 127);
#if 1		
		if (!IrpContext->createInfo.bNetWork)
		{
			Options = FILE_NON_DIRECTORY_FILE;
#ifdef USE_CACHE_READWRITE
			SetFlag(Options, FILE_WRITE_THROUGH);//直接写入
#endif
			/*
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
			*/
			Fcb->CcFileHandle = IrpContext->createInfo.hStreamHanle;
			Fcb->CcFileObject = IrpContext->createInfo.pStreamObject;

		}
		else
		{
			Fcb->CcFileObject = NULL;
		}

		if (InsertFcbList(&Fcb))
		{
			Ccb->StreamFileInfo.hStreamHandle = IrpContext->createInfo.hStreamHanle;
			Ccb->StreamFileInfo.StreamObject = IrpContext->createInfo.pStreamObject;
			Ccb->StreamFileInfo.pFO_Resource = FsAllocateResource();
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
		
#endif
		IrpContext->createInfo.pFcb = Fcb;
		IrpContext->createInfo.pCcb = Ccb;

		try_return(status = STATUS_SUCCESS);
try_exit:NOTHING;

	}
	__finally
	{
		if (AbnormalTermination() || !NT_SUCCESS(status))
		{
			status = STATUS_UNSUCCESSFUL;
			FltUninitializeOplock(&Fcb->Oplock);
			if (Fcb != NULL)
			{
				if (Fcb->FileLock)
				{
					if (TRUE/*FLT_FILE_LOCK*/)
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
				if (Ccb->StreamFileInfo.pFO_Resource != NULL)
				{
					ExDeleteResourceLite(Ccb->StreamFileInfo.pFO_Resource);
					ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Ccb->StreamFileInfo.pFO_Resource);
					Ccb->StreamFileInfo.pFO_Resource = NULL;
				}
				ExFreeToNPagedLookasideList(&g_CcbLookasideList, Ccb);
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
		Fcb->NtfsFcb = ExAllocateFromNPagedLookasideList(&g_NTFSFCBLookasideList);

		Fcb->Header.NodeTypeCode = LAYER_NTC_FCB;
		Fcb->Header.NodeByteSize = sizeof(DEFFCB);
		Fcb->Header.PagingIoResource = FsAllocateResource();
		Fcb->Resource = FsAllocateResource();
		Fcb->Header.Resource = FsAllocateResource();
		Fcb->Header.FastMutex = ExAllocateFromNPagedLookasideList(&g_FastMutexInFCBLookasideList);
		if (NULL == Fcb->Header.PagingIoResource || NULL == Fcb->Resource)
		{
			ExFreeToNPagedLookasideList(&g_FcbLookasideList, Fcb);
			return NULL;
		}
		if (Fcb->NtfsFcb)
		{
			Fcb->NtfsFcb->Resource = Fcb->Resource;
			Fcb->NtfsFcb->PageioResource = Fcb->Header.PagingIoResource;
		}
		ExInitializeResourceLite(Fcb->Resource);
		ExInitializeResourceLite(Fcb->Header.Resource);
		ExInitializeResourceLite(Fcb->Header.PagingIoResource);
		ExInitializeFastMutex(Fcb->Header.FastMutex);
		ExInitializeFastMutex(&Fcb->AdvancedFcbHeaderMutex);
		FsRtlSetupAdvancedHeader(&Fcb->Header, &Fcb->AdvancedFcbHeaderMutex);

		Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
		Fcb->Header.AllocationSize.QuadPart = -1;
		Fcb->Header.FileSize.QuadPart = 0;
		Fcb->Header.ValidDataLength.QuadPart = 0;
		Fcb->Vcb = szVcbPlacer;
		
		//Fcb->Vcb->VcbState = 1;
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
				Status = FltClose(Fcb->CcFileHandle);
				if (bSetBasicInfo)
				{
					Status = FsCloseSetFileBasicInfo(Fcb->CcFileObject, IrpContext, &fileInfo);
				}
			}
			else
			{
				Status = FltClose(Fcb->CcFileHandle);
			}
		}
		ObDereferenceObject(Fcb->CcFileObject);
		Fcb->CcFileObject = NULL;
	}
	if (Fcb->Header.PagingIoResource != NULL)
	{
		ExDeleteResourceLite(Fcb->Header.PagingIoResource);
		ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Fcb->Header.PagingIoResource);
		Fcb->Header.PagingIoResource = NULL;
	}
	if (Fcb->Header.Resource != NULL)
	{
		ExDeleteResourceLite(Fcb->Header.Resource);
		ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Fcb->Header.Resource);
		Fcb->Header.Resource = NULL;
	}
	if (Fcb->Resource != NULL)
	{
		ExDeleteResourceLite(Fcb->Resource);
		ExFreeToNPagedLookasideList(&g_EResourceLookasideList, Fcb->Resource);
		Fcb->Resource = NULL;
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
	FltUninitializeOplock(&Fcb->Oplock);
	if (TRUE/*FLT_FILE_LOCK*/)
	{
		FltUninitializeFileLock(Fcb->FileLock);
	}
	else
	{
		FsRtlUninitializeFileLock(Fcb->FileLock);
	}
	ExFreeToNPagedLookasideList(&g_FcbLookasideList, Fcb);
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
				DbgPrint("error:CcPurgeCacheSection failed...\n");
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
		Status = FltAllocateCallbackData(IrpContext->FltObjects->Instance, FileObject, &NewData);
		if (NT_SUCCESS(Status))
		{
			NewData->Iopb->MajorFunction = IRP_MJ_QUERY_INFORMATION;
			NewData->Iopb->MinorFunction = 0;
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
			DbgPrint("FsCloseGetFileBasicInfo failed(0x%x)....\n", Status);
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
		Status = FltAllocateCallbackData(IrpContext->FltObjects->Instance, FileObject, &NewData);
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
			DbgPrint("FsCloseSetFileBasicInfo failed(0x%x)....\n",Status);
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
	if (Data && FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_API))
	{
		return TRUE;
	}

	return FALSE;
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

PVOID FsMapUserBuffer(IN OUT PFLT_CALLBACK_DATA Data)
{
	NTSTATUS Status;
	PMDL pMdl;
	PVOID pBuffer;

	PMDL *ppMdl;
	PVOID * ppBuffer;
	PULONG Length;
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

	if (NULL == pMdl)
	{
		return pBuffer;
	}
	pSystemBuffer = MmGetSystemAddressForMdlSafe(pMdl, NormalPagePriority);
	if (NULL == pSystemBuffer)
	{
		FsRaiseStatus(NULL, STATUS_INSUFFICIENT_RESOURCES);
	}
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
	PFLT_RELATED_OBJECTS FltObjects = IrpContext->FltObjects;
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
		ExFreeToNPagedLookasideList(&g_CcbLookasideList, Ccb);
	}
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

BOOLEAN IsTest(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects)
{
	NTSTATUS status;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	HANDLE hProcessId = NULL;
	PEPROCESS Process = NULL;
	PUCHAR ProcessName = NULL;
	WCHAR wszName[32] = { L"1.docx" };

	if (FileObject && (NULL != FileObject->FileName.Buffer))
	{
		int nLength = FileObject->FileName.Length + sizeof(WCHAR);
		WCHAR * pwszName = (WCHAR *)ExAllocatePoolWithTag(NonPagedPool, nLength, 'aaaa');
		RtlZeroMemory(pwszName, nLength);
		RtlCopyMemory(pwszName, FileObject->FileName.Buffer, FileObject->FileName.Length);
		if (NULL != wcsstr(pwszName, wszName))
		{
			DbgPrint("cleanup:%S...\n", FileObject->FileName.Buffer);
			hProcessId = PsGetCurrentProcessId();
			if (NULL != hProcessId)
			{
				status = PsLookupProcessByProcessId(hProcessId, &Process);
				if (NT_SUCCESS(status))
				{
					ProcessName = PsGetProcessImageFileName(Process);
					DbgPrint("process name=%s...\n", ProcessName);
				}
			}
		}
		ExFreePoolWithTag(pwszName, 'aaaa');
	}

	if (ProcessName && 0 == stricmp("wps.exe", ProcessName))
	{
		return TRUE;
	}

	return FALSE;
}
