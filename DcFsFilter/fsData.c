#include "fsData.h"
#include "fatstruc.h"
#include <ntifs.h>

NPAGED_LOOKASIDE_LIST  g_IrpContextLookasideList;
NPAGED_LOOKASIDE_LIST  g_FcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_EResourceLookasideList;
NPAGED_LOOKASIDE_LIST  g_CcbLookasideList;
NPAGED_LOOKASIDE_LIST  g_IoContextLookasideList;
DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS = {0};

ULONG g_OsMajorVersion = 0;
ULONG g_OsMinorVersion = 0;

CACHE_MANAGER_CALLBACKS g_CacheManagerCallbacks = {0};

VOID initData()
{
	UNICODE_STRING RoutineString = { 0 };
	ExInitializeNPagedLookasideList(&g_IrpContextLookasideList, NULL, NULL, 0, sizeof(DEF_IRP_CONTEXT), 'IRC', 0);
//	ExInitializeNPagedLookasideList(&g_IoContextLoolasideList, NULL, NULL, sizeof(), 'IOC', 0);
	ExInitializeNPagedLookasideList(&g_FcbLookasideList, NULL, NULL, 0, sizeof(DEFFCB), 'FCB', 0);
	ExInitializeNPagedLookasideList(&g_CcbLookasideList, NULL, NULL, 0, sizeof(CCB), 'CCB', 0);
	ExInitializeNPagedLookasideList(&g_EResourceLookasideList, NULL, NULL, 0, sizeof(ERESOURCE), 'Res', 0);
	ExInitializeNPagedLookasideList(&g_EncryptFileListLookasideList, NULL, NULL, 0, sizeof(ENCRYPT_FILE_FCB), 'efl', 0);

	g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx = (fltCheckOplockEx)FltGetRoutineAddress("FltCheckOplockEx");
	g_DYNAMIC_FUNCTION_POINTERS.OplockBreakH = (fltOplockBreakH)FltGetRoutineAddress("FltOplockBreakH");

	RtlInitUnicodeString(&RoutineString, L"MmDoesFileHaveUserWritableReferences");
	g_DYNAMIC_FUNCTION_POINTERS.pMmDoesFileHaveUserWritableReferences = (fMmDoesFileHaveUserWritableReferences)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"FsRtlChangeBackingFileObject");
	g_DYNAMIC_FUNCTION_POINTERS.pFsRtlChangeBackingFileObject = (fsRtlChangeBackingFileObject)MmGetSystemRoutineAddress(&RoutineString);

	RtlInitUnicodeString(&RoutineString, L"RtlGetVersion");
	g_DYNAMIC_FUNCTION_POINTERS.pGetVersion = (fsGetVersion)MmGetSystemRoutineAddress(&RoutineString);

	g_CacheManagerCallbacks.AcquireForLazyWrite = &fsAcquireFcbForLazyWrite;
	g_CacheManagerCallbacks.ReleaseFromLazyWrite = &fsReleaseFcbFromLazyWrite;
	g_CacheManagerCallbacks.AcquireForReadAhead = &fsAcquireFcbForReadAhead;
	g_CacheManagerCallbacks.ReleaseFromReadAhead = &fsReleaseFcbFromReadAhead;

	InitializeListHead(&g_FcbEncryptFileList);
}

VOID unInitData()
{
	ExDeleteNPagedLookasideList(&g_FcbLookasideList);
	ExDeleteNPagedLookasideList(&g_CcbLookasideList);
	ExDeleteNPagedLookasideList(&g_EResourceLookasideList);
	ExDeleteNPagedLookasideList(&g_IrpContextLookasideList);
	ExDeleteNPagedLookasideList(&g_IoContextLookasideList);
}

PERESOURCE fsdAllocateResource()
{
	PERESOURCE Resource = NULL;

	Resource = (PERESOURCE)ExAllocateFromNPagedLookasideList(&g_EResourceLookasideList);

	ExInitializeResourceLite(Resource);

	return Resource;
}

BOOLEAN fsIsIrpTopLevel(IN PFLT_CALLBACK_DATA Data)
{
	if (NULL == IoGetTopLevelIrp())
	{
		IoSetTopLevelIrp((PIRP)Data);
		return TRUE;
	}

	return FALSE;
}

PDEF_IRP_CONTEXT fsCreateIrpContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN bWait)
{
	PDEF_IRP_CONTEXT pIrpContext = NULL;
	PFILE_OBJECT pFileObject = FltObjects->FileObject;


	return NULL;
}
//延迟写
BOOLEAN fsAcquireFcbForLazyWrite(IN PVOID Fcb, IN BOOLEAN Wait)
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

VOID fsReleaseFcbFromLazyWrite(IN PVOID Fcb)
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
	ExReleaseResourceLite(pFcb->Header.PagingIoResource);
}

//预读
BOOLEAN fsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait)
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

VOID fsReleaseFcbFromReadAhead(IN PVOID Fcb)
{
	DEFFCB * pFcb = (DEFFCB*)Fcb;

	PAGED_CODE();

	IoSetTopLevelIrp(NULL);

	if (NULL == pFcb)
	{
		return;
	}
	ExReleaseResourceLite(pFcb->Header.Resource);
}

BOOLEAN IsMyFakeFcb(PFILE_OBJECT FileObject)
{
	DEFFCB * Fcb;
	if (FileObject == NULL || FileObject->FsContext == NULL)
	{
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

PDEF_IRP_CONTEXT CreateIRPContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN Wait)
{
	PDEF_IRP_CONTEXT pIrpContext = NULL;
	PFILE_OBJECT FileObject = FltObjects->FileObject;

	PAGED_CODE();

	pIrpContext = ExAllocateFromNPagedLookasideList(&g_IrpContextLookasideList);
	if (NULL != pIrpContext)
	{
		RtlZeroMemory(pIrpContext, sizeof(DEF_IRP_CONTEXT));
		pIrpContext->NodeTypeCode = LAYER_NTC_FCB;
		pIrpContext->NodeByteSize = sizeof(IRP_CONTEXT);
		pIrpContext->OriginatingData = Data;

		pIrpContext->ProcessId = PsGetCurrentProcessId();

		if (Wait) { SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_WAIT); } //同步的

		// Write-Through 标志
		if (FlagOn(FileObject->Flags, FO_WRITE_THROUGH))
		{
			SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);
		}

		pIrpContext->MajorFunction = Data->Iopb->MajorFunction;
		pIrpContext->MinorFunction = Data->Iopb->MinorFunction;

		RtlCopyMemory(pIrpContext->Fileobject, FltObjects, FltObjects->Size);

		if ((PFLT_CALLBACK_DATA)IoGetTopLevelIrp() != Data)
		{
			SetFlag(pIrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL);
		}
	}
	return pIrpContext;
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
	PLIST_ENTRY pListEntry;
	PENCRYPT_FILE_FCB pContext = NULL;

	if (NULL == pFcb || NULL == pwszFile || wcslen(pwszFile) <= 0)
	{
		return FALSE;
	}

	RemoveFcbList(pwszFile);
	return InsertFcbList(pFcb);
}
