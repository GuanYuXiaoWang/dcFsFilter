#include "fsCreate.h"
#include "fsData.h"
#include "fatstruc.h"
#include "volumeContext.h"
#include <ntifs.h>
#include <wdm.h>
#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS	FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevel;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	ULONG uProcType = 0;
	DEF_CCB * Ccb = NULL;	

	PAGED_CODE();

#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreCreate"))
	{
		KdBreakPoint();
	}
#endif

	if (!IsFilterProcess(Data, &status, &uProcType))
	{
		if (NT_SUCCESS(status))
		{
			if (FlagOn(uProcType, PROCESS_ACCESS_DISABLE))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				return FLT_PREOP_COMPLETE;
			}
			if (IsMyFakeFcb(FileObject))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				return FLT_PREOP_COMPLETE;
			}
			if (IsMyFakeFcb(FileObject->RelatedFileObject))
			{
				Ccb = FileObject->RelatedFileObject->FsContext2;

				if (Ccb != NULL)
				{
					FileObject->RelatedFileObject = Ccb->StreamFileInfo.StreamObject;
				}
				else
				{
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					return FLT_PREOP_COMPLETE;
				}
			}
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{
			Data->IoStatus.Status = status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}

	if (FlagOn(uProcType, PROCESS_ACCESS_DISABLE))
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	DbgPrint("PtPreCreate......\n");
#ifdef TEST
	KdBreakPoint();
#endif

	FsRtlEnterFileSystem();
	if (FLT_IS_IRP_OPERATION(Data))//IRP operate
	{
		bTopLevel = IsTopLevelIRP(Data);
		__try
		{
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			IrpContext->createInfo.uProcType = uProcType;
			FltStatus = FsCommonCreate(Data, FltObjects, IrpContext);
		}
		__finally
		{
			if (bTopLevel)
			{
				IoSetTopLevelIrp(NULL);
			}
		}
	}
	else if (FLT_IS_FASTIO_OPERATION(Data))
	{
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	}
	else
	{
		Data->IoStatus.Status = STATUS_UNSUCCESSFUL;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	ULONG ProcType = 0;
	NTSTATUS Status;
#ifdef TEST	
	if (IsTest(Data, FltObjects, "PtPreOperationNetworkQueryOpen"))
	{
		
	}
#endif
	if (IsMyFakeFcb(FltObjects->FileObject) || IsFilterProcess(Data, &Status, &ProcType))
	{
		DbgPrint("PtPreOperationNetworkQueryOpen......\n");
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PtPostOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsCommonCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK IoStatus = { 0 };

	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bAcquireResource = FALSE;
	PVOLUMECONTEXT pVolCtx = NULL;
	PFLT_IO_PARAMETER_BLOCK pIopb = Data->Iopb;
	PFILE_OBJECT pFileObject, pRelatedFileObject;
	PUNICODE_STRING pFileName;
	PERESOURCE pFcbResource = NULL;
	BOOLEAN bPostIrp = FALSE;
	BOOLEAN bFOResourceAcquired = FALSE;
	PDEFFCB pFcb = NULL;
	PDEF_CCB pCcb = NULL;

	if (NULL == FltObjects)
	{
		pFileObject = IrpContext->Fileobject;
	}
	else
	{
		pFileObject = FltObjects->FileObject;
	}
	pRelatedFileObject = pFileObject->RelatedFileObject;
	pFileName = &pFileObject->FileName;
	__try
	{
		if (KernelMode == Data->RequestorMode)
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_PAGING_FILE))
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (FlagOn(pIopb->TargetFileObject->Flags, FO_VOLUME_OPEN))
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))
		{
			bPostIrp = TRUE;
			DbgPrint("No asynchronous create \n");
			try_return(FltStatus);
		}
		
		Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}
		
		if (IsMyFakeFcb(pRelatedFileObject))
		{
			pCcb = pRelatedFileObject->FsContext2;

			if (pCcb != NULL)
			{
				ExAcquireResourceSharedLite(pCcb->StreamFileInfo.pFO_Resource, TRUE);
				bFOResourceAcquired = TRUE;
				pFileObject->RelatedFileObject = pCcb->StreamFileInfo.StreamObject;
			}
			else
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}
		
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		{

			if (IsMyFakeFcb(pFileObject))
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if (!IsNeedSelfFcb(Data, &IrpContext->createInfo.nameInfo, &Status))
		{
			if (NT_SUCCESS(Status))
			{
				try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}


		if (pFileName->Length > sizeof(WCHAR) &&
			pFileName->Buffer[1] == L'\\' &&
			pFileName->Buffer[0] == L'\\')
		{
			pFileName->Length -= sizeof(WCHAR);

			RtlMoveMemory(
				&pFileName->Buffer[0],
				&pFileName->Buffer[1],
				pFileName->Length
				);

			if (pFileName->Length > sizeof(WCHAR) &&
				pFileName->Buffer[1] == L'\\' &&
				pFileName->Buffer[0] == L'\\')
			{
				Data->IoStatus.Status = STATUS_OBJECT_NAME_INVALID;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		ExAcquireResourceExclusiveLite(pVolCtx->pEresurce, TRUE);
		bAcquireResource = TRUE;

		if (pVolCtx->uDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			IrpContext->createInfo.bNetWork = TRUE;	//only read！！！！！！
		}

		IrpContext->ulSectorSize = pVolCtx->ulSectorSize;
		IrpContext->uSectorsPerAllocationUnit = pVolCtx->uSectorsPerAllocationUnit;

		Status = STATUS_SUCCESS;
		if (IsMyFakeFcb(pFileObject) || FindFcb(Data, pFileObject->FileName.Buffer, &pFcb))
		{
			Status = CreateFileByExistFcb(Data, FltObjects, pFcb, IrpContext);

			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}

			try_return(FltStatus = IrpContext->FltStatus);
		}
		else 
		{
			Status = CreateFileByNonExistFcb(Data, FltObjects, pFcb, IrpContext);

			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}
			try_return(FltStatus = IrpContext->FltStatus);
		}
try_exit:NOTHING;
		if (IrpContext->createInfo.bReissueIo)
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{
			Data->IoStatus.Information = IrpContext->createInfo.Information;
		}
	}
	__finally
	{
		if (NULL != IrpContext->createInfo.nameInfo)
		{
			FltReleaseFileNameInformation(IrpContext->createInfo.nameInfo);
		}
		if (bAcquireResource)
		{
			ExReleaseResourceLite(pVolCtx->pEresurce);
		}

		if (bFOResourceAcquired)
		{
			PDEF_CCB pTmp = pRelatedFileObject->FsContext2;
			if (pTmp && pTmp->StreamFileInfo.pFO_Resource)
			{
				ExReleaseResourceLite(pTmp->StreamFileInfo.pFO_Resource);
			}
		}

		if (NULL != pVolCtx)
		{
			FltReleaseContext(pVolCtx);
		}

		if (!NT_SUCCESS(Status) || FltStatus != FLT_PREOP_COMPLETE)
		{
			if (NULL != IrpContext->createInfo.pStreamObject)
			{
				ObDereferenceObject(IrpContext->createInfo.pStreamObject);
				FltClose(IrpContext->createInfo.hStreamHanle);
			}
		}
		if (bPostIrp && !IrpContext->createInfo.bOplockPostIrp)
		{
			Status = FsPostRequest(Data, IrpContext);
			if (STATUS_PENDING == Status)
			{
				FltStatus = FLT_PREOP_PENDING;
			}
			else
			{
				FltStatus = FLT_PREOP_COMPLETE;
			}
		}

		Data->IoStatus.Status = FLT_PREOP_SUCCESS_NO_CALLBACK == FltStatus ? 0 : Status;
		Data->IoStatus.Information = 0;

		if (!bPostIrp && !AbnormalTermination())
		{
			FsCompleteRequest(&IrpContext, &Data, Data->IoStatus.Status, FALSE);
		}
	}
	return FltStatus;
}

BOOLEAN IsNeedSelfFcb(__inout PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION * nameInfo, PNTSTATUS pStatus)
{
	NTSTATUS Status;
	BOOLEAN bDirectory = FALSE;
	if (!IsConcernedCreateOptions(Data))
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	Status = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &bDirectory);
	if (NT_SUCCESS(Status) && bDirectory)
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	Status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		nameInfo);
	if (!NT_SUCCESS(Status))
	{
		Status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_OPENED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			nameInfo);
		if (!NT_SUCCESS(Status))
		{
			*pStatus = Status;
			return FALSE;
		}
	}

	Status = FltParseFileNameInformation(*nameInfo);
	if (!NT_SUCCESS(Status))
	{
		*pStatus = Status;
		return FALSE;
	}
	//根据得到的文件信息剔除掉打开盘符的操作
	if (0 == (*nameInfo)->Name.Length)
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	
	if ((*nameInfo)->FinalComponent.Length == 0) //打开的是卷或者目录
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}

	if ((*nameInfo)->Extension.Length == 0 && (*nameInfo)->Share.Length != 0)
	{
		if ((*nameInfo)->Share.Length >= NAMED_PIPE_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName, &(*nameInfo)->Share, TRUE);

			if (!NT_SUCCESS(Status))
			{
				*pStatus = Status;
				return FALSE;
			}
			if (NAMED_PIPE_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer, ShareName.Length - NAMED_PIPE_PREFIX_LENGTH),
				NAMED_PIPE_PREFIX,
				NAMED_PIPE_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
		if ((*nameInfo)->Share.Length >= MAIL_SLOT_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName, &(*nameInfo)->Share, TRUE);

			if (!NT_SUCCESS(Status))
			{
				*pStatus = Status;
				return FALSE;
			}

			if (MAIL_SLOT_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer, ShareName.Length - MAIL_SLOT_PREFIX_LENGTH),
				MAIL_SLOT_PREFIX,
				MAIL_SLOT_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
	}
	if ((*nameInfo)->Stream.Length != 0) //file stream
	{
		ULONG i;
		for (i = 0; i < ((*nameInfo)->Stream.Length - sizeof(WCHAR)) / 2; i++)
		{
			if (((*nameInfo)->Stream.Buffer[i] == L':') &&
				((*nameInfo)->Stream.Buffer[i + 1] == L'$'))
			{
				DbgPrint("stream create!\n");
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}
		}

		*pStatus = STATUS_SUCCESS;
		return FALSE;  //TRUE?FALSE? 
	}

	return TRUE;
}

BOOLEAN IsConcernedCreateOptions(__inout PFLT_CALLBACK_DATA Data)
{
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;

	ULONG Options = Iopb->Parameters.Create.Options;

	BOOLEAN DirectoryFile = BooleanFlagOn(Options, FILE_DIRECTORY_FILE); //目录文件

	return !DirectoryFile;
}

#ifndef FILE_OPEN_REQUIRING_OPLOCK
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#endif

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;
	LARGE_INTEGER  AllocationSize;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

	PDEF_CCB Ccb = NULL;
	ACCESS_MASK DesiredAccess;
	ULONG  EaLength;
	PVOID  EaBuffer;
	ULONG  Options;
	ULONG  CreateDisposition;
	ULONG	FileAttributes;
	ULONG	ShareAccess;
	ULONG ClusterSize = 0;
	LARGE_INTEGER Temp;

	BOOLEAN NoEaKnowledge;
	BOOLEAN DeleteOnClose;
	BOOLEAN NoIntermediateBuffering;
	BOOLEAN TemporaryFile;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN OpenRequiringOplock = FALSE;

	BOOLEAN DecrementFcbOpenCount = FALSE;
	BOOLEAN RemoveShareAccess = FALSE;
	BOOLEAN AcquiredPagingResource = FALSE;
	PACCESS_MASK DesiredAccessPtr;
	PIO_SECURITY_CONTEXT  SecurityContext;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK PreDesiredAccess;
	BOOLEAN bFcbAcquired = FALSE;
	BOOLEAN bResourceAcquired = FALSE;
	UNREFERENCED_PARAMETER(FltObjects);

	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;
	EaBuffer = Iopb->Parameters.Create.EaBuffer;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	DesiredAccessPtr = &Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	SecurityContext = Iopb->Parameters.Create.SecurityContext;
	Options = Iopb->Parameters.Create.Options;
	FileAttributes = Iopb->Parameters.Create.FileAttributes;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	EaLength = Iopb->Parameters.Create.EaLength;

	CreateDisposition = (Options >> 24) & 0x000000ff;
	SecurityContext = Iopb->Parameters.Create.SecurityContext;
	PreDesiredAccess = DesiredAccess;

	OpenRequiringOplock = BooleanFlagOn(Options, FILE_OPEN_REQUIRING_OPLOCK);
	NoEaKnowledge = BooleanFlagOn(Options, FILE_NO_EA_KNOWLEDGE);
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	NoIntermediateBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);
	TemporaryFile = BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_TEMPORARY);

	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	if (IrpContext->OriginatingData != NULL)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}

	__try
	{
		bFcbAcquired = FsAcquireExclusiveFcb(IrpContext, Fcb);
		bResourceAcquired = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);

		if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE) && Fcb->OpenCount != 0)
		{
			try_return(Status = STATUS_DELETE_PENDING);
		}

		IrpContext->createInfo.bOplockPostIrp = FALSE;

		if (IsWin7OrLater())
		{
			FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx(&Fcb->Oplock,
				OrgData,
				OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
				NULL,
				NULL,
				NULL);

			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
		}

		if (FltCurrentBatchOplock(&Fcb->Oplock))
		{
			Data->IoStatus.Information = FILE_OPBATCH_BREAK_UNDERWAY;
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
				OrgData,
				IrpContext,
				FsOplockComplete,
				FsPrePostIrp);

			if (FLT_PREOP_PENDING == FltOplockStatus)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->createInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}

		}
		if (CreateDisposition == FILE_CREATE && Fcb->OpenCount != 0)
		{
			Status = STATUS_OBJECT_NAME_COLLISION;
			try_return(Status);
		}
		else if (CreateDisposition == FILE_OVERWRITE ||
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			SetFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA);
		}
		else if (CreateDisposition == FILE_SUPERSEDE)
		{
			SetFlag(DesiredAccess, DELETE);
		}

		if (!NT_SUCCESS(Status = IoCheckShareAccess(DesiredAccess,
			ShareAccess,
			FileObject,
			&Fcb->ShareAccess,
			FALSE)))
		{
			if (IsWin7OrLater())
			{
				if ((Status == STATUS_SHARING_VIOLATION) &&
					!FlagOn(OrgData->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
				{
					FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.OplockBreakH(&Fcb->Oplock,
						OrgData,
						0,
						IrpContext,
						FsOplockComplete,
						FsPrePostIrp);

					if (FltOplockStatus == FLT_PREOP_PENDING) 
					{
						Status = STATUS_PENDING;
						IrpContext->FltStatus = FLT_PREOP_PENDING;
						IrpContext->createInfo.bOplockPostIrp = TRUE;
						try_return(Status);
					}
					if (FltOplockStatus == FLT_PREOP_COMPLETE)
					{
						try_return(Status = OrgData->IoStatus.Status);
					}
					else
					{
						try_return(Status = STATUS_SHARING_VIOLATION);
					}
				}
			}
			try_return(Status);
		}
		if (IsWin7OrLater())
		{
			if (Fcb->OpenCount != 0)
			{

				FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
					OrgData,
					IrpContext,
					FsOplockComplete,
					FsPrePostIrp);
			}

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->createInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
			if (OpenRequiringOplock)
			{

				FltOplockStatus = FltOplockFsctrl(&Fcb->Oplock,
					OrgData,
					Fcb->OpenCount);

				if (OrgData->IoStatus.Status != STATUS_SUCCESS &&
					OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
				{
					try_return(Status = OrgData->IoStatus.Status);
				}
			}
		}
		else
		{
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
				OrgData,
				IrpContext,
				FsOplockComplete,
				FsPrePostIrp);

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->createInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
		}

		ExAcquireFastMutex(Fcb->Header.FastMutex);

		if (FltOplockIsFastIoPossible(&Fcb->Oplock))
		{
			if (Fcb->FileLock &&
				Fcb->FileLock->FastIoIsQuestionable)
			{
				Fcb->Header.IsFastIoPossible = FastIoIsQuestionable;
			}
			else
			{
				Fcb->Header.IsFastIoPossible = FastIoIsPossible;
			}
		}
		else
		{
			Fcb->Header.IsFastIoPossible = FastIoIsNotPossible;
		}
		ExReleaseFastMutex(Fcb->Header.FastMutex);

		if (FlagOn(DesiredAccess, FILE_WRITE_DATA) || DeleteOnClose)
		{
			InterlockedIncrement((PLONG)&Fcb->UncleanCount);
			DecrementFcbOpenCount = TRUE;

			if (!MmFlushImageSection(&Fcb->SectionObjectPointers,
				MmFlushForWrite))
			{
				Status = (DeleteOnClose ? STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION);
				try_return(Status);
			}
		}

		if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING) &&
			(Fcb->SectionObjectPointers.DataSectionObject != NULL))//先刷新缓存 //见fat create 2932
		{
			ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
			CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
			CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE);
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
		}

		if (DeleteOnClose)
		{
			SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
		}

		if (CreateDisposition == FILE_SUPERSEDE ||
			CreateDisposition == FILE_OVERWRITE ||
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			if (!MmCanFileBeTruncated(&Fcb->SectionObjectPointers, &Li0))
			{
				try_return(Status = STATUS_USER_MAPPED_FILE);
			}
		}

		Status = CreateFileLimitation(Data,
			FltObjects,
			&IrpContext->createInfo.nameInfo->Name,
			&IrpContext->createInfo.hStreamHanle,
			&IrpContext->createInfo.pStreamObject,
			&Data->IoStatus,
			IrpContext->createInfo.bNetWork
			);

		if (!NT_SUCCESS(Status)) 
		{
			if (Status == STATUS_FILE_IS_A_DIRECTORY)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		IrpContext->createInfo.Information = Data->IoStatus.Information;

		Status = FsGetFileStandardInfo(Data,
			FltObjects,
			IrpContext);

		if (!NT_SUCCESS(Status) || bDirectory)
		{
			try_return(IrpContext->FltStatus = (bDirectory ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE));
		}

		Status = FsCreatedFileHeaderInfo(FltObjects, IrpContext);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}
		//TODO::非加密文件不过滤
		if (!IrpContext->createInfo.bEnFile)
		{
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (IrpContext->createInfo.FileAccess == FILE_NO_ACCESS)
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if (IrpContext->createInfo.FileAccess == FILE_READ_ACCESS &&
			(BooleanFlagOn(DesiredAccess, FILE_WRITE_DATA) ||
			BooleanFlagOn(DesiredAccess, FILE_APPEND_DATA)))
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}

		//写过了加密头
		if (!Fcb->bEnFile && IrpContext->createInfo.bEnFile)
		{
			Fcb->bEnFile = IrpContext->createInfo.bEnFile;
			Fcb->FileHeaderLength = ENCRYPT_HEAD_LENGTH;
			SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
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
		Fcb->LastModificationTime = IrpContext->createInfo.BaseInfo.LastWriteTime.QuadPart;
		Fcb->LinkCount = IrpContext->createInfo.NumberOfLinks;
		Fcb->DeletePending = IrpContext->createInfo.DeletePending;
		Fcb->Directory = IrpContext->createInfo.Directory;
		Fcb->CcFileHandle = IrpContext->createInfo.hStreamHanle;
		Fcb->CcFileObject = IrpContext->createInfo.pStreamObject;

		Ccb = FsCreateCcb();
		Ccb->StreamFileInfo.hStreamHandle = IrpContext->createInfo.hStreamHanle;
		Ccb->StreamFileInfo.StreamObject = IrpContext->createInfo.pStreamObject;
		Ccb->StreamFileInfo.pFO_Resource = FsAllocateResource();
		Ccb->ProcType = IrpContext->createInfo.uProcType;
		Ccb->FileAccess = IrpContext->createInfo.FileAccess;
	
		if (IrpContext->createInfo.bNetWork)
		{
			SetFlag(Ccb->CcbState, CCB_FLAG_NETWORK_FILE);
		}

		ExInitializeFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);

		FileObject->FsContext = Fcb;
		FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
		FileObject->Vpb = IrpContext->createInfo.pStreamObject->Vpb;
		FileObject->FsContext2 = Ccb;

		//SetFlag(FileObject->Flags, FO_WRITE_THROUGH);

		if (CreateDisposition == FILE_SUPERSEDE ||
			CreateDisposition == FILE_OVERWRITE ||
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			Status = FsOverWriteFile(FileObject, Fcb, AllocationSize);
		}

		if (!NoIntermediateBuffering)
		{
			FileObject->Flags |= FO_CACHE_SUPPORTED;
		}

	try_exit: NOTHING;
		if (IrpContext->FltStatus == FLT_PREOP_COMPLETE)
		{
			if (NT_SUCCESS(Status) &&
				Status != STATUS_PENDING)
			{

				if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
				{
					NetFileSetCacheProperty(FileObject, DesiredAccess);
				}

				if (DesiredAccess != PreDesiredAccess)
				{
					DesiredAccess = PreDesiredAccess;
					Status = IoCheckShareAccess(
						DesiredAccess,
						ShareAccess,
						FileObject,
						&Fcb->ShareAccess,
						TRUE
						);
					ASSERT(Status == STATUS_SUCCESS);
				}
				else
				{
					IoUpdateShareAccess(
						FileObject,
						&Fcb->ShareAccess
						);
				}

				RemoveShareAccess = TRUE;

				if (DeleteOnClose)
				{
					SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
				}

				InterlockedIncrement((PLONG)&Fcb->OpenCount);
				InterlockedIncrement((PLONG)&Fcb->UncleanCount);

				if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
				{
					InterlockedIncrement((PLONG)&Fcb->NonCachedUnCleanupCount);
				}
			}
		}
	}
	__finally
	{
		if (DecrementFcbOpenCount)
		{
			InterlockedDecrement((PLONG)&Fcb->UncleanCount);
		}

		if (AbnormalTermination())
		{
			if (RemoveShareAccess)
			{
				IoRemoveShareAccess(
					FileObject,
					&Fcb->ShareAccess
					);
			}
			Status = STATUS_UNSUCCESSFUL;

			Ccb = FileObject->FsContext2;
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

		if (bFcbAcquired)
		{
			FsReleaseFcb(IrpContext, Fcb);
		}
		if (bResourceAcquired)
		{
			ExReleaseResourceLite(Fcb->Resource);
		}
	}
	return Status;
}

NTSTATUS CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Options;
	ULONG CreateDisposition;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN bEnFile = FALSE;
	BOOLEAN bDisEncryptFile = FALSE;

	BOOLEAN bNeedOwnFcb = FALSE;
	BOOLEAN bOrgEnFile = FALSE;
	BOOLEAN bDeleteOnClose = FALSE;
	BOOLEAN bNoIntermediaBuffering = FALSE;
	BOOLEAN bOpenRequiringOplock;

	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK DesiredAccess = 0;
	ULONG ShareAccess = 0;
	LARGE_INTEGER AllocationSize = {0};
//	LARGE_INTEGER FileBeginOffset;

	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	Options = Iopb->Parameters.Create.Options;
	CreateDisposition = (Options >> 24) & 0x000000ff;

	bOpenRequiringOplock = BooleanFlagOn(Options, FILE_OPEN_REQUIRING_OPLOCK);
	bDeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	bNoIntermediaBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);

	if (NULL != IrpContext->OriginatingData)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}
	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	__try
	{
		Status = CreateFileLimitation(Data, FltObjects, &IrpContext->createInfo.nameInfo->Name, &IrpContext->createInfo.hStreamHanle,
			&IrpContext->createInfo.pStreamObject, &Data->IoStatus, IrpContext->createInfo.bNetWork);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("CreateFileLimitation failed(0x%x)...\n", Status);
			if (STATUS_FILE_IS_A_DIRECTORY == Status)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				//Data->IoStatus.Status = Status;
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
		}
		IrpContext->createInfo.Information = Data->IoStatus.Information;
		Status = FsGetFileStandardInfo(Data, FltObjects, IrpContext);//这里还不能用FltObject中的文件对象
		if (!NT_SUCCESS(Status) || bDirectory)
		{
			try_return(IrpContext->FltStatus = (bDirectory ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE));
		}

		Status = FsCreatedFileHeaderInfo(FltObjects, IrpContext);
		if (!NT_SUCCESS(Status))
		{
			DbgPrint("FsCreatedFileHeaderInfo failed(0x%x)...\n", Status);
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		//TODO::非加密文件不过滤
		if (!IrpContext->createInfo.bEnFile)
		{
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if (FILE_NO_ACCESS == IrpContext->createInfo.FileAccess)
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if (IrpContext->createInfo.FileAccess == FILE_READ_ACCESS && (BooleanFlagOn(DesiredAccess, FILE_WRITE_DATA) ||
			BooleanFlagOn(DesiredAccess, FILE_APPEND_DATA)))
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		IrpContext->createInfo.bDeleteOnClose = bDeleteOnClose;

		Status = FsCreateFcbAndCcb(Data, FltObjects, IrpContext);
		if (NT_SUCCESS(Status))
		{
			PDEF_CCB Ccb;
			Fcb = IrpContext->createInfo.pFcb;
			Ccb = IrpContext->createInfo.pCcb;
			Ccb->TypeOfOpen = 2;//2:ntfs file open
			if (IsWin7OrLater())
			{
				FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx(&Fcb->Oplock, OrgData, OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
					NULL, NULL, NULL);

				if (FLT_PREOP_COMPLETE == FltOplockStatus)
				{
					try_return(Status = OrgData->IoStatus.Status);
				}
				if (bOpenRequiringOplock)
				{
					FltOplockStatus = FltOplockFsctrl(&Fcb->Oplock, OrgData, Fcb->OpenCount);
					if (OrgData->IoStatus.Status != STATUS_SUCCESS && OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
					{
						FsRaiseStatus(IrpContext, OrgData->IoStatus.Status);
					}
				}
			}

			FileObject->FsContext = Fcb;
			FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
			FileObject->Vpb = IrpContext->createInfo.pStreamObject->Vpb;
			FileObject->FsContext2 = Ccb;
		//	SetFlag(FileObject->Flags, FO_WRITE_THROUGH);

			IoSetShareAccess(DesiredAccess, ShareAccess, FileObject, &Fcb->ShareAccess);

			InterlockedIncrement(&Fcb->UncleanCount);
			InterlockedIncrement(&Fcb->OpenCount);

			if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
			{
				InterlockedIncrement(&Fcb->NonCachedUnCleanupCount);
			}
			if (IrpContext->createInfo.bDeleteOnClose)
			{
				SetFlag(Fcb->FcbState, FCB_STATE_DELAY_CLOSE);
			}

			if (FILE_SUPERSEDE == CreateDisposition ||
				FILE_OVERWRITE == CreateDisposition ||
				FILE_OVERWRITE_IF == CreateDisposition)
			{
				Status = FsOverWriteFile(FileObject, Fcb, AllocationSize);
			}
			if (!bNoIntermediaBuffering)
			{
				FileObject->Flags |= FO_CACHE_SUPPORTED;
			}
		}

try_exit: NOTHING;
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		PDEFFCB Fcb = FileObject->FsContext;
		PDEF_CCB Ccb = FileObject->FsContext2;
		IrpContext->createInfo.bReissueIo = FALSE;
		IrpContext->FltStatus = FLT_PREOP_COMPLETE;
		if (Fcb != NULL)
		{
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
	return Status;
}

NTSTATUS CreateFileLimitation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PUNICODE_STRING FileName, __out PHANDLE phFile,
								__out PFILE_OBJECT * pFileObject, __out PIO_STATUS_BLOCK IoStatus, __in BOOLEAN bNetWork)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ob = {0};
	PFLT_IO_PARAMETER_BLOCK CONST Iopb = Data->Iopb;
	LARGE_INTEGER AllocationSize;
	ACCESS_MASK DesiredAccess;
	ULONG EaLength;
	PVOID EaBuffer;
	ULONG Options;
	ULONG CreateDisposition;
	ULONG FileAttributes;
	ULONG	ShareAccess;
	ULONG	Flags = 0;
	PSECURITY_DESCRIPTOR  SecurityDescriptor = NULL;

	UNREFERENCED_PARAMETER(FltObjects);

	SecurityDescriptor = Iopb->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor;
	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;

	EaBuffer = Iopb->Parameters.Create.EaBuffer;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	Options = Iopb->Parameters.Create.Options;
	FileAttributes = Iopb->Parameters.Create.FileAttributes;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	EaLength = Iopb->Parameters.Create.EaLength;

	if (bNetWork)
	{
		//SetFlag (ShareAccess ,FILE_SHARE_READ); 
		//SetFlag (DesiredAccess ,FILE_READ_DATA  );

		//SetFlag (DesiredAccess , FILE_WRITE_DATA); //???
		ShareAccess = FILE_SHARE_READ;   //网络文件因为oplock，只能只读，要想解决去参考rdbss.sys
		ClearFlag(DesiredAccess, FILE_WRITE_DATA);
		ClearFlag(DesiredAccess, FILE_APPEND_DATA);

	}
#ifdef USE_CACHE_READWRITE

	SetFlag(Options, FILE_WRITE_THROUGH); //如果缓存写需要加上直接写入文件，否则cccaniwrite内部会导致等待pagingio产生死锁

#endif
	ClearFlag(Options, FILE_OPEN_BY_FILE_ID);
	ClearFlag(Options, FILE_OPEN_REQUIRING_OPLOCK);

	CreateDisposition = (Options >> 24) & 0x000000ff;

	InitializeObjectAttributes(&ob, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, SecurityDescriptor);
	
	Status = FltCreateFile(FltObjects->Filter, //FltCreateFileEx
		FltObjects->Instance,
		phFile,
		DesiredAccess,
		&ob,
		IoStatus,
		&AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		Options,
		EaBuffer,
		EaLength,
		Flags
		);
	if (NT_SUCCESS(Status))
	{
		Status = ObReferenceObjectByHandle(*phFile,
			0,
			*IoFileObjectType,
			KernelMode,
			pFileObject,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			FltClose(*phFile);
			*pFileObject = NULL;
		}
	}

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("create false filename %ws \n", FileName->Buffer);
	}
	
	return Status;
}
