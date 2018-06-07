#include "fsCreate.h"
#include "fsData.h"
#include "fatstruc.h"
#include "volumeContext.h"
#include <ntfs.h>

BOOLEAN IsFilterProcess(PCFLT_RELATED_OBJECTS pFltObjects, PNTSTATUS pStatus, PULONG pProcType)
{
	UNREFERENCED_PARAMETER(pFltObjects);
	UNREFERENCED_PARAMETER(pStatus);
	UNREFERENCED_PARAMETER(pProcType);

	return TRUE;
}

FLT_PREOP_CALLBACK_STATUS PtPreOperationCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS	FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevel;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	ULONG uProcType = 0;
	DEF_CCB * Ccb = NULL;

	PAGED_CODE();

	if (!IsFilterProcess(FltObjects, &status, &uProcType))
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

	FsRtlEnterFileSystem();
	if (FLT_IS_IRP_OPERATION(Data))//IRP write
	{
		bTopLevel = IsTopLevelIRP(Data);
		__try
		{
			IrpContext = CreateIRPContext(Data, FltObjects, FlagOn(Data->Iopb->OperationFlags, FO_SYNCHRONOUS_IO) ? TRUE : FALSE);
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

FLT_POSTOP_CALLBACK_STATUS PtPostOperationCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
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

	if (IsMyFakeFcb(FltObjects->FileObject) || IsFilterProcess(FltObjects, &Status, &ProcType))
	{
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
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
			__leave;
		}
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_PAGING_FILE))
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
			__leave;
		}
		if (FlagOn(pIopb->TargetFileObject->Flags, FO_VOLUME_OPEN))
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
			__leave;
		}
		if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))
		{
			bPostIrp = TRUE;
			DbgPrint("No asynchronous create \n");
			__leave;
		}
		
		Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
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
				return FLT_PREOP_COMPLETE;
			}
		}
		
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		{

			if (IsMyFakeFcb(pFileObject))
			{
				Status = STATUS_ACCESS_DENIED;
				return FLT_PREOP_COMPLETE;
			}
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}

		if (!IsNeedSelfFcb(Data, &IrpContext->createInfo.nameInfo, &Status))
		{
			if (NT_SUCCESS(Status))
			{
				return FLT_PREOP_SUCCESS_NO_CALLBACK;
			}
			else
			{
				Data->IoStatus.Status = Status;
				return FLT_PREOP_COMPLETE;
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
				return FLT_PREOP_COMPLETE;
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
		if (IsMyFakeFcb(pFileObject) || FindFcb(pFileObject->FileName.Buffer, &pFcb))
		{
			Status = CreateFileByExistFcb(Data, FltObjects, pFcb, IrpContext);

			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}

			return IrpContext->FltStatus;
		}
		else 
		{
			Status = CreateFileByNonExistFcb(Data, FltObjects, pFcb, IrpContext, HashValue);

			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}
			return IrpContext->FltStatus;
		}

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
		if (NT_SUCCESS())
		{
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

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	BOOLEAN Flag;
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

	BOOLEAN FcbAcquired = FALSE;
	BOOLEAN FsRtlHeaderLocked = TRUE;
	BOOLEAN EncryptResourceAcquired = FALSE;
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
		(VOID)X70FsdAcquireExclusiveFcb(IrpContext, Fcb);
		FcbAcquired = TRUE;

		ExAcquireResourceExclusiveLite(Fcb->EncryptResource, TRUE);
		EncryptResourceAcquired = TRUE;

		if (FlagOn(Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE) && Fcb->OpenHandleCount != 0)
		{
			try_return(Status = STATUS_DELETE_PENDING);
		}

		IrpContext->CreateInfo.OplockPostIrp = FALSE;

		if (IS_WINDOWS7() || IS_WINDOWS7_LATER())
		{
			FltOplockStatus = gDynamicFunctions.CheckOplockEx(&Fcb->Oplock,
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
				X70FsdOplockComplete,
				X70FsdPrePostIrp);

			if (FLT_PREOP_PENDING == FltOplockStatus)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}

		}
		if (CreateDisposition == FILE_CREATE && Fcb->OpenHandleCount != 0)
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
			if (IS_WINDOWS7() || IS_WINDOWS7_LATER())
			{

				if ((Status == STATUS_SHARING_VIOLATION) &&
					!FlagOn(OrgData->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
				{

					FltOplockStatus = gDynamicFunctions.OplockBreakH(&Fcb->Oplock,
						OrgData,
						0,
						IrpContext,
						X70FsdOplockComplete,
						X70FsdPrePostIrp);

					if (FltOplockStatus == FLT_PREOP_PENDING) {

						Status = STATUS_PENDING;
						IrpContext->FltStatus = FLT_PREOP_PENDING;
						IrpContext->CreateInfo.OplockPostIrp = TRUE;
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
		if (IS_WINDOWS7() || IS_WINDOWS7_LATER())
		{
			if (Fcb->OpenHandleCount != 0)
			{

				FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
					OrgData,
					IrpContext,
					X70FsdOplockComplete,
					X70FsdPrePostIrp);

			}

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
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
					Fcb->OpenHandleCount);

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
				X70FsdOplockComplete,
				X70FsdPrePostIrp);

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.OplockPostIrp = TRUE;
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

		Flag = FALSE;

		if (FlagOn(DesiredAccess, FILE_WRITE_DATA) || DeleteOnClose)
		{

			InterlockedIncrement((PLONG)&Fcb->ReferenceCount);
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
			CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
			ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE);
		}

		if (DeleteOnClose)
		{
			SetFlag(Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE);
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


		Status = CreateFileImitation(Data,
			FltObjects,
			&IrpContext->CreateInfo.nameInfo->Name,
			&IrpContext->CreateInfo.StreamHandle,
			&IrpContext->CreateInfo.StreamObject,
			&Data->IoStatus,
			IrpContext->CreateInfo.Network
			);

		if (!NT_SUCCESS(Status)) /
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

		IrpContext->CreateInfo.Information = Data->IoStatus.Information;

		Status = MyGetFileStandardInfo(Data,
			FltObjects,
			IrpContext->CreateInfo.StreamObject,
			&IrpContext->CreateInfo.FileAllocationSize,
			&IrpContext->CreateInfo.FileSize,
			&bDirectory);

		if (!NT_SUCCESS(Status) || bDirectory)
		{
			try_return(IrpContext->FltStatus = (bDirectory ? FLT_PREOP_SUCCESS_NO_CALLBACK : FLT_PREOP_COMPLETE));
		}

		Status = CreatedFileHeaderInfo(IrpContext);

		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		if (IrpContext->CreateInfo.FileAccess == FILE_NO_ACCESS)
		{

			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if (IrpContext->CreateInfo.FileAccess == FILE_ONLY_READ &&
			(BooleanFlagOn(DesiredAccess, FILE_WRITE_DATA) ||
			BooleanFlagOn(DesiredAccess, FILE_APPEND_DATA)))
		{

			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}

		//写过了加密头
		if (!Fcb->IsEnFile && IrpContext->CreateInfo.IsEnFile)
		{
			Fcb->IsEnFile = IrpContext->CreateInfo.IsEnFile;
			Fcb->FileHeaderLength = FILE_HEADER_LENGTH;
			SetFlag(Fcb->FcbState, SCB_STATE_FILEHEADER_WRITED);
		}


		Ccb = X70FsdCreateCcb();

		Ccb->StreamFileInfo.StreamHandle = IrpContext->CreateInfo.StreamHandle;
		Ccb->StreamFileInfo.StreamObject = IrpContext->CreateInfo.StreamObject;
		Ccb->StreamFileInfo.FO_Resource = X70FsdAllocateResource();
		Ccb->ProcType = IrpContext->CreateInfo.ProcType;
		Ccb->FileAccess = IrpContext->CreateInfo.FileAccess;
		RtlCopyMemory(Ccb->ProcessGuid, IrpContext->CreateInfo.ProcessGuid, GUID_SIZE);

		if (IrpContext->CreateInfo.Network)
		{
			SetFlag(Ccb->CcbState, CCB_FLAG_NETWORK_FILE);
		}

		ExInitializeFastMutex(&Ccb->StreamFileInfo.FileObjectMutex);

		FileObject->FsContext = Fcb;
		FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
		FileObject->Vpb = IrpContext->CreateInfo.StreamObject->Vpb;
		FileObject->FsContext2 = Ccb;

		SetFlag(FileObject->Flags, FO_WRITE_THROUGH);

		if (CreateDisposition == FILE_SUPERSEDE ||
			CreateDisposition == FILE_OVERWRITE ||
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			Status = X70FsdOverWriteFile(FileObject, Fcb, AllocationSize);
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
					SetFlag(Fcb->FcbState, SCB_STATE_DELETE_ON_CLOSE);
				}

				InterlockedIncrement((PLONG)&Fcb->ReferenceCount);
				InterlockedIncrement((PLONG)&Fcb->OpenHandleCount);

				if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
				{
					InterlockedIncrement((PLONG)&Fcb->NonCachedCleanupCount);
				}

			}
		}
	}
	finally
	{

		if (DecrementFcbOpenCount)
		{
			InterlockedDecrement((PLONG)&Fcb->ReferenceCount);
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
				if (Ccb->StreamFileInfo.FO_Resource != NULL)
				{
					ExDeleteResourceLite(Ccb->StreamFileInfo.FO_Resource);
					ExFreeToNPagedLookasideList(&G_EResourceLookasideList, Ccb->StreamFileInfo.FO_Resource);
					Ccb->StreamFileInfo.FO_Resource = NULL;
				}
				ExFreeToNPagedLookasideList(&G_CcbLookasideList, Ccb);
				FileObject->FsContext2 = NULL;
			}
		}

		if (FcbAcquired)
		{
			X70FsdReleaseFcb(IrpContext, Fcb);
		}
		if (EncryptResourceAcquired)
		{
			ExReleaseResourceLite(Fcb->EncryptResource);
		}
	}
	return Status;
}

NTSTATUS CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{

}
