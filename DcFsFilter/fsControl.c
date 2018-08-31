#include "fsControl.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreFileSystemControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG uProcessType = 0;
	BOOLEAN bTopLevelIrp = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreQueryInformation"))
	{
		KdBreakPoint();
	}
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
#endif
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	DbgPrint("PtPreFileSystemControl, control code=0x%x......\n", Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode);

	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = FsIsIrpTopLevel(Data);
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			if (NULL == IrpContext)
			{
				FsRaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
				__leave;
			}
			ntStatus = FsControl(Data, FltObjects, IrpContext);
			if (!NT_SUCCESS(ntStatus))
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
			}
		}
		__finally
		{
			if (bTopLevelIrp)
			{
				IoSetTopLevelIrp(NULL);
			}
			FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
		}	
	}
	else if (FLT_IS_FASTIO_OPERATION(Data))
	{
		FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	}
	else
	{
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostFileSystemControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS FsControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	
	switch (Iopb->MinorFunction)
	{
	case IRP_MN_USER_FS_REQUEST:
		ntStatus = FsUserRequestControl(Data, FltObjects, IrpContext);
		break;
	case IRP_MN_MOUNT_VOLUME:
		break;

	default:
		ntStatus = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	
	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS PtPreLockControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	BOOLEAN bTopLevelIrp = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	NTSTATUS Status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(CompletionContext);
	
	PAGED_CODE();
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	DbgPrint("PtPreLockControl....\n");
	bTopLevelIrp = FsIsIrpTopLevel(Data);
	if (FLT_IS_IRP_OPERATION(Data))
	{
		do
		{
			__try
			{
				if (NULL == IrpContext)
				{
					IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
				}
				FltStatus = FsCommonLockControl(Data, FltObjects, IrpContext);
				Status = IrpContext->ExceptionStatus;
				break;
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				FsProcessException(&IrpContext, &Data, GetExceptionCode());
				FltStatus = FLT_PREOP_COMPLETE;
				break;
			}
		} while (Status == STATUS_CANT_WAIT || Status == STATUS_LOG_FILE_FULL);
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
	
	if (bTopLevelIrp)
	{
		IoSetTopLevelIrp(NULL);
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostLockControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsCommonLockControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	BOOLEAN bFcbAcquired = FALSE;
	BOOLEAN bOplockPostIrp = FALSE;
	PFLT_CALLBACK_DATA OrgData = NULL;

	__try
	{
		if (NULL == Fcb || Fcb->OpenCount <= 1)
		{
			__leave;
		}
		if (IrpContext->OriginatingData != NULL)
		{
			OrgData = IrpContext->OriginatingData;
		}
		else
		{
			OrgData = Data;
		}

		bFcbAcquired = FsAcquireSharedFcb(IrpContext, Fcb);
		if (NULL == Fcb->CcFileObject)
		{
			__leave;
		}

		if (FltCurrentBatchOplock(&Fcb->Oplock))
		{
			DbgPrint("have file oplock...\n");
		}

		if (IsWin7OrLater())
		{
			FltStatus = g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx(&Fcb->Oplock,
				OrgData,
				OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
				IrpContext,
				FsOplockComplete,
				NULL);
		}
		else
		{
			FltStatus = FltCheckOplock(&Fcb->Oplock, OrgData, IrpContext, FsOplockComplete, NULL);
		}

		if (FltStatus == FLT_PREOP_PENDING)
		{
			IrpContext->FltStatus = FLT_PREOP_PENDING;
			IrpContext->createInfo.bOplockPostIrp = TRUE;
			try_return(NOTHING);
		}
		if (FltStatus == FLT_PREOP_COMPLETE)
		{
			try_return(NOTHING);
		}

	
// 		FltStatus = FltCheckOplock(&Fcb->Oplock, Data, IrpContext, FsOplockComplete, NULL);
// 		if (FLT_PREOP_COMPLETE == FltStatus)
// 		{
// 			__leave;
// 		}
// 		if (FLT_PREOP_PENDING == FltStatus)
// 		{
// 			FltStatus = FLT_PREOP_PENDING;
// 			bOplockPostIrp = TRUE;
// 			__leave;
// 		}
		ExAcquireFastMutex(Fcb->Header.FastMutex);
		if (FltOplockIsFastIoPossible(&Fcb->Oplock))
		{
			if (Fcb->FileLock && Fcb->FileLock->FastIoIsQuestionable)
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

		FltStatus = FltProcessFileLock(Fcb->FileLock, Data, NULL);
	try_exit:NOTHING;
	}
	__finally
	{
		if (!AbnormalTermination() && !bOplockPostIrp) {

			FsCompleteRequest(&IrpContext, NULL, STATUS_SUCCESS, FALSE);
		}
		if (bFcbAcquired)
		{
			FsReleaseFcb(IrpContext, Fcb);
		}
	}

	return FltStatus;
}

NTSTATUS FsUserRequestControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ULONG ControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
	ULONG OutBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;
	PFILE_OBJECTID_BUFFER pBuf = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
	PFILE_OBJECT FileObject = NULL;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	if (NULL == FltObjects)
	{
		FltObjects = &IrpContext->FltObjects;
	}
	if (FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Data->Iopb->TargetFileObject;
	}
	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	if (FSCTL_CREATE_OR_GET_OBJECT_ID == ControlCode)
	{
		if (OutBufferLength > 0)
		{
			ControlCode = FSCTL_GET_OBJECT_ID;
		}
		else
		{
			ControlCode = FSCTL_SET_OBJECT_ID;
		}
	}

	switch (ControlCode)
	{
	case FSCTL_GET_OBJECT_ID:
	//case FSCTL_CREATE_OR_GET_OBJECT_ID:
	{
		RtlCopyMemory(&pBuf->ObjectId, &Fcb->FileObjectIdInfo.ObjectId, 16);
		RtlCopyMemory(&pBuf->ExtendedInfo, &Fcb->FileObjectIdInfo.ExtendedInfo, 48);
		Data->IoStatus.Information = 64;
	}
		break;
	case FSCTL_SET_OBJECT_ID:
		ntStatus = STATUS_INVALID_PARAMETER;
		break;

	default:
		ntStatus = STATUS_INVALID_PARAMETER;
		break;
	}
	
	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS PtPreDirectoryControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	DbgPrint("PtPreDirectoryControl....\n");

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostDirectoryControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
