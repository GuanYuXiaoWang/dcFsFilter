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
	
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FsRtlEnterFileSystem();
	KdPrint(("PtPreFileSystemControl, control code=0x%x......\n", Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode));

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
			ntStatus = FsCommonFileSystemControl(Data, FltObjects, IrpContext);
		}
		__finally
		{
			if (bTopLevelIrp)
			{
				IoSetTopLevelIrp(NULL);
			}
			if (ntStatus == STATUS_PENDING && FSCTL_REQUEST_OPLOCK == Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode)
			{
				FltStatus = FLT_PREOP_PENDING;
			}
			else
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
			}
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

NTSTATUS FsCommonFileSystemControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
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
		FsCompleteRequest(&IrpContext, &Data, ntStatus, FALSE);
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
	
	if (!IsMyFakeFcb(FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FsRtlEnterFileSystem();
	KdPrint(("PtPreLockControl....\n"));
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
	PFILE_OBJECT FileObject = NULL;
	PDEFFCB Fcb = NULL;
	BOOLEAN bFcbAcquired = FALSE;
	BOOLEAN bOplockPostIrp = FALSE;
	PFLT_CALLBACK_DATA OrgData = NULL;

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
			KdPrint(("have file oplock...\n"));
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

#ifndef FSCTL_REQUEST_OPLOCK
#define FSCTL_REQUEST_OPLOCK                CTL_CODE(FILE_DEVICE_FILE_SYSTEM, 144, METHOD_BUFFERED, FILE_ANY_ACCESS)
#endif

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
		FILE_OBJECTID_BUFFER FileObjectIdInfo = { 0 };
		ULONG Length = sizeof(FILE_OBJECTID_BUFFER);
		ntStatus = FltFsControlFile(FltObjects->Instance, Fcb->CcFileObject, ControlCode, NULL, 0, &FileObjectIdInfo, Length, &Length);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s] FltFsControlFile failed(0x%x)....\n", __FUNCTION__, ntStatus));
		}
		RtlCopyMemory(&pBuf->ObjectId, &FileObjectIdInfo.ObjectId, 16);
		RtlCopyMemory(&pBuf->ExtendedInfo, &FileObjectIdInfo.ExtendedInfo, 48);
		Data->IoStatus.Information = 64;
		FsCompleteRequest(&IrpContext, &Data, ntStatus, FALSE);
	}
		break;
	case FSCTL_SET_OBJECT_ID:
	case FSCTL_GET_RETRIEVAL_POINTERS:
	{
		ntStatus = FsPostUnderlyingDriverControl(Data, FltObjects, Fcb->CcFileObject);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s]FsPostUnderlyingDriverControl failed(0x%x), line=%d....\n", __FUNCTION__, ntStatus, __LINE__));
		}
		FsCompleteRequest(&IrpContext, &Data, ntStatus, FALSE);
	}
		break;
		
	case FSCTL_REQUEST_FILTER_OPLOCK:
	case FSCTL_REQUEST_OPLOCK:
	{
		ntStatus = FsOplockRequest(Data, IrpContext, Fcb);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s] FsOplockRequest failed(0x%x)....\n", __FUNCTION__, ntStatus));
		}
	}
		break;
		
		
	default:
		ntStatus = STATUS_INVALID_PARAMETER;
		FsCompleteRequest(&IrpContext, &Data, ntStatus, FALSE);
		break;
	}

	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS PtPreDirectoryControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	BOOLEAN bTopIrp = FALSE;
	FILE_INFORMATION_CLASS FileClass;
	ULONG RetLength = 0;
	ULONG ProcessType = 0;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FsRtlEnterFileSystem();

	FileClass = Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileInformationClass;
	KdPrint(("PtPreDirectoryControl, file class=%d....\n", FileClass));

	__try
	{
		bTopIrp = IsTopLevelIRP(Data);
		Fcb = FltObjects->FileObject->FsContext;
		Ccb = FltObjects->FileObject->FsContext2;
		if (FileBothDirectoryInformation == FileClass ||
			FileDirectoryInformation == FileClass ||
			FileFullDirectoryInformation == FileClass ||
			FileIdBothDirectoryInformation == FileClass ||
			FileIdFullDirectoryInformation == FileClass ||
			FileNamesInformation == FileClass ||
			FileObjectIdInformation == FileClass ||
			FileReparsePointInformation == FileClass)
		{
			if (g_DYNAMIC_FUNCTION_POINTERS.QueryDirectoryFile)
			{
				ntStatus = g_DYNAMIC_FUNCTION_POINTERS.QueryDirectoryFile(FltObjects->Instance, FltObjects->FileObject, Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer,
					Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length, FileClass, TRUE, Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName, TRUE, &RetLength);
			}
			else
			{
				ntStatus = STATUS_INVALID_DEVICE_REQUEST;
			}
// 			ntStatus = FltQueryDirectoryFile(FltObjects->Instance, Fcb->CcFileObject, Data->Iopb->Parameters.DirectoryControl.QueryDirectory.DirectoryBuffer,
// 				Data->Iopb->Parameters.DirectoryControl.QueryDirectory.Length, FileClass, TRUE, Data->Iopb->Parameters.DirectoryControl.QueryDirectory.FileName, TRUE, &RetLength);
		}
	}
	__finally
	{
		Data->IoStatus.Status = ntStatus;
		Data->IoStatus.Information = RetLength;
		if (bTopIrp)
		{
			IoSetTopLevelIrp(NULL);
		}
	}

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

NTSTATUS FsPostUnderlyingDriverControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_CALLBACK_DATA NewData = NULL;

	Status = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(Status))
	{
		NewData->Iopb->MajorFunction = Data->Iopb->MajorFunction;
		NewData->Iopb->MinorFunction = Data->Iopb->MinorFunction;

		NewData->Iopb->Parameters.FileSystemControl.Common.FsControlCode = Data->Iopb->Parameters.FileSystemControl.Common.FsControlCode;
		NewData->Iopb->Parameters.FileSystemControl.Common.InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.InputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Common.OutputBufferLength;

		NewData->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer = Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode = Data->Iopb->Parameters.FileSystemControl.Buffered.FsControlCode;
		NewData->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;

		NewData->Iopb->Parameters.FileSystemControl.Direct.FsControlCode = Data->Iopb->Parameters.FileSystemControl.Direct.FsControlCode;
		NewData->Iopb->Parameters.FileSystemControl.Direct.InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Direct.InputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer = Data->Iopb->Parameters.FileSystemControl.Direct.InputSystemBuffer;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Direct.OutputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputMdlAddress = Data->Iopb->Parameters.FileSystemControl.Direct.OutputMdlAddress;
		NewData->Iopb->Parameters.FileSystemControl.Direct.OutputBuffer = Data->Iopb->Parameters.FileSystemControl.Direct.OutputBuffer;

		NewData->Iopb->Parameters.FileSystemControl.Neither.FsControlCode = Data->Iopb->Parameters.FileSystemControl.Neither.FsControlCode;
		NewData->Iopb->Parameters.FileSystemControl.Neither.InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Neither.InputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Neither.InputBuffer = Data->Iopb->Parameters.FileSystemControl.Neither.InputBuffer;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBufferLength;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer = Data->Iopb->Parameters.FileSystemControl.Neither.OutputBuffer;
		NewData->Iopb->Parameters.FileSystemControl.Neither.OutputMdlAddress = Data->Iopb->Parameters.FileSystemControl.Neither.OutputMdlAddress;
//
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

NTSTATUS FsOplockRequest(__inout PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext, __in PDEFFCB Fcb)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	BOOLEAN AcquireFcb = FALSE;
	ULONG OplockCount = 0;
	FLT_PREOP_CALLBACK_STATUS FltStatus;
	PFLT_CALLBACK_DATA OrgData = IrpContext->OriginatingData;

#if (NTDDI_VERSION >= NTDDI_WIN7)
	PREQUEST_OPLOCK_INPUT_BUFFER InputBuffer = NULL; //REQUEST_OPLOCK_INPUT_FLAG_REQUEST
	ULONG InputBufferLength;
	ULONG OutputBufferLength; //OPLOCK_LEVEL_CACHE_READ OPLOCK_LEVEL_CACHE_HANDLE OPLOCK_LEVEL_CACHE_WRITE
#endif

#if (NTDDI_VERSION >= NTDDI_WIN7)

	//
	//  Get the input & output buffer lengths and pointers.
	//
	InputBufferLength = Data->Iopb->Parameters.FileSystemControl.Buffered.InputBufferLength;
	InputBuffer = (PREQUEST_OPLOCK_INPUT_BUFFER)Data->Iopb->Parameters.FileSystemControl.Buffered.SystemBuffer;

	OutputBufferLength = Data->Iopb->Parameters.FileSystemControl.Buffered.OutputBufferLength;

	//
	//  Check for a minimum length on the input and ouput buffers.
	//

	if ((InputBufferLength < sizeof(REQUEST_OPLOCK_INPUT_BUFFER)) ||
		(OutputBufferLength < sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER))) 
	{
		FsCompleteRequest(&IrpContext, &Data, STATUS_BUFFER_TOO_SMALL, FALSE);
		return STATUS_BUFFER_TOO_SMALL;
	}
	
#endif

	
	__try
	{
#if (NTDDI_VERSION >= NTDDI_WIN7)
		if (FlagOn(InputBuffer->Flags, REQUEST_OPLOCK_INPUT_FLAG_REQUEST))
		{
			AcquireFcb = FsAcquireExclusiveFcb(IrpContext, Fcb);

#if (NTDDI_VERSION >= NTDDI_WIN7)
			if (g_DYNAMIC_FUNCTION_POINTERS.OplockIsSharedRequest && g_DYNAMIC_FUNCTION_POINTERS.OplockIsSharedRequest(Data)) {
#else
			if (FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2) {
#endif

// #if (NTDDI_VERSION >= NTDDI_WIN8)
//  				OplockCount = (ULONG) !g_DYNAMIC_FUNCTION_POINTERS.pFsRtlCheckLockForOplockRequest(Fcb->FileLock, &Fcb->Header.AllocationSize );
				if (IsFltFileLock())
				{
#if (NTDDI_VERSION >= NTDDI_WIN7)
					if (g_DYNAMIC_FUNCTION_POINTERS.RtlAreThereCurrentOrInProgressFileLocks)
					{
						OplockCount = g_DYNAMIC_FUNCTION_POINTERS.RtlAreThereCurrentOrInProgressFileLocks(Fcb->FileLock);
					}
					else
					{
						OplockCount = 0;
					}
#else
					OplockCount = (ULONG)FsRtlAreThereCurrentFileLocks(&Fcb->Specific.Fcb.FileLock);
#endif
				}
				else
				{
					OplockCount = Fcb->UncleanCount;
				}
			}
			else {

				OplockCount = Fcb->UncleanCount;
			}
		}

		if (FlagOn(InputBuffer->RequestedOplockLevel, OPLOCK_LEVEL_CACHE_HANDLE) && FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
		{
			ntStatus = STATUS_DELETE_PENDING;
			__leave;
		}

		FltStatus = FltOplockFsctrl(&Fcb->Oplock, OrgData, OplockCount);	
		if (OrgData->IoStatus.Status != STATUS_SUCCESS &&
			OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
		{
			ntStatus = OrgData->IoStatus.Status;
			KdPrint(("[%s] FltOplockFsctrl failed(0x%x)....\n", __FUNCTION__, ntStatus));
			__leave;
		}
		if (FltStatus == FLT_PREOP_PENDING)
		{
			ntStatus = STATUS_PENDING;
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
		Data = NULL;
#endif
	}
	__finally
	{
		if (AcquireFcb)
		{
			FsReleaseFcb(IrpContext, Fcb);
		}
		FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
	}
	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS PtPreDeviceControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	BOOLEAN bTopIrp = FALSE;
	ULONG RetLength = 0;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FsRtlEnterFileSystem();
	Fcb = FltObjects->FileObject->FsContext;
	Ccb = FltObjects->FileObject->FsContext2;
	__try
	{
		bTopIrp = IsTopLevelIRP(Data);
		ntStatus = FltDeviceIoControlFile(FltObjects->Instance, Fcb->CcFileObject, Data->Iopb->Parameters.DeviceIoControl.Common.IoControlCode,
			Data->Iopb->Parameters.DeviceIoControl.Buffered.SystemBuffer, Data->Iopb->Parameters.DeviceIoControl.Common.InputBufferLength,
			Data->Iopb->Parameters.DeviceIoControl.Direct.OutputBuffer, Data->Iopb->Parameters.DeviceIoControl.Common.OutputBufferLength, &RetLength);
	}
	__finally
	{
		Data->IoStatus.Status = ntStatus;
		Data->IoStatus.Information = RetLength;
		if (bTopIrp)
		{
			IoSetTopLevelIrp(NULL);
		}
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostDeviceControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

