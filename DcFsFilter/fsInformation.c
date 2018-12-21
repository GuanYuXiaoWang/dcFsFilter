#include "fsInformation.h"
#include "fsData.h"

//fastFat中，文件信息在创建FCB时就保存在FCB结构中
FLT_PREOP_CALLBACK_STATUS PtPreQueryInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
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
		
	}
#endif

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PreQueryInformation begin, fileclass=%d......\n", Data->Iopb->Parameters.QueryFileInformation.FileInformationClass));
#ifdef TEST
	KdBreakPoint();
#endif

	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = FsIsIrpTopLevel(Data);
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			if (NULL == IrpContext)
			{
				FsRaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
			}
			ntStatus = FsCommonQueryInformation(Data, FltObjects, IrpContext);

			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("FsCommonQueryInformation failed(0x%x)...\n", ntStatus));
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
			}
			FltStatus = FLT_PREOP_COMPLETE;
		}
		__finally
		{
			if (bTopLevelIrp)
			{
				IoSetTopLevelIrp(NULL);
			}
		}
		FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
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
	KdPrint(("PreQueryInformation end......\n"));
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostQueryInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS FsCommonQueryInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_BASIC_INFORMATION FileBasicInfo = NULL;
	PFILE_STANDARD_INFORMATION FileStandardInfo = NULL;
	PFILE_ALL_INFORMATION FileAllInfo = NULL;
	PFILE_NETWORK_OPEN_INFORMATION FileNetInfo = NULL;
	PFILE_POSITION_INFORMATION FilePositionInfo = NULL;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
	PVOID pFileInfoBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
	ULONG length = 0;
	PFILE_OBJECT FileObject = NULL;

	//查询信息，是否需要独占FCB资源？？？
	__try
	{
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
		if (NULL == Fcb)
		{
			KdPrint(("QueryInformation:Fcb is not exit!\n"));
			__leave;
		}

		switch (FileInfoClass)
		{
		case FileBasicInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_BASIC_INFORMATION))
			{
				KdPrint(("QueryInformation:length(%d) < sizeof(FILE_BASIC_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length));
				try_return(ntStatus);
			}
			length = sizeof(FILE_BASIC_INFORMATION);
			FileBasicInfo = (PFILE_BASIC_INFORMATION)pFileInfoBuffer;
			FileBasicInfo->CreationTime.QuadPart = Fcb->CreationTime;
			FileBasicInfo->ChangeTime.QuadPart = Fcb->LastChangeTime;
			FileBasicInfo->FileAttributes = Fcb->Attribute;
			FileBasicInfo->LastAccessTime.QuadPart = Fcb->LastAccessTime;
			FileBasicInfo->LastWriteTime.QuadPart = Fcb->LastWriteTime;
			break;
		case FileAllInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_ALL_INFORMATION))
			{
				KdPrint(("QueryInformation:length(%d) < sizeof(FILE_ALL_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length));
				try_return(ntStatus);
			}
			length = sizeof(FILE_ALL_INFORMATION);
			FileAllInfo = (PFILE_ALL_INFORMATION)pFileInfoBuffer;
			FileAllInfo->BasicInformation.CreationTime.QuadPart = Fcb->CreationTime;
			FileAllInfo->BasicInformation.ChangeTime.QuadPart = Fcb->LastChangeTime;
			FileAllInfo->BasicInformation.FileAttributes = Fcb->Attribute;
			FileAllInfo->BasicInformation.LastAccessTime.QuadPart = Fcb->LastAccessTime;
			FileAllInfo->BasicInformation.LastWriteTime.QuadPart = Fcb->LastChangeTime;
			FileAllInfo->StandardInformation.AllocationSize = Fcb->Header.AllocationSize;
			FileAllInfo->StandardInformation.DeletePending = BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			FileAllInfo->StandardInformation.Directory = Fcb->Directory;
			FileAllInfo->StandardInformation.NumberOfLinks = Fcb->LinkCount;
			FileAllInfo->StandardInformation.EndOfFile.QuadPart = Fcb->bEnFile? Fcb->Header.FileSize.QuadPart - ENCRYPT_HEAD_LENGTH : Fcb->Header.FileSize.QuadPart;
			break;
		case FileStandardInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_STANDARD_INFORMATION))
			{
				KdPrint(("QueryInformation:length(%d) < sizeof(FILE_STANDARD_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length));
				try_return(ntStatus);
			}
			length = sizeof(FILE_STANDARD_INFORMATION);
			FileStandardInfo = (PFILE_STANDARD_INFORMATION)pFileInfoBuffer;
			FileStandardInfo->AllocationSize = Fcb->Header.AllocationSize;
			FileStandardInfo->DeletePending = BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			FileStandardInfo->Directory = Fcb->Directory;
			FileStandardInfo->NumberOfLinks = Fcb->LinkCount;
			FileStandardInfo->EndOfFile.QuadPart = Fcb->bEnFile? Fcb->Header.FileSize.QuadPart - ENCRYPT_HEAD_LENGTH : Fcb->Header.FileSize.QuadPart;
			break;
		case FileNetworkOpenInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_NETWORK_OPEN_INFORMATION))
			{
				KdPrint(("QueryInformation:length(%d) < sizeof(FILE_STANDARD_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length));
				try_return(ntStatus);
			}
			length = sizeof(FILE_NETWORK_OPEN_INFORMATION);
			FileNetInfo = (PFILE_NETWORK_OPEN_INFORMATION)pFileInfoBuffer;
			FileNetInfo->AllocationSize.QuadPart = Fcb->Header.AllocationSize.QuadPart;
			FileNetInfo->ChangeTime.QuadPart = Fcb->LastChangeTime;
			FileNetInfo->CreationTime.QuadPart = Fcb->CreationTime;
			FileNetInfo->EndOfFile.QuadPart = Fcb->bEnFile? Fcb->Header.FileSize.QuadPart - ENCRYPT_HEAD_LENGTH : Fcb->Header.FileSize.QuadPart;
			FileNetInfo->LastAccessTime.QuadPart = Fcb->LastAccessTime;
			FileNetInfo->LastWriteTime.QuadPart = Fcb->LastWriteTime;
			FileNetInfo->FileAttributes = Fcb->Attribute;
			if (FlagOn(Fcb->FcbState, FCB_STATE_TEMPORARY))
			{
				SetFlag(FileNetInfo->FileAttributes, FILE_ATTRIBUTE_TEMPORARY);
			}
			break;
		case FilePositionInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_POSITION_INFORMATION))
			{
				KdPrint(("QueryInformation:length(%d) < sizeof(FILE_POSITION_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length));
				try_return(ntStatus);
			}
			length = sizeof(FILE_POSITION_INFORMATION);
			FilePositionInfo = (PFILE_POSITION_INFORMATION)pFileInfoBuffer;
			FilePositionInfo->CurrentByteOffset.QuadPart = FltObjects->FileObject->CurrentByteOffset.QuadPart;
			break;
		case FileAttributeTagInformation:
		case FileStreamInformation:
		case FileNameInformation:
		case FileEaInformation:
			ntStatus = FltQueryInformationFile(FltObjects->Instance, Fcb->CcFileObject,
				Data->Iopb->Parameters.QueryFileInformation.InfoBuffer, Data->Iopb->Parameters.QueryFileInformation.Length, 
				Data->Iopb->Parameters.QueryFileInformation.FileInformationClass, &length);
			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("FltQueryInformationFile failed(0x%x)...\n", ntStatus));
			}
			break;

		default:
			ntStatus = STATUS_INVALID_PARAMETER;
			break;
		}
		Data->IoStatus.Information = length;
	try_exit:NOTHING;
	}
	__finally
	{

	}
	return ntStatus;
}

FLT_PREOP_CALLBACK_STATUS PtPreSetInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	NTSTATUS ntStatus;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreSetInformation"))
	{
		KdPrint(("(FileClass=%d)......\n", Data->Iopb->Parameters.SetFileInformation.FileInformationClass));
	}
	
#endif

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsFileInfoChangedNotify(Data, FltObjects);
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreSetInformation begin, (FileClass=%d)......\n", FileInfoClass));
#ifdef TEST
	KdBreakPoint();
#endif

	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = FsIsIrpTopLevel(Data);
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			if (NULL == IrpContext)
			{
				FsRaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
			}
			ntStatus = FsCommonSetInformation(Data, FltObjects, IrpContext);
			if (!NT_SUCCESS(ntStatus))
			{
				Data->IoStatus.Status = ntStatus;
				Data->IoStatus.Information = 0;
			}
			FltStatus = FLT_PREOP_COMPLETE;
		}
		__finally
		{
			if (bTopLevelIrp)
			{
				IoSetTopLevelIrp(NULL);
			}
		}
		//FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
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
	KdPrint(("PtPreSetInformation end......\n"));
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostSetInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreQueryEA(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreQueryEA"))
	{
		KdBreakPoint();
	}
	
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PreQueryEa......\n"));
	__try
	{
		Fcb = FltObjects->FileObject->FsContext;
		if (g_DYNAMIC_FUNCTION_POINTERS.QueryEaFile)
		{
			 ntStatus = g_DYNAMIC_FUNCTION_POINTERS.QueryEaFile(FltObjects->Instance, Fcb->CcFileObject, Data->Iopb->Parameters.QueryEa.EaBuffer, Data->Iopb->Parameters.QueryEa.Length, TRUE,
				Data->Iopb->Parameters.QueryEa.EaList, Data->Iopb->Parameters.QueryEa.EaListLength, Data->Iopb->Parameters.QueryEa.EaIndex,
				TRUE, &Data->IoStatus.Information);
		}
		else
		{

		}
		
	}
	__finally
	{
		Data->IoStatus.Status = ntStatus;
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostQueryEA(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreSetEA(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (!IsTest(Data, FltObjects, "PtPreSetEA"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	KdBreakPoint();
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	KdPrint(("PreSetEa......\n"));
	__try
	{
		Fcb = FltObjects->FileObject->FsContext;
		if (g_DYNAMIC_FUNCTION_POINTERS.SetEaFile)
		{
			ntStatus = g_DYNAMIC_FUNCTION_POINTERS.SetEaFile(FltObjects->Instance, Fcb->CcFileObject, Data->Iopb->Parameters.SetEa.EaBuffer, Data->Iopb->Parameters.SetEa.Length);
		}
		else
		{

		}
	}
	__finally
	{
		Data->IoStatus.Status = ntStatus;
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostSetEA(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreAcquireForSection(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreAcquireForSection"))
	{
		KdBreakPoint();
	}
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	KdPrint(("PtPreAcquireForSection....\n"));

	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	if (Fcb && Fcb->Header.PagingIoResource)
	{
		ExAcquireResourceExclusive(Fcb->Header.PagingIoResource, TRUE);
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostAcquireForSection(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreReleaseForSection(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreReleaseForSection"))
	{
		KdBreakPoint();
	}
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreReleaseForSection....\n"));
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	if (Fcb && Fcb->Header.PagingIoResource)
	{
		ExReleaseResource(Fcb->Header.PagingIoResource);
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostReleaseForSection(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS FsCommonSetInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = NULL;
	FILE_INFORMATION_CLASS FileInfoClass;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	BOOLEAN bFcbAcquired = FALSE;
	BOOLEAN bPagingIo = FALSE;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;
	BOOLEAN bLazyWriterCallback = FALSE;
	
	FileInfoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;
	bPagingIo = BooleanFlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO);

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
	__try
	{
		if (FileEndOfFileInformation == FileInfoClass)
		{
			bLazyWriterCallback = Data->Iopb->Parameters.SetFileInformation.AdvanceOnly;
		}
		if (!bLazyWriterCallback && !bPagingIo &&
			((FileInfoClass == FileEndOfFileInformation) ||
			(FileInfoClass == FileAllocationInformation)))
		{
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock, Data, IrpContext, NULL, NULL);
			if (FLT_PREOP_COMPLETE == FltOplockStatus)
			{
				try_return(Status = Data->IoStatus.Status);
			}
			if (FLT_PREOP_PENDING == FltOplockStatus)
			{
				try_return(Status = STATUS_PENDING);
			}
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
		}
	
		bFcbAcquired = ExAcquireResourceShared(Fcb->Resource, TRUE);
		if (!bFcbAcquired)
		{
			Status = FsPostRequest(Data, IrpContext);
			try_return(Status);
		}

		Status = STATUS_SUCCESS;

		switch (FileInfoClass)
		{
		case FileBasicInformation:
			Status = FsSetBasicInfo(Data, IrpContext, Fcb);
			break;
		case FileDispositionInformation:
		{
			FILE_DISPOSITION_INFORMATION FileDisPosition;
			FileDisPosition.DeleteFile = TRUE;
			if (!Fcb->bRecycleBinFile && FlagOn(Ccb->ProcType, PROCESS_ACCESS_EXPLORER))
			{
				SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			}
			else
			{
				Status = FsSetFileInformation(FltObjects, Fcb->CcFileObject,
					&FileDisPosition, sizeof(FILE_DISPOSITION_INFORMATION), FileDispositionInformation);
				if (NT_SUCCESS(Status))
				{
					SetFlag(FileObject->Flags, FO_DELETE_ON_CLOSE);
					SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
				}
				else
				{
					KdPrint(("Cleanup:FltSetInformationFile failed(0x%x)....\n", Status));
				}
			}
		}
			break;
		case FileRenameInformation:
			Status = FsRenameFileInfo(Data, FltObjects, Fcb, Ccb);
			break;
		case FilePositionInformation:
			Status = FsSetPositionInfo(Data, FileObject);
			break;
		case FileAllocationInformation:
			Status = FsSetAllocationInfo(Data, IrpContext, FileObject, Fcb, Ccb);
			break;
		case FileEndOfFileInformation:
			Status = FsSetEndOfFileInfo(Data, IrpContext, FileObject, Fcb, Ccb);
			break;
		case FileValidDataLengthInformation:
			break;

		default:
			Status = STATUS_INVALID_DEVICE_REQUEST;
			break;
		}

	try_exit: NOTHING;
	}
	__finally
	{
		if (bFcbAcquired)
		{
			ExReleaseResource(Fcb->Resource);
		}
		if (!AbnormalTermination() && Status != STATUS_PENDING)
		{
			FsCompleteRequest(&IrpContext, &Data, Status, FALSE);
		}
	}
	return Status;
}

NTSTATUS FsSetBasicInfo(__inout PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext, __inout PDEFFCB Fcb)
{
	LONGLONG CurrentTime;
	BOOLEAN bTimeChanged = FALSE;
	PFILE_BASIC_INFORMATION pBasic = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

	KeQuerySystemTime((PLARGE_INTEGER)&CurrentTime);
	if (pBasic->FileAttributes != 0)
	{
		Fcb->LastChangeTime = CurrentTime;
		bTimeChanged = TRUE;
	}
	if (pBasic->CreationTime.QuadPart != 0)
	{
		Fcb->CreationTime = pBasic->CreationTime.QuadPart;
		Fcb->LastChangeTime = CurrentTime;
		bTimeChanged = TRUE;
	}
	if (pBasic->LastAccessTime.QuadPart != 0)
	{
		Fcb->LastAccessTime = pBasic->LastAccessTime.QuadPart;
		Fcb->LastChangeTime = CurrentTime;
		bTimeChanged = TRUE;
	}
	if (pBasic->LastWriteTime.QuadPart != 0)
	{
		Fcb->LastWriteTime = pBasic->LastWriteTime.QuadPart;
		Fcb->LastChangeTime = CurrentTime;
		bTimeChanged = TRUE;
	}
	if (!bTimeChanged)
	{
		Fcb->LastChangeTime = CurrentTime;
	}
	return STATUS_SUCCESS;
}

NTSTATUS FsSetAllocationInfo(__in PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_OBJECT FileObject, __inout PDEFFCB Fcb, __in PDEF_CCB Ccb)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_ALLOCATION_INFORMATION Buffer = NULL;
	ULONG NewAllocationSize = 0;
	ULONG HeaderSize = 0;

	BOOLEAN bFileSizeTruncated = FALSE;
	BOOLEAN bCacheMapInitialized = FALSE;
	BOOLEAN bResourceAcquired = FALSE;
	BOOLEAN bFileSizeChanged = FALSE;
	ULONG OrgFileSize = 0;
	ULONG OrgValidDataLength = 0;

	PAGED_CODE();

	Buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	NewAllocationSize = Buffer->AllocationSize.LowPart;

	//  Check that the new file allocation is legal
	if (!FsIsIoRangeValid(Buffer->AllocationSize, 0))
	{
		return STATUS_DISK_FULL;
	}
	//  If we haven't yet looked up the correct AllocationSize, do so.
	if (FCB_LOOKUP_ALLOCATIONSIZE_HINT == Fcb->Header.AllocationSize.QuadPart)
	{
		FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
	}
	//  This is kinda gross, but if the file is not cached, but there is
	//  a data section, we have to cache the file to avoid a bunch of
	//  extra work.
	if ((NULL != FileObject->SectionObjectPointer->DataSectionObject) &&
		(NULL == FileObject->SectionObjectPointer->SharedCacheMap) && 
		!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
	{
		CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, FALSE, &g_CacheManagerCallbacks, Fcb);
		bCacheMapInitialized = TRUE;
	}
	
	Fcb->FcbState |= FCB_STATE_TRUNCATE_ON_CLOSE; //  Now mark the fact that the file needs to be truncated on close

	SetFlag(FileObject->Flags, FO_FILE_MODIFIED);//  Now mark that the time on the dirent needs to be updated on close.
	__try
	{
		bFileSizeChanged = (NewAllocationSize != Fcb->Header.AllocationSize.QuadPart);
		if (NewAllocationSize > Fcb->Header.AllocationSize.QuadPart)
		{
			Fcb->Header.AllocationSize.QuadPart = NewAllocationSize;
			KdPrint(("[%s] file size:%d, allocationSize:%d, line=%d....\n", __FUNCTION__, Fcb->Header.FileSize.QuadPart, Fcb->Header.AllocationSize.QuadPart, __LINE__));
		}
		else
		{
			//
			//  Check here if we will be decreasing file size and synchonize with
			//  paging IO.
			//
			if (Fcb->Header.FileSize.QuadPart > (NewAllocationSize + (Fcb->bEnFile ? Fcb->FileHeaderLength : 0)))
			{
				if (!MmCanFileBeTruncated(FileObject->SectionObjectPointer,
					&Buffer->AllocationSize))
				{
					bFileSizeChanged = FALSE;
					try_return(Status = STATUS_USER_MAPPED_FILE);
				}

				OrgFileSize = Fcb->Header.FileSize.LowPart;
				OrgValidDataLength = Fcb->Header.ValidDataLength.LowPart;

				bResourceAcquired = FsAcquireExclusiveFcb(IrpContext, Fcb);

				Fcb->Header.FileSize.LowPart = NewAllocationSize;

				//
				//  If we reduced the file size to less than the ValidDataLength,
				//  adjust the VDL.  Likewise ValidDataToDisk.
				//

				if (Fcb->Header.ValidDataLength.LowPart > Fcb->Header.FileSize.LowPart)
				{
					Fcb->Header.ValidDataLength.LowPart = Fcb->Header.FileSize.LowPart;
				}
			}
			KdPrint(("[%s] file size:%d, allocationSize:%d, line=%d....\n", __FUNCTION__, Fcb->Header.FileSize.QuadPart, Fcb->Header.AllocationSize.QuadPart, __LINE__));
			if (bFileSizeChanged)
			{
				CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
			}
		}
	try_exit:NOTHING;
	}
	__finally
	{
		if (AbnormalTermination() && bFileSizeChanged)
		{
			Fcb->Header.FileSize.LowPart = OrgFileSize;
			Fcb->Header.ValidDataLength.LowPart = OrgValidDataLength;
			if (NULL != FileObject->SectionObjectPointer->SharedCacheMap)
			{
				*CcGetFileSizePointer(FileObject) = Fcb->Header.FileSize;
			}
		}
		if (bCacheMapInitialized)
		{
			CcUninitializeCacheMap(FileObject, NULL, NULL);
		}
		if (bResourceAcquired)
		{
			FsReleaseFcb(IrpContext, Fcb);
		}
	}
	return Status;
}

BOOLEAN FsIsIoRangeValid(__in LARGE_INTEGER Start, __in ULONG Length)
{
	return !(Start.HighPart || Start.LowPart + Length < Start.LowPart);
}

NTSTATUS FsSetEndOfFileInfo(__in PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_OBJECT FileObject, __inout PDEFFCB Fcb, __in PDEF_CCB Ccb)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_END_OF_FILE_INFORMATION Buffer = NULL;

	ULONG NewFileSize = 0;
	ULONG InitialFileSize = 0;
	ULONG InitialValidDataLength = 0;

	BOOLEAN bCacheMapInitialized = FALSE;
// 	BOOLEAN bUnwindFileSizes = FALSE;
 	BOOLEAN bResourceAcquired = FALSE;
	BOOLEAN bFileSizeChanged = FALSE;

	Buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

	__try
	{
		if (!FsIsIoRangeValid(Buffer->EndOfFile, 0))
		{
			try_return(Status = STATUS_INVALID_DEVICE_REQUEST);
		}
		NewFileSize = Fcb->bEnFile ? Buffer->EndOfFile.LowPart + Fcb->FileHeaderLength : Buffer->EndOfFile.LowPart;
		if (FCB_LOOKUP_ALLOCATIONSIZE_HINT == Fcb->Header.AllocationSize.QuadPart)
		{
			FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
		}
		if ((NULL != FileObject->SectionObjectPointer->DataSectionObject) &&
			(NULL == FileObject->SectionObjectPointer->SharedCacheMap) &&
			!FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
		{
			if (FlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE))
			{
				FsRaiseStatus(IrpContext, STATUS_FILE_CLOSED);
			}
			CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, FALSE, &g_CacheManagerCallbacks, Fcb);
			bCacheMapInitialized = TRUE;
		}
		if (Data->Iopb->Parameters.SetFileInformation.AdvanceOnly)
		{
			InitialValidDataLength = NewFileSize;
			NewFileSize = Fcb->Header.FileSize.LowPart;
			//
			//  We can always move the valid data length in the Scb up to valid data
			//  on disk for this call back.  Otherwise we may lose data in a mapped
			//  file if a user does a cached write to the middle of a page.
			//  For the typical case, Scb valid data length and file size are
			//  equal so no adjustment is necessary.
			//
			if ((Fcb->Header.ValidDataLength.QuadPart < NewFileSize) &&
				(InitialValidDataLength > Fcb->Header.ValidDataLength.QuadPart)
				)
			{
				//
				//  Set the valid data length to the smaller of ValidDataToDisk
				//  or file size.
				//
				if (InitialValidDataLength >= Fcb->Header.FileSize.LowPart)
				{

					InitialValidDataLength = Fcb->Header.FileSize.LowPart;
				}


				ExAcquireFastMutex(Fcb->Header.FastMutex);

				Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength;
				ExReleaseFastMutex(Fcb->Header.FastMutex);
			}
		}
		else
		{
			//
			//  Check if we really are changing the file size.
			//
			if (Fcb->Header.FileSize.QuadPart != NewFileSize)
			{
				bFileSizeChanged = TRUE;
			}
			//  Check if we are shrinking a mapped file in the non-lazywriter case.  MM
			//  will tell us if someone currently has the file mapped.
			//
			if ((NewFileSize < Fcb->Header.FileSize.QuadPart) &&
				!MmCanFileBeTruncated(FileObject->SectionObjectPointer,
				(PLARGE_INTEGER)&NewFileSize))
			{
				try_return(Status = STATUS_USER_MAPPED_FILE);
			}
			//
			//  It is extremely expensive to make this call on a file that is not
			//  cached, and Ntfs has suffered stack overflows in addition to massive
			//  time and disk I/O expense (CcZero data on user mapped files!).  Therefore,
			//  if no one has the file cached, we cache it here to make this call cheaper.
			//
			//  Don't create the stream file if called from FsRtlSetFileSize (which sets
			//  IRP_PAGING_IO) because mm is in the process of creating a section.
			//
			//
			//  We now test if we need to modify the non-resident Eof.  We will
			//  do this in two cases.  Either we're converting from resident in
			//  two steps or the attribute was initially non-resident.  We can ignore
			//  this step if not changing the file size.
			//
			{
				//
				//  Now determine where the new file size lines up with the
				//  current file layout.  The two cases we need to consider are
				//  where the new file size is less than the current file size and
				//  valid data length, in which case we need to shrink them.
				//  Or we new file size is greater than the current allocation,
				//  in which case we need to extend the allocation to match the
				//  new file size.
				//
				InitialValidDataLength = Fcb->Header.ValidDataLength.LowPart;
				if (NewFileSize < InitialValidDataLength)
				{
					Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength = NewFileSize;
				}

				Fcb->Header.FileSize.QuadPart = NewFileSize;
				//
				//  Call our common routine to modify the file sizes.  We are now
				//  done with NewFileSize and NewValidDataLength, and we have
				//  PagingIo + main exclusive (so no one can be working on this Scb).
				//  NtfsWriteFileSizes uses the sizes in the Scb, and this is the
				//  one place where in Ntfs where we wish to use a different value
				//  for ValidDataLength.  Therefore, we save the current ValidData
				//  and plug it with our desired value and restore on return.
				//
				if (NewFileSize > Fcb->Header.AllocationSize.QuadPart)
				{
					LARGE_INTEGER temp1;
					temp1.QuadPart = NewFileSize + g_SectorSize - 1;
					temp1.LowPart &= ~((ULONG)g_SectorSize - 1);//动态获取扇区大小，以后可能会变
					Fcb->Header.AllocationSize.QuadPart = temp1.QuadPart;
				}
			}
			//  If the file size changed then mark this file object as having changed the size.
			if (bFileSizeChanged)
			{
				SetFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
			}
			//  Only call if the file is cached now, because the other case
			//  may cause recursion in write!

			if (CcIsFileCached(FileObject))
			{
				//  We want to checkpoint the transaction if there is one active.		
				CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
			}
		} 
		Status = STATUS_SUCCESS;
	try_exit:NOTHING;
	}
	__finally
	{
		if (bCacheMapInitialized)
		{
			CcUninitializeCacheMap(FileObject, NULL, NULL);
		}
	}


	return Status;
}

NTSTATUS FsSetPositionInfo(__in PFLT_CALLBACK_DATA Data, __in PFILE_OBJECT FileObject)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PDEVICE_OBJECT DeviceObject = NULL;
	PFILE_POSITION_INFORMATION Buffer = NULL;

	if (Data->Iopb->TargetFileObject != NULL)
	{
		DeviceObject = Data->Iopb->TargetFileObject->DeviceObject;
	}
	Buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	//
	//  Check if the file does not use intermediate buffering.  If it does
	//  not use intermediate buffering then the new position we're supplied
	//  must be aligned properly for the device
	//
	if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
	{
		if (Buffer != NULL && DeviceObject != NULL && (Buffer->CurrentByteOffset.LowPart & DeviceObject->AlignmentRequirement) != 0)
		{
			return STATUS_INVALID_PARAMETER;
		}
	}
	if (Buffer != NULL)
	{
		FileObject->CurrentByteOffset = Buffer->CurrentByteOffset;
	}
	return Status;
}

FLT_PREOP_CALLBACK_STATUS PtPreQuerySecurity(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	BOOLEAN bAcquireResource = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;
	ULONG RetLength = 0;

	PAGED_CODE();
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreQuerySecurity start, is irp operation(%d)....\n", FLT_IS_IRP_OPERATION(Data)));

	Fcb = FltObjects->FileObject->FsContext;
	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = IsTopLevelIRP(Data);
			//bAcquireResource = ExAcquireResourceShared(Fcb->Resource, TRUE);
			ntStatus = FsGetFileSecurityInfo(Data, FltObjects, Fcb);

			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("FltQuerySecurityObject failed(0x%x)...\n", ntStatus));
			}
		}
		__finally
		{
			if (bAcquireResource)
			{
				ExReleaseResourceLite(Fcb->Resource);
			}
			if (bTopLevelIrp)
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
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
	}
	KdPrint(("PtPreQuerySecurity end....\n"));
	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostQuerySecurity(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreSetSecurity(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	BOOLEAN bAcquireResource = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;

	PAGED_CODE();
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreSetSecurity start....\n"));

	Fcb = FltObjects->FileObject->FsContext;
	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = IsTopLevelIRP(Data);
			bAcquireResource = ExAcquireResourceShared(Fcb->Resource, TRUE);
			ntStatus = FltSetSecurityObject(FltObjects->Instance, Fcb->CcFileObject, Data->Iopb->Parameters.SetSecurity.SecurityInformation, Data->Iopb->Parameters.SetSecurity.SecurityDescriptor);
			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("FltSetSecurityObject failed(0x%x)...\n", ntStatus));
				__leave;
			}
		}
		__finally
		{
			Data->IoStatus.Status = ntStatus;
			if (bAcquireResource)
			{
				ExReleaseResourceLite(Fcb->Resource);
			}
			if (bTopLevelIrp)
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
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
	}
	KdPrint(("PtPreSetSecurity end....\n"));
	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostSetSecurity(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreQueryVolumeInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	PFLT_CALLBACK_DATA NewData = NULL;
	ULONG Retlength = 0;
	PDEVICE_OBJECT DeviceObject = NULL;
	PFILE_FS_VOLUME_INFORMATION VolumeInfo = Data->Iopb->Parameters.QueryVolumeInformation.VolumeBuffer;
	FS_INFORMATION_CLASS FsClass = Data->Iopb->Parameters.QueryVolumeInformation.FsInformationClass;
	ULONG Length = Data->Iopb->Parameters.QueryVolumeInformation.Length;

	PAGED_CODE();
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreQueryVolumeInformation....\n"));

	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			Fcb = FltObjects->FileObject->FsContext;
			Ccb = FltObjects->FileObject->FsContext2;
			bTopLevelIrp = IsTopLevelIRP(Data);
			if (!BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
			{
				ntStatus = FltQueryVolumeInformation(FltObjects->Instance, &Data->IoStatus, VolumeInfo, Length, FsClass);
				__leave;
			}
			if (FileFsVolumeInformation == FsClass)
			{
				VolumeInfo->VolumeCreationTime.QuadPart = Fcb->Vpb.VolumeCreationTime.QuadPart;
				VolumeInfo->VolumeSerialNumber = Fcb->Vpb.VolumeSerialNumber;
				VolumeInfo->VolumeLabelLength = Fcb->Vpb.VolumeLabelLength;
				VolumeInfo->SupportsObjects = Fcb->Vpb.SupportsObjects;
				RtlCopyMemory(VolumeInfo->VolumeLabel, Fcb->Vpb.VolumeLabel, VolumeInfo->VolumeLabelLength);
				Retlength = Length;
			}
			else
			{
				ntStatus = FltQueryVolumeInformationFile(FltObjects->Instance, Fcb->CcFileObject, VolumeInfo, Data->Iopb->Parameters.QueryVolumeInformation.Length, 
					FsClass, &Retlength);
			}
			Data->IoStatus.Information = Retlength;
		}
		__finally
		{
			Data->IoStatus.Status = ntStatus;
			
			if (bTopLevelIrp)
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
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostQueryVolumeInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreSetVolumeInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;

	PAGED_CODE();
	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreSetVolumeInformation....\n"));

	Fcb = FltObjects->FileObject->FsContext;
	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevelIrp = IsTopLevelIRP(Data);
			ntStatus = FltSetVolumeInformation(FltObjects->Instance, &Data->IoStatus, Data->Iopb->Parameters.SetVolumeInformation.VolumeBuffer, 
				Data->Iopb->Parameters.SetVolumeInformation.Length, Data->Iopb->Parameters.SetVolumeInformation.FsInformationClass);
			if (!NT_SUCCESS(ntStatus))
			{
				KdPrint(("FltSetVolumeInformation failed(0x%x)...\n", ntStatus));
			}
		}
		__finally
		{
			Data->IoStatus.Status = ntStatus;
			if (bTopLevelIrp)
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
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostSetVolumeInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

BOOLEAN GetVolDevNameByQueryObj(__in UNICODE_STRING * pSymName, __out UNICODE_STRING * pDevName, __out PULONG ReturnLength)
{
	BOOLEAN				bRet = FALSE;
	OBJECT_ATTRIBUTES	Oa = { 0 };
	NTSTATUS			ntStatus = STATUS_UNSUCCESSFUL;
	HANDLE				Handle = NULL;

	__try
	{
		if (!pSymName || !pDevName)
		{
			__leave;
		}

		InitializeObjectAttributes(
			&Oa,
			pSymName,
			OBJ_CASE_INSENSITIVE,
			NULL,
			NULL
			);

		ntStatus = ZwOpenSymbolicLinkObject(
			&Handle,
			GENERIC_READ,
			&Oa
			);
		if (!NT_SUCCESS(ntStatus))
		{
			__leave;
		}
		ntStatus = ZwQuerySymbolicLinkObject(
			Handle,
			pDevName,
			ReturnLength
			);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("[%s]ZwQuerySymbolicLinkObject failed(0x%x)...\n", __FUNCTION__, ntStatus));
			__leave;
		}

		bRet = TRUE;
	}
	__finally
	{
		if (Handle)
		{
			ZwClose(Handle);
			Handle = NULL;
		}
	}

	return bRet;
}

NTSTATUS FsRenameFileInfo(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEFFCB Fcb, __in PDEF_CCB Ccb)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = Fcb->CcFileObject;
	PFILE_RENAME_INFORMATION FileRenameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	IO_STATUS_BLOCK IoStatus = {0};
	__try
	{
		if (CcIsFileCached(FileObject))
		{
			CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &IoStatus);
			if (!NT_SUCCESS(IoStatus.Status))
			{
				KdPrint(("[%s]CcFlushCache failed(0x%x)...\n", __FUNCTION__, IoStatus.Status));
			}
		}
	
		//更新fcb，更新相关文件信息（已打开文件的相关关闭）或设置Flag，close时判断处理
		ntStatus = FltSetInformationFile(FltObjects->Instance, FileObject, Data->Iopb->Parameters.SetFileInformation.InfoBuffer,
			Data->Iopb->Parameters.SetFileInformation.Length, Data->Iopb->Parameters.SetFileInformation.FileInformationClass);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("FltSetInformationFile failed(0x%x)...\n", ntStatus));
			__leave;
		}
		SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
		
	try_exit:NOTHING;
//  		RtlZeroMemory(Fcb->wszFile, FILE_PATH_LENGTH_MAX);
//  		RtlCopyMemory(Fcb->wszFile, strNtName.Buffer, strNtName.Length);
	}
	__finally
	{
	}
	return ntStatus;
}
