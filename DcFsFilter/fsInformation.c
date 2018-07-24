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
	if (!IsTest(Data, FltObjects, "PtPreQueryInformation"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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
	PDEFFCB Fcb = NULL;
	FILE_INFORMATION_CLASS FileInfoClass = Data->Iopb->Parameters.QueryFileInformation.FileInformationClass;
	PVOID pFileInfoBuffer = Data->Iopb->Parameters.QueryFileInformation.InfoBuffer;
	ULONG length = 0;

	//查询信息，是否需要独占FCB资源？？？
	__try
	{
		Fcb = FltObjects->FileObject->FsContext;
		if (NULL == Fcb)
		{
			DbgPrint("QueryInformation:Fcb is not exit!\n");
			__leave;
		}

		switch (FileInfoClass)
		{
		case FileBasicInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_BASIC_INFORMATION))
			{
				DbgPrint("QueryInformation:length(%d) < sizeof(FILE_BASIC_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length);
				try_return(ntStatus);
			}
			length = sizeof(FILE_BASIC_INFORMATION);
			FileBasicInfo = (PFILE_BASIC_INFORMATION)pFileInfoBuffer;
			FileBasicInfo->CreationTime.QuadPart = Fcb->CreationTime;
			FileBasicInfo->ChangeTime.QuadPart = Fcb->LastChangeTime;
			FileBasicInfo->FileAttributes = Fcb->Attribute;
			FileBasicInfo->LastAccessTime.QuadPart = Fcb->LastAccessTime;
			FileBasicInfo->LastWriteTime.QuadPart = Fcb->LastChangeTime;
			break;
		case FileAllInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_ALL_INFORMATION))
			{
				DbgPrint("QueryInformation:length(%d) < sizeof(FILE_ALL_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length);
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
			FileAllInfo->StandardInformation.EndOfFile = Fcb->Header.FileSize;
			break;
		case FileStandardInformation:
			if (Data->Iopb->Parameters.QueryFileInformation.Length < sizeof(FILE_STANDARD_INFORMATION))
			{
				DbgPrint("QueryInformation:length(%d) < sizeof(FILE_STANDARD_INFORMATION)...\n", Data->Iopb->Parameters.QueryFileInformation.Length);
				try_return(ntStatus);
			}
			length = sizeof(FILE_STANDARD_INFORMATION);
			FileStandardInfo = (PFILE_STANDARD_INFORMATION)pFileInfoBuffer;
			FileStandardInfo->AllocationSize = Fcb->Header.AllocationSize;
			FileStandardInfo->DeletePending = BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			FileStandardInfo->Directory = Fcb->Directory;
			FileStandardInfo->NumberOfLinks = Fcb->LinkCount;
			FileStandardInfo->EndOfFile = Fcb->Header.FileSize;
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

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (!IsTest(Data, FltObjects, "PtPreSetInformation"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif
	return FLT_PREOP_COMPLETE;
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
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (!IsTest(Data, FltObjects, "PtPreQueryEA"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif

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
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (!IsTest(Data, FltObjects, "PtPreSetEA"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif
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
	if (!IsTest(Data, FltObjects, "PtPreAcquireForSection"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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
	if (!IsTest(Data, FltObjects, "PtPreReleaseForSection"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdBreakPoint();
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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
