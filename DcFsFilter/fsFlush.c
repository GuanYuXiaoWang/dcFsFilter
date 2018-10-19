#include "fsFlush.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	BOOLEAN bTopLevelIrp = FALSE;
	NTSTATUS Status = STATUS_SUCCESS;

	PAGED_CODE();

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	__try
	{
		bTopLevelIrp = IsTopLevelIRP(Data);
		if (FLT_IS_IRP_OPERATION(Data))
		{
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			Status = FsCommonFlush(Data, FltObjects, IrpContext);
			if (!NT_SUCCESS(Status))
			{
				Data->IoStatus.Status = Status;
				Data->IoStatus.Information = 0;
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
	}
	__finally
	{
		if (bTopLevelIrp)
		{
			IoSetTopLevelIrp(NULL);
		}
	}

	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

NTSTATUS FsCommonFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	IO_STATUS_BLOCK IoStatus;
	PDEFFCB Fcb = NULL;
	PFILE_OBJECT FileObject = NULL;
	BOOLEAN bAcquiredResource = FALSE;
	
	if (NULL == FltObjects)
	{
		FileObject = IrpContext->FileObject;
	}
	else
	{
		FileObject = FltObjects->FileObject;
	}
	if (NULL == FileObject)
	{
		return STATUS_SUCCESS;
	}
	
	Fcb = FileObject->FsContext;
	do 
	{
		__try
		{
			if (!CcIsFileCached(FileObject))
			{
				break;
			}
			bAcquiredResource = ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
			SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
			CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, &IoStatus);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			FsProcessException(&IrpContext, &Data, GetExceptionCode());
			IoStatus.Status = STATUS_UNSUCCESSFUL;
		}
		if (bAcquiredResource)
		{
			ExReleaseResourceLite(Fcb->Header.Resource);
		}
	} while (STATUS_CANT_WAIT == IoStatus.Status || STATUS_LOG_FILE_FULL == IoStatus.Status);

	FsCompleteRequest(&IrpContext, &Data, IoStatus.Status, FALSE);
	return IoStatus.Status;
}

FLT_PREOP_CALLBACK_STATUS PtPreAcquireForCcFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreAcquireForCcFlush......\n"));

	if (Fcb && Fcb->Header.PagingIoResource != NULL)
	{
		ExAcquireResourceShared(Fcb->Header.PagingIoResource, TRUE);
	}
	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostAcquireForCcFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreReleaseForCcFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreReleaseForCcFlush......\n"));
	if (Fcb && Fcb->Header.PagingIoResource != NULL)
	{
		ExReleaseResource(Fcb->Header.PagingIoResource);
	}
	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostReleaseForCcFlush(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
