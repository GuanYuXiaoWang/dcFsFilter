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

	if (IsTest(Data, FltObjects, "PtPreQueryInformation"))
	{
		KdBreakPoint();
	}
	else
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

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
			ntStatus = FsControl(Data, FltObjects, (PVOID)&IrpContext);
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

NTSTATUS FsControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;

	switch (Iopb->MinorFunction)
	{
	case IRP_MN_USER_FS_REQUEST:
		break;
	case IRP_MN_MOUNT_VOLUME:
		break;
	}


	
	return ntStatus;
}
