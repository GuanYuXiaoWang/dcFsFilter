#include "fsClose.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreClose(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevelIrp = FALSE;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	PLARGE_INTEGER TruncateSize = NULL;
	BOOLEAN bAcquire = FALSE;
	ULONG i = 0;

	PAGED_CODE();
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}	
	KdPrint(("PtPreClose begin......\n"));
	FsRtlEnterFileSystem();
	bTopLevelIrp = IsTopLevelIRP(Data);
	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			Fcb = FltObjects->FileObject->FsContext;
			Ccb = FltObjects->FileObject->FsContext2;
			if (NULL == Fcb)
			{
				__leave;
			}
			KdPrint(("close:openCount=%d, uncleanup=%d...\n", Fcb->OpenCount, Fcb->UncleanCount));
			if (0 == Fcb->OpenCount)
			{
				bAcquire = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);
				
				if (BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE) || Fcb->bRecycleBinFile)
				{
					Fcb->CcFileObject = NULL;
					Fcb->CcFileHandle = NULL;
				}

				if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
				{
					KdPrint(("file deleted.......\n"));
					ClearFlag(Fcb->FcbState, FCB_STATE_REAME_INFO);
					if (bAcquire)
					{
						ExReleaseResourceLite(Fcb->Resource);
						bAcquire = FALSE;
					}
					FsFreeFcb(Fcb, NULL);
					FltObjects->FileObject->FsContext = NULL;
				}
				if (Fcb)
				{
					ClearFlag(Fcb->FcbState, FCB_STATE_DELAY_CLOSE);
				}
			}
			if (Ccb->StreamFileInfo.StreamObject)
			{
				ObDereferenceObject(Ccb->StreamFileInfo.StreamObject);
				FltClose(Ccb->StreamFileInfo.hStreamHandle);
				Ccb->StreamFileInfo.StreamObject = NULL;
				Ccb->StreamFileInfo.hStreamHandle = NULL;
			}
			FsFreeCcb(Ccb);
			FltObjects->FileObject->FsContext2 = NULL;
		}
		__finally
		{
			if (bAcquire)
			{
				ExReleaseResourceLite(Fcb->Resource);
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

	if (bTopLevelIrp)
	{
		IoSetTopLevelIrp(NULL);
	}
	KdPrint(("PtPreClose end......\n"));
	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostClose(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(CompletionContext);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
