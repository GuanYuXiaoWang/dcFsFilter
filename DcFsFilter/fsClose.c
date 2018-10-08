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
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreClose"))
	{
		Fcb = FltObjects->FileObject->FsContext;
		KdBreakPoint();
	}
	
#endif
	FsRtlEnterFileSystem();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}	
	KdPrint(("PtPreClose......\n"));

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
				if (BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
				{
					for (i = 0; i < Fcb->FileAllOpenCount; i++)
					{
						if (Fcb->FileAllOpenInfo[i].FileObject)
						{
							ObDereferenceObject(Fcb->FileAllOpenInfo[i].FileObject);
						}
						if (Fcb->FileAllOpenInfo[i].FileHandle)
						{
							FltClose(Fcb->FileAllOpenInfo[i].FileHandle);
						}
					}
					RtlZeroMemory(Fcb->FileAllOpenInfo, sizeof(FILE_OPEN_INFO)* SUPPORT_OPEN_COUNT_MAX);
					Fcb->FileAllOpenCount = 0;
					Fcb->CcFileObject = NULL;
					Fcb->CcFileHandle = NULL;
				}
				if (FlagOn(Fcb->FcbState, FCB_STATE_REAME_INFO))
				{
					if (Fcb->CcFileObject)
					{
						ObDereferenceObject(Fcb->CcFileObject);
						FltClose(Fcb->CcFileHandle);
						Fcb->CcFileObject = NULL;
						Fcb->CcFileHandle = NULL;
					}
					ClearFlag(Fcb->FcbState, FCB_STATE_REAME_INFO);
				}
				if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
				{
					ClearFlag(Fcb->FcbState, FCB_STATE_REAME_INFO);
					FsFreeFcb(Fcb, NULL);
					FltObjects->FileObject->FsContext = NULL;
				}
				else if (!BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
				{
					//有一种情况：文件关闭，手动删除，把另一个文件重命名为该文件，那么FCB就需要重新更新了或删除
					//解决方法：监控非受控进程的文件行为，如果存在删除、移动、重命名情况，直接删除从FCB链表里摧毁该FCB
					//
				}

				FsFreeCcb(Ccb);
				FltObjects->FileObject->FsContext2 = NULL;
				Fcb->Ccb = NULL;
			}
		}
		__finally
		{

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
