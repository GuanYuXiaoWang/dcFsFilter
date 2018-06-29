#include "fsCleanup.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS  status;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	BOOLEAN bTopLevelIrp = IsTopLevelIRP(Data);

	PAGED_CODE();

	FsRtlEnterFileSystem();
	if (!IsMyFakeFcb(FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	
	__try
	{
		IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
		status = FsCommonCleanup(Data, FltObjects, IrpContext);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		FsProcessException(&IrpContext, &Data, GetExceptionCode());
		FltStatus = FLT_PREOP_COMPLETE;
	}

	if (bTopLevelIrp)
	{
		IoSetTopLevelIrp(NULL);
	}
	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	FLT_POSTOP_CALLBACK_STATUS FltStatus = FLT_POSTOP_FINISHED_PROCESSING;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FltStatus;
}

FLT_PREOP_CALLBACK_STATUS FsCommonCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	BOOLEAN bAcquireFcb = FALSE;
	PLARGE_INTEGER TruncateSize = NULL;
	LARGE_INTEGER LocalTruncateSize;

	UNREFERENCED_PARAMETER(Data);

	Fcb = FltObjects->FileObject->FsContext;
	Ccb = FltObjects->FileObject->FsContext2;
	//
	//  If this was the last cached open, and there are open
	//  non-cached handles, attempt a flush and purge operation
	//  to avoid cache coherency overhead from these non-cached
	//  handles later.  We ignore any I/O errors from the flush.
	//
	__try
	{
		//先不考虑文件只被打开一次（即当前只有一个访问者，只有一个文件句柄）

		if (1 == Fcb->UncleanCount)
		{
			//
			//  Check if we should be deleting the file.  The
			//  delete operation really deletes the file but
			//  keeps the Fcb around for close to do away with.
			//
			if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
			{
				//todo:delete opereation
			}
			else
			{

			}
			LocalTruncateSize = Fcb->Header.FileSize;
			TruncateSize = &LocalTruncateSize;

			if (FlagOn(Fcb->FcbState, FO_CACHE_SUPPORTED) && (Fcb->NonCachedUnCleanupCount != 0) &&
				(Fcb->NonCachedUnCleanupCount == Fcb->UncleanCount))
			{
				//CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
				ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
				ExReleaseResourceLite(Fcb->Header.PagingIoResource);
				CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE);
			}
			CcUninitializeCacheMap(FltObjects->FileObject, TruncateSize, NULL);

			FsFreeFcb(Fcb, IrpContext);
			FsFreeCcb(Ccb);
		}
	}
	__finally
	{

	}
	return FLT_PREOP_COMPLETE;
}
