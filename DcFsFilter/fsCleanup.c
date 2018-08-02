#include "fsCleanup.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	PDEF_IRP_CONTEXT IrpContext = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	BOOLEAN bTopLevelIrp = FALSE;
	ULONG ProcessType = 0;
	LARGE_INTEGER FlushValidSize;
	BOOLEAN bPure = FALSE;

	PAGED_CODE();

#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreCleanup"))
	{
		KdBreakPoint();
		PFSRTL_COMMON_FCB_HEADER Fcb = FltObjects->FileObject->FsContext;
		IO_STATUS_BLOCK IoStatus;
		if (FltObjects->FileObject->SectionObjectPointer)
		{
			FlushValidSize = CcGetFlushedValidData(FltObjects->FileObject->SectionObjectPointer, FALSE);
			if (FileObject->SectionObjectPointer->DataSectionObject != NULL &&
				FileObject->SectionObjectPointer->ImageSectionObject == NULL &&
				MmCanFileBeTruncated(FileObject->SectionObjectPointer, NULL))
			{
				ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);
				ExAcquireResourceExclusiveLite(Fcb->PagingIoResource, TRUE);
				CcFlushCache(FileObject->SectionObjectPointer, NULL, 0, &IoStatus);
				if (NT_SUCCESS(IoStatus.Status))
				{
					bPure = CcPurgeCacheSection(FileObject->SectionObjectPointer, NULL, 0, 0);
				}
				ExReleaseResourceLite(Fcb->Resource);
				ExReleaseResourceLite(Fcb->PagingIoResource);
				bPure = CcUninitializeCacheMap(FileObject, &Fcb->FileSize, NULL);
			}
		}
	}
	
#endif

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	DbgPrint("PtPreCleanup......\n");
	FsRtlEnterFileSystem();
	bTopLevelIrp = IsTopLevelIRP(Data);

	if (FLT_IS_IRP_OPERATION(Data))//IRP operate
	{
		__try
		{
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			FltStatus = FsCommonCleanup(Data, FltObjects, IrpContext);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			FsProcessException(&IrpContext, &Data, GetExceptionCode());
			FltStatus = FLT_PREOP_COMPLETE;
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
	NTSTATUS Status = STATUS_SUCCESS;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	BOOLEAN bAcquireFcb = FALSE;
	LARGE_INTEGER TruncateSize;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	IO_STATUS_BLOCK IoStatus = { 0 };
	FILE_END_OF_FILE_INFORMATION FileSize;
	BOOLEAN bPureCache = FALSE;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	//
	//  If this was the last cached open, and there are open
	//  non-cached handles, attempt a flush and purge operation
	//  to avoid cache coherency overhead from these non-cached
	//  handles later.  We ignore any I/O errors from the flush.
	//
	__try
	{
		//先不考虑文件只被打开一次（即当前只有一个访问者，只有一个文件句柄）

		if (1 == Fcb->OpenCount)
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
			bAcquireFcb = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);
			
			FltCheckOplock(&Fcb->Oplock, Data, IrpContext, NULL, NULL);

			if (FlagOn(FileObject->Flags, FO_CACHE_SUPPORTED) && (Fcb->UncleanCount != 0) &&
				(Fcb->NonCachedUnCleanupCount == (Fcb->UncleanCount - 1)) &&
				Fcb->SectionObjectPointers.DataSectionObject != NULL && 
				Fcb->SectionObjectPointers.ImageSectionObject == NULL &&
				MmCanFileBeTruncated(&Fcb->SectionObjectPointers, NULL))
			{
				__try
				{
					ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
					ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);

					CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, &IoStatus);
					if (NT_SUCCESS(IoStatus.Status))
					{
						bPureCache = CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, 0);
					}
				}
				__finally
				{
					ExReleaseResourceLite(Fcb->Header.PagingIoResource);
					ExReleaseResourceLite(Fcb->Header.Resource);
				}
			}
			
			if (Fcb->DestCacheObject != NULL && FileObject->PrivateCacheMap != NULL)
			{
				CACHE_UNINITIALIZE_EVENT Event;
				KeInitializeEvent(&Event.Event, NotificationEvent, FALSE);
				TruncateSize.QuadPart = Fcb->Header.FileSize.QuadPart;
				bPureCache = CcUninitializeCacheMap(FileObject, &TruncateSize, &Event);
				if (!bPureCache)
				{
					KeWaitForSingleObject(&Event.Event, Executive, KernelMode, FALSE, NULL);
				}
			}

			InterlockedDecrement((PLONG)&Fcb->OpenCount);
			InterlockedDecrement((PLONG)&Fcb->UncleanCount);

			IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
			if (bAcquireFcb)
			{
				ExReleaseResourceLite(Fcb->Resource);
				bAcquireFcb = FALSE;
			}

			if (FlagOn(FileObject->Flags, FO_FILE_SIZE_CHANGED))
			{
				FILE_END_OF_FILE_INFORMATION FileSize;
				FileSize.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
				Status = FsSetFileInformation(FltObjects, Fcb->CcFileObject, &FileSize, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);
				if (!NT_SUCCESS(Status))
				{
					DbgPrint("Cleanup:FltSetInformationFile failed(0x%x)....\n", Status);
				}
			}

			FsFreeCcb(Ccb);
			Fcb->DestCacheObject = NULL;
			Fcb->CcFileObject = NULL;
		}
		else if (&Fcb->OpenCount > 1)
		{
			InterlockedDecrement((PLONG)&Fcb->OpenCount);
			InterlockedDecrement((PLONG)&Fcb->UncleanCount);
		}
	}
	__finally
	{
		if (bAcquireFcb)
		{
			ExReleaseResourceLite(Fcb->Resource);
		}

		FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
	}
	return FLT_PREOP_COMPLETE;
}
