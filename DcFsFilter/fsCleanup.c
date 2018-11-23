#include "fsCleanup.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreCleanup(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	PDEF_IRP_CONTEXT IrpContext = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	BOOLEAN bTopLevelIrp = FALSE;
	ULONG ProcessType = 0;
	BOOLEAN bPure = FALSE;

	PAGED_CODE();

#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreCleanup"))
	{
		KdBreakPoint();
		PFSRTL_COMMON_FCB_HEADER Header = FltObjects->FileObject->FsContext;
		if (NULL != Header)
		{
			KdPrint(("File Size=%d, vaildata size=%d....\n", Header->FileSize.QuadPart, Header->ValidDataLength.QuadPart));
		}
	}
#endif

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreCleanup begin......\n"));
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
	KdPrint(("PtPreCleanup end......\n"));
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
	PFILE_OBJECT FileObject = NULL;
	IO_STATUS_BLOCK IoStatus = { 0 };
	BOOLEAN bPureCache = FALSE;
	ULONG i = 0;

	if (NULL == FltObjects || NULL == FltObjects->FileObject)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FileObject = FltObjects->FileObject;
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
		if (NULL == Fcb)
		{
			__leave;
		}
		//先不考虑文件只被打开一次（即当前只有一个访问者，只有一个文件句柄）
		KdPrint(("clean:openCount=%d, uncleanup=%d, filesize=%d...\n", Fcb->OpenCount, Fcb->UncleanCount, Fcb->Header.FileSize.LowPart));
		if (1 == Fcb->OpenCount)
		{
			//
			//  Check if we should be deleting the file.  The
			//  delete operation really deletes the file but
			//  keeps the Fcb around for close to do away with.
			//
// 			if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
// 			{
// 				//todo:delete opereation
// 				FsFreeCcb(Ccb);
// 				FsFreeFcb(Fcb, NULL);
// 				FileObject->FsContext = NULL;
// 				FileObject->FsContext2 = NULL;
// 			}
// 			else
			{
				ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
				ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
				bAcquireFcb = TRUE;
				FltCheckOplock(&Fcb->Oplock, Data, IrpContext, NULL, NULL);

				if (FlagOn(FileObject->Flags, FO_CACHE_SUPPORTED) && (Fcb->UncleanCount != 0) &&
					Fcb->SectionObjectPointers.DataSectionObject != NULL &&
					Fcb->SectionObjectPointers.ImageSectionObject == NULL &&
					MmCanFileBeTruncated(&Fcb->SectionObjectPointers, NULL))
				{
 					CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, &IoStatus);
 					bPureCache = CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, 0);
				}
				if (bAcquireFcb)
				{
					ExReleaseResourceLite(Fcb->Header.PagingIoResource);
					ExReleaseResourceLite(Fcb->Header.Resource);
					bAcquireFcb = FALSE;
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
			
				SetFlag(FileObject->Flags, FO_CLEANUP_COMPLETE);
				if (Fcb->bAddHeaderLength)
				{
					Fcb->bAddHeaderLength = FALSE;
					Fcb->Header.FileSize.QuadPart += ENCRYPT_HEAD_LENGTH;
				}

				if (FlagOn(FileObject->Flags, FO_FILE_SIZE_CHANGED))
				{
					FILE_END_OF_FILE_INFORMATION FileSize;
					FileSize.EndOfFile.QuadPart = Fcb->Header.FileSize.QuadPart;
					KdPrint(("clean:file size =%d...\n", FileSize.EndOfFile.LowPart));
					Status = FsSetFileInformation(FltObjects, Fcb->CcFileObject, &FileSize, sizeof(FILE_END_OF_FILE_INFORMATION), FileEndOfFileInformation);
					if (!NT_SUCCESS(Status))
					{
						KdPrint(("Cleanup:FltSetInformationFile failed(0x%x)....\n", Status));
					}
					ClearFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
				}

				if (!BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
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

					if (Fcb->CcFileObject /*&& Fcb->FileAcessType != FILE_TXT_ACCESS*/)
					{
						ObDereferenceObject(Fcb->CcFileObject);
						FltClose(Fcb->CcFileHandle);
						Fcb->CcFileObject = NULL;
						Fcb->CcFileHandle = NULL;
					}
				}

				Fcb->DestCacheObject = NULL;
				Fcb->bAddHeaderLength = FALSE;
				Fcb->DestCacheObject = NULL;
			}
		}
		IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
		InterlockedDecrement((PLONG)&Fcb->OpenCount);
		InterlockedDecrement((PLONG)&Fcb->UncleanCount);
	}
	__finally
	{
		if (bAcquireFcb)
		{
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			ExReleaseResourceLite(Fcb->Header.Resource);
		}

		FsCompleteRequest(&IrpContext, &Data, STATUS_SUCCESS, FALSE);
	}
	return FLT_PREOP_COMPLETE;
}
