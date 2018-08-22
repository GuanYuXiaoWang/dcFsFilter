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
		PFSRTL_COMMON_FCB_HEADER Header = FltObjects->FileObject->FsContext;
		if (NULL != Header)
		{
			DbgPrint("File Size=%d, vaildata size=%d....\n", Header->FileSize.QuadPart, Header->ValidDataLength.QuadPart);
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
	int i = 0;

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
		//�Ȳ������ļ�ֻ����һ�Σ�����ǰֻ��һ�������ߣ�ֻ��һ���ļ������
		DbgPrint("clean:openCount=%d, uncleanup=%d...\n", Fcb->OpenCount, Fcb->UncleanCount);
		if (1 == Fcb->OpenCount)
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

			//
			//  Check if we should be deleting the file.  The
			//  delete operation really deletes the file but
			//  keeps the Fcb around for close to do away with.
			//
			if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE))
			{
				//todo:delete opereation
				FsFreeCcb(Ccb);
				FsFreeFcb(Fcb, NULL);
				FileObject->FsContext = NULL;
				FileObject->FsContext2 = NULL;
			}
			else
			{
				bAcquireFcb = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);

				FltCheckOplock(&Fcb->Oplock, Data, IrpContext, NULL, NULL);

				if (FlagOn(FileObject->Flags, FO_CACHE_SUPPORTED) && (Fcb->UncleanCount != 0) &&
					Fcb->SectionObjectPointers.DataSectionObject != NULL &&
					Fcb->SectionObjectPointers.ImageSectionObject == NULL &&
					MmCanFileBeTruncated(&Fcb->SectionObjectPointers, NULL))
				{
					__try
					{
						ExAcquireResourceExclusiveLite(Fcb->Header.Resource, TRUE);
						ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
 						CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, &IoStatus);
 						bPureCache = CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, 0);
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
				SetFlag(FileObject->Flags, FO_CLEANUP_COMPLETE);
				if (bAcquireFcb)
				{
					ExReleaseResourceLite(Fcb->Resource);
					bAcquireFcb = FALSE;
				}

				if (/*!Fcb->bWriteHead*/FALSE)
				{
					Status = FsNonCacheWriteFileHeader(FltObjects, Fcb->CcFileObject, 52, Fcb);
					if (NT_SUCCESS(Status))
					{
						Fcb->bWriteHead = TRUE;
						Fcb->bAddHeaderLength = TRUE;
						SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
						SetFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
					}
					else
					{
						DbgPrint("write file header failed(0x%x)...\n", Status);
					}
				}

				if (Fcb->bAddHeaderLength)
				{
					Fcb->bAddHeaderLength = FALSE;
					Fcb->Header.FileSize.QuadPart += ENCRYPT_HEAD_LENGTH;
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
					ClearFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
				}

				RtlZeroMemory(Fcb->FileAllOpenInfo, sizeof(FILE_OPEN_INFO)* SUPPORT_OPEN_COUNT_MAX);
				Fcb->FileAllOpenCount = 0;
				FsFreeCcb(Ccb);
				Fcb->DestCacheObject = NULL;
				Fcb->bAddHeaderLength = FALSE;
				FileObject->FsContext2 = NULL;
				Fcb->Ccb = NULL;
				IoRemoveShareAccess(FileObject, &Fcb->ShareAccess);
			}
		}
		InterlockedDecrement((PLONG)&Fcb->OpenCount);
		InterlockedDecrement((PLONG)&Fcb->UncleanCount);
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
