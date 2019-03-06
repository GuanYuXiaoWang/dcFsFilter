#include "defaultStruct.h"
#include "fsWrite.h"
#include "fsData.h"
#include "volumeContext.h"
#include "Crypto.h"
#include "Head.h"

FLT_PREOP_CALLBACK_STATUS PtPreWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevel = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	BOOLEAN bModifyWriter = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	FsRtlEnterFileSystem();
	KdPrint(("PtPreWrite begin......\n"));

	if (FLT_IS_IRP_OPERATION(Data))
	{
		__try
		{
			bTopLevel = IsTopLevelIRP(Data);
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			if (NULL == IrpContext)
			{
				FsRaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
			}
			if (IoGetTopLevelIrp() == (PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP)
			{
				bModifyWriter = TRUE;
				IoSetTopLevelIrp((PIRP)Data);
			}
			if (FlagOn(Data->Iopb->MinorFunction, IRP_MN_COMPLETE))
			{
				FltStatus = FsCompleteMdl(Data, FltObjects, IrpContext);
			}
			else
			{
				FltStatus = FsCommonWrite(Data, FltObjects, IrpContext);
			}
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			FsProcessException(&IrpContext, &Data, GetExceptionCode());
		}
		if (bModifyWriter)
		{
			IoSetTopLevelIrp((PIRP)FSRTL_MOD_WRITE_TOP_LEVEL_IRP);
		}
		if (bTopLevel)
		{
			IoSetTopLevelIrp(NULL);
		}
	}
	else if (FLT_IS_FASTIO_OPERATION(Data))
	{
		FltStatus = FsFastIoWrite(Data, FltObjects);
	}
	else
	{
		Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Data->IoStatus.Information = 0;
		FltStatus = FLT_PREOP_COMPLETE;
	}
	FsRtlExitFileSystem();
	KdPrint(("PtPreWrite end......\n"));
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsFastIoWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects)
{
	PDEF_FCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PDEVICE_OBJECT targetDevice = IoGetRelatedDeviceObject(FileObject);
	PFAST_IO_DISPATCH FastIoDispatch = targetDevice->DriverObject->FastIoDispatch;
	PLARGE_INTEGER FileOffset = &Iopb->Parameters.Write.ByteOffset;
	ULONG LockKey = Iopb->Parameters.Write.Key;
	ULONG Length = Iopb->Parameters.Write.Length;
	PVOID Buffer = FsMapUserBuffer(Data, NULL);

	BOOLEAN bWait = CanFsWait(Data);
	BOOLEAN bAcquireResource = FALSE;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	bAcquireResource = ExAcquireResourceSharedLite(Fcb->Resource, TRUE);
	if (!Fcb->bEnFile && BooleanFlagOn(Ccb->ProcType, PROCESS_ACCESS_EXPLORER))
	{
		if (bAcquireResource)
		{
			ExReleaseResourceLite(Fcb->Resource);
		}
		return FLT_PREOP_DISALLOW_FASTIO;
	}

	if (FsRtlCopyWrite(FileObject, FileOffset, Length, bWait, LockKey, Buffer, &Data->IoStatus, targetDevice))
	{
		FltStatus = FLT_PREOP_COMPLETE;
	}
	if (bAcquireResource)
	{
		ExReleaseResourceLite(Fcb->Resource);
	}
	return FltStatus;
}

FLT_PREOP_CALLBACK_STATUS FsCommonWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_OBJECT FileObject = NULL;
	PDEF_FCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	PFSRTL_ADVANCED_FCB_HEADER Header = NULL;

	LARGE_INTEGER StartByte;
	LARGE_INTEGER ByteRange;
	LARGE_INTEGER ValidDataLength;
	LARGE_INTEGER FileSize;
	LARGE_INTEGER InitialFileSize;
	LARGE_INTEGER InitialValidDataLength;

	LONGLONG FileSizeOld = 0;
	ULONG ByteCount = 0;
	ULONG RequestedByteCount = 0;
	BOOLEAN bFileSizeChanged = FALSE;

	BOOLEAN bWait = FALSE;
	BOOLEAN bPagingIo = FALSE;
	BOOLEAN bNonCachedIo = FALSE;
	BOOLEAN bSynchronousIo = FALSE;
	BOOLEAN bWriteToEndOfFile = FALSE;

	BOOLEAN bPostIrp = FALSE;
	BOOLEAN bOplockPostIrp = FALSE;
	BOOLEAN bCalledByLazyWrite = FALSE;
	BOOLEAN bRecursiveWriteThrough = FALSE;
	BOOLEAN bPagingIoResourceAcquired = FALSE;

	BOOLEAN bFcbAcquired = FALSE;
	BOOLEAN bFcbAcquredExclusive = FALSE;
	BOOLEAN bFOResourceAcquired = FALSE;
	BOOLEAN bNonCachedIoPending = FALSE;

	BOOLEAN bResouceAcquired = FALSE;
	BOOLEAN bFcbCanDemoteToShared = FALSE;
	BOOLEAN bSwitchBackToAsync = FALSE;
	BOOLEAN bUnwindOutstandingAsync = FALSE;
	BOOLEAN bExtendingValidData = FALSE;

	BOOLEAN bWriteFileSizeToDirent = FALSE;
	BOOLEAN bExtendingFile = FALSE;
	PVOID SystemBuffer = NULL;
	PVOLUMECONTEXT volCtx = NULL;
	DEF_IO_CONTEXT IoContext = {0};
	BOOLEAN bNeedCheckContext = FALSE;

	StartByte = Iopb->Parameters.Write.ByteOffset;
	ByteCount = Iopb->Parameters.Write.Length;
	ByteRange.QuadPart = StartByte.QuadPart + (LONGLONG)ByteCount;
	if (NULL == FltObjects)
	{
		FltObjects = &IrpContext->FltObjects;
	}
	if (NULL != FltObjects)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}
	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	if (NULL == Fcb || NULL == Ccb)
	{
		Data->IoStatus.Status = STATUS_SUCCESS;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	bWait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	bPagingIo = BooleanFlagOn(Iopb->IrpFlags, IRP_PAGING_IO);
	bNonCachedIo = BooleanFlagOn(Iopb->IrpFlags, IRP_NOCACHE);
	bSynchronousIo = BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO);
	bWriteToEndOfFile = ((FILE_WRITE_TO_END_OF_FILE == StartByte.LowPart) && (-1 == StartByte.HighPart));
	//����дʱ�����д������ݾ��Ǽ��ܵģ���ô�죿�����罫Ҫд���������Դһ�����ܿ����͵ļ����ļ���
	//������������˫�ؼ���
	bNeedCheckContext = BooleanFlagOn(Ccb->CcbState, CCB_FLAG_CHECK_ORIGIN_ENCRYPTED);

	if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
	{
		SetFlag(IrpContext->Flags, IRP_CONTEXT_NETWORK_FILE);
	}
	
	if (0 == ByteCount)
	{
		Data->IoStatus.Status = STATUS_SUCCESS;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	KdPrint(("[%s]bNonCachedIo:%d, bPagingIo:%d,bEnFile:%d, StartByte:%d, ByteCount:%d...\n", __FUNCTION__, bNonCachedIo, bPagingIo, Fcb->bEnFile, StartByte, ByteCount));
	//���һ���Ǽ����ļ��յ���д����ת������Ϊ�����ļ�
	if (!bPagingIo && !Fcb->bEnFile&& BooleanFlagOn(Ccb->ProcType, PROCESS_ACCESS_EXPLORER))
	{
		Status = FsNonCacheWriteFileHeader(FltObjects, FsGetCcFileObjectByFcbOrCcb(Fcb, Ccb), Fcb);
		//Status = FsEncrypteFile(Data, FltObjects->Filter, FltObjects->Instance, Fcb->wszFile, wcslen(Fcb->wszFile) * sizeof(WCHAR), FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE), Ccb->StreamFileInfo.StreamObject);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}	
		Fcb->bEnFile = TRUE;
		Fcb->FileHeaderLength = ENCRYPT_HEAD_LENGTH;
		Fcb->bWriteHead = TRUE;
		SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
	}
	// �����ӳ�д����(�ǻ����pagingio ����֧���ӳ�д��)
	if (!bPagingIo && !bNonCachedIo && 
		!CcCanIWrite(FileObject, 
					ByteCount, 
					(BOOLEAN)(FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT) &&
					!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP)),
					BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_DEFERRED_WRITE)))
	{
		BOOLEAN bRetry = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_DEFERRED_WRITE);
		FsPrePostIrp(Data, IrpContext);
		SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_DEFERRED_WRITE);
		CcDeferWrite(FileObject,
			(PCC_POST_DEFERRED_WRITE)FsAddToWorkQueue,
			Data,
			IrpContext,
			ByteCount,
			bRetry);
		return FLT_PREOP_PENDING;
	}
	Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &volCtx);
	if (!NT_SUCCESS(Status))
	{
		Data->IoStatus.Status = Status;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	Header = &Fcb->Header;
	if (bNonCachedIo)
	{
		if (NULL == IrpContext->IoContext)
		{
			if (!bWait)
			{
				IrpContext->IoContext = ExAllocateFromNPagedLookasideList(&g_IoContextLookasideList);
			}
			else
			{
				IrpContext->IoContext = &IoContext;
				SetFlag(IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT);
			}
		}
		RtlZeroMemory(IrpContext->IoContext, sizeof(DEF_IO_CONTEXT));
		if (bWait)
		{
			KeInitializeEvent(&IrpContext->IoContext->Wait.SyncEvent, NotificationEvent, FALSE);
			IrpContext->IoContext->bPagingIo = bPagingIo;
		}
		else
		{
			IrpContext->IoContext->bPagingIo = bPagingIo;
			IrpContext->IoContext->Wait.Async.ResourceThreadId = ExGetCurrentResourceThread();
			IrpContext->IoContext->Wait.Async.RequestedByteCount = ByteCount;
			IrpContext->IoContext->Wait.Async.FileObject = FileObject;
		}
	}
	__try
	{
		if ((bNonCachedIo /*|| FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE)*/) && !bPagingIo && 
			(NULL != FileObject->SectionObjectPointer->DataSectionObject))
		{
			if (!FsAcquireExclusiveFcb(IrpContext, Fcb))
			{
				try_return(bPostIrp = TRUE);
			}
			bFcbAcquired = TRUE;
			bFcbAcquredExclusive = TRUE;
			bPagingIoResourceAcquired = ExAcquireSharedStarveExclusive(Header->PagingIoResource, TRUE);
			CcFlushCache(FileObject->SectionObjectPointer,
				bWriteToEndOfFile ? &Header->FileSize : (PLARGE_INTEGER)&StartByte,
				ByteCount,
				&Data->IoStatus);
			
			if (!NT_SUCCESS(Data->IoStatus.Status))
			{
				ExReleaseResourceLite(Header->PagingIoResource);
				bPagingIoResourceAcquired = FALSE;
				try_return(Status = Data->IoStatus.Status);
			}
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			bPagingIoResourceAcquired = ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
			CcPurgeCacheSection(FileObject->SectionObjectPointer, bWriteToEndOfFile ? &Header->FileSize : (PLARGE_INTEGER)&StartByte, ByteCount, FALSE);
			bFcbCanDemoteToShared = TRUE;
		}
		if (bPagingIo)
		{
			bPagingIoResourceAcquired = ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, TRUE);
			if (!bWait)
			{
				IrpContext->IoContext->Wait.Async.Resource = Header->PagingIoResource;
			}
			if (Fcb->MoveFileEvent)//TODO������move�¼�
			{
				KeWaitForSingleObject(Fcb->MoveFileEvent, Executive, KernelMode, FALSE, NULL);
			}
		}
		else
		{
			if (!bWait && bNonCachedIo)
			{
				if (!bFcbAcquired && !FsAcquireSharedFcbWaitForEx(IrpContext, Fcb))
				{
					try_return(bPostIrp = TRUE);
				}
				IrpContext->IoContext->Wait.Async.Resource = Header->Resource;
				IrpContext->IoContext->Wait.Async.ResourceThreadId = ((ULONG_PTR)IrpContext->IoContext) | 3;
				if (bFcbCanDemoteToShared)
				{
					IrpContext->IoContext->Wait.Async.Resource2 = Header->PagingIoResource;
				}
			}
			else
			{
				if (!bFcbAcquired && !FsAcquireSharedFcb(IrpContext, Fcb))
				{
					try_return(bPostIrp = TRUE);
				}
			}
			bFcbAcquired = TRUE;
		}
		ValidDataLength.QuadPart = Header->ValidDataLength.QuadPart;
		FileSize.QuadPart = Header->FileSize.QuadPart;
// 		ValidDataLength.QuadPart = Fcb->bWriteHead ? Header->ValidDataLength.QuadPart - Fcb->FileHeaderLength : Header->ValidDataLength.QuadPart;
// 		FileSize.QuadPart = Fcb->bWriteHead ? Header->FileSize.QuadPart - Fcb->FileHeaderLength : Header->FileSize.QuadPart;
		if (bPagingIo)
		{
			if (StartByte.QuadPart >= FileSize.QuadPart)
			{
				Data->IoStatus.Information = 0;
				try_return(Status = STATUS_SUCCESS);
			}
			if (ByteCount > (ULONG)(FileSize.QuadPart - StartByte.QuadPart))
			{
				ByteCount = (ULONG)(FileSize.QuadPart - StartByte.QuadPart);
			}
		}

		if ((Fcb->LazyWriteThread[0] == PsGetCurrentThread()) ||
			(Fcb->LazyWriteThread[1] == PsGetCurrentThread()))  //��ʾ����һ���ӳ�д
		{
			bCalledByLazyWrite = TRUE; //��ǰ��һ���ӳٵ�д����Ļ� �ǲ�����չ�ļ���С��
			if (FlagOn(Fcb->Header.Flags, FSRTL_FLAG_USER_MAPPED_FILE))  //������ļ�ӳ��
			{
				if ((StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart) &&
					(StartByte.QuadPart < FileSize.QuadPart))
				{
					if (StartByte.QuadPart + ByteCount >((ValidDataLength.QuadPart + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))) //��֤���ˢ�µ�ҳ������Ч����
					{
						try_return(Status = STATUS_FILE_LOCK_CONFLICT);
					}
				}
			}
		}
		if (FlagOn(Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) &&
			FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL))
		{
			//����������Ҳ��д��ֱ��д��
			PFLT_CALLBACK_DATA TopLevelData = (PFLT_CALLBACK_DATA)IoGetTopLevelIrp();
			if ((ULONG_PTR)TopLevelData > FSRTL_MAX_TOP_LEVEL_IRP_FLAG &&
				FLT_IS_IRP_OPERATION(TopLevelData))
			{
				PFLT_IO_PARAMETER_BLOCK Iopb = TopLevelData->Iopb;
				if ((Iopb->MajorFunction == IRP_MJ_WRITE) &&
					(Iopb->TargetFileObject->FsContext == FileObject->FsContext))
				{
					bRecursiveWriteThrough = TRUE;
					SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);
				}
			}
		}

		if (!bCalledByLazyWrite && !bRecursiveWriteThrough && (bWriteToEndOfFile || StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart))//��Ҫת���Ϊͬ������
		{
			if (!bWait)//�첽�����ó�ͬ��
			{
				bWait = TRUE;
				SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
				if (bNonCachedIo)
				{
					bSwitchBackToAsync = TRUE;//��ͬ����ת���Ϊͬ���ġ�
				}
			}
			//�����չ���ļ����Ǿ�Ҫ��ռ��Դ��
			if (bPagingIo)
			{
				ExReleaseResourceLite(Fcb->Header.PagingIoResource);
				bPagingIoResourceAcquired = FALSE;
			}
			else
			{
				if (!bFcbAcquredExclusive)
				{
					FsReleaseFcb(IrpContext, Fcb);
					bFcbAcquired = FALSE;
					if (!FsAcquireExclusiveFcb(IrpContext, Fcb))
					{
						try_return(bPostIrp = TRUE);
					}
					bFcbAcquired = TRUE;
					bFcbAcquredExclusive = TRUE;
				}
			}
			if (bSwitchBackToAsync)//����Ƿ�Ҫת�����첽������Ҫfcb����Դ�ͷ�ǰ������Ч��С
			{
				if ((Fcb->SectionObjectPointers.DataSectionObject != NULL) ||		//�����������������ͼ��Ҫ����ͬ��
					(StartByte.QuadPart + ByteCount > Fcb->Header.ValidDataLength.QuadPart))
				{
					RtlZeroMemory(IrpContext->IoContext, sizeof(DEF_IO_CONTEXT));
					KeInitializeEvent(&IrpContext->IoContext->Wait.SyncEvent, NotificationEvent, FALSE);
					bSwitchBackToAsync = FALSE;
				}
				else
				{
					if (!Fcb->OutstandingAsyncEvent)
					{
						Fcb->OutstandingAsyncEvent = FsRtlAllocatePoolWithTag(NonPagedPool, sizeof(KEVENT), 'evn');
						KeInitializeEvent(Fcb->OutstandingAsyncEvent, NotificationEvent, FALSE);
					}

					if (ExInterlockedAddUlong(&Fcb->OutstandingAsyncWrites, 1, &g_GeneralSpinLock) == 0)//�¼�����ͬ���첽����չ��Ч���ȵķǻ���д
					{
						KeClearEvent(Fcb->OutstandingAsyncEvent);
					}
					bUnwindOutstandingAsync = TRUE;
					IrpContext->IoContext->Wait.Async.OutstandingAsyncEvent = Fcb->OutstandingAsyncEvent;
					IrpContext->IoContext->Wait.Async.OutstandingAsyncWrites = Fcb->OutstandingAsyncWrites;
				}
			}
			//������Դ������ȡ���ļ���С��Ϣ
 			ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
 			FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;

// 			ValidDataLength.QuadPart = Fcb->bWriteHead ? Fcb->Header.ValidDataLength.QuadPart - Fcb->FileHeaderLength : Fcb->Header.ValidDataLength.QuadPart;
// 			FileSize.QuadPart = Fcb->bWriteHead ? Fcb->Header.FileSize.QuadPart - Fcb->FileHeaderLength : Fcb->Header.FileSize.QuadPart;

			if (bPagingIo)
			{
				if (StartByte.QuadPart >= FileSize.QuadPart)
				{
					Data->IoStatus.Information = 0;
					try_return(Status = STATUS_SUCCESS);
				}
				ByteCount = Iopb->Parameters.Write.Length;
				if (ByteCount > (ULONG)(FileSize.QuadPart - StartByte.QuadPart))
				{
					ByteCount = (ULONG)(FileSize.QuadPart - StartByte.QuadPart);
				}
			}
		}
		if (bNonCachedIo && !bWait)
		{
			IrpContext->IoContext->Wait.Async.RequestedByteCount = ByteCount;
		}
		if (NULL == Fcb->CcFileObject && NULL == Ccb->StreamInfo.FileObject)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}
		InitialFileSize.QuadPart = FileSize.QuadPart;
		InitialValidDataLength.QuadPart = ValidDataLength.QuadPart;
		if (bWriteToEndOfFile)
		{
			StartByte = Fcb->Header.FileSize;
		}
		if (!bPagingIo)
		{
			FLT_PREOP_CALLBACK_STATUS FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
				Data,
				IrpContext,
				FsOplockComplete,
				FsPrePostIrp);

			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = Data->IoStatus.Status);
			}

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				FltStatus = FLT_PREOP_PENDING;
				bOplockPostIrp = TRUE;
				bPostIrp = TRUE;
				try_return(NOTHING);
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
		if (IsFltFileLock())
		{
			if (!bPagingIo &&(Fcb->FileLock != NULL) && !FltCheckLockForWriteAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}
		else
		{
			if (!bPagingIo && (Fcb->FileLock != NULL) && !FsMyFltCheckLockForWriteAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}
		if (!bPagingIo && (StartByte.QuadPart + ByteCount + Fcb->FileHeaderLength > FileSize.QuadPart ))
		{
			bExtendingFile = TRUE;
		}

		if (bExtendingFile) //��չ���ļ���С
		{
			FileSize.QuadPart = StartByte.QuadPart + ByteCount + Fcb->FileHeaderLength;
			if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT)
			{
				FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
			}

			if (FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
			{
				ULONG ClusterSize = volCtx->ulSectorSize * volCtx->uSectorsPerAllocationUnit; //�ش�С
				LARGE_INTEGER TempLI;

				TempLI.QuadPart = FileSize.QuadPart;//ռ�ô�С
				TempLI.QuadPart += ClusterSize;
				TempLI.HighPart += (ULONG)((LONGLONG)ClusterSize >> 32);

				if (TempLI.LowPart == 0) //����Ҫ��λ 
				{
					TempLI.HighPart -= 1;
				}
				Fcb->Header.AllocationSize.LowPart = ((ULONG)FileSize.LowPart + (ClusterSize - 1)) & (~(ClusterSize - 1));
				Fcb->Header.AllocationSize.HighPart = TempLI.HighPart;
			}

			Fcb->Header.FileSize.QuadPart = FileSize.QuadPart;
			KdPrint(("[%s] file size:%d, allocationSize:%d, line=%d....\n", __FUNCTION__, Fcb->Header.FileSize.QuadPart, Fcb->Header.AllocationSize.QuadPart, __LINE__));
			if (CcIsFileCached(FileObject))
			{
				CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
			}
			else
				bFileSizeChanged = TRUE;
		}

		if (!bCalledByLazyWrite && !bRecursiveWriteThrough && (StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart))
		{
			bExtendingValidData = TRUE;
		}
		else
		{
			if (bFcbCanDemoteToShared)
			{
				ExConvertExclusiveToSharedLite(Fcb->Header.Resource);
				bFcbAcquredExclusive = FALSE;
			}
		}

		if (bNonCachedIo)
		{
			LARGE_INTEGER NewByteOffset;
			ULONG WriteLen = ByteCount;
			ULONG RealWriteLen = ByteCount;
			PUCHAR newBuf = NULL;
			PMDL newMdl = NULL;
			ULONG_PTR RetBytes = 0;
			ULONG SectorSize = volCtx->ulSectorSize;
			BOOLEAN bFileMap = FALSE;
			
			if (Ccb && FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
			{
				Fcb->CcFileObject = Ccb->StreamInfo.FileObject;
			}
			if (NULL == Fcb->CcFileObject)
			{
				Status = FsGetCcFileInfo(FltObjects->Filter, FltObjects->Instance, Fcb->wszFile, &Fcb->CcFileHandle, &Fcb->CcFileObject, FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE));
				if (!NT_SUCCESS(Status))
				{
					try_return(NOTHING);
				}
				bFileMap = TRUE;
			}

			SystemBuffer = FsMapUserBuffer(Data, NULL);
			//������С�������������
			//WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen,CRYPT_UNIT); error

			WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen, SectorSize);
			if (Fcb->DestCacheObject && ((((ULONG)StartByte.QuadPart) & (SectorSize - 1)) ||
				((WriteLen != ByteCount) && (StartByte.QuadPart + (LONGLONG)ByteCount < ValidDataLength.QuadPart))))
			{
				try_return(Status = STATUS_NOT_IMPLEMENTED);
			}
			//��0����
			if (!bCalledByLazyWrite && !bRecursiveWriteThrough && (StartByte.QuadPart > ValidDataLength.QuadPart))
			{
				FsZeroData(IrpContext,
					Fcb,
					FileObject,
					ValidDataLength.QuadPart,
					StartByte.QuadPart - ValidDataLength.QuadPart,
					volCtx->ulSectorSize);
			}

			bWriteFileSizeToDirent = TRUE;
			if (bSwitchBackToAsync)
			{
				//��Ȼ��һ���첽�����������϶����첽���������������¼�
				bWait = FALSE;
				ClearFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
			}

			//�������ǵ�ԭʼ�ļ���������ݽ��ж�ȡ��Ȼ���Ƶ���Ҫ������������
			newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLen, 'wn');
			if (newBuf == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}

			RtlZeroMemory(newBuf, WriteLen);
			RtlCopyMemory(newBuf, SystemBuffer, ByteCount);

			bFOResourceAcquired = ExAcquireResourceSharedLite(Ccb->StreamInfo.FoResource, TRUE);
			IrpContext->IoContext->Wait.Async.FO_Resource = Ccb->StreamInfo.FoResource;

			bResouceAcquired = ExAcquireResourceSharedLite(Fcb->Resource, TRUE);
			IrpContext->IoContext->Wait.Async.Resource2 = Fcb->Resource;

			if (Fcb->bEnFile)
			{
				if (!Fcb->bWriteHead)
				{
					Status = FsNonCacheWriteFileHeader(FltObjects, Fcb->CcFileObject, Fcb);
					if (NT_SUCCESS(Status))
					{
						Fcb->FileHeaderLength = ENCRYPT_HEAD_LENGTH;
						Fcb->bWriteHead = TRUE;
						Fcb->bAddHeaderLength = TRUE;
						SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
						SetFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
					}
					else
					{
						KdPrint(("write file header failed(0x%x)...\n", Status));
					}
				}
				//RealWriteLen = (ULONG)ROUND_TO_SIZE(RealWriteLen,CRYPT_UNIT);
				//����newBuf
				EncBuf(newBuf, ByteCount, Fcb->szFileHead);
			}
			NewByteOffset.QuadPart = StartByte.QuadPart + Fcb->FileHeaderLength;

			IrpContext->FileObject = bFileMap ? Fcb->CcFileObject : FsGetCcFileObjectByFcbOrCcb(Fcb, Ccb);
			IrpContext->IoContext->Data = Data;
			IrpContext->IoContext->SystemBuffer = SystemBuffer;
			IrpContext->IoContext->SwapBuffer = newBuf;
			IrpContext->IoContext->SwapMdl = newMdl;
			IrpContext->IoContext->VolCtx = volCtx;
			IrpContext->IoContext->Wait.Async.RequestedByteCount = ByteCount;
			IrpContext->IoContext->Wait.Async.FileObjectMutex = NULL;//&Ccb->StreamFileInfo.FileObjectMutex;
			IrpContext->IoContext->ByteOffset.QuadPart = StartByte.QuadPart;
			IrpContext->IoContext->FltObjects = FltObjects;
			IrpContext->IoContext->Instance = FltObjects->Instance;
			Status = FsRealWriteFile(FltObjects, IrpContext, newBuf, NewByteOffset, ByteCount, &RetBytes);
			if (bFileMap)
			{
				FsFreeCcFileInfo(&Fcb->CcFileHandle, &Fcb->CcFileObject);
			}
			if (!NT_SUCCESS(Status))
			{
				KdPrint(("[%s]FsRealWriteFile ret:0x%x....\n", __FUNCTION__, Status));
			}
			if (bWait)
			{
				Data->IoStatus.Status = Status;
				Data->IoStatus.Information = (RetBytes < ByteCount) ? RetBytes : ByteCount;

			}
			else if (NT_SUCCESS(Status))
			{
				bUnwindOutstandingAsync = FALSE;
				bNonCachedIoPending = TRUE;
				IrpContext->IoContext = NULL;
				volCtx = NULL;
				newBuf = NULL;
			}

			if (newMdl != NULL)//�ͷ��ڴ�
			{
				IoFreeMdl(newMdl);
			}
			if (newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, newBuf, 'wn');
			}
			try_return(Status);

		}
// 		if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
// 		{
// 			//�����ļ��ݲ�����������ڼӽ��ܣ����봦��
// 		}
// 		else
		{
			if (NULL == FileObject->PrivateCacheMap)
			{
				if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT)
				{
					FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
				}

				if (FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
				{
					FsPopUpFileCorrupt(IrpContext, Fcb);
					FsRaiseStatus(IrpContext, STATUS_FILE_CORRUPT_ERROR);
				}
				CcInitializeCacheMap(
					FileObject,
					(PCC_FILE_SIZES)&Header->AllocationSize,
					FALSE,
					&g_CacheManagerCallbacks,
					Fcb
					);

				if (bFileSizeChanged)
				{
					CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
				}

				CcSetReadAheadGranularity(FileObject, READ_AHEAD_GRANULARITY);
				//CcSetAdditionalCacheAttributes(FileObject, FALSE, TRUE);
				Fcb->DestCacheObject = FileObject;
			}

			//���д���ʱ���С��������Ч���ݷ�Χ������Ҫ��0
			FileSizeOld = StartByte.QuadPart - ValidDataLength.QuadPart;
			if (FileSizeOld > 0)
			{
				if (!FsZeroData(
					IrpContext,
					Fcb,
					FileObject,
					ValidDataLength.QuadPart,
					FileSizeOld,
					volCtx->ulSectorSize))
				{
					try_return(bPostIrp = TRUE);
				}
			}
			bWriteFileSizeToDirent = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH);
			if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL))
			{
				SystemBuffer = FsMapUserBuffer(Data, NULL);
				if (!CcCopyWrite(FileObject,
					(PLARGE_INTEGER)&StartByte,
					(ULONG)ByteCount,
					BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT),
					SystemBuffer))
				{
					try_return(bPostIrp = TRUE);
				}
				Data->IoStatus.Status = STATUS_SUCCESS;
				Data->IoStatus.Information = (ULONG)ByteCount;
				try_return(Status = STATUS_SUCCESS);
			}
			else
			{
				ASSERT(FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT));
				CcPrepareMdlWrite(FileObject,
					(PLARGE_INTEGER)&StartByte,
					(ULONG)ByteCount,
					&Iopb->Parameters.Write.MdlAddress,
					&Data->IoStatus);
				Status = Data->IoStatus.Status;
				try_return(Status);
			}
		}
	try_exit:NOTHING;
		if (!bNonCachedIoPending)
		{
			if (!bPostIrp)
			{
				ULONG ActualBytesWrote = (ULONG)Data->IoStatus.Information;
				if (bSynchronousIo && !bPagingIo)
				{
					FileObject->CurrentByteOffset.QuadPart = StartByte.QuadPart + ActualBytesWrote;
				}

				if (NT_SUCCESS(Status))
				{
					if (!bPagingIo)
					{
						SetFlag(FileObject->Flags, FO_FILE_MODIFIED);
					}

					if (bExtendingFile /*&& !bWriteFileSizeToDirent*/)
					{
						SetFlag(FileObject->Flags, FO_FILE_SIZE_CHANGED);
					}

					if (bExtendingValidData)
					{
						LARGE_INTEGER EndingVboWritten;
						EndingVboWritten.QuadPart = StartByte.QuadPart + ActualBytesWrote;

						if (FileSize.QuadPart < EndingVboWritten.QuadPart)
						{
							Fcb->Header.ValidDataLength.QuadPart = FileSize.QuadPart;
						}
						else
						{
							Fcb->Header.ValidDataLength.QuadPart = EndingVboWritten.QuadPart;
						}

						if (bNonCachedIo && CcIsFileCached(FileObject))  //�����»����еļ�¼
						{
							CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
						}
					}
				}
			}
			else
			{
				if (!bOplockPostIrp)
				{
					if (bExtendingFile)
					{
						if (Fcb->Header.PagingIoResource != NULL) 
						{
							(VOID)ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
						}
						Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;
						KdPrint(("[%s] file size:%d, allocationSize:%d, line=%d....\n", __FUNCTION__, Fcb->Header.FileSize.QuadPart, Fcb->Header.AllocationSize.QuadPart, __LINE__));
						if (FileObject->SectionObjectPointer->SharedCacheMap != NULL) 
						{
							CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
						}
						if (Fcb->Header.PagingIoResource != NULL)
						{
							ExReleaseResourceLite(Fcb->Header.PagingIoResource);
						}
					}
					Status = FsPostRequest(Data, IrpContext);
				}
			}
		}
	}
	__finally
	{
		if (AbnormalTermination())
		{
			PERESOURCE PagingIoResource = NULL;
			if (bExtendingFile || bExtendingValidData)
			{
				Fcb->Header.FileSize.QuadPart = InitialFileSize.QuadPart;
				Fcb->Header.ValidDataLength.QuadPart = InitialValidDataLength.QuadPart;
				if (FileObject->SectionObjectPointer->SharedCacheMap != NULL)
				{
					CcGetFileSizePointer(FileObject)->QuadPart = Fcb->Header.FileSize.QuadPart;
				}
			}
		}

		if (bUnwindOutstandingAsync)
		{
			ExInterlockedAddUlong(&Fcb->OutstandingAsyncWrites,
				0xffffffff,
				&g_GeneralSpinLock);
		}
		if (!bNonCachedIoPending)
		{
			if (bFcbAcquired)
			{
				FsReleaseFcb(NULL, Fcb);
			}
			if (bPagingIoResourceAcquired)
			{
				ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			}

			if (bFOResourceAcquired)
			{
				ExReleaseResourceLite(Ccb->StreamInfo.FoResource);
			}

			if (bResouceAcquired)
			{
				ExReleaseResourceLite(Fcb->Resource);
			}
		}
// 		else
// 		{
// 			if (BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE) && bFcbAcquired)
// 			{
// 				FsReleaseFcb(NULL, Fcb);
// 			}
// 		}

		if (volCtx != NULL)
		{
			FltReleaseContext(volCtx);
			volCtx = NULL;
		}

		if (!NT_SUCCESS(Status))
		{

		}
		else
		{
			SetFlag(Ccb->CcbState, CCB_FLAG_FILE_CHANGED);
		}
		if (Status == STATUS_FILE_CLOSED)
		{

		}
		if (bNonCachedIoPending || Status == STATUS_PENDING)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		if (FltStatus != FLT_PREOP_PENDING)
		{
			Data->IoStatus.Status = Status;

			FltStatus = FLT_PREOP_COMPLETE;
		}

		if (!bPostIrp && !AbnormalTermination())
		{
			FsCompleteRequest(&IrpContext, &Data, Data->IoStatus.Status, FALSE);
		}
	}
	return FltStatus;
}

NTSTATUS FsRealWriteFile(__in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext, __in PVOID SystemBuffer, __in LARGE_INTEGER ByteOffset, __in ULONG ByteCount, __in PULONG_PTR RetBytes)
{
	NTSTATUS Status;
	PFLT_CALLBACK_DATA NewData = NULL;
	PFILE_OBJECT FileObject = IrpContext->FileObject;
	BOOLEAN Wait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	ULONG IrpFlags = IRP_WRITE_OPERATION;

#ifndef USE_CACHE_READWRITE
	SetFlag(IrpFlags, IRP_NOCACHE);
#endif

	Status = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(Status))
	{
		NewData->Iopb->MajorFunction = IRP_MJ_WRITE;
		NewData->Iopb->Parameters.Write.ByteOffset = ByteOffset;
		NewData->Iopb->Parameters.Write.Length = ByteCount;
		NewData->Iopb->Parameters.Write.WriteBuffer = SystemBuffer;
		NewData->Iopb->TargetFileObject = FileObject;
		SetFlag(NewData->Iopb->IrpFlags, IrpFlags);

		if (Wait)
		{
			SetFlag(NewData->Iopb->IrpFlags, IRP_SYNCHRONOUS_API);
			FltPerformSynchronousIo(NewData);

			Status = NewData->IoStatus.Status;
			*RetBytes = NewData->IoStatus.Information;
		}
		else
		{
			if (FlagOn(IrpContext->IoContext->Wait.Async.ResourceThreadId, 3))
			{
				if (IrpContext->IoContext->Wait.Async.Resource != NULL)
				{
					ExSetResourceOwnerPointer(IrpContext->IoContext->Wait.Async.Resource, (PVOID)IrpContext->IoContext->Wait.Async.ResourceThreadId);
				}
				if (IrpContext->IoContext->Wait.Async.Resource2 != NULL)
				{
					ExSetResourceOwnerPointer(IrpContext->IoContext->Wait.Async.Resource2, (PVOID)IrpContext->IoContext->Wait.Async.ResourceThreadId);
				}
				if (IrpContext->IoContext->Wait.Async.FO_Resource != NULL)
				{
					ExSetResourceOwnerPointer(IrpContext->IoContext->Wait.Async.FO_Resource, (PVOID)IrpContext->IoContext->Wait.Async.ResourceThreadId);
				}
			}
			Status = FltPerformAsynchronousIo(NewData, FsWriteFileAsyncCompletionRoutine, IrpContext->IoContext);
		}
	}

	if (NewData != NULL && Wait)
	{
		FltFreeCallbackData(NewData);
	}

	return Status;
}

VOID FsWriteFileAsyncCompletionRoutine(__in PFLT_CALLBACK_DATA Data, __in PFLT_CONTEXT Context)
{
	PDEF_IO_CONTEXT IoContext = (PDEF_IO_CONTEXT)Context;
	PERESOURCE Resource = IoContext->Wait.Async.Resource;
	PERESOURCE Resource2 = IoContext->Wait.Async.Resource2;
	PERESOURCE FO_Resource = IoContext->Wait.Async.FO_Resource;
	ERESOURCE_THREAD ResourceThreadId = IoContext->Wait.Async.ResourceThreadId;
	PVOLUMECONTEXT volCtx = IoContext->VolCtx;
	PFLT_CALLBACK_DATA OrgData = IoContext->Data;
	PFILE_OBJECT FileObject = IoContext->Wait.Async.FileObject;
	PDEF_FCB Fcb = (PDEF_FCB)FileObject->FsContext;
	PFAST_MUTEX pFileObjectMutex = IoContext->Wait.Async.FileObjectMutex;
	LONGLONG EndByteOffset = 0;
	ULONG ByteCount = IoContext->Wait.Async.RequestedByteCount;
	ULONG_PTR RetBytes = Data->IoStatus.Information;
	PIRP TopLevelIrp = IoContext->TopLevelIrp;

	EndByteOffset = IoContext->ByteOffset.QuadPart + ByteCount;
	OrgData->IoStatus.Status = Data->IoStatus.Status;

	if (NT_SUCCESS(OrgData->IoStatus.Status))
	{
		if (!IoContext->bPagingIo)
		{
			SetFlag(FileObject->Flags, FO_FILE_MODIFIED);
		}
	}

	OrgData->IoStatus.Information = (RetBytes < ByteCount) ? RetBytes : ByteCount;

	if ((IoContext->Wait.Async.OutstandingAsyncEvent != NULL) &&
		(ExInterlockedAddUlong(&IoContext->Wait.Async.OutstandingAsyncWrites,
		0xffffffff,
		&g_GeneralSpinLock) == 1))
	{
		KeSetEvent(IoContext->Wait.Async.OutstandingAsyncEvent, 0, FALSE);
	}

	if (Resource != NULL)
	{
		ExReleaseResourceForThreadLite(
			Resource,
			ResourceThreadId
			);
	}

	if (Resource2 != NULL)
	{
		ExReleaseResourceForThreadLite(
			Resource2,
			ResourceThreadId
			);
	}
	FltFreeCallbackData(Data);

	if (IoContext->SwapMdl != NULL)
	{
		IoFreeMdl(IoContext->SwapMdl);
	}

	FltFreePoolAlignedWithTag(IoContext->Instance, IoContext->SwapBuffer, 'rn');

	ExFreeToNPagedLookasideList(
		&g_IoContextLookasideList,
		IoContext
		);

	if (pFileObjectMutex != NULL)
	{
		ExReleaseFastMutex(pFileObjectMutex);
	}
	if (FO_Resource != NULL)
	{
		ExReleaseResourceForThreadLite(
			FO_Resource,
			ResourceThreadId
			);
	}

	if (volCtx != NULL)
	{
		FltReleaseContext(volCtx);
		volCtx = NULL;
	}
	FltCompletePendedPreOperation(OrgData, FLT_PREOP_COMPLETE, NULL);
}

FLT_PREOP_CALLBACK_STATUS PtPreAcquireForModWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	BOOLEAN bAcquiredFile = FALSE;
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreAcquireForModWrite......\n"));
	PDEF_FCB Fcb = FltObjects->FileObject->FsContext;
	if (Fcb != NULL && Fcb->Header.PagingIoResource != NULL)
	{
		bAcquiredFile = ExAcquireResourceShared(Fcb->Header.PagingIoResource, FALSE);
	}

	if (!bAcquiredFile)
	{
		Data->IoStatus.Status = STATUS_CANT_WAIT;
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostAcquireForModWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreReleaseForModWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	KdPrint(("PtPreReleaseForModWrite......\n"));
	PDEF_FCB Fcb = FltObjects->FileObject->FsContext;
	if (Fcb && Fcb->Header.PagingIoResource != NULL)
	{
		ExReleaseResource(Fcb->Header.PagingIoResource);
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostReleaseForModWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

