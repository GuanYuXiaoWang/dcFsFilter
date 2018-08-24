#include "defaultStruct.h"
#include "fsWrite.h"
#include "fsData.h"
#include "volumeContext.h"
#include "Crypto.h"

FLT_PREOP_CALLBACK_STATUS PtPreWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevel = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	BOOLEAN bModifyWriter = FALSE;

	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreWrite"))
	{
		PDEFFCB Fcb = FltObjects->FileObject->FsContext;
		KdBreakPoint();
	}


#endif

	FsRtlEnterFileSystem();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		FsRtlExitFileSystem();
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
#ifdef TEST
	KdBreakPoint();
#endif
	DbgPrint("PtPreWrite......\n");

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
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PDEVICE_OBJECT targetDevice = IoGetRelatedDeviceObject(FileObject);
	PFAST_IO_DISPATCH FastIoDispatch = targetDevice->DriverObject->FastIoDispatch;
	PLARGE_INTEGER FileOffset = &Iopb->Parameters.Write.ByteOffset;
	ULONG LockKey = Iopb->Parameters.Write.Key;
	ULONG Length = Iopb->Parameters.Write.Length;
	PVOID Buffer = FsMapUserBuffer(Data);

	BOOLEAN bWait = CanFsWait(Data);
	BOOLEAN bAcquireResource = FALSE;

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	bAcquireResource = ExAcquireResourceSharedLite(Fcb->Resource, TRUE);
	if (!Fcb->bEnFile && BooleanFlagOn(Fcb->FileAcessType, FILE_ACCESS_PROCESS_RW))
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
	PDEFFCB Fcb = NULL;
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
	BOOLEAN bCcFileSizeChangeDue = FALSE;
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

	DEF_IO_CONTEXT IoContext;

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

	if (NULL == Fcb || NULL == Ccb || BooleanFlagOn(FileObject->Flags, FO_CLEANUP_COMPLETE))
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
	if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
	{
		SetFlag(IrpContext->Flags, IRP_CONTEXT_NETWORK_FILE);
	}
	//KdBreakPoint();
	if (0 == ByteCount)
	{
		Data->IoStatus.Status = STATUS_SUCCESS;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}
	//如果一个非加密文件收到了写请求转变他成为加密文件
	if (!bPagingIo && !Fcb->bEnFile&& BooleanFlagOn(Fcb->FileAcessType, FILE_ACCESS_PROCESS_RW))
	{
		Status = FsTransformFileToEncrypted(Data, FltObjects, Fcb, Ccb);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			return FLT_PREOP_COMPLETE;
		}
	}
	// 处理延迟写请求(非缓存跟pagingio 均不支持延迟写入)
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
		if (NULL == IrpContext->pIoContext)
		{
			if (!bWait)
			{
				IrpContext->pIoContext = ExAllocateFromNPagedLookasideList(&g_IoContextLookasideList);
			}
			else
			{
				IrpContext->pIoContext = &IoContext;
				SetFlag(IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT);
			}
		}
		RtlZeroMemory(IrpContext->pIoContext, sizeof(DEF_IO_CONTEXT));
		if (bWait)
		{
			KeInitializeEvent(&IrpContext->pIoContext->Wait.SyncEvent, NotificationEvent, FALSE);
			IrpContext->pIoContext->bPagingIo = bPagingIo;
		}
		else
		{
			IrpContext->pIoContext->bPagingIo = bPagingIo;
			IrpContext->pIoContext->Wait.Async.ResourceThreadId = ExGetCurrentResourceThread();
			IrpContext->pIoContext->Wait.Async.RequestedByteCount = ByteCount;
			IrpContext->pIoContext->Wait.Async.FileObject = FileObject;
		}
	}
	__try
	{
		if ((bNonCachedIo || FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE)) && !bPagingIo && 
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

			CcPurgeCacheSection(FileObject->SectionObjectPointer,
				bWriteToEndOfFile ? &Header->FileSize : (PLARGE_INTEGER)&StartByte,
				ByteCount,
				FALSE);
			if (bPagingIoResourceAcquired)
			{
				ExReleaseResourceLite(Header->PagingIoResource);
				bPagingIoResourceAcquired = FALSE;
			}
			bFcbCanDemoteToShared = TRUE;
		}
		if (bPagingIo)
		{
			bPagingIoResourceAcquired = ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, TRUE);
			if (!bWait)
			{
				IrpContext->pIoContext->Wait.Async.Resource = Header->PagingIoResource;
			}
			if (Fcb->MoveFileEvent)//TODO：处理move事件
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
				IrpContext->pIoContext->Wait.Async.Resource = Header->Resource;
				if (bFcbCanDemoteToShared)
				{
					IrpContext->pIoContext->Wait.Async.Resource2 = Header->PagingIoResource;
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
			(Fcb->LazyWriteThread[1] == PsGetCurrentThread()))  //表示这是一个延迟写
		{
			bCalledByLazyWrite = TRUE; //当前是一个延迟的写请求的话 是不能扩展文件大小的
			if (FlagOn(Fcb->Header.Flags, FSRTL_FLAG_USER_MAPPED_FILE))  //如果是文件映射
			{
				if ((StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart) &&
					(StartByte.QuadPart < FileSize.QuadPart))
				{
					if (StartByte.QuadPart + ByteCount >((ValidDataLength.QuadPart + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1))) //保证这次刷新的页包含有效数据
					{
						try_return(Status = STATUS_FILE_LOCK_CONFLICT);
					}
				}
			}
		}
		if (FlagOn(Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO) &&
			FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_RECURSIVE_CALL))
		{
			//如果顶层操作也是写就直接写入
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

		if (!bCalledByLazyWrite && !bRecursiveWriteThrough && (bWriteToEndOfFile || StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart))//需要转变成为同步操作
		{
			if (!bWait)//异步的设置成同步
			{
				bWait = TRUE;
				SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
				if (bNonCachedIo)
				{
					bSwitchBackToAsync = TRUE;//非同步的转变成为同步的。
				}
			}
			//如果扩展的文件我们就要独占资源了
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
			if (bSwitchBackToAsync)//检查是否要转换回异步，我们要fcb主资源释放前更新有效大小
			{
				if ((Fcb->SectionObjectPointers.DataSectionObject != NULL) ||		//如果这里是有数据视图需要保持同步
					(StartByte.QuadPart + ByteCount > Fcb->Header.ValidDataLength.QuadPart))
				{

					RtlZeroMemory(IrpContext->pIoContext, sizeof(DEF_IO_CONTEXT));

					KeInitializeEvent(&IrpContext->pIoContext->Wait.SyncEvent,
						NotificationEvent,
						FALSE);
					bSwitchBackToAsync = FALSE;
				}
				else
				{
					if (!Fcb->OutstandingAsyncEvent)
					{
						Fcb->OutstandingAsyncEvent =
							FsRtlAllocatePoolWithTag(NonPagedPool,
							sizeof(KEVENT),
							'evn');

						KeInitializeEvent(Fcb->OutstandingAsyncEvent,
							NotificationEvent,
							FALSE);
					}

					if (ExInterlockedAddUlong(&Fcb->OutstandingAsyncWrites,
						1,
						&g_GeneralSpinLock) == 0)  //事件用来同步异步的扩展有效长度的非缓存写
					{
						KeClearEvent(Fcb->OutstandingAsyncEvent);
					}
					bUnwindOutstandingAsync = TRUE;

					IrpContext->pIoContext->Wait.Async.OutstandingAsyncEvent = Fcb->OutstandingAsyncEvent;
					IrpContext->pIoContext->Wait.Async.OutstandingAsyncWrites = Fcb->OutstandingAsyncWrites;
				}
			}
			//调整资源后重新取得文件大小信息
			ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;
			FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;

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
			IrpContext->pIoContext->Wait.Async.RequestedByteCount = ByteCount;
		}
		if (NULL == Fcb->CcFileObject && NULL == Ccb->StreamFileInfo.StreamObject)
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
				if (Fcb->FileLock &&
					Fcb->FileLock->FastIoIsQuestionable)
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
		if (TRUE/*IS_FLT_FILE_LOCK()*/)
		{
			if (!bPagingIo &&
				(Fcb->FileLock != NULL) &&
				!FltCheckLockForWriteAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}
		else
		{
			if (!bPagingIo &&
				(Fcb->FileLock != NULL) &&
				!FsMyFltCheckLockForWriteAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}
		if (!bPagingIo && (StartByte.QuadPart + ByteCount > FileSize.QuadPart))
		{
			bExtendingFile = TRUE;
		}

		if (bExtendingFile) //扩展了文件大小
		{
			FileSize.QuadPart = StartByte.QuadPart + ByteCount;
			if (Fcb->Header.AllocationSize.QuadPart == FCB_LOOKUP_ALLOCATIONSIZE_HINT)
			{
				FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
			}

			if (FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
			{
				ULONG ClusterSize = volCtx->ulSectorSize * volCtx->uSectorsPerAllocationUnit; //簇大小
				LARGE_INTEGER TempLI;

				TempLI.QuadPart = FileSize.QuadPart;//占用大小
				TempLI.QuadPart += ClusterSize;
				TempLI.HighPart += (ULONG)((LONGLONG)ClusterSize >> 32);

				if (TempLI.LowPart == 0) //不需要进位 
				{
					TempLI.HighPart -= 1;
				}
				Fcb->Header.AllocationSize.LowPart = ((ULONG)FileSize.LowPart + (ClusterSize - 1)) & (~(ClusterSize - 1));
				Fcb->Header.AllocationSize.HighPart = TempLI.HighPart;
			}

			Fcb->Header.FileSize.QuadPart = FileSize.QuadPart;
			if (CcIsFileCached(FileObject))
			{
				CcSetFileSizes(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize);
			}
			else
				bFileSizeChanged = TRUE;
		}

		if (!bCalledByLazyWrite &&
			!bRecursiveWriteThrough &&
			(StartByte.QuadPart + ByteCount > ValidDataLength.QuadPart))
		{
			bExtendingValidData = TRUE;
#ifndef CHANGE_TOP_IRP
			//FsExtendingValidDataSetFile(FltObjects, Fcb, Ccb);
#endif
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

			SystemBuffer = FsMapUserBuffer(Data);
			//修正大小变成扇区整数倍
			//WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen,CRYPT_UNIT); error

			WriteLen = (ULONG)ROUND_TO_SIZE(WriteLen, SectorSize);
			if (Fcb->DestCacheObject && ((((ULONG)StartByte.QuadPart) & (SectorSize - 1)) ||
				((WriteLen != ByteCount) && (StartByte.QuadPart + (LONGLONG)ByteCount < ValidDataLength.QuadPart))))
			{
				try_return(Status = STATUS_NOT_IMPLEMENTED);
			}
			//清0数据
			if (!bCalledByLazyWrite &&
				!bRecursiveWriteThrough &&
				(StartByte.QuadPart > ValidDataLength.QuadPart))
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
				//依然是一个异步操作，这样肯定能异步完成例程里面完成事件
				bWait = FALSE;
				ClearFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
			}

			//利用我们的原始文件对象对数据进行读取，然后复制到需要的数据区里面
			newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLen, 'wn');

			if (newBuf == NULL)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}

			RtlZeroMemory(newBuf, WriteLen);
			RtlCopyMemory(newBuf, SystemBuffer, ByteCount);

			bFOResourceAcquired = ExAcquireResourceSharedLite(Ccb->StreamFileInfo.pFO_Resource, TRUE);
			IrpContext->pIoContext->Wait.Async.FO_Resource = Ccb->StreamFileInfo.pFO_Resource;

			bResouceAcquired = ExAcquireResourceSharedLite(Fcb->Resource, TRUE);
			IrpContext->pIoContext->Wait.Async.Resource2 = Fcb->Resource;

			NewByteOffset.QuadPart = StartByte.QuadPart + Fcb->FileHeaderLength;

			if (Fcb->bEnFile)
			{
				if (!Fcb->bWriteHead)
				{
					Status = FsNonCacheWriteFileHeader(FltObjects, Fcb->CcFileObject, volCtx->ulSectorSize, Fcb);
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
				//RealWriteLen = (ULONG)ROUND_TO_SIZE(RealWriteLen,CRYPT_UNIT);
				//TODO：加密newBuf
				EncBuf(newBuf, ByteCount, Fcb->szFileHead);
			}

			IrpContext->FileObject = BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE) ? Ccb->StreamFileInfo.StreamObject : Fcb->CcFileObject;
			IrpContext->pIoContext->Data = Data;
			IrpContext->pIoContext->SystemBuffer = SystemBuffer;
			IrpContext->pIoContext->SwapBuffer = newBuf;
			IrpContext->pIoContext->SwapMdl = newMdl;
			IrpContext->pIoContext->volCtx = volCtx;
			IrpContext->pIoContext->Wait.Async.RequestedByteCount = ByteCount;
			IrpContext->pIoContext->Wait.Async.FileObjectMutex = NULL;//&Ccb->StreamFileInfo.FileObjectMutex;
			IrpContext->pIoContext->ByteOffset.QuadPart = StartByte.QuadPart;
			IrpContext->pIoContext->FltObjects = FltObjects;
			IrpContext->pIoContext->Instance = FltObjects->Instance;
			Status = FsRealWriteFile(FltObjects, IrpContext, newBuf, NewByteOffset, ByteCount, &RetBytes);

			if (bWait)
			{
				Data->IoStatus.Status = Status;
				Data->IoStatus.Information = (RetBytes < ByteCount) ? RetBytes : ByteCount;

			}
			else if (NT_SUCCESS(Status))
			{
				bUnwindOutstandingAsync = FALSE;
				bWait = TRUE;
				SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
				bNonCachedIoPending = TRUE;
				IrpContext->pIoContext = NULL;
				volCtx = NULL;
				newBuf = NULL;
			}

			if (newMdl != NULL)//释放内存
			{
				IoFreeMdl(newMdl);
			}
			if (newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, newBuf, 'wn');
			}
			try_return(Status);

		}
		if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
		{
			//网络文件暂不处理，如果用于加解密，必须处理
		}
		else
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

			//如果写入的时候大小超过了有效数据范围我们需要清0
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
				SystemBuffer = FsMapUserBuffer(Data);
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

						if (bNonCachedIo && CcIsFileCached(FileObject))  //更新下缓存中的记录
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
				DbgPrint("[%s]Release paging IO resource,%d.....\n", __FUNCDNAME__, __LINE__);
				ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			}

			if (bFOResourceAcquired)
			{
				ExReleaseResourceLite(Ccb->StreamFileInfo.pFO_Resource);
			}

			if (bResouceAcquired)
			{
				ExReleaseResourceLite(Fcb->Resource);
			}
		}

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
#ifdef CHANGE_TOP_IRP
		PIRP TopLevelIrp = IoGetTopLevelIrp();
		IoSetTopLevelIrp(NULL);
#endif	

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
			Status = FltPerformAsynchronousIo(NewData, FsWriteFileAsyncCompletionRoutine, IrpContext->pIoContext);
		}

#ifdef	CHANGE_TOP_IRP			
		IoSetTopLevelIrp(TopLevelIrp);
#endif
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
	PVOLUMECONTEXT volCtx = IoContext->volCtx;
	PFLT_CALLBACK_DATA OrgData = IoContext->Data;
	PFILE_OBJECT FileObject = IoContext->Wait.Async.FileObject;
	PDEFFCB Fcb = (PDEFFCB)FileObject->FsContext;
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
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreAcquireForModWrite"))
	{
		KdBreakPoint();
	}
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	DbgPrint("PtPreAcquireForModWrite......\n");
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
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
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreReleaseForModWrite"))
	{
		KdBreakPoint();
	}
	
#endif
	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	DbgPrint("PtPreReleaseForModWrite......\n");
	PDEFFCB Fcb = FltObjects->FileObject->FsContext;
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

NTSTATUS FsNonCacheWriteFileHeader(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in ULONG SectorSize, __in PDEFFCB Fcb)
{
	NTSTATUS Status;
	PFLT_CALLBACK_DATA NewData = NULL;
	ULONG WriteLength = ENCRYPT_HEAD_LENGTH;
	PUCHAR NewBuf = NULL;
	PUCHAR pHeader = NULL;
	ULONG ulCryptTpe = 0;
	
	if (strlen(Fcb->szOrgFileHead) <= 0)
	{
		RtlZeroMemory(Fcb->szFileHead, ENCRYPT_HEAD_LENGTH);
		CreateFileHead(Fcb->szFileHead);
	}

	NewBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, WriteLength, "wn");
	if (NULL == NewBuf)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	RtlZeroMemory(NewBuf, WriteLength);
	RtlCopyMemory(NewBuf, Fcb->szFileHead, ENCRYPT_HEAD_LENGTH);
	EncryptFileHead(NewBuf);

	Status = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(Status))
	{
#ifdef CHANGE_TOP_IRP
		PIRP TopLevelIrp = IoGetTopLevelIrp();
		IoSetTopLevelIrp(NULL);
#endif	

		NewData->Iopb->MajorFunction = IRP_MJ_WRITE;
		NewData->Iopb->MinorFunction = IRP_MN_NORMAL;
		NewData->Iopb->Parameters.Write.ByteOffset.QuadPart = 0;
		NewData->Iopb->Parameters.Write.Length = ENCRYPT_HEAD_LENGTH;
		NewData->Iopb->Parameters.Write.WriteBuffer = NewBuf;

		NewData->Iopb->TargetFileObject = FileObject;
		NewData->Iopb->IrpFlags = IRP_WRITE_OPERATION | IRP_NOCACHE | IRP_SYNCHRONOUS_API;
		FltPerformSynchronousIo(NewData);
		Status = NewData->IoStatus.Status;

#ifdef	CHANGE_TOP_IRP			
		IoSetTopLevelIrp(TopLevelIrp);
#endif
	}

	if (NewData != NULL)
	{
		FltFreeCallbackData(NewData);
	}
	if (NewBuf != NULL)
	{
		FltFreePoolAlignedWithTag(FltObjects->Instance, NewBuf, "wn");
	}

	return Status;
}
