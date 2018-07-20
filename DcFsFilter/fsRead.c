#include "fsRead.h"
#include "fsData.h"

#if defined(_M_IX86)
#define OVERFLOW_READ_THRESHHOLD         (0xE00)
#else
#define OVERFLOW_READ_THRESHHOLD         (0x1000)
#endif // defined(_M_IX86)

#define SafeZeroMemory(AT,BYTE_COUNT) {\
	__try {\
		RtlZeroMemory((AT), (BYTE_COUNT));\
	} __except(EXCEPTION_EXECUTE_HANDLER) {\
		FsRaiseStatus(IrpContext, STATUS_INVALID_USER_BUFFER); \
	}\
}

FLT_PREOP_CALLBACK_STATUS PtPreRead(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	FLT_PREOP_CALLBACK_STATUS FltStatus;
	BOOLEAN bTopLevel = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG ProcessType = 0;

	PAGED_CODE();

#ifdef TEST
	if (!IsTest(Data, FltObjects, "PtPreRead"))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
#endif

	FsRtlEnterFileSystem();
 	if (!IsMyFakeFcb(FltObjects->FileObject))
 	{
 		FsRtlExitFileSystem();
 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
 	}

	KdBreakPoint();

	bTopLevel = FsIsIrpTopLevel(Data);
	__try
	{
		if (FLT_IS_IRP_OPERATION(Data))
		{
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			if (NULL == IrpContext)
			{
				FsRaiseStatus(IrpContext, STATUS_INSUFFICIENT_RESOURCES);
			}
			if (FlagOn(Data->Iopb->MinorFunction, IRP_MN_COMPLETE))
			{
				FltStatus = FsCompleteMdl(Data, FltObjects, IrpContext);
			}
			else if (IoGetRemainingStackSize() < OVERFLOW_READ_THRESHHOLD)
			{
				FltStatus = FsPostStackOverflowRead(Data, FltObjects, IrpContext);
			}
			else
			{
				FltStatus = FsCommonRead(Data, FltObjects, IrpContext);
			}
		}
		else if (FLT_IS_FASTIO_OPERATION(Data))
		{
			FltStatus = FsFastIoRead(Data, FltObjects);
		}
		else
		{
			Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			Data->IoStatus.Information = 0;
			FltStatus = FLT_PREOP_COMPLETE;
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		FsProcessException(&IrpContext, &Data, GetExceptionCode());
		FltStatus = FLT_PREOP_COMPLETE;
	}
	if (bTopLevel)
	{
		IoSetTopLevelIrp(NULL);
	}
	FsRtlExitFileSystem();
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostRead(__inout PFLT_CALLBACK_DATA Data,
												__in PCFLT_RELATED_OBJECTS FltObjects,
												__in_opt PVOID CompletionContext,
												__in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsCommonRead(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

	LONGLONG StartByte;
	LARGE_INTEGER ByteRange;
	LARGE_INTEGER FileSize;
	LARGE_INTEGER ValidDataLength;
	PVOLUMECONTEXT volCtx = NULL;
	BOOLEAN bPostIrp = FALSE;
	BOOLEAN bOplockPostIrp = FALSE;

	ULONG ByteCount;
	ULONG RequestedByteCount;
	ULONG ActualBytesRead;
	PFILE_OBJECT FileObject;
	PDEFFCB Fcb = NULL;
	PDEF_CCB Ccb = NULL;
	PVOID SystemBuffer = NULL;

	BOOLEAN bWait = FALSE;
	BOOLEAN bPagingIo = FALSE;
	BOOLEAN bSynchronousIo = FALSE;
	BOOLEAN bNonCachedIo = FALSE;
	BOOLEAN bNonCachedIoPending = FALSE;
	BOOLEAN bScbAcquired = FALSE;
	BOOLEAN bFOResourceAcquired = FALSE;
	BOOLEAN bFcbResourceAcquired = FALSE;
	DEF_IO_CONTEXT stackIoContext = { 0 };
	
	StartByte = Iopb->Parameters.Read.ByteOffset.QuadPart;
	ByteCount = Iopb->Parameters.Read.Length;
	ByteRange.QuadPart = StartByte + (LONGLONG)ByteCount;
	RequestedByteCount = ByteCount;

	if (NULL == FltObjects)
	{
		FltObjects = IrpContext->FltObjects;
	}
	if (FltObjects != NULL)
	{
		FileObject = FltObjects->FileObject;
	}
	else
	{
		FileObject = Iopb->TargetFileObject;
	}

	//DbgPrint("ExGetCurrentResourceThread()=%d......\n", ExGetCurrentResourceThread());

	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;

	bWait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	bPagingIo = BooleanFlagOn(Iopb->IrpFlags, IRP_PAGING_IO);
	bNonCachedIo = BooleanFlagOn(Iopb->IrpFlags, IRP_NOCACHE);
	bSynchronousIo = BooleanFlagOn(FileObject->Flags, FO_SYNCHRONOUS_IO);

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

	Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &volCtx);
	if (!NT_SUCCESS(Status))
	{
		Data->IoStatus.Status = Status;
		Data->IoStatus.Information = 0;
		return FLT_PREOP_COMPLETE;
	}

	if (bNonCachedIo)
	{
		if (NULL == IrpContext->pIoContext)
		{
			if (!bWait)
			{
				IrpContext->pIoContext = (PDEF_IO_CONTEXT)ExAllocateFromNPagedLookasideList(&g_IoContextLookasideList);
				ClearFlag(IrpContext->Flags, IRP_CONTEXT_STACK_IO_CONTEXT);
			}
			else
			{
				IrpContext->pIoContext = &stackIoContext;
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
			IrpContext->pIoContext->Wait.Async.ResourceThreadId = IrpContext->ProcessId;
			IrpContext->pIoContext->Wait.Async.RequestedByteCount = ByteCount;
			IrpContext->pIoContext->Wait.Async.FileObject = FileObject;
		}
	}

	__try
	{
		//文件有一个缓存，并且是非缓存的I0,并且不是分页io 这个时候刷新缓存,分页io是vmm缺页调用的，这个时候不能刷新缓存数据
		if ((bNonCachedIo ||  FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE)) && !bPagingIo && (FileObject->SectionObjectPointer->DataSectionObject != NULL))
		{
			if (!FsAcquireExclusiveFcb(IrpContext, Fcb))
			{
				try_return(bPostIrp = TRUE);
			}
			ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, TRUE);
			CcFlushCache(FileObject->SectionObjectPointer, (PLARGE_INTEGER)&StartByte, (ULONG)ByteCount, &Data->IoStatus);
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
			Status = Data->IoStatus.Status;
			if (!NT_SUCCESS(Status))
			{
				try_return(Status);
			}
			ExAcquireResourceExclusive(Fcb->Header.PagingIoResource, TRUE);
			ExReleaseResource(Fcb->Header.PagingIoResource);
		}
		if (!bPagingIo)
		{
			if (!bWait && bNonCachedIo)
			{
				if (!FsAcquireSharedFcbWaitForEx(IrpContext, Fcb))
				{
					try_return(bPostIrp = TRUE);
				}
				IrpContext->pIoContext->Wait.Async.Resource = Fcb->Header.Resource;
			}
			else
			{
				if (!FsAcquireSharedFcb(IrpContext, Fcb))
				{
					try_return(bPostIrp = TRUE);
				}
			}
		}
		else
		{
			if (Fcb->Header.PagingIoResource != NULL)
			{
				if (!ExAcquireResourceSharedLite(Fcb->Header.PagingIoResource, bWait))
				{
					try_return(bPostIrp = TRUE);
				}
				if (!bWait)
				{
					IrpContext->pIoContext->Wait.Async.Resource = Fcb->Header.PagingIoResource;
				}
			}
		}
		bScbAcquired = TRUE;

		if (!bPagingIo)
		{
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock, Data, IrpContext, FsOplockComplete, FsPrePostIrp);
			if (FLT_PREOP_COMPLETE == FltOplockStatus)
			{
				try_return(Status = Data->IoStatus.Status);
			}
			if (FLT_PREOP_PENDING == FltOplockStatus)
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
		if (TRUE/*IsFltFileLock()*/)
		{
			if (!bPagingIo && (Fcb->FileLock != NULL) && !FltCheckLockForReadAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}
		else
		{
			if (!bPagingIo && (Fcb->FileLock != NULL) && !MyFltCheckLockForReadAccess(Fcb->FileLock, Data))
			{
				try_return(Status = STATUS_FILE_LOCK_CONFLICT);
			}
		}

		FileSize.QuadPart = Fcb->Header.FileSize.QuadPart;
		ValidDataLength.QuadPart = Fcb->Header.ValidDataLength.QuadPart;

		if (StartByte >= FileSize.QuadPart)
		{
			Data->IoStatus.Status = 0;
			try_return(Status = STATUS_END_OF_FILE);
		}
		if (NULL == Fcb->CcFileObject && NULL == Ccb->StreamFileInfo.StreamObject)
		{
			try_return(Status = STATUS_FILE_DELETED);
		}

		if (ByteRange.QuadPart > FileSize.QuadPart)
		{
			ByteCount = (ULONG)(FileSize.QuadPart - StartByte);
			ByteRange.QuadPart = StartByte + (ULONG)ByteCount;
			RequestedByteCount = (ULONG)ByteCount;
			if (bNonCachedIo && !bWait)
			{
				IrpContext->pIoContext->Wait.Async.RequestedByteCount = (ULONG)RequestedByteCount;
			}
		}
		if (bNonCachedIo)
		{
			LARGE_INTEGER NewByteOffset;
			ULONG readLen = ByteCount;
			PUCHAR newBuf = NULL;
			PMDL newMdl = NULL;
			ULONG_PTR RetBytes = 0;

			ULONG_PTR ZeroOffset = 0;
			ULONG_PTR ZeroLength = 0;
			
			SystemBuffer = FsMapUserBuffer(Data);
			if (ByteRange.QuadPart > ValidDataLength.QuadPart)
			{
				if (StartByte < ValidDataLength.QuadPart)
				{
					ZeroLength = (ULONG_PTR)ByteCount;
					ZeroOffset = (ULONG_PTR)(ValidDataLength.QuadPart - StartByte);
					if (ByteCount > ZeroOffset)
					{
						SafeZeroMemory(Add2Ptr(SystemBuffer, ZeroOffset), ZeroLength - ZeroOffset);
					}
				}
				else
				{
					SafeZeroMemory((PUCHAR)SystemBuffer, ByteCount);
					Data->IoStatus.Information = (ULONG_PTR)ByteCount;
					try_return(Status = STATUS_SUCCESS);
				}
			}
			ByteCount = ((ULONG)(ValidDataLength.QuadPart - StartByte) < ByteCount) ?
				(ULONG)(ValidDataLength.QuadPart - StartByte) : ByteCount;

			readLen = (ULONG)ROUND_TO_SIZE(ByteCount, volCtx->ulSectorSize);
			newBuf = FltAllocatePoolAlignedWithTag(FltObjects->Instance, NonPagedPool, readLen, 'rn');
			if (NULL == newBuf)
			{
				try_return(Status = STATUS_INSUFFICIENT_RESOURCES);
			}
			RtlZeroMemory(newBuf, readLen);
			if (ExAcquireResourceSharedLite(Ccb->StreamFileInfo.pFO_Resource, TRUE))
			{
				bFOResourceAcquired = TRUE;
			}
			IrpContext->pIoContext->Wait.Async.FO_Resource = Ccb->StreamFileInfo.pFO_Resource;
			if (ExAcquireResourceSharedLite(Fcb->Resource, TRUE))
			{
				bFcbResourceAcquired = TRUE;
			}
			IrpContext->pIoContext->Wait.Async.Resource = Fcb->Resource;

			NewByteOffset.QuadPart = StartByte + Fcb->FileHeaderLength;

			IrpContext->Fileobject = BooleanFlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE) ? Ccb->StreamFileInfo.StreamObject : Fcb->CcFileObject;
			IrpContext->pIoContext->Data = Data;
			IrpContext->pIoContext->SystemBuffer = SystemBuffer;
			IrpContext->pIoContext->SwapBuffer = newBuf;
			IrpContext->pIoContext->SwapMdl = newMdl;
			IrpContext->pIoContext->volCtx = volCtx;
			IrpContext->pIoContext->Wait.Async.ByteCount = ByteCount;
			IrpContext->pIoContext->Wait.Async.FileObjectMutex = NULL;
			IrpContext->pIoContext->FltObjects = FltObjects;
			IrpContext->pIoContext->Instance = FltObjects->Instance;
			IrpContext->pIoContext->FileHeaderLength = Fcb->FileHeaderLength;
			IrpContext->pIoContext->bEnFile = Fcb->bEnFile;

			Status = FsRealReadFile(FltObjects, IrpContext, newBuf, NewByteOffset, readLen, &RetBytes);
			if (bWait)
			{
				if (Fcb->bEnFile)
				{
					//解密Buf
				}
				RtlCopyMemory(SystemBuffer, newBuf, ByteCount);
				if (NT_SUCCESS(Status))
				{
					Data->IoStatus.Information = (RetBytes < ByteCount) ? RetBytes : RequestedByteCount;
				}
			}
			else if (NT_SUCCESS(Status))
			{
				bNonCachedIoPending = TRUE;
				IrpContext->pIoContext = NULL;
				volCtx = NULL;
				newBuf = NULL;
				newMdl = NULL;
			}

			if (newMdl != NULL)
			{
				IoFreeMdl(newMdl);
			}
			if (newBuf != NULL)
			{
				FltFreePoolAlignedWithTag(FltObjects->Instance, newBuf, 'rn');
			}
			
			try_return(Status);
		}
		else
		{
			if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
			{
				//网络文件暂不处理，如果用于加解密，必须处理
			}
			else
			{
				if (NULL == FileObject->PrivateCacheMap)
				{
					if (FCB_LOOKUP_ALLOCATIONSIZE_HINT == Fcb->Header.AllocationSize.QuadPart)
					{
						FsLookupFileAllocationSize(IrpContext, Fcb, Ccb);
					}

					if (FileSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
					{
						FsPopUpFileCorrupt(IrpContext, Fcb);
						FsRaiseStatus(IrpContext, STATUS_FILE_CORRUPT_ERROR);
					}

					CcInitializeCacheMap(FileObject, (PCC_FILE_SIZES)&Fcb->Header.AllocationSize, FALSE, &g_CacheManagerCallbacks, Fcb);
					CcSetReadAheadGranularity(FileObject, READ_AHEAD_GRANULARITY);
					Fcb->CacheObject = FileObject;
				}
				if (!FlagOn(IrpContext->MinorFunction, IRP_MN_MDL))
				{
					SystemBuffer = FsMapUserBuffer(Data);
					if (!CcCopyRead(FileObject, (PLARGE_INTEGER)&StartByte, ByteCount, bWait, SystemBuffer, &Data->IoStatus))
					{
						try_return(bPostIrp = TRUE);
					}
					DbgPrint("CcCopyRead:%s...\n", SystemBuffer);
					
					FileObject->CurrentByteOffset.QuadPart += (StartByte + ByteCount);
					Status = Data->IoStatus.Status;
					try_return(Status);
				}
				else
				{
					CcMdlRead(FileObject, (PLARGE_INTEGER)&StartByte, ByteCount, &Iopb->Parameters.Read.MdlAddress, &Data->IoStatus);
					FileObject->CurrentByteOffset.QuadPart += (StartByte + ByteCount);
					Status = Data->IoStatus.Status;
					try_return(Status);
				}
			}
		}
try_exit:NOTHING;
		if (!bNonCachedIoPending)
		{
			if (!bPostIrp)
			{
				ActualBytesRead = (ULONG)Data->IoStatus.Information;
				if (bSynchronousIo && !bPagingIo)
				{
					SetFlag(FileObject->Flags, FO_FILE_FAST_IO_READ);
				}
			}
			else
			{
				if (!bOplockPostIrp)
				{
					Status = FsPostRequest(Data, IrpContext);
					FltStatus = FLT_PREOP_PENDING;
				}
			}
		}
	}
	__finally
	{
		if (!bNonCachedIoPending)
		{
			if (bFOResourceAcquired)
			{
				ExReleaseResource(Ccb->StreamFileInfo.pFO_Resource);
			}
			if (bFcbResourceAcquired)
			{
				ExReleaseResourceLite(Fcb->Resource);
			}
			if (bScbAcquired)
			{
				if (bPagingIo)
				{
					ExReleaseResourceLite(Fcb->Header.PagingIoResource);
				}
				else
				{
					FsReleaseFcb(NULL, Fcb);
				}
			}
		}

		if (volCtx != NULL)
		{
			FltReleaseContext(volCtx);
			volCtx = NULL;
		}
		if (bNonCachedIoPending || STATUS_PENDING == Status)
		{
			FltStatus = FLT_PREOP_PENDING;
		}
		if (FltStatus != FLT_PREOP_PENDING)
		{
			Data->IoStatus.Status = Status;
			FltStatus = FLT_PREOP_COMPLETE;
		}
		if (AbnormalTermination())
		{
			DbgPrint("CcFileObject = %x ,StreamObject = %x,Flags = %x, \n", Fcb->CcFileObject, Ccb->StreamFileInfo.StreamObject, Data->Iopb->IrpFlags);
		}
		if (!bPostIrp  && !AbnormalTermination())
		{
			FsCompleteRequest(&IrpContext, &Data, Data->IoStatus.Status, FALSE);
		}
	}
	return FltStatus;
}

FLT_PREOP_CALLBACK_STATUS FsFastIoRead(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects)
{
	PDEF_CCB Ccb = NULL;
	PDEFFCB Fcb = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PDEVICE_OBJECT targetVdo = IoGetRelatedDeviceObject(FileObject);
	PFAST_IO_DISPATCH FastIoDispath = targetVdo->DriverObject->FastIoDispatch;

	PLARGE_INTEGER FileOffset = &Iopb->Parameters.Read.ByteOffset;
	ULONG LockKey = Iopb->Parameters.Read.Key;
	ULONG Length = Iopb->Parameters.Read.Length;
	
	BOOLEAN bWait = FltIsOperationSynchronous(Data);
	PIO_STATUS_BLOCK IoStatus = &Data->IoStatus;

	PVOID Buffer = FsMapUserBuffer(Data);
	//Buffer == NULL???
	Fcb = FileObject->FsContext;
	Ccb = FileObject->FsContext2;
	if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
	//if (MyFltCheckLockForReadAccess(Fcb->FileLock, Data))
	{
		if (FsRtlCopyRead(FileObject, FileOffset, Length, bWait, LockKey, Buffer, IoStatus, targetVdo))
		{
			FltStatus = FLT_PREOP_COMPLETE;
		}
	}
	return FltStatus;
}

VOID FsStackOverflowRead(IN PVOID Context, IN PKEVENT Event)
{
	NTSTATUS ExceptionCode;
	PDEF_IRP_CONTEXT IrpContext = (PDEF_IRP_CONTEXT)Context;
	if (NULL == IrpContext)
	{
		return;
	}

	SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_IN_FSP);

	__try
	{
		FsCommonRead(IrpContext->OriginatingData, NULL, IrpContext);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ExceptionCode = GetExceptionCode();
		if (STATUS_FILE_DELETED == ExceptionCode)
		{
			IrpContext->ExceptionStatus = ExceptionCode = STATUS_END_OF_FILE;
			IrpContext->OriginatingData->IoStatus.Information = 0;
		}
		FsProcessException(&IrpContext, &IrpContext->OriginatingData, ExceptionCode);
	}
	KeSetEvent(Event, 0, FALSE);
}

FLT_PREOP_CALLBACK_STATUS FsPostStackOverflowRead(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	KEVENT Event;
	PERESOURCE Resource;
	PDEFFCB Fcb;
	KeInitializeEvent(&Event, NotificationEvent, FALSE);
	Fcb = Data->Iopb->TargetFileObject->FsContext;
	if (NULL == Fcb)
	{
		return FLT_PREOP_PENDING;
	}

	if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) && Fcb->Header.PagingIoResource != NULL)
	{
		Resource = Fcb->Header.PagingIoResource;
	}
	else
	{
		Resource = Fcb->Header.Resource;
	}
	__try
	{
		FsPrePostIrp(Data, IrpContext);
		FsRtlPostStackOverflow(IrpContext, &Event, FsStackOverflowRead);
		KeWaitForSingleObject(&Event, Executive, KernelMode, FALSE, NULL);
	}
	__finally
	{
		if (Resource)
		{
			ExReleaseResourceLite(Resource);
		}
	}
	return FLT_PREOP_PENDING;
}

VOID FsReadFileAsyncCompletionRoutine(IN PFLT_CALLBACK_DATA Data, IN PFLT_CONTEXT Context)
{
	PDEF_IO_CONTEXT IoContext = (PDEF_IO_CONTEXT)Context;
	PERESOURCE Resource = IoContext->Wait.Async.Resource;
	PERESOURCE FO_Resource = IoContext->Wait.Async.FO_Resource;
	PVOLUMECONTEXT volCtx = IoContext->volCtx;
	ERESOURCE_THREAD ResourceThreadId = IoContext->Wait.Async.ResourceThreadId;
	PFLT_CALLBACK_DATA orgData = IoContext->Data;
	PFAST_MUTEX FileObjectMutex = IoContext->Wait.Async.FileObjectMutex;
	ULONG RequestByteCout = IoContext->Wait.Async.RequestedByteCount;
	ULONG ByteCount = IoContext->Wait.Async.ByteCount;
	ULONG_PTR RetBytes = Data->IoStatus.Information;
	PIRP TopLevelIrp = IoContext->TopLevelIrp;
	orgData->IoStatus.Status = Data->IoStatus.Status;
	char * pBuf = (char*)IoContext->SwapBuffer;
	int i = 0;

	KdBreakPoint();

	if (NT_SUCCESS(orgData->IoStatus.Status))
	{
		if (!IoContext->bPagingIo)
		{
			SetFlag(IoContext->Wait.Async.FileObject->Flags, FO_FILE_FAST_IO_READ);
		}
	}
	orgData->IoStatus.Information = (RetBytes < ByteCount) ? RetBytes : RequestByteCout;

	if (NULL != Resource)
	{
		ExReleaseResourceForThreadLite(Resource, ResourceThreadId);
	}

	if (NT_SUCCESS(orgData->IoStatus.Status))
	{
		//解密buf
		if (IoContext->bEnFile)
		{
			//SwapBuffer
			DbgPrint("FileText=%s.....\n", IoContext->SwapBuffer);
			for (i; i < ByteCount; i++)
			{
				pBuf[i] = pBuf[i] + 1;
			}
			DbgPrint("FileText=%s.....\n", IoContext->SwapBuffer);
		}
		RtlCopyMemory(IoContext->SystemBuffer, IoContext->SwapBuffer, ByteCount);
	}

	FltFreeCallbackData(Data);
	if (IoContext->SwapMdl != NULL)
	{
		IoFreeMdl(IoContext->SwapMdl);
		IoContext->SwapMdl = NULL;
	}
	FltFreePoolAlignedWithTag(IoContext->Instance, IoContext->SwapBuffer, 'iosw');
	ExFreeToNPagedLookasideList(&g_IoContextLookasideList, IoContext);

	if (FileObjectMutex != NULL)
	{
		ExReleaseFastMutex(FileObjectMutex);
	}

	if (FO_Resource != NULL)
	{
		ExReleaseResourceForThreadLite(FO_Resource, ResourceThreadId);
	}
	if (volCtx != NULL)
	{
		FltReleaseContext(volCtx);
		volCtx = NULL;
	}
	//orgData->IoStatus.Status = STATUS_SUCCESS;
	FltCompletePendedPreOperation(orgData, FLT_PREOP_COMPLETE, NULL);//可以在dpc级别调用
}

NTSTATUS FsRealReadFile(IN PCFLT_RELATED_OBJECTS FltObjects, IN PDEF_IRP_CONTEXT IrpContext, IN PVOID SystemBuffer, IN LARGE_INTEGER ByteOffset, IN ULONG ByteCount, OUT PULONG_PTR RetBytes)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFLT_CALLBACK_DATA NewData = NULL;
	PFILE_OBJECT FileObject = IrpContext->Fileobject;
	BOOLEAN bWait = BooleanFlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT);
	ULONG IrpFlags = IRP_READ_OPERATION;
	PIRP TopLevelIrp = NULL;

#ifndef USE_CACHE_READWRITE
	SetFlag(IrpFlags, IRP_NOCACHE);
#endif
	Status = FltAllocateCallbackData(FltObjects->Instance, FileObject, &NewData);
	if (NT_SUCCESS(Status))
	{
		/*
		if(!InSameVACB(ByteOffset.QuadPart,ByteOffset.QuadPart+ByteCount))
		{
		//
		}
		*/
#ifdef CHANGE_TOP_IRP
		TopLevelIrp = IoGetTopLevelIrp();
		IoSetTopLevelIrp(NULL);
#endif
		NewData->Iopb->MajorFunction = IRP_MJ_READ;
		NewData->Iopb->Parameters.Read.ByteOffset = ByteOffset;
		NewData->Iopb->Parameters.Read.Length = ByteCount;
		NewData->Iopb->Parameters.Read.ReadBuffer = SystemBuffer;
		NewData->Iopb->TargetFileObject = FileObject;

		SetFlag(NewData->Iopb->IrpFlags, IrpFlags);

		if (bWait)
		{
			SetFlag(NewData->Iopb->IrpFlags, IRP_SYNCHRONOUS_API);
			FltPerformSynchronousIo(NewData);
			Status = NewData->IoStatus.Status;
			*RetBytes = NewData->IoStatus.Information;
		}
		else
		{
			Status = FltPerformAsynchronousIo(NewData, FsReadFileAsyncCompletionRoutine, IrpContext->pIoContext);
		}
	}

	if (NewData != NULL && bWait)
	{
		FltFreeCallbackData(NewData);
	}
	return Status;
}
