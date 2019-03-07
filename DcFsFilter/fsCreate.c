#include "fsCreate.h"
#include "fsData.h"
#include "fatstruc.h"
#include "volumeContext.h"
#include <ntifs.h>
#include <wdm.h>
#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS status = STATUS_SUCCESS;
	FLT_PREOP_CALLBACK_STATUS	FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bTopLevel;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	ULONG uProcType = 0;
	DEF_CCB * Ccb = NULL;

	PAGED_CODE();

	FsRtlEnterFileSystem();
	if (!IsFilterProcess(Data, &status, &uProcType))
	{
		if (NT_SUCCESS(status))
		{
			if (FlagOn(uProcType, PROCESS_ACCESS_DISABLE))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				FsRtlExitFileSystem();
				return FLT_PREOP_COMPLETE;
			}
			if (IsMyFakeFcb(FileObject))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
				FsRtlExitFileSystem();
				return FLT_PREOP_COMPLETE;
			}
			if (IsMyFakeFcb(FileObject->RelatedFileObject))
			{
				Ccb = FileObject->RelatedFileObject->FsContext2;

				if (Ccb != NULL)
				{
					FileObject->RelatedFileObject = Ccb->StreamInfo.FileObject;
				}
				else
				{
					Data->IoStatus.Status = STATUS_ACCESS_DENIED;
					Data->IoStatus.Information = 0;
					FsRtlExitFileSystem();
					return FLT_PREOP_COMPLETE;
				}
			}
			FsRtlExitFileSystem();
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{
			Data->IoStatus.Status = 0;
			Data->IoStatus.Information = 0;
			FsRtlExitFileSystem();
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
	}

	if (FlagOn(uProcType, PROCESS_ACCESS_DISABLE))
	{
		Data->IoStatus.Status = STATUS_ACCESS_DENIED;
		Data->IoStatus.Information = 0;
		FsRtlExitFileSystem();
		return FLT_PREOP_COMPLETE;
	}

	KdPrint(("PtPreCreate begin, Data Flag=0x%x......\n", Data->Flags));
#ifdef TEST
	KdBreakPoint();
#endif

	if (FLT_IS_IRP_OPERATION(Data))//IRP operate
	{
		bTopLevel = IsTopLevelIRP(Data);
		__try
		{
			IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
			IrpContext->CreateInfo.ProcType = uProcType;
			FltStatus = FsCommonCreate(Data, FltObjects, IrpContext);
		}
		__finally
		{
			if (bTopLevel)
			{
				IoSetTopLevelIrp(NULL);
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

	FsRtlExitFileSystem();
	KdPrint(("PtPreCreate end......\n"));
	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS PtPreOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	ULONG ProcType = 0;
	NTSTATUS Status;
	BOOLEAN bTopLevel = FALSE;
	PDEF_IRP_CONTEXT IrpContext = NULL;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_DISALLOW_FASTIO;
	ULONG uProcType = 0;
	IO_STATUS_BLOCK IoStatus = {0};
	PVOLUMECONTEXT pVolCtx = NULL;
	BOOLEAN bAcquireResource = FALSE;

	PAGED_CODE();
   	if (!(IsMyFakeFcb(FltObjects->FileObject) || IsFilterProcess(Data, &Status, &ProcType)))
  	{		
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
 	}
	//if (ProcType != PROCESS_ACCESS_EXPLORER)
	{
		return FLT_PREOP_DISALLOW_FASTIO;
	}
  	//return FLT_PREOP_SUCCESS_NO_CALLBACK;
	//
// 	if (!IsFilterProcess(Data, &Status, &ProcType))
// 	{
// 		return FLT_PREOP_SUCCESS_NO_CALLBACK;
// 	}

	KdPrint(("PtPreOperationNetworkQueryOpen begin, data flag=0x%x......\n", Data->Flags));
	FsRtlEnterFileSystem();
	__try
	{
		IrpContext = FsCreateIrpContext(Data, FltObjects, CanFsWait(Data));
		IrpContext->CreateInfo.ProcType = uProcType;
		if (!IsNeedSelfFcb(Data, &IrpContext->CreateInfo.NameInfo, &Status))
		{
			__leave;
		}

		Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}
		ExAcquireResourceExclusiveLite(pVolCtx->pEresurce, TRUE);
		if (pVolCtx->uDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			IrpContext->CreateInfo.bNetWork = TRUE;
		}
		ExReleaseResourceLite(pVolCtx->pEresurce);

		if (IrpContext->CreateInfo.bNetWork)
		{
			__leave;
		}

		Status = FsGetCcFileInfo(FltObjects->Filter, FltObjects->Instance, IrpContext->CreateInfo.NameInfo->Name.Buffer, &IrpContext->CreateInfo.StreamHanle, 
			&IrpContext->CreateInfo.StreamObject, IrpContext->CreateInfo.bNetWork);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s]FsGetCcFileInfo failed(0x%x)...\n", __FUNCTION__, Status));
			__leave;
		}

		IrpContext->CreateInfo.Information = Data->IoStatus.Information;
		Status = FsGetFileStandardInfo(Data, FltObjects, IrpContext);//这里还不能用FltObject中的文件对象
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s]FsGetFileStandardInfo failed(0x%x)...\n", __FUNCTION__, Status));
			__leave;
		}

		Status = FsGetFileHeaderInfo(FltObjects, IrpContext);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("[%s]FsCreatedFileHeaderInfo failed(0x%x)...\n", __FUNCTION__, Status));
			__leave;
		}
		FltStatus = FLT_PREOP_COMPLETE;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->CreationTime.QuadPart = IrpContext->CreateInfo.BaseInfo.CreationTime.QuadPart;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->ChangeTime.QuadPart = IrpContext->CreateInfo.BaseInfo.ChangeTime.QuadPart;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->LastAccessTime.QuadPart = IrpContext->CreateInfo.BaseInfo.LastAccessTime.QuadPart;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->LastWriteTime.QuadPart = IrpContext->CreateInfo.BaseInfo.LastWriteTime.QuadPart;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->EndOfFile.QuadPart = IrpContext->CreateInfo.FileSize.QuadPart;
		Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->AllocationSize.QuadPart = IrpContext->CreateInfo.FileAllocationSize.QuadPart;
		//if (0 == Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->FileAttributes)
		{
			Data->Iopb->Parameters.NetworkQueryOpen.NetworkInformation->FileAttributes = IrpContext->CreateInfo.BaseInfo.FileAttributes;
		}
		Data->IoStatus.Information = sizeof(FILE_NETWORK_OPEN_INFORMATION);
	}
	__finally
	{
		Data->IoStatus.Status = Status;
		if (NULL != pVolCtx)
		{
			FltReleaseContext(pVolCtx);
		}

		if (NULL != IrpContext->CreateInfo.NameInfo)
		{
			FltReleaseFileNameInformation(IrpContext->CreateInfo.NameInfo);
		}
		FsFreeCcFileInfo(&IrpContext->CreateInfo.StreamHanle, &IrpContext->CreateInfo.StreamObject);
		FsCompleteRequest(&IrpContext, &Data, Data->IoStatus.Status, FALSE);
	}

	KdPrint(("PtPreOperationNetworkQueryOpen end......\n"));
	FsRtlExitFileSystem();

	return FltStatus;
}

FLT_POSTOP_CALLBACK_STATUS PtPostOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}

FLT_PREOP_CALLBACK_STATUS FsCommonCreate(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	IO_STATUS_BLOCK IoStatus = { 0 };

	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	BOOLEAN bAcquireResource = FALSE;
	PVOLUMECONTEXT pVolCtx = NULL;
	PFLT_IO_PARAMETER_BLOCK pIopb = Data->Iopb;
	PFILE_OBJECT pFileObject, pRelatedFileObject;
	PUNICODE_STRING pFileName;
	PERESOURCE pFcbResource = NULL;
	BOOLEAN bPostIrp = FALSE;
	BOOLEAN bFOResourceAcquired = FALSE;
	PDEF_FCB pFcb = NULL;
	PDEF_CCB pCcb = NULL;
	THREAD_PARAM * Param = NULL;
	ULONG Length = 0;

	if (NULL == FltObjects)
	{
		pFileObject = IrpContext->FileObject;
		FltObjects = &IrpContext->FltObjects;
	}
	else
	{
		pFileObject = FltObjects->FileObject;
	}
	if (NULL == pFileObject)
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	pRelatedFileObject = pFileObject->RelatedFileObject;
	pFileName = &pFileObject->FileName;
	__try
	{
		if (KernelMode == Data->RequestorMode)
		{
			//try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_PAGING_FILE))
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (FlagOn(pIopb->TargetFileObject->Flags, FO_VOLUME_OPEN))
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (!FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WAIT))
		{
			bPostIrp = TRUE;
			KdPrint(("No asynchronous create \n"));
			try_return(FltStatus);
		}
		
		Status = FltGetVolumeContext(FltObjects->Filter, FltObjects->Volume, &pVolCtx);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			Data->IoStatus.Information = 0;
			try_return(FltStatus = FLT_PREOP_COMPLETE);
		}
		
		if (IsMyFakeFcb(pRelatedFileObject))
		{
			pCcb = pRelatedFileObject->FsContext2;
			if (pCcb != NULL)
			{
				ExAcquireResourceSharedLite(pCcb->StreamInfo.FoResource, TRUE);
				bFOResourceAcquired = TRUE;
				pFileObject->RelatedFileObject = pCcb->StreamInfo.FileObject;
			}
			else
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}
		
		if (FlagOn(pIopb->OperationFlags, SL_OPEN_TARGET_DIRECTORY))
		{
			if (IsMyFakeFcb(pFileObject))
			{
				Status = STATUS_ACCESS_DENIED;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		if (!IsNeedSelfFcb(Data, &IrpContext->CreateInfo.NameInfo, &Status))
		{
			if (NT_SUCCESS(Status))
			{
				try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
				Data->IoStatus.Status = Status;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		if (pFileName->Length > sizeof(WCHAR) &&
			pFileName->Buffer[1] == L'\\' &&
			pFileName->Buffer[0] == L'\\')
		{
			pFileName->Length -= sizeof(WCHAR);

			RtlMoveMemory(
				&pFileName->Buffer[0],
				&pFileName->Buffer[1],
				pFileName->Length
				);

			if (pFileName->Length > sizeof(WCHAR) &&
				pFileName->Buffer[1] == L'\\' &&
				pFileName->Buffer[0] == L'\\')
			{
				Data->IoStatus.Status = STATUS_OBJECT_NAME_INVALID;
				try_return(FltStatus = FLT_PREOP_COMPLETE);
			}
		}

		ExAcquireResourceExclusiveLite(pVolCtx->pEresurce, TRUE);
		bAcquireResource = TRUE;
		if (pVolCtx->uDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM)
		{
			IrpContext->CreateInfo.bNetWork = TRUE;	//only read！！！！！！
		}
		
		if (IrpContext->CreateInfo.bNetWork && 4 == PsGetCurrentProcessId())
		{
			try_return(FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		IrpContext->SectorSize = pVolCtx->ulSectorSize;
		IrpContext->SectorsPerAllocationUnit = pVolCtx->uSectorsPerAllocationUnit;
		
		if (IsMyFakeFcb(pFileObject))
		{
			pFcb = pFileObject->FsContext;
		}
		else
		{
			FindFcb(NULL, IrpContext->CreateInfo.NameInfo->Name.Buffer, &pFcb);
		}
		if (IrpContext->CreateInfo.bNetWork)
		{
			if (FsFindEncryptingFilesInfo(NULL == pFcb ? Data : NULL, NULL == pFcb ? NULL : pFcb->wszFile))
			{
				if (4 == PsGetCurrentProcessId())
				{
					IrpContext->FltStatus = FLT_PREOP_COMPLETE;
					try_return(Status = STATUS_NO_SUCH_FILE);
				}
				KeSleep(100);
				KdPrint(("[%s]sleep......\n", __FUNCTION__));
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
				try_return(Status = STATUS_PENDING);
			}
			if (4 != PsGetCurrentProcessId())
			{
				Param = ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_PARAM), 'tpfp');
				if (NULL == Param)
				{
					__leave;
				}
				Length = IrpContext->CreateInfo.NameInfo->Name.Length;
				Param->Length = Length + sizeof(WCHAR);
				Param->FilePath = ExAllocatePoolWithTag(NonPagedPool, Param->Length, 'tpfp');
				if (NULL == Param->FilePath)
				{
					ExFreePoolWithTag(Param, 'tpfp');
					Param = NULL;
					KdPrint(("[%s]ExAllocatePoolWithTag failed...\n", __FUNCTION__));
					__leave;
				}
				RtlZeroMemory(Param->FilePath, Param->Length);
				RtlCopyMemory(Param->FilePath, IrpContext->CreateInfo.NameInfo->Name.Buffer, Length);
				FsInsertEncryptingFilesInfo(Param);
			}
		}
		if (bAcquireResource)
		{
			ExReleaseResourceLite(pVolCtx->pEresurce);
			bAcquireResource = FALSE;
		}
		Status = STATUS_SUCCESS;
		if (pFcb)
		{
			Status = CreateFileByExistFcb(Data, FltObjects, pFcb, IrpContext, FALSE);
			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}
			if (!NT_SUCCESS(Status) || IrpContext->FltStatus != FLT_PREOP_COMPLETE)
			{
				KdPrint(("CreateFileByExistFcb failed(0x%x), fltStatus=%d...\n", Status, IrpContext->FltStatus));
			}

			try_return(FltStatus = IrpContext->FltStatus);
		}
		else 
		{
			Status = CreateFileByNonExistFcb(Data, FltObjects, pFcb, IrpContext);
			if (Status == STATUS_PENDING)
			{
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				bPostIrp = TRUE;
			}
			if (!NT_SUCCESS(Status) || IrpContext->FltStatus != FLT_PREOP_COMPLETE)
			{
				KdPrint(("CreateFileByNonExistFcb failed(0x%x), fltStatus=%d...\n", Status, IrpContext->FltStatus));
				if (PROCESS_ACCESS_ANTIS == IrpContext->CreateInfo.ProcType)
				{
					IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
				}
				bPostIrp = FALSE;
			}
			try_return(FltStatus = IrpContext->FltStatus);
		}
	try_exit:NOTHING;
		if (IrpContext->CreateInfo.bReissueIo)
		{
			FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		else
		{
			Data->IoStatus.Information = IrpContext->CreateInfo.Information;
		}
		
		pFcb = FltObjects->FileObject->FsContext;
		pCcb = FltObjects->FileObject->FsContext2;
		if (NT_SUCCESS(Status) && pFcb != NULL)
		{
			KdPrint(("FileSize=0x%x(%d)...\n", pFcb->Header.FileSize.QuadPart, pFcb->Header.FileSize.QuadPart));
		}
	}
	__finally
	{
		if (Param)
		{
			FsDeleteEncryptingFilesInfo(Param->FilePath, Param->Length, Param);
		}
		if (NULL != IrpContext->CreateInfo.NameInfo)
		{
			FltReleaseFileNameInformation(IrpContext->CreateInfo.NameInfo);
			IrpContext->CreateInfo.NameInfo = NULL;
		}
		if (bAcquireResource)
		{
			ExReleaseResourceLite(pVolCtx->pEresurce);
		}

		if (bFOResourceAcquired)
		{
			PDEF_CCB pTmp = pRelatedFileObject->FsContext2;
			if (pTmp && pTmp->StreamInfo.FoResource)
			{
				ExReleaseResourceLite(pTmp->StreamInfo.FoResource);
			}
		}

		if (NULL != pVolCtx)
		{
			FltReleaseContext(pVolCtx);
		}

		if (!NT_SUCCESS(Status) || FltStatus != FLT_PREOP_COMPLETE)
		{
			if (NULL != IrpContext->CreateInfo.StreamObject)
			{
				ObDereferenceObject(IrpContext->CreateInfo.StreamObject);
				FltClose(IrpContext->CreateInfo.StreamHanle);
				IrpContext->CreateInfo.StreamObject = NULL;
				IrpContext->CreateInfo.StreamHanle = NULL;
			}
		}
		if (bPostIrp && !IrpContext->CreateInfo.bOplockPostIrp)
		{
			Status = FsPostRequest(Data, IrpContext);
			if (STATUS_PENDING == Status)
			{
				FltStatus = FLT_PREOP_PENDING;
			}
			else
			{
				FltStatus = FLT_PREOP_COMPLETE;
			}
		}
		if (PROCESS_ACCESS_EXPLORER == IrpContext->CreateInfo.ProcType)
		{
			//if (!(STATUS_OBJECT_NAME_NOT_FOUND == Status && IrpContext->createInfo.bNetWork))
			{
				if (FLT_PREOP_SUCCESS_NO_CALLBACK == FltStatus)
				{
					FsSetExplorerInfo(NULL, NULL);
				}
				else
				{
					if (pFcb && pFcb->bEnFile)
					{
						FsSetExplorerInfo(pFileObject, pFcb);
					}
					else if (!bPostIrp)
					{
						FsSetExplorerInfo(NULL, NULL);
					}
				}
			}
		}	

		Data->IoStatus.Status = (FLT_PREOP_SUCCESS_NO_CALLBACK == FltStatus ? 0 : Status);
		if (NT_SUCCESS(Data->IoStatus.Status) && FLT_PREOP_COMPLETE == FltStatus)
		{
			Data->IoStatus.Information = FILE_OPENED;
		}

		if (!bPostIrp && !AbnormalTermination())
		{
			FsCompleteRequest(&IrpContext, &Data, Data->IoStatus.Status, FALSE);
		}
	}
	return FltStatus;
}

BOOLEAN IsNeedSelfFcb(__inout PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION * nameInfo, PNTSTATUS pStatus)
{
	NTSTATUS Status;
	BOOLEAN bDirectory = FALSE;
	if (!IsConcernedCreateOptions(Data))
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	Status = FltIsDirectory(Data->Iopb->TargetFileObject, Data->Iopb->TargetInstance, &bDirectory);
	if (NT_SUCCESS(Status) && bDirectory)
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	Status = FltGetFileNameInformation(Data,
		FLT_FILE_NAME_NORMALIZED |
		FLT_FILE_NAME_QUERY_DEFAULT,
		nameInfo);
	if (!NT_SUCCESS(Status))
	{
		Status = FltGetFileNameInformation(Data,
			FLT_FILE_NAME_OPENED |
			FLT_FILE_NAME_QUERY_DEFAULT,
			nameInfo);
		if (!NT_SUCCESS(Status))
		{
			*pStatus = Status;
			return FALSE;
		}
	}

	Status = FltParseFileNameInformation(*nameInfo);
	if (!NT_SUCCESS(Status))
	{
		*pStatus = Status;
		return FALSE;
	}
	//根据得到的文件信息剔除掉打开盘符的操作
	if (0 == (*nameInfo)->Name.Length)
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}
	
	if ((*nameInfo)->FinalComponent.Length == 0) //打开的是卷或者目录
	{
		*pStatus = STATUS_SUCCESS;
		return FALSE;
	}

	if ((*nameInfo)->Extension.Length == 0 && (*nameInfo)->Share.Length != 0)
	{
		if ((*nameInfo)->Share.Length >= NAMED_PIPE_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName, &(*nameInfo)->Share, TRUE);

			if (!NT_SUCCESS(Status))
			{
				*pStatus = Status;
				return FALSE;
			}
			if (NAMED_PIPE_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer, ShareName.Length - NAMED_PIPE_PREFIX_LENGTH),
				NAMED_PIPE_PREFIX,
				NAMED_PIPE_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
		if ((*nameInfo)->Share.Length >= MAIL_SLOT_PREFIX_LENGTH)
		{
			UNICODE_STRING ShareName;

			Status = RtlUpcaseUnicodeString(&ShareName, &(*nameInfo)->Share, TRUE);

			if (!NT_SUCCESS(Status))
			{
				*pStatus = Status;
				return FALSE;
			}

			if (MAIL_SLOT_PREFIX_LENGTH == RtlCompareMemory(Add2Ptr(ShareName.Buffer, ShareName.Length - MAIL_SLOT_PREFIX_LENGTH),
				MAIL_SLOT_PREFIX,
				MAIL_SLOT_PREFIX_LENGTH))
			{
				RtlFreeUnicodeString(&ShareName);
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}

			RtlFreeUnicodeString(&ShareName);
		}
	}
	if ((*nameInfo)->Stream.Length != 0) //file stream
	{
		ULONG i;
		for (i = 0; i < ((*nameInfo)->Stream.Length - sizeof(WCHAR)) / 2; i++)
		{
			if (((*nameInfo)->Stream.Buffer[i] == L':') &&
				((*nameInfo)->Stream.Buffer[i + 1] == L'$'))
			{
				KdPrint(("stream create!\n"));
				*pStatus = STATUS_SUCCESS;
				return FALSE;
			}
		}

		*pStatus = STATUS_SUCCESS;
		return FALSE;  //TRUE?FALSE? 
	}

	return TRUE;
}

BOOLEAN IsConcernedCreateOptions(__inout PFLT_CALLBACK_DATA Data)
{
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;

	ULONG Options = Iopb->Parameters.Create.Options;

	BOOLEAN DirectoryFile = BooleanFlagOn(Options, FILE_DIRECTORY_FILE); //目录文件

	return !DirectoryFile;
}

#ifndef FILE_OPEN_REQUIRING_OPLOCK
#define FILE_OPEN_REQUIRING_OPLOCK              0x00010000
#endif

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_FCB Fcb, __in PDEF_IRP_CONTEXT IrpContext, __in BOOLEAN bSkipCreate)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	PFLT_IO_PARAMETER_BLOCK CONST  Iopb = Data->Iopb;
	LARGE_INTEGER  AllocationSize;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;

	PDEF_CCB Ccb = NULL;
	ACCESS_MASK	AddedAccess = 0;
	ACCESS_MASK DesiredAccess = 0;
	ULONG  EaLength = 0;
	PVOID  EaBuffer = NULL;
	ULONG  Options = 0;
	ULONG  CreateDisposition = 0;
	ULONG	FileAttributes = 0;
	ULONG	ShareAccess = 0;
	ULONG ClusterSize = 0;
	LARGE_INTEGER Temp;

	BOOLEAN NoEaKnowledge;
	BOOLEAN DeleteOnClose;
	BOOLEAN NoIntermediateBuffering;
	BOOLEAN TemporaryFile;
	BOOLEAN OpenRequiringOplock = FALSE;

	BOOLEAN DecrementFcbOpenCount = FALSE;
	BOOLEAN RemoveShareAccess = FALSE;
	BOOLEAN AcquiredPagingResource = FALSE;
	PACCESS_MASK DesiredAccessPtr;
	PIO_SECURITY_CONTEXT  SecurityContext;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK PreDesiredAccess;
	BOOLEAN bFcbAcquired = FALSE;
	UNREFERENCED_PARAMETER(FltObjects);

	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;
	EaBuffer = Iopb->Parameters.Create.EaBuffer;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	DesiredAccessPtr = &Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	SecurityContext = Iopb->Parameters.Create.SecurityContext;
	Options = Iopb->Parameters.Create.Options;
	FileAttributes = Iopb->Parameters.Create.FileAttributes;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	EaLength = Iopb->Parameters.Create.EaLength;

	CreateDisposition = (Options >> 24) & 0x000000ff;
	SecurityContext = Iopb->Parameters.Create.SecurityContext;
	PreDesiredAccess = DesiredAccess;
	ULONG i = 0;
	
	KdPrint(("create:ProcessID:%d, DesiredAccess:0x%x, ShareAccess:0x%x, Options=0x%x, CreateDisposition=0x%x...\n", PsGetCurrentProcessId(), DesiredAccess, ShareAccess, Options, CreateDisposition));

	OpenRequiringOplock = BooleanFlagOn(Options, FILE_OPEN_REQUIRING_OPLOCK);
	NoEaKnowledge = BooleanFlagOn(Options, FILE_NO_EA_KNOWLEDGE);
	DeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	NoIntermediateBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);
	TemporaryFile = BooleanFlagOn(FileAttributes, FILE_ATTRIBUTE_TEMPORARY);

	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	if (IrpContext->OriginatingData != NULL)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}

	__try
	{
		//bFcbAcquired = ExAcquireResourceExclusiveLite(Fcb->Resource, TRUE);
		//bFcbAcquired = FsAcquireExclusiveFcb(IrpContext, Fcb);
		if (FlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE) && Fcb->OpenCount != 0)
		{
			try_return(Status = STATUS_DELETE_PENDING);
		}

		IrpContext->CreateInfo.bOplockPostIrp = FALSE;

		if (IsWin7OrLater())
		{
			FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx(&Fcb->Oplock,
				OrgData,
				OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
				NULL,
				NULL,
				NULL);

			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
		}

		if (FltCurrentBatchOplock(&Fcb->Oplock))
		{
			Data->IoStatus.Information = FILE_OPBATCH_BREAK_UNDERWAY;
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
				OrgData,
				IrpContext,
				FsOplockComplete,
				FsPrePostIrp);
			if (FLT_PREOP_PENDING == FltOplockStatus)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->CreateInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
		}
		if (CreateDisposition == FILE_CREATE && Fcb->OpenCount != 0)
		{
			Status = STATUS_OBJECT_NAME_COLLISION;
			try_return(Status);
		}
		else if (CreateDisposition == FILE_OVERWRITE || CreateDisposition == FILE_OVERWRITE_IF)
		{
			SetFlag(AddedAccess, (FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES) & (~DesiredAccess));
			SetFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES | FILE_WRITE_EA | FILE_WRITE_DATA);
		}
		else if (CreateDisposition == FILE_SUPERSEDE)
		{
			SetFlag(AddedAccess, DELETE & ~DesiredAccess);
			SetFlag(DesiredAccess, DELETE);
		}

// 		if (!NT_SUCCESS(Status = IoCheckShareAccess(DesiredAccess,
// 			ShareAccess,
// 			FileObject,
// 			&Fcb->ShareAccess,
// 			FALSE)))
// 		{
// 			if (IsWin7OrLater())
// 			{
// 				if ((Status == STATUS_SHARING_VIOLATION) &&
// 					!FlagOn(OrgData->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED))
// 				{
// 					FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.OplockBreakH(&Fcb->Oplock,
// 						OrgData,
// 						0,
// 						IrpContext,
// 						FsOplockComplete,
// 						FsPrePostIrp);
// 
// 					if (FltOplockStatus == FLT_PREOP_PENDING) 
// 					{
// 						Status = STATUS_PENDING;
// 						IrpContext->FltStatus = FLT_PREOP_PENDING;
// 						IrpContext->createInfo.bOplockPostIrp = TRUE;
// 						try_return(Status);
// 					}
// 					if (FltOplockStatus == FLT_PREOP_COMPLETE)
// 					{
// 						try_return(Status = OrgData->IoStatus.Status);
// 					}
// 					else
// 					{
// 						try_return(Status = STATUS_SHARING_VIOLATION);
// 					}
// 				}
// 			}
// 			try_return(Status);
// 		}
		/*
		if (IsWin7OrLater())
		{
			if (Fcb->OpenCount != 0)
			{
				FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
					OrgData,
					IrpContext,
					FsOplockComplete,
					FsPrePostIrp);
			}

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->createInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
			if (OpenRequiringOplock)
			{
				FltOplockStatus = FltOplockFsctrl(&Fcb->Oplock,
					OrgData,
					Fcb->OpenCount);

				if (OrgData->IoStatus.Status != STATUS_SUCCESS &&
					OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
				{
					try_return(Status = OrgData->IoStatus.Status);
				}
			}
		}
		else
		{
			FltOplockStatus = FltCheckOplock(&Fcb->Oplock,
				OrgData,
				IrpContext,
				FsOplockComplete,
				FsPrePostIrp);

			if (FltOplockStatus == FLT_PREOP_PENDING)
			{
				Status = STATUS_PENDING;
				IrpContext->FltStatus = FLT_PREOP_PENDING;
				IrpContext->createInfo.bOplockPostIrp = TRUE;
				try_return(Status);
			}
			if (FltOplockStatus == FLT_PREOP_COMPLETE)
			{
				try_return(Status = OrgData->IoStatus.Status);
			}
		}
		*/
		ExAcquireFastMutex(Fcb->Header.FastMutex);
		if (IsFltFileLock())
		{
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
		}
		else
		{
			Fcb->Header.IsFastIoPossible = FsRtlOplockIsFastIoPossible(&Fcb->Oplock) ? FastIoIsPossible : FastIoIsNotPossible;
		}
		
		ExReleaseFastMutex(Fcb->Header.FastMutex);

		if (FlagOn(DesiredAccess, FILE_WRITE_DATA) || DeleteOnClose)
		{
			InterlockedIncrement((PLONG)&Fcb->UncleanCount);
			DecrementFcbOpenCount = TRUE;

			if (!MmFlushImageSection(&Fcb->SectionObjectPointers,
				MmFlushForWrite))
			{
				Status = (DeleteOnClose ? STATUS_CANNOT_DELETE : STATUS_SHARING_VIOLATION);
				try_return(Status);
			}
		}

		if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING) &&
			(Fcb->SectionObjectPointers.DataSectionObject != NULL))//先刷新缓存 //见fat create 2932
		{
			ExAcquireResourceExclusiveLite(Fcb->Header.PagingIoResource, TRUE);
			CcFlushCache(&Fcb->SectionObjectPointers, NULL, 0, NULL);
			CcPurgeCacheSection(&Fcb->SectionObjectPointers, NULL, 0, FALSE);
			ExReleaseResourceLite(Fcb->Header.PagingIoResource);
		}

		if (DeleteOnClose)
		{
			SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
		}

		if (FILE_SUPERSEDE == CreateDisposition || FILE_OVERWRITE == CreateDisposition || FILE_OVERWRITE_IF == CreateDisposition)
		{
			if (!MmCanFileBeTruncated(&Fcb->SectionObjectPointers, &Li0))
			{
				try_return(Status = STATUS_USER_MAPPED_FILE);
			}
		}

// 		if (FlagOn(IrpContext->CreateInfo.ProcType, PROCESS_ACCESS_EXPLORER) && Fcb->bRecycleBinFile && Fcb->CcFileObject)
// 		{
// 			ObDereferenceObject(Fcb->CcFileObject);
//			FltClose(Fcb->CcFileHandle);
// 			Fcb->CcFileObject = NULL;
// 			Fcb->CcFileHandle = NULL;
// 		}
		if (!bSkipCreate)
		{
			Status = FsCreateFileLimitation(Data,
				FltObjects,
				&IrpContext->CreateInfo.NameInfo->Name,
				&IrpContext->CreateInfo.StreamHanle,
				&IrpContext->CreateInfo.StreamObject,
				&Data->IoStatus,
				IrpContext->CreateInfo.bNetWork,
				&IrpContext->CreateInfo.Vpb,
				IrpContext->CreateInfo.ProcType
				);

			if (!NT_SUCCESS(Status))
			{
				if (Status == STATUS_FILE_IS_A_DIRECTORY)
				{
					try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
				}
				else
				{
					if (PROCESS_ACCESS_ANTIS == IrpContext->CreateInfo.ProcType && FALSE)
					{
						try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
					}
					else
					{
						Data->IoStatus.Status = Status;
						try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
					}
				}
			}
		}

		IrpContext->CreateInfo.Information = Data->IoStatus.Information;
		Status = FsGetFileStandardInfo(Data, FltObjects, IrpContext);
		if (!NT_SUCCESS(Status) || IrpContext->CreateInfo.Directory)
		{
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		Status = FsGetFileHeaderInfo(FltObjects, IrpContext);
		if (!NT_SUCCESS(Status))
		{
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		if (PROCESS_ACCESS_ANTIS == IrpContext->CreateInfo.ProcType && FALSE)
		{
			if (!IrpContext->CreateInfo.bEnFile && IrpContext->CreateInfo.FileSize.QuadPart > 0)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
		}
		else
		{
			//test：原来是加密的，后来被删除了或覆盖写，目前是一个新的，那么加密一下（应该监控文件的状态，比如，删除、重命名、修改等，如果删除了，应把Fcb里的状态置零）
			if (Fcb->bEnFile && !IrpContext->CreateInfo.bEnFile)
			{
				//需要重新写入加密头信息
				Fcb->bWriteHead = FALSE;
				ClearFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
				Fcb->FileHeaderLength = 0;
			}
		}

		if (IrpContext->CreateInfo.FileAccess == FILE_NO_ACCESS)
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if (IrpContext->CreateInfo.FileAccess == FILE_READ_ACCESS &&
			(BooleanFlagOn(DesiredAccess, FILE_WRITE_DATA) ||
			BooleanFlagOn(DesiredAccess, FILE_APPEND_DATA)))
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}

		//写过了加密头
		if (IrpContext->CreateInfo.bEnFile)
		{
			Fcb->bEnFile = IrpContext->CreateInfo.bEnFile;
			Fcb->bWriteHead = IrpContext->CreateInfo.bWriteHeader;
			SetFlag(Fcb->FcbState, FCB_STATE_FILEHEADER_WRITED);
			Fcb->FileHeaderLength = ENCRYPT_HEAD_LENGTH;
			RtlCopyMemory(Fcb->szFileHead, IrpContext->CreateInfo.FileHeader, ENCRYPT_HEAD_LENGTH);
			RtlCopyMemory(Fcb->szOrgFileHead, IrpContext->CreateInfo.OrgFileHeader, ENCRYPT_HEAD_LENGTH);
		}

		//todo::如果解密，需减去加密头的长度
		if (IrpContext->CreateInfo.bDecrementHeader)
		{
			IrpContext->CreateInfo.FileSize.QuadPart -= ENCRYPT_HEAD_LENGTH;
			IrpContext->CreateInfo.FileAllocationSize.QuadPart -= ENCRYPT_HEAD_LENGTH;
		}

		Fcb->Header.FileSize.QuadPart = IrpContext->CreateInfo.FileSize.QuadPart;
		Fcb->Header.ValidDataLength.QuadPart = IrpContext->CreateInfo.FileSize.QuadPart;
		if (IrpContext->CreateInfo.FileSize.QuadPart > IrpContext->CreateInfo.FileAllocationSize.QuadPart)
		{
			ClusterSize = IrpContext->SectorSize * IrpContext->SectorsPerAllocationUnit;
			Temp.QuadPart = Fcb->Header.FileSize.QuadPart;
			Temp.QuadPart += ClusterSize;
			Temp.HighPart += (ULONG)((LONGLONG)ClusterSize >> 32);

			if (0 == Temp.LowPart)
			{
				Temp.LowPart -= 1;
			}
			Fcb->Header.AllocationSize.LowPart = ((ULONG)Fcb->Header.FileSize.LowPart + (ClusterSize - 1)) & (~(ClusterSize - 1));
			Fcb->Header.AllocationSize.HighPart = Temp.HighPart;
		}
		else
		{
			Fcb->Header.AllocationSize.QuadPart = IrpContext->CreateInfo.FileAllocationSize.QuadPart;
		}

		if (IrpContext->CreateInfo.bRealSize)
		{
			if (IrpContext->CreateInfo.RealSize.QuadPart > Fcb->Header.AllocationSize.QuadPart)
			{
				IrpContext->CreateInfo.RealSize.QuadPart = IrpContext->CreateInfo.FileSize.QuadPart;
			}
			else
			{
				Fcb->Header.FileSize.QuadPart = IrpContext->CreateInfo.RealSize.QuadPart;
				Fcb->Header.ValidDataLength.QuadPart = IrpContext->CreateInfo.RealSize.QuadPart;
				Fcb->ValidDataToDisk.QuadPart = IrpContext->CreateInfo.FileSize.QuadPart;
			}
		}
		Fcb->LastAccessTime = IrpContext->CreateInfo.BaseInfo.LastAccessTime.QuadPart;
		Fcb->CreationTime = IrpContext->CreateInfo.BaseInfo.CreationTime.QuadPart;
		Fcb->CurrentLastAccess = IrpContext->CreateInfo.BaseInfo.ChangeTime.QuadPart;
		Fcb->Attribute = IrpContext->CreateInfo.BaseInfo.FileAttributes;
		Fcb->LastWriteTime = IrpContext->CreateInfo.BaseInfo.LastWriteTime.QuadPart;
		Fcb->LastChangeTime = IrpContext->CreateInfo.BaseInfo.ChangeTime.QuadPart;
		Fcb->LinkCount = IrpContext->CreateInfo.NumberOfLinks;
		Fcb->DeletePending = IrpContext->CreateInfo.DeletePending;
		Fcb->Directory = IrpContext->CreateInfo.Directory;
		if (IrpContext->CreateInfo.bNetWork || Fcb->bRecycleBinFile)
		{
			Fcb->CcFileHandle = IrpContext->CreateInfo.StreamHanle;
 			Fcb->CcFileObject = IrpContext->CreateInfo.StreamObject;
		}
		else if (NULL == Fcb->CcFileObject)
		{
			UNICODE_STRING unicodeString;
			IO_STATUS_BLOCK IoStatus;
			OBJECT_ATTRIBUTES ob;
			RtlInitUnicodeString(&unicodeString, Fcb->wszFile);
			InitializeObjectAttributes(&ob, &unicodeString, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);
			Status = FltCreateFile(FltObjects->Filter, FltObjects->Instance, &Fcb->CcFileHandle, FILE_SPECIAL_ACCESS, &ob, &IoStatus,
				NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, Options, NULL, 0, 0);
			if (!NT_SUCCESS(Status))
			{
				try_return(Status);
			}
			Status = ObReferenceObjectByHandle(Fcb->CcFileHandle, 0, *IoFileObjectType, KernelMode, &Fcb->CcFileObject, NULL);
			if (!NT_SUCCESS(Status))
			{
				FltClose(Fcb->CcFileHandle);
				Fcb->CcFileHandle = NULL;
				try_return(Status);
			}
		}

		Ccb = FsCreateCcb();
		Ccb->StreamInfo.FileHandle = IrpContext->CreateInfo.StreamHanle;
		Ccb->StreamInfo.FileObject = IrpContext->CreateInfo.StreamObject;
		Ccb->StreamInfo.FoResource = FsAllocateResource();
		Ccb->ProcType = IrpContext->CreateInfo.ProcType;
		Ccb->FileAccess = IrpContext->CreateInfo.FileAccess;
		Fcb->ProcessAcessType = IrpContext->CreateInfo.ProcType;
	
		if (IrpContext->CreateInfo.bNetWork)
		{
			SetFlag(Ccb->CcbState, CCB_FLAG_NETWORK_FILE);
		}
		if (Fcb->bRecycleBinFile)
		{
			SetFlag(Ccb->CcbState, CCB_FLAG_RECYCLE_BIN_FILE);
		}

		ExInitializeFastMutex(&Ccb->StreamInfo.FoMutex);

		FileObject->FsContext = Fcb;
		FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
		FileObject->FsContext2 = Ccb;

		SetFlag(FileObject->Flags, FO_WRITE_THROUGH);

		if (CreateDisposition == FILE_SUPERSEDE ||
			CreateDisposition == FILE_OVERWRITE ||
			CreateDisposition == FILE_OVERWRITE_IF)
		{
			Status = FsOverWriteFile(FileObject, Fcb, AllocationSize);
			SetFlag(Ccb->CcbState, CCB_FLAG_CHECK_ORIGIN_ENCRYPTED);
		}

		if (!NoIntermediateBuffering)
		{
			FileObject->Flags |= FO_CACHE_SUPPORTED;
		}
		KdPrint(("[%s]Fcb bEnFile:%d, bWriteHead:%d, bAddHeaderLength:%d, Ccb bEnFile:%d, FileSize:%d....\n", __FUNCTION__, Fcb->bEnFile, Fcb->bWriteHead, Fcb->bAddHeaderLength, IrpContext->CreateInfo.bEnFile, Fcb->Header.FileSize.QuadPart));
	try_exit: NOTHING;
		if (IrpContext->FltStatus == FLT_PREOP_COMPLETE)
		{
			if (NT_SUCCESS(Status) &&
				Status != STATUS_PENDING)
			{
				if (FlagOn(Ccb->CcbState, CCB_FLAG_NETWORK_FILE))
				{
					NetFileSetCacheProperty(FileObject, DesiredAccess);
				}

				if (/*DesiredAccess != PreDesiredAccess*/AddedAccess)
				{
					ClearFlag(DesiredAccess, AddedAccess);
					//DesiredAccess = PreDesiredAccess;
					NTSTATUS Status = IoCheckShareAccess(
						DesiredAccess,
						ShareAccess,
						FileObject,
						&Fcb->ShareAccess,
						TRUE
						);
					ASSERT(Status == STATUS_SUCCESS);
				}
				else
				{
					IoUpdateShareAccess(
						FileObject,
						&Fcb->ShareAccess
						);
				}

				RemoveShareAccess = TRUE;

				if (DeleteOnClose)
				{
					SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
				}

				InterlockedIncrement((PLONG)&Fcb->OpenCount);
				InterlockedIncrement((PLONG)&Fcb->UncleanCount);

				if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
				{
					InterlockedIncrement((PLONG)&Fcb->NonCachedUnCleanupCount);
				}
			}
		}
	}
	__finally
	{
		if (DecrementFcbOpenCount)
		{
			InterlockedDecrement((PLONG)&Fcb->UncleanCount);
		}

		if (AbnormalTermination())
		{
			if (RemoveShareAccess)
			{
				IoRemoveShareAccess(
					FileObject,
					&Fcb->ShareAccess
					);
			}
			Status = STATUS_UNSUCCESSFUL;

			Ccb = FileObject->FsContext2;
			if (Ccb != NULL)
			{
				FsFreeCcb(Ccb);
				FileObject->FsContext2 = NULL;
			}
		}

		if (bFcbAcquired)
		{
			//ExReleaseResource(Fcb->Resource);
			FsReleaseFcbEx(IrpContext, Fcb);
		}
	}
	return Status;
}

NTSTATUS CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_FCB Fcb, __in PDEF_IRP_CONTEXT IrpContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG Options;
	ULONG CreateDisposition;
	BOOLEAN bDirectory = FALSE;
	BOOLEAN bEnFile = FALSE;
	BOOLEAN bDisEncryptFile = FALSE;

	BOOLEAN bNeedOwnFcb = FALSE;
	BOOLEAN bOrgEnFile = FALSE;
	BOOLEAN bDeleteOnClose = FALSE;
	BOOLEAN bNoIntermediaBuffering = FALSE;
	BOOLEAN bOpenRequiringOplock;

	PFLT_IO_PARAMETER_BLOCK Iopb = Data->Iopb;
	PFILE_OBJECT FileObject = FltObjects->FileObject;
	FLT_PREOP_CALLBACK_STATUS FltOplockStatus;
	PFLT_CALLBACK_DATA OrgData = NULL;

	ACCESS_MASK DesiredAccess = 0;
	ULONG ShareAccess = 0;
	LARGE_INTEGER AllocationSize = {0};

	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	Options = Iopb->Parameters.Create.Options;
	CreateDisposition = (Options >> 24) & 0x000000ff;

	KdPrint(("[%s]create:DesiredAccess:0x%x, ShareAccess:0x%x, Options=0x%x, CreateDisposition=0x%x...\n", __FUNCTION__, DesiredAccess, ShareAccess, Options, CreateDisposition));

	bOpenRequiringOplock = BooleanFlagOn(Options, FILE_OPEN_REQUIRING_OPLOCK);
	bDeleteOnClose = BooleanFlagOn(Options, FILE_DELETE_ON_CLOSE);
	bNoIntermediaBuffering = BooleanFlagOn(Options, FILE_NO_INTERMEDIATE_BUFFERING);

	if (NULL != IrpContext->OriginatingData)
	{
		OrgData = IrpContext->OriginatingData;
	}
	else
	{
		OrgData = Data;
	}
	IrpContext->FltStatus = FLT_PREOP_COMPLETE;

	__try
	{
		if (PROCESS_ACCESS_EXPLORER == IrpContext->CreateInfo.ProcType && (FILE_CREATE == CreateDisposition || FILE_OVERWRITE == CreateDisposition || FILE_OVERWRITE_IF == CreateDisposition) && !IsNeedEncrypted())
		{
			Status = STATUS_UNSUCCESSFUL;
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}

		Status = FsCreateFileLimitation(Data, FltObjects, &IrpContext->CreateInfo.NameInfo->Name, &IrpContext->CreateInfo.StreamHanle,
			&IrpContext->CreateInfo.StreamObject, &Data->IoStatus, IrpContext->CreateInfo.bNetWork, &IrpContext->CreateInfo.Vpb, IrpContext->CreateInfo.ProcType);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("CreateFileLimitation failed(0x%x)...\n", Status));
			if (STATUS_FILE_IS_A_DIRECTORY == Status || (PROCESS_ACCESS_EXPLORER != IrpContext->CreateInfo.ProcType && STATUS_OBJECT_NAME_NOT_FOUND == Status))
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
			else
			{
 				if (PROCESS_ACCESS_ANTIS == IrpContext->CreateInfo.ProcType)
 				{
 					try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
 				}

				Data->IoStatus.Status = Status;
				IrpContext->FltStatus = FLT_PREOP_COMPLETE;
				try_return(NOTHING);
			}
		}
		//趋势驱动里hook了FltCreate等函数来监视文件，FsCreateFileLimitation里使用FltCreate来打开文件，会被监视到，TmXPFlt.sys驱动里会创建线程来读取该文件以判断是否含有病毒
		//此时又会产生IRP_CREATE，直到线程检测文件完毕后才会调用系统原来的FltCreate，这样就产生了Fcb.
		//这里重新判断Fcb是否存在
		if (FindFcb(Data, IrpContext->CreateInfo.NameInfo->Name.Buffer, &Fcb))
		{
			Status = CreateFileByExistFcb(Data, FltObjects, Fcb, IrpContext, TRUE);
			try_return(NOTHING);
		}
		IrpContext->CreateInfo.Information = Data->IoStatus.Information;
		Status = FsGetFileStandardInfo(Data, FltObjects, IrpContext);//这里还不能用FltObject中的文件对象
		if (IrpContext->CreateInfo.Directory)
		{
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FsGetFileStandardInfo failed(0x%x)...\n", Status));
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_COMPLETE);
		}

		Status = FsGetFileHeaderInfo(FltObjects, IrpContext);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("FsCreatedFileHeaderInfo failed(0x%x)...\n", Status));
			Data->IoStatus.Status = Status;
			try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
		}
		//非加密文件不过滤
		if (PROCESS_ACCESS_ANTIS == IrpContext->CreateInfo.ProcType && FALSE)
		{
			if (!IrpContext->CreateInfo.bEnFile)
			{
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
		}
		else
		{
			if (PROCESS_ACCESS_EXPLORER == IrpContext->CreateInfo.ProcType && !IrpContext->CreateInfo.bEnFile && !(FILE_CREATE == CreateDisposition || FILE_OVERWRITE == CreateDisposition || FILE_OVERWRITE_IF == CreateDisposition))
			{
				KdPrint(("is note EnFile \n"));
				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
			}
// 			if (PROCESS_ACCESS_EXPLORER != IrpContext->createInfo.uProcType && !IrpContext->createInfo.bEnFile /*&& !IrpContext->createInfo.bNetWork*/)
// 			{
// 				try_return(IrpContext->FltStatus = FLT_PREOP_SUCCESS_NO_CALLBACK);
// 			}
		}

		if (FILE_NO_ACCESS == IrpContext->CreateInfo.FileAccess)
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		if (IrpContext->CreateInfo.FileAccess == FILE_READ_ACCESS && (BooleanFlagOn(DesiredAccess, FILE_WRITE_DATA) ||
			BooleanFlagOn(DesiredAccess, FILE_APPEND_DATA)))
		{
			Status = STATUS_ACCESS_DENIED;
			try_return(Status);
		}
		IrpContext->CreateInfo.bDeleteOnClose = bDeleteOnClose;
		Status = FsCreateFcbAndCcb(Data, FltObjects, IrpContext);
		if (NT_SUCCESS(Status))
		{
			PDEF_CCB Ccb;
			Fcb = IrpContext->CreateInfo.Fcb;
			Ccb = IrpContext->CreateInfo.Ccb;
			Ccb->TypeOfOpen = 2;//2:ntfs file open
			if (IsWin7OrLater())
			{
				FltOplockStatus = g_DYNAMIC_FUNCTION_POINTERS.CheckOplockEx(&Fcb->Oplock, OrgData, OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY,
					NULL, NULL, NULL);

				if (FLT_PREOP_COMPLETE == FltOplockStatus)
				{
					try_return(Status = OrgData->IoStatus.Status);
				}
				if (bOpenRequiringOplock)
				{
					FltOplockStatus = FltOplockFsctrl(&Fcb->Oplock, OrgData, Fcb->OpenCount);
					if (OrgData->IoStatus.Status != STATUS_SUCCESS && OrgData->IoStatus.Status != STATUS_OPLOCK_BREAK_IN_PROGRESS)
					{
						FsRaiseStatus(IrpContext, OrgData->IoStatus.Status);
					}
				}
			}

			FileObject->FsContext = Fcb;
			FileObject->SectionObjectPointer = &Fcb->SectionObjectPointers;
			FileObject->FsContext2 = Ccb;
			SetFlag(FileObject->Flags, FO_WRITE_THROUGH);

			IoSetShareAccess(DesiredAccess, ShareAccess, FileObject, &Fcb->ShareAccess);

			InterlockedIncrement(&Fcb->UncleanCount);
			InterlockedIncrement(&Fcb->OpenCount);

			if (FlagOn(FileObject->Flags, FO_NO_INTERMEDIATE_BUFFERING))
			{
				InterlockedIncrement(&Fcb->NonCachedUnCleanupCount);
			}
			if (IrpContext->CreateInfo.bDeleteOnClose)
			{
				SetFlag(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE);
			}
		
			if (FILE_SUPERSEDE == CreateDisposition ||
				FILE_OVERWRITE == CreateDisposition ||
				FILE_OVERWRITE_IF == CreateDisposition)
			{
				Status = FsOverWriteFile(FileObject, Fcb, AllocationSize);
				SetFlag(Ccb->CcbState, CCB_FLAG_CHECK_ORIGIN_ENCRYPTED);
			}
			
			if (!bNoIntermediaBuffering)
			{
				FileObject->Flags |= FO_CACHE_SUPPORTED;
			}

			Fcb->Vpb.SupportsObjects = IrpContext->CreateInfo.Vpb.SupportsObjects;
			Fcb->Vpb.VolumeCreationTime.QuadPart = IrpContext->CreateInfo.Vpb.VolumeCreationTime.QuadPart;
			Fcb->Vpb.VolumeSerialNumber = IrpContext->CreateInfo.Vpb.VolumeSerialNumber;
			Fcb->Vpb.VolumeLabelLength = IrpContext->CreateInfo.Vpb.VolumeLabelLength;
			RtlCopyMemory(Fcb->Vpb.VolumeLabel, IrpContext->CreateInfo.Vpb.VolumeLabel, Fcb->Vpb.VolumeLabelLength);
			KdPrint(("[%s]Fcb bEnFile:%d, bWriteHead:%d, bAddHeaderLength:%d, Ccb bEnFile:%d, FileSize:%d....\n", __FUNCTION__, Fcb->bEnFile, Fcb->bWriteHead, Fcb->bAddHeaderLength, IrpContext->CreateInfo.bEnFile, Fcb->Header.FileSize.QuadPart));
		}
	try_exit: NOTHING;
	}
	__finally
	{
		if (!NT_SUCCESS(Status))
		{
			if (IrpContext->CreateInfo.Fcb != NULL)
			{
				FsFreeFcb(IrpContext->CreateInfo.Fcb, NULL);
				IrpContext->CreateInfo.Fcb = NULL;
			}
			if (IrpContext->CreateInfo.Ccb)
			{
				FsFreeCcb(IrpContext->CreateInfo.Ccb);
				IrpContext->CreateInfo.Ccb = NULL;
			}
		}
	}
	KdPrint(("[%s]line=%d.....\n", __FUNCTION__, __LINE__));
	return Status;
}

NTSTATUS FsCreateFileLimitation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PUNICODE_STRING FileName, __out PHANDLE phFile,
	__out PFILE_OBJECT * pFileObject, __out PIO_STATUS_BLOCK IoStatus, __in BOOLEAN bNetWork, __inout PDEF_VPB Vpb, __in ULONG ProcessType)
{
	NTSTATUS Status = STATUS_SUCCESS;
	OBJECT_ATTRIBUTES ob = { 0 };
	PFLT_IO_PARAMETER_BLOCK CONST Iopb = Data->Iopb;
	LARGE_INTEGER AllocationSize;
	ACCESS_MASK DesiredAccess;
	ULONG EaLength;
	PVOID EaBuffer;
	ULONG Options;
	ULONG CreateDisposition;
	ULONG FileAttributes;
	ULONG	ShareAccess;
	ULONG	Flags = 0;//FILE_FLAG_OVERLAPPED
	PSECURITY_DESCRIPTOR  SecurityDescriptor = NULL;
	UCHAR szBuf[128] = { 0 };
	ULONG RetLength = 0;
	PFILE_FS_VOLUME_INFORMATION VolumeInfo = (PFILE_FS_VOLUME_INFORMATION)szBuf;

	UNREFERENCED_PARAMETER(FltObjects);
	if (Iopb->Parameters.Create.SecurityContext && Iopb->Parameters.Create.SecurityContext->AccessState)
	{
		SecurityDescriptor = Iopb->Parameters.Create.SecurityContext->AccessState->SecurityDescriptor;
	}
	
	AllocationSize.QuadPart = Iopb->Parameters.Create.AllocationSize.QuadPart;

	EaBuffer = Iopb->Parameters.Create.EaBuffer;
	DesiredAccess = Iopb->Parameters.Create.SecurityContext->DesiredAccess;
	Options = Iopb->Parameters.Create.Options;
	FileAttributes = Iopb->Parameters.Create.FileAttributes;
	ShareAccess = Iopb->Parameters.Create.ShareAccess;
	EaLength = Iopb->Parameters.Create.EaLength;
	if (bNetWork)
	{
		//todo::wps打开时缺少READ_CONTROL，SYNCHRONIZE导致无法读内容
		//DesiredAccess:0x120196, ShareAccess:0x1, Options=0x1000060, CreateDisposition=0x1
		SetFlag(DesiredAccess, READ_CONTROL);//0x120089
		SetFlag(DesiredAccess, SYNCHRONIZE);
		SetFlag(ShareAccess, FILE_SHARE_READ);
		SetFlag(DesiredAccess, FILE_READ_DATA);

		//  
		//SetFlag (DesiredAccess , FILE_WRITE_DATA); //???
		//ShareAccess = FILE_SHARE_READ;   //网络文件因为oplock，只能只读，要想解决去参考rdbss.sys
		//ClearFlag(DesiredAccess, FILE_WRITE_DATA);
		//ClearFlag(DesiredAccess, FILE_APPEND_DATA);
	}
#ifdef USE_CACHE_READWRITE
	SetFlag(Options, FILE_WRITE_THROUGH); //如果缓存写需要加上直接写入文件，否则cccaniwrite内部会导致等待pagingio产生死锁
#endif
	CreateDisposition = (Options >> 24) & 0x000000ff;

	if (FILE_CREATE != CreateDisposition)
	{
		ClearFlag(Options, FILE_OPEN_BY_FILE_ID);
		ClearFlag(Options, FILE_OPEN_REQUIRING_OPLOCK);
	}
	
	InitializeObjectAttributes(&ob, FileName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, SecurityDescriptor);

	if (PROCESS_ACCESS_ANTIS == ProcessType && FALSE)
	{
		if (FILE_CREATE == CreateDisposition)
		{
			Status = STATUS_OBJECT_NAME_NOT_FOUND;
			return Status;
		}
		//尝试去打开一个文件（不创建，如果文件不存在，直接返回）
		if (FILE_SUPERSEDE == CreateDisposition ||
			FILE_OPEN_IF == CreateDisposition ||
			FILE_OVERWRITE_IF == CreateDisposition)
		{
			//尝试去打开一个文件（不创建，如果文件不存在，直接返回）
			Status = FltCreateFile(FltObjects->Filter, //FltCreateFileEx
				FltObjects->Instance,
				phFile,
				DesiredAccess,
				&ob,
				IoStatus,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				FILE_SHARE_READ,
				FILE_OPEN,
				Options,
				NULL,
				0,
				0
				);
			if (!NT_SUCCESS(Status) && STATUS_OBJECT_NAME_NOT_FOUND == Status)
			{
				KdPrint(("open file failed(0x%x)...\n", Status));
				return Status;
			}
			else if (NT_SUCCESS(Status))
			{
				FltClose(*phFile);
			}
		}
	}
	if ((PROCESS_ACCESS_EXPLORER != ProcessType && PROCESS_ACCESS_WPS != ProcessType) && !bNetWork && FILE_CREATE == CreateDisposition)
	{
		Status = STATUS_OBJECT_NAME_NOT_FOUND;
		return Status;
	}
	Status = FltCreateFile(FltObjects->Filter, //FltCreateFileEx
		FltObjects->Instance,
		phFile,
		DesiredAccess,
		&ob,
		IoStatus,
		&AllocationSize,
		FileAttributes,
		ShareAccess,
		CreateDisposition,
		Options,
		EaBuffer,
		EaLength,
		Flags
		);
	if (NT_SUCCESS(Status))
	{
		Status = ObReferenceObjectByHandle(*phFile,
			0,
			*IoFileObjectType,
			KernelMode,
			pFileObject,
			NULL);
		if (!NT_SUCCESS(Status))
		{
			KdPrint(("ObReferenceObjectByHandle  failed(0x%x) \n", Status));
			FltClose(*phFile);
			*pFileObject = NULL;
		}
	}
	if (NT_SUCCESS(Status))
	{
		if (bNetWork)
		{
			NTSTATUS ntStatus = FltQueryVolumeInformationFile(FltObjects->Instance, *pFileObject, VolumeInfo, 128, FileFsVolumeInformation, &RetLength);
			if (NT_SUCCESS(ntStatus))
			{
				Vpb->VolumeCreationTime.QuadPart = VolumeInfo->VolumeCreationTime.QuadPart;
				Vpb->VolumeSerialNumber = VolumeInfo->VolumeSerialNumber;
				Vpb->SupportsObjects = VolumeInfo->SupportsObjects;
				Vpb->VolumeLabelLength = VolumeInfo->VolumeLabelLength > VOLUME_LABEL_MAX_LENGTH ? VOLUME_LABEL_MAX_LENGTH : VolumeInfo->VolumeLabelLength;
				RtlCopyMemory(Vpb->VolumeLabel, VolumeInfo->VolumeLabel, Vpb->VolumeLabelLength);
			}
			else
			{
				KdPrint(("[%s]FltQueryVolumeInformationFile failed(0x%x)...\n", __FUNCTION__, ntStatus));
			}
		}
	}
	return Status;
}