#include "dcFsFilter.h"
#include <wdm.h>
#include "volumeContext.h"
#include "fsdata.h"
#include "fsCreate.h"
#include "fsInformation.h"
#include "fsRead.h"
#include "fsClose.h"
#include "fsCleanup.h"
#include "fsControl.h"
#include "fsWrite.h"
#include "FsFastIo.h"
#include "fsFlush.h"
#include "fsCommunication.h"
#include "threadMgr.h"

PFLT_FILTER gFilterHandle = NULL;

NTSTATUS
DriverEntry(
__in PDRIVER_OBJECT DriverObject,
__in PUNICODE_STRING RegistryPath
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif


CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	0,
	PtPreCreate,
	PtPostCreate },

	{ IRP_MJ_CREATE_NAMED_PIPE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_CLOSE,
	0,
	PtPreClose,
	PtPostClose},

	{ IRP_MJ_READ,
	0,
	PtPreRead,
	PtPostRead },

	{ IRP_MJ_WRITE,
	0,
	PtPreWrite,
	PtPostWrite },

	{ IRP_MJ_QUERY_INFORMATION,
	0,
	PtPreQueryInformation,
	PtPostQueryInformation },

	{ IRP_MJ_SET_INFORMATION,
	0,
	PtPreSetInformation,
	PtPostSetInformation },

	{ IRP_MJ_QUERY_EA,
	0,
	PtPreQueryEA,
	PtPostQueryEA },

	{ IRP_MJ_SET_EA,
	0,
	PtPreSetEA,
	PtPostSetEA },

	{ IRP_MJ_FLUSH_BUFFERS,
	0,
	PtPreFlush,
	PtPostFlush },

	{ IRP_MJ_QUERY_VOLUME_INFORMATION,
	0,
	PtPreQueryVolumeInformation,
	PtPostQueryVolumeInformation },

	{ IRP_MJ_SET_VOLUME_INFORMATION,
	0,
	PtPreSetVolumeInformation,
	PtPostSetVolumeInformation },

	{ IRP_MJ_DIRECTORY_CONTROL,
	0,
	PtPreDirectoryControl,
	PtPostDirectoryControl },

	{ IRP_MJ_FILE_SYSTEM_CONTROL,
	0,
	PtPreFileSystemControl,
	PtPostFileSystemControl },

	{ IRP_MJ_DEVICE_CONTROL,
	0,
	PtPreDeviceControl,
	PtPostDeviceControl },

	{ IRP_MJ_INTERNAL_DEVICE_CONTROL,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_SHUTDOWN,
	0,
	PtPreOperationNoPostOperationPassThrough,
	NULL },                               //post operations not supported

	{ IRP_MJ_LOCK_CONTROL,
	0,
	PtPreLockControl,
	PtPostLockControl},

	{ IRP_MJ_CLEANUP,
	0,
	PtPreCleanup,
	PtPostCleanup },

	{ IRP_MJ_CREATE_MAILSLOT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_QUERY_SECURITY,
	0,
	PtPreQuerySecurity,
	PtPostQuerySecurity },

	{ IRP_MJ_SET_SECURITY,
	0,
	PtPreSetSecurity,
	PtPostSetSecurity },

	{ IRP_MJ_QUERY_QUOTA,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_SET_QUOTA,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_PNP,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
	0,
	PtPreAcquireForSection,
	PtPostAcquireForSection },

	{ IRP_MJ_RELEASE_FOR_SECTION_SYNCHRONIZATION,
	0,
	PtPreReleaseForSection,
	PtPostReleaseForSection },

	{ IRP_MJ_ACQUIRE_FOR_MOD_WRITE,
	0,
	PtPreAcquireForModWrite,
	PtPostAcquireForModWrite },

	{ IRP_MJ_RELEASE_FOR_MOD_WRITE,
	0,
	PtPreReleaseForModWrite,
	PtPostReleaseForModWrite },

	{ IRP_MJ_ACQUIRE_FOR_CC_FLUSH,
	0,
	PtPreAcquireForCcFlush,
	PtPostAcquireForCcFlush },

	{ IRP_MJ_RELEASE_FOR_CC_FLUSH,
	0,
	PtPreReleaseForCcFlush,
	PtPostReleaseForCcFlush },

	{ IRP_MJ_FAST_IO_CHECK_IF_POSSIBLE,
	0,
	PtPreFastIoCheckPossible,
	PtPostFastIoCheckPossible },

	{ IRP_MJ_NETWORK_QUERY_OPEN,
	0,
	PtPreOperationNetworkQueryOpen,
	PtPostOperationNetworkQueryOpen },

	{ IRP_MJ_MDL_READ,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_MDL_READ_COMPLETE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_PREPARE_MDL_WRITE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_MDL_WRITE_COMPLETE,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_MOUNT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_VOLUME_DISMOUNT,
	0,
	PtPreOperationPassThrough,
	PtPostOperationPassThrough },

	{ IRP_MJ_OPERATION_END }
};

const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
	{
		FLT_VOLUME_CONTEXT,
		0,
		VolumeCleanup,
		sizeof(VOLUMECONTEXT),
		VOLUME_CONTEXT_POOL_TAG
	},

	{
		FLT_CONTEXT_END
	}
};

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	ContextRegistration,                //  Context
	Callbacks,                          //  Operation callbacks

	PtUnload,                           //  MiniFilterUnload

	PtInstanceSetup,                    //  InstanceSetup
	PtInstanceQueryTeardown,            //  InstanceQueryTeardown
	PtInstanceTeardownStart,            //  InstanceTeardownStart
	PtInstanceTeardownComplete,         //  InstanceTeardownComplete

	/*GenerateFileName*/NULL,                               //  GenerateFileName
	/*NormalizeNameComponentCallback*/NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent
};


NTSTATUS
PtInstanceSetup(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_SETUP_FLAGS Flags,
__in DEVICE_TYPE VolumeDeviceType,
__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
/*++

Routine Description:

This routine is called whenever a new instance is created on a volume. This
gives us a chance to decide if we need to attach to this volume or not.

If this routine is not defined in the registration structure, automatic
instances are alwasys created.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Flags describing the reason for this attach request.

Return Value:

STATUS_SUCCESS - attach
STATUS_FLT_DO_NOT_ATTACH - do not attach

--*/
{
	NTSTATUS status = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	
	UCHAR szTmp[sizeof(FLT_VOLUME_PROPERTIES)+512] = { 0 };
	//msdn:FltGetVolumeProperties:参数2指向的空间一定要大于等于sizeof（FLT_VOLUME_PROPERTIES）
	PFLT_VOLUME_PROPERTIES pVolumeProperties = (PFLT_VOLUME_PROPERTIES)szTmp;
	ULONG ulRetLength = 0;
	PUCHAR pVolumeInfo = NULL;

	PAGED_CODE();

	__try
	{
		status = FltGetVolumeProperties(FltObjects->Volume, pVolumeProperties, sizeof(FLT_VOLUME_PROPERTIES) + 512, &ulRetLength);
		if (STATUS_BUFFER_OVERFLOW == status || STATUS_BUFFER_TOO_SMALL == status)
		{
			pVolumeInfo = (PUCHAR)ExAllocatePoolWithTag(NonPagedPool, ulRetLength + 1, FILTER_TMP_POOL_TAG);
			if (NULL == pVolumeInfo)
			{
				PT_DBG_PRINT(PTDBG_TRACE_ROUTINES, ("ExAllocatePoolWithTag failed!\n"));
				__leave;
			}
			pVolumeProperties = (PFLT_VOLUME_PROPERTIES)pVolumeInfo;
			status = FltGetVolumeProperties(FltObjects->Volume, pVolumeProperties, ulRetLength, &ulRetLength);
			if (!NT_SUCCESS(status))
			{
				__leave;
			}
		}
		else if (!NT_SUCCESS(status))
		{
			__leave;
		}
		//success
		if (/*(FLT_FSTYPE_NTFS != VolumeFilesystemType && FLT_FSTYPE_FAT != VolumeFilesystemType && 
			FLT_FSTYPE_CDFS != VolumeFilesystemType && FLT_FSTYPE_UDFS != VolumeFilesystemType &&
			FLT_FSTYPE_NFS != VolumeFilesystemType && FLT_FSTYPE_EXFAT != VolumeFilesystemType) ||
			FILE_DEVICE_DISK_FILE_SYSTEM != pVolumeProperties->DeviceType ||*/
			IsShadowCopyType(&pVolumeProperties->RealDeviceName))
		{
			status = STATUS_FLT_DO_NOT_ATTACH;
			__leave;
		}
		status = SetVolumeContext(FltObjects, pVolumeProperties, FltObjects->Volume);
	}
	__finally
	{
		if (NULL != pVolumeInfo)
		{
			ExFreePoolWithTag(pVolumeInfo, FILTER_TMP_POOL_TAG);
		}
	}
	
	
	return status;
}


NTSTATUS
PtInstanceQueryTeardown(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This is called when an instance is being manually deleted by a
call to FltDetachVolume or FilterDetach thereby giving us a
chance to fail that detach request.

If this routine is not defined in the registration structure, explicit
detach requests via FltDetachVolume or FilterDetach will always be
failed.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Indicating where this detach request came from.

Return Value:

Returns the status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the start of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is been deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownStart: Entered\n"));
}


VOID
PtInstanceTeardownComplete(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
/*++

Routine Description:

This routine is called at the end of instance teardown.

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance and its associated volume.

Flags - Reason why this instance is been deleted.

Return Value:

None.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtInstanceTeardownComplete: Entered\n"));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDeviceObject, PUNICODE_STRING pRegistryPath)
{
	NTSTATUS status = STATUS_SUCCESS;

	UNREFERENCED_PARAMETER(pRegistryPath);
	
	InitData();
	InitThreadMgr(pDeviceObject);

	status = FltRegisterFilter(pDeviceObject, &FilterRegistration, &gFilterHandle);
	if (NT_SUCCESS(status))
	{
		status = FltStartFiltering(gFilterHandle);
		if (!NT_SUCCESS(status))
		{
			g_bUnloading = TRUE;
			g_bAllModuleInitOk = FALSE;
			UnInitData();
			UnInitThreadMgr();
			FltUnregisterFilter(gFilterHandle);
		}
		else
		{
			InitCommunication(gFilterHandle);
			g_bAllModuleInitOk = TRUE;
		}
	}
	else
	{
		UnInitData();
		UnInitThreadMgr();
	}
	
	return status;
}

NTSTATUS
PtUnload(
__in FLT_FILTER_UNLOAD_FLAGS Flags
)
/*++

Routine Description:

This is the unload routine for this miniFilter driver. This is called
when the minifilter is about to be unloaded. We can fail this unload
request if this is not a mandatory unloaded indicated by the Flags
parameter.

Arguments:

Flags - Indicating if this is a mandatory unload.

Return Value:

Returns the final status of this operation.

--*/
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	g_bUnloading = TRUE;
	g_bAllModuleInitOk = FALSE;

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtUnload: Entered\n"));
	if (gFilterHandle)
	{
		FltUnregisterFilter(gFilterHandle);
	}

	UnInitData();
	UnInitCommunication();
	UnInitThreadMgr();
	return STATUS_SUCCESS;
}


/*************************************************************************
MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

This routine is the main pre-operation dispatch routine for this
miniFilter. Since this is just a simple passThrough miniFilter it
does not do anything with the callbackData but rather return
FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
miniFilter in the chain.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	NTSTATUS status;
	FLT_PREOP_CALLBACK_STATUS FltStatus = FLT_PREOP_COMPLETE;
	
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationPassThrough: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//
#ifdef TEST
	if (IsTest(Data, FltObjects, "PtPreOperationPassThrough"))
	{
		//return FltStatus;
	}
#endif	

	if (IsMyFakeFcb(FltObjects->FileObject))
	{
		KdPrint(("PtPreOperationPassThrough:major=0x%x, minor=0x%x...\n", Data->Iopb->MajorFunction, Data->Iopb->MinorFunction));
		if (FLT_IS_FASTIO_OPERATION(Data))
		{
			FltStatus = FLT_PREOP_DISALLOW_FASTIO;
			return FltStatus;
		}
		if (FLT_IS_IRP_OPERATION(Data))
		{
			FltStatus = FsPrePassThroughIrp(Data, FltObjects, CompletionContext);
			return FltStatus;
		}
		if (FLT_IS_FS_FILTER_OPERATION(Data))
		{
			Data->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			return FltStatus;
		}
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	if (PtDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			PtOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("PassThrough!PtPreOperationPassThrough: FltRequestOperationStatusCallback Failed, status=%08x\n",
				status));
		}
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
PtOperationStatusCallback(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
__in NTSTATUS OperationStatus,
__in PVOID RequesterContext
)
/*++

Routine Description:

This routine is called when the given operation returns from the call
to IoCallDriver.  This is useful for operations where STATUS_PENDING
means the operation was successfully queued.  This is useful for OpLocks
and directory change notification operations.

This callback is called in the context of the originating thread and will
never be called at DPC level.  The file object has been correctly
referenced so that you can access it.  It will be automatically
dereferenced upon return.

This is non-pageable because it could be called on the paging path

Arguments:

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

RequesterContext - The context for the completion routine for this
operation.

OperationStatus -

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("PassThrough!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
		OperationStatus,
		RequesterContext,
		ParameterSnapshot->MajorFunction,
		ParameterSnapshot->MinorFunction,
		FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in_opt PVOID CompletionContext,
__in FLT_POST_OPERATION_FLAGS Flags
)
/*++

Routine Description:

This routine is the post-operation completion routine for this
miniFilter.

This is non-pageable because it may be called at DPC level.

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The completion context set in the pre-operation routine.

Flags - Denotes whether the completion is successful or is being drained.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPostOperationPassThrough: Entered\n"));

	return FLT_POSTOP_FINISHED_PROCESSING;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
)
/*++

Routine Description:

This routine is the main pre-operation dispatch routine for this
miniFilter. Since this is just a simple passThrough miniFilter it
does not do anything with the callbackData but rather return
FLT_PREOP_SUCCESS_WITH_CALLBACK thereby passing it down to the next
miniFilter in the chain.

This is non-pageable because it could be called on the paging path

Arguments:

Data - Pointer to the filter callbackData that is passed to us.

FltObjects - Pointer to the FLT_RELATED_OBJECTS data structure containing
opaque handles to this filter, instance, its associated volume and
file object.

CompletionContext - The context for the completion routine for this
operation.

Return Value:

The return value is the status of the operation.

--*/
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("PassThrough!PtPreOperationNoPostOperationPassThrough: Entered\n"));

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
__in PFLT_CALLBACK_DATA Data
)
/*++

Routine Description:

This identifies those operations we want the operation status for.  These
are typically operations that return STATUS_PENDING as a normal completion
status.

Arguments:

Return Value:

TRUE - If we want the operation status
FALSE - If we don't

--*/
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
		(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

		||

		//
		//    Check for directy change notification
		//

		((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
		(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
		);
}

BOOLEAN IsShadowCopyType(PUNICODE_STRING pDeviceName)
{
	UNICODE_STRING unicodeString;
	WCHAR * pWstrShadowCopy = L"\\Device\\HarddiskVolumeShadowCopy";
	if (NULL == pDeviceName)
	{
		return FALSE;
	}
	RtlInitUnicodeString(&unicodeString, pWstrShadowCopy);
	if (0 == RtlCompareUnicodeString(pDeviceName, &unicodeString, TRUE))
	{
		return TRUE;
	}
	return FALSE;
}

NTSTATUS GenerateFileName(IN PFLT_INSTANCE Instance, __in PFILE_OBJECT FileObject, __in PFLT_CALLBACK_DATA CallbackData, __in FLT_FILE_NAME_OPTIONS NameOptions, __inout PBOOLEAN CacheFileNameInformation, __inout PFLT_NAME_CONTROL FileName)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PFILE_OBJECT StreamObject = FileObject;
	PFLT_FILE_NAME_INFORMATION FileNameInformation = NULL;
	BOOLEAN bEncryptResource = FALSE;
	PDEFFCB Fcb = FileObject->FsContext;
	PDEF_CCB Ccb = FileObject->FsContext2;

	FsRtlEnterFileSystem();

	__try
	{
		if (IsMyFakeFcb(FileObject))
		{
			bEncryptResource = ExAcquireResourceSharedLite(Fcb->Resource, TRUE);
			if (BooleanFlagOn(Fcb->FcbState, FCB_STATE_DELETE_ON_CLOSE) || Ccb->StreamFileInfo.StreamObject == NULL)
			{
				try_return(Status = STATUS_FILE_DELETED);
			}
			else
			{
				StreamObject = Ccb->StreamFileInfo.StreamObject;
			}
		}

		ClearFlag(NameOptions, FLT_FILE_NAME_REQUEST_FROM_CURRENT_PROVIDER);

		if (FlagOn(NameOptions, FLT_FILE_NAME_NORMALIZED))
		{
			ClearFlag(NameOptions, FLT_FILE_NAME_NORMALIZED);
			SetFlag(NameOptions, FLT_FILE_NAME_OPENED);
		}

		if (CallbackData)
		{
			PFILE_OBJECT TemFileObject = CallbackData->Iopb->TargetFileObject;
			CallbackData->Iopb->TargetFileObject = StreamObject;

			FltSetCallbackDataDirty(CallbackData);

			Status = FltGetFileNameInformation(CallbackData, NameOptions, &FileNameInformation);

			CallbackData->Iopb->TargetFileObject = TemFileObject;
			FltClearCallbackDataDirty(CallbackData);
		}
		else
		{
			Status = FltGetFileNameInformationUnsafe(StreamObject, Instance, NameOptions, &FileNameInformation);
		}
		if (!NT_SUCCESS(Status))
		{
			try_return(Status);
		}
		Status = FltCheckAndGrowNameControl(FileName, FileNameInformation->Name.Length);

		if (!NT_SUCCESS(Status))
		{
			try_return(Status);
		}

		RtlCopyUnicodeString(&FileName->Name, &FileNameInformation->Name);

		if (FileNameInformation != NULL)
		{
			FltReleaseFileNameInformation(FileNameInformation);
		}
		Status = STATUS_SUCCESS;
	try_exit: NOTHING;
	}
	__finally
	{
		if (bEncryptResource)
		{
			ExReleaseResourceLite(Fcb->Resource);
		}
	}
	FsRtlExitFileSystem();
	return Status;
}

NTSTATUS NormalizeNameComponentCallback(__in PFLT_INSTANCE Instance, __in PCUNICODE_STRING ParentDirectory, __in USHORT VolumeNameLength, __in PCUNICODE_STRING Component, __inout PFILE_NAMES_INFORMATION ExpandComponentName, __in ULONG ExpandComponentNameLength, __in FLT_NORMALIZE_NAME_FLAGS Flags, __inout PVOID *NormalizationContext)
{
	return STATUS_UNSUCCESSFUL;
}
