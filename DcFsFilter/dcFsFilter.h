#ifndef DCFSFILTER_H
#define DCFSFILTER_H

#include <fltKernel.h>

ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002
ULONG gTraceFlags = 0;

#define FILTER_TMP_POOL_TAG 'tmp0'


#define PT_DBG_PRINT( _dbgLevel, _string )          \
	(FlagOn(gTraceFlags, (_dbgLevel)) ? \
	DbgPrint _string : \
	((int)0))

#ifdef __cplusplus
extern "C"
{
#endif

NTSTATUS
PtInstanceSetup(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_SETUP_FLAGS Flags,
__in DEVICE_TYPE VolumeDeviceType,
__in FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
PtInstanceTeardownStart(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
PtInstanceTeardownComplete(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
PtUnload(
__in FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
PtInstanceQueryTeardown(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

VOID
PtOperationStatusCallback(
__in PCFLT_RELATED_OBJECTS FltObjects,
__in PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
__in NTSTATUS OperationStatus,
__in PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__in_opt PVOID CompletionContext,
__in FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationPassThrough(
__inout PFLT_CALLBACK_DATA Data,
__in PCFLT_RELATED_OBJECTS FltObjects,
__deref_out_opt PVOID *CompletionContext
);

BOOLEAN
PtDoRequestOperationStatus(
__in PFLT_CALLBACK_DATA Data
);

NTSTATUS GenerateFileName(__in PFLT_INSTANCE  Instance,
__in PFILE_OBJECT  FileObject,
__in PFLT_CALLBACK_DATA  CallbackData,
__in FLT_FILE_NAME_OPTIONS  NameOptions,
__inout PBOOLEAN  CacheFileNameInformation,
__inout PFLT_NAME_CONTROL  FileName
);

NTSTATUS NormalizeNameComponentCallback(__in PFLT_INSTANCE  Instance,
__in PCUNICODE_STRING  ParentDirectory,
__in USHORT  VolumeNameLength,
__in PCUNICODE_STRING  Component,
__inout PFILE_NAMES_INFORMATION  ExpandComponentName,
__in ULONG  ExpandComponentNameLength,
__in FLT_NORMALIZE_NAME_FLAGS  Flags,
__inout PVOID  *NormalizationContext
);

BOOLEAN IsShadowCopyType(PUNICODE_STRING pDeviceName);

#ifdef __cplusplus
}
#endif
#endif