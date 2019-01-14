#ifndef FSWRITE_H
#define FSWRITE_H

#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext);


FLT_POSTOP_CALLBACK_STATUS PtPostWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FsFastIoWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects);

FLT_PREOP_CALLBACK_STATUS FsCommonWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);

NTSTATUS FsRealWriteFile(__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PDEF_IRP_CONTEXT IrpContext,
	__in PVOID SystemBuffer,
	__in LARGE_INTEGER ByteOffset,
	__in ULONG ByteCount,
	__in PULONG_PTR RetBytes
	);

VOID FsWriteFileAsyncCompletionRoutine(__in PFLT_CALLBACK_DATA Data, __in PFLT_CONTEXT Context);

FLT_PREOP_CALLBACK_STATUS PtPreAcquireForModWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostAcquireForModWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS PtPreReleaseForModWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostReleaseForModWrite(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

#endif