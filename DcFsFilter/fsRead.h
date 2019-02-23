#ifndef FSREAD_H
#define FSREAD_H

#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreRead(__inout PFLT_CALLBACK_DATA Data,
											__in PCFLT_RELATED_OBJECTS FltObjects,
											__deref_out_opt PVOID *CompletionContext);


FLT_POSTOP_CALLBACK_STATUS PtPostRead(__inout PFLT_CALLBACK_DATA Data,
											__in PCFLT_RELATED_OBJECTS FltObjects,
											__in_opt PVOID CompletionContext,
											__in FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FsCommonRead(__inout PFLT_CALLBACK_DATA Data,
										__in PCFLT_RELATED_OBJECTS FltObjects,
										__in PDEF_IRP_CONTEXT IrpContext);


FLT_PREOP_CALLBACK_STATUS FsFastIoRead(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects);

FLT_PREOP_CALLBACK_STATUS FsPostStackOverflowRead(__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__in PDEF_IRP_CONTEXT IrpContext);

NTSTATUS FsRealReadFile(__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PDEF_IRP_CONTEXT IrpContext,
	__in PVOID SystemBuffer,
	__in LARGE_INTEGER ByteOffset,
	__in ULONG ByteCount,
	OUT PULONG_PTR RetBytes);	

#endif