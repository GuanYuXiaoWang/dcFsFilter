#ifndef FSCONTROL_H
#define FSCONTROL_H

#include "defaultStruct.h"


FLT_PREOP_CALLBACK_STATUS PtPreFileSystemControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostFileSystemControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

NTSTATUS FsCommonFileSystemControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PDEF_IRP_CONTEXT IrpContext
	);

FLT_PREOP_CALLBACK_STATUS PtPreLockControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostLockControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

FLT_PREOP_CALLBACK_STATUS FsCommonLockControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in PDEF_IRP_CONTEXT IrpContext);

NTSTATUS FsUserRequestControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);

FLT_PREOP_CALLBACK_STATUS PtPreDirectoryControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostDirectoryControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

NTSTATUS FsPostUnderlyingDriverControl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject);

NTSTATUS FsOplockRequest(__inout PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext, __in PDEFFCB Fcb);

FLT_PREOP_CALLBACK_STATUS PtPreDeviceControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext
	);

FLT_POSTOP_CALLBACK_STATUS PtPostDeviceControl(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags
	);

#endif