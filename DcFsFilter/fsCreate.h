#ifndef FSCREATE_H
#define FSCREATE_H

#include "defaultStruct.h"

#ifdef __cplusplus
extern "C" {
#endif

FLT_PREOP_CALLBACK_STATUS PtPreCreate(__inout PFLT_CALLBACK_DATA Data,
												__in PCFLT_RELATED_OBJECTS FltObjects,
												__deref_out_opt PVOID *CompletionContext
												);

FLT_POSTOP_CALLBACK_STATUS PtPostCreate(__inout PFLT_CALLBACK_DATA Data,
												__in PCFLT_RELATED_OBJECTS FltObjects,
												__in_opt PVOID CompletionContext,
												__in FLT_POST_OPERATION_FLAGS Flags
												);

FLT_PREOP_CALLBACK_STATUS PtPreOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data,
														__in PCFLT_RELATED_OBJECTS FltObjects,
														__deref_out_opt PVOID *CompletionContext
														);

FLT_POSTOP_CALLBACK_STATUS PtPostOperationNetworkQueryOpen(__inout PFLT_CALLBACK_DATA Data,
															__in PCFLT_RELATED_OBJECTS FltObjects,
															__in_opt PVOID CompletionContext,
															__in FLT_POST_OPERATION_FLAGS Flags
															);

FLT_PREOP_CALLBACK_STATUS FsCommonCreate(__inout PFLT_CALLBACK_DATA Data,
										__in PCFLT_RELATED_OBJECTS FltObjects,
										__in PDEF_IRP_CONTEXT IrpContext
										);

BOOLEAN IsNeedSelfFcb(__inout PFLT_CALLBACK_DATA Data, PFLT_FILE_NAME_INFORMATION * nameInfo, PNTSTATUS pStatus);
BOOLEAN IsConcernedCreateOptions(__inout PFLT_CALLBACK_DATA Data);

NTSTATUS CreateFileByExistFcb(__inout PFLT_CALLBACK_DATA Data,
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in PDEFFCB Fcb,
							__in PDEF_IRP_CONTEXT IrpContext
							);

NTSTATUS  CreateFileByNonExistFcb(__inout PFLT_CALLBACK_DATA Data,
								__in PCFLT_RELATED_OBJECTS FltObjects,
								__in PDEFFCB Fcb,
								__in PDEF_IRP_CONTEXT IrpContext
								);

NTSTATUS CreateFileLimitation(__inout PFLT_CALLBACK_DATA Data, 
							__in PCFLT_RELATED_OBJECTS FltObjects,
							__in PUNICODE_STRING FileName,
							__out PHANDLE phFile,
							__out PFILE_OBJECT * pFileObject,
							__out PIO_STATUS_BLOCK IoStatus,
							__in BOOLEAN bNetWork
							);
#ifdef __cplusplus
}
#endif

#endif