#ifndef FSINFORMATION_H
#define FSINFORMATION_H

#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreQueryInformation(__inout PFLT_CALLBACK_DATA Data,
														__in PCFLT_RELATED_OBJECTS FltObjects,
														__deref_out_opt PVOID *CompletionContext);


FLT_POSTOP_CALLBACK_STATUS PtPostQueryInformation(__inout PFLT_CALLBACK_DATA Data,
														__in PCFLT_RELATED_OBJECTS FltObjects,
														__in_opt PVOID CompletionContext,
														__in FLT_POST_OPERATION_FLAGS Flags);



NTSTATUS FsCommonQueryInformation(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);



#endif