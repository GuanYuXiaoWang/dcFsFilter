#ifndef FSFASTIO_H
#define FSFASTIO_H

#include "defaultStruct.h"

FLT_PREOP_CALLBACK_STATUS PtPreFastIoCheckPossible(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__deref_out_opt PVOID *CompletionContext);


FLT_POSTOP_CALLBACK_STATUS PtPostFastIoCheckPossible(__inout PFLT_CALLBACK_DATA Data,
	__in PCFLT_RELATED_OBJECTS FltObjects,
	__in_opt PVOID CompletionContext,
	__in FLT_POST_OPERATION_FLAGS Flags);


#endif