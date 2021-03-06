#include "fsWrite.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	UNREFERENCED_PARAMETER(CompletionContext);


	PAGED_CODE();

	if (IsTest(Data, FltObjects, "PtPreWrite"))
	{
		KdBreakPoint();
	}
	else
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_PREOP_COMPLETE;
}

FLT_POSTOP_CALLBACK_STATUS PtPostWrite(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	if (IsTest(Data, FltObjects, "PtPostWrite"))
	{
		KdBreakPoint();
	}
	else
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}
