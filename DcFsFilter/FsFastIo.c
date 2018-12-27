#include "FsFastIo.h"
#include "fsData.h"

FLT_PREOP_CALLBACK_STATUS PtPreFastIoCheckPossible(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext)
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG ProcessType = 0;

	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(CompletionContext);

	PAGED_CODE();

	if (!IsMyFakeFcb(FltObjects->FileObject))
	{
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	FsRtlEnterFileSystem();
	KdPrint(("PtPreFastIoCheckPossible....\n"));

	FsRtlExitFileSystem();
	return FLT_PREOP_DISALLOW_FASTIO;
}

FLT_POSTOP_CALLBACK_STATUS PtPostFastIoCheckPossible(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in_opt PVOID CompletionContext, __in FLT_POST_OPERATION_FLAGS Flags)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	return FLT_POSTOP_FINISHED_PROCESSING;
}
