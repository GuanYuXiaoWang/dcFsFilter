#ifndef VOLUMECONTEXT_H
#define VOLUMECONTEXT_H
#include <fltKernel.h>

#define DEVICE_NAME_LENGTH_MAX 256
#define METADATA_FILE_COUNT 12

#define VOLUME_CONTEXT_POOL_TAG 'vlpt'

extern PFLT_FILTER gFilterHandle;

typedef struct tagWSTRING
{
	WCHAR *pwszName;
	ULONG ulLength;
}WSTRING, *PWSTRING;

typedef struct tagVOLUMECONTEXT
{
	ULONG ulSectorSize;
	WSTRING strDeviceName;
	PERESOURCE pEresurce;
	ULONG uDeviceType;
	ULONG uSectorsPerAllocationUnit;
	BOOLEAN bWrite;
}VOLUMECONTEXT, *PVOLUMECONTEXT;

#ifdef __cplusplus
extern "C"
{
#endif

	NTSTATUS SetVolumeContext(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFLT_VOLUME_PROPERTIES pVolumePro, __in PFLT_VOLUME pFltVolume);
	VOID VolumeCleanup(__in PFLT_CONTEXT Context, __in FLT_CONTEXT_TYPE ContextType);

	FLT_PREOP_CALLBACK_STATUS PtPreVolumeMount(__inout PFLT_CALLBACK_DATA Data,
		__in PCFLT_RELATED_OBJECTS FltObjects,
		__deref_out_opt PVOID *CompletionContext);


	FLT_POSTOP_CALLBACK_STATUS PtPostVolumeMount(__inout PFLT_CALLBACK_DATA Data,
		__in PCFLT_RELATED_OBJECTS FltObjects,
		__in_opt PVOID CompletionContext,
		__in FLT_POST_OPERATION_FLAGS Flags);

#ifdef __cplusplus
}
#endif

#endif
