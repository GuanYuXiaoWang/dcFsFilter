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
	PWSTRING strMetaDataList;
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

#ifdef __cplusplus
}
#endif

#endif
