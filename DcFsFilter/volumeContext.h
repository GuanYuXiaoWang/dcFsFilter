#ifndef VOLUMECONTEXT_H
#define VOLUMECONTEXT_H
#include <fltKernel.h>

#define DEVICE_NAME_LENGTH_MAX 256
#define METADATA_FILE_COUNT 12

#define MIN_SECTOR_SIZE			0x1000
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
	WSTRING strMetaDataList[METADATA_FILE_COUNT];
}VOLUMECONTEXT, *PVOLUMECONTEXT;

NTSTATUS setVolumeContext(ULONG ulSectorSize, PUNICODE_STRING pDevName, PFLT_VOLUME pFltVolume);

#endif
