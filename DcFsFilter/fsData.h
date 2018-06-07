#ifndef FSDATA_H
#define FSDATA_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "defaultStruct.h"

extern NPAGED_LOOKASIDE_LIST  g_IrpContextLookasideList;
extern NPAGED_LOOKASIDE_LIST  g_IoContextLookasideList;
extern NPAGED_LOOKASIDE_LIST  g_FcbLookasideList;
extern NPAGED_LOOKASIDE_LIST  g_CcbLookasideList;
extern NPAGED_LOOKASIDE_LIST  g_EResourceLookasideList;

#define ENCRYPT_FILE_NAME_LENGTH 128
typedef struct tagENCRYPT_FILE_FCB
{
	LIST_ENTRY listEntry;
	PDEFFCB Fcb;
	ULONG uType;
}ENCRYPT_FILE_FCB, *PENCRYPT_FILE_FCB;

PAGED_LOOKASIDE_LIST g_EncryptFileListLookasideList;
ERESOURCE g_FcbResource;
LIST_ENTRY g_FcbEncryptFileList;

extern DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS;

#ifdef __cplusplus
extern "C" {
#endif

	VOID initData();
	VOID unInitData();
	PERESOURCE fsdAllocateResource();
	BOOLEAN fsIsIrpTopLevel(IN PFLT_CALLBACK_DATA Data);
	PDEF_IRP_CONTEXT fsCreateIrpContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN bWait);

	BOOLEAN fsAcquireFcbForLazyWrite(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID fsReleaseFcbFromLazyWrite(IN PVOID Fcb);
	BOOLEAN fsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID fsReleaseFcbFromReadAhead(IN PVOID Fcb);

	BOOLEAN IsMyFakeFcb(PFILE_OBJECT FileObject);
	BOOLEAN IsTopLevelIRP(IN PFLT_CALLBACK_DATA Data);

	PDEF_IRP_CONTEXT CreateIRPContext(IN PFLT_CALLBACK_DATA Data,
									IN PCFLT_RELATED_OBJECTS FltObjects,
									IN BOOLEAN Wait
									);
	BOOLEAN GetVersion();
	BOOLEAN IsWin7OrLater();

	BOOLEAN InsertFcbList(PDEFFCB *Fcb);
	BOOLEAN RemoveFcbList(WCHAR * pwszFile);
	BOOLEAN FindFcb(WCHAR * pwszFile, PDEFFCB * pFcb);
	BOOLEAN UpdateFcbList(WCHAR * pwszFile, PDEFFCB * pFcb);

#ifdef __cplusplus
}
#endif

#endif // !FSDATA_H
