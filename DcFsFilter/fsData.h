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
extern LARGE_INTEGER  Li0;

#ifdef __cplusplus
extern "C" {
#endif

	VOID InitData();
	VOID UnInitData();
	PERESOURCE FsdAllocateResource();
	BOOLEAN FsIsIrpTopLevel(IN PFLT_CALLBACK_DATA Data);
	PDEF_IRP_CONTEXT FsCreateIrpContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN bWait);

	BOOLEAN FsAcquireFcbForLazyWrite(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID FsReleaseFcbFromLazyWrite(IN PVOID Fcb);
	BOOLEAN FsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID FsReleaseFcbFromReadAhead(IN PVOID Fcb);

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

	BOOLEAN FsdAcquireExclusiveFcb(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb);
	VOID FsVerifyOperationIsLegal(IN PDEF_IRP_CONTEXT IrpContext);
	VOID FsRaiseStatus(PDEF_IRP_CONTEXT IrpContext,NTSTATUS Status);

	VOID FsPrePostIrp(IN PFLT_CALLBACK_DATA Data, IN PVOID Context);
	VOID FsOplockComplete(IN PFLT_CALLBACK_DATA Data, IN PVOID Context);
	VOID FsAddToWorkQueue(IN PFLT_CALLBACK_DATA Data, IN PDEF_IRP_CONTEXT IrpContext);
	VOID FsCompleteRequest(IN OUT PDEF_IRP_CONTEXT * IrpContext OPTIONAL, IN OUT PFLT_CALLBACK_DATA *Data OPTIONAL,
		IN NTSTATUS Status,
		IN BOOLEAN Pending);

	VOID FsDispatchWorkItem(IN PDEVICE_OBJECT DeviceObject, IN PVOID Context);
	NTSTATUS FsPostRequest(IN OUT PFLT_CALLBACK_DATA Data, IN PDEF_IRP_CONTEXT IrpContext);
	VOID FsDeleteIrpContext(IN OUT PDEF_IRP_CONTEXT * IrpContext);

	PDEF_CCB FsCreateCcb();
	PERESOURCE FsAllocateResource();
	VOID NetFileSetCacheProperty(IN PFILE_OBJECT FileObject, IN ACCESS_MASK DesiredAccess);
	NTSTATUS MyGetFileStandardInfo(__in PFLT_CALLBACK_DATA Data,
									__in PCFLT_RELATED_OBJECTS FltObject,
									__in PFILE_OBJECT FileObject,
									__in PLARGE_INTEGER FileAllocateSize,
									__in PLARGE_INTEGER FileSize,
									__in PBOOLEAN bDirectory);

	NTSTATUS CreatedFileHeaderInfo(__in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS CreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	PDEFFCB  FsCreateFcb();
	BOOLEAN FsFreeFcb(__in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS FsOverWriteFile(__in PFILE_OBJECT FileObject, __in PDEFFCB Fcb, __in LARGE_INTEGER AllocationSize);
	NTSTATUS FsCloseGetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __inout PFILE_BASIC_INFORMATION FileInfo);
	NTSTATUS FsCloseSetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_BASIC_INFORMATION FileInfo);


#ifdef __cplusplus
}
#endif

#endif // !FSDATA_H
