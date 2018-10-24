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
extern CACHE_MANAGER_CALLBACKS g_CacheManagerCallbacks;
extern NPAGED_LOOKASIDE_LIST g_NTFSFCBLookasideList;
extern NPAGED_LOOKASIDE_LIST g_FastMutexInFCBLookasideList;
extern ULONG g_SectorSize;
extern NPAGED_LOOKASIDE_LIST	g_Npaged4KBList;
extern NPAGED_LOOKASIDE_LIST	g_Npaged64KBList;

extern BOOLEAN g_bUnloading;
extern BOOLEAN g_bAllModuleInitOk;
extern BOOLEAN g_bSafeDataReady;

UCHAR szVcbPlacer[300];

#define READ_AHEAD_GRANULARITY           (0x10000)

#define ENCRYPT_FILE_NAME_LENGTH 128
typedef struct tagENCRYPT_FILE_FCB
{
	LIST_ENTRY listEntry;
	PDEFFCB Fcb;
	ULONG uType;
}ENCRYPT_FILE_FCB, *PENCRYPT_FILE_FCB;

extern PAGED_LOOKASIDE_LIST g_EncryptFileListLookasideList;
extern ERESOURCE g_FcbResource;
extern LIST_ENTRY g_FcbEncryptFileList;

extern DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS;
extern LARGE_INTEGER  Li0;
extern KSPIN_LOCK g_GeneralSpinLock;

#ifdef __cplusplus
extern "C" {
#endif

	VOID InitData();
	VOID UnInitData();

	BOOLEAN IsFilterProcess(IN PFLT_CALLBACK_DATA Data, IN PNTSTATUS pStatus, IN PULONG pProcType);

	PERESOURCE FsdAllocateResource();
	BOOLEAN FsIsIrpTopLevel(IN PFLT_CALLBACK_DATA Data);
	PDEF_IRP_CONTEXT FsCreateIrpContext(IN PFLT_CALLBACK_DATA Data, IN PCFLT_RELATED_OBJECTS FltObjects, IN BOOLEAN bWait);

	BOOLEAN FsAcquireFcbForLazyWrite(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID FsReleaseFcbFromLazyWrite(IN PVOID Fcb);
	BOOLEAN FsAcquireFcbForReadAhead(IN PVOID Fcb, IN BOOLEAN Wait);
	VOID FsReleaseFcbFromReadAhead(IN PVOID Fcb);

	BOOLEAN IsMyFakeFcb(PFILE_OBJECT FileObject);
	BOOLEAN IsTopLevelIRP(IN PFLT_CALLBACK_DATA Data);
	BOOLEAN GetVersion();
	BOOLEAN IsWin7OrLater();
	BOOLEAN IsVistaOrLater();

	BOOLEAN InsertFcbList(PDEFFCB *Fcb);
	BOOLEAN RemoveFcbList(WCHAR * pwszFile);
	VOID ClearFcbList();
	BOOLEAN FindFcb(IN PFLT_CALLBACK_DATA Data, IN WCHAR * pwszFile, IN PDEFFCB * pFcb);
	BOOLEAN UpdateFcbList(WCHAR * pwszFile, PDEFFCB * pFcb);

	BOOLEAN FsAcquireExclusiveFcb(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb);
	BOOLEAN FsAcquireSharedFcbWaitForEx(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb);
	BOOLEAN FsAcquireSharedFcb(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb);

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
	VOID FsFreeCcb(IN PDEF_CCB Ccb);
	PERESOURCE FsAllocateResource();
	void FsFreeResource(PERESOURCE Resource);

	VOID NetFileSetCacheProperty(IN PFILE_OBJECT FileObject, IN ACCESS_MASK DesiredAccess);
	NTSTATUS FsGetFileStandardInfo(__in PFLT_CALLBACK_DATA Data,
									__in PCFLT_RELATED_OBJECTS FltObject,
									__inout PDEF_IRP_CONTEXT IrpContext);

	NTSTATUS FsGetFileHeaderInfo(__in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS FsCreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	PDEFFCB  FsCreateFcb();
	BOOLEAN FsFreeFcb(__in PDEFFCB Fcb, __in PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS FsOverWriteFile(__in PFILE_OBJECT FileObject, __in PDEFFCB Fcb, __in LARGE_INTEGER AllocationSize);
	NTSTATUS FsCloseGetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __inout PFILE_BASIC_INFORMATION FileInfo);
	NTSTATUS FsCloseSetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_BASIC_INFORMATION FileInfo);

	BOOLEAN CanFsWait(__in PFLT_CALLBACK_DATA Data);

	FLT_PREOP_CALLBACK_STATUS FsCompleteMdl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	VOID FsProcessException (IN OUT PDEF_IRP_CONTEXT *IrpContext OPTIONAL, IN OUT PFLT_CALLBACK_DATA *Data  OPTIONAL, IN NTSTATUS Status);
	PVOID FsMapUserBuffer(__inout PFLT_CALLBACK_DATA Data, __inout PULONG RetLength);

	BOOLEAN MyFltCheckLockForReadAccess(IN PFILE_LOCK FileLock, IN PFLT_CALLBACK_DATA  Data);
	VOID FsLookupFileAllocationSize(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb, IN PDEF_CCB Ccb);
	VOID FsPopUpFileCorrupt(IN PDEF_IRP_CONTEXT IrpContext, IN PDEFFCB Fcb);

	FLT_PREOP_CALLBACK_STATUS FsPrePassThroughIrp(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext);

	BOOLEAN IsTest(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PUCHAR FunctionName);

	BOOLEAN FsGetFileExtFromFileName(__in PUNICODE_STRING pFilePath, __inout WCHAR * FileExt, __inout USHORT* nLength);
	NTSTATUS FsTransformFileToEncrypted(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEFFCB Fcb, __in PDEF_CCB Ccb);
	NTSTATUS FsWriteFileHeader(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in PLARGE_INTEGER RealFileSize, __in WCHAR * FileFullName);
	NTSTATUS FsExtendingValidDataSetFile(__in PCFLT_RELATED_OBJECTS FltObjects, PDEFFCB Fcb, PDEF_CCB Ccb);
	BOOLEAN FsZeroData(IN PDEF_IRP_CONTEXT IrpContext,
		IN PDEFFCB Fcb,
		IN PFILE_OBJECT FileObject,
		IN LONGLONG StartingZero,
		IN LONGLONG ByteCount,
		IN ULONG SectorSize);
	BOOLEAN FsMyFltCheckLockForWriteAccess(__in PFILE_LOCK FileLock, __in PFLT_CALLBACK_DATA  Data);

	NTSTATUS FsSetFileInformation(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in PVOID FileInfoBuffer, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInfoClass);
	BOOLEAN CheckEnv(__in ULONG ulMinifilterEnvType);
	BOOLEAN IsFilterFileByExt(__in WCHAR * pwszExtName, __in USHORT Length);
	NTSTATUS FsGetFileObjectIdInfo(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __inout PDEFFCB Fcb);
	NTSTATUS FsGetFileSecurityInfo(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEFFCB Fcb);

	NTSTATUS FsFileInfoChangedNotify(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects);
	NTSTATUS FsGetProcessName(__in ULONG ProcessID, __inout PUNICODE_STRING ProcessImageName);
	NTSTATUS FsGetCcFileInfo(__in PCFLT_RELATED_OBJECTS FltObject, __in PWCHAR FileName, __inout PHANDLE CcFileHandle, __inout PVOID * CcFileObject);
	VOID FsFreeCcFileInfo(__in PHANDLE CcFileHandle, __in PVOID * CcFileObject);
#ifdef __cplusplus
}
#endif

#endif // !FSDATA_H
