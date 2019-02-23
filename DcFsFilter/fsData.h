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
extern NPAGED_LOOKASIDE_LIST g_FastMutexInFCBLookasideList;
extern ULONG g_SectorSize;
extern NPAGED_LOOKASIDE_LIST	g_Npaged4KBList;
extern NPAGED_LOOKASIDE_LIST	g_Npaged64KBList;

extern BOOLEAN g_bUnloading;
extern BOOLEAN g_bAllModuleInitOk;
extern BOOLEAN g_bSafeDataReady;

#define READ_AHEAD_GRANULARITY           (0x10000)

#define ENCRYPT_FILE_NAME_LENGTH 128
typedef struct tagENCRYPT_FILE_FCB
{
	LIST_ENTRY listEntry;
	PDEF_FCB Fcb;
	ULONG uType;
}ENCRYPT_FILE_FCB, *PENCRYPT_FILE_FCB;

extern PAGED_LOOKASIDE_LIST g_EncryptFileListLookasideList;
extern ERESOURCE g_FcbResource;
extern LIST_ENTRY g_FcbEncryptFileList;

extern DYNAMIC_FUNCTION_POINTERS g_DYNAMIC_FUNCTION_POINTERS;
extern LARGE_INTEGER  Li0;
extern KSPIN_LOCK g_GeneralSpinLock;


typedef struct  tagTHREAD_PARAM
{
	PFLT_FILTER Filter;
	PFLT_INSTANCE Instance;
	BOOLEAN NetFile;
	ULONG Length;
	WCHAR * FilePath;
}THREAD_PARAM;

typedef struct tagENCRYPTING_FILE_INFO
{
	LIST_ENTRY listEntry;
	THREAD_PARAM * Paream;
}ENCRYPTING_FILE_INFO, *PENCRYPTING_FILE_INFO;

#ifdef __cplusplus
extern "C" {
#endif

	VOID InitData();
	VOID UnInitData();

	BOOLEAN IsFilterProcess(__in PFLT_CALLBACK_DATA Data, __in PNTSTATUS Status, __in PULONG ProcType);
	BOOLEAN IsControlProcessByProcessId(__in HANDLE ProcessID, __inout ULONG * ProcessType);
	BOOLEAN IsFltFileLock();
	BOOLEAN IsNeedEncrypted();
	BOOLEAN IsLastAccessNetWorkFile();
	VOID FsSetExplorerInfo(__in  PFILE_OBJECT FileObject, __in PDEF_FCB Fcb);

	PDEF_IRP_CONTEXT FsCreateIrpContext(__in PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in BOOLEAN Wait);

	BOOLEAN FsAcquireFcbForLazyWrite(__in PVOID Fcb, __in BOOLEAN Wait);
	VOID FsReleaseFcbFromLazyWrite(__in PVOID Fcb);
	BOOLEAN FsAcquireFcbForReadAhead(__in PVOID Fcb, __in BOOLEAN Wait);
	VOID FsReleaseFcbFromReadAhead(__in PVOID Fcb);

	BOOLEAN IsMyFakeFcb(__in PFILE_OBJECT FileObject);
	BOOLEAN IsTopLevelIRP(__in PFLT_CALLBACK_DATA Data);
	BOOLEAN GetVersion();
	BOOLEAN IsWin7OrLater();
	BOOLEAN IsVistaOrLater();
	BOOLEAN IsWin10();

	BOOLEAN InsertFcbList(__in PDEF_FCB *Fcb);
	BOOLEAN RemoveFcbList(__in WCHAR * pwszFile);
	VOID ClearFcbList();
	BOOLEAN FindFcb(__in PFLT_CALLBACK_DATA Data, __in WCHAR * pwszFile, __in PDEF_FCB * pFcb);
	BOOLEAN UpdateFcbList(WCHAR * pwszFile, PDEF_FCB * pFcb);

	BOOLEAN FsAcquireExclusiveFcb(__in PDEF_IRP_CONTEXT IrpContext, __in PDEF_FCB Fcb);
	BOOLEAN FsAcquireSharedFcbWaitForEx(__in PDEF_IRP_CONTEXT IrpContext, __in PDEF_FCB Fcb);
	BOOLEAN FsAcquireSharedFcb(__in PDEF_IRP_CONTEXT IrpContext, __in PDEF_FCB Fcb);

	VOID FsVerifyOperationIsLegal(__in PDEF_IRP_CONTEXT IrpContext);
	VOID FsRaiseStatus(__in PDEF_IRP_CONTEXT IrpContext, __in NTSTATUS Status);

	VOID FsPrePostIrp(__in PFLT_CALLBACK_DATA Data, __in PVOID Context);
	VOID FsOplockComplete(__in PFLT_CALLBACK_DATA Data, __in PVOID Context);
	VOID FsAddToWorkQueue(__in PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext);
	VOID FsCompleteRequest(__inout PDEF_IRP_CONTEXT * IrpContext OPTIONAL, __inout PFLT_CALLBACK_DATA *Data OPTIONAL,
		__in NTSTATUS Status,
		__in BOOLEAN Pending);

	VOID FsDispatchWorkItem(__in PDEVICE_OBJECT DeviceObject, __in PVOID Context);
	NTSTATUS FsPostRequest(__inout PFLT_CALLBACK_DATA Data, __in PDEF_IRP_CONTEXT IrpContext);
	VOID FsDeleteIrpContext(__inout PDEF_IRP_CONTEXT * IrpContext);

	PDEF_CCB FsCreateCcb();
	VOID FsFreeCcb(__in PDEF_CCB Ccb);
	PERESOURCE FsAllocateResource();
	void FsFreeResource(__in PERESOURCE Resource);

	VOID NetFileSetCacheProperty(__in PFILE_OBJECT FileObject, __in ACCESS_MASK DesiredAccess);
	NTSTATUS FsGetFileStandardInfo(__in PFLT_CALLBACK_DATA Data,
									__in PCFLT_RELATED_OBJECTS FltObject,
									__inout PDEF_IRP_CONTEXT IrpContext);

	NTSTATUS FsGetFileHeaderInfo(__in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS FsCreateFcbAndCcb(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	PDEF_FCB  FsCreateFcb();
	BOOLEAN FsFreeFcb(__in PDEF_FCB Fcb, __in PDEF_IRP_CONTEXT IrpContext);
	NTSTATUS FsOverWriteFile(__in PFILE_OBJECT FileObject, __in PDEF_FCB Fcb, __in LARGE_INTEGER AllocationSize);
	NTSTATUS FsCloseGetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __inout PFILE_BASIC_INFORMATION FileInfo);
	NTSTATUS FsCloseSetFileBasicInfo(__in PFILE_OBJECT FileObject, __in PDEF_IRP_CONTEXT IrpContext, __in PFILE_BASIC_INFORMATION FileInfo);

	BOOLEAN CanFsWait(__in PFLT_CALLBACK_DATA Data);

	FLT_PREOP_CALLBACK_STATUS FsCompleteMdl(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __in PDEF_IRP_CONTEXT IrpContext);
	VOID FsProcessException(__inout PDEF_IRP_CONTEXT *IrpContext, __inout PFLT_CALLBACK_DATA *Data, __in NTSTATUS Status);
	PVOID FsMapUserBuffer(__inout PFLT_CALLBACK_DATA Data, __inout PULONG RetLength);

	BOOLEAN MyFltCheckLockForReadAccess(__in PFILE_LOCK FileLock, __in PFLT_CALLBACK_DATA  Data);
	VOID FsLookupFileAllocationSize(__in PDEF_IRP_CONTEXT IrpContext, __in PDEF_FCB Fcb, __in PDEF_CCB Ccb);
	VOID FsPopUpFileCorrupt(__in PDEF_IRP_CONTEXT IrpContext, __in PDEF_FCB Fcb);

	FLT_PREOP_CALLBACK_STATUS FsPrePassThroughIrp(__inout PFLT_CALLBACK_DATA Data, __in PCFLT_RELATED_OBJECTS FltObjects, __deref_out_opt PVOID *CompletionContext);

	BOOLEAN FsGetFileExtFromFileName(__in PUNICODE_STRING pFilePath, __inout WCHAR * FileExt, __inout USHORT* nLength);
	NTSTATUS FsWriteFileHeader(__in PFLT_INSTANCE Instance, __in PFILE_OBJECT FileObject, __inout PVOID HeadBuf);
	NTSTATUS FsNonCacheWriteFileHeader(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in PDEF_FCB Fcb);
	BOOLEAN FsZeroData(__in PDEF_IRP_CONTEXT IrpContext,
		__in PDEF_FCB Fcb,
		__in PFILE_OBJECT FileObject,
		__in LONGLONG StartingZero,
		__in LONGLONG ByteCount,
		__in ULONG SectorSize);
	BOOLEAN FsMyFltCheckLockForWriteAccess(__in PFILE_LOCK FileLock, __in PFLT_CALLBACK_DATA  Data);

	NTSTATUS FsSetFileInformation(__in PCFLT_RELATED_OBJECTS FltObjects, __in PFILE_OBJECT FileObject, __in PVOID FileInfoBuffer, __in ULONG Length, __in FILE_INFORMATION_CLASS FileInfoClass);
	BOOLEAN CheckEnv(__in ULONG ulMinifilterEnvType);
	
	NTSTATUS FsGetFileSecurityInfo(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects, __inout PDEF_FCB Fcb, __in PDEF_CCB Ccb);

	NTSTATUS FsFileInfoChangedNotify(__in PFLT_CALLBACK_DATA  Data, __in PCFLT_RELATED_OBJECTS FltObjects);
	NTSTATUS FsGetProcessName(__in ULONG ProcessID, __inout PUNICODE_STRING ProcessImageName);
	NTSTATUS FsGetCcFileInfo(__in PFLT_FILTER Filter, __in PFLT_INSTANCE Instance, __in PWCHAR FileName, __inout PHANDLE CcFileHandle, __inout PVOID * CcFileObject, __in BOOLEAN NetWork);
	VOID FsFreeCcFileInfo(__in PHANDLE CcFileHandle, __in PVOID * CcFileObject);
	NTSTATUS FsEncrypteFile(__in PFLT_CALLBACK_DATA Data, __in PFLT_FILTER Filter, __in PFLT_INSTANCE Instance, __in  PWCHAR FilePath, __in ULONG FileLength, __in BOOLEAN NetWork, __in PFILE_OBJECT CcFileObject);

	NTSTATUS FsDelayEncrypteFile(__in PCFLT_RELATED_OBJECTS FltObjects, __in  PWCHAR FilePath, __in ULONG Length, __in BOOLEAN NetFile);
	VOID KeSleep(LONG MilliSecond);
	BOOLEAN IsRecycleBinFile(__in PWCHAR  FilePath, __in USHORT Length);
	PFILE_OBJECT FsGetCcFileObjectByFcbOrCcb(__in PDEF_FCB Fcb, __in PDEF_CCB Ccb);

	BOOLEAN FsInsertEncryptingFilesInfo(__in THREAD_PARAM * Param);
	VOID FsDeleteEncryptingFilesInfo(__in WCHAR * FileName, __in ULONG Length, __in THREAD_PARAM * Param);
	BOOLEAN FsFindEncryptingFilesInfo(__in PFLT_CALLBACK_DATA  Data, __in WCHAR * FileName);
	VOID FsClearEncryptingFilesInfo();

#ifdef __cplusplus
}
#endif

#endif // !FSDATA_H
