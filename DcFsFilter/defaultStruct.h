#ifndef DEFAULTSTRUCT_H
#define DEFAULTSTRUCT_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "nodetype.h"
#include "fatstruc.h"
#include "volumeContext.h"

#define FILE_NO_ACCESS 0x800
#define FILE_PASS_ACCESS 0x400

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

typedef enum tagCREATE_ACCESS_TYPE
{
	CREATE_ACCESS_INVALID,
	CREATE_ACCESS_READ,
	CREATE_ACCESS_WRITE,
	CREATE_ACCESS_READWRITE
}CREATE_ACCESS_TYPE;

#define CACHE_READ		0x001
#define CACHE_READWRITE		0x002
#define CACHE_DISABLE		0x004
#define CACHE_ALLOW			0x008

#define FILE_ACCESS_PROCESS_READ 0x001
#define FILE_ACCESS_PROCESS_RW 0x002
#define FILE_ACCESS_PROCESS_DISABLE 0x004

#ifndef ENCRYPT_HEAD_LENGTH
#define ENCRYPT_HEAD_LENGTH 1024
#endif

#define SUPPORT_OPEN_COUNT_MAX 100

typedef struct tagFILE_OPEN_INFO
{
	PVOID FileObject;
	HANDLE FileHandle;
}FILE_OPEN_INFO, *PFILE_OPEN_INFO;

typedef struct tagDEF_IO_CONTEXT
{
	//
	//  A copy of the IrpContext flags preserved for use in
	//  async I/O completion.
	//

	ULONG IrpContextFlags;

	//
	//  These two field are used for multiple run Io
	//
	PIRP TopLevelIrp;

	//
	//  MDL to describe partial sector zeroing
	//

	PMDL SwapMdl;

	union {

		//
		//  This element handles the asychronous non-cached Io
		//

		struct {
			PERESOURCE Resource;
			PERESOURCE Resource2;
			ERESOURCE_THREAD ResourceThreadId;
			ULONG RequestedByteCount;
			PFILE_OBJECT FileObject;
			PNON_PAGED_FCB NonPagedFcb;
			PERESOURCE FO_Resource;
			PFAST_MUTEX FileObjectMutex;
			ULONG ByteCount;
			PRKEVENT		OutstandingAsyncEvent;
			ULONG			OutstandingAsyncWrites;
		} Async;

		//
		//  and this element the sycnrhonous non-cached Io
		//

		KEVENT SyncEvent;

	} Wait;

	PVOLUMECONTEXT volCtx;
	PFLT_CALLBACK_DATA Data;

	BOOLEAN bPagingIo;
	BOOLEAN bEnFile;

	PVOID SystemBuffer;
	PVOID SwapBuffer;
	PFLT_INSTANCE Instance;
	PFLT_RELATED_OBJECTS FltObjects;
	ULONG FileHeaderLength;
	LARGE_INTEGER ByteOffset;
	UCHAR FileHeader[ENCRYPT_HEAD_LENGTH];
}DEF_IO_CONTEXT, *PDEF_IO_CONTEXT;

#define MIN_SECTOR_SIZE 0x200

typedef struct _tagNTFSFCB
{
	UCHAR sz[64];
	PERESOURCE Resource;
	PERESOURCE PageioResource;
}NTFS_FCB, *PNTFS_FCB;

typedef struct tagDISKFILEOBJECT
{
	LIST_ENTRY		list;					//

	LIST_ENTRY		UserFileObjList;		// USERFILEOBJECT 的链表 usermode 传递过来的文件对象，可以有多个打开的usermode的文件对象
	ERESOURCE		UserObjectResource;
	LONG			nReferenceCount;		//跟踪磁盘文件打开的被引用的次数
	PFILE_OBJECT	pDiskFileObjectWriteThrough;		//对应于usermode 在磁盘上打开的 实际的文件对象
	HANDLE			hFileWriteThrough;				//打开的磁盘上的文件的句柄：主要是内核中使用ntcreatefile NTReadFile 时候使用的
	PDEVICE_OBJECT	pOurSpyDevice;
	PVOID			pFCB;

	BOOLEAN			bFileNOTEncypted; //文件已经存在 ，并且是明文形式
	BOOLEAN			bAllHandleClosed;
	BOOLEAN			bNeedBackUp;
	UNICODE_STRING	FullFilePath;			//打开的 文件对应的全路径
	UNICODE_STRING	FileNameOnDisk;
	//////////////////////////////////////////////////////////////////////////
	HANDLE			hBackUpFileHandle;
	PFILE_OBJECT	hBackUpFileObject;
	BOOLEAN			bProcessOpened;
	BOOLEAN			bUnderSecurFolder;
	BOOLEAN			bFileTypeNeedEncrypt;
	BOOLEAN			bOpeningAfterAllGothroughCleanup;
	PVOID			pVirtualDiskFile;
	PERESOURCE		pParentDirResource;
}DISKFILEOBJECT, *PDISKFILEOBJECT;

typedef struct tagDISKDIROBEJECT
{
	LIST_ENTRY		list;
	PVOID			pParent;
	ERESOURCE*		AccssLocker;
	UNICODE_STRING	DirName;

	PDEVICE_OBJECT	pOurSpyDevice;
	PVOID			pDCB; //ppfpfcb for directory
	BOOLEAN			bInMemory;// means this is a real directory					
	UNICODE_STRING  FullFilePath;

	LIST_ENTRY		ChildVirtualDirLists;//子目录

	LIST_ENTRY		VirtualDiskFileLists;//子文件
	BOOLEAN			bRoot;
}DISKDIROBEJECT, *PDISKDIROBEJECT;

typedef struct tagSTREAM_FILE_INFO
{
	PFILE_OBJECT StreamObject;
	PERESOURCE pFO_Resource;
	HANDLE hStreamHandle;
	FAST_MUTEX FileObjectMutex;
}STREAM_FILE_INFO;

typedef struct tagDEF_CCB
{
	ULONG ProcType;
	ULONG FileAccess;
	ULONG CcbState;
	STREAM_FILE_INFO StreamFileInfo;
	UCHAR TypeOfOpen;
}DEF_CCB, *PDEF_CCB;

typedef struct tagDEFFCB
{
	FSRTL_ADVANCED_FCB_HEADER	Header;
	// added for aglined to NTFS;
	PERESOURCE					Resource;// this will be treated as pageio resource
	UCHAR						szAlinged[4];
	LIST_ENTRY					FcbLinks;
	PNTFS_FCB					NtfsFcb;//ntfs
	PVOID						Vcb;
	ULONG						FcbState;
	ULONG						NonCachedUnCleanupCount;
	ULONG						UncleanCount;
	ULONG						OpenCount;
	SHARE_ACCESS				ShareAccess;//+0x068
	PVOID						LazyWriteThread[2];
	FAST_MUTEX					AdvancedFcbHeaderMutex;
	//
	//  The following field is used by the oplock module
	//  to maintain current oplock information.
	//
	OPLOCK		Oplock;
	PFILE_LOCK	FileLock;
	ULONG		CCBFlags;

	UCHAR		Flags;

	LONGLONG	CreationTime;                                          //  offset = 0x000
	LONGLONG	LastModificationTime;                                  //  offset = 0x008
	//
	//  Last time any attribute was modified.
	//
	LONGLONG		LastChangeTime;                                        //  offset = 0x010
	//
	//  Last time the file was accessed.  This field may not always
	//  be updated (write-protected media), and even when it is
	//  updated, it may only be updated if the time would change by
	//  a certain delta.  It is meant to tell someone approximately
	//  when the file was last accessed, for purposes of possible
	//  file migration.
	//
	LONGLONG		LastAccessTime;                                        //  offset = 0x018
	ULONG			Attribute;
	ULONG			LinkCount;
	LONGLONG		CurrentLastAccess;
	BOOLEAN			DeletePending;
	BOOLEAN			Directory;

	BOOLEAN			bModifiedByOther; //当这个cleanup里面把 UncleanCount 减为零的时候，就说明所有的Process 全部把自己的close 关闭了
	//如果没有立即收到Close 的irp话，那么就是说明系统有这个Fileobject的reference。
	//当可信的进程打开的时候很显然肯定要increament 这个UncleanCount 的值 ，同时把这个条件 设为FALSE
	//当非可信的进程有要求写的时候，判断是不是为TRUE，如果是那么ok 让它打开，
	//当非可惜进程要求写的时候，判断为false，那么返回 说明这个文件正在编辑，以只读方式打开？？？
	PFAST_MUTEX		Other_Mutex;
	BOOLEAN			bWriteHead;
	BOOLEAN			bAddHeaderLength;
	WCHAR			wszFile[MAX_PATH];
	UCHAR			szFileHead[ENCRYPT_HEAD_LENGTH];
	UCHAR			szOrgFileHead[ENCRYPT_HEAD_LENGTH];

	PRKEVENT		OutstandingAsyncEvent;
	ULONG			OutstandingAsyncWrites;

	SECTION_OBJECT_POINTERS SectionObjectPointers;
	ULONG CacheType;
	PFILE_OBJECT DestCacheObject;
	LARGE_INTEGER ValidDataToDisk;
	BOOLEAN bEnFile;
	ULONG FileHeaderLength;
	ULONG FileAcessType;
	HANDLE CcFileHandle;
	PVOID CcFileObject;
	PVOID Ccb;
	PKEVENT MoveFileEvent;
	FILE_OPEN_INFO FileAllOpenInfo[SUPPORT_OPEN_COUNT_MAX];//用链表存储更好，不用限制次数
	ULONG FileAllOpenCount;
	FILE_OBJECTID_INFORMATION FileObjectIdInfo;
}DEFFCB, *PDEFFCB;

//////////////////////////////////////////////////////////////////////////
//下面的数据结构 记录了每个进程的那些的类型的文件需要加密的（读和写）
//////////////////////////////////////////////////////////////////////////
#define FILETYPELEN 50
typedef struct _tagFILETYPE
{
	LIST_ENTRY	list;

	WCHAR 		FileExt[50];// 文件类型，也就是文件的后缀
	BOOLEAN		bBackUp;
	BOOLEAN		bSelected;
}FILETYPE, *PFILETYPE;

////////////////////////////////////////////////////////////////////////////
// 下面这个结构也写在磁盘上，初始化的时候要从磁盘文件读进来
//1：初始化的时候要从磁盘文件读进来
//2：程序在用户设置以后，会立即更新磁盘上的数据
//	(1):用户添加一个进程
//	(2):用户删除一个进程
//	(3):用户对一个进程删除一个或多个文件类型
//	(4):用户对一个进程添加一个或多个文件类型
//////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
//访问这个数据结构的时候是同步的 ，所以没有必要使用同步方式的数据
//////////////////////////////////////////////////////////////////////////
#define PROCESSHASHVALULENGTH  512
typedef struct _tagPROCESSINFO
{
	LIST_ENTRY		list;

	HANDLE			hProcess;			//每个当前在运行的进程的ID,每个进程在创建的时候 
	LIST_ENTRY		hProcessList;
	FAST_MUTEX      HandleMutex;
	//我们要把这个进程的句柄放到这个内存数据段中，这个值是不保存到磁盘上的

	UNICODE_STRING	ProcessName;		// ！！！！为了方便，现在只检测进程的名字来判断它访问的文件类型是不是加密的

	UCHAR			ProcessHashValue[PROCESSHASHVALULENGTH];	//每个进程的hash 值 用来判断是不是伪造的进程。！！！！
	//产品中应该使用进程的Image的一部分的hash值来判断
	BOOLEAN			bAllowInherent;

	FAST_MUTEX      FileTypesMutex;
	LIST_ENTRY		FileTypes;			//此进程所访问或者创建的需要加密的文件类型
	LIST_ENTRY		FileTypesForBrowser[5];
	LONG			nRef;
	BOOLEAN			bNeedBackUp;
	BOOLEAN			bEnableEncrypt;
	BOOLEAN			bForceEncryption;
	BOOLEAN			bAlone;
	BOOLEAN			bBowser;
	BOOLEAN			bAllCreateExeFile;
	ULONG			nEncryptTypes;
}PROCESSINFO, *PPROCESSINFO;

typedef struct tagCREATE_INFO
{
	UCHAR FileHeader[ENCRYPT_HEAD_LENGTH];
	UCHAR OrgFileHeader[ENCRYPT_HEAD_LENGTH];
	UNICODE_STRING strName;
	HANDLE hStreamHanle;
	PFILE_OBJECT pStreamObject;
	BOOLEAN bNetWork;
	ULONG_PTR Information;

	//file base info
	FILE_BASIC_INFORMATION BaseInfo;

	//standard info
	ULONG NumberOfLinks;
	BOOLEAN DeletePending;
	LARGE_INTEGER FileAllocationSize;
	LARGE_INTEGER FileSize;
	LARGE_INTEGER RealSize;
	BOOLEAN bRealSize;
	BOOLEAN Directory;

	ULONG uProcType;

	ULONG FileAccess;
	BOOLEAN bDeleteOnClose;

	PDEFFCB pFcb;
	PDEF_CCB pCcb;

	BOOLEAN bReissueIo;
	BOOLEAN bOplockPostIrp;
	PERESOURCE pFO_Resource;
	PFLT_FILE_NAME_INFORMATION nameInfo;
	BOOLEAN bWriteHeader;
	BOOLEAN bEnFile;
	BOOLEAN bDecrementHeader;
}CREATE_INFO, *PCREATE_INFO;


typedef struct tagIRP_CONTEXT
{

	//
	//  Type and size of this record (must be NTFS_NTC_IRP_CONTEXT)
	//
	//  Assumption here is that this structure is allocated from pool so
	//  base of structure is on an odd 64-bit boundary.
	//

	NODE_TYPE_CODE NodeTypeCode;
	NODE_BYTE_SIZE NodeByteSize;

	//
	//  Irp Context flags
	//

	ULONG Flags;

	//
	//  The following field contains the NTSTATUS value used when we are
	//  unwinding due to an exception.  We will temporarily store the Ccb
	//  for a delayed or deferred close here while the request is queued.
	//

	NTSTATUS ExceptionStatus;

	//
	//  Major and minor function codes copied from the Irp
	//

	UCHAR MajorFunction;
	UCHAR MinorFunction;
	PIO_WORKITEM	WorkItem;

	PFLT_CALLBACK_DATA OriginatingData;
	ULONG_PTR ProcessId;

	//
	//  Originating Device (required for workque algorithms)
	//
	FLT_RELATED_OBJECTS FltObjects;
	PFILE_OBJECT   Fileobject;

	CREATE_INFO createInfo;
	ULONG ulSectorSize;
	ULONG uSectorsPerAllocationUnit;

	FLT_PREOP_CALLBACK_STATUS FltStatus;
	PFILE_OBJECT FileObject;

	PMDL AllocateMdl;
	PDEF_IO_CONTEXT pIoContext;
}DEF_IRP_CONTEXT, *PDEF_IRP_CONTEXT;


typedef enum tagPROCETYPE
{
	PROCESS_ACCESS_ALLOW,
	PROCESS_ACCESS_DISABLE
}PROCETYPE;

#define NTFS_NTC_DATA_HEADER             ((NODE_TYPE_CODE)0x0700)
#define NTFS_NTC_VCB                     ((NODE_TYPE_CODE)0x0701)
#define NTFS_NTC_FCB                     ((NODE_TYPE_CODE)0x0702)
#define NTFS_NTC_IRP_CONTEXT             ((NODE_TYPE_CODE)0x070A)

#define MY_NTC_VCB 0x0100
#define MY_NTC_FCB 0x0101

typedef FLT_PREOP_CALLBACK_STATUS
(*fltCheckOplockEx)(
_In_ POPLOCK Oplock,
_In_ PFLT_CALLBACK_DATA CallbackData,
_In_ ULONG Flags,
_In_opt_ PVOID Context,
_In_opt_ PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
_In_opt_ PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
);

typedef FLT_PREOP_CALLBACK_STATUS
(*fltOplockBreakH)(
_In_ POPLOCK Oplock,
_In_ PFLT_CALLBACK_DATA CallbackData,
_In_ ULONG Flags,
_In_opt_ PVOID Context,
_In_opt_ PFLTOPLOCK_WAIT_COMPLETE_ROUTINE WaitCompletionRoutine,
_In_opt_ PFLTOPLOCK_PREPOST_CALLBACKDATA_ROUTINE PrePostCallbackDataRoutine
);

typedef ULONG
(*fMmDoesFileHaveUserWritableReferences)(
_In_ PSECTION_OBJECT_POINTERS SectionPointer
);

typedef NTSTATUS
(*fsRtlChangeBackingFileObject)(
_In_opt_ PFILE_OBJECT CurrentFileObject,
_In_ PFILE_OBJECT NewFileObject,
_In_ FSRTL_CHANGE_BACKING_TYPE ChangeBackingType,
_In_ ULONG Flags                //reserved, must be zero
);

typedef
NTSTATUS
(*fsGetVersion) (
__inout PRTL_OSVERSIONINFOW VersionInformation
);

typedef NTSTATUS
(*fltQueryDirectoryFile)(
__in PFLT_INSTANCE Instance,
__in PFILE_OBJECT FileObject,
__out_bcount(Length) PVOID FileInformation,
__in ULONG Length,
__in FILE_INFORMATION_CLASS FileInformationClass,
__in BOOLEAN ReturnSingleEntry,
__in_opt PUNICODE_STRING FileName,
__in BOOLEAN RestartScan,
__out_opt PULONG LengthReturned
);

typedef struct tagDYNAMIC_FUNCTION_POINTERS
{
	fltCheckOplockEx CheckOplockEx;
	fltOplockBreakH OplockBreakH;
	fMmDoesFileHaveUserWritableReferences pMmDoesFileHaveUserWritableReferences;
	fsRtlChangeBackingFileObject pFsRtlChangeBackingFileObject;
	fsGetVersion pGetVersion;
	fltQueryDirectoryFile  QueryDirectoryFile;
}DYNAMIC_FUNCTION_POINTERS;

#define NAMED_PIPE_PREFIX                "\\\\.\\Pipe"
#define NAMED_PIPE_PREFIX_LENGTH         (sizeof(NAMED_PIPE_PREFIX)-1)

#define MAIL_SLOT_PREFIX                "\\\\.\\MailSlot"
#define MAIL_SLOT_PREFIX_LENGTH         (sizeof(MAIL_SLOT_PREFIX)-1)

#define LAYER_NTC_FCB -32768
#define CCB_FLAG_NETWORK_FILE 0x0010
#define CCB_FLAG_FILE_CHANGED 0x0020

#ifndef OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY //win7及以后的系统才支持
#define OPLOCK_FLAG_OPLOCK_KEY_CHECK_ONLY   0x00000002
#endif

#define try_return(S) { S; goto try_exit; }
#define try_leave(S) { S; __leave; }

#define FsReleaseFcb(IRPCONTEXT,Fcb) {                 \
	ExReleaseResourceLite((Fcb)->Header.Resource);    \
}

#endif