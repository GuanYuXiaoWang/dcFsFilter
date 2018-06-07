#ifndef DEFAULTSTRUCT_H
#define DEFAULTSTRUCT_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "nodetype.h"

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

	LIST_ENTRY		UserFileObjList;		// USERFILEOBJECT ������ usermode ���ݹ������ļ����󣬿����ж���򿪵�usermode���ļ�����
	ERESOURCE		UserObjectResource;
	LONG			nReferenceCount;		//���ٴ����ļ��򿪵ı����õĴ���
	PFILE_OBJECT	pDiskFileObjectWriteThrough;		//��Ӧ��usermode �ڴ����ϴ򿪵� ʵ�ʵ��ļ�����
	HANDLE			hFileWriteThrough;				//�򿪵Ĵ����ϵ��ļ��ľ������Ҫ���ں���ʹ��ntcreatefile NTReadFile ʱ��ʹ�õ�
	PDEVICE_OBJECT	pOurSpyDevice;
	PVOID			pFCB;

	BOOLEAN			bFileNOTEncypted; //�ļ��Ѿ����� ��������������ʽ
	BOOLEAN			bAllHandleClosed;
	BOOLEAN			bNeedBackUp;
	UNICODE_STRING	FullFilePath;			//�򿪵� �ļ���Ӧ��ȫ·��
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

	LIST_ENTRY		ChildVirtualDirLists;//��Ŀ¼

	LIST_ENTRY		VirtualDiskFileLists;//���ļ�
	BOOLEAN			bRoot;
}DISKDIROBEJECT, *PDISKDIROBEJECT;


typedef struct tagDEFFCB
{
	FSRTL_COMMON_FCB_HEADER	Header;
	// added for aglined to NTFS;
	PERESOURCE					Resource;// this will be treated as pageio resource
	UCHAR						szAlinged[4];
	LIST_ENTRY					FcbLinks;
	NTFS_FCB*					NtFsFCB;//+0x050 // this filed will be used by call back of ntfs.
	PVOID						Vcb;//+0x054
	ULONG						State;
	ULONG						NonCachedUnCleanupCount;
	ULONG						UncleanCount;
	ULONG						OpenCount;
	SHARE_ACCESS				ShareAccess;//+0x068
	ULONG						AttributeTypeCode_PLACE;
	UNICODE_STRING				AttributeName_PLACE;
	PFILE_OBJECT				FileObject_PLACE;
	PVOID						NoPagedFCB;
	PVOID						LazyWriteThread[2];
	SECTION_OBJECT_POINTERS		SegmentObject;
	//
	//  The following field is used by the oplock module
	//  to maintain current oplock information.
	//

	OPLOCK		Oplock;

	//
	//  The following field is used by the filelock module
	//  to maintain current byte range locking information.
	//
	// this field is protected by the fastmutex in Header.

	PLIST_ENTRY PendingEofAdvances;
	PFILE_LOCK	FileLock;
	ULONG		FcbState;
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

	BOOLEAN			bNeedEncrypt;
	union
	{
		PDISKFILEOBJECT	pDiskFileObject;// ����directory��ʱ�� �����ó�DISKDIROBEJECT
		PDISKDIROBEJECT pDiskDirObject;
	};

	BOOLEAN			bModifiedByOther; //�����cleanup����� UncleanCount ��Ϊ���ʱ�򣬾�˵�����е�Process ȫ�����Լ���close �ر���
	//���û�������յ�Close ��irp������ô����˵��ϵͳ�����Fileobject��reference��
	//�����ŵĽ��̴򿪵�ʱ�����Ȼ�϶�Ҫincreament ���UncleanCount ��ֵ ��ͬʱ��������� ��ΪFALSE
	//���ǿ��ŵĽ�����Ҫ��д��ʱ���ж��ǲ���ΪTRUE���������ôok �����򿪣�
	//���ǿ�ϧ����Ҫ��д��ʱ���ж�Ϊfalse����ô���� ˵������ļ����ڱ༭����ֻ����ʽ�򿪣�����
	PFAST_MUTEX		Other_Mutex;
	UCHAR			szAlinged1[36];
	PVOID			CreateSectionThread;	//+0x12c
	UCHAR			szAligned2[20]; //+0x130
	BOOLEAN			bWriteHead;
	WCHAR			wszFile[128];
}DEFFCB, *PDEFFCB;

//////////////////////////////////////////////////////////////////////////
//��������ݽṹ ��¼��ÿ�����̵���Щ�����͵��ļ���Ҫ���ܵģ�����д��
//////////////////////////////////////////////////////////////////////////
#define FILETYPELEN 50
typedef struct _tagFILETYPE
{
	LIST_ENTRY	list;

	WCHAR 		FileExt[50];// �ļ����ͣ�Ҳ�����ļ��ĺ�׺
	BOOLEAN		bBackUp;
	BOOLEAN		bSelected;
}FILETYPE, *PFILETYPE;

////////////////////////////////////////////////////////////////////////////
// ��������ṹҲд�ڴ����ϣ���ʼ����ʱ��Ҫ�Ӵ����ļ�������
//1����ʼ����ʱ��Ҫ�Ӵ����ļ�������
//2���������û������Ժ󣬻��������´����ϵ�����
//	(1):�û����һ������
//	(2):�û�ɾ��һ������
//	(3):�û���һ������ɾ��һ�������ļ�����
//	(4):�û���һ���������һ�������ļ�����
//////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////
//����������ݽṹ��ʱ����ͬ���� ������û�б�Ҫʹ��ͬ����ʽ������
//////////////////////////////////////////////////////////////////////////
#define PROCESSHASHVALULENGTH  512
typedef struct _tagPROCESSINFO
{
	LIST_ENTRY		list;

	HANDLE			hProcess;			//ÿ����ǰ�����еĽ��̵�ID,ÿ�������ڴ�����ʱ�� 
	LIST_ENTRY		hProcessList;
	FAST_MUTEX      HandleMutex;
	//����Ҫ��������̵ľ���ŵ�����ڴ����ݶ��У����ֵ�ǲ����浽�����ϵ�

	UNICODE_STRING	ProcessName;		// ��������Ϊ�˷��㣬����ֻ�����̵��������ж������ʵ��ļ������ǲ��Ǽ��ܵ�

	UCHAR			ProcessHashValue[PROCESSHASHVALULENGTH];	//ÿ�����̵�hash ֵ �����ж��ǲ���α��Ľ��̡���������
	//��Ʒ��Ӧ��ʹ�ý��̵�Image��һ���ֵ�hashֵ���ж�
	BOOLEAN			bAllowInherent;

	FAST_MUTEX      FileTypesMutex;
	LIST_ENTRY		FileTypes;			//�˽��������ʻ��ߴ�������Ҫ���ܵ��ļ�����
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

typedef struct tagSTREAM_FILE_INFO
{
	PFILE_OBJECT StreamObject;
	PERESOURCE pFO_Resource;
}STREAM_FILE_INFO;

typedef struct tagDEF_CCB
{
	STREAM_FILE_INFO StreamFileInfo;
}DEF_CCB, *PDEF_CCB;

typedef struct tagCREATE_INFO
{
	UNICODE_STRING strName;
	HANDLE hStreamHanle;
	PFILE_OBJECT pStreamObject;
	BOOLEAN bNetWork;
	ULONG_PTR Information;
	LARGE_INTEGER FileAllocationSize;
	LARGE_INTEGER FileSize;
	LARGE_INTEGER RealSize;
	ULONG uProcType;

	ULONG FileAccess;
	BOOLEAN bDeleteOnClose;

	PDEFFCB pFcb;
	PDEF_CCB pCcb;

	BOOLEAN bReissueIo;
	BOOLEAN bOplockPostIrp;
	PERESOURCE pFO_Resource;
	PFLT_FILE_NAME_INFORMATION nameInfo;
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
	//  This is the IrpContext for the top level request.
	//

	struct _IRP_CONTEXT *TopLevelIrpContext;

	//
	//  The following union contains pointers to the IoContext for I/O
	//  based requests and a pointer to a security context for requests
	//  which need to capture the subject context in the calling thread.
	//

	union
	{


		//  The following context block is used for non-cached Io.

		struct _NTFS_IO_CONTEXT *NtfsIoContext;

		//  The following is the captured subject context.

		PSECURITY_SUBJECT_CONTEXT SubjectContext;

		//  The following is used during create for oplock cleanup.

		struct _OPLOCK_CLEANUP *OplockCleanup;

	} Union;

	//
	//  A pointer to the originating Irp.  We will store the Scb for
	//  delayed or async closes here while the request is queued.
	//

	PIRP OriginatingIrp;

	//
	//  Major and minor function codes copied from the Irp
	//

	UCHAR MajorFunction;
	UCHAR MinorFunction;

	//
	//  The following field is used to maintain a queue of records that
	//  have been deallocated while processing this irp context.
	//

	LIST_ENTRY RecentlyDeallocatedQueue;

	//PIO_WORKITEM  
	//  This structure is used for posting to the Ex worker threads.
	//

	WORK_QUEUE_ITEM WorkQueueItem;
	PIO_WORKITEM	WorkItem;

	PFLT_CALLBACK_DATA OriginatingData;
	HANDLE ProcessId;
	DEFFCB*			FcbWithPagingExclusive;

	//
	//  Originating Device (required for workque algorithms)
	//

	PDEVICE_OBJECT RealDevice;

	PFILE_OBJECT   Fileobject;
	PDEVICE_OBJECT pNextDevice;
	PPROCESSINFO   pProcessInfo;
	HANDLE		   hProcessOrignal;

	CREATE_INFO createInfo;
	ULONG ulSectorSize;
	ULONG uSectorsPerAllocationUnit;

	FLT_PREOP_CALLBACK_STATUS FltStatus;
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

typedef struct tagDYNAMIC_FUNCTION_POINTERS
{
	fltCheckOplockEx CheckOplockEx;
	fltOplockBreakH OplockBreakH;
	fMmDoesFileHaveUserWritableReferences pMmDoesFileHaveUserWritableReferences;
	fsRtlChangeBackingFileObject pFsRtlChangeBackingFileObject;
	fsGetVersion pGetVersion;
}DYNAMIC_FUNCTION_POINTERS;

#define NAMED_PIPE_PREFIX                "\\\\.\\Pipe"
#define NAMED_PIPE_PREFIX_LENGTH         (sizeof(NAMED_PIPE_PREFIX)-1)

#define MAIL_SLOT_PREFIX                "\\\\.\\MailSlot"
#define MAIL_SLOT_PREFIX_LENGTH         (sizeof(MAIL_SLOT_PREFIX)-1)

#define LAYER_NTC_FCB 12345

#define try_return(S) { S; goto try_exit; }
#define try_leave(S) { S; __leave; }

#endif