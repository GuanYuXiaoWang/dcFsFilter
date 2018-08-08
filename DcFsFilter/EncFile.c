
#include "EncFile.h"
#include "EncFlagData.h"
#include "Crypto.h"
#include "Head.h"
#include <wdm.h>
#include <ntifs.h>

NPAGED_LOOKASIDE_LIST	g_Npaged4KBList;
NPAGED_LOOKASIDE_LIST	g_Npaged64KBList;

BOOLEAN WriteEncFlag(__in PCFLT_RELATED_OBJECTS FltObjects, PVOID pBuf)
{
	FLT_IO_OPERATION_FLAGS flag = FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET;
	ULONG bytes;

	NTSTATUS status;
	LARGE_INTEGER WriteOffset;


	// ��������Լ�����α�ʶ
	WriteOffset.LowPart = 0;
	WriteOffset.HighPart = 0;
	status = FltWriteFile(
		FltObjects->Instance,
		FltObjects->FileObject,
		&WriteOffset,
		ENCRYPT_HEAD_LENGTH,
		pBuf,
		flag,
		&bytes, 0, 0);

	if (!NT_SUCCESS(status))
		return FALSE;
	return TRUE;
}

BOOLEAN EncFile(__in PCFLT_RELATED_OBJECTS FltObjects, __inout char *lpHead)
{
	PFSRTL_COMMON_FCB_HEADER pFcb;

	NTSTATUS status;
	void *pBuf = NULL;
	void *p4KBuf = NULL;
	int nRestBytes;	// ������64Kʣ���ֽ���
	int nEncCount;	// ���ܴ���
	int nWriteBytes;// ׼��д����ֽ���
	LARGE_INTEGER ReadOffset;
	LARGE_INTEGER WriteOffset;
	LARGE_INTEGER fileSize;
	LARGE_INTEGER tmp;


	BOOLEAN bRet = FALSE;
	BOOLEAN bHasRestBytes = FALSE; // ��ʶ�Ƿ���ʣ���ֽ�δ������
	BOOLEAN bNoNeedSetFileLen = FALSE;

	if (0 == GetDogId())
	{
		bRet = FALSE;
		goto LOOP_RET;
	}
	pFcb = (PFSRTL_COMMON_FCB_HEADER)FltObjects->FileObject->FsContext;
	pBuf = NULL;
	fileSize.LowPart = pFcb->FileSize.LowPart;
	fileSize.HighPart = pFcb->FileSize.HighPart;

	p4KBuf = ExAllocateFromNPagedLookasideList(&g_Npaged4KBList);// 4K����
	if (!p4KBuf)
	{
		bRet = FALSE;
		goto LOOP_RET;
	}
	RtlZeroMemory(p4KBuf, SIZEOF_4KBList);

	CreateFileHead((UCHAR *)p4KBuf);
	RtlCopyMemory(lpHead, p4KBuf, ENCRYPT_HEAD_LENGTH);

	// ���ļ�����ֱ��д���ܱ�ʶ����
	if (RtlLargeIntegerEqualToZero(fileSize))
	{
		//fileSize.QuadPart = 0;
		bNoNeedSetFileLen = TRUE;
		goto WRITE_ENCFLAG;
	}

	pBuf = ExAllocateFromNPagedLookasideList(&g_Npaged64KBList);// 64K����
	if (!pBuf)
	{
		bRet = FALSE;
		goto LOOP_RET;
	}
	RtlZeroMemory(pBuf, SIZEOF_64KBList);


	// ��������ʣ���ֽ���
	tmp.QuadPart = fileSize.QuadPart % SIZEOF_64KBList;
	nRestBytes = tmp.LowPart;

	// ������Ҫ���ܵĴ���
	tmp.QuadPart = fileSize.QuadPart / SIZEOF_64KBList;
	nEncCount = tmp.LowPart;

	if (nRestBytes != 0)
	{
		bHasRestBytes = TRUE;
		nEncCount += 1;
	}


	ReadOffset = fileSize;

	while (nEncCount > 0)
	{
		if (bHasRestBytes)
		{
			bHasRestBytes = FALSE;
			ReadOffset.QuadPart -= nRestBytes;
			nWriteBytes = nRestBytes;
		}
		else
		{
			ASSERT(ReadOffset.QuadPart % SIZEOF_64KBList == 0);

			ReadOffset.QuadPart -= SIZEOF_64KBList;
			nWriteBytes = SIZEOF_64KBList;
		}


		status = FltReadFile(
			FltObjects->Instance,
			FltObjects->FileObject,
			&ReadOffset,
			nWriteBytes,
			pBuf,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			NULL, NULL, NULL);
		if (!NT_SUCCESS(status))
			goto LOOP_RET;

		EncBuf(pBuf, nWriteBytes, (const UCHAR *)p4KBuf);

		DbgPrint("[%s] [Lind] [%d] [Pid] [%d] [Tid] [%d] %wZ \n", __FUNCTION__, __LINE__, PsGetCurrentProcessId(), PsGetCurrentThreadId(), &FltObjects->FileObject->FileName);

		WriteOffset.QuadPart = ReadOffset.QuadPart + ENCRYPT_HEAD_LENGTH;
		status = FltWriteFile(
			FltObjects->Instance,
			FltObjects->FileObject,
			&WriteOffset,
			nWriteBytes,
			pBuf,
			FLTFL_IO_OPERATION_NON_CACHED | FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
			0, 0, 0);

		if (!NT_SUCCESS(status))
			goto LOOP_RET;
		RtlZeroMemory(pBuf, SIZEOF_64KBList);
		--nEncCount;
	}

WRITE_ENCFLAG:
	EncryptFileHead((UCHAR *)p4KBuf);
	if (WriteEncFlag(FltObjects, p4KBuf))
	{
		if (!bNoNeedSetFileLen)
		{
			// �����ļ�����
			fileSize.QuadPart += ENCRYPT_HEAD_LENGTH;
			FltSetInformationFile(
				FltObjects->Instance,
				FltObjects->FileObject,
				&fileSize, sizeof(fileSize),
				FileEndOfFileInformation);
		}
		bRet = TRUE;
	}

LOOP_RET:
	if (pBuf)
		ExFreeToNPagedLookasideList(&g_Npaged64KBList, pBuf);

	if (p4KBuf)
	{
		ExFreeToNPagedLookasideList(&g_Npaged4KBList, p4KBuf);
	}
	return bRet;
}

