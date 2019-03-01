#include "threadMgr.h"
#include "regMgr.h"
#include "EncFile.h"

LIST_ENTRY	ms_ListHead;
ERESOURCE	ms_Lock;
BOOLEAN		ms_bSetThreadNotifyRoutine;
ULONG		ms_ulControlSysNameCount = 0;
PDRIVER_OBJECT ms_pDriverObject = NULL;

ULONG_PTR	ms_ulETHREADStartAddressOffset = 0;
ULONG_PTR	ms_ulEPROCESSThreadListHeadOffset = 0;
ULONG_PTR	ms_ulETHREADThreadListEntryOffset = 0;
BOOLEAN		ms_bUnloaded = FALSE;
BOOLEAN		ms_bSetThreadNotifyRoutine = FALSE;
ULONG_PTR	ms_NtClose = 0;
ULONG_PTR	ms_ulNtCloseSize = 0;
ULONG_PTR	ms_ObpCloseHandle = 0;
ULONG_PTR	ms_ulObpCloseHandleSize = 0;
CHAR		ms_chCharacteristicValue[CHARACTERISTIC_VALUE_COUNT][CHARACTERISTIC_VALUE_SIZE] = {
	TMXPFLT_THREAD
};
static
VOID
ThreadNotifyRoutine(
__in HANDLE		hPid,
__in HANDLE		hTid,
__in BOOLEAN	bCreate
);

BOOLEAN InitThreadMgr(PDRIVER_OBJECT DeviceObject)
{
#ifdef REAL_ENCRYPTE
//	return TRUE;
#endif
	BOOLEAN		bRet = FALSE;
	NTSTATUS	ntStatus = STATUS_UNSUCCESSFUL;
	ms_pDriverObject = DeviceObject;
	__try
	{
		InitializeListHead(&ms_ListHead);
		ExInitializeResourceLite(&ms_Lock);

		if (!InitOffset())
			KdPrint(("InitOffset failed"));

		ntStatus = PsSetCreateThreadNotifyRoutine(ThreadNotifyRoutine);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("PsSetCreateThreadNotifyRoutine failed. (0x%x)", ntStatus));
			__leave;
		}

		ms_bSetThreadNotifyRoutine = TRUE;

		if (!Enum())
			KdPrint(("Enum failed",ntStatus));
	
		bRet = TRUE;
	}
	__finally
	{
		if (!bRet)
		{
			if (!UnInitThreadMgr())
				KdPrint(("Unload failed"));
		}
	}

	return bRet;
}

BOOLEAN UnInitThreadMgr()
{
#ifdef REAL_ENCRYPTE
//	return TRUE;
#endif
	BOOLEAN		bRet = FALSE;
	NTSTATUS	ntStatus = STATUS_UNSUCCESSFUL;

	if (ms_bUnloaded)
		return TRUE;

	__try
	{
		GetLock();

		if (ms_bSetThreadNotifyRoutine)
		{
			ntStatus = PsRemoveCreateThreadNotifyRoutine(ThreadNotifyRoutine);
			if (!NT_SUCCESS(ntStatus))
				KdPrint(("PsRemoveCreateThreadNotifyRoutine failed. (0x%x)", ntStatus));
		}

		Clear();

		bRet = TRUE;
	}
	__finally
	{
		FreeLock();

		ms_ulControlSysNameCount = 0;

		ExDeleteResourceLite(&ms_Lock);
		RtlZeroMemory(&ms_Lock, sizeof(ms_Lock));

		ms_bUnloaded = TRUE;
	}

	return bRet;
}


static VOID ThreadNotifyRoutine(
__in HANDLE		hPid,
__in HANDLE		hTid,
__in BOOLEAN	bCreate
)
{
	__try
	{
		if ((HANDLE)4 != hPid)
			__leave;

		if (bCreate)
		{
			if (!IsInControlSysNameList((ULONG)hTid, NULL))
				__leave;

			if (!Insert((ULONG)hTid))
			{
				__leave;
			}
		}
		else
			Delete((ULONG)hTid);
	}
	__finally
	{
		;
	}
}

BOOLEAN InitOffset()
{
	BOOLEAN					bRet = FALSE;

	PRTL_OSVERSIONINFOEXW	pVersionInfo = NULL;
	NTSTATUS				ntStatus = STATUS_UNSUCCESSFUL;
	ULONG					ulRelativeOffsetWithNtClose = 0;
	ULONG					ulRelativeOffsetToObpCloseHandle = 0;
	CHAR					chRelativeOffsetToObpCloseHandle[4] = { 0 };


	__try
	{
		pVersionInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(RTL_OSVERSIONINFOEXW), PROC_TBL_TAG);
		pVersionInfo->dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
		ntStatus = RtlGetVersion((PRTL_OSVERSIONINFOW)pVersionInfo);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("RtlGetVersion failed (0x%x)", ntStatus));
			__leave;
		}

		ms_NtClose = (ULONG_PTR)NtClose;

		switch (pVersionInfo->dwMajorVersion)
		{
		case 5:
		{
				  switch (pVersionInfo->dwMinorVersion)
				  {
				  case 0:
				  {
							break;
				  }
				  case 1:
				  {
							KdPrint(("Windows XP"));

							// ok
							ms_ulEPROCESSThreadListHeadOffset = 0x190;

							ms_ulETHREADStartAddressOffset = 0x224;
							ms_ulETHREADThreadListEntryOffset = 0x22C;

							switch (pVersionInfo->wServicePackMajor)
							{
							case 0:
							{
									  ms_ulNtCloseSize = 0x57;
									  ms_ulObpCloseHandleSize = 0x81;

									  ulRelativeOffsetWithNtClose = 0x14;

									  chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
									  chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
									  chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
									  chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

									  RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

									  if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
									  {
										  ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
										  ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
									  }
									  else
										  ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;

									  break;
							}
							case 1:
								break;
							case 2:
							case 3:
							{
									  ms_ulNtCloseSize = 0x26;
									  ms_ulObpCloseHandleSize = 0x186;

									  ulRelativeOffsetWithNtClose = 0x18;

									  chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
									  chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
									  chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
									  chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

									  RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

									  if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
									  {
										  ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
										  ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
									  }
									  else
										  ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;

									  break;
							}
							default:
								break;
							}

							break;
				  }
				  case 2:
				  {
							if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
							{
								KdPrint(("Windows XP Professional x64 Edition"));

								if (1 == pVersionInfo->wServicePackMajor)
								{
									// ok
									ms_ulEPROCESSThreadListHeadOffset = 0x290;

									ms_ulETHREADStartAddressOffset = 0x3D8;
									ms_ulETHREADThreadListEntryOffset = 0x3E8;

									ms_ulNtCloseSize = 0x40;
									ms_ulObpCloseHandleSize = 0xe0;

									ulRelativeOffsetWithNtClose = 0x10;

									chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
									chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
									chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
									chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

									RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

									if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
									{
										ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
										ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
									}
									else
										ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;
								}
								else if (2 == pVersionInfo->wServicePackMajor)
								{
									// ok
									ms_ulEPROCESSThreadListHeadOffset = 0x290;

									ms_ulETHREADStartAddressOffset = 0x3C0;
									ms_ulETHREADThreadListEntryOffset = 0x3D0;

									ms_ulNtCloseSize = 0x20;
									ms_ulObpCloseHandleSize = 0x1f0;
									ulRelativeOffsetWithNtClose = 0x10;

									chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
									chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
									chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
									chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

									RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

									if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
									{
										ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
										ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
									}
									else
										ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;
								}
							}
							else if (VER_SUITE_WH_SERVER == pVersionInfo->wSuiteMask)
								KdPrint(("Windows Server 2003"));
							else
								KdPrint(("Windows Home Server"));

							break;
				  }
				  default:
					  break;
				  }

				  break;
		}
		case 6:
		{
				  switch (pVersionInfo->dwMinorVersion)
				  {
				  case 0:
				  {
							if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
								KdPrint(("Windows Vista"));
							else
								KdPrint(("Windows Server 2008"));

							break;
				  }
				  case 1:
				  {
							if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
							{
								KdPrint(("Windows 7"));
#ifdef _X86_
								// ok
								ms_ulEPROCESSThreadListHeadOffset = 0x188;

								ms_ulETHREADStartAddressOffset = 0x218;
								ms_ulETHREADThreadListEntryOffset = 0x268;

								ms_ulNtCloseSize = 0x58;
								ms_ulObpCloseHandleSize = 0x138;

								ulRelativeOffsetWithNtClose = 0x49;

								chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
								chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
								chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
								chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

								RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

								if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
								{
									ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
									ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
								}
								else
									ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;
#else
								// ok
								ms_ulEPROCESSThreadListHeadOffset = 0x308;

								ms_ulETHREADStartAddressOffset = 0x388;
								ms_ulETHREADThreadListEntryOffset = 0x420;

								if (0 == pVersionInfo->wServicePackMajor)
								{
									ms_ulNtCloseSize = 0x50;
									ms_ulObpCloseHandleSize = 0xd0;

									ulRelativeOffsetWithNtClose = 0x3c;
								}
								else
								{
									ms_ulNtCloseSize = 0x80;
									ms_ulObpCloseHandleSize = 0xd0;

									ulRelativeOffsetWithNtClose = 0x38;
								}

								chRelativeOffsetToObpCloseHandle[0] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x1));
								chRelativeOffsetToObpCloseHandle[1] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x2));
								chRelativeOffsetToObpCloseHandle[2] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x3));
								chRelativeOffsetToObpCloseHandle[3] = *((CHAR *)(ms_NtClose + ulRelativeOffsetWithNtClose + 0x4));

								RtlCopyMemory(&ulRelativeOffsetToObpCloseHandle, chRelativeOffsetToObpCloseHandle, 4);

								if (0 > (LONG)ulRelativeOffsetToObpCloseHandle)
								{
									ulRelativeOffsetToObpCloseHandle = ~ulRelativeOffsetToObpCloseHandle;
									ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose - ulRelativeOffsetToObpCloseHandle + 0x4;
								}
								else
									ms_ObpCloseHandle = ms_NtClose + ulRelativeOffsetWithNtClose + ulRelativeOffsetToObpCloseHandle + 0x4;
#endif
							}
							else
								KdPrint(("Windows Server 2008 R2"));

							break;
				  }
				  case 2:
				  {
							if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
								KdPrint(("Windows 8"));
							else
								KdPrint(("Windows Server 2012"));

							break;
				  }
				  case 3:
				  {
							if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
							{
								KdPrint(("Windows 8.1"));
#ifdef _X86_
								// ok
								ms_ulEPROCESSThreadListHeadOffset = 0x194;

								ms_ulETHREADStartAddressOffset = 0x350;
								ms_ulETHREADThreadListEntryOffset = 0x39c;
#else
								// ok
								ms_ulEPROCESSThreadListHeadOffset = 0x470;

								ms_ulETHREADStartAddressOffset = 0x5f8;
								ms_ulETHREADThreadListEntryOffset = 0x688;

								if ((ULONG_PTR)IoGetIrpExtraCreateParameter == ms_NtClose + 0x4e40)
								{
									// with update
									ms_ulNtCloseSize = 0x964;
								}
								else
								{
									//  without update
									ms_ulNtCloseSize = 0xad0;
								}
#endif
							}
							else
								KdPrint(("Windows Server 2012 R2"));

							break;
				  }
				  default:
					  break;
				  }

				  break;
		}
		case 10:
		{
				   switch (pVersionInfo->dwMinorVersion)
				   {
				   case 0:
				   {
							 if (VER_NT_WORKSTATION == pVersionInfo->wProductType)
							 {
								 KdPrint(("Windows 10"));
#ifdef _X86_
								 switch (pVersionInfo->dwBuildNumber)
								 {
								 case 10240:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x194;

											   ms_ulETHREADStartAddressOffset = 0x360;
											   ms_ulETHREADThreadListEntryOffset = 0x3ac;

											   ms_ulNtCloseSize = 0x140;

											   break;
								 }
								 case 10586:
								 case 14393:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x198;

											   ms_ulETHREADStartAddressOffset = 0x360;
											   ms_ulETHREADThreadListEntryOffset = 0x3ac;

											   ms_ulNtCloseSize = 0x120;

											   break;
								 }
								 case 15063:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x1a0;

											   ms_ulETHREADStartAddressOffset = 0x368;
											   ms_ulETHREADThreadListEntryOffset = 0x3b4;

											   ms_ulNtCloseSize = 0x32;

											   break;
								 }
								 default:
									 break;
								 }
#else
								 switch (pVersionInfo->dwBuildNumber)
								 {
								 case 10240:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x480;

											   ms_ulETHREADStartAddressOffset = 0x600;
											   ms_ulETHREADThreadListEntryOffset = 0x690;

											   ms_ulNtCloseSize = 0x190;

											   break;
								 }
								 case 10586:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x488;

											   ms_ulETHREADStartAddressOffset = 0x600;
											   ms_ulETHREADThreadListEntryOffset = 0x690;

											   ms_ulNtCloseSize = 0x160;

											   break;
								 }
								 case 14393:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x488;

											   ms_ulETHREADStartAddressOffset = 0x608;
											   ms_ulETHREADThreadListEntryOffset = 0x698;

											   ms_ulNtCloseSize = 0x150;

											   break;
								 }
								 case 15063:
								 {
											   // ok
											   ms_ulEPROCESSThreadListHeadOffset = 0x488;

											   ms_ulETHREADStartAddressOffset = 0x610;
											   ms_ulETHREADThreadListEntryOffset = 0x6a0;

											   ms_ulNtCloseSize = 0x160;

											   break;
								 }
								 default:
									 break;
								 }
#endif
							 }
							 else
								 KdPrint(("Windows Server 2016"));

							 break;
				   }
				   default:
					   break;
				   }

				   break;
		}
		default:
			break;
		}

		bRet = TRUE;
	}
	__finally
	{
		ExFreePoolWithTag(pVersionInfo, PROC_TBL_TAG);
		pVersionInfo = NULL;
	}

	return bRet;
}

BOOLEAN Enum()
{
	BOOLEAN		bRet = FALSE;

	NTSTATUS	ntStatus = STATUS_UNSUCCESSFUL;
	PEPROCESS	pEprocess = NULL;
	PLIST_ENTRY	pThreadListHead = NULL;
	PLIST_ENTRY	pThreadListEntry = NULL;
	PETHREAD	pEthread = NULL;
	ULONG		ulTid = 0;


	__try
	{
		GetLock();

		if (!ms_ulEPROCESSThreadListHeadOffset || !ms_ulETHREADThreadListEntryOffset)
			__leave;

		ntStatus = PsLookupProcessByProcessId((HANDLE)4, &pEprocess);
		if (!NT_SUCCESS(ntStatus))
		{
			KdPrint(("PsLookupProcessByProcessId failed. (0x%x)", ntStatus));

			__leave;
		}

		if (!pEprocess)
		{
			KdPrint(("pEprocess error"));
			__leave;
		}

		pThreadListHead = ((PLIST_ENTRY)((ULONG_PTR)pEprocess + ms_ulEPROCESSThreadListHeadOffset));
		if (!pThreadListHead)
		{
			KdPrint(("ThreadListHead error"));
			__leave;
		}

		for (pThreadListEntry = pThreadListHead->Blink; pThreadListEntry != pThreadListHead; pThreadListEntry = pThreadListEntry->Blink)
		{
			pEthread = (PETHREAD)((ULONG_PTR)pThreadListEntry - ms_ulETHREADThreadListEntryOffset);
			if (!pEthread)
			{
				KdPrint(("pEthread error"));
				__leave;
			}

			ulTid = (ULONG)PsGetThreadId(pEthread);
			if (!ulTid)
			{
				KdPrint(("PsGetThreadId failed"));
				__leave;
			}

			if (IsInControlSysNameList(ulTid, pEthread))
			{
				if (!Insert(ulTid))
				{
					KdPrint(("Insert failed. (%d)",ulTid));
					__leave;
				}
			}
		}

		bRet = TRUE;
	}
	__finally
	{
		if (pEprocess)
		{
			ObDereferenceObject(pEprocess);
			pEprocess = NULL;
		}

		FreeLock();
	}

	return bRet;
}

VOID GetLock()
{
	KeEnterCriticalRegion();
	ExAcquireResourceExclusiveLite(&ms_Lock, TRUE);
}

VOID FreeLock()
{
	ExReleaseResourceLite(&ms_Lock);
	KeLeaveCriticalRegion();
}

BOOLEAN IsInControlSysNameList(__in ULONG ulTid, __in PETHREAD pEThread)
{
	BOOLEAN						bRet = FALSE;
	ULONG						ulIndex = 0;
	NTSTATUS					ntStatus = STATUS_UNSUCCESSFUL;
	BOOLEAN						bGetEThread = FALSE;
	PVOID						pThreadStartAddress = NULL;
	LPLDR_DATA_TABLE_ENTRY		lpEntry = NULL;
	LPLDR_DATA_TABLE_ENTRY		lpFirstEntry = NULL;
#ifndef STACK_BACK_TRACE_ENUM_DRIVER
	ULONG_PTR					pFrameAddress[62] = { 0 };
#ifdef STACK_BACK_TRACE_RTLCAPTURESTACKBACKTRACE
	ULONG						ulFramesToSkip = 0;
#endif
	ULONG						ulFramesToCapture = 0;
	ULONG						i = 0;
	ULONG						j = 0;
	ULONG						ulFrameCount = 0;
#endif


	__try
	{
		if (!pEThread)
		{
			if (!ulTid)
			{
				KdPrint(("input argument error"));
				__leave;
			}

			ntStatus = PsLookupThreadByThreadId((HANDLE)ulTid, &pEThread);
			if (!NT_SUCCESS(ntStatus))
			{
				if (STATUS_INVALID_PARAMETER != ntStatus)
					KdPrint(("PsLookupThreadByThreadId failed. (0x%x)", ntStatus));
				else
					Enum();

				__leave;
			}

			if (!pEThread)
			{
				KdPrint(("pEThread error"));
				__leave;
			}

			bGetEThread = TRUE;
		}

		if (!ms_ulETHREADStartAddressOffset)
			__leave;

		pThreadStartAddress = (PVOID)*((PULONG_PTR)((ULONG_PTR)pEThread + ms_ulETHREADStartAddressOffset));

#ifdef STACK_BACK_TRACE_ENUM_DRIVER
		lpFirstEntry = (LPLDR_DATA_TABLE_ENTRY)(ms_pDriverObject->DriverSection);
		for (lpEntry = lpFirstEntry; lpFirstEntry != (LPLDR_DATA_TABLE_ENTRY)(lpEntry->InLoadOrderLinks.Blink); lpEntry = (LPLDR_DATA_TABLE_ENTRY)(lpEntry->InLoadOrderLinks.Blink))
		{
			if ((ULONG_PTR)lpEntry->DllBase <= (ULONG_PTR)pThreadStartAddress &&
				(ULONG_PTR)pThreadStartAddress <= (ULONG_PTR)lpEntry->DllBase + lpEntry->SizeOfImage)
			{
				if (!&lpEntry->BaseDllName)
					__leave;

				KdPrint(("sys name=%S...\n", lpEntry->BaseDllName.Buffer));

				if (IsControlSys(lpEntry->BaseDllName.Buffer, lpEntry->BaseDllName.Length))
				{
					bRet = TRUE;
					__leave;
				}

				__leave;
			}
		}
#else
		ulFramesToCapture = 99;
#ifdef STACK_BACK_TRACE_RTLWALKFRAMECHAIN
		ulFrameCount = RtlWalkFrameChain((PVOID *)pFrameAddress, ulFramesToCapture, 0);
#else
#ifdef STACK_BACK_TRACE_RTLCAPTURESTACKBACKTRACE
		if (MAX_FRAME_CAPTURE_NUM < ulFramesToSkip + ulFramesToCapture)
			__leave;

		ulFrameCount = RtlCaptureStackBackTrace(
			ulFramesToSkip,
			ulFramesToCapture,
			(PVOID *)pFrameAddress,
			NULL
			);
#endif
#endif
		if (!ulFrameCount)
			__leave;

		for (; ulIndex < ulFrameCount; ulIndex++)
		{
			for (i = 0; i < CHARACTERISTIC_VALUE_COUNT; i++)
			{
				for (j = 0; j < CHARACTERISTIC_VALUE_SIZE; j++)
				{
					if (ms_chCharacteristicValue[i][j] != *((PCHAR)(pFrameAddress[ulIndex]) + j))
						break;
				}

				if (CHARACTERISTIC_VALUE_SIZE == j)
				{
					// KdPrintKrnl(LOG_PRINTF_LEVEL_INFO, LOG_RECORED_LEVEL_NEED, L"[RetAddress] 0x%p", pFrameAddress[ulIndex]);
					bRet = TRUE;
					__leave;
				}
			}
		}
#endif
	}
	__finally
	{
		if (bGetEThread && pEThread)
		{
			ObDereferenceObject(pEThread);
			pEThread = NULL;
		}
	}

	return bRet;
}

BOOLEAN Insert(__in ULONG ulTid)
{
	BOOLEAN			bResult = FALSE;

	LPTHREAD_INFO	lpThreadInfo = NULL;


	__try
	{
		GetLock();

		if (!ulTid)
		{
			__leave;
		}

		lpThreadInfo = Get(ulTid);
		if (lpThreadInfo)
		{
			bResult = TRUE;
			__leave;
		}
		lpThreadInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(THREAD_INFO), THREAD_TBL_TAG);
		lpThreadInfo->ulTid = ulTid;

		InsertTailList(&ms_ListHead, &lpThreadInfo->List);

		bResult = TRUE;
	}
	__finally
	{
		if (!bResult && lpThreadInfo)
		{
			ExFreePoolWithTag(lpThreadInfo, THREAD_TBL_TAG);
			lpThreadInfo = NULL;
		}

		FreeLock();
	}

	return bResult;
}

LPTHREAD_INFO Get(__in ULONG ulTid)
{
	LPTHREAD_INFO	lpThreadInfo = NULL;

	PLIST_ENTRY		pNode = NULL;


	__try
	{
		GetLock();

		if (IsListEmpty(&ms_ListHead))
			__leave;

		for (pNode = ms_ListHead.Flink; pNode != &ms_ListHead; pNode = pNode->Flink, lpThreadInfo = NULL)
		{
			lpThreadInfo = CONTAINING_RECORD(pNode, THREAD_INFO, List);
			if (!lpThreadInfo)
			{
				__leave;
			}

			if (ulTid == lpThreadInfo->ulTid)
				__leave;
		}
	}
	__finally
	{
		FreeLock();
	}

	return lpThreadInfo;
}

BOOLEAN Delete(__in ULONG ulTid)
{
	BOOLEAN			bRet = FALSE;

	LPTHREAD_INFO	lpThreadInfo = NULL;


	__try
	{
		GetLock();

		lpThreadInfo = Get(ulTid);
		if (!lpThreadInfo)
			__leave;

		RemoveEntryList(&lpThreadInfo->List);
		ExFreePoolWithTag(lpThreadInfo, THREAD_TBL_TAG);
		lpThreadInfo = NULL;

		bRet = TRUE;
	}
	__finally
	{
		FreeLock();
	}

	return bRet;
}


BOOLEAN Clear()
{
	BOOLEAN			bRet = FALSE;
	LPTHREAD_INFO	lpThreadInfo = NULL;

	__try
	{
		GetLock();

		while (!IsListEmpty(&ms_ListHead))
		{
			lpThreadInfo = CONTAINING_RECORD(ms_ListHead.Flink, THREAD_INFO, List);
			if (!lpThreadInfo)
			{
				__leave;
			}
	
			RemoveEntryList(&lpThreadInfo->List);
			ExFreePoolWithTag(lpThreadInfo, THREAD_TBL_TAG);
			lpThreadInfo = NULL;
		}

		bRet = TRUE;
	}
	__finally
	{
		FreeLock();
	}
	return bRet;
}

BOOLEAN IsIn(__in ULONG ulTid)
{
	if (Get(ulTid))
		return TRUE;
	else
		return FALSE;
}

