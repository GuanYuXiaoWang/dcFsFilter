#include "fsCommunication.h"
#include "fsData.h"
#include <ntifs.h>
#include <wdm.h>

#define PortName  L"\\HuatuDriverPort"

PFLT_PORT g_FltPort = NULL;

//NTKERNELAPI UCHAR * PsGetProcessImageFileName(__in PEPROCESS Process);

BOOLEAN InitCommunication(__in PFLT_FILTER FltFilter)
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PSECURITY_DESCRIPTOR Sd = NULL;
	OBJECT_ATTRIBUTES ob = { 0 };
	UNICODE_STRING ustrPort;
	RtlInitUnicodeString(&ustrPort, PortName);
	__try
	{
		Status = FltBuildDefaultSecurityDescriptor(&Sd, FLT_PORT_ALL_ACCESS);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}
		InitializeObjectAttributes(&ob, &ustrPort, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, Sd);
		Status = FltCreateCommunicationPort(FltFilter, &g_FltPort, &ob, NULL, ConnectNotify, DisConnectNotify, MessageNotify, 1);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}
		Status = STATUS_SUCCESS;
	}
	__finally
	{
		if (Sd != NULL)
		{
			FltFreeSecurityDescriptor(Sd);
		}
	}
	
	return (STATUS_SUCCESS == Status ? TRUE : FALSE);
}


NTSTATUS FLTAPI ConnectNotify(
	__in PFLT_PORT ClientPort,
	__in_opt PVOID ServerPortCookie,
	__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
	__in ULONG SizeOfContext,
	__deref_out_opt PVOID *ConnectionPortCookie
	)
{
	NTSTATUS Status = STATUS_SUCCESS;
	HANDLE ProcessID = NULL;
	PEPROCESS Process = NULL;
	PUCHAR ProcessImageName = NULL;
	
	UNREFERENCED_PARAMETER(ServerPortCookie);
	UNREFERENCED_PARAMETER(ConnectionContext);
	UNREFERENCED_PARAMETER(SizeOfContext);
	UNREFERENCED_PARAMETER(ConnectionPortCookie);
	
	__try
	{
		ProcessID = PsGetCurrentProcessId();
		if (NULL == ProcessID)
		{
			__leave;
		}
		Status = PsLookupProcessByProcessId(ProcessID, &Process);
		if (!NT_SUCCESS(Status))
		{
			__leave;
		}
// 		ProcessImageName = PsGetProcessImageFileName(Process);
// 		if (NULL == ProcessImageName)
// 		{
// 			__leave;
// 		}
		//DbgPrint("process image name = %s....\n", ProcessImageName);
	}
	__finally
	{
		if (Process != NULL)
		{
			ObDereferenceObject(Process);
		}
	}

	DbgPrint("Recv Connect Msg, process id=0x%x......\n", ProcessID);

	return Status;
}

VOID FLTAPI DisConnectNotify(__in_opt PVOID ConnectionCookie)
{

}

NTSTATUS FLTAPI MessageNotify(__in_opt PVOID PortCookie, __in_bcount_opt(InputBufferLength) PVOID InputBuffer, __in ULONG InputBufferLength, __out_bcount_part_opt(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer, __in ULONG OutputBufferLength, __out PULONG ReturnOutputBufferLength)
{
	NTSTATUS Status = STATUS_SUCCESS;


	return Status;
}

VOID UnInitCommunication()
{
	if (g_FltPort != NULL)
	{
		FltCloseCommunicationPort(g_FltPort);
	}
}
