#ifndef FSCOMMUNICATION_H
#define FSCOMMUNICATION_H

#include <fltKernel.h>
#include "defaultStruct.h"

#ifdef __cplusplus
extern "C" {
#endif

	BOOLEAN InitCommunication(__in PFLT_FILTER FltFilter);
	VOID UnInitCommunication();

	NTSTATUS FLTAPI ConnectNotify(
		__in PFLT_PORT ClientPort,
		__in_opt PVOID ServerPortCookie,
		__in_bcount_opt(SizeOfContext) PVOID ConnectionContext,
		__in ULONG SizeOfContext,
		__deref_out_opt PVOID *ConnectionPortCookie
		);

	VOID FLTAPI DisConnectNotify(
		__in_opt PVOID ConnectionCookie
		);

	NTSTATUS FLTAPI MessageNotify(
		__in_opt PVOID PortCookie,
		__in_bcount_opt(InputBufferLength) PVOID InputBuffer,
		__in ULONG InputBufferLength,
		__out_bcount_part_opt(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
		__in ULONG OutputBufferLength,
		__out PULONG ReturnOutputBufferLength
		);

#ifdef __cplusplus
}
#endif

#endif