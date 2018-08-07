
#ifndef CRYPTO_H
#define CRYPTO_H

#include <fltKernel.h>

#define CRYPTO_TAG 'TPRC' // CRPT

// �˺�����Ƿ�ʹ�ø�ǿ�ȼ����㷨��0��ʹ��+1��-1���ӽ����Է�����Է�������0��ʹ�ø�ǿ�ȼӽ���
#define USE_STRONG_CRYPTO 0

#ifdef __cplusplus
extern "C" {
#endif

	VOID EncBuf(
		__inout PVOID pBufToEnc,
		__in ULONG nBytes,
		__in const UCHAR* pHead
		);

	VOID DecBuf(
		__inout PVOID pBufToDec,
		__in ULONG nBytes,
		__in const UCHAR* pHead
		);

#ifdef __cplusplus
}
#endif

#endif
