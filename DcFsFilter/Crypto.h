
#ifndef CRYPTO_H
#define CRYPTO_H

#include <fltKernel.h>

#define CRYPTO_TAG 'TPRC' // CRPT

// 此宏控制是否使用高强度加密算法，0即使用+1和-1来加解密以方便调试分析，非0即使用高强度加解密
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
