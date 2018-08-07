
#include "Crypto.h"
#include "Head.h"

VOID EncBuf(
	__inout PVOID pBufToEnc,
	__in ULONG nBytes,
	__in const UCHAR* pHead
	)
{
#if USE_STRONG_CRYPTO
	const int nEncFlagT = 0x5201223;

	AesEnc(pBufToEnc, nBytes, nEncFlagT);

#else
	UCHAR *p = (UCHAR *)pBufToEnc;
	UCHAR* lpInfo = (UCHAR*)pHead + SMALL_FILE_FLAG_LEN + KEY_LEN;
	ULONG i;
	for (i = 0; i < nBytes; i++)
	{
		p[i] = lpInfo[p[i]];
	}
#endif

}

VOID DecBuf(
	__inout PVOID pBufToDec,
	__in ULONG nBytes,
	__in const UCHAR *pHead
	)
{
#if USE_STRONG_CRYPTO
	const int nEncFlagT = 0x5201223;
	AesDec(pBufToDec, nBytes, nEncFlagT);

#else
	UCHAR* lpInfo = (UCHAR*)pHead + SMALL_FILE_FLAG_LEN + KEY_LEN;
	UCHAR btDeCrypt[ENCODE_LEN];
	UCHAR *p;
	ULONG i;
	for (i = 0; i < ENCODE_LEN; i++)
	{
		btDeCrypt[lpInfo[i]] = (UCHAR)i;
	}
	p = (UCHAR *)pBufToDec;
	for (i = 0; i < nBytes; i++)
	{
		p[i] = btDeCrypt[p[i]];
	}
#endif

}
