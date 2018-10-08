
#include "Head.h"

DRV_DATA g_SafeData = {0};

void FileFlag_XOR(UCHAR *p, int Len)
{
	for (int i = 0; i < Len; i++)
	{
		p[i] ^= XOR_CODE1;
	}
}

void CryptKey(UCHAR *btKey, int nKeyLength)
{
	for (int i = 0; i < nKeyLength; i++)
	{
		btKey[i] ^= XOR_CODE2;
	}
}

void ChangeEncodeByKey(UCHAR *btEncode, const UCHAR *btKey, int nKeyLength)
{
	for (int i = 0; i < ENCODE_LEN; i++)
	{
		btEncode[i] ^= btKey[i % nKeyLength];
	}
}

void CreateEncode(UCHAR btEncode[ENCODE_LEN])
{
	for (int i = 0; i < ENCODE_LEN; i++)
	{
		btEncode[i] = (UCHAR)i;
	}

	ULONG ulRan = 0;

	for (int i = 0; i < 10000; i++)
	{
		int index1 = RtlRandom(&ulRan) % ENCODE_LEN;
		int index2 = RtlRandom(&ulRan) % ENCODE_LEN;
		UCHAR bt = btEncode[index1];
		btEncode[index1] = btEncode[index2];
		btEncode[index2] = bt;
	}
}

void EncryptFileHead(UCHAR *lpBuff)
{
	FileFlag_XOR(lpBuff, SMALL_FILE_FLAG_LEN);

	int POS = SMALL_FILE_FLAG_LEN;

	CryptKey(lpBuff + POS, KEY_LEN);

	POS += KEY_LEN;

	ChangeEncodeByKey(lpBuff + POS, (const UCHAR *)g_SafeData.szbtKey, (int)strlen(g_SafeData.szbtKey));
}

void CreateFileHead(UCHAR lpBuff[ENCRYPT_HEAD_LENGTH])
{
	//CryptFileHeadThree *headInfo = (CryptFileHeadThree *)lpBuff;
	memset(lpBuff, 0, ENCRYPT_HEAD_LENGTH);

	memcpy(lpBuff, "DG_FILE VER 3.0", DOCGUARDER_SMALL_HEAD_LENGTH);
	ULONG ul = ENCRYPT_TYPE_DOCGUARDER_THREE;
	memcpy(lpBuff + DOCGUARDER_SMALL_HEAD_LENGTH, &ul, sizeof(ULONG));
	ul = 0;
	memcpy(lpBuff + DOCGUARDER_SMALL_HEAD_LENGTH + sizeof(ULONG), &ul, sizeof(ULONG));

	ul = g_SafeData.SystemUser.DogID;
	memcpy(lpBuff + DOCGUARDER_SMALL_HEAD_LENGTH + 2 * sizeof(ULONG), &ul, sizeof(ULONG));

	memcpy(lpBuff + SMALL_FILE_FLAG_LEN, g_SafeData.szbtKey, strlen(g_SafeData.szbtKey));

	CreateEncode(lpBuff + SMALL_FILE_FLAG_LEN + KEY_LEN);

	ul = g_SafeData.SystemUser.dwCryptLevel;
	memcpy(lpBuff + CRYPT_LEVEL_POS, &ul, sizeof(ULONG));
	ul ^= CHECK_CODE;
	memcpy(lpBuff + CRYPT_LEVEL_POS + sizeof(ULONG), &ul, sizeof(ULONG));


	memset(lpBuff + CRYPT_GUID_POS, 0xff, sizeof(GUID));
	memset(lpBuff + CRYPT_COMPUTER_POS, 0xff, sizeof(GUID));
	memset(lpBuff + CRYPT_AUTHORIZE_POS, 0xff, sizeof(GUID));
}

BOOLEAN IsEncryptedFileHead(UCHAR *lpBuff, ULONG *dwCryptType, UCHAR *lpbtHeadInfo)
{
	BOOLEAN bRet = FALSE;
	if (!lpBuff || !lpbtHeadInfo)
	{
		return bRet;
	}

	RtlCopyMemory(lpbtHeadInfo, lpBuff, ENCRYPT_HEAD_LENGTH);
	FileFlag_XOR(lpbtHeadInfo, SMALL_FILE_FLAG_LEN);

	KdPrint(("Dog id=%d...\n", g_SafeData.SystemUser.DogID));
	ULONG dogID = 0;
	memcpy(&dogID, lpbtHeadInfo + DOCGUARDER_SMALL_HEAD_LENGTH + 2 * sizeof(ULONG), sizeof(ULONG));
	if (dogID != g_SafeData.SystemUser.DogID)
	{
		return bRet;
	}

	ULONG MajorVersion = 0;
	memcpy(&MajorVersion, lpbtHeadInfo + DOCGUARDER_SMALL_HEAD_LENGTH, sizeof(ULONG));
	if (MajorVersion == ENCRYPT_TYPE_DOCGUARDER_ONE)
	{
		if (!RtlEqualMemory(lpbtHeadInfo, "DOCGUARDER_FILE", DOCGUARDER_SMALL_HEAD_LENGTH))
		{
			return bRet;
		}
		CryptKey(lpbtHeadInfo + SMALL_FILE_FLAG_LEN, KEY_LEN);

		if (!RtlEqualMemory(lpbtHeadInfo + SMALL_FILE_FLAG_LEN, g_SafeData.szbtKey, KEY_LEN))
		{
			return bRet;
		}

		ChangeEncodeByKey(lpbtHeadInfo + SMALL_FILE_FLAG_LEN + KEY_LEN, (const UCHAR *)g_SafeData.szbtKey, (int)strlen(g_SafeData.szbtKey));
		if (dwCryptType)
		{
			*dwCryptType = ENCRYPT_TYPE_DOCGUARDER_ONE;
		}

		bRet = TRUE;
	}
	else if (MajorVersion == ENCRYPT_TYPE_DOCGUARDER_THREE)
	{
		if (!RtlEqualMemory(lpbtHeadInfo, "DG_FILE VER 3.0", DOCGUARDER_SMALL_HEAD_LENGTH))
		{
			return bRet;
		}

		CryptKey(lpbtHeadInfo + SMALL_FILE_FLAG_LEN, KEY_LEN);
		if (!RtlEqualMemory(lpbtHeadInfo + SMALL_FILE_FLAG_LEN, g_SafeData.szbtKey, KEY_LEN))
		{
			return bRet;
		}
		ChangeEncodeByKey(lpbtHeadInfo + SMALL_FILE_FLAG_LEN + KEY_LEN, (const UCHAR *)g_SafeData.szbtKey, (int)strlen(g_SafeData.szbtKey));
		if (dwCryptType)
		{
			*dwCryptType = ENCRYPT_TYPE_DOCGUARDER_THREE;
		}

		bRet = TRUE;
	}

	return bRet;
}

BOOLEAN IsEncryptedFileHeadByDogID(UCHAR *lpBuff, UCHAR *lpbtHeadInfo)
{
	BOOLEAN bRet = FALSE;
	ULONG dogID = 0;
	if (!lpBuff || !lpbtHeadInfo)
	{
		return bRet;
	}

	RtlCopyMemory(lpbtHeadInfo, lpBuff, SMALL_FILE_FLAG_LEN);
	FileFlag_XOR(lpbtHeadInfo, SMALL_FILE_FLAG_LEN);

	memcpy(&dogID, lpbtHeadInfo + DOCGUARDER_SMALL_HEAD_LENGTH + 2 * sizeof(ULONG), sizeof(ULONG));
	if (dogID != g_SafeData.SystemUser.DogID)
	{
		return bRet;
	}

	return TRUE;
}

BOOLEAN IsUserCanAccess(int* arrPolicy, int count, ULONG dwCryptLevel, ULONG dwFileLevel, int nPrivType)
{
	int type = 0;
	for (int i = 0; i < count; i++)
	{
		if (type == nPrivType)
		{
			if (type == 0 && dwCryptLevel == dwFileLevel) //文件打开权限,只要同等级就行了
			{
				return TRUE;
			}

			if (arrPolicy[i] == 0xFFFFFFFF)
			{
				type++;
				if (type > nPrivType)
					break;
			}

			if (dwFileLevel == (ULONG)arrPolicy[i])			  //有权限
				return TRUE;
		}
		else
		{
			if (arrPolicy[i] == 0xFFFFFFFF)
			{
				type++;
			}
		}
	}

	return FALSE;
}

ULONG GetDogId()
{
	return g_SafeData.SystemUser.DogID;
}

PDRV_DATA GetDrvData()
{
	return &g_SafeData;
}
