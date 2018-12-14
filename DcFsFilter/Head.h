
#ifndef DEFHEAD_H
#define DEFHEAD_H

#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include "userkernel.h"

// 文件加密标识占用字节数
#ifndef ENCRYPT_HEAD_LENGTH
#define ENCRYPT_HEAD_LENGTH		1024
#endif

extern DRV_DATA g_SafeData;

#define XOR_CODE1 0x5c
#define XOR_CODE2 0xc5
#define CHECK_CODE 0x89abcdef

#define KEY_LEN	128
#define ENCODE_LEN	256
#define TABLE_LEN	256
#define DOCGUARDER_SMALL_HEAD_LENGTH	15
#define DOCGUARDER_SMALL_RESERVE_LENGTH	5



#define SMALL_FILE_FLAG_LEN	32
#define DOCGUARDER_USER_LEN	128
#define RESERVE_LEN_THREE	124

#define CRYPT_LEVEL_POS 0x2a0  //672
#define CRYPT_TIME_POS	(0x2a0 + 2 * sizeof(ULONG))
#define CRYPT_GUID_POS  (CRYPT_TIME_POS + sizeof(CryptFileTime))
#define CRYPT_COMPUTER_POS  (CRYPT_GUID_POS + sizeof(GUID))
#define CRYPT_OWNER_POS	(CRYPT_COMPUTER_POS + sizeof(GUID))
#define CRYPT_PERMISSION_POS	(CRYPT_OWNER_POS + DOCGUARDER_USER_LEN)
#define CRYPT_AUTHORIZE_POS	(CRYPT_PERMISSION_POS + sizeof(ULONG))
#define CRYPT_RESERVE_POS	(CRYPT_AUTHORIZE_POS + sizeof(GUID))
enum
{
	ENCRYPT_TYPE_NORMAL = 0,
	ENCRYPT_TYPE_DOCGUARDER_ONE = 1,
	ENCRYPT_TYPE_DOCGUARDER_THREE = 3,
	ENCRYPT_TYPE_DOCGUARDER_FOUR = 4,
	ENCRYPT_TYPE_DOCGUARDER_FIVE = 5,
	ENCRYPT_TYPE_AES_ONE = 0x10,
	ENCRYPT_TYPE_AES_TWO = 0x20,
};

enum
{
	ACCESS_TYPE_OPEN = 0,
	ACCESS_TYPE_PRINT = 1,
};

typedef struct _FileFlag
{
	UCHAR btHead[DOCGUARDER_SMALL_HEAD_LENGTH];
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG DogID;
	UCHAR btReserve[DOCGUARDER_SMALL_RESERVE_LENGTH];
}FileFlag;

typedef struct _SYSTEMTIME {
	USHORT wYear;
	USHORT wMonth;
	USHORT wDayOfWeek;
	USHORT wDay;
	USHORT wHour;
	USHORT wMinute;
	USHORT wSecond;
	USHORT wMilliseconds;
} SYSTEMTIME, *PSYSTEMTIME, *LPSYSTEMTIME;

typedef struct _CryptFileTime
{
	char	   btFlag[10];				//离线时间的标记
	SYSTEMTIME tOverTime;
	int		   nOffineLine;				//离线处理方式
	int		   nFileOper;				//受限文件处理方式
}CryptFileTime;

typedef struct _CryptFileHeadThree
{
	FileFlag fileflag;

	UCHAR btKey[KEY_LEN];
	UCHAR btEncode[ENCODE_LEN];
	UCHAR btEncodeTable[TABLE_LEN];

	ULONG dwEncryptLevel;
	ULONG dwEncryptLevelCheck;

	CryptFileTime timeInfo;

	GUID guidFile;

	GUID guidOutside;

	UCHAR btOwner[DOCGUARDER_USER_LEN];
	ULONG dwPermission;
	GUID guidAuthorize;

	UCHAR btReserve[RESERVE_LEN_THREE];
}CryptFileHeadThree;

#ifdef __cplusplus
extern "C" {
#endif

void FileFlag_XOR(UCHAR *p, int Len);

void CryptKey(UCHAR *btKey, int nKeyLength);

void ChangeEncodeByKey(UCHAR *btEncode, const UCHAR *btKey, int nKeyLength);

void CreateEncode(UCHAR btEncode[ENCODE_LEN]);

void EncryptFileHead(UCHAR *lpBuff);

BOOLEAN IsEncryptedFileHead(UCHAR *lpBuff, ULONG *dwCryptType, UCHAR *lpbtHeadInfo);

void CreateFileHead(UCHAR *lpBuff);

BOOLEAN IsEncryptedFileHeadByDogID(UCHAR *lpBuff, UCHAR *lpbtHeadInfo);

BOOLEAN IsUserCanAccess(int* arrPolicy, int count, ULONG dwCryptLevel, ULONG dwFileLevel, int nPrivType);

ULONG GetDogId();
PDRV_DATA GetDrvData();
ULONG GetClientProcessId();


#ifdef __cplusplus
}
#endif

#endif