
#ifndef __UserKernel_H__
#define __UserKernel_H__

#include "EncFlagData.h"
#ifndef KEY_LEN
#define KEY_LEN 128
#endif
	//
	//  Name of port used to communicate
	//

#define PortName  L"\\HuatuDriverPort"
#define PolicyFileName L"\\systemroot\\system32\\ZCSafe.db"



#define USERKERNEL_BYTE char

#define PUSERKERNEL_BYTE char*


	// �ӽ���һ�ο�����ɵ���ֽ���
#define CRYPT_BLOCK_MAX_LEN			16

	// �ӽ���KEY����(�ֽ���)
#define CRYPTO_KEY_LEN				32


	// ͨ�����
	typedef enum _EWorkState
	{
		eWorkStateMin = 1,
		eWorkStateNormal = 2, // ����״̬
		eWorkStateOffline = 4, // ��ȫ����״̬
		eWorkStateSpecial = 8, // �ڶ�״̬
		eWorkStateOfflineNor = 16, // ���߿�����͸���ӽ���״̬
		eWorkStateMax = 32,
	} EWorkState;

	// Ӧ�ò��������������ִ���������͵Ĳ�ѯ/���ò���
	typedef enum _ESafeCommandType
	{
		// ���ò���
		eInitPolicy,

		// ���¼���Ŀ¼
		eUpdateDir,

		// ��ȡ�����汾��
		eGetDrvVersion,

		// ��ȡ��������״̬:�Ƿ�Ϊ����
		eGetWorkState,

		// ������������״̬Ϊ����/����
		eSetWorkState,

		// ���û���ͣ�����ļ���Ŀ¼��⣨��ͣ����1.7.5.2��֮ǰ�İ汾��ͬ)
		eSetPauseDir,

		// ��̬���һ���ԣ����ܽ��ܲ��ڵ�ǰ���������ڵĽ��̣�ÿ�ε��ýӿڿ������һ�����̵���Ϣ
		eAppendPolicy,

		// ��ֱ̬�����ý��̵�״̬��Ҫ��PID
		eSetProcAuthentic,

		// ��ȡ������¼�ĵ�ǰ���ŵĽ���ID��
		eGetAuthProcIDs,

		// ����������ָ���ļ�
		eEncryptFile,

		// ����������ָ���ļ�
		eDecryptFile,

		// ���ָ���ļ��Ƿ����
		eIsEncryptedFile,

		//�����û���Ϣ
		eSetSystemUse,

		//�����ں��ܿؽ���ID
		eSetKenlPID,

	} ESafeCommandType;

	// Ӧ�ò㴫����������������ṹ��
	typedef struct _CommandMsg
	{
		// ��������
		ESafeCommandType CommandType;

		// MsgInfo��ʵ��Ч�ֽ���
		int nBytes;

		// ��Ϣ����
		unsigned char MsgInfo[4];
	} CommandMsg, *PCommandMsg;


	// ������������״̬
	typedef struct _CmdSetWorkStateParam
	{
		EWorkState NewWorkState;
	} CmdSetWorkStateParam, *PCmdSetWorkStateParam;


	typedef struct _DrvVerInfo
	{
		// �汾��,ʵ����д����ΪUNICODE�ַ���
		USERKERNEL_BYTE Version[56];
	} DrvVerInfo, *PDrvVerInfo;



	typedef enum _EResult
	{
		eError = 0x0,	// ����
		eSuccess = 0x1,	// ��ѯ�ɹ�(ע��:ֻҪδ�������󣬵���eBufferTooSmallʱҲ����eSuccess)
		eBufferTooSmall = 0x2,	// �ṩ�Ļ����С�޷�����������Ϣ
	} EResult;

	// ���������ص��������Ĳ����ڽ���ID���������>0�򲻿ɸ��²��ԣ���������²��ԣ�
	typedef struct _InPolicyProcsId
	{
		// ��ʶ����Ƿ���Ч,EResult���е�һ������
		ULONG Result;

		// ����
		int nNum;
		unsigned long procId[1];
	}InPolicyProcsId, *PInPolicyProcsId;


	// ����һ������̵�״̬�Ƿ�Ϊ���ţ����ֻ����һ�������Ľ���
	typedef struct _SetProcAuthenticStateInfo
	{
		// ע�⣺Ϊ��32λ��64λ��Ӧ�ò����ͨ��ʹ��UINT����HANDLE��ԭ��HANDLE��64λ����64λ�ģ���32λ����32λ�ģ����½ṹ���С��һ��
		unsigned int hPID;	// ����ID�������ǵ�ǰ�����еĽ���ID�������ʧ��
		int bAuthentic;		// �Ƿ����
	}SetProcAuthenticStateInfo, *PSetProcAuthenticStateInfo;

	// ���һ�����̼���������͵�������������Ҫ����Ϣ
	typedef struct _AppendPolicyInfo
	{
		int nProcNameChars;		// �������ַ���
		int nBaseExtsChars;		// ���л������ʹ��ַ�����ע������ð�ŷָ���ͬ��������
		int nFingerPrintChars;	// ָ���ַ���
		wchar_t infoBuf[4];		// infoBuf��һ������UNICODE�ַ���������ǰnProcNameBytes�ֽ��ǽ���������nBaseExtsBytes�����л������ͣ������nFingerPrintChars���ַ�/FINGERPRINT_BYTES��ָ��
	}AppendPolicyInfo, *PAppendPolicyInfo;



	//{{������Ӧ�ò㷢����֪ͨ������

	// ����֪ͨӦ�ò����Ӧ�ò�����ִ���������͵�֪ͨ/��ȡ��Ϣ����
	typedef enum _EDrvCommandType
	{
		// ����֪ͨӦ�ò�˽��������Ϣ
		eDrvNotifyPrivateData = 1,

		// ��������Ӧ�ò㷵��˽������
		eDrvGetPrivateData = 2,

		// ����֪ͨӦ�ò�ĳ�������������ļ�
		eDrvNotifyRename = 3,
	} EDrvCommandType;

	typedef union _DrvMsgParameters
	{

		// ����֪ͨӦ�ò㽫Ҫ�����ļ���˽������
		struct _NotifyPrivateDataMsg
		{
			ULONG pid;	// �������ĵĽ���ID
			wchar_t FileFullPath[528]; // ȫ·���ļ���
			unsigned char PrivateData[PRIVATE_DATA_LEN]; // ˽������
		} MsgNotifyPrivateData, *PMsgNotifyPrivateData;

		// ��������Ӧ�ò㷵�ؽ�Ҫ�����ļ���˽������
		struct _MsgGetPrivateData
		{
			ULONG pid;	// �������ĵĽ���ID
			wchar_t FileFullPath[528]; // ȫ·���ļ���
		} MsgGetPrivateData, *PMsgGetPrivateData;

		struct _MsgNotifyRename
		{
			ULONG pid;
			wchar_t FileOrigName[262];
			wchar_t FileNewName[262];
		} MsgNotifyRename, *PMsgNotifyRename;

	} DrvMsgParameters, *PDrvMsgParameters;

	typedef struct _DrvMsgData
	{
		// ������������
		EDrvCommandType CommandType;

		// ������Ϣ����
		DrvMsgParameters msgParam;
	} DrvMsgData, *PDrvMsgData;

	//}}

	//{{ Ӧ�ò���Ӧ���ظ���������Ϣ
	typedef union _AppReplyMsgParams
	{
		struct _PrivateData
		{
			unsigned char data[PRIVATE_DATA_LEN]; // ˽������
		} PrivateData;

		int nDecRequestRet;
	} AppReplyMsgParams, *PAppReplyMsgParams;
	//}}

	typedef struct SystemApi32Use //��Ӧ�ó�����봫�ݵ�����
	{
		UCHAR  Key[KEY_LEN];			//������Կ
		ULONG DogID;			//����
		ULONG dwCurPriv;		//��ǰ���û�Ȩ��
		ULONG dwCryptLevel;		//�û��ĵȼ�
		int	  nPolicyType;		//���Ե�����  (��ʱ��Ч)
		int	  nPolicyCount;		//���Ե�ʵ�ʸ���
		int	  arrPolicy[1000];  //֧��1000���ȼ��Ĵ򿪲���
	}SystemApi32Use, *PSystemApi32Use;

	typedef struct _DRV_DATA
	{
		SystemApi32Use	SystemUser;
		char			szbtKey[129];
	} DRV_DATA, *PDRV_DATA, *LPDRV_DATA;

#endif //  __UserKernel_H__





