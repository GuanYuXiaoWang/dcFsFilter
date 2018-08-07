
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


	// 加解密一次可以完成的最长字节数
#define CRYPT_BLOCK_MAX_LEN			16

	// 加解密KEY长度(字节数)
#define CRYPTO_KEY_LEN				32


	// 通信相关
	typedef enum _EWorkState
	{
		eWorkStateMin = 1,
		eWorkStateNormal = 2, // 正常状态
		eWorkStateOffline = 4, // 完全离线状态
		eWorkStateSpecial = 8, // 摆渡状态
		eWorkStateOfflineNor = 16, // 离线可正常透明加解密状态
		eWorkStateMax = 32,
	} EWorkState;

	// 应用层可以向驱动请求执行以下类型的查询/设置操作
	typedef enum _ESafeCommandType
	{
		// 设置策略
		eInitPolicy,

		// 更新加密目录
		eUpdateDir,

		// 获取驱动版本号
		eGetDrvVersion,

		// 获取驱动工作状态:是否为离线
		eGetWorkState,

		// 设置驱动工作状态为离线/在线
		eSetWorkState,

		// 启用或暂停驱动的加密目录检测（暂停后与1.7.5.2及之前的版本相同)
		eSetPauseDir,

		// 动态添加一策略，仅能接受不在当前驱动策略内的进程，每次调用接口可以添加一个进程的信息
		eAppendPolicy,

		// 动态直接设置进程的状态需要其PID
		eSetProcAuthentic,

		// 获取驱动记录的当前可信的进程ID组
		eGetAuthProcIDs,

		// 让驱动加密指定文件
		eEncryptFile,

		// 让驱动解密指定文件
		eDecryptFile,

		// 检测指定文件是否加密
		eIsEncryptedFile,

		//设置用户信息
		eSetSystemUse,

		//设置内核受控进程ID
		eSetKenlPID,

	} ESafeCommandType;

	// 应用层传给驱动的请求命令结构体
	typedef struct _CommandMsg
	{
		// 请求类型
		ESafeCommandType CommandType;

		// MsgInfo真实有效字节数
		int nBytes;

		// 信息缓冲
		unsigned char MsgInfo[4];
	} CommandMsg, *PCommandMsg;


	// 设置驱动工作状态
	typedef struct _CmdSetWorkStateParam
	{
		EWorkState NewWorkState;
	} CmdSetWorkStateParam, *PCmdSetWorkStateParam;


	typedef struct _DrvVerInfo
	{
		// 版本号,实际填写内容为UNICODE字符串
		USERKERNEL_BYTE Version[56];
	} DrvVerInfo, *PDrvVerInfo;



	typedef enum _EResult
	{
		eError = 0x0,	// 错误
		eSuccess = 0x1,	// 查询成功(注意:只要未发生错误，当有eBufferTooSmall时也会置eSuccess)
		eBufferTooSmall = 0x2,	// 提供的缓冲过小无法容纳所有信息
	} EResult;

	// 从驱动返回的已启动的策略内进程ID，如果个数>0则不可更新策略（可以添加新策略）
	typedef struct _InPolicyProcsId
	{
		// 标识结果是否有效,EResult的中的一个或多个
		ULONG Result;

		// 个数
		int nNum;
		unsigned long procId[1];
	}InPolicyProcsId, *PInPolicyProcsId;


	// 设置一特殊进程的状态是否为可信，最多只会有一个这样的进程
	typedef struct _SetProcAuthenticStateInfo
	{
		// 注意：为了32位与64位的应用层可以通用使用UINT代替HANDLE，原因：HANDLE在64位中是64位的，在32位中是32位的，导致结构体大小不一致
		unsigned int hPID;	// 进程ID，必须是当前运行中的进程ID，否则会失败
		int bAuthentic;		// 是否可信
	}SetProcAuthenticStateInfo, *PSetProcAuthenticStateInfo;

	// 添加一个进程及其基本类型到驱动策略中需要的信息
	typedef struct _AppendPolicyInfo
	{
		int nProcNameChars;		// 进程名字符数
		int nBaseExtsChars;		// 所有基本类型串字符数，注意是以冒号分隔不同基本类型
		int nFingerPrintChars;	// 指纹字符数
		wchar_t infoBuf[4];		// infoBuf是一连续的UNICODE字符串，其中前nProcNameBytes字节是进程名，后nBaseExtsBytes是所有基本类型，最后是nFingerPrintChars个字符/FINGERPRINT_BYTES个指纹
	}AppendPolicyInfo, *PAppendPolicyInfo;



	//{{驱动向应用层发出的通知或请求

	// 驱动通知应用层或向应用层请求执行以下类型的通知/获取信息操作
	typedef enum _EDrvCommandType
	{
		// 驱动通知应用层私有数据信息
		eDrvNotifyPrivateData = 1,

		// 驱动请求应用层返回私有数据
		eDrvGetPrivateData = 2,

		// 驱动通知应用层某进程在重命名文件
		eDrvNotifyRename = 3,
	} EDrvCommandType;

	typedef union _DrvMsgParameters
	{

		// 驱动通知应用层将要解密文件的私有数据
		struct _NotifyPrivateDataMsg
		{
			ULONG pid;	// 操作密文的进程ID
			wchar_t FileFullPath[528]; // 全路径文件名
			unsigned char PrivateData[PRIVATE_DATA_LEN]; // 私有数据
		} MsgNotifyPrivateData, *PMsgNotifyPrivateData;

		// 驱动请求应用层返回将要加密文件的私有数据
		struct _MsgGetPrivateData
		{
			ULONG pid;	// 操作密文的进程ID
			wchar_t FileFullPath[528]; // 全路径文件名
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
		// 驱动请求类型
		EDrvCommandType CommandType;

		// 驱动消息参数
		DrvMsgParameters msgParam;
	} DrvMsgData, *PDrvMsgData;

	//}}

	//{{ 应用层响应返回给驱动的信息
	typedef union _AppReplyMsgParams
	{
		struct _PrivateData
		{
			unsigned char data[PRIVATE_DATA_LEN]; // 私有数据
		} PrivateData;

		int nDecRequestRet;
	} AppReplyMsgParams, *PAppReplyMsgParams;
	//}}

	typedef struct SystemApi32Use //对应用程序必须传递的数据
	{
		UCHAR  Key[KEY_LEN];			//加密密钥
		ULONG DogID;			//狗号
		ULONG dwCurPriv;		//当前的用户权限
		ULONG dwCryptLevel;		//用户的等级
		int	  nPolicyType;		//策略的类型  (暂时无效)
		int	  nPolicyCount;		//策略的实际个数
		int	  arrPolicy[1000];  //支持1000个等级的打开策略
	}SystemApi32Use, *PSystemApi32Use;

	typedef struct _DRV_DATA
	{
		SystemApi32Use	SystemUser;
		char			szbtKey[129];
	} DRV_DATA, *PDRV_DATA, *LPDRV_DATA;

#endif //  __UserKernel_H__





