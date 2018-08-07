
#ifndef ENCFILE_H
#define ENCFILE_H

#include <fltKernel.h>
#include "userkernel.h"

#define MINIFILTER_TAG			'TFNM' // MNFT
#define	PRE_2_POST_CONTEXT_TAG	'CP2P' // P2PC
#define BUF_4KB_TAG				'4bCE' // ECb4
#define BUF_64KB_TAG			'6bCE' // ECb6

//#define MIN_SECTOR_SIZE			0x1000
#define SIZEOF_4KBList			4096
#define SIZEOF_64KBList			65536

typedef enum _MINIFILTER_LOCK_TYPE
{
	MINIFILTER_LOCK_TYPE_UNLOCKED,
	MINIFILTER_LOCK_TYPE_LOCKED
} MINIFILTER_LOCK_TYPE, *PMINIFILTER_LOCK_TYPE, *LPMINIFILTER_LOCK_TYPE;

typedef enum _MINIFILTER_ENV_TYPE
{
	MINIFILTER_ENV_TYPE_NULL = 0x00000000,
	MINIFILTER_ENV_TYPE_ALL_MODULE_INIT = 0x00000001,
	MINIFILTER_ENV_TYPE_RUNING = 0x00000002,
	MINIFILTER_ENV_TYPE_FLT_FILTER = 0x00000004,
	MINIFILTER_ENV_TYPE_SAFE_DATA = 0x00000008
} MINIFILTER_ENV_TYPE, *PMINIFILTER_ENV_TYPE, *LPMINIFILTER_ENV_TYPE;

#define ENC_FILE_TAG 'LFNE' // ENFL

// �ļ�ͷ�汾��
#define FILE_HEADER_VER 1

// ���ļ���֮����ӵ���չ�������ڽ�ԭ�ļ�������(�൱�ڱ��ݣ���ֱ�Ӽ����ļ�ʱ����ʱ�ļ�
#define FILE_NEED_DELETE_EXT L".DGFileDel"

#ifdef __cplusplus
extern "C" {
#endif
// ����ָ�����ļ�
BOOLEAN EncFile(__in PCFLT_RELATED_OBJECTS FltObjects, __inout char *lpHead);

#ifdef __cplusplus
}
#endif

#endif 