#pragma once
//#define WIN32_LEAN_AND_MEAN
//#define _USER_MODE
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <ntundoc.h>
#define ALIGN_DOWN(x, align) (x & ~(align-1))
#define ALIGN_UP(x, align) ((x & (align-1)) ?ALIGN_DOWN(x, align) + align:x)
#pragma pack (push,1)
typedef struct _SCOMP
{
	BYTE bXOR;								//CryptByte
	DWORD dwSzFull;           //Full size with base64
	DWORD dwSzCompBlock;			//size of compressed block, if == 0, then no compressed. for example arhive or jpg
	DWORD dwSzUncompBlock;		//size of uncompressed block
	DWORD dwImageBase;
	DWORD dwSizeOfImage;
	BYTE bData[0];					  //data
}SCOMP,*PSCOMP;
#pragma pack(pop)
//===========================================================================================
