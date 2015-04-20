/***************************************************************************************************************\
*																												*
*									������ �� ���������������� �������											*
*												(����������)													*
*																												*
*				��������� Process ID �� ����, ��������� (�����������) ������ �� (�����.) ��������,				*
*				����������� ����������� ���� ��� ���������� �����������,										*
*				���� ����� ���� � �������� ������� �����. ����													*
*																												*
*				GetPIDOnWindow, GetStringFromProcess, IsWindowSuitable, ClickLBM								*
*																												*
\***************************************************************************************************************/



#pragma once

#include <windows.h>



#define STR_CURDIR			0x24	//current directory
#define STR_DLLPATH			0x30	//dll path
#define STR_IMAGEPATHNAME	0x38	//ImagePathName
#define STR_CMDLINE			0x40	//command line; 



typedef LONG NTSTATUS; 

typedef NTSTATUS (NTAPI *_NtQueryInformationProcess)(HANDLE ProcessHandle, DWORD ProcessInformationClass, 
													  PVOID ProcessInformation, DWORD ProcessInformationLength, 
													  PDWORD ReturnLength);

typedef struct _PROCESS_BASIC_INFORMATION
{
	NTSTATUS ExitStatus;
	PVOID PebBaseAddress;	//��, ��� ��� �����, ����� ������� PEB; 
	ULONG_PTR AffinityMask;
	LONG BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, *PPROCESS_BASIC_INFORMATION; 

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;



HWND GetPIDOnWindow(char *pszWindowName, DWORD *pid); 
char *GetStringFromProcess(DWORD pid, DWORD str_type);
BOOL IsWindowSuitable(HWND hWnd);
void ClickLBM(HWND hWnd, int x, int y); 
