#include <Windows.h>
#include <WinNT.h>

#include "klog.h"
#include "init.h"
#include "common.h"

extern	KLOG* pLog;
extern	PFN_RtlAnsiStringToUnicodeString aRtlAnsiStringToUnicodeString;
extern	PFN_RtlFreeUnicodeString aRtlFreeUnicodeString;

void ReplaceUnicodeStr(char* s, KUNICODE_STRING* pUs){
	KUNICODE_STRING TmpU;
	ZeroMemory(&TmpU, sizeof(KUNICODE_STRING));
	KSTRING AnsiStr;
	ZeroMemory(&AnsiStr, sizeof(KSTRING));
	AnsiStr.Buffer = s;
	AnsiStr.Length = strlen(s);
	AnsiStr.MaximumLength = AnsiStr.Length + 2;
	aRtlAnsiStringToUnicodeString(&TmpU, &AnsiStr, 1);
	*pUs=TmpU;
}

//DWORD Init(char* szEXE, DWORD Len){
//	char szIni[260];
//	char szExe[260];
//	char szArg[260];
//	char szDir[260];
//
//	DWORD i=0;
//	int err = 0;
//	pLog = new ("debug.txt", 1, &err) KLOG;
//	Log("PE Loader v1.2\r\n");
//
//	aRtlAnsiStringToUnicodeString=(PFN_RtlAnsiStringToUnicodeString)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlAnsiStringToUnicodeString");
//	if(!aRtlAnsiStringToUnicodeString){
//		Log("RtlAnsiStringToUnicodeString error\r\n");
//		return -1;//return error_code;
//	}
//	aRtlFreeUnicodeString=(PFN_RtlFreeUnicodeString)GetProcAddress(GetModuleHandle("ntdll.dll"), "RtlFreeUnicodeString");
//	if(!aRtlAnsiStringToUnicodeString){
//		Log("RtlFreeUnicodeString error\r\n");
//		return -1;//return error_code;
//	}
//
//	//Read settings
//	GetModuleFileName(0, szIni, 260);
//	for(i=(DWORD)strlen(szIni); i>0; i--){if(szIni[i-1]=='\\'){szIni[i]=0; break;}}
//	strcat(szIni, "peldr.ini");
//
//	//Set current directory
//	szDir[0]=0;
//	GetPrivateProfileString("Settings", "Dir", "", szDir, 260, szIni);
//	if(szDir[0]){//Use dir from settings
//		SetCurrentDirectory(szDir);
//	}
//	else{//Use dir from Exe
//		GetPrivateProfileString("Settings", "Exe", szIni, szDir, 260, szIni);
//		for(i=(DWORD)strlen(szDir); i>0; i--){if(szDir[i-1]=='\\'){szDir[i]=0; break;}}
//		SetCurrentDirectory(szDir);
//	}
//
//	//Read target EXE file name and path
//	szExe[0]=0;
//	GetPrivateProfileString("Settings", "Exe", szIni, szExe, 260, szIni);
//	Log("Exe : %s\r\n", szExe);
//
//
//	KPEB* pKPEB=0;
//	__asm{
//		mov eax, fs:[0x30]
//		mov	pKPEB, eax
//	}
//
//	//Change LDR_MODULE
//	LDR_MODULE* pModule=(LDR_MODULE*)pKPEB->Ldr->InLoadOrderModuleList.Flink;
//	ReplaceUnicodeStr(szExe, &pModule->FullDllName);
//	for(i=(DWORD)strlen(szExe); i>0; i--){
//		if(szExe[i-1]=='\\') break;
//	}
//	ReplaceUnicodeStr(&szExe[i], &pModule->BaseDllName);
//
//	szExe[0]=0;
//	GetPrivateProfileString("Settings", "Exe", szIni, szExe, 260, szIni);
//
//	ReplaceUnicodeStr(szExe, &pKPEB->ProcessParameters->ImagePathName);
//	ReplaceUnicodeStr(szExe, &pKPEB->ProcessParameters->WindowTitle);
//	
//	szArg[0]=0;
//	GetPrivateProfileString("Settings", "Arg", "", szArg, 260, szIni);
//	if(szArg[0]){
//		Log("Arg : %s\r\n", szArg);
//		strcat(szExe, " ");
//		strcat(szExe, szArg);
//	}
//	//Set command line arguments
//	ReplaceUnicodeStr(szExe, &pKPEB->ProcessParameters->CommandLine);
//
//
//	//Set DLL Path
//	KUNICODE_STRING Ustr;
//	ZeroMemory(&Ustr, sizeof(KUNICODE_STRING));
//	KSTRING Ansi;
//	ZeroMemory(&Ansi, sizeof(KSTRING));
//	szDir[strlen(szDir)-1]=0;//Del last slash
//	Ansi.Buffer = szDir;
//	Ansi.Length=strlen(szDir);
//	Ansi.MaximumLength=Ansi.Length+2;
//	aRtlAnsiStringToUnicodeString(&Ustr, &Ansi, 1);
//
//	KUNICODE_STRING* t = &(pKPEB->ProcessParameters->DllPath);
//	for(i=0; i < t->Length/2; i++){
//		if(t->Buffer[i]==';') break;
//	}
//	
//	DWORD ResultLen = Ustr.Length + t->Length - i;
//	WORD* pRes=(WORD*)MemAlloc(ResultLen);
//	wcscpy(pRes, Ustr.Buffer);
//	wcscat(pRes, L";");
//	wcscat(pRes, &t->Buffer[i + 1]);
//	t->Buffer = pRes;
//	t->Length = ResultLen;
//	t->MaximumLength = t->Length + 2;
//	aRtlFreeUnicodeString(&Ustr);
//
//
//	GetPrivateProfileString("Settings", "Exe", szIni, szEXE, Len, szIni);
//
//	return 0;
//}

