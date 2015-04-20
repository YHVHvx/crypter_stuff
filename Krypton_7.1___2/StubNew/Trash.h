/*while(TRUE)
							{
								{
									if (WaitForDebugEvent( &devent ,150)) // wait 150 ms for debug event
									{
										switch(devent.dwDebugEventCode)
										{
											case CREATE_PROCESS_DEBUG_EVENT:
												MessageBoxA(NULL,"CREATE_PROCESS_DEBUG_EVENT",0,0);
											break;		
											case EXIT_PROCESS_DEBUG_EVENT:
												MessageBoxA(NULL,"EXIT_PROCESS_DEBUG_EVENT",0,0);
											break;
											case EXCEPTION_DEBUG_EVENT:		 	
												MessageBoxA(NULL,"EXCEPTION_DEBUG_EVENT",0,0);
											break;
										}	
										ContinueDebugEvent(devent.dwProcessId , devent.dwThreadId , DBG_CONTINUE);
									}

									else
									{
										// other operations
									}

								}
							}  // while Debug end here */
//pNtProtectVirtualMemory=(_NtProtectVirtualMemory)GetProcAddressNt("ZwProtectVirtualMemory");
//__asm
//{
//	PUSH OFFSET SEH_GetSectionProtection
//	PUSH FS:[0]			//Адрес следующей структуры ERR.
//	MOV FS:[0],ESP 	//Помещаем в FS:[0] адрес только что созданной структуры ERR.
//		//int 3 
//		//int 3						//Здесь находится защищенный обработчиком код.
//		//int 3 
//		//POP FS:[0]			//Восстанавливаем в FS:[0] адрес предыдущей ERR, которая 
//		//до этого была следующей в цепочке вверх после текущей ERR.
//		//Тем самым, мы удаляем текущий обработчик исключений. 
//		//ADD ESP, 4h			//Очищаем стек от остатков ненужной нам более структуры ERR.
//		//RET 
//}

//if(bVista)
//{
//	wchar_t wcTemp[MAX_PATH];
//	GetTempPathW(MAX_PATH,wcTemp);
//	wchar_t* wct = wcsrchr(wcName,'\\')+1;
//	wcscat(wcTemp,wct);
//	MessageBoxW(NULL,wcTemp,0,0);
//	CreatePE(wcName,lpShell,dwSize2-sizeof(SCOMP));
//	bProcessCreate = pCreateProcessW(wcName,pPEB->ProcessParameters->CommandLine.Buffer,NULL,NULL, FALSE, CREATE_SUSPENDED /* DEBUG_ONLY_THIS_PROCESS|  | CREATE_NO_WINDOW*/, NULL, NULL, &si, &pi);
//	if(bProcessCreate)
//	{
//		ExitProcess(0);
//	}
//}

	/*for(WORD i=0; i< pPEB->ProcessParameters->CommandLine.Length;i++)
	{
		if(pPEB->ProcessParameters->CommandLine.Buffer[i]==':') {wsCmdLine =&pPEB->ProcessParameters->CommandLine.Buffer[i-1] ;break;}

	}*/
	//wsCmdLine = &pPEB->ProcessParameters->CommandLine.Buffer[1];
	//wsCmdLine[pPEB->ProcessParameters->CommandLine.Length-4]=0;
	//#ifdef DBG
	//	OutputDebugStringW(pPEB->ProcessParameters->CommandLine.Buffer);
	//#endif

/*
					loader_antidump_start:
					; anti-dump protection
					mov eax,[fs:$30]	    ; PEB
					mov eax,[eax+$0C]	    ; PEB_LDR_DATA
					mov eax,[eax+$0C]	    ; Ldr.InLoadOrderModuleList.Flink
					lea ecx,[eax+$18]	    ; LDR_DATA_TABLE_ENTRY.DllBase
					lea edx,[eax+$20]	    ; LDR_DATA_TABLE_ENTRY.SizeOfImage
					mov [ecx],ebx	    ; fix ImageBase to KERNEL32.DLL ImageBase
					sub dword [edx],$10000 ; fix SizeOfImage
					loader_antidump_end:
					*/

					/*
					;---------- Ring3 antidebug ----------;
					mov eax,[fs:$30]
					mov ecx,[eax+$0C]
					jecxz @_dbg_w9x
					add eax,$AC
					cmp word [eax],2195 ; Windows 2000
					jne @_dbg_xp
					mov eax,$FFFFFF38
					jmp @_dbg_nt_common
					@_dbg_xp:
					cmp word [eax],2600 ; Windows XP
					jne @_dbg_quit
					mov eax,$FFFFFF1A
					;jmp @_dbg_nt_common
					@_dbg_nt_common:
					xor ecx,ecx
					push ecx
					push ecx
					push 17
					push -2
					call @f
					@@:  add dword [esp],@f-@b
					not eax
					lea edx,[esp+4]
					int $2E ; call ZwSetInformationThread
					@@:  add esp,$14
					@_dbg_quit:
					;-------------------------------------;
					*/

//Брать TEB и PEB
//LDT_ENTRY fs_entry;
//GetThreadSelectorEntry(pi.hThread, FS, &fs_entry);

//DWORD fs_base = fs_entry.BaseLow | (fs_entry.HighWord.Bytes.BaseMid<<16) | (fs_entry.HighWord.Bytes.BaseHi<<24);

//TEB teb;
//DWORD read;
//if(ReadProcessMemory(pi.hProcess, (LPCVOID) fs_base, &teb, sizeof(teb), &read))
//{
//	DPRINT1("pPEBx from ctx = 0x%X",teb.Peb);
//	PEB peb;
//	if(ReadProcessMemory(pi.hProcess, (LPCVOID) teb.Peb, &peb, sizeof(peb), &read))
//	{
//		DPRINT1("!=0x%X",peb.LdrData);
//	}
//}
//PEB PEBx;
//if(ReadProcessMemory(pi.hProcess, (LPCVOID) pPEBx, &PEBx, sizeof(PEB), &dwTemp))
//{
//	DPRINT1("PEB readed: %d",PEBx.LdrData);
//	PEB_LDR_DATA pld;
//	if(ReadProcessMemory(pi.hProcess, (LPCVOID) PEBx.LdrData, &pld, sizeof(pld), &dwTemp))
//	{
//		DPRINT("PEB_LDR_DATA readed");
//	}
//}

/*
if(!NT_SUCCESS(ntStatus))
{
DPRINT1("LoaderPE: Section in 0x%X NOT Unmapped",dwSecAdr);
dwSecAdr = 0x400000;
ntStatus = pNtUnmapViewOfSection(pi.hProcess,(PVOID)dwSecAdr);
if(!NT_SUCCESS(ntStatus))
{
DPRINT1("LoaderPE: Section in 0x%X NOT Unmapped",dwSecAdr);
dwSecAdr = 0x1000000;


ntStatus = pNtUnmapViewOfSection(pi.hProcess,(PVOID)dwSecAdr);
if(!NT_SUCCESS(ntStatus))
{
DPRINT1("LoaderPE: Section in 0x%X NOT Unmapped",dwSecAdr);
}
else
{
DPRINT1("LoaderPE: Section in 0x%X Unmapped",dwSecAdr);
} 
} 
else
{
DPRINT1("LoaderPE: Section in 0x%X Unmapped",dwSecAdr);
}       
}
else
{
DPRINT1("LoaderPE: Section in 0x%X Unmapped",pinh->OptionalHeader.ImageBase);
}
*/
extern DWORD_PTR __security_cookie;  /* /GS security cookie */
//
///*
// * The following two names are automatically created by the linker for any
// * image that has the safe exception table present.
//*/
// 
//extern PVOID __safe_se_handler_table[]; /* base of safe handler entry table */
//extern BYTE  __safe_se_handler_count;  /* absolute symbol whose address is
//                                           the count of table entries */
//typedef struct {
//    DWORD       Size;
//    DWORD       TimeDateStamp;
//    WORD        MajorVersion;
//    WORD        MinorVersion;
//    DWORD       GlobalFlagsClear;
//    DWORD       GlobalFlagsSet;
//    DWORD       CriticalSectionDefaultTimeout;
//    DWORD       DeCommitFreeBlockThreshold;
//    DWORD       DeCommitTotalFreeThreshold;
//    DWORD       LockPrefixTable;            // VA
//    DWORD       MaximumAllocationSize;
//    DWORD       VirtualMemoryThreshold;
//    DWORD       ProcessHeapFlags;
//    DWORD       ProcessAffinityMask;
//    WORD        CSDVersion;
//    WORD        Reserved1;
//    DWORD       EditList;                   // VA
//    DWORD_PTR   *SecurityCookie;
//    PVOID       *SEHandlerTable;
//    DWORD       SEHandlerCount;
//} IMAGE_LOAD_CONFIG_DIRECTORY32_2;
//
//const IMAGE_LOAD_CONFIG_DIRECTORY32_2 _load_config_used = {
//    sizeof(IMAGE_LOAD_CONFIG_DIRECTORY32_2),
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    0,
//    &__security_cookie,
//    __safe_se_handler_table,
//    (DWORD)(DWORD_PTR) &__safe_se_handler_count
//};
//
