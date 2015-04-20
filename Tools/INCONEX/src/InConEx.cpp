/*

  InContextExecute
  ----------------

  Attempt to execute a PE image in the own process memory context.

  project start: 12th April 2k2

  YOU ARE ALLOWED TO USE MY CODE IN YOUR OWN PROJECTS IF YOU
  MENTION MY NAME.

  by yoda

*/

#define  WIN32_LEAN_AND_MEAN 
#include "InConEx.h"

#pragma  comment(linker, "/FILEALIGN:512")
#pragma  optimize("", off)

//
// debug control
//
//#define DEBUG_CLIENT_EXEC
//#define DEBUG_EXITPROC_HOOK_INSTALL
//#define DEBUG_EXITPROC_HOOK_DEINSTALL

//
// structures
//
typedef struct _MODULE_INFO_TO_ADJUST
{
	DWORD          ImageBase;
	DWORD          ImageSize;
	char           cExeFilePath[MAX_PATH];
} MODULE_INFO_TO_ADJUST, *PMODULE_INFO_TO_ADJUST;

//
// constants
//
#define TITLE   "-------------------------------------------------------------------------------\n" \
	            " InContextExecute 1.0 by yoda\n" \
                "-------------------------------------------------------------------------------\n"

//
// function prototypes
//
int WINAPI      WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow);
BOOL            ProcessExecutableImage(char* szPath);
void*           BuildAndInitializePEImage(void* p);
void*           VAlloc(DWORD dwSize);
BOOL            VFree(void* p);
void            ThreadEndStub();
void __stdcall  EntryThreadStub(void* pParam);
HANDLE          ExecutePEImage(DWORD dwEntryPtr);
BOOL __stdcall  ExitProcess_HookProc(PCH_LOC_HOOK_CALLBACK_INFO pinfo);
BOOL            AdjustOperationSystemStructs(PMODULE_INFO_TO_ADJUST pinfo);

//
// global variables
//
BOOL                   g_bWorkerThread;
CodeHook               g_hooker;
MODULE_INFO_TO_ADJUST  g_OrgCallModInfo;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
	OFN       *pOFN;
	int       hCrt;
	FILE      *hf;

	pOFN = new OFN;

	//
	// let user select target file
	//
	pOFN->ofnOpen.lpstrFilter = "*.EXE\0*.EXE\0*.*\0*.*\0";
	if ( !pOFN->GetOpenFilePath() )
		return -1; // ERR

	//
	// install a console window
	//
	if ( !AllocConsole() )
		return -1; // ERR
	// make CRT functions as "printf" accessible (MSDN: Article ID: Q105305)
	hCrt = _open_osfhandle(
			 (long) GetStdHandle(STD_OUTPUT_HANDLE),
			 _O_TEXT
		  );
	hf = _fdopen(hCrt, "w");
	*stdout = *hf;
	setvbuf(stdout, NULL, _IONBF, 0);

	//
	// call root routine
	//
	ProcessExecutableImage(pOFN->cPathOpen);
	printf("\nPress any key to close console...");
	getch();

	//
	// cleanup
	//
	fclose(hf);
	FreeConsole();
	delete pOFN;

	return 0;
}

BOOL ProcessExecutableImage(char* szPath)
{
	clsFILE       f;
	void*         pImage, *pExitProcess;
	HANDLE        hThread;
	DWORD         dwEntryPtr;
	PPE_IMAGE     pi, ppiCallMod;

	// print title
	printf(TITLE);
	printf("\n");
	printf("Processing...%s\n\n", szPath);

	//
	// map file
	//
	if ( !f.GetFileHandle(szPath, F_OPENEXISTING_R) )
	{
		printf("!! Couldn't open file...\n");
		return FALSE; // ERR
	}
	if ( !f.MapFile() )
	{
		printf("!! Error while mapping file...\n");
		return FALSE; // ERR
	}

	//
	// build + init file image
	//
	OutputDebugString("InConEx: Building+Initializing pseudo process module...\n");
	pImage = BuildAndInitializePEImage(f.GetMapPtr());
	if (!pImage)
		return FALSE; // ERR
	f.Destroy(); // free raw file buffer
	printf("-> Pseudo module image mapped to 0x%08lX\n", (DWORD)pImage);

	//
	// hook ExitProcess API
	//
	printf("-> Installing ExitProcess hook...\n");
	OutputDebugString("InConEx: Installing ExitProcess hook...\n");
	pExitProcess = GetProcAddress(
		GetModuleHandle("KERNEL32"),
		"ExitProcess");
	if (!pExitProcess)
	{
		printf("!! Couldn't obtain ExitProcess API entry...\n");
		goto Cleanup;
	}
#if defined(DEBUG_EXITPROC_HOOK_INSTALL)
	__asm INT 3
#endif
	if ( !g_hooker.InstallLocationHook(
		pExitProcess,
		ExitProcess_HookProc))
	{
		printf("!! Error while hooking ExitProcess API entry...\n");
		goto Cleanup;
	}

	//
	// adjust win vars
	//
	printf("-> Adjusting OS variables...\n");
	OutputDebugString("InConEx: Adjusting OS variables...\n");

	// save current calling module info for later
	GetModuleFileName(
		NULL,
		g_OrgCallModInfo.cExeFilePath,
		sizeof(g_OrgCallModInfo.cExeFilePath));
	g_OrgCallModInfo.ImageBase = (DWORD)GetModuleHandle(NULL);
	ppiCallMod = new PE_IMAGE((void*)g_OrgCallModInfo.ImageBase, PI_MODE_VIRTUAL);
	g_OrgCallModInfo.ImageSize = ppiCallMod->m_pNT->OptionalHeader.SizeOfImage;
	delete ppiCallMod;

	// adjust!
	pi = new PE_IMAGE(pImage, PI_MODE_VIRTUAL);
	MODULE_INFO_TO_ADJUST info;

	lstrcpy(info.cExeFilePath, szPath);
	info.ImageBase = (DWORD)pImage;
	info.ImageSize = pi->m_pNT->OptionalHeader.SizeOfImage;
	if ( !AdjustOperationSystemStructs(&info) )
	{
		printf("!! Error while patching OS structures...\n");
	}

	//
	// execute virtual image
	//

	// execute EntryPoint
	printf("-> Creating worker thread...\n");
	OutputDebugString("InConEx: Creating worker thread...\n");
	dwEntryPtr = pi->m_pNT->OptionalHeader.AddressOfEntryPoint + (DWORD)pImage;
	delete pi; // CLEANUP pi
	hThread = ExecutePEImage(dwEntryPtr);
	if (!hThread)
	{
		printf("!! Error during thread creation...\n");
		goto Cleanup;
	}

	// wait for client thread to exit
	g_bWorkerThread = TRUE;
	do
	{} while (g_bWorkerThread != FALSE);
	OutputDebugString("InConEx: Worker thread has terminated...\n");
	printf("-> Worker thread has terminated...\n");
	printf("-> Pseudo module was executed successfully :)\n");

	//
	// reset original calling module information
	//
	printf("-> Reseting original OS variables...\n");
	if ( !AdjustOperationSystemStructs(&g_OrgCallModInfo) )
	{
		printf("!! Failed...\n");
	}

Cleanup:
	//
	// cleanup
	//
	printf("-> Cleaning up...\n");
#if defined(DEBUG_EXITPROC_HOOK_DEINSTALL)
	__asm INT 3
#endif // DEBUG_EXITPROC_HOOK_DEINSTALL
	g_hooker.DeinstallLocationHook(pExitProcess);
	VFree(pImage);

	return TRUE; // OK
}

//
// (lists errors itself)
//
// Returns: ptr to build PE file image if successful (must be freed with VFree)
//
void* BuildAndInitializePEImage(void* p)
{
	PE_IMAGE                  piRaw(p, PI_MODE_RAW);
	PE_IMAGE                  *piVirtual = NULL;
	void*                     pPEI = NULL;
	void                      *pProc;
	DWORD                     dwHdrSize, dwBlockSize;
	UINT                      i;
	PIMAGE_SECTION_HEADER     pSH;
	PIMAGE_IMPORT_DESCRIPTOR  pIID;
	DWORD                     *pdwThunk, *pdwThunk2Init, dwOrdinal, dwItems;
	char*                     szDll;
	HMODULE                   hmCurDll;
	PIMAGE_IMPORT_BY_NAME     pIIBN;
	PIMAGE_BASE_RELOCATION    pIBR;
	WORD                      *pW;

	// check the input raw image
	if ( !piRaw.IsAssigned() )
	{
		printf("!! Invalid PE file...\n");
		return NULL; // ERR
	}
	if ( piRaw.IsPE32Plus() )
	{
		printf("!! 64bit PE files aren't supported...\n");
		return NULL; // ERR
	}
	if ( !piRaw.GetDataDirectoryPtr(IMAGE_DIRECTORY_ENTRY_BASERELOC)->VirtualAddress )
	{
		printf("!! No BaseRelocationDirectory present...\n");
		return NULL; // ERR
	}

	//
	// alloc memory for virtual file image
	//
	printf("-> Allocating memory for virtual image...\n");
	pPEI = VAlloc(piRaw.m_pNT->OptionalHeader.SizeOfImage);
	if (!pPEI)
	{
		printf("!! Not enough memory available...\n");
		return FALSE; // ERR
	}

	try
	{
		//
		// zero pseudo module memory
		// -> zero out unitialized data blocks in image
		//
		memset(pPEI, 0, piRaw.m_pNT->OptionalHeader.SizeOfCode);

		//
		// write hdr + sections to virtual map
		//
		printf("-> Copying raw file image partions to virtual image...\n");
		// hdr
		dwHdrSize = piRaw.GetRealSizeOfHeader();
		memcpy(
			pPEI,
			p,
			dwHdrSize);
		// sections
		pSH = piRaw.m_pSHT;
		for (i = 0; i < piRaw.m_pNT->FileHeader.NumberOfSections; i++)
		{
			// -pay attention to special PEs with zero'd VritualSize
			// -always use lower one, RawSize or VirtualSize
			if (!pSH->Misc.VirtualSize)
				dwBlockSize = pSH->SizeOfRawData;
			else
				dwBlockSize = min(pSH->Misc.VirtualSize, pSH->SizeOfRawData);
			memcpy(
				MakePtr(PVOID, pPEI, pSH->VirtualAddress),
				MakePtr(PVOID, p, pSH->PointerToRawData),
				dwBlockSize);
			++pSH;
		}

		piVirtual = new PE_IMAGE(pPEI, PI_MODE_VIRTUAL);

		//
		// initialize ImportTable
		//
		printf("-> Initializing ImportTable...\n");
		// get ptr
		pIID = (PIMAGE_IMPORT_DESCRIPTOR)piVirtual->GetDataDirectoryEntryPtr(
			IMAGE_DIRECTORY_ENTRY_IMPORT);
		while (pIID->FirstThunk)
		{
			// load dll
			szDll = (char*)piVirtual->RvaToVa(pIID->Name);
			printf("   Loading module: %s...", szDll);
			hmCurDll = LoadLibrary(szDll);
			if (!hmCurDll)
			{
				printf("failed\n");
				goto ErrorOccurred;
			}
			printf("done\n");

			// trace thunks
			printf("   Initializing module's thunk chain...\n");
			pdwThunk = (PDWORD)piVirtual->RvaToVa(
				pIID->OriginalFirstThunk ? pIID->OriginalFirstThunk : pIID->FirstThunk);
			pdwThunk2Init = (PDWORD)piVirtual->RvaToVa(pIID->FirstThunk);
			while (*pdwThunk)
			{
				if ( IMAGE_SNAP_BY_ORDINAL32(*pdwThunk) )
				{
					//
					// ordinal Import
					//
					dwOrdinal = IMAGE_ORDINAL32(*pdwThunk);
					pProc = GetProcAddress(hmCurDll, (PSTR)dwOrdinal);
					if (!pProc)
					{
						printf("!! Couldn't resolve symbol reference: Ordinal:0x%04lX...\n",
							dwOrdinal);
						goto ErrorOccurred;
					}
					*pdwThunk2Init = (DWORD)pProc;
				}
				else
				{
					//
					// import by name
					//
					pIIBN = (PIMAGE_IMPORT_BY_NAME)piVirtual->RvaToVa(*pdwThunk);
					pProc = GetProcAddress(hmCurDll, (char*)&pIIBN->Name[0]);
					if (!pProc)
					{
						printf("!! Couldn't resolve symbol reference: %s...\n", (char*)&pIIBN->Name[0]);
						goto ErrorOccurred;
					}
					*pdwThunk2Init = (DWORD)pProc;
				}
				// next thunks
				++pdwThunk;
				++pdwThunk2Init;
			}
			++pIID; // next IID
		}

		//
		// apply fixups
		//
		printf("-> Applying fixups...\n");
		pIBR = (PIMAGE_BASE_RELOCATION)piVirtual->GetDataDirectoryEntryPtr(
			IMAGE_DIRECTORY_ENTRY_BASERELOC);
		DWORD dwDelta = (DWORD)pPEI - (DWORD)piVirtual->m_pNT->OptionalHeader.ImageBase;
		while (pIBR->VirtualAddress)
		{
			// get relocation item count of current block
			dwItems = (pIBR->SizeOfBlock - 8) / sizeof(WORD);
			if (!dwItems)
				break;
			// apply relocation items to virtual image
			pW = (PWORD)(pIBR + 1);
			for (i = 0; i < dwItems; i++)
			{
				if ((*pW & 0xFFF) == 0xdb1)
					__asm NOP
				if ((*pW >> 12) == IMAGE_REL_BASED_HIGHLOW)
					*(PDWORD)((DWORD)pPEI + pIBR->VirtualAddress + (*pW & 0xFFF)) +=
						dwDelta;
				++pW; // next relocation item
			}
			// set pIBR where another block could start
			pIBR = MakePtr(PIMAGE_BASE_RELOCATION, pIBR, pIBR->SizeOfBlock);
		}
	}
	catch(...)
	{
		if (pPEI)
			VFree(pPEI);
		if (piVirtual)
			delete piVirtual;
		printf("!! Access violation...\n");
		return NULL; // ERR
	}

ErrorOccurred:
	//
	// cleanup
	//
	if (piVirtual)
		delete piVirtual;

	return pPEI;
}

void* VAlloc(DWORD dwSize)
{
	return VirtualAlloc(NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
}

BOOL VFree(void* p)
{
	return VirtualFree(p, 0, MEM_RELEASE);
}

void ThreadEndStub()
{
	// signalize main thread that this thread is down
	InterlockedDecrement( (PLONG)&g_bWorkerThread );
	// exit worker thread
	ExitThread(0x1234);

	return;
}

//
// Args:
// pParam - EntryPtr
//
void __stdcall EntryThreadStub(void* pParam)
{
	try
	{
		OutputDebugString("InConEx: Executing client's EntryPoint in own thread...\n");
		__asm
		{
#if defined(DEBUG_CLIENT_EXEC)
			INT     3
#endif // DEBUG_CLIENT_EXEC
			// push routine entry because the app could exit via "RET"
			PUSH    OFFSET ThreadEndStub 
			JMP     pParam
			// ...this place should never be reached
		}
	}
	catch(...)
	{
		printf("!! Exception caught while executing virtual image...\n");
		//...
	}
	ThreadEndStub();
}

//
// Returns: handle of the new thread or NULL (error)
//
HANDLE ExecutePEImage(DWORD dwEntryPtr)
{
	printf("-> Executing virtual image in new thread...\n");
	CThread th;

	if (!th.Create(
		(LPTHREAD_START_ROUTINE)EntryThreadStub,
		(void*)dwEntryPtr,
		0))
		return NULL;

	return th.GetThreadHandle();
}

BOOL __stdcall ExitProcess_HookProc(PCH_LOC_HOOK_CALLBACK_INFO pinfo)
{
	// brutally kill current thread
	printf("-> Client passed ExitProcess hook...\n");
	OutputDebugString("InConEx: Client passed ExitProcess hook...\n");
	ThreadEndStub();

	// ...this code is never be reached
	return TRUE;
}

//
// patch windows intern variables and structures e.g. calling module path, base, size
//
// Returns:
// FALSE    - access violation
//
BOOL AdjustOperationSystemStructs(PMODULE_INFO_TO_ADJUST pinfo)
{
	static char        cClientDir[MAX_PATH];
	char               cCmdLine[1024];
	static WCHAR       wcCmdLine[1024];
	PPE_IMAGE          ppi;

	// fill buffers needed to adjust 9x and NT structs
	lstrcpy(cClientDir, pinfo->cExeFilePath);
	CPathString::PathToDir(cClientDir);
	wsprintf(cCmdLine, "\"%s\"", pinfo->cExeFilePath);
	WideChar::SingleToWideCharStr(
		cCmdLine,
		wcCmdLine,
		sizeof(wcCmdLine));

	try
	{
		if (_IsNT)
		{
			//
			// adjust NT internal structures
			//
			PPEB                     pPeb;
			PPEB_LDR_DATA            pLdrData;
			PLDR_ENTRY               pLdrEntry;
			PPROCESS_PARAMETERS      pProcArg;
			static WCHAR             wcFilePath[MAX_PATH];
			static WCHAR             wcBaseName[MAX_PATH];
			static WCHAR             wcClientDir[MAX_PATH];
			static UNICODE_STRING    usFilePath;
			static UNICODE_STRING    usBaseName;
			static UNICODE_STRING    usClientDir;
			static UNICODE_STRING    usCmdLine;

			//
			// adjusts PEB, LDR_ENTRY entry of calling module,
			// PROCESS_PARAMETERS
			//
			WideChar::SingleToWideCharStr(
				CPathString::ExtractFileName(pinfo->cExeFilePath),
				wcBaseName,
				sizeof(wcBaseName));
			WideChar::NtDllInitUnicodeString(
				&usBaseName, wcBaseName);

			WideChar::SingleToWideCharStr(
				pinfo->cExeFilePath,
				wcFilePath,
				sizeof(wcFilePath));
			WideChar::NtDllInitUnicodeString(
				&usFilePath, wcFilePath);

			WideChar::SingleToWideCharStr(
				cClientDir,
				wcClientDir,
				sizeof(wcClientDir));
			WideChar::NtDllInitUnicodeString(
				&usClientDir, wcClientDir);

			WideChar::NtDllInitUnicodeString(
				&usCmdLine, wcCmdLine);

			// process PEB
			__asm PUSH    FS:[0x30]
			__asm POP     pPeb
			pPeb->ImageBaseAddress = pinfo->ImageBase;

			// process PROCESS_PARAMETERS
			pProcArg = (PPROCESS_PARAMETERS)pPeb->ProcessParameters;
			pProcArg->ImagePath         = usFilePath;
			pProcArg->CurrentDirectory  = usClientDir;
			pProcArg->CommandLine       = usCmdLine;
			pProcArg->WindowTitle       = usFilePath;

			// process calling module's PEB_ENTRY
			pLdrData = (PPEB_LDR_DATA)pPeb->PebLdrData;
			pLdrEntry = (PLDR_ENTRY)pLdrData->InLoadOrderModuleListHead;
			pLdrEntry->ModuleSize     = pinfo->ImageSize;
			pLdrEntry->ModuleBase     = pinfo->ImageBase;
			pLdrEntry->ModuleFileName = usFilePath;
			pLdrEntry->ModuleBaseName = usBaseName;
			ppi = new PE_IMAGE((void*)pinfo->ImageBase, PI_MODE_VIRTUAL);
			pLdrEntry->EntryPoint     = pinfo->ImageBase +
				ppi->m_pNT->OptionalHeader.AddressOfEntryPoint;
			delete ppi;

		}
		else
		{
			//
			// adjust 9x internal structures
			//
			PPROCESS_DATABASE      pPDB;
			PIMTE                  *pModTable, pCallModIMTE;
			PENVIRONMENT_DATABASE  pEDB;
//			static char            cFullModPath[MAX_PATH];
//			static char            cModBaseName[MAX_PATH];
			char                   cShortPathName[MAX_PATH];
			DWORD                  dwCurBase;

			//
			// adjust 
			//
			__asm PUSH    FS:[0x30]
			__asm POP     pPDB;

			dwCurBase = (DWORD)GetModuleHandle(NULL);
			__asm MOV     pModTable, ECX
			__asm MOV     pCallModIMTE, EDX

			//
			// fix calling modules IMTE
			//
			pCallModIMTE->baseAddress = pinfo->ImageBase;
			// adjust windows's PE header
			ppi = new PE_IMAGE((void*)pinfo->ImageBase, PI_MODE_VIRTUAL);
			memcpy(
				(void*)pCallModIMTE->pNTHdr,
				(void*)ppi->m_pNT,
				4 + sizeof(IMAGE_FILE_HEADER) + 
				ppi->m_pNT->FileHeader.SizeOfOptionalHeader);
			// fix ImageBase by hand
			pCallModIMTE->pNTHdr->OptionalHeader.ImageBase = pinfo->ImageBase;

			//
			// fix short/long module names and paths
			// (the module base name pointers are just pointers into corresponding
			//  FilePath buffer)
			//

			// long file path
			lstrcpy(
				pCallModIMTE->pszFileName,
				pinfo->cExeFilePath);
			pCallModIMTE->cbFileName = lstrlen(pinfo->cExeFilePath) + 1;

			// long module name
			pCallModIMTE->pszModName = CPathString::ExtractFileName(pCallModIMTE->pszFileName);
			pCallModIMTE->cbModName  = lstrlen(pCallModIMTE->pszModName) + 1;

			// short file path
			GetShortPathName(
				pCallModIMTE->pszFileName,
				cShortPathName,
				sizeof(cShortPathName));
			lstrcpy(
				pCallModIMTE->pszFileName2,
				cShortPathName);
			pCallModIMTE->cbFileName2 = lstrlen(cShortPathName) + 1;

			// short module name
			pCallModIMTE->pszModName2 = CPathString::ExtractFileName(pCallModIMTE->pszFileName2);
			pCallModIMTE->cbModName2  = lstrlen(pCallModIMTE->pszModName2) + 1;

			delete ppi;

			// process ENVIRONMENT_DATABASE
			pEDB                      = pPDB->pEDB;
			pEDB->pszCurrDirectory    = cClientDir;
		}
		// Because on NT patching PROCESS_PARAMETERS.CommandLine doesn't
		// seems to give effects to client's GetCommandLineA/W calls
		// we patch the command line buffers directly.
		// On 9x patching ENVIRONMENT_DATABASE.pszCmdLine doesn't show
		// effects to GetCommandLineW calls :(
		PWCHAR pwcStr  = GetCommandLineW();
		lstrcpyW(pwcStr, wcCmdLine);
		PCHAR pcStr    = GetCommandLine();
		lstrcpyA(pcStr, cCmdLine);
	}
	catch(...)
	{
		return FALSE; // ERR
	}

	return TRUE; // OK
}