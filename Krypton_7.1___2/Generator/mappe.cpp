#include <Windows.h>
#include <WinNT.h>
#include "mappe.h"
#include "common.h"
#include "init.h"


DWORD MapPE(char* szExeFile, DWORD* Entry)
{
	DWORD dwTemp , i;
	DWORD PEMagic;
	IMAGE_DOS_HEADER		ImageDosHeader={0};
	IMAGE_FILE_HEADER		ImageFileHeader={0};
	IMAGE_OPTIONAL_HEADER	ImageOptionalHeader={0};
	IMAGE_SECTION_HEADER*	pImageSectionHeader=0;
	char szBuf[260];


	HANDLE hFile = CreateFile(szExeFile, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if(hFile == INVALID_HANDLE_VALUE){
		Log("Can't open %s\r\n", szExeFile);
		return 0;
	}

	ReadFile(hFile, &ImageDosHeader, sizeof(IMAGE_DOS_HEADER), &dwTemp, 0);
	SetFilePointer(hFile, ImageDosHeader.e_lfanew, 0, FILE_BEGIN);

	ReadFile(hFile, &PEMagic, 4, &dwTemp, 0);
	ReadFile(hFile, &ImageFileHeader, sizeof(IMAGE_FILE_HEADER), &dwTemp, 0);

	Log("**IMAGE_FILE_HEADER**\r\n");
	Log("NumberOfSections     :%x\r\n", (DWORD)ImageFileHeader.NumberOfSections);
	Log("SizeOfOptionalHeader :%x\r\n\r\n", (DWORD)ImageFileHeader.SizeOfOptionalHeader);

	ReadFile(hFile, &ImageOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), &dwTemp, 0);

	Log("**IMAGE_OPTIONAL_HEADER**\r\n");
	Log("ImageBase           : %x\r\n", ImageOptionalHeader.ImageBase);
	Log("AddressOfEntryPoint : %x\r\n", ImageOptionalHeader.AddressOfEntryPoint);
	Log("SectionAlignment    : %x\r\n", ImageOptionalHeader.SectionAlignment);
	Log("FileAlignment       : %x\r\n", ImageOptionalHeader.FileAlignment);
	Log("SizeOfImage         : %x\r\n", ImageOptionalHeader.SizeOfImage);
	Log("\r\n");

	pImageSectionHeader = (IMAGE_SECTION_HEADER*)MemAlloc(ImageFileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
	SetFilePointer(hFile, ImageDosHeader.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER) + ImageFileHeader.SizeOfOptionalHeader, 0, FILE_BEGIN);
	ReadFile(hFile, pImageSectionHeader, ImageFileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), &dwTemp, 0);

	for(i = 0; i < ImageFileHeader.NumberOfSections; i++){
		Log("**SECTION: %d**\r\n", i);
		Log("VirtualSize      : %x\r\n",pImageSectionHeader[i].Misc.VirtualSize);
		Log("VirtualAddress   : %x\r\n",pImageSectionHeader[i].VirtualAddress);
		Log("SizeOfRawData    : %x\r\n",pImageSectionHeader[i].SizeOfRawData);
		Log("PointerToRawData : %x\r\n",pImageSectionHeader[i].PointerToRawData);
		Log("Characteristics  : %x\r\n\r\n",pImageSectionHeader[i].Characteristics);
	}
	Log("\r\n");

	DWORD size = ALIGN_UP(ImageOptionalHeader.SizeOfImage, ImageOptionalHeader.SectionAlignment);
	//str2log("SizeOfImage %x\r\n", size);
	DWORD BaseAddr = (DWORD)VirtualAlloc((LPVOID)ImageOptionalHeader.ImageBase, ALIGN_UP(ImageOptionalHeader.SizeOfImage, ImageOptionalHeader.SectionAlignment), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if(BaseAddr == 0){
		Log("Memory for image alloc error\r\n");
		return 0;
	}
	else if(BaseAddr != ImageOptionalHeader.ImageBase){
		Log("Warning! BaseAddr != Allocated addr\r\n");
	}
	else{
		Log("Memory for image allocated\r\n");
	}

	DWORD FirstSectionVA = pImageSectionHeader[0].VirtualAddress;

	//Find section with minimum raw offset
	DWORD MinRawOffs = -1;
	for(i = 0; i < ImageFileHeader.NumberOfSections; i++){
		DWORD SectionRawOffset = pImageSectionHeader[i].PointerToRawData;
		if((SectionRawOffset != 0) && (SectionRawOffset < MinRawOffs)) MinRawOffs = SectionRawOffset;
	}

	DWORD RawHeaderLen = ALIGN_UP(MIN(FirstSectionVA, MinRawOffs), ImageOptionalHeader.FileAlignment);
	Log("Header size on file: %x\r\n", RawHeaderLen);

	//Map PE
	//Header
	SetFilePointer(hFile, 0, 0, FILE_BEGIN);
	ReadFile(hFile, (LPVOID)BaseAddr, RawHeaderLen, &dwTemp, 0);

	//Sections
	for(i = 0; i < ImageFileHeader.NumberOfSections; i++){
		Log("Map section : %d\r\n", i);
		if(pImageSectionHeader[i].SizeOfRawData != 0 && pImageSectionHeader[i].PointerToRawData != 0){//Section are presented on disk

			DWORD SectionFileOffset = pImageSectionHeader[i].PointerToRawData;

			SetFilePointer(hFile, SectionFileOffset, 0, FILE_BEGIN);

			DWORD SectionVA = BaseAddr + pImageSectionHeader[i].VirtualAddress;
			DWORD SectionFileSize=ALIGN_UP(pImageSectionHeader[i].SizeOfRawData, ImageOptionalHeader.FileAlignment);
			Log("File     Offset : %x\r\n", SectionFileOffset);
			Log("File     Size   : %x\r\n", SectionFileSize);
			Log("Virtual Address : %x\r\n", SectionVA);

			ReadFile(hFile, (LPVOID)(SectionVA), SectionFileSize, &dwTemp, 0);
		}
		else{
			Log("Section not present on file\r\n");
		}
		Log("\r\n");
	}
	CloseHandle(hFile);


	//Process imports if present in file
	if(ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress){
		ProcessImports(BaseAddr, (IMAGE_IMPORT_DESCRIPTOR*)(BaseAddr+ImageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress));
	}

	if(ImageOptionalHeader.Subsystem == 3) AllocConsole();//Create console for CUI applications
	
	KPEB* pKPEB=0;
	__asm{
		mov eax, fs:[0x30]
		mov	pKPEB, eax
	}
	pKPEB->ImageBaseAddress = BaseAddr;

	//Change LDR_MODULE
	LDR_MODULE* pModule=(LDR_MODULE*)pKPEB->Ldr->InLoadOrderModuleList.Flink;
	pModule->BaseAddress = BaseAddr;
	pModule->EntryPoint = BaseAddr + ImageOptionalHeader.AddressOfEntryPoint;
	pModule->SizeOfImage=ImageOptionalHeader.SizeOfImage;
	pModule->TimeDateStamp=ImageFileHeader.TimeDateStamp;

/*	int err;
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	new (GetProcAddress(hKernel32, "GetCommandLineA"), Fake_GetCommandLineA, &err, -1) KHOOK;
	new (GetProcAddress(hKernel32, "GetCommandLineW"), Fake_GetCommandLineW, &err, -1) KHOOK;

	pHook_GetModuleFileNameA = new (GetProcAddress(hKernel32, "GetModuleFileNameA"), Fake_GetModuleFileNameA, &err, -1) KHOOK;
	pHook_GetModuleFileNameW = new (GetProcAddress(hKernel32, "GetModuleFileNameW"), Fake_GetModuleFileNameW, &err, -1) KHOOK;
*/
	*Entry = BaseAddr + ImageOptionalHeader.AddressOfEntryPoint;
}


DWORD ProcessImports(DWORD ImageBase, IMAGE_IMPORT_DESCRIPTOR* pImport){
	PIMAGE_THUNK_DATA			pThunkDataIn	= NULL;
	PIMAGE_THUNK_DATA			pThunkDataOut	= NULL;
	PIMAGE_IMPORT_BY_NAME		pImpotByName	= NULL;
	HMODULE hDLL = 0;

	if(pImport->OriginalFirstThunk){
		while(pImport->OriginalFirstThunk){
			char* szDll = (char*)(DWORD_PTR)(pImport->Name + ImageBase);
			hDLL = GetModuleHandleA(szDll);
			if(!hDLL) hDLL = LoadLibraryA(szDll);

			pThunkDataIn  = (PIMAGE_THUNK_DATA)(DWORD_PTR)(pImport->OriginalFirstThunk + ImageBase);
			pThunkDataOut = (PIMAGE_THUNK_DATA)(DWORD_PTR)(pImport->FirstThunk + ImageBase);


			DWORD* pIAT=(DWORD*)pThunkDataOut;
			DWORD FuncVA=0;
			while(pThunkDataIn->u1.Function){
				if(pThunkDataIn->u1.Ordinal & IMAGE_ORDINAL_FLAG){//Import By Ordinal
					FuncVA = (DWORD)GetProcAddress(hDLL, MAKEINTRESOURCEA(pThunkDataIn->u1.Ordinal));
				}
				else{//Import By Name
					pImpotByName = (PIMAGE_IMPORT_BY_NAME)(DWORD_PTR)(pThunkDataIn->u1.AddressOfData + ImageBase);
					FuncVA = (DWORD)GetProcAddress(hDLL, (char*)pImpotByName->Name);
				}
				//Patch
				*pIAT = FuncVA;

				pThunkDataIn++;
				pThunkDataOut++;
				pIAT++;
			}
			pImport++;
		}
	}
	else if(pImport->FirstThunk){
		while(pImport->FirstThunk){
			char* szDll = (char*)(DWORD_PTR)(pImport->Name + ImageBase);
			hDLL = GetModuleHandleA(szDll);
			if(!hDLL) hDLL = LoadLibraryA(szDll);

			pThunkDataIn  = (PIMAGE_THUNK_DATA)(DWORD_PTR)(pImport->FirstThunk + ImageBase);
			pThunkDataOut = pThunkDataIn;


			DWORD* pIAT=(DWORD*)pThunkDataOut;
			DWORD FuncVA=0;
			while(pThunkDataIn->u1.Function){
				if(pThunkDataIn->u1.Ordinal & IMAGE_ORDINAL_FLAG){//Import By Ordinal
					FuncVA = (DWORD)GetProcAddress(hDLL, MAKEINTRESOURCEA(pThunkDataIn->u1.Ordinal));
				}
				else{//Import By Name
					pImpotByName = (PIMAGE_IMPORT_BY_NAME)(DWORD_PTR)(pThunkDataIn->u1.AddressOfData + ImageBase);
					FuncVA = (DWORD)GetProcAddress(hDLL, (char*)pImpotByName->Name);
				}
				//Patch
				*pIAT = FuncVA;

				pThunkDataIn++;
				pThunkDataOut++;
				pIAT++;
			}
			pImport++;
		}
	}
	return 0;
}
