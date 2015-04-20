#include "bin2code.h"
typedef void (WINAPI* _GenerateRubbishCode)(void* buf,DWORD dwSize, void* VirtAdr);
_GenerateRubbishCode __GenerateRubbishCode=NULL;
//********************************************************************************************
//LPSTR base64Encode(LPBYTE source, SIZE_T sourceSize, SIZE_T *destSize)
//{
//	LPBYTE dest = (LPBYTE)malloc(sourceSize * 8 + 1);
//	RtlZeroMemory();
//	DWORD dwSizeB64=0;
//	CryptBinaryToStringA((BYTE*)lpZData,dwFullSize,CRYPT_STRING_BASE64, NULL,&dwSizeB64);
//	if(dwSizeB64>dwFullSize) lpTempBuf=(char*)GlobalReAlloc(lpTempBuf,dwSizeB64,GMEM_ZEROINIT); else RtlZeroMemory(lpTempBuf,dwSizeB64);
//	//кодируем файл
//	if(CryptBinaryToStringA((BYTE*)lpZData,dwFullSize,CRYPT_STRING_BASE64,lpTempBuf,&dwSizeB64))
//	{
//		d=MAX_PATH;
//		//кодируем путь
//		char szName[MAX_PATH+1]={0};
//		if(CryptBinaryToStringA((BYTE*)lpszFileName,strlen(lpszFileName),CRYPT_STRING_BASE64,szName,&d))
//		{
//	#ifdef DBG
//			DPRINT("PLUGIN: %d - %d",dH,dwSizeB64);
//	#endif
//			BOOL re = FALSE;
//			while(!re)
//			{
//				re = funcPlugIn(2,NULL,szName,NULL,lpTempBuf,dwSizeB64);
//				if(!re) Sleep(1000);
//			}
//		}
//	}
//	GlobalFree(lpZData);
//}
//********************************************************************************************
LPSTR base64Encode(LPBYTE source, SIZE_T sourceSize, SIZE_T *destSize)
{
	static const char cb64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	DWORD dwSizeBuff = (sourceSize + 2) / 3 * 8 + 1;
	LPBYTE dest = (LPBYTE)malloc(dwSizeBuff);
	if(dest != NULL)
	{
		RtlZeroMemory(dest,dwSizeBuff);
		LPBYTE p = dest;
		BYTE cur[3];

		while(sourceSize > 0)
		{
			DWORD len = 0;
			for(DWORD i = 0; i < 3; i++)
			{
				if(sourceSize > 0)
				{
					sourceSize--;
					len++;
					cur[i] = source[i];
				}
				else cur[i] = 0;
			}

			source += 3;

			p[0] = cb64[cur[0] >> 2];
			p[1] = cb64[((cur[0] & 0x03) << 4) | ((cur[1] & 0xF0) >> 4)];
			p[2] = (BYTE)(len > 1 ? cb64[((cur[1] & 0x0F) << 2) | ((cur[2] & 0xC0) >> 6) ] : '=');
			p[3] = (BYTE)(len > 2 ? cb64[cur[2] & 0x3F] : '=');

			p += 4;
		}

		*p = 0;
		if(destSize)*destSize = (SIZE_T)(p - dest);
	}

	return (LPSTR)dest;
}
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
		if(GetModuleFileName(NULL,tmp1,MAX_PATH))
		{
			char* a = strrchr(tmp1,'\\')+1;
			strcpy(tmp2,a);
			strcat(tmp2,": ");
		}
		strcat(tmp2,tmp);
		OutputDebugString(tmp2);
		printf(tmp2);
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
	printf("Error: %s!\n",ers);
	DPRINT("Error: %s",ers);
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
	srand(xrand());
	static unsigned long x=xrand()^rand(),
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
	static unsigned long x=xrand()^rand()^123456789,y=362436069,z=521288629,w=88675123;
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
DWORD Compressor(IN PBYTE lpUBuffer,OUT PBYTE lpCBuffer,IN DWORD uc_size,IN DWORD c_size)
{
	ULONG ws_size, fs_size,res_size;
	NTSTATUS status= RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, &ws_size, &fs_size);
	if (NT_SUCCESS(status)) 
	{
		PVOID  workspace = (PVOID) malloc(ws_size);
		RtlZeroMemory(workspace,ws_size);
		if(workspace!=NULL)
		{
			RtlZeroMemory(lpCBuffer,c_size);
			status = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,lpUBuffer,
																	uc_size,lpCBuffer,c_size,0x1000,&res_size,workspace);
			free(workspace);
			if(NT_SUCCESS(status))
			{
				return res_size;
			} else __ERR("compressor");
		}
	}
	return 0;
}
//===========================================================================================
//********************************************************************************************
//МОРФИНГ

//Морфинг буфера с метками hlt,cli,cld */
BOOL Morpher(IN BOOL b_Morph,IN PBYTE lpBuffer,IN DWORD dwSz)
{
	BOOL bRet = FALSE;
	//Поиск маркеров в стабе
	int cnt = 0;
	BYTE bBuf[4096];
	DWORD jj=0;	//Счётчик Nop - ов + 3 байта hlt,cli,cld
	for(DWORD i=0;i<dwSz;i++)
	{
		//Поиск сигнатурных меток
		if(lpBuffer[i]==0xF4 && lpBuffer[i+1]==0xFA && lpBuffer[i+2]==0xFC)
		{
			//Подсчёт Nop - ов
			jj=3;
			while(lpBuffer[i+jj]==0x90 || (lpBuffer[i+jj]==0xC3 && lpBuffer[i+jj+1]==0xC3))
			{
				jj++;
			}
			if(b_Morph && __GenerateRubbishCode!=NULL)
			{
				//морфинг найденного блока, если задано
				memset(bBuf,0,sizeof(bBuf));
				__GenerateRubbishCode(bBuf,jj,0);
				memcpy(&lpBuffer[i],bBuf,jj);
				i+=jj;
			}
			else
			{
				//Затирание маркерв Nop-ами, если не задан морфинг
				lpBuffer[i]=0x90; lpBuffer[i+1]=0x90;	lpBuffer[i+2]=0x90;// lpBuffer[i+jj]=0x90;
			}
			cnt++;
			printf("Scomp: %2d Morphed code in offset: 0x%X, Size: %d\n",cnt,i,jj);
			bRet = TRUE;
		}
	}
	return bRet;
}
//===========================================================================================
//*******************************************************************************************
int main(int argc, char* argv[])
{
	DWORD dwRaznost;
	char szTarget[MAX_PATH];
	printf("LZNT1 Native compressor\t(c)2011 SYSENTER\n\n");
	printf("Usage: scomp.exe source1 source2 ... destination\n\n");
	if(argc<=1) __ERR("Number of arguments is invalid");
  char szCurDir[MAX_PATH+1]={0};
	GetModuleFileName(NULL, szCurDir, MAX_PATH);
	*(strrchr(szCurDir,'\\')+1) =0;
	SetCurrentDirectory(szCurDir);
	char szPluginDir[MAX_PATH]={0};
	char szCurDir2[MAX_PATH]={0};
	char szPmorph[MAX_PATH]={0};
	strcpy(szCurDir2,szCurDir);
	strcpy(szPluginDir,szCurDir2); strcat(szPluginDir,"PlugIn\\");
	strcpy(szPmorph,szPluginDir); strcat(szPmorph,"pmorph.dll");
	//MessageBoxA(NULL,szPmorph,0,0);
	HMODULE hMorph = LoadLibrary(szPmorph);
	if(hMorph)
	{
		__GenerateRubbishCode=(_GenerateRubbishCode)GetProcAddress(hMorph,"GenerateRubbishCode");
		if(__GenerateRubbishCode) printf("Scomp: Polymorh Engine Loaded\n");
	}
	int i = 0;
	int i_dest	=	argc - 1;			// destination index
	int c_sourc = i_dest - 1;		//number of input files
	HANDLE hFile;
	DWORD dwInFileSz={0};
	DWORD dwCmpSz={0};
	DWORD dwInTotalSz=0;
	DWORD dwOutTotalSz=0;
	LPBYTE lpInBuff;
	LPBYTE lpOutBuff;
	printf("Total file: %d\n", c_sourc);
	SCOMP scomp={0};
	OutputDebugString("Start cicle\n");
	//Calculate Buffer size
	i=0;
	printf("File: %s\tsize:",argv[i+1]);
	strcpy(szTarget,argv[i+1]);
	hFile = CreateFile(argv[i+1],GENERIC_READ,FILE_SHARE_READ, NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL, NULL);
		
	if(hFile == NULL || hFile == INVALID_HANDLE_VALUE) __ERR("open file");
	DPRINT("File: %s opened",argv[i+1]);
	dwInFileSz= GetFileSize(hFile,NULL);
	if(dwInFileSz<=0) __ERR("get file size");
	DPRINT("File size: %d\n",dwInFileSz);
	scomp.dwSzUncompBlock = dwInFileSz;
	lpInBuff= (LPBYTE)malloc(dwInFileSz);
	DWORD dwOutSz = 5* dwInFileSz;
	lpOutBuff = (LPBYTE)malloc(dwOutSz);
	if(lpInBuff==NULL || lpOutBuff==NULL) __ERR("allocate memory to file buffer");
	DPRINT("Memory Allocated\n");
	DWORD dwReaded=0;
	DPRINT("Try ReadFile\n");
	if(!ReadFile(hFile,lpInBuff,dwInFileSz,&dwReaded,NULL)) {printf("0x%.8X\n",GetLastError());__ERR("read file");}
	Morpher(TRUE,(PBYTE)lpInBuff,dwInFileSz);
	//Сохраняем базу и размер образа из хидера
	PIMAGE_DOS_HEADER pidh;
	PIMAGE_NT_HEADERS pinh;
	PIMAGE_OPTIONAL_HEADER32 ioh;
	pidh = (PIMAGE_DOS_HEADER)&lpInBuff[0];
	pinh = (PIMAGE_NT_HEADERS)&lpInBuff[pidh->e_lfanew];
	ioh = &(pinh->OptionalHeader);
	scomp.dwImageBase = ioh->ImageBase;
	scomp.dwSizeOfImage = ioh->SizeOfImage;
	
	DPRINT("ImgBase: 0x%X, ImgSize: %d\n",scomp.dwImageBase,scomp.dwSizeOfImage);
	DPRINT("Start compress\n");

	//dwCmpSz = dwInFileSz;
	dwCmpSz = Compressor(lpInBuff,lpOutBuff,dwInFileSz,dwOutSz);
	printf("Compressor: FirsOutByte=0x%X\n",lpOutBuff[0]);
	dwRaznost= dwInFileSz - dwCmpSz;

	printf("COMPRESS DELTA: %d\n",dwRaznost);
	dwInTotalSz = dwInTotalSz + dwInFileSz;
	dwOutTotalSz = dwOutTotalSz + dwCmpSz;
	scomp.dwSzCompBlock = dwCmpSz;
	//free(lpInBuff);
	CloseHandle(hFile);
	scomp.bXOR = xor128(1,255);
	printf("Total uncompressed size: %d byte\n", dwInTotalSz);
	printf("Total compressed size: %d byte\n", dwOutTotalSz);
	printf("Ratio: x%d\n",dwInTotalSz/dwOutTotalSz);
	DWORD dwStructSz = sizeof(SCOMP) + dwOutTotalSz;
	PSCOMP pCOMP =(PSCOMP) malloc(dwStructSz*12);
	if(pCOMP == NULL)__ERR("allocate memory to global buffer");
	RtlZeroMemory(pCOMP,dwStructSz*2);
	RtlCopyMemory(pCOMP,&scomp,sizeof(SCOMP));
	LPBYTE lpTmp =(LPBYTE)pCOMP + sizeof(SCOMP);
	DWORD delta=0;
	i = 0;
	{
		RtlCopyMemory(lpTmp,lpOutBuff,scomp.dwSzCompBlock);
		lpTmp = lpTmp + scomp.dwSzCompBlock;
		free(lpOutBuff);
	}
	DeleteFile(argv[i_dest]);
	printf("Start crypt with key:0x%X\n",scomp.bXOR);
	//Crypt full buff
	BYTE* lptmp = (BYTE*)pCOMP;
	DWORD k = 0;
	printf("Start crypt InFirstByte:0x%X\n",lptmp[0]);
	printf("Start crypt Size= %d\n",dwStructSz);
	for(k=1;k<dwStructSz;k++)
	{
		lptmp[k] = lptmp[k] ^ scomp.bXOR;
//		lptmp[k] = lptmp[k] ^ 0x94;
	}
	RtlCopyMemory(lptmp,&scomp,sizeof(SCOMP));
	printf("End crypt, OutFirstByte:0x%X\n",lptmp[0]);
	DWORD dwNewSz = dwStructSz;
	HANDLE hOutFile = CreateFile(argv[i_dest],GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ, NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);
	if(hOutFile == INVALID_HANDLE_VALUE) __ERR("create output file");
	DWORD dwWritten=0;
	if(!WriteFile(hOutFile,pCOMP,dwNewSz,&dwWritten,NULL))  __ERR("write output .bin file");
	FlushFileBuffers(hOutFile);
	CloseHandle(hOutFile);
	char szTxt[MAX_PATH]={0};
	sprintf(szTxt,"%s\\data2.h",szCurDir);//argv[i_dest]); strcat(szTxt,".h");
	char* pszB = (char*) malloc(dwNewSz*50);
	if(pszB == NULL ) __ERR("alloc mem");
	DPRINT("Mem for code Allocated");
	
	DeleteFile(szTxt);
	PROCESS_INFORMATION pi;
	STARTUPINFOA si;
	ZeroMemory(&si,sizeof(si));
	si.cb = sizeof(STARTUPINFOA);

	char szCmdLine[MAX_PATH];
	sprintf(szCmdLine,"%s data2.h C",argv[i_dest]);
	argv[1]=argv[i_dest];
	argv[2]="data2.h";
	argv[3]="C";
	sprintf(pszB,"/*Copyright (c)2010-2013 Sysenter*/\r\n//File: %s\r\n",szTarget);
	
	HANDLE hTxtFile = CreateFile(szTxt,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ, NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL, NULL);
	if(hTxtFile!=INVALID_HANDLE_VALUE) printf("File create\n\n");
	PBYTE pB = (BYTE*)(pCOMP);
	
	//Мусор
	DWORD dwMusor = 0;
	if(dwRaznost>0) dwMusor = 0;//xor128X(0.01*dwRaznost, 0.05*dwRaznost);//dwRaznost;//xor128X(0,0.07*dwStructSz);//ALIGN_UP(xor128X(0,0.07*dwStructSz),64);//xor128X(0,0.03*dwStructSz);//********************************************************
	if(dwMusor)
	{
		DPRINT("SCOMP ADDED: %d\r\n",dwMusor);
		LPBYTE lpBy = pB + dwStructSz +1;
		BYTE bRand = xor128(0,255);
		for(DWORD y=0;y<dwMusor;y++)
		{
			lpBy[y]= bRand;//0;//xor128(0,255);//
		}
		//__GenerateRubbishCode(lpBy,dwMusor,0);
		dwNewSz=dwNewSz+dwMusor;
	}

	DWORD dwT = 0;

	//********************************
	//В base64
	LPBYTE lpbOverScomp = pB+sizeof(SCOMP);
	DWORD dwInTo64 = dwNewSz-sizeof(SCOMP);
	DWORD dwCRC32 = RtlComputeCrc32(0,lpbOverScomp,dwInTo64);
	printf("base64Encode - OK: InSz=%d, FirstByteIn = 0x%X\n",dwInTo64,lpbOverScomp[0]);
	LPSTR lpbT = base64Encode(lpbOverScomp,dwInTo64,&dwT);
	printf("base64Encode - OK: InSz=%d, OutSz=%d, FirstByteOut = 0x%X\n",dwNewSz,dwT,lpbT[0]);
	memcpy(lpbOverScomp,lpbT,dwT);
	scomp.dwSzFull = dwT+sizeof(SCOMP);
	dwNewSz = scomp.dwSzFull;
	//********************************
	memcpy(pB,&scomp,sizeof(SCOMP));

	char TX[MAX_PATH];
	sprintf(TX,"#pragma data_seg (\".text\")\r\nDWORD dwCRC32 = 0x%p;\r\nDWORD dwSize2 = 0x%p;\r\nDWORD dwSizeFull64 = 0x%p;\r\n",dwCRC32,dwNewSz,dwT);
//	dwNewSz = dwT;
	strcat(pszB,TX);
	strcat(pszB,"char szGLOBAL2[]={");

	DWORD c = 0, cc = 0;
	DPRINT("Start generate code, len: %d\r\n",dwNewSz);
	for(k=0;k<dwNewSz;k++)
	{
		if(c>=16)
		{
			c=0;
			strcat(pszB,"\r\n");
		}
		char szT[24]={0};
		sprintf(szT,"0x%X",*(pB+k));
		if(cc>=512)	
		{
			cc=0;
			//printf("%d / %d, code: %s\n",k,dwNewSz,szT);
			WriteFile(hTxtFile,pszB,strlen(pszB),&dwWritten,NULL);
			pszB[0]=0;
		}
		strcat(pszB,szT);
		if(k!=dwNewSz-1) strcat(pszB,", ");
		c++; cc++;
	}
	strcat(pszB,"};\r\n#pragma data_seg ()");
	dwNewSz = strlen(pszB);
	printf("End cicle, len:%d\n",dwNewSz);
	DPRINT("End generate code, len:%d\n",dwNewSz);
	if(!WriteFile(hTxtFile,pszB,dwNewSz,&dwWritten,NULL))  __ERR("write output .cpp file");
	FlushFileBuffers(hTxtFile);
	CloseHandle(hTxtFile);
	printf("Total write: %d bytes\n\n",dwWritten);
	return 0;
}

