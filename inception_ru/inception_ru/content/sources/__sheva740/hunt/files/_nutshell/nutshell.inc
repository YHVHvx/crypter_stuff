memset			PROTO c:DWORD, :DWORD, :DWORD 
RemoteDeleteService		PROTO
RemoteStartService		PROTO
StdOutThread		PROTO
StdInThread		PROTO
StdErrThread		PROTO

.const
	IDM_SERVICE	EQU 100 
.data

	szHelp	db 'Usage: nutshell.exe \\comp /user:USERNAME /pwd:* /shell ',13,10
		db '  Nutshell installs and connects to a remote service on the target machine.',13,10
		db 'Only one instance of this service can be accessed at a time so no more than one user',13,10
		db 'can shell in at once.',13,10,0
	szlf		db 13,10,0

	szOpenConnADMIN	db 'Opening connection to ADMIN$...        ',0
	szOpenConnIPC	db 'Opening connection to IPC$...          ',0
	szDropService	db 'Dropping remote service to system32... ',0

	szOK		db '[OK]',13,10,0
	szFailed		db '[FAILED]',13,10,0
	szConnected	db '[CONNECTED]',13,10,0
	szNotRun		db '[NOT RUNNING]',13,10,0

	szCheckStat	db 'Checking service status...             ',0
	szStartService	db 'Starting remote service...             ',0
	szConnectService	db 'Connecting to remote service...        ',0
	szAdmin		db 'ADMIN$',0
	szIPC		db 'IPC$',0	


	lpszComputer	db [MAX_PATH] dup(0) 
	lpszUsername	db [MAX_PATH] dup(0) 
	lpszPassword	db [MAX_PATH] dup(0)
	lpszPathtoFile	db [MAX_PATH] dup(0) 

	szServiceEXE	db 'nutshell_service.exe',0
	szServiceName	db 'nutshell',0


	sznutshell_stdout	db 'nutshell_stdout',0
	sznutshell_stdin	db 'nutshell_stdin',0
	sznutshell_stderr	db 'nutshell_stderr',0

.code
;******************************************************************************** 
; void DisplayHelp()
; Input	- NULL
; Output	- Show help string
DisplayHelp proc
	invoke	StdOut, addr szHelp	
	ret
DisplayHelp endp
;******************************************************************************** 
;bool FindFlag(lpszFlag, lpszCommandLine)
; Input	- lpszFlag - sample for finding
;	- lpszCommandLine - pointer of command line
; Output	- bool TRUE or FALSE
FindFlag proc uses edi	lpszFlag:DWORD, lpszCommandLine:DWORD
	mov	edi,lpszCommandLine
	mov	esi,lpszFlag
	invoke	lstrlen, lpszCommandLine
	mov	ecx,eax
___find:	cmp	byte ptr [edi], '/'
	jne	___next1
	pushad	
	inc	edi
	invoke	lstrcmp, edi,lpszFlag
	.if	eax == 0
		xor	eax,eax
		mov	eax,1
		ret
	.endif
	popad
___next1:	cmp	byte ptr [edi], '-'
	jne	___next2
	pushad	
	inc	edi
	invoke	lstrcmp, edi,lpszFlag
	.if	eax == 0
		xor	eax,eax
		mov	eax,1
		ret
	.endif
	popad
___next2:	inc	edi
	loop	___find
	xor	eax,eax
	ret
FindFlag endp

;********************************************************************************
;handle GetFlagValue(lpszFlag, lpszCommandLine, outbuff)
; Input	- lpszFlag - sample for finding
;	- lpszCommandLine - pointer of command line
; Output	- outbuff - handle of substring
.data
	szBlankChar	db 20h
.code
GetFlagValue proc 	lpszFlag:DWORD, lpszCommandLine:DWORD, outbuff:DWORD
local	temp[MAX_PATH]:BYTE

	invoke	memset, addr temp, 0, MAX_PATH
	invoke	lstrcpy, addr temp, lpszCommandLine
	invoke	lstrcat, addr temp, addr szBlankChar
	lea	edi,temp
	mov	esi,lpszFlag

	; тут в Stdlib - ошибка. Вместо StrPos в теле функции, в файле StrPos.asm,
	; стоит код функции StrStr. Ошибка наверное.
	; так что используем StrStr но держим StrPos в уме
	invoke	StrStr, addr temp, lpszFlag 
	.if	eax!=-1
		add	edi,eax
		invoke	lstrlen, lpszFlag
		add	edi,eax
		push	edi	
		invoke	lstrlen, edi
		mov	ecx,eax
__setZero:	cmp	byte ptr [edi],20h	; 20h - пробел 
		je	__pachStr
		inc	edi
		loop	__setZero
__pachStr:	mov	byte ptr [edi],0 ;
		pop	edi
		.if	outbuff != 0	
			invoke	lstrcpy, outbuff, edi
		.endif
		xor	eax,eax
		inc	eax		
		ret
	.else
		xor	eax,eax
		ret	
	.endif

GetFlagValue endp
;******************************************************************************** 
;void InputPassword(lpszPass, dwbuffSize)
; Input	- lpszPass - string for input pwd
;	- dwbuffSize - size of lpszPass
; Output	- filing fo lpszPass
InputPassword proc 	lpszPass:DWORD, dwbuffSize:DWORD
local	dwRet:DWORD
local	dwMode:DWORD
local	hStdIn:DWORD
	invoke	GetStdHandle, STD_INPUT_HANDLE
	mov	hStdIn, eax

	invoke	GetConsoleMode, hStdIn, addr dwMode; сохранение флагов
	mov	edx, dwMode
	and	edx, -5
	mov	dwMode, edx
	invoke	SetConsoleMode, hStdIn, dwMode; отмена режима эхо-вывода
	; в dwRet -длина введенного пароля + 2 (0ah, 0dh) 
	invoke	ReadConsole, hStdIn, lpszPass, dwbuffSize, addr dwRet, NULL	
	mov	edx,dwRet
	sub	edx,2
	mov	edi,lpszPass
	mov	byte ptr [edi+edx],0
	mov	byte ptr [edi+edx+1],0	

	mov	eax, dwMode
	or	al, 4		;dwMode |= ENABLE_ECHO_INPUT;		
	mov	dwMode, eax
	invoke	SetConsoleMode, hStdIn, dwMode ; восстановление режима
	invoke	StdOut, addr szlf
	ret
InputPassword endp


;******************************************************************************** 
;void ShowUsersList()
; Input	- NULL
; Output	- list of local users 
.data
ui		USER_INFO_1 <>
lf		db 13,10,0

.data?
entries_read	dd ?
entries_total	dd ?
resume_hndl	dd ?

.code
ShowUsersList proc 
local tmpstr[256]:BYTE
local cyrBuffer[256]:BYTE

	invoke	NetUserEnum, 0, 1,FILTER_NORMAL_ACCOUNT,\
			offset ui,\
			MAX_PREFERRED_LENGTH,\
			offset entries_read,\
			offset entries_total,\
			offset resume_hndl
	xor	ecx,ecx
	mov	esi,dword ptr ui

@@:	mov	edi,[esi]

	push	ecx
	push	esi
	invoke	WideCharToMultiByte, CP_ACP, 0, \
		edi,  -1, addr tmpstr, \
		256,  NULL, NULL
 
	invoke	CharToOem, addr tmpstr,addr cyrBuffer 
	invoke	StdOut, addr cyrBuffer
	invoke	StdOut, addr lf	
	pop	esi
	pop	ecx

	inc	ecx
	add	esi,sizeof USER_INFO_1
	cmp	ecx,entries_read
	jb	@b

	invoke	NetApiBufferFree,offset ui
	ret	
ShowUsersList endp

;******************************************************************************** 
;void WNetConnection(lpszMachine, lpszShare, bEstablish)
; Input	- lpszMachine
; Input	- lpszShare
; Input	- bEstablish
; Output	- set connection whith some resource
.data
	szNetAddrFormat	db '\\%s\%s',0
.code
WNetConnection	proc	lpszMachine:DWORD, lpszShare:DWORD, bEstablish:BYTE
local	nr: NETRESOURCE
local	lpszNetworkResource[128]: BYTE

	invoke	wsprintf, addr lpszNetworkResource, addr szNetAddrFormat,\
					lpszMachine,\
					lpszShare
	.if	(bEstablish)

		assume	edi:ptr NETRESOURCE
		lea	edi,nr
		mov	[edi].dwType, RESOURCETYPE_ANY    
		mov	[edi].lpLocalName, NULL
		lea	esi,lpszNetworkResource
		mov	[edi].lpRemoteName, esi
		mov	[edi].lpProvider,NULL

		invoke	WNetAddConnection2, addr nr,\
				addr lpszPassword,\
				addr lpszUsername,\
				NULL
		.if	eax != NO_ERROR
			xor	eax,eax
			dec	eax
			ret
		.endif
		
	.else
		invoke	WNetCancelConnection2, addr lpszNetworkResource,\
				0, TRUE
	.endif
	xor	eax,eax
	ret
WNetConnection	endp

;******************************************************************************** 
;BOOL RemoteResourceDrop()
; Input	- NULL
; Output	- unpach file on remote resource 
.data
	szRemoteSystem32Path	db '\\%s\ADMIN$\system32\%s',0
	sztype			db 'BIN',0
.code
RemoteResourceDrop	proc
local	hInstance:DWORD
local	hRes:DWORD
local	hResLoaded:DWORD
local	lpService:DWORD
local	dwSize:DWORD
local	lpszServicePath[256]:BYTE
local	hFile:DWORD
local	dwRet:DWORD

	invoke	GetModuleHandle,NULL
	mov	hInstance,eax
	invoke	FindResource, hInstance, IDM_SERVICE, addr sztype
	.if	eax == 0
		xor	eax,eax
		mov	eax,-1
		ret
	.endif
	mov	hRes,eax
	invoke	LoadResource,hInstance, hRes
	mov	hResLoaded ,eax
	invoke	LockResource,hResLoaded
	mov	lpService,eax
	invoke	SizeofResource,hInstance,hRes
	mov	dwSize,eax

	invoke	wsprintf, addr lpszServicePath, addr szRemoteSystem32Path,\
					addr lpszComputer,\
					addr szServiceEXE


	invoke	CreateFile, addr lpszServicePath, GENERIC_WRITE, \
				0, NULL, \
				CREATE_ALWAYS, \
				FILE_ATTRIBUTE_NORMAL, \
				NULL
	mov	hFile, eax
	.if	eax != INVALID_HANDLE_VALUE
		invoke	WriteFile, hFile, lpService, dwSize, addr dwRet,NULL
		invoke	CloseHandle, hFile
	.else
		xor	eax,eax
		mov	eax,-1
		ret	
	.endif	


	invoke	Sleep, 100


	invoke	FreeResource,hResLoaded
	xor	eax,eax
	ret
RemoteResourceDrop	endp
;******************************************************************************** 
;BOOL ConnectToService(nRetry,DWORD)
; Input	- nRetry		- number of attempts
; Input	- nTimeOut	- timeout for waiting
; Output	- get connection
.data
	szPipePath	db '\\%s\pipe\%s',0
.data
	nutshell_StdOut	dd INVALID_HANDLE_VALUE
	nutshell_StdIn	dd INVALID_HANDLE_VALUE
	nutshell_StdErr	dd INVALID_HANDLE_VALUE
.code
ConnectToService	proc nRetry:DWORD, nTimeOut:DWORD
local lpszStdOut[MAX_PATH]:BYTE
local lpszStdIn[MAX_PATH]:BYTE
local lpszStdErr[MAX_PATH]:BYTE
local sa:SECURITY_ATTRIBUTES
local sd:SECURITY_DESCRIPTOR

	invoke	memset, addr lpszStdOut, 0, MAX_PATH
	invoke	memset, addr lpszStdIn,  0, MAX_PATH
	invoke	memset, addr lpszStdErr, 0, MAX_PATH

	invoke	wsprintf, addr lpszStdOut, addr szPipePath,\
					addr lpszComputer,\
					addr sznutshell_stdout

	invoke	wsprintf, addr lpszStdIn, addr szPipePath,\
					addr lpszComputer,\
					addr sznutshell_stdin

	invoke	wsprintf, addr lpszStdErr, addr szPipePath,\
					addr lpszComputer,\
					addr sznutshell_stderr

	invoke	memset, addr sa, 0, sizeof SECURITY_ATTRIBUTES
	invoke	memset, addr sd, 0, sizeof SECURITY_DESCRIPTOR

	invoke	InitializeSecurityDescriptor, addr sd, \
				SECURITY_DESCRIPTOR_REVISION
	invoke	SetSecurityDescriptorDacl, addr sd, \
				TRUE, NULL, FALSE
	lea	edi,sd
	mov	sa.lpSecurityDescriptor, edi
	mov	sa.nLength, sizeof SECURITY_ATTRIBUTES
	mov	sa.bInheritHandle, TRUE

	xor	ecx,ecx
	mov	ecx,nRetry
	.while	ecx
		push	ecx
		.if	nutshell_StdOut == INVALID_HANDLE_VALUE
			invoke	WaitNamedPipe, addr lpszStdOut, NULL
			.if	eax !=0
				invoke	CreateFile, addr lpszStdOut, \
					GENERIC_READ, \
					0, \
					addr sa, \
					OPEN_EXISTING, \
					FILE_ATTRIBUTE_NORMAL, \
					NULL
				mov	nutshell_StdOut,eax	
			.endif
		.endif

		.if	nutshell_StdIn == INVALID_HANDLE_VALUE
			invoke	WaitNamedPipe, addr lpszStdIn, NULL
			.if	eax !=0
				invoke	CreateFile, addr lpszStdIn, \
					GENERIC_WRITE, \
					0, \
					addr sa, \
					OPEN_EXISTING, \
					FILE_ATTRIBUTE_NORMAL, \
					NULL
				mov	nutshell_StdIn,eax	
			.endif
		.endif

		.if	nutshell_StdErr == INVALID_HANDLE_VALUE
			invoke	WaitNamedPipe, addr lpszStdErr, NULL
			.if	eax !=0
				invoke	CreateFile, addr lpszStdErr, \
					GENERIC_READ, \
					0, \
					addr sa, \
					OPEN_EXISTING, \
					FILE_ATTRIBUTE_NORMAL, \
					NULL
				mov	nutshell_StdErr,eax	
			.endif


		.endif

		.if	(nutshell_StdOut != INVALID_HANDLE_VALUE)&& \
			(nutshell_StdIn  != INVALID_HANDLE_VALUE)&& \
			(nutshell_StdErr != INVALID_HANDLE_VALUE)
			.break

		.endif

		invoke	Sleep, nTimeOut
		pop	ecx
		dec	ecx	
	.endw

	.if	(nutshell_StdOut == INVALID_HANDLE_VALUE)|| \
		(nutshell_StdIn  == INVALID_HANDLE_VALUE)|| \
		(nutshell_StdErr == INVALID_HANDLE_VALUE)

		invoke	CloseHandle, nutshell_StdOut
		invoke	CloseHandle, nutshell_StdIn
		invoke	CloseHandle, nutshell_StdErr
		xor	eax,eax
		mov	eax,-1
		ret
	.endif
		
	invoke	CreateThread, NULL, 0, offset StdOutThread, NULL, 0, NULL
	invoke	CreateThread, NULL, 0, offset StdInThread,  NULL, 0, NULL
	invoke	CreateThread, NULL, 0, offset StdErrThread, NULL, 0, NULL
	xor	eax,eax
	ret
ConnectToService	endp

;******************************************************************************** 
;StdOutThread()
; Input	- 
; Output	- 
StdOutThread	proc
local	lpszBuff[MAX_PATH]:BYTE
local	dwRet:DWORD

	.while	bExitFlag != 1
		invoke	memset, addr lpszBuff, 0, MAX_PATH
		invoke	ReadFile, nutshell_StdOut, addr lpszBuff, MAX_PATH, addr dwRet, NULL
		.if	eax || dwRet == 0
			invoke	GetLastError
			.if	eax == 	ERROR_NO_DATA
				.break
			.endif
		.endif
		invoke	StdOut, addr lpszBuff
	.endw
	invoke	CloseHandle, nutshell_StdOut
	mov	eax,INVALID_HANDLE_VALUE
	mov	nutshell_StdOut,eax
	xor	eax,eax
	ret
StdOutThread	endp

;******************************************************************************** 
;StdInThread()
; Input	- 
; Output	- 
.data
	szExit	db 'exit',13,10,0
.code
StdInThread	proc
local	lpszBuff[MAX_PATH]:BYTE
local	dwRead:DWORD
local	dwWrote:DWORD
local	hStdIn:DWORD

	invoke	GetStdHandle, STD_INPUT_HANDLE
	mov	hStdIn, eax
	.while	bExitFlag != 1
		invoke	memset, addr lpszBuff, 0, MAX_PATH
		invoke	ReadConsole, hStdIn, addr lpszBuff, MAX_PATH, addr dwRead, NULL
		.if	!eax 
			invoke	GetLastError
			.if	eax == 	ERROR_NO_DATA
				.break
			.endif
		.endif
		invoke	WriteFile, nutshell_StdIn, addr lpszBuff, dwRead, addr dwWrote, NULL
		.if	!eax 
			.break
		.endif
		invoke	lstrcmp	,addr lpszBuff, addr szExit
		.if	eax == 0
			mov	bExitFlag, 1
			invoke	RemoteDeleteService 
			.break
		.endif	
	.endw
	invoke	CloseHandle, nutshell_StdIn
	mov	eax, INVALID_HANDLE_VALUE
	mov	nutshell_StdIn,eax
	xor	eax, eax
	ret
StdInThread	endp

;******************************************************************************** 
;StdErrThread()
; Input	- 
; Output	- 
StdErrThread	proc
local	lpszBuff[MAX_PATH]:BYTE
local	dwRet:DWORD

	.while	bExitFlag != 1
		invoke	memset, addr lpszBuff, 0, MAX_PATH
		invoke	ReadFile, nutshell_StdErr, addr lpszBuff, MAX_PATH, addr dwRet, NULL
		.if	eax || dwRet == 0
			invoke	GetLastError
			.if	eax == 	ERROR_NO_DATA
				.break
			.endif
		.endif
		invoke	StdOut, addr lpszBuff
	.endw
	invoke	CloseHandle, nutshell_StdErr
	mov	eax,INVALID_HANDLE_VALUE
	mov	nutshell_StdErr,eax
	xor	eax,eax
	ret
StdErrThread	endp

;******************************************************************************** 
;RemoteStartService()
; Input	- 
; Output	- 
.data
	szServiceSYS32Path	db '%s\nutshell_service.exe',0
	szSleshTempl	db '\\%s',0	
.code
RemoteStartService	proc
local	lpszBuff[MAX_PATH]:BYTE
local	lpszTemp[MAX_PATH]:BYTE
local	lpszTempBuff[MAX_PATH]:BYTE
local	hSCM:DWORD
local	hService:DWORD
local	dwRet:DWORD

	invoke	memset, addr lpszBuff, 0, MAX_PATH
	invoke	memset, addr lpszTempBuff,  0, MAX_PATH
	invoke	memset, addr lpszTemp,  0, MAX_PATH

	invoke	GetSystemDirectory, addr lpszTempBuff, MAX_PATH
	invoke	wsprintf, addr lpszBuff, addr szServiceSYS32Path, \
					addr lpszTempBuff
	invoke	wsprintf, addr lpszTemp, addr szSleshTempl, \
					addr lpszComputer

	invoke	OpenSCManager, addr lpszTemp, NULL, SC_MANAGER_ALL_ACCESS
	mov	hSCM, eax
	.if	eax == NULL
		xor	eax,eax
		mov	eax,-1
		ret
	.endif

	invoke	OpenService, hSCM, addr szServiceName, SERVICE_ALL_ACCESS
	mov	hService, eax
	.if	eax == NULL
		invoke	CreateService, hSCM,addr szServiceName, \
				addr szServiceName, \
				SERVICE_ALL_ACCESS, \
				SERVICE_WIN32_OWN_PROCESS, \
				SERVICE_DEMAND_START, \
				SERVICE_ERROR_NORMAL, \
				addr lpszBuff, \
				NULL,NULL, \
				NULL,NULL, \
				NULL
		mov	hService, eax
	.endif

	.if	hService == NULL
		invoke	CloseServiceHandle, hSCM 
		xor	eax,eax
		mov	eax,-1
		ret
	.endif

	invoke	StartService, hService, 0, NULL
	mov	dwRet,eax
	invoke	CloseServiceHandle, hService
	invoke	CloseServiceHandle, hSCM
 	xor	eax,eax
	ret
RemoteStartService	endp

;******************************************************************************** 
;RemoteDeleteService()
; Input	- 
; Output	- 
RemoteDeleteService	proc
local	hSCM:DWORD
local	hService:DWORD
	invoke	OpenSCManager, addr lpszComputer, NULL, SC_MANAGER_ALL_ACCESS
	mov	hSCM, eax
	.if	eax 
		invoke	OpenService, hSCM, addr szServiceName, SERVICE_ALL_ACCESS
		mov	hService, eax
		.if	eax == NULL
			invoke	DeleteService, hService
		.endif
		invoke	CloseServiceHandle, hService
		invoke	CloseServiceHandle, hSCM 
	.endif
	ret
RemoteDeleteService	endp
;******************************************************************************** 
;doShell()
; Input	- 
; Output	- 
doShell	proc
	invoke	StdOut, addr szOpenConnADMIN	; Opening connection to ADMIN$...			;
	invoke	WNetConnection, addr lpszComputer, addr szAdmin, 1; ADMIN$	
	.if	eax == 0
			invoke	StdOut, addr szOK		; [OK]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
	.endif

	invoke	StdOut, addr szOpenConnIPC	; Opening connection to IPC$...			;
	invoke	WNetConnection, addr lpszComputer, addr szIPC, 1	; IPC$	
	.if	eax == 0
			invoke	StdOut, addr szOK		; [OK]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
	.endif

	invoke	StdOut, addr szDropService	; Dropping remote service to system32...			;
	invoke	RemoteResourceDrop
	.if	eax == 0
			invoke	StdOut, addr szOK		; [OK]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
	.endif

	invoke	StdOut, addr szCheckStat	; Checking service status...			;
	invoke	ConnectToService, 1, 0
	.if	eax == 0
			invoke	StdOut, addr szConnected	; [CONNECTED]
			jmp	connected
	.else
			invoke	StdOut, addr szNotRun	; [NOT RUNNING]
	.endif


	invoke	StdOut, addr szStartService	; Starting remote service...			;
	invoke	RemoteStartService
	.if	eax == 0
			invoke	StdOut, addr szOK		; [OK]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
			jmp	cleanup
	.endif

	invoke	StdOut, addr szConnectService	; Connecting to remote service...
;int 3			;
	invoke	ConnectToService, 5, 1000
	.if	eax == 0
			invoke	StdOut, addr szConnected	; [CONNECTED]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
			jmp	cleanup
	.endif


connected:
	.while	(nutshell_StdOut != INVALID_HANDLE_VALUE) && \
		(nutshell_StdIn  != INVALID_HANDLE_VALUE) && \
		(nutshell_StdErr != INVALID_HANDLE_VALUE) 
		invoke	Sleep, 10
	.endw

cleanup:
	invoke	WNetConnection, addr lpszComputer, addr szAdmin, FALSE
	invoke	WNetConnection, addr lpszComputer, addr szIPC,   FALSE	
	invoke	StdOut, addr lf

	ret
doShell	endp
;******************************************************************************** 
;doMove()
; Input	- 
; Output	- 
.data
	;szOpenConnIPC	db 'Opening connection to IPC$...          ',0
	szNetAddrFormat2	db '\\%s\%s\System32\%s',0
	szFileCopy	db 'Moving file %s is...             ',0
.code
doMove	proc
local	lpszNetworkResource[MAX_PATH]: BYTE
local	lpszFileName[MAX_PATH]: BYTE
local	temp[MAX_PATH]: BYTE

	invoke	memset, addr lpszNetworkResource, 0, MAX_PATH
	invoke	memset, addr lpszFileName, 0, MAX_PATH


	invoke	wsprintf, addr lpszNetworkResource, addr szNetAddrFormat,\
					addr lpszComputer, \
					addr szIPC

	invoke	StdOut, addr szOpenConnIPC	; Opening connection to IPC$...
	invoke	WNetConnection, addr lpszComputer, addr szIPC, 1	; IPC$	
	.if	eax == 0
			invoke	StdOut, addr szOK		; [OK]
	.else
			invoke	StdOut, addr szFailed	; [FAILED]
	.endif

	invoke	memset, addr lpszNetworkResource, 0, MAX_PATH
	invoke	ExtractFileName, addr lpszPathtoFile, addr lpszFileName 

	invoke	wsprintf, addr lpszNetworkResource, addr szNetAddrFormat2,\
					addr lpszComputer, \
					addr szAdmin, \
					addr lpszFileName	
	invoke	memset, addr temp, 0, MAX_PATH

	invoke	ExtractFileName, addr lpszPathtoFile, addr lpszFileName 
	invoke	wsprintf, addr temp, addr szFileCopy, addr lpszFileName

	invoke	StdOut, addr temp
	invoke	CopyFile, addr lpszPathtoFile, addr lpszNetworkResource,FALSE
	.if eax == 0
			invoke	StdOut, addr szFailed	; [FAILED]
	.else
			invoke	StdOut, addr szOK		; [OK]
	.endif
	invoke	WNetConnection, addr lpszComputer, addr szIPC,   FALSE	
	invoke	StdOut, addr lf
	ret
doMove	endp
;******************************************************************************** 