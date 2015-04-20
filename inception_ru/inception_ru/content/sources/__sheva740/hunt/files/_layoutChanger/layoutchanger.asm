.686
include	\masm32\include\masm32rt.inc
include	\masm32\include\mpr.inc
include	\masm32\include\advapi32.inc
include	\masm32\include\netapi32.inc
include	.\Stdlib\Stdlib.inc	
include	.\Stdlib\Stdlib.mac
include	\masm32\macros\macros.asm
include	totaltime.inc
includelib \masm32\lib\msvcrt.lib
includelib .\Stdlib\Stdlib.lib

includelib \masm32\lib\mpr.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\netapi32.lib

changeLayout	PROTO :DWORD, :DWORD
changeLayout2	PROTO :DWORD, :DWORD
DisplayHelp	PROTO
FindFlag		PROTO :DWORD, :DWORD
GetFlagValue	PROTO :DWORD, :DWORD, :DWORD
ShowUsersList	PROTO
memset		PROTO c:DWORD, :DWORD, :DWORD 
;******************************************************************************** 
align 4
.data?
hModuleHandle		DWORD ?
szFileName		BYTE MAX_PATH dup(?)

.data
crlf			BYTE 13,10,0
szResultFile		BYTE 'res.txt',0
szResultFileFormat		BYTE '%s',13,10,0

szNoDicFileErr		BYTE 'Sorry,dic file not exists.',0
szCreateFileMappingErr	BYTE 'CreateFileMapping Error!',0
szMapViewOfFileErr		BYTE 'MapViewOfFile Error!',0

szUsage			BYTE 'Usage: layoutChanger.exe /help',13,10,0
szHelpl			BYTE 'help',0
szHelp2			BYTE 'h',0
szHelp3			BYTE '?',0
ddFlag			DWORD 0

lpszPathtoFile		BYTE [MAX_PATH] dup(0) 
szPathtoFile		BYTE '/file:',0

.data
eng			BYTE "00000409"
rus			BYTE "00000419"

KEYBOARDSTATE struct
        keydata	BYTE 256 dup(0)
KEYBOARDSTATE ends

buffer BYTE 2 dup(0)

szBuff			BYTE MAX_PATH dup(0)
;szBuff1			BYTE MAX_PATH dup(0)
szRezLine			BYTE 13,10,40 dup('-'),13,10,0
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
		invoke	WriteFile,@hResultFile,offset szNoDicFileErr,sizeof szNoDicFileErr,addr @dwWritten,NULL
		jmp	_Error_Exit
	.endif
	mov	@hPswDic,eax

	invoke	GetFileSize,@hPswDic,NULL
	mov	@dwPswDicFileSize,eax
;**********CreateFileMapping**********
	invoke	CreateFileMapping,@hPswDic,NULL,PAGE_READONLY,0,0,NULL
	.if	eax==NULL
		invoke	WriteFile,@hResultFile,offset szCreateFileMappingErr,\
				sizeof szCreateFileMappingErr,addr @dwWritten,NULL
		jmp	_Error_Exit      
	.endif
	mov	@hPswDicFileMap,eax
;**********MapViewOfFile**********
	invoke	MapViewOfFile,eax,FILE_MAP_READ,0,0,0
	.if	eax==NULL
	invoke	WriteFile,@hResultFile,offset szMapViewOfFileErr,\
			sizeof szMapViewOfFileErr,addr @dwWritten,NULL
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
	@@:
		lodsb
		.if	al!=0dh
			stosb
			inc	ecx
			.if	ecx==@dwPswDicFileSize
				jmp	@F
			.elseif	ecx>@dwPswDicFileSize
				jmp	_NotFound
			.endif
			jmp	@B
		.endif
	@@:
		add	ecx,2
		xor	eax,eax
		stosw
      
		lea	eax,[esi+1]
		mov	@lpNext,eax

          	push	ecx

		invoke	RtlZeroMemory,addr szBuff,MAX_PATH
		;invoke	RtlZeroMemory,addr szBuff1,MAX_PATH

		invoke	changeLayout2, addr @szPswTmp , addr szBuff 
		invoke	StdOut, addr szBuff 
		invoke	StdOut, addr crlf
		invoke	lstrcat, addr szBuff, addr crlf	
		;invoke	wsprintf,addr szBuff1,offset szResultFileFormat,addr szBuff
		invoke	Sleep, 1		; даем время на выполнение дисковой операции	
		invoke	lstrlen, addr szBuff
		mov	@dwContentLength, eax
		invoke	WriteFile,@hResultFile, addr szBuff,\
			@dwContentLength, addr @dwWritten,NULL

		.if	eax!=NULL		; продолжаем 	
			pop	ecx
			push	@lpNext
			pop	@lpStart
			inc	@dwTriedTimes
			.continue
		.endif
	.endw
_NotFound:
	invoke	GetTickCount
	sub	eax,@dwStart
	mov	@dwStart,eax

	invoke	totaltime,addr @szPswTmp,@dwStart,@dwTriedTimes,NULL
	invoke	lstrcpy,addr @szBuf,addr @szPswTmp

	invoke	StdOut, addr crlf
	invoke	StdOut, addr szRezLine	

	invoke	StdOut, addr @szBuf
	invoke	StdOut, addr crlf

_Error_Exit:
        xor        eax,eax
        ret
_WinMain        endp
;******************************************************************************** 
changeLayout proc uses edi  caddr:DWORD, outstraddr:DWORD
local ks:KEYBOARDSTATE
local dwhk_r:DWORD
local dwhk_e:DWORD

	mov	edi,offset eng    
	invoke	LoadKeyboardLayout,edi,KLF_ACTIVATE
	mov	dwhk_e, eax  
 
	mov	edi,offset rus    
	invoke	LoadKeyboardLayout,edi,KLF_ACTIVATE
	mov	dwhk_r, eax   


	invoke	GetKeyboardState, addr ks
	mov	edi, caddr

	invoke	VkKeyScanEx,edi, dwhk_r
	mov	ecx,eax

	lea	ebx,buffer
	invoke	ToAsciiEx, ecx, 0, addr ks, ebx, 2, dwhk_e
	invoke	CharToOem,ebx,ebx
	mov	edi,outstraddr
	mov	DWORD PTR [edi], ebx
	ret
changeLayout endp
;******************************************************************************** 
changeLayout2 proc   caddr:DWORD, outstraddr:DWORD
local ks:KEYBOARDSTATE
local dwhk_r:DWORD
local dwhk_e:DWORD

local curChar:DWORD
local sizeInStr:DWORD
local dwTemp:DWORD
local sztempBuff[MAX_PATH]:BYTE

	invoke	RtlZeroMemory,addr sztempBuff,MAX_PATH
	lea	edi,sztempBuff

	xor	eax, eax
	mov	curChar,eax

	invoke	lstrlen, caddr
	mov	sizeInStr,eax	

	mov	curChar, 0
	jmp	__gofor
__gofornext:
	inc	curChar
__gofor:
	mov	edx, curChar
	cmp	edx, sizeInStr
	jge	__gofor_exit

	mov	eax, curChar
	mov	edx, caddr
	add	edx,eax
	movsx	ecx, byte ptr [edx]	
	
		lea	eax,dwTemp
		push	eax	
		push	ecx
		call	changeLayout

	lea	eax,dwTemp
	mov	eax,[eax] ; тут адрес '61' 
	xor	ecx, ecx
	movsx	ecx, byte ptr [eax]
	mov	eax,ecx
	stosb
	jmp	__gofornext
__gofor_exit:

	invoke	lstrlen, addr sztempBuff
	xor	ecx, ecx
	mov	ecx,eax
	lea	esi, sztempBuff
	mov	edi, outstraddr
	rep	movsb
	ret
changeLayout2 endp
;******************************************************************************** 
; void DisplayHelp()
; Input	- NULL
; Output	- Show help string
.data

	szHelp	db 'Usage: layoutChanger.exe /file: [path to file] ',13,10,0
	szlf	db 13,10,0
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
	invoke	ParamCount	; В eax - количество параметров ком. строки
	.if	eax == 0
		invoke	StdOut, addr szUsage
		jmp	__quit
	.endif

	call	GetCommandLine	; в eax полностью полный путь к командной строке
	invoke	lstrcpy, addr szBuff, eax

	; Начнем разбор ком. строки
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
	invoke	GetFlagValue, addr szPathtoFile, addr szBuff, addr lpszPathtoFile
	and	ddFlag,eax
	.if	ddFlag == 0
		invoke	StdOut, addr szHelp
		ret	
	.endif
__noUsersList:
;******************************************************************************** 
	invoke	GetModuleHandle,NULL
	mov	hModuleHandle,eax
	invoke	GetModuleFileName, hModuleHandle, offset szFileName, sizeof szFileName
	invoke	lstrlen, offset szFileName
	cld
	mov	esi, offset szFileName
	add	esi,eax
	std
@@:
	lodsb
	cmp	al,5ch
	jne	@B
	mov	byte ptr [esi+2],0
	cld

	invoke	SetCurrentDirectory, offset szFileName
	call	_WinMain
__quit:
	invoke	ExitProcess,NULL
;******************************************************************************** 
        end        start