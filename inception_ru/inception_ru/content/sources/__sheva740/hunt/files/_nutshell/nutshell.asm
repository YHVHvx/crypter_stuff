.686
include	\masm32\include\masm32rt.inc
include	\masm32\include\mpr.inc
include	\masm32\include\advapi32.inc
include	\masm32\include\netapi32.inc
include	.\Stdlib\Stdlib.inc	
include	.\Stdlib\Stdlib.mac
include	\masm32\macros\macros.asm

include	nutshell.inc	


includelib \masm32\lib\mpr.lib
includelib \masm32\lib\advapi32.lib
includelib \masm32\lib\netapi32.lib
includelib \masm32\lib\msvcrt.lib

includelib .\Stdlib\Stdlib.lib

DEBUG			EQU 0

DisplayHelp		PROTO
FindFlag			PROTO :DWORD, :DWORD
GetFlagValue		PROTO :DWORD, :DWORD, :DWORD
InputPassword		PROTO :DWORD, :DWORD
ShowUsersList		PROTO
WNetConnection		PROTO :DWORD,:DWORD,:BYTE
RemoteResourceDrop		PROTO
ConnectToService		PROTO :DWORD, :DWORD
doShell			PROTO
doMove			PROTO

.data
	buff		db [MAX_PATH] dup(0) 	

	szUsage		db 'Usage: nutshell.exe /help',13,10,0

	szHelpl		db 'help',0
	szHelp2		db 'h',0
	szHelp3		db '?',0
	ddFlag		dd 0
	
	szNonFlagStr	db '\\',0
	szUserStr		db '/user:',0
	szPwdStr		db '/pwd:',0
	szInPwd		db 'Input Password: ',0
	
	szShell		db '/shell',0		
	szMove		db '/move:',0
	
	bExitFlag		db 0
.code
start:

	invoke	ParamCount	; ¬ eax - количество параметров ком. строки
	.if	eax == 0
		invoke	StdOut, addr szUsage
		jmp	__quit
	.endif

	call	GetCommandLine	; в eax полностью полный путь к командной строке
	invoke	lstrcpy, addr buff, eax

	; Ќачнем разбор ком. строки
	invoke	FindFlag, addr szHelpl, addr buff	; 'help'	- DisplayHelp()
	or	ddFlag,eax
	invoke	FindFlag, addr szHelp2, addr buff	; 'h'	- DisplayHelp()
	or	ddFlag,eax
	invoke	FindFlag, addr szHelp3, addr buff	; '?'	- DisplayHelp()
	or	ddFlag,eax

	.if	ddFlag != 0
		invoke	StdOut, addr szHelp
		ret	
	.endif


	mov	ddFlag,1
	invoke	GetFlagValue, addr szNonFlagStr, addr buff, addr lpszComputer
	and	ddFlag,eax
	invoke	GetFlagValue, addr szUserStr, addr buff, addr lpszUsername
	and	ddFlag,eax
	invoke	GetFlagValue, addr szPwdStr, addr buff, addr lpszPassword
	and	ddFlag,eax

	lea	edi,lpszUsername
	cmp	byte ptr [edi],'*'
	jne	__noUsersList
	invoke	ShowUsersList
	ret
__noUsersList:
	.if	ddFlag == 0
		invoke	StdOut, addr szHelp
		ret	
	.endif

IF DEBUG
invoke	StdOut, addr szlf
invoke	StdOut, addr lpszComputer
invoke	StdOut, addr szlf
invoke	StdOut, addr lpszUsername
invoke	StdOut, addr szlf
invoke	StdOut, addr lpszPassword
invoke	StdOut, addr szlf
ENDIF


	lea	edi,lpszPassword
	cmp	byte ptr [edi],'*'
	jne	__noHidePwd
	mov	byte ptr [edi],00	; трем звездочку
	
	invoke	StdOut, addr szInPwd
	invoke	InputPassword, addr lpszPassword, MAX_PATH

	; проверка на то что пользователь ввел /pwd:*
	; и на предложение ввести скрыто пароль ввел [Enter]
	; Ќу вдруг дурачитс€ ? ))) 	
	lea	edi,lpszPassword	
	cmp	byte ptr [edi],0
	jne	__okInputPwd
	invoke	StdOut, addr szHelp
	ret	
__okInputPwd:

IF DEBUG
invoke	StdOut, addr szlf
invoke	StdOut, addr lpszPassword
invoke	StdOut, addr szlf
ENDIF
__noHidePwd:
IF DEBUG
.data
	szSelll db 'do Shell()',13,10,0
	szMovee db 'do Move()',13,10,0		
.code
ENDIF

;int 3
invoke	GetFlagValue, addr szShell, addr buff, 0			;'/shell'
.if	eax
	IF DEBUG
	invoke	StdOut, addr szSelll
	ENDIF
	invoke	doShell
	ret
.else	
	invoke	GetFlagValue, addr szMove, addr buff, addr lpszPathtoFile	;'/move:'
	.if	eax
		IF DEBUG
		invoke	StdOut, addr szMovee
		invoke	StdOut, addr lf		
		invoke	StdOut, addr lpszPathtoFile
		invoke	StdOut, addr lf
		ENDIF			
		invoke	doMove
	.else	
		invoke	StdOut, addr szHelp
		ret	
	.endif
.endif

__quit:
	invoke	ExitProcess,0

end start
