;@ECHO OFF
;GOTO MAKE

.586p
.MODEL FLAT, STDCALL
OPTION CASEMAP : NONE

INCLUDE    \masm32\include\kernel32.inc
INCLUDELIB \masm32\lib\kernel32.lib
INCLUDE    \masm32\include\user32.inc
INCLUDELIB \masm32\lib\user32.lib

INCLUDE    \masm32\include\windows.inc

;------------EXTRN----------------------------------------------------
GetCommandLineW  PROTO
MessageBoxW      PROTO :DWORD, :LPSTR, :LPSTR, :DWORD

;------------CONST----------------------------------------------------
.CONST
szCap                              DB "GetCommandLineA:", 0
szCapW                             DW 'G', 'e', 't', 'C', 'o', 'm', 'm', 'a', 'n'
                                   DW 'd', 'L', 'i', 'n', 'e', 'W', ':', 0

;------------CODE-----------------------------------------------------
.CODE
	ASSUME FS : NOTHING
Main:
	CALL     GetCommandLineA
	PUSH     MB_ICONINFORMATION
	PUSH     OFFSET szCap
	PUSH     EAX
	PUSH     0
	CALL     MessageBoxA
	CALL     GetCommandLineW
	PUSH     MB_ICONINFORMATION
	PUSH     OFFSET szCapW
	PUSH     EAX
	PUSH     0
	CALL     MessageBoxW
	RET                                                          ; exit by RET !
End Main

:MAKE
\MASM32\BIN\ML /nologo /c /coff /Gz /Cp /Zp1 ShowCmdLine.BAT
\MASM32\BIN\LINK /nologo /FIXED:NO /MERGE:.idata=.text /MERGE:.data=.text /MERGE:.rdata=.text /SECTION:.text,EWR /IGNORE:4078 /SUBSYSTEM:WINDOWS ShowCmdLine.obj
DEL *.OBJ

ECHO.
PAUSE
CLS