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

;------------CONST----------------------------------------------------
.CONST
szTxt                              DB "This proggy terminates via a RET instruction (no ExitProcess) !", 0
szCap                              DB "InConEx - test code", 0

;------------CODE-----------------------------------------------------
.CODE
	ASSUME FS : NOTHING
Main:
	PUSH     MB_ICONINFORMATION
	PUSH     OFFSET szCap
	PUSH     OFFSET szTxt
	PUSH     0
	CALL     MessageBox
	RET                                                          ; exit by RET !
End Main

:MAKE
\MASM32\BIN\ML /nologo /c /coff /Gz /Cp /Zp1 RetExit.BAT
\MASM32\BIN\LINK /nologo /FIXED:NO /MERGE:.idata=.text /MERGE:.data=.text /MERGE:.rdata=.text /SECTION:.text,EWR /IGNORE:4078 /SUBSYSTEM:WINDOWS RetExit.obj
DEL *.OBJ

ECHO.
PAUSE
CLS