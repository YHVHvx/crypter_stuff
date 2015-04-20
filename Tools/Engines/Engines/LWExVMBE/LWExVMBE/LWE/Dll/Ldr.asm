	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
.data
	include Map.inc
.code
	include ..\LWE.inc

Dll$	CHAR "123.dll",0

%NTERR macro
	.if Eax
		Int 3
	.endif
endm

Entry proc
Local DllHandle:PVOID
Local Api[3]:PVOID
	lea ecx,DllHandle
	mov eax,LWE_LOAD_DLL
	push ecx
	push offset Dll$
	push offset Map
	Call LWE
	%NTERR
	
	lea ecx,Api
	mov dword ptr Api[0],1C5F5F9FH	; HASH("Initialize")
	mov dword ptr Api[4],00016B7AH	; HASH("Xcpt")
	mov dword ptr Api[2*4],0	; EOL
	push ecx
	push DllHandle
	mov eax,LWE_GET_PROC
	Call LWE
	%NTERR
	
	Call dword ptr Api[0]	; "Initialize"
	
	Call dword ptr Api[4]	; "Xcpt"
	; Eax = 0x1234
	
	invoke ExitProcess, Eax
	ret
Entry endp
end Entry