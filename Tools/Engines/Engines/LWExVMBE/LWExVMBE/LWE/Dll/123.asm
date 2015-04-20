	.686
	.model flat, stdcall
	option casemap :none

	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib
	
	include \masm32\include\user32.inc
	includelib \masm32\lib\user32.lib
	
.code
DllEntry proc hModule:DWORD, Teason:DWORD, Unused:DWORD
	mov eax,TRUE
	ret
DllEntry Endp

$Str		CHAR "..",0

Initialize proc
	invoke MessageBox, 0, addr $Str, addr $Str, MB_OK
	ret
Initialize endp

SEH proc ExceptionRecord:PEXCEPTION_RECORD, EstablisherFrame:PVOID, ContextRecord:PCONTEXT, DispatcherContext:PVOID
	mov ecx,ContextRecord
	xor eax,eax	; ExceptionContinueExecution
	inc CONTEXT.rEip[ecx]
	ret
SEH endp

	assume fs:nothing
Xcpt proc
	push offset SEH
	push dword ptr fs:[0]
	mov dword ptr fs:[0],esp
	Int 3
	mov eax,1234H
	pop dword ptr fs:[0]
	pop ecx
	ret
Xcpt endp
end DllEntry