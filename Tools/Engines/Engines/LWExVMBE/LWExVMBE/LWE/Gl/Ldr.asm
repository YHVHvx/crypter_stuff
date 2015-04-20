	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc

.code
	include Map.inc
	
LWE_LOAD_DLL	equ 0	; Загружает модуль.
LWE_GET_PROC	equ 1	; Раскодирует список апи по хэшам.
LWE_CHECK_IP	equ 2	; Проверяет вхождение адреса в пределы проекции, даже если описатель модуля удалён из загрузчика.

Dll$	CHAR "glx.dll",0

%NTERR macro
	.if Eax
		Int 3
	.endif
endm

LoadDll proto :DWORD, :DWORD, :DWORD
LdrEncodeEntriesList proto :DWORD, :DWORD

Entry proc
Local DllHandle:PVOID
Local Api[2]:PVOID
	lea ecx,DllHandle
	push ecx
	push offset Dll$
	push offset Map
	mov eax,LWE_LOAD_DLL
	Call LoadDll
	%NTERR
	
	lea ecx,Api
	mov dword ptr Api[0],002ADBEAH	; HASH("Start")
	mov dword ptr Api[4],0	; EOL
	push ecx
	push DllHandle
	mov eax,LWE_GET_PROC
	Call LdrEncodeEntriesList
	%NTERR
	
	Call dword ptr Api[0]	; Start()
	ret
Entry endp
end Entry