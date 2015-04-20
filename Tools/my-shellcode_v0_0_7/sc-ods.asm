; Shellcode to send "Hello from sc-ods" via OutputDebugString, and sleep 5 seconds
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2008/10/14: start
;   2008/10/15: LookupFunctions
;   2008/11/24: Refactored to use include file

BITS 32

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS equ 2
KERNEL32_OUTPUTDEBUGSTRINGA_HASH equ 0x038a721e
KERNEL32_SLEEP_HASH equ 0x00001abc

segment .text
	call geteip
geteip:
	pop ebx

  ; Setup environment
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; OutputDebugString and sleep
	lea eax, [HELLO-geteip+ebx]
	push eax
	call [KERNEL32_OUTPUTDEBUGSTRINGA-geteip+ebx]
	push 5000
	call [KERNEL32_SLEEP-geteip+ebx]

	ret
	
%include "sc-api-functions.asm"
	
KERNEL32_HASHES_TABLE:
	dd KERNEL32_OUTPUTDEBUGSTRINGA_HASH
	dd KERNEL32_SLEEP_HASH

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_OUTPUTDEBUGSTRINGA dd 0x00000000
KERNEL32_SLEEP dd 0x00000000

HELLO:
	db "Hello from sc-ods", 0
