; x64 shellcode to ExitProcess
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; Source code put in public domain by Didier Stevens, no Copyright
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2012/05/01: Call ExitProcess

%include "sc-x64-macros.asm"

INDEX_KERNEL32_LOADLIBRARYA		equ 0 * POINTERSIZE + STACKSPACE
INDEX_KERNEL32_EXITPROCESS		equ 1 * POINTERSIZE + STACKSPACE
APIFUNCTIONCOUNT							equ 2

segment .text

	; Setup environment
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE		;reserve stack space for called functions and for API addresses
	and rsp, 0x0fffffffffffffff0																				;make sure stack is 16-byte aligned

	LOOKUP_API KERNEL32DLL, KERNEL32_LOADLIBRARYA, INDEX_KERNEL32_LOADLIBRARYA
	LOOKUP_API KERNEL32DLL, KERNEL32_EXITPROCESS, INDEX_KERNEL32_EXITPROCESS, INDEX_KERNEL32_LOADLIBRARYA

	; ExitProcess
	xor rcx, rcx
	call [rsp + INDEX_KERNEL32_EXITPROCESS]

%include "sc-x64-api-functions.asm"

KERNEL32DLL							db	"KERNEL32.DLL", 0
KERNEL32_LOADLIBRARYA		db	"LoadLibraryA", 0
KERNEL32_EXITPROCESS		db	"ExitProcess", 0
