; x64 shellcode to display a "Hello from injected shell code!" MessageBox, then return to caller
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; Source code put in public domain by Didier Stevens, no Copyright
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2011/12/27: Refactored functions to include file sc-x64-api-functions.asm

%include "sc-x64-macros.asm"

INDEX_KERNEL32_LOADLIBRARYA		equ 0 * POINTERSIZE + STACKSPACE
INDEX_MESSAGEBOXA							equ 1 * POINTERSIZE + STACKSPACE
APIFUNCTIONCOUNT							equ 2

segment .text

	; Setup environment
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE		;reserve stack space for called functions and for API addresses

	LOOKUP_API KERNEL32DLL, KERNEL32_LOADLIBRARYA, INDEX_KERNEL32_LOADLIBRARYA

	lea rcx, [rel USER32DLL]
	call [rsp + INDEX_KERNEL32_LOADLIBRARYA]

	LOOKUP_API USER32DLL, USER32_MESSAGEBOXA, INDEX_MESSAGEBOXA, INDEX_KERNEL32_LOADLIBRARYA

	; Display MessageBox
	xor r9, r9
	lea r8, [rel TITLE]
	lea rdx, [rel HELLO]
	xor rcx, rcx
	call [rsp + INDEX_MESSAGEBOXA]

	add rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	ret

%include "sc-x64-api-functions.asm"

KERNEL32DLL							db	"KERNEL32.DLL", 0
KERNEL32_LOADLIBRARYA		db	"LoadLibraryA", 0

USER32DLL								db	"USER32.DLL", 0
USER32_MESSAGEBOXA			db	"MessageBoxA", 0

HELLO										db	"Hello from injected shell code!", 0
TITLE										db	"Message", 0
