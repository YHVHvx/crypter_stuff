; x64 shellcode to DebugOutput "Hello from injected shell code!", then return to caller
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; Source code put in public domain by Didier Stevens, no Copyright
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2011/12/27: start

%include "sc-x64-macros.asm"

INDEX_KERNEL32_OUTPUTDEBUGSTRINGA		equ 0 * POINTERSIZE + STACKSPACE
APIFUNCTIONCOUNT										equ 1

segment .text

	; Setup environment
	sub rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE		;reserve stack space for called functions and for API addresses

	LOOKUP_API KERNEL32DLL, KERNEL32_OUTPUTDEBUGSTRINGA, INDEX_KERNEL32_OUTPUTDEBUGSTRINGA

	lea rcx, [rel HELLO]
	call [rsp + INDEX_KERNEL32_OUTPUTDEBUGSTRINGA]

	add rsp, STACKSPACE + ROUND_EVEN(APIFUNCTIONCOUNT) * POINTERSIZE
	ret

%include "sc-x64-api-functions.asm"

KERNEL32DLL										db	"KERNEL32.DLL", 0
KERNEL32_OUTPUTDEBUGSTRINGA		db	"OutputDebugStringA", 0

HELLO													db	"Hello from injected shell code!", 0
