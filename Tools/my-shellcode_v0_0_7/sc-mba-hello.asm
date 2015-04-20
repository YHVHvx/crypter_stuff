; Shellcode to display a "Hello from injected shell code!" MessageBox
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2008/10/14: start, based on The Shellcoder's Handbook http://eu.wiley.com/WileyCDA/WileyTitle/productCd-0764544683.html
;   2008/10/15: LookupFunctions
;   2008/10/18: Cleanup for bpmtk inject-code demo
;   2008/11/22: Refactoring
;   2008/11/24: Refactored functions to include file

BITS 32

USER32_HASH equ 0x00038f88
USER32_NUMBER_OF_FUNCTIONS equ 1
USER32_MESSAGEBOXA_HASH equ 0x0006b81a

segment .text
	call geteip
geteip:
	pop ebx

  ; Setup environment
	lea esi, [USER32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [USER32_HASHES_TABLE-geteip+ebx]
	push esi
	push USER32_NUMBER_OF_FUNCTIONS
	push USER32_HASH
	call LookupFunctions
	
	; Display MessageBox
	push 0x00
	lea eax, [HELLO-geteip+ebx]
	push eax
	push eax
	push 0x00
	call [USER32_MESSAGEBOXA-geteip+ebx]

	ret

%include "sc-api-functions.asm"
	
USER32_HASHES_TABLE:
	dd USER32_MESSAGEBOXA_HASH

USER32_FUNCTIONS_TABLE:
USER32_MESSAGEBOXA dd 0x00000000

HELLO:
	db "Hello from injected shellcode!", 0
