.386 
.model flat, stdcall
option casemap:none

include windows.inc

include kernel32.inc
include user32.inc

includelib kernel32.lib
includelib user32.lib

APEX_POLYMORPH_STRUCT STRUCT

	DECRYPTOR_ADDRESS	dd 0
	DECRYPTOR_SIZE		dd 0
	DECRYPTOR_EP		dd 0

APEX_POLYMORPH_STRUCT ENDS

.data
	xtg_trash_gen_buf			db		1000h	dup	(00)				
	irpe_polymorph_gen_buf		db		1000h	dup (00)
	trash_code_buf				db		5000h	dup	(00)
	tcb_size					equ		$ - trash_code_buf

.code
	engines:
	include		rang32.asm													
	include		xtg.inc	
	include		xtg.asm
	include		faka.asm
	include		logic.asm
	include		irpe.asm

LibMain proc hInstDLL:DWORD, reason:DWORD, unused:DWORD

    .if reason == DLL_PROCESS_ATTACH 
      mov eax, TRUE
    .elseif reason == DLL_PROCESS_DETACH 
    .elseif reason == DLL_THREAD_ATTACH
    .elseif reason == DLL_THREAD_DETACH
    .endif
    ret

LibMain endp

xVirtualAlloc:
	pushad
	mov		eax, dword ptr [esp + 24h]
	
	push	PAGE_EXECUTE_READWRITE
	push	MEM_RESERVE + MEM_COMMIT
	push	eax
	push	0
	call	VirtualAlloc
	
	mov		dword ptr [esp + 1Ch], eax 
	popad
	ret		04

xVirtualFree:
	pushad
	mov		eax, dword ptr [esp + 24h]
	
	push	MEM_RELEASE
	push	0
	push	eax
	call	VirtualFree
	
	popad
	ret		04

GenerateDecryptor proc pCode:LPVOID, dwCodeSize:DWORD

	; Create XTG_TRASH_GEN
	lea ecx, xtg_trash_gen_buf
	assume ecx: ptr XTG_TRASH_GEN

	; Fill XTG_TRASH_GEN
	mov [ecx].fmode, XTG_REALISTIC					; Realistic code structure
	mov [ecx].rang_addr, RANG32						; RNG
	mov [ecx].faka_addr, 0							; No Fake API
	mov [ecx].xfunc_struct_addr, 0					; Function already set to XTG_REALISTIC
	mov [ecx].alloc_addr, xVirtualAlloc				; VirtualAlloc 
	mov [ecx].free_addr, xVirtualFree				; VirtualFree
	mov [ecx].xmask1, XTG_LOGIC	+ XTG_FUNC			; Flags, self explainatory
	mov [ecx].xmask2, 0	
	mov [ecx].fregs, 0								; Requires no register preservation
	mov [ecx].xdata_struct_addr, 0					; No data fields
	mov [ecx].xlogic_struct_addr, 0
	mov [ecx].icb_struct_addr, 0

	; Allocate code
	push dwCodeSize
	call [ecx].alloc_addr
	push dwCodeSize
	push eax
	call xmemset
	mov [ecx].tw_trash_addr, eax
	mov eax, dwCodeSize
	mov [ecx].trash_size, eax

	; Create IRPE
	push IRPE_ALLOC_BUFFER
	call [ecx].alloc_addr							; EAX = ALLOC_ADDR
		
	lea edx, irpe_polymorph_gen_buf
	assume edx: ptr IRPE_POLYMORPH_GEN
	mov [edx].xmask, 0; (IRPE_CALL_DECRYPTED_CODE)

	; Fill IRPE
	mov [edx].xtg_struct_addr, ecx					; XTG_TRASH_GEN structure for poly engine
	mov [edx].xtg_addr, xTG							; XTG Engine function for poly engine
	mov esi, pCode
	mov [edx].code_addr, esi						; Pointer to code to encrypt
	mov [edx].va_code_addr, eax						; Returned by call [ecx].alloc_addr above
	mov esi, dwCodeSize
	mov [edx].code_size, esi						; Length of code to encrypt
	mov [edx].decryptor_size, 1000h					; Length of decryptor routine
	
	push edx
	call iRPE

	pushad

		push 12
		call [ecx].alloc_addr
		assume eax: ptr APEX_POLYMORPH_STRUCT
		
		mov esi, [edx].decryptor_addr
		mov [eax].DECRYPTOR_ADDRESS, esi

		mov esi, [edx].total_size
		mov [eax].DECRYPTOR_SIZE, esi

		mov esi, [edx].ep_polymorph_addr
		mov [eax].DECRYPTOR_EP, esi

		mov [esp + 28], eax
	
	popad
	
	ret	

GenerateDecryptor endp

End LibMain