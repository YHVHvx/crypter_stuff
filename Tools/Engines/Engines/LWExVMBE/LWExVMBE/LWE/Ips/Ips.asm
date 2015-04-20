	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
.code
	include ..\LWE.inc
	
Entry proc
	push 123H
	mov eax,LWE_CHECK_IP
	Call LWE
	
	push offset Entry
	mov eax,LWE_CHECK_IP
	Call LWE
	ret
Entry endp
end Entry