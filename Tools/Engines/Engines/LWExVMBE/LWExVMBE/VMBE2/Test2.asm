	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

	include \masm32\include\kernel32.inc
	includelib \masm32\lib\kernel32.lib

.data
	Ips	ULONG ?
	LastIp	PVOID ?
	
.code
; LINK: /SECTION:.text,ERW
;
Buffer	BYTE 32 DUP (?)	; 16, MAX_IP_LENGTH

	include VMBE2.inc

$Ip	CHAR "0x%X", 13, 10, 0
	
Tclbk proc Arg:PVOID, Ip:PVOID, State:PTSTATE
	mov eax,Ip
	mov LastIp,eax
	invoke DbgPrint, addr $Ip, Ip
	inc Ips
	xor eax,eax
	ret
Tclbk endp

_imp__LoadLibraryA proto :PSTR

$Name	CHAR "psapi.dll", 0
$Msg		CHAR "BASE: 0x%X, Ip's: 0x%X", 0

EP proc C
	push offset $Name
	push esp	; Arg's
	push 1	; Arg num.
	push 0	; Callback arg.
	push offset Tclbk
	push D[_imp__LoadLibraryA]	; Ip
	push offset Buffer
	Call MI
	pop ecx
	invoke DbgPrint, addr $Msg, Eax, Ips
	ret
EP endp
end EP