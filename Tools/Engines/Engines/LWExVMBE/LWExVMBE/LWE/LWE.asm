; LWE
;
; o MI, UM
;
; (c) Indy, 2012
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

;	OPT_ENABLE_DBG_LOG	equ TRUE
	OPT_ENABLE_SCN		equ TRUE
	
	include Hdr.inc
.code
LWE_LOAD_DLL	equ 0	; Загружает модуль.

; typedef NTSTATUS (*PLWE)(
;   IN PVOID MapToLoad,	; Ссылка на образ.
;   IN PSTR DllName,	; Имя модуля.
;   OUT PVOID *DllHandle	; Принимает адрес загрузки.
;   );

LWE_GET_PROC	equ 1	; Раскодирует список апи по хэшам.

; typedef NTSTATUS (*PLWE)(
; 	IN PVOID ImageBase OPTIONAL,	; База модуля, если ноль, то используется ntdll.
; 	IN OUT *PVOID ApiList	; Список хэшей, завершающийся нулём(EOL).
; 	);

LWE_CHECK_IP	equ 2	; Проверяет вхождение адреса в пределы проекции, даже если описатель модуля удалён из загрузчика.

; typedef ULONG (*PLWE)(
; 	IN PVOID Ip	; Тестируемый адрес.
; 	);

; Результат:
; Eax = 0 - инициализация выполнилась с ошибкой.
; Eax = 1 - адрес вне модуля.
; Eax = 2 - адрес в модуле.

LWE:
	test eax,eax
	jz LoadDll
	dec eax
	jz LdrEncodeEntriesList
CheckIp proc C
	%GETENVPTR Eax
	.if !Eax
		Initialize proto
		invoke Initialize
		.if Eax
			xor eax,eax
Exit:
			ret 4
		.endif
		%GETENVPTR Eax
	.endif
	push dword ptr [esp + 4]	; Ip
	push ebp
	xor ecx,ecx
	mov ebp,esp
	push ecx
	push ecx
	mov edx,esp
	Call @f
	add esp,2*4
	leave
	pop ecx
	jmp Exit
@@:
	push ecx
	push 2
	push edx
	push UENV.pDbgBreakPoint[eax]
	Jmp UENV.pRtlWalkFrameChain[eax]
CheckIp endp

	%GET_GRAPH_REFERENCE

	include Img.asm
	
NTOPENSECTION struct
Ip				PVOID ?
SectionHandle		HANDLE ?
DesiredAccess		ULONG ?
ObjectAttributes	POBJECT_ATTRIBUTES ?
NTOPENSECTION ends

xZwOpenSection:
	%GET_CURRENT_GRAPH_ENTRY
_ZwOpenSection proc uses ebx SectionHandle:PHANDLE, DesiredAccess:ACCESS_MASK, ObjectAttributes:POBJECT_ATTRIBUTES
Local NameBuffer[MAX_PATH*2]:WCHAR
Local ObjectName:UNICODE_STRING
Local ReturnLength:ULONG
Local TempName:PUNICODE_STRING
	%GETENVPTR Ebx
	assume ebx:PUENV
	%DBG "LWE: ZwOpenSection(DesiredAccess = 0x%X)", DesiredAccess
	cmp [ebx].Status,LDR_STATUS_PROCESSING
	mov ecx,ObjectAttributes
	jne Exit
	assume ecx:POBJECT_ATTRIBUTES
	cmp [ecx].uLength,sizeof(OBJECT_ATTRIBUTES)
	jne Exit
	cmp [ecx].hRootDirectory,0
	mov edx,[ecx].pObjectName
	je Exit
	test edx,edx
	lea eax,NameBuffer
	jz Exit
	%DBG "LWE: ZwOpenSection(%wZ, RootDirectory = 0x%X)", [Ecx].hRootDirectory, [Ecx].pObjectName
	mov ObjectName.Buffer,eax
	mov TempName,edx
	lea eax,ReturnLength
	lea edx,ObjectName
	mov ObjectName.MaximumLength,MAX_PATH*2
	mov ObjectName._Length,MAX_PATH*2
	push eax
	push MAX_PATH*2 + sizeof(UNICODE_STRING)
	push edx
	push ObjectNameInformation
	push [Ecx].hRootDirectory
	Call [Ebx].pZwQueryObject
	%DBG "LWE: ZwOpenSection.ZwQueryObject(): 0x%X", Eax
	test eax,eax
	lea ecx,ObjectName
	jnz Exit
	lea edx,[ebx].Directory
	push TRUE
	push ecx
	push edx
	Call [Ebx].pRtlCompareUnicodeString
	.if Eax
		lea ecx,ObjectName
		lea edx,[ebx].Directory32
		push TRUE
		push ecx
		push edx
		Call [Ebx].pRtlCompareUnicodeString
		.if Eax
Exit:
			mov eax,[ebx].pZwOpenSection
			%DBG "LWE: ZwOpenSection(SKIP)"
			pop ebx
			leave
			Jmp Eax
		.endif
	.endif
	lea ecx,[ebx].DllName
	push TRUE
	push TempName
	push ecx
	Call [Ebx].pRtlCompareUnicodeString
	test eax,eax
	jnz Exit
	%DBG "LWE: ZwOpenSection(TARGET SECTION): STATUS_SUCCESS"
	mov ecx,SectionHandle
	mov edx,[ebx].SectionHandle
	xor eax,eax	; STATUS_SUCCESS
	mov dword ptr [ecx],edx
	inc [ebx].Status	; LDR_STATUS_SECTION_OPENED
	ret
_ZwOpenSection endp

NTMAPVIEWOFSECTION struct
Ip				PVOID ?
SectionHandle		HANDLE ?
ProcessHandle		HANDLE  ?
BaseAddress		PVOID ?
ZeroBits			ULONG ?
CommitSize		ULONG ?
SectionOffset		PLARGE_INTEGER ?
ViewSize			PULONG ?
InheritDisposition	ULONG ?	; SECTION_INHERIT
AllocationType		ULONG ?
Protect			ULONG ?
NTMAPVIEWOFSECTION ends

xZwMapViewOfSection:
	%GET_CURRENT_GRAPH_ENTRY
_ZwMapViewOfSection proc uses ebx SectionHandle:HANDLE, 
					ProcessHandle:HANDLE, 
					BaseAddress:PPVOID, 
					ZeroBits:ULONG, 
					CommitSize:ULONG,
					SectionOffset:PLARGE_INTEGER, 
					ViewSize:PULONG, 
					InheritDisposition:ULONG, 
					AllocationType:ULONG, 
					Protect:ULONG
Local LBase:PVOID, LSize:ULONG
	%GETENVPTR Ebx
	assume ebx:PUENV
	mov ecx,SectionHandle
	ifdef OPT_ENABLE_DBG_LOG
		mov edx,BaseAddress
		mov edx,dword ptr [edx]
	endif
	%DBG "LWE: ZwMapViewOfSection(SectionHandle = 0x%X, BaseAddress = 0x%X, AllocationType = 0x%X, Protect = 0x%X)", Protect, AllocationType, Edx, SectionHandle
	cmp [ebx].SectionHandle,ecx
	jne Exit
	xor eax,eax
	cmp ProcessHandle,NT_CURRENT_PROCESS
	jne Exit
	cmp SectionOffset,eax
	mov edx,[ebx].DllBase
	jne Exit
	cmp [ebx].Status,LDR_STATUS_SECTION_OPENED
	mov ecx,BaseAddress
	jne IsMapped
	cmp dword ptr [ecx],eax
	jne Exit
	lea ecx,LSize
	push PAGE_EXECUTE_READWRITE	; Protect
	push 0
	push ViewShare
	mov edx,[ebx].DllBase
	push ecx
	push eax
	push eax
	lea ecx,LBase
	push eax
	mov LBase,edx
	mov LSize,eax
	push ecx
	push NtCurrentProcess
	push [ebx].SectionHandle
	Call [Ebx].pZwMapViewOfSection
	%DBG "LWE: ZwMapViewOfSection.Zw1: 0x%X", Eax
	test eax,eax
	jnz Relocate
Store:
	push LSize
	mov edx,ViewSize
	inc [ebx].Status	; LDR_STATUS_SECTION_MAPPED
	pop dword ptr [edx]
	mov ecx,LBase
	mov edx,BaseAddress
	mov [ebx].ViewBase,ecx
	mov dword ptr [edx],ecx
Skip:
	ret
Relocate:
	xor eax,eax
	lea ecx,LSize
	push PAGE_EXECUTE_READWRITE
	push 0
	push ViewShare
	push ecx
	push eax
	push eax
	lea ecx,LBase
	push eax
	mov LBase,eax
	push ecx
	push NtCurrentProcess
	push [ebx].SectionHandle
	Call [Ebx].pZwMapViewOfSection
	%DBG "LWE: ZwMapViewOfSection.Zw2: 0x%X", Eax
	test eax,eax
	jnz Skip
	mov eax,STATUS_IMAGE_NOT_AT_BASE
	jmp Store
IsMapped:
	cmp [ebx].Status,LDR_STATUS_SECTION_MAPPED
	jne Exit
	mov edx,[ebx].ViewBase
	mov ecx,BaseAddress
	mov dword ptr [ecx],edx
	xor eax,eax	; STATUS_SUCCESS
	inc [ebx].Status	; LDR_STATUS_SECTION_CHECKED
	jmp Skip
Exit:
	mov eax,[ebx].pZwMapViewOfSection
	%DBG "LWE: ZwMapViewOfSection(SKIP)"
	pop ebx
	leave
	Jmp Eax
_ZwMapViewOfSection endp

xZwClose:
	%GET_CURRENT_GRAPH_ENTRY
_ZwClose proc C
; [Esp + 4]	IN HANDLE Handle
	%GETENVPTR Eax
	assume eax:PUENV
	ifdef OPT_ENABLE_DBG_LOG
		mov ecx,dword ptr [esp + 4]
	endif
	%DBG "LWE: ZwClose(0x%X)", Ecx
	cmp [eax].Status,LDR_STATUS_PROCESSING
	je Exit
	cmp [eax].Status,LDR_STATUS_SECTION_CLOSED
	mov ecx,dword ptr [esp + 4]
	jnb Exit
	cmp [eax].SectionHandle,ecx
	jne Exit
	mov [eax].Status,LDR_STATUS_SECTION_CLOSED
	%DBG "LWE: ZwClose(): STATUS_SUCCESS"
	xor eax,eax	; STATUS_SUCCESS
	ret 4
Exit:
	Jmp [Eax].pZwClose
_ZwClose endp

NTQUERYINFORMATIONPROCESS struct
Ip				PVOID ?
ProcessHandle		HANDLE ?
InfoClass			ULONG ?
Information		PVOID ?
InfoLength		ULONG ?
ReturnLength		PULONG ?
NTQUERYINFORMATIONPROCESS ends

ProcessExecuteFlags	equ 22H

MEM_EXECUTE_OPTION_DISABLE				equ 1 
MEM_EXECUTE_OPTION_ENABLE				equ 2
MEM_EXECUTE_OPTION_DISABLE_THUNK_EMULATION	equ 4
MEM_EXECUTE_OPTION_PERMANENT				equ 8
MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE	equ 10H
MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE	equ 20H

xZwQueryInformationProcess:
	%GET_CURRENT_GRAPH_ENTRY
_ZwQueryInformationProcess proc C
	%DBG "LWE: ZwQueryInformationProcess()"
	cmp NTQUERYINFORMATIONPROCESS.ProcessHandle[esp],NT_CURRENT_PROCESS
	mov ecx,NTQUERYINFORMATIONPROCESS.Information[esp]
	jne @f
	cmp NTQUERYINFORMATIONPROCESS.InfoClass[esp],ProcessExecuteFlags
	jne @f
	cmp NTQUERYINFORMATIONPROCESS.InfoLength[esp],sizeof(ULONG)
	jne @f
	test ecx,ecx
	mov edx,NTQUERYINFORMATIONPROCESS.ReturnLength[esp]
	jz @f
	%DBG "LWE: ZwQueryInformationProcess() HANDLED"
	mov dword ptr [ecx],40H or MEM_EXECUTE_OPTION_PERMANENT \
		or MEM_EXECUTE_OPTION_ENABLE \
		or MEM_EXECUTE_OPTION_EXECUTE_DISPATCH_ENABLE \
		or MEM_EXECUTE_OPTION_IMAGE_DISPATCH_ENABLE
	.if Edx
		mov dword ptr [edx],sizeof(ULONG)
	.endif
	xor eax,eax
	retn sizeof(NTQUERYINFORMATIONPROCESS) - sizeof(PVOID)
@@:
	%GETENVPTR Eax
	Jmp UENV.pZwQueryInformationProcess[Eax]
_ZwQueryInformationProcess endp

NTQUERYVIRTUALMEMORY struct
Ip					PVOID ?
ProcessHandle			HANDLE ?
BaseAddress			PVOID ?
InformationClass		ULONG ?
Information			PVOID ?
InformationLength		ULONG ?
ReturnLength			PULONG ?
NTQUERYVIRTUALMEMORY ends

xZwQueryVirtualMemory:
	%GET_CURRENT_GRAPH_ENTRY
_ZwQueryVirtualMemory proc uses ebx ProcessHandle:HANDLE, BaseAddress:PVOID, InformationClass:ULONG, Information:PVOID, InformationLength:ULONG, ReturnLength:PULONG
	%DBG "LWE: ZwQueryVirtualMemory()"
	%GETENVPTR Ebx
	assume ebx:PUENV
	cmp ProcessHandle,NT_CURRENT_PROCESS
	jne @f
	cmp InformationClass,MemoryBasicInformation
	jne @f
	cmp InformationLength,sizeof(MEMORY_BASIC_INFORMATION)
	jne @f
; Стаб для RtlpStkIsPointerInDllRange().
	push BaseAddress
	mov eax,LWE_CHECK_IP
	Call LWE
	%DBG "LWE: WALK(0x%X): 0x%X", Eax, BaseAddress
	dec eax
	dec eax
	jnz @f
	push ReturnLength
	push InformationLength
	push Information
	push InformationClass
	push BaseAddress
	push ProcessHandle
	Call [ebx].pZwQueryVirtualMemory
	%DBG "LWE: ZwQueryVirtualMemory(): 0x%X", Eax
	test eax,eax
	mov ecx,Information
	jnz @f
	mov MEMORY_BASIC_INFORMATION._Type[ecx],MEM_IMAGE
	xor eax,eax
	ret
@@:
	mov eax,[ebx].pZwQueryVirtualMemory
	%DBG "LWE: ZwQueryVirtualMemory(SKIP)"
	pop ebx
	leave
	Jmp Eax
_ZwQueryVirtualMemory endp

xVEH:
	%GET_CURRENT_GRAPH_ENTRY
VEH proc uses ebx esi ExceptionPointers:PEXCEPTION_POINTERS
	%DBG "LWE: VEH CALLED", Eax
	%GETENVPTR Esi
	assume esi:PUENV
	mov ebx,ebp
	assume ebx:PSTACK_FRAME
	jmp @f
Next:
	mov ebx,[ebx].Next
@@:
	cmp fs:[PcStackBase],ebx
	jna Exit
	cmp fs:[PcStackLimit],ebx
	ja Exit
	mov eax,[ebx].Ip
	cmp [esi].CodeBase,eax
	ja Next
	cmp [esi].CodeLimit,eax
	mov ecx,[esi].Delta
	jna Next
	%DBG "LWE: VEH ROUTE IP = 0x%X", Eax
	sub [ebx].Ip,ecx
	jmp Next
Exit:
	xor eax,eax
	ret
VEH endp

Initialize proc uses ebx esi edi
Local Status:NTSTATUS
Local NT2:PVOID
Local Header:PIMAGE_NT_HEADERS
Local SectionSize:ULONG
Local Env:UENV
Local EnvBase:PUENV, EnvSize:ULONG
Local Dir$[4*4]:CHAR
	%GETENVPTR Ebx
	test ebx,ebx
	cld
	mov Status,STATUS_UNSUCCESSFUL
	jnz Init
	lea edi,Env
%GENHASH 	024741E13H,
		0EA7DF819H,
		0DA44E712H,
		05CC20C59H,
		0C9419E41H,
		008C1BF69H,
		03BF9E770H,
		0DE02B845H,
		06E8164AFH,
		034DF9700H,
		07085AB5AH,
		0815C378DH,
		059B88A67H,
		0240265F3H,
		0DB164279H,
		09E1E35CEH,
		0019FD26EH,
		00F551A13H

	xor eax,eax		
	mov ecx,fs:[TEB.Peb]
	stosd	; EOL
	mov ecx,PEB.Ldr[ecx]
	mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[ecx]
	mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
	mov esi,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	%DBG "LWE: NT BASE: 0x%X", Esi
	invoke LdrEncodeEntriesList, Esi, addr Env
	%DBG "LWE: LdrEncodeEntriesList(): 0x%X", Eax
	test eax,eax
	lea ecx,Header
	jnz Exit
	push ecx
	push esi
	Call LdrImageNtHeader
	mov eax,Header
	mov NT2,NULL
	ifdef OPT_ENABLE_SCN
		movzx edi,IMAGE_NT_HEADERS.FileHeader.SizeOfOptionalHeader[eax]
		add esi,IMAGE_SECTION_HEADER.VirtualAddress[eax + edi + IMAGE_NT_HEADERS.OptionalHeader]
		mov edi,IMAGE_SECTION_HEADER.VirtualSize[eax + edi + IMAGE_NT_HEADERS.OptionalHeader]
		add edi,11B
	else
		add esi,IMAGE_NT_HEADERS.OptionalHeader.BaseOfCode[eax]
		mov edi,IMAGE_NT_HEADERS.OptionalHeader.SizeOfCode[eax]
	endif
	mov SectionSize,edi
	%DBG "LWE: NT CODE: 0x%X, 0x%X", Edi, Esi
	lea eax,SectionSize
	lea ecx,NT2
	mov Env.CodeBase,esi
	mov Env.CodeLimit,edi
	push PAGE_EXECUTE_READWRITE
	push MEM_COMMIT
	push eax
	push 0
	push ecx
	push NtCurrentProcess
	add Env.CodeLimit,esi
	Call Env.pZwAllocateVirtualMemory
	%DBG "LWE: ZwAllocateVirtualMemory(1): 0x%X", Eax
	test eax,eax
	mov Status,eax
	jnz Exit
	%DBG "LWE: NT2 BASE OF CODE: 0x%X", NT2
	
	mov EnvBase,eax
	mov EnvSize,sizeof(UENV)
	lea eax,EnvSize
	lea ecx,EnvBase
	push PAGE_READWRITE
	push MEM_COMMIT
	push eax
	push 0
	push ecx
	push NtCurrentProcess
	Call Env.pZwAllocateVirtualMemory
	%DBG "LWE: ZwAllocateVirtualMemory(2): 0x%X", Eax
	%DBG "LWE: ENVIRONMENT BASE: 0x%X", EnvBase
	test eax,eax
	mov Status,eax
	jnz Fail1
	
	mov edx,esi
	mov ecx,edi
	cld
	shr ecx,2
	mov edi,NT2
	rep movsd
	mov esi,edx
	sub esi,NT2
	mov Env.Delta,esi

%HOOK macro Api, Gp
	%GET_GRAPH_ENTRY Gp
	mov ecx,Api
	Call SetHook
endm

	%HOOK Env.pZwOpenSection, xZwOpenSection
	%HOOK Env.pZwMapViewOfSection, xZwMapViewOfSection
	%HOOK Env.pZwClose, xZwClose
	%HOOK Env.pZwQueryInformationProcess, xZwQueryInformationProcess
	%HOOK Env.pZwQueryVirtualMemory, xZwQueryVirtualMemory

	lea esi,Dir$
	lea edi,Env.Directory
	mov dword ptr Dir$[0],"onK\"
	mov dword ptr Dir$[4],"lDnw"
	mov dword ptr Dir$[2*4],"sl"
	push esi
	push edi
	Call Env.pRtlCreateUnicodeStringFromAsciiz
	lea edi,Env.Directory32
	test eax,eax
	mov dword ptr Dir$[2*4],"23sl"
	mov dword ptr Dir$[3*4],EOL
	jz Fail2
	push esi
	push edi
	Call Env.pRtlCreateUnicodeStringFromAsciiz
	test eax,eax
	mov ebx,EnvBase
	jz Fail3
	inc Env.pDbgBreakPoint

	%GET_GRAPH_ENTRY xVEH
	push eax
	push 1
	Call Env.pRtlAddVectoredExceptionHandler
	%DBG "LWE: RtlAddVectoredExceptionHandler(): 0x%X", Eax
	test eax,eax
	mov Env.VehHandle,eax
	jz Fail4

	mov edi,ebx
	lea esi,Env
	mov ecx,UENV.Var/4
	rep movsd
	
	%SETENVPTR Ebx
Init:
	xor eax,eax
Exit:
	mov eax,Status
	ret
Fail4:
	lea eax,Env.Directory32
	push eax
	Call Env.pRtlFreeUnicodeString
Fail3:
	lea eax,Env.Directory
	push eax
	Call Env.pRtlFreeUnicodeString
Fail2:
	lea eax,EnvSize
	lea ecx,EnvBase
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call Env.pZwFreeVirtualMemory
Fail1:
	lea eax,SectionSize
	lea ecx,NT2
	push MEM_RELEASE
	push eax
	push ecx
	push NtCurrentProcess
	Call Env.pZwFreeVirtualMemory
	jmp Exit
SetHook:
	sub ecx,esi
	mov byte ptr [ecx],0E9H	; OP_JMP_NEAR
	sub eax,ecx
	sub eax,5
	mov dword ptr [ecx + 1],eax
	retn
Initialize endp

LoadDll proc uses ebx DllMap:PVOID, DllName:PSTR, DllHandle:PHANDLE
Local Status:NTSTATUS
Local Header:PIMAGE_NT_HEADERS
Local DllCharacteristics:ULONG
	%GETENVPTR Ebx
	mov Status,STATUS_UNSUCCESSFUL
	.if !Ebx
		invoke Initialize
		test eax,eax
		jnz Exit
		%GETENVPTR Ebx
	.endif
	assume ebx:PUENV
	lea ecx,[ebx].DllName
	push DllName
	push ecx
	Call [Ebx].pRtlCreateUnicodeStringFromAsciiz
	test eax,eax
	lea ecx,[ebx].DllName
	lea edx,[ebx].SectionHandle
	jz Exit
	invoke LdrCreateImageSection, Ebx, Edx, DllMap, Ecx
	%DBG "LWE: LdrCreateImageSection(): 0x%X", Eax
	test eax,eax
	mov Status,eax
	jnz Fail
	invoke LdrImageNtHeader, DllMap, addr Header
	%DBG "LWE: LdrImageNtHeader(): 0x%X", Eax
	mov ecx,Header
	mov DllCharacteristics,eax
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.ImageBase[ecx]
	mov [ebx].Status,eax	; LDR_STATUS_PROCESSING
	mov [ebx].DllBase,ecx
	%DBG "LWE: DESIRED BASE: 0x%X", Ecx
	lea edx,DllCharacteristics
	lea ecx,[ebx].DllName
	mov eax,[ebx].pLdrLoadDll
	push DllHandle
	push ecx
	sub eax,[ebx].Delta
	push edx
	push NULL
	Call Eax
	%DBG "LWE: LdrLoadDll(): 0x%X", Eax
	lea ecx,[ebx].DllName
	mov Status,eax
	push ecx
	push [ebx].SectionHandle
	Call [Ebx].pZwClose
	Call [Ebx].pRtlFreeUnicodeString
Exit:
	mov eax,Status
	ret
Fail:
	lea eax,[ebx].DllName
	push eax
	Call [Ebx].pRtlFreeUnicodeString
	jmp Exit
LoadDll endp
end LoadDll