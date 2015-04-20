EOL	equ NULL
CRLF	equ <13, 10, EOL>

%DBG macro Msg$, ArgList:VARARG
Local S$
	ifdef OPT_ENABLE_DBG_LOG
		pushfd
		pushad
		Args = 1
		For Arg, <ArgList>
			Args = Args + 1
			push Arg
		Endm
	.data
		S$ CHAR Msg$, CRLF
	.code
		push offset S$
		Call DbgPrint
		add esp,Args * 4
		popad
		popfd
	endif
endm

LDR_STATUS_PROCESSING		equ 0
LDR_STATUS_SECTION_OPENED	equ 1
LDR_STATUS_SECTION_MAPPED	equ 2
LDR_STATUS_SECTION_CHECKED	equ 3
LDR_STATUS_SECTION_CLOSED	equ 4

PPVOID	typedef ptr PVOID

%GET_CURRENT_GRAPH_ENTRY macro
	Call GPREF
endm

%GET_GRAPH_ENTRY macro PGET_CURRENT_GRAPH_ENTRY
	Call PGET_CURRENT_GRAPH_ENTRY
endm

%GET_GRAPH_REFERENCE macro
GPREF::
	pop eax
	ret
endm

UENV struct
pZwAllocateVirtualMemory			PVOID ?
;pZwProtectVirtualMemory			PVOID ?
pZwQueryVirtualMemory			PVOID ?
pZwFreeVirtualMemory			PVOID ?
pZwCreateSection				PVOID ?
pZwOpenSection					PVOID ?
pZwMapViewOfSection				PVOID ?
pZwUnmapViewOfSection			PVOID ?
pZwClose						PVOID ?
pZwQueryObject					PVOID ?
pZwQueryInformationProcess		PVOID ?
pZwQuerySystemInformation		PVOID ?
pRtlAddVectoredExceptionHandler	PVOID ?
pRtlCreateUnicodeStringFromAsciiz	PVOID ?
pRtlCompareUnicodeString			PVOID ?
pRtlFreeUnicodeString			PVOID ?
pLdrLoadDll					PVOID ?
pDbgBreakPoint					PVOID ?
pRtlWalkFrameChain				PVOID ?
Directory						UNICODE_STRING <>
Directory32					UNICODE_STRING <>
CodeBase						PVOID ?
CodeLimit						PVOID ?
Delta						ULONG ?
VehHandle						HANDLE ?
;			~ var's ~
union
	Var						DWORD ?
	DllName					UNICODE_STRING <>
ends
DllBase						PVOID ?	; Des. base
SectionHandle					HANDLE ?
ViewBase						PVOID ?
Status						ULONG ?
UENV ends
PUENV typedef ptr UENV

EOL	equ NULL
CRLF	equ <13, 10, EOL>

ENV_OFFSET	equ (X86_PAGE_SIZE - 4)

%APICALL macro pApi, Args
	Call pApi
endm

; ks386.inc
TePeb	equ 30H	; TEB.Peb
PcSelfPcr	equ 1CH

%GETENVPTR macro Reg32
	assume fs:nothing
	mov Reg32,dword ptr fs:[TEB.Peb]
	mov Reg32,dword ptr [Reg32 + ENV_OFFSET]
endm

%SETENVPTR macro Val
	assume fs:nothing
	mov eax,dword ptr fs:[TEB.Peb]
	mov dword ptr [eax + ENV_OFFSET],Val
endm

%GENHASH macro HashList:VARARG
Local Iter, PrevHash
   Iter = 0
   for Hash, <HashList>
      if Iter eq 0
         xor eax,eax
         sub eax,-Hash
      elseif (Iter eq 1) or (Iter eq 3)
         xor eax,(PrevHash xor Hash)
      elseif Iter eq 2
         add eax,dword ptr (Hash - PrevHash)
      elseif Iter eq 4
         sub eax,dword ptr (PrevHash - Hash)
      endif
      stosd
      Iter = Iter + 1
      PrevHash = Hash
      if Iter eq 5
         Iter = 1
      endif
   endm
endm

STACK_FRAME struct
Next		PVOID ?	; PSTACK_FRAME
Ip		PVOID ?
STACK_FRAME ends
PSTACK_FRAME typedef ptr STACK_FRAME

PcStackBase	equ 4
PcStackLimit	equ 8