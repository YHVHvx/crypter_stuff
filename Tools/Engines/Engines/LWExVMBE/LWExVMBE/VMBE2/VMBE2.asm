; VMBE 2.1
;
; (c) Indy, 2013
;
; o IA32, UM, MI
;
	.686
	.model flat, stdcall
	option casemap :none
	
	include \masm32\include\ntdll.inc
	includelib \masm32\lib\ntdll.lib

.code
	jmp VMBYPASS	; IDLE

	include VirXasm32b.asm	; LDE
	
MAX_IP_LENGTH	equ 15

; +
; Eax - число префиксов.
; Ecx - последний префикс.
; Edx - 0x67 Pfx.
;
LPFX proc uses ebx esi edi Address:PVOID
Local PrefixesTable[12]:BYTE
Local IpLength:ULONG
comment '
PrefixesTable:
	BYTE PREFIX_LOCK
	BYTE PREFIX_REPNZ
	BYTE PREFIX_REP
	BYTE PREFIX_CS
	BYTE PREFIX_DS
	BYTE PREFIX_SS
	BYTE PREFIX_ES
	BYTE PREFIX_FS
	BYTE PREFIX_GS
	BYTE PREFIX_DATA_SIZE
	BYTE PREFIX_ADDR_SIZE
	'
	mov IpLength,MAX_IP_LENGTH + 1
	mov dword ptr [PrefixesTable],02EF3F2F0H
	mov dword ptr [PrefixesTable + 4],06426363EH
	mov dword ptr [PrefixesTable + 8],000676665H
	mov esi,Address
	cld
	lea edx,PrefixesTable
	xor ebx,ebx
@@:
	dec IpLength
	.if Zero?
		xor eax,eax
		xor ecx,ecx
		jmp Exit
	.endif
	lodsb
	mov edi,edx
	cmp al,PREFIX_ADDR_SIZE
	mov ecx,11
	.if Zero?
		or bl,1
	.endif
	repne scasb
	jz @b
	dec esi
	xor eax,eax
	movzx ecx,byte ptr [esi - 1]
	sub esi,Address
	.if Zero?
		xor ecx,ecx
	.else
		mov eax,esi
	.endif
Exit:
	mov edx,ebx
	ret
LPFX endp

MODRM_MOD		equ 11000000B
MODRM_REG		equ 00111000B
MODRM_RM		equ 00000111B

SIB_SCALE		equ 11000000B
SIB_INDEX		equ 00111000B
SIB_BASE		equ 00000111B

RGP struct
rEdi		DWORD ?
rEsi		DWORD ?
rEbp		DWORD ?
rEsp		DWORD ?
rEbx		DWORD ?
rEdx		DWORD ?
rEcx		DWORD ?
rEax		DWORD ?
RGP ends
PRGP typedef ptr RGP

; +
;
; Раскодировка ModR/M.
;
	assume fs:nothing
ModRM proc uses ebx esi edi pModRM:PVOID, Pfx:ULONG, State:PRGP
	mov ebx,pModRM
	xor edi,edi	; Длина.
	movzx eax,byte ptr [ebx]	; ModRM
	mov esi,State
	mov edx,eax
	not al
	rol dl,2
	and al,MODRM_RM	; R/M
	and dl,(MODRM_MOD shr 6)	; MOD
	assume esi:PRGP
	jz Mod00
	dec dl
	jz Mod01
	dec dl
	jz Mod10
Mod11:
	mov eax,D[esi + eax*4]
	jmp Exit
Mod00:
	cmp al,MODRM_RM and NOT(100B)
	je Mod00_100
	cmp al,MODRM_RM and NOT(101B)
	je Mod00_101
	mov eax,D[esi + eax*4]
	jmp Read
Mod00_101:
	; DISP32
	mov eax,D[ebx + 1]
	add edi,4
	jmp Read
Mod00_100:
	Call SIB
	inc edi
	jmp Read
Mod01:
	cmp al,MODRM_RM and NOT(100B)
	jz Mod01_100
	mov eax,D[esi + eax*4]
Mod01_100_Disp:
	movzx edx,B[ebx + edi + 1]	; Disp8
	inc edi
	btr edx,7	; S
	.if Carry?
		sub eax,80H
	.endif
	add eax,edx
	jmp Read
Mod01_100:
	Call SIB
	inc edi
	jmp Mod01_100_Disp
Mod10:
	cmp al,MODRM_RM and NOT(100B)
	jz Mod10_100
	mov eax,D[esi + eax*4]
Mod10_100_Disp:
	add eax,D[ebx + edi + 1]	; Disp32
	add edi,4
	jmp Read
Mod10_100:
	Call SIB
	inc edi
	jmp Mod10_100_Disp
Read:
	.if Pfx == PREFIX_FS
		mov eax,D fs:[eax]
	.else
		mov eax,D ds:[eax]
	.endif
Exit:
	mov ecx,edi
	ret
SIB:
	movzx eax,B[ebx + 1]	; SIB
	mov ecx,eax
	not al
	push eax
	rol cl,2
	shr eax,1
	and cl,(SIB_SCALE shr 6)	; Scale
	and al,(SIB_INDEX shr 1)	; Index
	mov eax,D[esi + eax]	; Index reg.
	shl eax,cl	; Scale * Index
	pop ecx
	and cl,SIB_BASE
	.if (cl == (SIB_BASE and NOT(101B))) && (!dl) ; MOD: 00
		add eax,D[ebx + 2]
		add edi,4
	.else
		add eax,D[esi + ecx*4]	; Base reg.
	.endif
	retn 0
ModRM endp

JCC_TYPE_MASK	equ 00001111B

; +
;
; !ZF: TRUE
;
IsCC proc JccType:DWORD, EFlags:DWORD
	and JccType,JCC_TYPE_MASK
	mov eax,JccType
	mov ecx,EFlags
	and JccType,1
	Call @f
	setc al
	xor JccType,eax
	ret
@@:
	shr eax,1
	and eax,JCC_TYPE_MASK/2
	jz CC_O
	dec al
	jz CC_C
	dec al
	jz CC_Z
	dec al
	jz CC_NA
	dec al
	jz CC_S
	dec al
	jz CC_P
	dec al
	jz CC_L
	dec al
CC_NG:
	bt ecx,6
	.if Carry?
		retn
	.endif
CC_L:
	test ecx,EFLAGS_SF
	bt ecx,11
	.if Zero?
		jc Set
	.else
		jnc Set
	.endif
	xor eax,eax
	retn
Set:
	stc
	retn
CC_O:
	bt ecx,11
	retn
CC_C:
	bt ecx,0
	retn
CC_Z:
	bt ecx,6
	retn
CC_S:
	bt ecx,7
	retn
CC_P:
	bt ecx,2
	retn
CC_NA:
	test ecx,EFLAGS_CF or EFLAGS_ZF
	jnz Set
	retn
IsCC endp

OP_ESC2B	equ 0FH

JCC_SHORT_OPCODE_BASE	equ 70H
JCC_NEAR_OPCODE_BASE	equ 80H

JCC_O	equ 0	; OF
JCC_NO	equ 1	; !OF
JCC_C	equ 2	; CF
JCC_B	equ 2	; CF
JCC_NAE	equ 2	; CF
JCC_NC	equ 3	; !CF
JCC_NB	equ 3	; !CF
JCC_AE	equ 3	; !CF
JCC_Z	equ 4	; ZF
JCC_E	equ 4	; ZF
JCC_NZ	equ 5	; !ZF
JCC_NE	equ 5	; !ZF
JCC_NA	equ 6	; CF | ZF
JCC_BE	equ 6	; CF | ZF
JCC_A	equ 7	; !CF & !ZF
JCC_NBE	equ 7	; !CF & !ZF
JCC_S	equ 8	; SF
JCC_NS	equ 9	; !SF
JCC_P	equ 0AH	; PF
JCC_PE	equ 0AH	; PF
JCC_NP	equ 0BH	; !PF
JCC_PO	equ 0BH	; !PF
JCC_L	equ 0CH	; SF != OF
JCC_NGE	equ 0CH	; SF != OF
JCC_NL	equ 0DH	; SF = OF
JCC_GE	equ 0DH	; SF = OF
JCC_NG	equ 0EH	; ZF | (SF != OF)
JCC_LE	equ 0EH	; ZF | (SF != OF)
JCC_G	equ 0FH	; !ZF & (SF = OF)
JCC_NLE	equ 0FH	; !ZF & (SF = OF)

; o Jump short: 0x70 + JCC_*
; o Jump near: 0x0F 0x80 + JCC_*

JCC_LOOPNE	equ 0E0H	; Ecx & !ZF
JCC_LOOPE		equ 0E1H	; Ecx & ZF
JCC_LOOP		equ 0E2H	; Ecx
JCC_ECXZ		equ 0E3H	; !Ecx

JCX_OPCODE_BASE	equ 0E0H

; +
;
; Определяет следующую инструкцию, после исполнения ветвления(Jcc/Jcx).
;
JccToCC proc uses ebx Ip:PVOID, EFlags:DWORD, prEcx:DWORD
	mov ebx,Ip
	movzx eax,byte ptr [ebx]	; Opcode
	cmp al,OP_ESC2B
	je IsNear
	cmp al,JCC_SHORT_OPCODE_BASE
	jb Error
	cmp al,JCC_SHORT_OPCODE_BASE + 15
	ja IsJcx
	invoke IsCC, Eax, EFlags
	.if Zero?
		movzx eax,byte ptr [ebx + 1]	; Disp.
		add ebx,2
	.else
Jcx:
		movzx eax,byte ptr [ebx + 1]	; Disp.
		btr eax,7
		.if Carry?
			sub eax,80H
		.endif
		lea ebx,[eax + ebx + 2]
		.if Edx
			and ebx,0FFFFH
		.endif
	.endif
	jmp Exit	
IsNear:
	movzx eax,byte ptr [ebx + 1]
	cmp al,JCC_NEAR_OPCODE_BASE
	jb Error
	cmp al,JCC_NEAR_OPCODE_BASE + 15
	ja Error
	invoke IsCC, Eax, EFlags
	.if Zero?
		add ebx,6
	.else
		mov eax,dword ptr [ebx + 2]
		lea ebx,[eax + ebx + 6]
	.endif
	jmp Exit
IsJcx:
	mov ecx,prEcx
	sub al,JCX_OPCODE_BASE
	jb Error
	cmp al,(JCC_ECXZ - JCX_OPCODE_BASE)
	ja Error
; ADDR SIZE NOT USED!
	.if Zero?	; JCC_LOOPNE; Ecx & !ZF
		bt EFlags,6	; ZF
		dec D[ecx]	; !ZF & !CF
		ja Jcx		
	.else
		dec eax
		.if Zero?	; JCC_LOOPE; Ecx & ZF
			bt EFlags,6	; ZF
			dec D[ecx]	; !ZF & CF
			cmc	; !ZF & !CF
			ja Jcx
		.else
			dec eax
			.if Zero?	; JCC_LOOP; Ecx
				dec D[ecx]	; !ZF & CF
				jnz Jcx
			.else	; JCC_ECXZ; !Ecx
				cmp D[ecx],0
				je Jcx
			.endif
		.endif
	.endif
	add ebx,2
Exit:
	mov eax,ebx
@@:
	ret
Error:
	xor eax,eax
	jmp @b
JccToCC endp

OP_JMP_SHORT	equ 0EBH
OP_JMP_NEAR	equ 0E9H
OP_JMP_FAR	equ 0EAH

; +
;
JmpToCC proc uses ebx Ip:PVOID, Pfx:ULONG, State:PRGP
	mov ebx,Ip
	movzx eax,byte ptr [ebx]	; Opcode
	cmp al,OP_JMP_SHORT
	jne @f
	movzx eax,byte ptr [ebx + 1]
	btr eax,7
	.if Carry?
		sub eax,80H
	.endif
	lea eax,[eax + ebx + 2]
	jmp Exit
@@:
	cmp al,OP_JMP_NEAR
	jne @f
	mov eax,dword ptr [ebx + 1]
	lea eax,[eax + ebx + 5]
	jmp Exit
@@:
	cmp al,0FFH	; Grp. 5
	jne Error
	movzx eax,byte ptr [ebx + 1]	; ModR/M
	and al,MODRM_REG
	shr al,3
	.if al == 100B
		inc ebx
		invoke ModRM, Ebx, Pfx, State
	.else
Error:
		xor eax,eax
	.endif
Exit:
	ret
JmpToCC endp

OP_CALL_REL	equ 0E8H

; +
;
CallToCC proc uses ebx Ip:PVOID, Pfx:ULONG, State:PRGP
	mov ebx,Ip
	movzx ecx,byte ptr [ebx]	; Opcode
	cmp cl,OP_CALL_REL
	jne @f
	lea ecx,[eax + 5]
	mov edx,dword ptr [ebx + 1]
	lea eax,[edx + ebx + 5]
	jmp Exit
@@:
	cmp cl,0FFH	; Grp. 5
	jne Error
	movzx ecx,byte ptr [ebx + 1]	; ModR/M
	and cl,MODRM_REG
	shr cl,3
	.if cl == 010B
		push eax
		inc ebx
		invoke ModRM, Ebx, Pfx, State
		pop edx
		lea ecx,[ecx + edx + 2]
	.else
Error:
		xor eax,eax
	.endif
Exit:
	ret
CallToCC endp

	assume fs:nothing
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

	%GET_GRAPH_REFERENCE

TSTATE struct
Rgp		RGP <>
EFlags	DWORD ?
Ip		DWORD ?
TSTATE ends
PTSTATE typedef ptr TSTATE

%TLSSET macro Value
	mov eax,fs:[TEB.Tib.StackBase]
	mov D[eax - 4],Value
endm

%TLSGET macro r32
	mov r32,fs:[TEB.Tib.StackBase]
	mov r32,D[r32 - 4]
endm

DBG_PRINTEXCEPTION_C	equ 40010006H

OP_INT	equ 0CDH
OP_RET	equ 0C3H
OP_RETW	equ 0C2H

; typedef ULONG (*PENTRY)(
;	IN PVOID BufferRWE,
;	IN PVOID Ip,
;	IN PCALLBACK Callback OPTIONAL,
;	IN PVOID CallbackArg,
;	IN ULONG ArgN,
;	IN PVOID Args
;	)

; typedef NTSTATUS (*PCALLBACK)(
;	IN PVOID CallbackArg,
;	IN PVOID Ip,
;	IN PTSTATE State
;	)

PUBLIC VT_SYSENTER
PUBLIC VT_INT2D
PUBLIC VT_INT2E
PUBLIC VT_ISXCPT
PUBLIC VT_WOW

VMBYPASS proc uses ebx esi edi BufferRWE:PVOID, Ip:PVOID, Clbk:PVOID, ClbkArg:PVOID, ArgN:ULONG, Args:PVOID
Local pSp:PVOID
Local pBreak:PVOID
Local Pfx:ULONG
	mov ecx,ArgN
	%TLSSET Ebp
	mov pSp,esp	; stdcall conv.
	mov eax,Args
	.if Ecx
		.repeat
			push dword ptr [eax + ecx*4 - 4]
			dec ecx
		.until Zero?
	.endif
	Call Start
Exit:
	popad
	popfd
	lea esp,[esp + 4]	; Ip
Lv:
	ret
Start:
	push 0	; Ip
	pushfd
	pushad
	sub pSp,sizeof(TSTATE)
Step:
	cmp Clbk,NULL
	cld
	.if !Zero?
		push esp
		push Ip
		push ClbkArg
		Call Clbk
		.if Eax
			mov esp,pSp
			add esp,sizeof(TSTATE)
			jmp Lv
		.endif
	.endif
	mov esi,Ip
	Call VirXasm32
	mov ebx,eax	; LDE()
	add Ip,eax	; Ip'
	invoke LPFX, Esi
	mov Pfx,ecx
	lea edi,[esi + eax]	; @OPCODE
	invoke JmpToCC, Edi, Pfx, Esp
	test eax,eax
	jnz Store
	invoke JccToCC, Edi, TSTATE.EFlags[Esp + 4], addr TSTATE.Rgp.rEcx[Esp]
	test eax,eax
	jnz Store
	invoke CallToCC, Edi, Pfx, Esp
	test eax,eax
	jz IsRet
PushIp:
	mov edx,Ip
	push eax
	mov edi,esp
	lea esi,[edi + 4]
	mov ecx,sizeof(TSTATE)/4
	rep movsd
	mov D[edi],edx
	jmp Store
IsRet:
	.if (B[Esi] == OP_JMP_FAR) && (W[Esi + 5] == 33H)	; jmp far
VT_WOW::
		mov ecx,TSTATE.Rgp.rEsp[esp]
		%GET_GRAPH_ENTRY xGate
		xchg D[ecx + 4],eax
		mov Ip,eax	; ~ stub
		jmp VT_INT2E
	.endif
	cmp B[edi],OP_RET
	jne IsRetW
	mov eax,D[esp + sizeof(TSTATE)]
	lea esi,[esp + sizeof(TSTATE) - 4]
	lea edi,[esi + 4]
	std
	mov ecx,sizeof(TSTATE)/4
	rep movsd
	pop edx	; -4
	cld
	jmp IsEnd
IsRetW:
	cmp B[edi],OP_RETW
	jne @f
	mov eax,D[esp + sizeof(TSTATE)]
	movzx edx,W[edi + 1]
	std
	lea esi,[esp + sizeof(TSTATE) - 4]
	lea edi,[esi + edx + 4]
	mov ecx,sizeof(TSTATE)/4
	rep movsd
	lea esp,[esp + edx + 4]
	cld
IsEnd:
	cmp pSp,esp
	jbe Exit
	jmp Store
@@:
comment '
Возврат из сискола(sysenter) происходит не на следующую за ней инструкцию, а на 
адрес KiFastSystemCallRet(инструкция Ret), так как эта инструкция не передаёт в 
хэндлер текущий адрес(Eip). Управление будет передано на трассируемый код. После 
возврат в основной цикл на стеке не будет TSTATE. Контекст рандомный и при возв
рате из цикла возникнет #AV. Для устранения этого можно поступить следующим обр
азом:
 o Заменить Sysenter на Int 0x2e.
 o Загружать на стек адрес заглушки(xGate).
Используем 2-й способ.'
	cmp B[edi],0FH
	jne @f
	cmp B[edi + 1],34H	; SYSENTER
	jne @f
VT_SYSENTER::
	mov ecx,TSTATE.Rgp.rEdx[esp]
	%GET_GRAPH_ENTRY xGate
	xchg D[ecx],eax
	mov Ip,eax	; ~ stub
	mov eax,TSTATE.Rgp.rEdx[esp]
	add eax,2*4
	jmp IsXcpt
@@:
; Возврат из отладочного прерывания выполняется на $+1.
	cmp B[edi],OP_INT
	jne Line
	cmp B[edi + 1],2DH		; KiDebugService
	jne @f
VT_INT2D::
	mov edi,BufferRWE
	mov D[edi],90902DCDH	; Int 0x2D/Nop/Nop
	inc Ip
	add edi,4
	jmp Load
@@:
	cmp B[edi + 1],2EH		; KiSystemService
	jne Line
VT_INT2E::
	mov eax,TSTATE.Rgp.rEdx[esp]
VT_ISXCPT::
comment '
Сервис NtRaiseException загружает контекст в процессор(аналогично NtContinue).
Это приведёт к выходу из под трассировки и дальнейшему фолту(как и Sysenter).
Сервис используется для отладочного вывода(посылка DBG_PRINTEXCEPTION_C). Это 
событие необходимо обнаружить и загрузить в контекст заглушку.'
; ZwRaiseException(
;	IN PEXCEPTION_RECORD ExceptionRecord,
;	IN PCONTEXT Context,
;	IN BOOLEAN FirstChance
;	):NTSTATUS
IsXcpt:
	mov ecx,fs:[TEB.Tib.StackBase]
; o Аргументы на стеке.
	cmp TSTATE.Rgp.rEsp[esp],eax
	mov edi,BufferRWE
	ja Line
	cmp eax,ecx
	jnb Line
; o FirstChance: TRUE
	cmp D[eax + 2*4],TRUE
	mov edx,D[eax]
	jne Line
; o PEXCEPTION_RECORD на стеке.
	cmp TSTATE.Rgp.rEsp[esp],edx
	ja Line
	cmp edx,ecx
	jnb Line
; o #DBG_PRINTEXCEPTION_C
	cmp EXCEPTION_RECORD.ExceptionCode[edx],DBG_PRINTEXCEPTION_C
	jne Line
; o Arg's: 2
	cmp EXCEPTION_RECORD.NumberParameters[edx],2
	jne Line
; o PCONTEXT на стеке.
	mov edx,D[eax + 4]
	cmp TSTATE.Rgp.rEsp[esp],edx
	ja Line
	cmp edx,ecx
	jnb Line
; o Flags.
	cmp CONTEXT.ContextFlags[edx],CONTEXT_CONTROL or CONTEXT_INTEGER or CONTEXT_SEGMENTS
	jne Line
; Заглушку в контекст.
	%GET_GRAPH_ENTRY xGate
	xchg CONTEXT.rEip[edx],eax
	mov Ip,eax
Line:
	mov ecx,ebx
	mov edi,BufferRWE
	rep movsb
Load:
	%GET_GRAPH_ENTRY xGate
	mov ecx,BufferRWE
	mov B[edi],68H	; "push imm32"
	mov D[edi + 1],eax
	mov B[edi + 5],0C3H	; "ret"
	mov TSTATE.Ip[esp],ecx
	popad
	popfd
	retn 0
Store:
	mov Ip,eax
	jmp Step
xGate:
	%GET_CURRENT_GRAPH_ENTRY
	push 0	; Ip
	pushfd
	pushad
	%TLSGET Ebp
	jmp Step
VMBYPASS endp
end VMBYPASS