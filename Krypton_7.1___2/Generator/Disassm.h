#define _SALC	0xD6
#define _AAM	0xD4
#define NRM_TAB_LEN	53

#define DB __asm _emit



__declspec(naked) DWORD _cdecl MDAL_GetOpcodeLen(BYTE* opcode)
{
	_asm
	{
		mov esi, [esp + 4]
		pushad
			push	000001510h
			push	0100101FFh
			push	0FFFFFF55h
			push	0FFFFFFF8h
			push	0F8FF7FA0h
			push	00F0EC40Dh
			push	007551004h
			push	001D005FFh
			push	0550D5D55h
			push	0555F0F88h
			push	0F3F3FFFFh
			push	00A0C1154h

			mov	edx, esi
			mov	esi, esp

			push	11001b
			push	10110000101011000000101110000000b
			push	10111111101100011111001100111110b
			push	00000000000100011110101001011000b
			mov	ebx, esp
			sub	esp, 110
			mov	edi, esp

			cld
			push	100
			pop	ecx
xa_nxtIndx:
		bt	[ebx], ecx
			DB _SALC

			jnc	xa_is0
			lodsb
xa_is0:
		stosb
			loop	xa_nxtIndx
			mov	esi, edx

			push	2
			pop	ebx
			mov	edx, ebx
xa_NxtByte:
		lodsb
			push	eax
			push	eax
			cmp	al, 66h
			cmove	ebx, ecx
			cmp	al, 67h
			cmove	edx, ecx
			cmp	al, 0EAh
			je	xa_jmp
			cmp	al, 09Ah
			jne	xa_nocall

			inc	esi
xa_jmp:
		lea	esi, [esi+ebx+3]
xa_nocall:
		cmp	al, 0C8h
			je	xa_i16
			and	al, 0F7h
			cmp	al, 0C2h
			jne	xa_no16
xa_i16:
		inc	esi
			inc	esi

xa_no16:
		and	al, 0E7h
			cmp	al, 26h
			pop	eax
			je	xa_PopNxt
			cmp	al, 0F1h
			je	xa_F1
			and	al, 0FCh
			cmp	al, 0A0h
			jne	xa_noMOV
			lea	esi, [esi+edx+2]
xa_noMOV:
		cmp	al, 0F0h
			je	xa_PopNxt
xa_F1:
		cmp	al, 64h
xa_PopNxt:
		pop	eax
			je	xa_NxtByte

			mov	edi, esp
			push	edx
			push	eax
			cmp	al, 0Fh
			jne	xa_Nrm
			lodsb
xa_Nrm:
		pushfd
			DB _AAM
			DB 10h
			xchg	cl, ah
			cwde
			cdq
			xor	ebp, ebp
			popfd
			jne	xa_NrmGroup

			add	edi, NRM_TAB_LEN
			jecxz	xa_3
xa_1:
		bt	[edi], ebp
			jnc	xa_2
			inc	edx
xa_2:
		inc	ebp
			loop	xa_1
			jc	xa_3
			DB _SALC
			cdq
xa_3:
		shl	edx, 1
			jmp	xa_ProcOpcode

xa_NrmGroup:
		sub	cl, 4
			jns	xa_4
			mov	cl, 0Ch
			and	al, 7
xa_4:
		jecxz	xa_4x
xa_5:
		adc	dl, 1
			inc	ebp
			bt	[edi], ebp
			loop	xa_5
			jc	xa_ProcOpcode
xa_4x:
		shr	al, 1

xa_ProcOpcode:
		xchg	cl, al
			lea	edx, [edx*8+ecx]
		pop	ecx
			pop	ebp
			bt	[edi+2], edx
			jnc	xa_noModRM

			lodsb
			DB _AAM
			DB 8
			shl	ah, 4
			jnc	xa_isModRM
			js	xa_enModRM
xa_isModRM:
		pushfd
			test	ebp, ebp
			jnz	xa_addr32	
			sub	al, 6
			jnz	xa_noSIB
			mov	al, 5
xa_addr32:
		cmp	al, 4
			jne	xa_noSIB
			lodsb
			and	al, 7
xa_noSIB:
		popfd
			jc	xa_iWD
			js	xa_i8
			cmp	al, 5
			jne	xa_enModRM
xa_iWD:	
		add	esi, ebp
			inc	esi
xa_i8:
		inc	esi

xa_enModRM:
		test	ah, 60h
			jnz	xa_noModRM
			xchg	eax, ecx
			cmp	al, 0F6h
			je	xa_ti8
			cmp	al, 0F7h
			jne	xa_noModRM
			add	esi, ebx
			inc	esi
xa_ti8:
		inc	esi

xa_noModRM:
		shl	edx, 1
			bt	[edi+2+17], edx
			jnc	xa_Exit
			inc	edx
			bt	[edi+2+17], edx
			jnc	xa_im8
			adc	esi, ebx
xa_im8:
		inc	esi

xa_Exit:
		add	esp, 110+64
			sub	esi, [esp+4]
		mov	[esp+7*4], esi
			popad
			ret
	}
}


int MDAL_GetOpcodesLenByNeedLen(BYTE* opcode, int NeedLen)
{
	int FullLen = 0;
	int len;

	do
	{
		len = MDAL_GetOpcodeLen(opcode + FullLen);
		if (!len)
		{
			return 0;
		}
		FullLen += len;
	}
	while (FullLen < NeedLen);

	return FullLen;
}

DWORD _getOpcodeLength(void *pAddress)
{
	int ll = MDAL_GetOpcodeLen((PBYTE)pAddress);
	Sleep(0);
	return ll;
}

//Читаем опкоды, пока их суммарная длина не достигнит INJECT_SIZE.
//DWORD_PTR opcodeOffset = 0;
//for(;;)
//{
//	LPBYTE currentOpcode = buf + opcodeOffset;
//	DWORD currentOpcodeLen = Disasm::_getOpcodeLength(currentOpcode);
//
//	//Неизвестный опкод.
//	if(currentOpcodeLen == (DWORD)-1)
//	{
//		DPRINT2("Bad opcode detected at offset %u for function 0x%p", opcodeOffset, functionForHook);
//
//		goto END; 
//	}
//
//	opcodeOffset += currentOpcodeLen;
//
//	if(opcodeOffset > sizeof(buf) - JMP_ADDR_SIZE)
//	{
//		DPRINT2("Very long opcode detected at offset %u for function 0x%p", opcodeOffset - currentOpcodeLen, functionForHook);
//		goto END; 
//	}
//
//	//Отностиельные call и jmp.
//	if((currentOpcode[0] == 0xE9 || currentOpcode[0] == 0xE8) && currentOpcodeLen == 1 + sizeof(DWORD)) //FIXME: не уверен для x64.
//	{
//		DPRINT1("Relative JMP/CALL(%02X) detected.", currentOpcode[0]);
//		DWORD *relAddrSet = (DWORD *)(currentOpcode + 1);
//		DWORD_PTR to = (*relAddrSet) + ((DWORD_PTR)functionForHook + opcodeOffset);
//		*relAddrSet = (DWORD)(to - ((DWORD_PTR)originalFunction + opcodeOffset));
//	}
//
//	if(opcodeOffset >= INJECT_SIZE)break;
//}