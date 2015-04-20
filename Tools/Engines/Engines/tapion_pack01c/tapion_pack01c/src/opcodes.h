 /*

  			        
		-------------------------------------------------------
                 TAPION POLYMORPHIC DECRYPTOR GENERATOR
         -------------------------------------------------------
			     by Piotr Bania <bania.piotr@gmail.com>
				      http://pb.specialised.info

					     All rights reserved!


  */




#ifndef __OPCODES_H__
#define __OPCODES_H__

// ----------------------------------------------------
// PREFIX  OPCODE  MODRM  SIB  FLAG  SIZE
// ----------------------------------------------------


#define		  __R_EAX				0
#define		  __R_ECX				1
#define		  __R_EDX				2
#define		  __R_EBX				3
#define		  __R_ESI				4
#define		  __R_EDI				5
#define		  __R_EBP				6

#define		  _MR_EAX				0
#define		  _MR_ECX				1
#define		  _MR_EDX				2
#define		  _MR_EBX				3
#define		  _MR_ESI				6
#define		  _MR_EDI				7
#define		  _MR_ESP				4

#define		  BLOCK1r				0		// xor reg0,reg0
#define		  BLOCK2r				0		// mov reg0,shellcode_size
#define		  BLOCK3r				1		// get_eip (reg1)
#define		  BLOCK4r				2		// mov reg2(PASS),reg1(EIP)
#define		  BLOCK5r				3		// mov reg3,do_shellcodu
#define		  BLOCK6r				4		// mov reg4,[reg3]



// every block has own register

#define POSSIBLE_REGS_SIZE 5

unsigned long possible_regs[]=	{_MR_EAX, _MR_ECX,  _MR_EDX, _MR_EBX, _MR_ESI, _MR_EDI};
unsigned long mut_regs_var[]=	{_MR_EBX, _MR_ECX,  _MR_ESI, _MR_EDX, _MR_EAX, _MR_EDI};





#define		END_TR			0xFF
#define		NO_M			0x2d
#define		C_NONE			0
#define		C_SRC			1
#define		C_DST			2
#define		C_BOTH			3



typedef struct t_op {
	BYTE prefix;
	BYTE opcode;
	BYTE modrm;
	BYTE sib;
	BYTE flag;
	BYTE size;
} t_op;


DWORD geip_table[] = {
		0xC324048b,				//	(04-modrm) mov reg,[esp] / ret
		0xC3905058,				//  (50-push reg)(58-pop reg)
		0xBBC35058,				//  (BB-random)(50-push reg)(58-pop reg)
		0xE0FF5890				//	(58-pop reg)(0e0FF-jmp reg 0e-modrm)
	};



unsigned char i_copro_init[] = {
	0x9B, 0xDB, 0xE3
};

unsigned char i_copro[] = {
	0xD9, 0xF0, 0xD9, 0xE1, 0xDE, 0xC1, 0xDE, 0xC1, 0xD9, 0xE0, 0xDB, 0xE2, 0xD8, 0xD1, 0xD8, 0xD9, 
	0xDE, 0xD9, 0xD9, 0xFF, 0xD9, 0xF6, 0xDE, 0xF9, 0xDE, 0xF9, 0xDE, 0xF1, 0xDE, 0xF1, 0xDD, 0xC1, 
	0xD9, 0xF7, 0xD9, 0xE8, 0xD9, 0xE9, 0xD9, 0xEA, 0xD9, 0xEB, 0xD9, 0xED, 0xDE, 0xC9, 0xDE, 0xC9, 
	0xDB, 0xE2, 0xD9, 0xD0, 0xD9, 0xF3, 0xD9, 0xF8, 0xD9, 0xF5, 0xD9, 0xF2, 0xD9, 0xFC, 0xD9, 0xFD, 
	0xD9, 0xFE, 0xD9, 0xFB, 0xD9, 0xFA, 0xDD, 0xD1, 0xDD, 0xD9, 0xDE, 0xE9, 0xDE, 0xE9, 0xDE, 0xE1, 
	0xDE, 0xE1, 0xD9, 0xE4, 0xDD, 0xE1, 0xDD, 0xE9, 0xDA, 0xE9, 0xD9, 0xE5, 0xD9, 0xF4, 0xD9, 0xF1, 
	0xD9, 0xF9
};




const t_op t_op_tbl[] = {
		{	NO_M,  0x33,  0xC0,  NO_M,  C_BOTH, 0x2 },			// xor reg,reg
		{	NO_M,  0xC7,  0xC0,  NO_M,  C_SRC,  0x6 },			// mov reg,num
		{   NO_M,  0x68,  NO_M,  NO_M,  C_NONE, 0x5 },			// push num
		{   NO_M,  0x58,  NO_M,  NO_M,  C_SRC,  0x1 },			// pop reg
		{   NO_M,  0x81,  0xE8,  NO_M,  C_SRC,  0x6 },			// sub reg,num
		{	NO_M,  0x81,  0xC0,  NO_M,  C_SRC,  0x6 },			// add reg,num
		{   NO_M,  0x40,  NO_M,  NO_M,  C_SRC,  0x1 },			// inc reg
		{   NO_M,  0x81,  0xF0,  NO_M,  C_SRC,  0x6 },          // xor reg,NUM
		{   NO_M,  0x2b,  0xC0,  NO_M,  C_BOTH, 0x2 },			// sub reg,reg
		{	NO_M,  0xf7,  0xD8,  NO_M,  C_SRC,  0x2 },			// neg reg
		{   NO_M,  0x0f,  0xC8,  NO_M,  C_SRC,  0x2 },			// bswap reg
		{	NO_M,  0x48,  NO_M,  NO_M,  C_SRC,  0x1 },			// dec reg
		{   NO_M,  0x8b,  0xC4,  NO_M,  C_BOTH, 0x2 },			// mov reg,reg
		{   NO_M,  0xff,  0xD0,  NO_M,  C_SRC,  0x2 },			// call reg
		{	NO_M,  0x8d,  0x1C,  0x24,  C_BOTH, 0x3 },          // lea reg,[reg]
		{	NO_M,  0x50,  NO_M,  NO_M,  C_SRC,  0x1 },			// push reg
		{	NO_M,  0x03,  0xC3,  NO_M,  C_BOTH, 0x1 },			// add reg,reg
		{	NO_M,  0x8b,  0x03,  NO_M,  C_BOTH, 0x2 },			// mov reg,[reg]
		{	NO_M,  0xff,  0x30,  NO_M,  C_SRC,  0x2 },			// push [reg]
		{	NO_M,  0x80,  0x3E,  NO_M,  C_SRC,  0x3 },			// cmp byte ptr [reg],magic
		{	NO_M,  0x75,  NO_M,  NO_M,  C_NONE, 0x2 },			// jne $-+
		{	NO_M,  0x85,  0xC0,  NO_M,  C_BOTH, 0x2 },			// test reg,reg
		{	NO_M,  0x21,  0xC0,  NO_M,  C_BOTH, 0x2 },			// and reg,reg
		{	NO_M,  0x09,  0xC0,  NO_M,  C_BOTH, 0x2 },			// or reg,reg
		{	NO_M,  0x90,  NO_M,  NO_M,  C_NONE, 0x1 },			// nop
		{	NO_M,  0x3b,  0xC3,  NO_M,  C_BOTH, 0x2 },			// cmp reg,reg
		{	NO_M,  0x81,  0xF8,  NO_M,  C_SRC,  0x6 },			// cmp reg,num
		{	NO_M,  0xF5,  NO_M,  NO_M,  C_NONE, 0x1 },			// cmc
		{	NO_M,  0xF9,  NO_M,  NO_M,  C_NONE, 0x1 },			// stc
		{	NO_M,  0xFD,  NO_M,  NO_M,  C_NONE, 0x1 },			// std
		{	NO_M,  0xFC,  NO_M,  NO_M,  C_NONE, 0x1 },			// cld
		{	NO_M,  0x7F,  NO_M,  NO_M,  C_NONE, 0x2 },			// jg $-+
		{	NO_M,  0x87,  0xC3,  NO_M,  C_BOTH, 0x2 },			// xchg reg,reg
		{	NO_M,  0x87,  0x18,  NO_M,  C_BOTH, 0x2 },			// xchg reg,[reg]
		{	NO_M,  0x31,  0x18,  NO_M,  C_BOTH, 0x2 },			// xor [reg],reg
		{	NO_M,  0xAD,  NO_M,  NO_M,  C_NONE, 0x1 },			// lodsd
		{	NO_M,  0x8F,  NO_M,  NO_M,  C_NONE, 0x5 },			// jg long $-+

};


#define		p_xor_reg_reg	0
#define		p_mov_reg_num	1
#define		p_push_num		2
#define		p_pop_reg		3
#define		p_sub_reg_num	4
#define		p_add_reg_num	5
#define		p_inc_reg		6
#define		p_xor_reg_num	7
#define		p_sub_reg_reg	8
#define		p_neg_reg		9
#define		p_bswap_reg		10
#define		p_dec_reg		11
#define		p_mov_reg_reg	12
#define		p_call_reg		13
#define		p_lea_reg_dreg	14
#define		p_push_reg		15
#define		p_add_reg_reg	16
#define		p_mov_reg_dreg	17
#define		p_push_dreg		18
#define		p_cmp_breg_val	19
#define		p_jne			20
#define		p_test_reg_reg	21
#define		p_and_reg_reg	22
#define		p_or_reg_reg	23
#define		p_nop			24
#define		p_cmp_reg_reg	25
#define		p_cmp_reg_num	26
#define		p_cmc			27
#define		p_stc			28
#define		p_std			29
#define		p_cld			30
#define		p_jg			31
#define		p_xchg_reg_reg	32
#define		p_xchg_reg_dreg	33
#define		p_xor_dreg_reg	34
#define		p_lodsd			35
#define		p_jg_long		36

#define		P_16b			0x66
#define		P_LOCK			0xF0


unsigned char i_gar_normal[] = {
	p_mov_reg_reg, p_and_reg_reg, p_test_reg_reg, p_or_reg_reg, p_nop, 
	p_cmp_reg_reg, p_cmp_reg_num, p_cmc, p_stc, p_std, p_cld
};

unsigned char i_gar_jmp[] = {
	0x77, 0x73, 0x72, 0x76, 0x74, 0x7F, 0x7D, 0x7C, 0x7E, 0x76,
	0x75, 0x71, 0x7B, 0x79, 0x75, 0x70, 0x7A, 0xE3, 0xEB,
	0x77 // repeat
};



#endif