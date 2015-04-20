 /*

  			        
		-------------------------------------------------------
                 TAPION POLYMORPHIC DECRYPTOR GENERATOR
         -------------------------------------------------------
			     by Piotr Bania <bania.piotr@gmail.com>
				      http://pb.specialised.info

					     All rights reserved!


  */



#ifndef __TPOLY_H__
#define __TPOLY_H__

#include "main.h"



#define		TYPE_DEC				0
#define		TYPE_INC				1

#define		gen_xor_reg				gen_block1
#define		gen_mov_reg_num			gen_block2
#define		gen_get_eip				gen_block3
#define		gen_copy_reg			gen_block4
#define		gen_mov_reg_dreg		gen_block6
#define		gen_crypto				gen_block7
#define		gen_inc_dec_reg			gen_block8
#define		gen_cmp_breg_magic		gen_block9
#define		gen_cmp_final			gen_block10



extern char filename[MAX_PATH+1];

extern DWORD garbage_size;

extern int do_jumps;
extern int choosen_var;
extern int hard_var;
extern int last_randomized;

extern int was_add;
extern int magic_store;
extern int przed_magic;
extern int step_inc;
extern int step_dec;
extern int f_decr;
extern int f2_decr;
extern int f3_decr;
extern int garbage_global_flag;

extern DWORD fix_magic;
extern int copro_init;
extern int garbage_flag;
extern DWORD where_call;
extern DWORD DwordAleatorio1;
extern DWORD DwordAleatorio2;
extern DWORD DwordAleatorio3;

void setup_random(void);
DWORD get_random(void);
DWORD random_eax(DWORD max_value);
DWORD random_without_zero(void);
int is_good_num(DWORD r);

int	 gen_instruction(unsigned char *loc, BYTE prefix, DWORD i_num, char operand[], BYTE src_reg, BYTE dst_reg);
void sample(void);

int gen_block1(unsigned char *loc, BYTE reg);					// block 1 is: xor reg,reg
int	gen_block2(unsigned char *loc, BYTE reg, DWORD s_size);		// mov reg,shellcode_size
int gen_block3(unsigned char *loc, BYTE reg);					// gen getEIP block
int gen_block4(unsigned char *loc, BYTE src_reg, BYTE dst_reg); // gen mov dst_reg,src_reg

int gen_block6(unsigned char *loc, BYTE src_reg, BYTE dst_reg); // gen mov dst_reg,[src_reg]
int gen_block7(unsigned char *loc, BYTE src1_reg, BYTE src2_reg, BYTE dst_reg); // xor
int gen_block8(unsigned char *loc, BYTE reg, int type, int ile);			// inc/dec reg

int gen_block9(unsigned char *loc, BYTE pass_ptr_reg, BYTE src_reg, BYTE dst_reg, BYTE magic, int stepx_inc);  // cmp byte ptr [pass],magic
																				    // jne over
																					// call gen_block4

int gen_block10(unsigned char *loc, BYTE reg, DWORD jmp_dst, int neg);	// cmp reg,0 => jnz jmp_dst
int place_anti_emul(unsigned char *loc, BYTE reg, BYTE reg_over);    	// rdtsc anti emul
int place_garbage(unsigned char *loc);
int gen_decryptor_loop(unsigned char *pp_loop, int step_inc, int step_dec);

int read_shell_from_file(unsigned char *where);
int dump_shell_to_file(unsigned char *where, int size);
void mutate_regs(void);


#endif