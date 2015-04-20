#include "_LiTo_01.h"
//#include <iostream.h>

/******************************************************************************************
*																						  *
*                                                                                         *
*					xxxx                 xxxxxxxxxxxxxxxxxxxxxxxxx                        *                  
*					xxxx                 xxxxxxxxxxxxxxxxxxxxxxx                          *                                 
*					xxxx                 xxxxxxxxxxxxxxxxxxxx                             *                     
*					xxxx            xxxx         xxxx           xxxxxxxxxx                *                               	
*					xxxx            xxxx         xxxx          xxxxxxxxxxxx               *                    					
*					xxxx            xxxx         xxxx         xx          xx              *             						
*					xxxx                         xxxx         xx          xx              *                					
*					xxxx            xxxx         xxxx         xx          xx              *                   						
*					xxxx            xxxx         xxxx         xx          xx              *        							
*					xxxx            xxxx         xxxx         xx          xx              *     									
*					xxxxxxxxxxx     xxxx         xxxx         xx          xx              *                      	               											
*					xxxxxxxxxxx	    xxxx         xxxx          xxxxxxxxxxxx               *           						
*		 xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx   *
*																						  *
*																						  *
*																						  *
*																						  *
*																						  *
*******************************************************************************************
*						  Advanced Length dIsassembler moTOr:)							  *
*																						  *
*                                     xxx  xxx											  *
*                                     xxx  x   x										  *
*                                          x    x                                         *    
*                                          x    x                                         *
*                                     xxx  x   x                                          *  
*                                     xxx  xxx                                            *    
*                                                                                         *
*******************************************************************************************
*	Функция _LiTo_(ubyte *pCode,void *outdata)											  *
*	(+) Разбор машинной команды															  *
*	(+) Определение длины машинной команды												  *
*	Вход:																				  *
*	ubyte *pCode - указатель на машинную команду;										  *
*	void *outdata - указатель на выходные данные;										  *
*	Выход:																				  *
*	(+) заполняется соответствующая структура(массив)(outdata)							  *
*	(+) функия возвращает длину машинной команды;										  *											  
*	Заметки:																			  *
*	(+) outdata представлена в виде:													  *
*=========================================================================================*
*	struct INSTR																		  *
*	{																					  *
*		int  len_com;		//00		(+) длина машинной команды						  *
*		int  flags;			//04		(+) флаги команды								  *
*		int  len_offset;	//08		(+) длина смещения								  *
*		int  len_operand;	//12		(+)	длина операнда								  *
*		ubyte seg;			//16		(+) последний сегментный регистр в данной команде *
*		ubyte rep;			//17		(+) наличие REP[NE/E]							  *
*		ubyte opcode1;		//18		(+) опкод команды								  *
*		ubyte opcode2;		//19		(+) наличие 2 байта в опкоде					  *
*		ubyte modrm;		//20		(+) байт MODRM в команде						  *
*		ubyte sib;			//21		(+) байт SIB									  *
*		ubyte offset[8];	//22		(+) смещение (если есть)						  *
*		ubyte operand[8];	//30		(+) операнд (если есть:)						  *
*	};																					  *
*==========================================================================================
*	(+) флаг B_RELX стоит на командах условного и безусловного перехода, некоторых		  *
*		call-ах, loop, etc (короче - смотри исходник:)									  *
*	(+) понимаются только general purpose & fpu instructions (остальный нафиг не нужны)   *
*******************************************************************************************
*																						  *
*																						  *
*******************************************************************************************
*										ФИЧИ:											  *
*	(+) Базонезависимость																  *
*	(+) Легкость добавления новых инструкций											  *
*																						  *
*	(-) Не оптимизирован																  *
*******************************************************************************************
*																						  *
*																						  *
*******************************************************************************************
*									ИСПОЛЬЗОВАНИЕ:										  *
*	Подключение:																		  *
*		"_LiTo_01.h"																	  *
*	Вызов:																				  *
*		char *pCode=(char*)0x00401000;													  *
*		INSTR i1={sizeof(i1)};															  *
*		int	  len=_LiTo_(pCode,&i1);													  *
******************************************************************************************/
																				//m1x
																	//pr0mix@mail.ru
extern "C" int __stdcall _LiTo_(ubyte *pCode,void *outdata)
{
//=============================================================================================
	ubyte TableFlags1[]=
	{
		B_MODRM,						//0x00
		B_MODRM,						//0x01
		B_MODRM,						//0x02
		B_MODRM,						//0x03
		B_DATA8,						//0x04
		B_PREFIX6X,						//0x05
		B_NONE,							//0x06
		B_NONE,							//0x07
		B_MODRM,						//0x08
		B_MODRM,						//0x09
		B_MODRM,						//0x0A
		B_MODRM,						//0x0B
		B_DATA8,						//0x0C
		B_PREFIX6X,						//0x0D
		B_NONE,							//0x0E
		B_NONE,							//0x0F

		B_MODRM,						//0x10
		B_MODRM,						//0x11
		B_MODRM,						//0x12
		B_MODRM,						//0x13
		B_DATA8,						//0x14
		B_PREFIX6X,						//0x15
		B_NONE,							//0x16
		B_NONE,							//0x17
		B_MODRM,						//0x18
		B_MODRM,						//0x19
		B_MODRM,						//0x1A
		B_MODRM,						//0x1B
		B_DATA8,						//0x1C
		B_PREFIX6X,						//0x1D
		B_NONE,							//0x1E
		B_NONE,							//0x1F

		B_MODRM,						//0x20
		B_MODRM,						//0x21
		B_MODRM,						//0x22
		B_MODRM,						//0x23
		B_DATA8,						//0x24
		B_PREFIX6X,						//0x25
		B_NONE,							//0x26
		B_NONE,							//0x27
		B_MODRM,						//0x28
		B_MODRM,						//0x29
		B_MODRM,						//0x2A
		B_MODRM,						//0x2B
		B_DATA8,						//0x2C
		B_PREFIX6X,						//0x2D
		B_NONE,							//0x2E
		B_NONE,							//0x2F

		B_MODRM,						//0x30
		B_MODRM,						//0x31
		B_MODRM,						//0x32
		B_MODRM,						//0x33
		B_DATA8,						//0x34
		B_PREFIX6X,						//0x35
		B_NONE,							//0x36
		B_NONE,							//0x37
		B_MODRM,						//0x38
		B_MODRM,						//0x39
		B_MODRM,						//0x3A
		B_MODRM,						//0x3B
		B_DATA8,						//0x3C
		B_PREFIX6X,						//0x3D
		B_NONE,							//0x3E
		B_NONE,							//0x3F

		B_NONE,							//0x40
		B_NONE,							//0x41
		B_NONE,							//0x42
		B_NONE,							//0x43
		B_NONE,							//0x44
		B_NONE,							//0x45
		B_NONE,							//0x46
		B_NONE,							//0x47
		B_NONE,							//0x48
		B_NONE,							//0x49
		B_NONE,							//0x4A
		B_NONE,							//0x4B
		B_NONE,							//0x4C
		B_NONE,							//0x4D
		B_NONE,							//0x4E
		B_NONE,							//0x4F

		B_NONE,							//0x50
		B_NONE,							//0x51
		B_NONE,							//0x52
		B_NONE,							//0x53
		B_NONE,							//0x54
		B_NONE,							//0x55
		B_NONE,							//0x56
		B_NONE,							//0x57
		B_NONE,							//0x58
		B_NONE,							//0x59
		B_NONE,							//0x5A
		B_NONE,							//0x5B
		B_NONE,							//0x5C
		B_NONE,							//0x5D
		B_NONE,							//0x5E
		B_NONE,							//0x5F

		B_NONE,							//0x60
		B_NONE,							//0x61
		B_MODRM,						//0x62
		B_MODRM,						//0x63
		B_NONE,							//0x64
		B_NONE,							//0x65
		B_NONE,							//0x66
		B_NONE,							//0x67
		B_PREFIX6X,						//0x68
		B_MODRM | B_PREFIX6X,			//0x69
		B_DATA8,						//0x6A
		B_MODRM | B_DATA8,				//0x6B
		B_NONE,							//0x6C
		B_NONE,							//0x6D
		B_NONE,							//0x6E
		B_NONE,							//0x6F

		B_DATA8 | B_RELX,				//0x70
		B_DATA8 | B_RELX,				//0x71
		B_DATA8 | B_RELX,				//0x72
		B_DATA8 | B_RELX,				//0x73
		B_DATA8 | B_RELX,				//0x74
		B_DATA8 | B_RELX,				//0x75
		B_DATA8 | B_RELX,				//0x76
		B_DATA8 | B_RELX,				//0x77
		B_DATA8 | B_RELX,				//0x78
		B_DATA8 | B_RELX,				//0x79
		B_DATA8 | B_RELX,				//0x7A
		B_DATA8 | B_RELX,				//0x7B
		B_DATA8 | B_RELX,				//0x7C
		B_DATA8 | B_RELX,				//0x7D
		B_DATA8 | B_RELX,				//0x7E
		B_DATA8 | B_RELX,				//0x7F

		B_MODRM | B_DATA8,				//0x80
		B_MODRM | B_PREFIX6X,			//0x81
		B_MODRM | B_DATA8,				//0x82
		B_MODRM | B_DATA8,				//0x83
		B_MODRM,						//0x84
		B_MODRM,						//0x85
		B_MODRM,						//0x86
		B_MODRM,						//0x87
		B_MODRM,						//0x88
		B_MODRM,						//0x89
		B_MODRM,						//0x8A
		B_MODRM,						//0x8B
		B_MODRM,						//0x8C
		B_MODRM,						//0x8D
		B_MODRM,						//0x8E
		B_MODRM,						//0x8F

		B_NONE,							//0x90
		B_NONE,							//0x91
		B_NONE,							//0x92
		B_NONE,							//0x93
		B_NONE,							//0x94
		B_NONE,							//0x95
		B_NONE,							//0x96
		B_NONE,							//0x97
		B_NONE,							//0x98
		B_NONE,							//0x99
		B_PREFIX6X | B_DATA16,			//0x9A
		B_NONE,							//0x9B
		B_NONE,							//0x9C
		B_NONE,							//0x9D
		B_NONE,							//0x9E			
		B_NONE,							//0x9F

		B_PREFIX6X,						//0xA0
		B_PREFIX6X,						//0xA1
		B_PREFIX6X,						//0xA2
		B_PREFIX6X,						//0xA3
		B_NONE,							//0xA4
		B_NONE,							//0xA5
		B_NONE,							//0xA6
		B_NONE,							//0xA7
		B_DATA8,						//0xA8
		B_PREFIX6X,						//0xA9
		B_NONE,							//0xAA
		B_NONE,							//0xAB
		B_NONE,							//0xAC
		B_NONE,							//0xAD
		B_NONE,							//0xAE
		B_NONE,							//0xAF

		B_DATA8,						//0xB0
		B_DATA8,						//0xB1
		B_DATA8,						//0xB2
		B_DATA8,						//0xB3
		B_DATA8,						//0xB4
		B_DATA8,						//0xB5
		B_DATA8,						//0xB6
		B_DATA8,						//0xB7
		B_PREFIX6X,						//0xB8
		B_PREFIX6X,						//0xB9
		B_PREFIX6X,						//0xBA
		B_PREFIX6X,						//0xBB
		B_PREFIX6X,						//0xBC
		B_PREFIX6X,						//0xBD
		B_PREFIX6X,						//0xBE
		B_PREFIX6X,						//0xBF

		B_MODRM | B_DATA8,				//0xC0
		B_MODRM | B_DATA8,				//0xC1
		B_DATA16,						//0xC2
		B_NONE,							//0xC3
		B_MODRM,						//0xC4
		B_MODRM,						//0xC5
		B_MODRM | B_DATA8,				//0xC6
		B_MODRM | B_PREFIX6X,			//0xC7
		B_DATA16 | B_DATA8,				//0xC8
		B_NONE,							//0xC9
		B_DATA16,						//0xCA
		B_NONE,							//0xCB
		B_NONE,							//0xCC
		B_DATA8,						//0xCD
		B_NONE,							//0xCE
		B_NONE,							//0xCF

		B_MODRM,						//0xD0
		B_MODRM,						//0xD1
		B_MODRM,						//0xD2
		B_MODRM,						//0xD3
		B_DATA8,						//0xD4
		B_DATA8,						//0xD5	
		B_NONE,							//0xD6
		B_NONE,							//0xD7
		B_MODRM,						//0xD8
		B_MODRM,						//0xD9
		B_MODRM,						//0xDA
		B_MODRM,						//0xDB
		B_MODRM,						//0xDC
		B_MODRM,						//0xDD
		B_MODRM,						//0xDE
		B_MODRM,						//0xDF

		B_DATA8 | B_RELX,				//0xE0
		B_DATA8 | B_RELX,				//0xE1
		B_DATA8 | B_RELX,				//0xE2
		B_DATA8 | B_RELX,				//0xE3
		B_DATA8,						//0xE4
		B_DATA8,						//0xE5
		B_DATA8,						//0xE6
		B_DATA8,						//0xE7
		B_PREFIX6X | B_RELX,			//0xE8
		B_PREFIX6X | B_RELX,			//0xE9
		B_PREFIX6X | B_DATA16,			//0xEA
		B_DATA8 | B_RELX,				//0xEB
		B_NONE,							//0xEC
		B_NONE,							//0xED
		B_NONE,							//0xEE
		B_NONE,							//0xEF

		B_NONE,							//0xF0
		B_NONE,							//0xF1
		B_NONE,							//0xF2
		B_NONE,							//0xF3
		B_NONE,							//0xF4
		B_NONE,							//0xF5
		B_MODRM,						//0xF6
		B_MODRM,						//0xF7
		B_NONE,							//0xF8
		B_NONE,							//0xF9
		B_NONE,							//0xFA
		B_NONE,							//0xFB
		B_NONE,							//0xFC
		B_NONE,							//0xFD
		B_MODRM,						//0xFE
		B_MODRM							//0xFF
	};
//=============================================================================================
	ubyte TableFlags2[]=
	{
		B_MODRM,						//0x00
		B_MODRM,						//0x01
		B_MODRM,						//0x02
		B_MODRM,						//0x03
		B_NONE,							//0x04
		B_NONE,							//0x05
		B_NONE,							//0x06
		B_NONE,							//0x07
		B_NONE,							//0x08
		B_NONE,							//0x09
		B_NONE,							//0x0A
		B_NONE,							//0x0B
		B_NONE,							//0x0C
		B_MODRM,						//0x0D
		B_NONE,							//0x0E
		B_NONE,							//0x0F

		B_NONE,							//0x10
		B_NONE,							//0x11
		B_NONE,							//0x12
		B_NONE,							//0x13
		B_NONE,							//0x14
		B_NONE,							//0x15
		B_NONE,							//0x16
		B_NONE,							//0x17
		B_NONE,							//0x18
		B_NONE,							//0x19
		B_NONE,							//0x1A
		B_NONE,							//0x1B
		B_NONE,							//0x1C
		B_NONE,							//0x1D
		B_NONE,							//0x1E
		B_MODRM,						//0x1F

		B_MODRM,						//0x20
		B_MODRM,						//0x21
		B_MODRM,						//0x22
		B_MODRM,						//0x23
		B_NONE,							//0x24
		B_NONE,							//0x25
		B_NONE,							//0x26
		B_NONE,							//0x27
		B_NONE,							//0x28
		B_NONE,							//0x29
		B_NONE,							//0x2A
		B_NONE,							//0x2B
		B_NONE,							//0x2C
		B_NONE,							//0x2D
		B_NONE,							//0x2E
		B_NONE,							//0x2F

		B_NONE,							//0x30
		B_NONE,							//0x31
		B_NONE,							//0x32
		B_NONE,							//0x33
		B_NONE,							//0x34
		B_NONE,							//0x35
		B_NONE,							//0x36
		B_NONE,							//0x37
		B_NONE,							//0x38
		B_NONE,							//0x39
		B_NONE,							//0x3A
		B_NONE,							//0x3B
		B_NONE,							//0x3C
		B_NONE,							//0x3D
		B_NONE,							//0x3E
		B_NONE,							//0x3F

		B_MODRM,						//0x40
		B_MODRM,						//0x41
		B_MODRM,						//0x42
		B_MODRM,						//0x43
		B_MODRM,						//0x44
		B_MODRM,						//0x45
		B_MODRM,						//0x46
		B_MODRM,						//0x47
		B_MODRM,						//0x48
		B_MODRM,						//0x49
		B_MODRM,						//0x4A
		B_MODRM,						//0x4B
		B_MODRM,						//0x4C
		B_MODRM,						//0x4D
		B_MODRM,						//0x4E
		B_MODRM,						//0x4F

		B_NONE,							//0x50
		B_NONE,							//0x51
		B_NONE,							//0x52
		B_NONE,							//0x53
		B_NONE,							//0x54
		B_NONE,							//0x55
		B_NONE,							//0x56
		B_NONE,							//0x57
		B_NONE,							//0x58
		B_NONE,							//0x59
		B_NONE,							//0x5A
		B_NONE,							//0x5B
		B_NONE,							//0x5C
		B_NONE,							//0x5D
		B_NONE,							//0x5E
		B_NONE,							//0x5F

		B_NONE,							//0x60
		B_NONE,							//0x61
		B_NONE,							//0x62
		B_NONE,							//0x63
		B_NONE,							//0x64
		B_NONE,							//0x65
		B_NONE,							//0x66
		B_NONE,							//0x67
		B_NONE,							//0x68
		B_NONE,							//0x69
		B_NONE,							//0x6A
		B_NONE,							//0x6B
		B_NONE,							//0x6C
		B_NONE,							//0x6D
		B_NONE,							//0x6E
		B_NONE,							//0x6F

		B_NONE,							//0x70
		B_NONE,							//0x71
		B_NONE,							//0x72
		B_NONE,							//0x73
		B_NONE,							//0x74
		B_NONE,							//0x75
		B_NONE,							//0x76
		B_NONE,							//0x77
		B_NONE,							//0x78
		B_NONE,							//0x79
		B_NONE,							//0x7A
		B_NONE,							//0x7B
		B_NONE,							//0x7C
		B_NONE,							//0x7D
		B_NONE,							//0x7E
		B_NONE,							//0x7F

		B_PREFIX6X | B_RELX,			//0x80
		B_PREFIX6X | B_RELX,			//0x81
		B_PREFIX6X | B_RELX,			//0x82
		B_PREFIX6X | B_RELX,			//0x83
		B_PREFIX6X | B_RELX,			//0x84
		B_PREFIX6X | B_RELX,			//0x85
		B_PREFIX6X | B_RELX,			//0x86
		B_PREFIX6X | B_RELX,			//0x87
		B_PREFIX6X | B_RELX,			//0x88
		B_PREFIX6X | B_RELX,			//0x89
		B_PREFIX6X | B_RELX,			//0x8A
		B_PREFIX6X | B_RELX,			//0x8B
		B_PREFIX6X | B_RELX,			//0x8C
		B_PREFIX6X | B_RELX,			//0x8D
		B_PREFIX6X | B_RELX,			//0x8E
		B_PREFIX6X | B_RELX,			//0x8F

		B_MODRM,						//0x90
		B_MODRM,						//0x91
		B_MODRM,						//0x92
		B_MODRM,						//0x93
		B_MODRM,						//0x94
		B_MODRM,						//0x95
		B_MODRM,						//0x96
		B_MODRM,						//0x97
		B_MODRM,						//0x98
		B_MODRM,						//0x99
		B_MODRM,						//0x9A
		B_MODRM,						//0x9B
		B_MODRM,						//0x9C
		B_MODRM,						//0x9D
		B_MODRM,						//0x9E
		B_MODRM,						//0x9F

		B_NONE,							//0xA0
		B_NONE,							//0xA1
		B_NONE,							//0xA2
		B_MODRM,						//0xA3
		B_MODRM | B_DATA8,				//0xA4
		B_MODRM,						//0xA5
		B_NONE,							//0xA6
		B_NONE,							//0xA7
		B_NONE,							//0xA8
		B_NONE,							//0xA9
		B_NONE,							//0xAA
		B_MODRM,						//0xAB
		B_MODRM | B_DATA8,				//0xAC
		B_MODRM,						//0xAD
		B_NONE,							//0xAE
		B_MODRM,						//0xAF

		B_MODRM,						//0xB0
		B_MODRM,						//0xB1
		B_MODRM,						//0xB2
		B_MODRM,						//0xB3
		B_MODRM,						//0xB4
		B_MODRM,						//0xB5
		B_MODRM,						//0xB6
		B_MODRM,						//0xB7
		B_NONE,							//0xB8
		B_NONE,							//0xB9
		B_MODRM | B_DATA8,				//0xBA
		B_MODRM,						//0xBB
		B_MODRM,						//0xBC
		B_MODRM,						//0xBD
		B_MODRM,						//0xBE
		B_MODRM,						//0xBF

		B_MODRM,						//0xC0
		B_MODRM,						//0xC1
		B_NONE,							//0xC2
		B_NONE,							//0xC3
		B_NONE,							//0xC4
		B_NONE,							//0xC5
		B_NONE,							//0xC6
		B_MODRM,						//0xC7
		B_NONE,							//0xC8
		B_NONE,							//0xC9
		B_NONE,							//0xCA
		B_NONE,							//0xCB
		B_NONE,							//0xCC
		B_NONE,							//0xCD
		B_NONE,							//0xCE
		B_NONE,							//0xCF

		B_NONE,							//0xD0
		B_NONE,							//0xD1
		B_NONE,							//0xD2
		B_NONE,							//0xD3
		B_NONE,							//0xD4
		B_NONE,							//0xD5
		B_NONE,							//0xD6
		B_NONE,							//0xD7
		B_NONE,							//0xD8
		B_NONE,							//0xD9
		B_NONE,							//0xDA
		B_NONE,							//0xDB
		B_NONE,							//0xDC
		B_NONE,							//0xDD
		B_NONE,							//0xDE
		B_NONE,							//0xDF

		B_NONE,							//0xE0
		B_NONE,							//0xE1
		B_NONE,							//0xE2
		B_NONE,							//0xE3
		B_NONE,							//0xE4
		B_NONE,							//0xE5
		B_NONE,							//0xE6
		B_NONE,							//0xE7
		B_NONE,							//0xE8
		B_NONE,							//0xE9
		B_NONE,							//0xEA
		B_NONE,							//0xEB
		B_NONE,							//0xEC
		B_NONE,							//0xED
		B_NONE,							//0xEE
		B_NONE,							//0xEF

		B_NONE,							//0xF0
		B_NONE,							//0xF1
		B_NONE,							//0xF2
		B_NONE,							//0xF3
		B_NONE,							//0xF4
		B_NONE,							//0xF5
		B_NONE,							//0xF6
		B_NONE,							//0xF7
		B_NONE,							//0xF8
		B_NONE,							//0xF9
		B_NONE,							//0xFA
		B_NONE,							//0xFB
		B_NONE,							//0xFC
		B_NONE,							//0xFD
		B_NONE,							//0xFE
		B_NONE,							//0xFF
	};
//=============================================================================================
	ubyte Opcode=*pCode;
	ubyte *pFirstByte=pCode;
	int len_offset=0,len_operand=0;
	int flags=0;
	ubyte sib=0;
	ubyte mod=0,reg=0,rm=0;
	ubyte seg=0;
	ubyte reg3=0;
	ubyte rep=0;
	ubyte p66=0,p67=0;
	int i=0;
//=============================================================================================
	while(Opcode==0x2E || Opcode==0x36 || Opcode==0x3E || Opcode==0x26 ||
		  Opcode==0x64 || Opcode==0x65 || Opcode==0xF2 || Opcode==0xF3 ||
		  Opcode==0xF0 || Opcode==0x67 || Opcode==0x66)
	{
		if(Opcode==0x66)	 {	flags|=B_PFX66; p66=1; }
		else if(Opcode==0x67){	flags|=B_PFX67; p67=1; }
		else if(Opcode==0xF0)	flags|=B_LOCK;
		else if((Opcode & 0xFE)==0xF2)
		{
			flags|=B_REP;
			rep=Opcode;
		}
		else
		{
			flags|=B_SEG;
			seg=Opcode;
		}
		Opcode=*(++pCode);
	}
//=============================================================================================
	*(ubyte*)((int)outdata+18)=Opcode;
	if(Opcode==0x0F)
	{
		Opcode=*(++pCode);
		*(ubyte*)((int)outdata+19)=Opcode;
		flags|=TableFlags2[Opcode];	
		flags|=B_OPCODE2;
	}
	else
	{
		flags|=TableFlags1[Opcode];
		if(Opcode>=0xA0 && Opcode<=0xA3)	p66=p67;
	}

	pCode++;
//=============================================================================================
	if(flags & B_MODRM)
	{
		*(ubyte*)((int)outdata+20)=*pCode;
		mod=*pCode>>6;
		reg=(*pCode & 0x38)>>3;
		rm =*pCode & 0x07;
		sib=(!p67 && rm==0x04);
//---------------------------------------------------------------------------------------------
		if(Opcode==0xF6 && !reg)			flags|=B_DATA8;
		if(Opcode==0xF7 && !reg)			flags|=B_PREFIX6X;
		if(Opcode==0xFF && (reg==0x02 || reg==0x04))
			flags|=B_RELX;
//---------------------------------------------------------------------------------------------
		switch(mod)
		{
		case 00:	//00b
			if(p67  && (rm==0x06))	len_offset=2;
			if(!p67 && (rm==0x05))	len_offset=4;
			break;
		case 0x01:	//01b
			len_offset=1;
			break;
		case 0x02:	//10b
			len_offset=2;
			if(!p67) len_offset+=2;
			break;
		case 0x03:	//11b
			sib=0;
			break;
		}
		pCode++;
//---------------------------------------------------------------------------------------------
		if(sib)
		{
			*(ubyte*)((int)outdata+21)=*pCode;
			reg3=*pCode & 0x07;		
			if(reg3==0x05 && !mod)
			{
				len_offset=4;
			}
			pCode++;
		}
	}	
//=============================================================================================
	if(flags & B_DATA8)		len_operand++;
	if(flags & B_DATA16)	len_operand+=2;
	if(flags & B_PREFIX6X)
		if(p66)		len_operand+=2;
		else		len_operand+=4;
//=============================================================================================		
	for(i=0;i<len_offset;i++)
		*(ubyte*)((int)outdata+22+i)=*pCode++;
	for(i=0;i<len_operand;i++)
		*(ubyte*)((int)outdata+30+i)=*pCode++;
//=============================================================================================	
	int len=(int)(pCode-pFirstByte);
	*(int*)((int)outdata+0)=len;
	*(int*)((int)outdata+4)=flags;
	*(ubyte*)((int)outdata+8)=len_offset;
	*(ubyte*)((int)outdata+12)=len_operand;
	*(ubyte*)((int)outdata+16)=seg;
	*(ubyte*)((int)outdata+17)=rep;
//=============================================================================================		
	return len;
}
/******************************************************************************************
*	Конец функции _LiTo_																  *
******************************************************************************************/

/*
int main()
{
	struct INSTR																		  
	{																					  
		int  len_com;		//00		(+) длина машинной команды						  
		int  flags;			//04		(+) флаги команды								  
		int  len_offset;	//08		(+) длина смещения								  
		int  len_operand;	//12		(+)	длина операнда								  
		ubyte seg;			//16		(+) последний сегментный регистр в данной команде 
		ubyte rep;			//17
		ubyte opcode1;		//18		(+) опкод команды								  
		ubyte opcode2;		//19		(+) наличие 2 байта в опкоде
		ubyte modrm;		//20		(+) байт MODRM в команде						  
		ubyte sib;			//21		(+) байт SIB									  
		ubyte offset[8];	//22		(+) смещение (если есть)						  
		ubyte operand[8];	//30		(+) операнд (если есть:)						  
	};
	INSTR i1={sizeof(i1)};
	unsigned char pCode[]={0xe9,0x07,0x05,0x03,0x01};
	int len=_LiTo_(pCode,&i1);
//---------------------------------------------------------------------------------------------
	cout<<hex<<"len_com="<<i1.len_com<<endl;
	cout<<"flags="<<i1.flags<<endl;
	cout<<"len_offset="<<i1.len_offset<<endl;
	cout<<"len_operand="<<i1.len_operand<<endl;
	cout<<"seg="<<(int)i1.seg<<endl;
	cout<<"rep="<<(int)i1.rep<<endl;
	cout<<"opcode1="<<(int)i1.opcode1<<endl;
	cout<<"opcode2="<<(int)i1.opcode2<<endl;
	cout<<"modrm="<<(int)i1.modrm<<endl;
	cout<<"sib="<<(int)i1.sib<<endl;
	cout<<"**********************"<<endl;
	cout<<"OFFSET:"<<endl;
	for(int i=0;i<i1.len_offset;i++)
		cout<<(int)i1.offset[i]<<"\t";
	cout<<endl<<"OPERAND:"<<endl;
	for(i=0;i<i1.len_operand;i++)
		cout<<(int)i1.operand[i]<<"\t";
	cout<<endl;
//---------------------------------------------------------------------------------------------
	return 0;
}
*/