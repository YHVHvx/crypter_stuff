;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;                                                                                                        ;
;                                                                                                        ;
;                                   xxxxxxxxxxxx     xxxxxxxxxx                                          ;    
;                                   xxxxxxxxxxxx    xxxxxxxxxxx                                          ;   
;                                       xxxx       xxxx    xxxx                                          ;         
;                                       xxxx       xxxx                                                  ;
;                       xxx   xxx       xxxx       xxxx                                                  ;
;                        xxx xxx        xxxx       xxxx                                                  ;  
;                         xxxxx         xxxx       xxxx   xxxxx                                          ;
;                         xxxxx         xxxx       xxxx    xxxx                                          ;
;                        xxx xxx        xxxx        xxxxxxxxxxx                                          ;
;                       xxx   xxx       xxxx         xxxxxxxxxx                                          ;
;                                                                                                        ;    
;                                                                                                        ;        
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;     
;					    eXperimental/eXtended/eXecutable Trash Generator                                 ;
;											xTG                											 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											:)!															 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										�㭪�� xTG														 ;
;			�����������������/�����������/���������� ��������� �������� ���������� 	 					 ;
;																										 ; 
;																										 ;
;����:																									 ;
;1 ��ࠬ��� (� �����⢥���) - ���� �������� (TRASHGEN) (�� ���ᠭ�� ᬮ�� ����) 					 ;     
;--------------------------------------------------------------------------------------------------------;																										 ;
;�����:																									 ;
;EAX - ���� ��� ���쭥�襩 ����� (�᫨ ⠪���� �㤥� �㦭�) (����� ���ਬ�� ��।���� ���� etc).   ;
;� ⠪�� ����ᠭ��� ����� �⬥����� ���쬠 (��� ������ ������) �� 㪠������� ����� � 㪠������       ;
;ࠧ���.																				 			     ; 
;--------------------------------------------------------------------------------------------------------;
;�������: 																								 ;
;(+) �������, 㪠��⥫� �� ������ ��।�� � ����⢥ ��ࠬ���, �� �������, �.�. ����� � ��� ��᫥  ;
;    �맮�� ������� ���� ������� ⥬� ��.       													 ; 
;(+) �᫨ ���� �� �㦭� ������� ���誨 ��� �� ��㣮� ��稭�, � ���������� ⥫� ����㭪� fakeapi. 	 ;   
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;											!															 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										�������� ��������� 												 ;
;											TRASHGEN 													 ;
;																										 ;
;																										 ;
;TRASHGEN	struct																						 ;
;	rgen_addr		dd		?	;���� ������� ���砩��� ��ᥫ (���)									 ;
;	buf_for_trash	dd		?	;���� (����), �㤠 �����뢠�� ������㥬�� (��, ����⢥����) ���쬮	 ;
;	size_trash		dd		?	;ࠧ��� (� �����), ᪮�쪮 ���� �������  							 ;
;	regs			dd		?	;������ ॣ����� (2 ��)  												 ;
;	xmask1			dd		?	;64-��⭠� ��᪠ ��� �����樨  										 ;
;	xmask2			dd		?	;������ ������ (��� 䨫���)											 ;
;	beg_addr		dd		?	;��砫�� ����														 ;
;	end_addr		dd		?	;������ ���� 														 ;
;	mapped_addr		dd		?	;��१�ࢨ஢��� (���� ���� ����� (aka ���� 䠩�� � �����)) 		 ;    
;	reserv1			dd		?	;��१�ࢨ஢��� (�, ����� �����-� ⠬ �� � �㤥�) 					 ; 
;TRASHGEN	ends																						 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											! 															 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;							��������� � ����� ��������� TRASHGEN: 										 ; 
;																										 ;
;																										 ;
;[   rgen_addr   ] : 																					 ; 
;					 ⠪ ��� ����� ������ (xTG) ࠧࠡ�⠭ ��� �ਢ離� � ������-���� ��㣮�� �����,	 ;
;					 � ��� �����樨 ���� ����� ���, ���⮬� ���� ��� �࠭���� � (������) ���� 		 ;
;					 ��������. �����: �᫨ ���� xTG �㤥� �ᯮ�짮���� ��㣮� ��� (� �� ��, ����� 	 ;
;					 ���� � ��� � ��������), ����, �⮡� ��� ��㣮� ��� �ਭ���� � ����⢥ 1-�� 		 ;
;					 (� �����⢥�����!) ��ࠬ��� � ��� �᫮ (������� ��� N), ⠪ ��� ���� �㤥� � 	 ;
;					 ��������� [0..n-1]. � �� ��室� ��㣮� ���	������ �������� � EAX ��砩��� �᫮. ; 	
;					 ��⠫�� ॣ����� ������ ������� ��������묨. ��. (���� ᥡ� �� :)			 ; 
;--------------------------------------------------------------------------------------------------------; 
;[ buf_for_trash ] : 																					 ;
;					 �� ����� ���� ���ᨢ etc. �㬠�, ��� �� � ⠪ �᭮.								 ; 
;--------------------------------------------------------------------------------------------------------;
;[  size_trash   ] : 																					 ;
;					 㪠��� ���ਬ�� 50 ����, ��� �⮫쪮 ���� ������ ������ ᣥ������� � ��������� 	 ;
;					 ��	㪠������� �����.																 ; 
;--------------------------------------------------------------------------------------------------------;
;[ 	   regs 	 ] : 																					 ; 
;					 ����� ���ࠧ㬥������, �� �������, ��������, �㤥� �ᯮ�짮������ ����� � 		 ;
;					 ��������� �������. ����� 㪠���� ������ 2 ������� ॣ����. ���� �������� 		 ;
;					 �ਬ��. ��� ���ਬ�� ⠪ ����� �룫拉�� �� ����: 0x00000201. ����� 1 ������ 	 ;
;					 ॣ���� EDX (2), � 2-�� ������ ECX (1). �� �ਬ��: 0x00000007. ����� 1 ������ 	 ;
;					 ॣ���� EAX (0), 2-�� EDI (7).	�.�. �����, ��� �ਬ�୮ ������ �룫拉�� �� ���� 	 ;
;					 � �������. �᫨, � �ਬ���, �� �⨬, �⮡� 1 ������ ॣ���� �� ESI (6), � 	 ;
;					 2-�� EDX (2), � ���� [ regs ] �㤥� �� ����� 0x00000062 (�� �������� �।), � 	 ;
;					 �㤥� ����� 0x00000602. �� ⠪�� ������ ॣ����? �� ॣ�����, � ������ 		 ;
;					 ��室���� ����� � ���祭��, � �� ॣ����� �������� �� � ���� ��砥 �����. 		 ;
;					 ������ xTG �����, �� 㪠���� ������ ॣ�����, � ������� �� �㤥� �� �ᯮ�짮���� ;
;					 ��� �����樨 ������, ⥬ ᠬ� ������ ॣ����� ��⠭���� ���஭��묨 			 ;
;					 (���, ����୮� �� ���� �뫮 ������� �ࠧ�). � �� ���� ������ �����᪨� push ��। ;
;					 � pop ��᫥ �맮�� ������. � ���ਬ�� �ᯮ���� ��� ������ (xTG) � ᢮�� �������� ;
;					 (�� ���� ⮦� � ��������:)! ). �� ������ ॣ�����	���筮 �ᯮ������� � 		 ;
;					 �������䭮� ������. � � � � ����� ���� ����� ����� ������� ���⥫�� 		 ;
;					 १����. � ��饬, ��� �ᥣ��, ���� ����, ����. 								 	 ;
; 																										 ;	
;			 		 ��� ���, ��� ������ �� �����, ����� ���� � ���� ���� ����� 0, 0xFF, 1 etc			 ;	 	
;			 		 (�᫨ �������, �� ��࠭���� � ॣ�����). 										 ;		 	
;																										 ;
;			 		 ���: �� ����讬 ������� ����� ������ ���� ������ � �� ����襥 ���-�� ������� 	 ;
;						  ॣ���஢, ���� �� �ਬ�஢ �⮣� ���� � ������ ������. ����� � ���砩 		 ;
;						  ��室����. 																	 ;
;																										 ;
;			 		 ESP & EBP - �ᥣ�� ��࠭����� (�� ����������). ���⮬� � ��� ����� ᬥ�� ������.	 ;		 	
;--------------------------------------------------------------------------------------------------------;
;[ 	   xmask1	 ] 																						 ;
;		 &																								 ;
;[	   xmask2	 ] : 																					 ;
;					 �� ���� �ᮡ������� ������� ������ � ⮬, �� ��� �����樨 ���� �� �ਬ���� 	 ;
;					 ���� (64-ࠧ�來��). ����� ��ࠧ��, ����� �����஢��� ⮫쪮 ��।������ 		 ;
;					 �������. �� �뢠�� �㦭�, ���ਬ�� ��� �����樨 ��������᪮�� ����, ��� 	 ;
;					 �������, ��� ������ 堮�. �ਬ������ ���. ���� �� ��᪠ �।�⠢��� ᮡ�� ��� 	 ;
;					 32-����� �᫠ (����� � ������ �� ����室�����), ��� ����� ��� �⢥砥� �� 	 ;
;					 ��।������� �������. �᫨ ��� ࠢ�� 1, �����, ����祭� ������� ��।������� 	 ;
;					 �������. �᫨ ��� = 0, ��।������� ������� �����஢�����	�� �㤥�. ���ਬ��, 	 ;
;					 ����� ��᪠ = 00000000000000001000000000100001b (xmask1) � 01b (xmask2). �����, �� ;	 	
;					 ���⠢���� ���� (��稭�� ����� �� 1) 1, 6 � 16 � xmask1 � 1 � xmask2. �����, 	 ;
;					 ࠧ�襭� ������� ������ (INC/DEC/AAA/etc), (MOV REG32/REG16,IMM32/IMM16), 		 ;
;					 (JXX NEAR) � (NOP/CMC/CLD/etc). �.�. 1-� ��� �⢥砥� �� ������� 1-�� ��㯯� 	 ;
;					 ������ (INC/DEC), �� � ⠡��窥 ����, 16-� ��� �� ������� 16-�� ��㯯� ������ 	 ;
;					 (MOV) �.�.. � ��饬, ᬮ�ਬ � ⠡����.		 									 ;		
;																										 ;
;			 		 �����: ᠬ� ���訩 ��� ��᪨ (� xmask1) �⢥砥� �� 堮�. 						 ;
;							�� ���஡����ﬨ - ᬮ�� ��室����.   										 ;
;																										 ;
;			 		 ������ ���������! �� ����������� ������������ ��������� MMX/SSE & one_byte, �.�. 	 ;
;									   �� ����� �ਢ��� � �᪫�祭��. �᫨ ����, � �।�� �� 		 ;
;									   (᭠砫� ������ ����, �� �몫��� ��㣮� � �.�.). 			 ;
;																										 ;
;					 ���: ���� �ᥣ�� ��ন� ����祭�� ᠬ� ����訩 ��� (� xmask1), �⮡� �� �뫮 	 ;		
;						  �㯥�. ���� ����� �ந���� ��横�������.									 ;								 	
;																										 ;
;					 ��� ���, ��� ������ �� �����, ����� ���� � ���� ��������� ����� 					 ;
;					 							   0xFFFFFFFF (xmask1) � 0x00 (xmask2).  				 ;	 
;					 (�᫨ �������, ����� ���� ᣥ��������).											 ;		 	
;--------------------------------------------------------------------------------------------------------;  
;[    beg_addr   ]   																					 ;
;	  	 �																								 ;	 	
;[	  end_addr	 ] :   																					 ;
;			 		 �᫨ �� ��ࠬ���� !=0, ⮣�� ��� ������ ᮤ�ঠ�� ॠ��� ����, �� ����� 	 ;
;					 ����� �㤥� �����뢠�� ����� �७�. �� ���� �ᯮ������� ��� �����樨 ���ਬ�� ;
;					 ⠪��� ����:	mov [0x004010F0],edx. ��� ��砫�� ���� ���ਬ�� ����� ���� ⠪��  ;	
;					 0x00401000. � ������ 0x00402000. � �� ���� � �⮬ ��������� ����� ���� 		 ;
;					 ������⢮����. �᫨ ��	���� �� ���� ⠪�� ������ �������, ⮣�� ᫥��� �⪫���� ;
;					 �㦭� ��� � ��᪥, ���� �� � ��� ��ࠬ���� ��।��� �㫨, ��� ᤥ���� � � � 	 ;
;					 ��㣮�.								 											 ;
;			 																							 ;
;					 ��� ���, ��� ������ �� �����, ����� ���� � ���� ���������� ����� ����.				 ;		 	
;--------------------------------------------------------------------------------------------------------; 
;[  mapped_addr  ] :																					 ; 
;					 �� ���� ��१�ࢨ஢���. ���� �� � (�����) �������� ���� ����� (��� ���� 	 ;
;					 䠩�� � �����), � ⠪�� � ��᪥ ������ �㦭� ��� � 1 � ��᪮����஢��� (�� 	 ;
;					 ����室�����) ᮤ�ন��� ����㭪樨 fakeapi, ����� ��室���� � ������ ������. 	 ;
;					 �� �� ��� ⮣�, �⮡� ����� �뫮 ������� ����� ���誨. 						 ;
;					 � ⠪�� ��砥 �㤥� �ந������ ���� � ������� �� ���襪, ����� ��࠭�� 		 ;   
;					 �����⮢���� � ���㫥 [ faka.asm ] � �����-���� �� ��� ���襪 ������� � 			 ;
;					 �஥�஢����� � ������ 䠩��. ���஡���� �� �����樨 ������ ������ �⠩ � 	 ;
;					 [ faka.asm ] (FAKA). ���. 													   		 ; 		
;			 																							 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;                         
;																										 ;
;											y0p!														 ;
;																										 ;  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											����														 ;
;																										 ;
;																										 ;
;(+) ������� �᭮���� ������権 (������) (1, 2, 3, 4, 5, 6 ���⮢)									 ;
;		* ⠪�� ������� call, jmp, jxx, loop, mov/xchg/lea/cmp [address]/REG,REG/[address] etc;		 ;
;		* �離� cmp/test + jxx (�᫮��� ���室) - �.�. �᫨ ���� cmp/test, � �� ��� �ࠧ� ���� jxx;	 ;
;--------------------------------------------------------------------------------------------------------; 
;(+) ������� fpu/mmx/sse ������権 																	 ;
;--------------------------------------------------------------------------------------------------------;
;(+) ������� ������権 �� ��᪥ (䨫�����): 														 ;
;		* ����������� �����஢���� ��������᪮��, ���᪮��, ᯥ樠�쭮�� ����, etc; 			 ;
;--------------------------------------------------------------------------------------------------------;
;(+) ����������� �����஢��� �஫��� � ����� (�⤥�쭮 ��� �����)									 ;  
;--------------------------------------------------------------------------------------------------------;
;(+) ����������� �����஢��� Fake WinApi 																 ; 
;--------------------------------------------------------------------------------------------------------; 
;(+) ����������ᨬ����																					 ;
;--------------------------------------------------------------------------------------------------------;
;(+) ��� �ਢ離� � ��㣨� ������� (��� ����� �� �� - �᫮��� �⠩ ���;)						 ;
;		* ����� ��������� ��� ᠬ����⥫�� �����;													 ;            
;--------------------------------------------------------------------------------------------------------; 
;(+) �� �� WinAPI																					 ;
;--------------------------------------------------------------------------------------------------------;
;(X) �� ������� ����� ���� �� ����� �����筮 ���� ��� ���樨 ������ 							 ;
;																										 ; 				
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											y0p!														 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										�������������: 													 ;
;																										 ;
;																										 ;
;1) ������祭��:																						 ;
;		xTG.asm																							 ;
;2) �맮� (�ਬ�� stdcall):																				 ;
;		...																								 ;
;		szBuf		db 100 dup (00h) 																	 ;
;		...										      													 ;
;		lea		ecx,szBuf																				 ;
;		assume	ecx:ptr TRASHGEN																		 ;
;		mov		[ecx].rgen_addr,00401000h		;�� �⮬� ����� ������ ��室����� ���					 ;
;		mov		[ecx].buf_for_trash,00402000h	;�� �⮬� ����� �㤥� �����뢠�� ����					 ;
;		mov		[ecx].size_trash,100			;����襬 100 ���� ����								 ;
;		mov		[ecx].regs,0203h				;����� �ᯮ�짮���� � ���� ॣ����� EDX (2) & EBX (3) ;
;		mov		[ecx].xmask1,08Fh				;�� ��᪥ ࠧ�襭� ������� ᫥����� ������  		 ;
;												;(0000008fh==10001111b):								 ;
;												;inc_dec_r32, 											 ;
;												;not_neg_r32, 											 ;
;												;lea_r32_mem32, 										 ;
;												;mov_xchg_32, 											 ;
;												;add_sub_r8.											 ;
;												;��⠫�� ��ࠬ���� ���㫥��.							 ;
;		call	xTG								;��뢠�� ������� ������ ������  					 ;				 	
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;v1.0.1  




														; m1x
													;pr0mix@mail.ru
												;EOF



;========================================================================================================
;������� TRASHGEN, ����室���� ��� ������� ������� 
;========================================================================================================
TRASHGEN	struct

	rgen_addr		dd		?
	buf_for_trash	dd		?
	size_trash		dd		?
	regs			dd		?
	xmask1			dd		?
	xmask2			dd		?
	beg_addr		dd		?
	end_addr		dd		?
	mapped_addr		dd		? 
	reserv1			dd		?
	
TRASHGEN	ends
;========================================================================================================





NUM_CMD			equ		39;33					;������⢮ ��������� ������ (��㯯 ������) 
												;�� ���������� ������ ����� � ⠡����, 㢥����� �� ���祭�� 
FOREBP			equ		1Ch 					;�ᯮ����⥫쭠� ����⠭� (��� �����樨 ������ �������� mov reg,dword ptr [ebp-0xXX] etc) 


											   


xTG:                                       		 
	pushad										;��࠭塞 ॣ�����
	mov		ebp,dword ptr [esp+24h] 
	assume	ebp:ptr TRASHGEN	                                           
	call 	_delta_trash_                             
;--------------------------------------------------------------------------------------------------------
_delta_trash_:                                
	pop 	ebx									;����砥� �����-ᬥ饭��
	mov		ecx,[ebp].size_trash				;� ecx ��࠭塞 ࠧ��� ����, ����� ���� ᣥ�����
	mov		edi,[ebp].buf_for_trash				;� edi - ����, �㤠 �㤥� �����뢠�� ��� ����           
	cld
;--------------------------------------------------------------------------------------------------------	                                  	   
_mask_trash_:                                             
	lea 	esi,[ebx+(_table_ - _delta_trash_)]	;����砥� ���� ⠡��窨, � ���ன �࠭���� ����ﭨ� (� �����) ����㭪権 
	push	NUM_CMD								;������⢮ ����⮢ � ⠡��窥 
	call	[ebp].rgen_addr						;��뢠�� ��� 
	cmp		eax,30								;�᫨ >30, ����� �㤥� �஢����� ���� �� 2-�� �������� ��᪨ 
	jg		_2mask_
_1mask_: 	                      
	bt		[ebp].xmask1,eax					;�஢��塞 ���� �� 1-�� ���������  ��᪨ (� ��� ��᪠ 64-��⭠�)  (⨯� 䨫�����:)
	jnc		_mask_trash_						;��� �� ��⠭�����?
	jmp		_gotoinstr_ 
_2mask_:
	push	eax
	sub		eax,30+1
	bt		[ebp].xmask2,eax					;�஢��塞 ���� �� 2-�� �������� ��᪨ 
	pop		eax
	jnc		_mask_trash_ 
_gotoinstr_:
	shl 	eax,1								;㬭����� eax �� 2
	add 	eax,esi								;������塞 ᬥ饭�� _table_
	movzx 	eax,word ptr[eax]					;���뢠�� ����ﭨ� �� ����祭���� (��砩����) ᬥ饭��
	add 	eax,esi								;�ਡ���塞 ��� � ᬥ饭��
	call 	eax									;� ���室�� �� ������ ���� 
	jmp 	_mask_trash_						;�� �����:)! 
;========================================================================================================
_table_:										;⠡��窠 ����ﭨ�  
	dw	(offset inc_dec_r32		 -		offset _table_)	;0		;1
	dw	(offset not_neg_r32		 -		offset _table_)	;1		;2	 	
	dw	(offset lea_r32_mem32	 -		offset _table_)	;2		;3    	
	dw	(offset mov_xchg_r32	 -		offset _table_)	;3		;4	
	dw	(offset mov_xchg_r8		 -		offset _table_)	;4		;5	    	
	dw	(offset mov_r_imm		 -		offset _table_)	;5		;6        	
	dw	(offset add_sub_r		 -		offset _table_)	;6		;7	
	dw	(offset add_sub_r8		 -		offset _table_)	;7		;8	   	
	dw	(offset add_sub_r32_imm	 -		offset _table_)	;8		;9    		
	dw	(offset shl_shr_r_imm8	 -		offset _table_)	;9		;10       				
	dw	(offset push_pop_r32_imm -		offset _table_)	;10		;11        		
	dw	(offset cmp_r_imm		 -		offset _table_)	;11		;12        		
	dw	(offset test_r			 -		offset _table_)	;12		;13        		
	dw	(offset jxx_short_down	 -		offset _table_)	;13		;14	
	dw	(offset jxx_short_up	 -		offset _table_)	;14		;15	
	dw	(offset jxx_near_down	 -		offset _table_)	;15		;16	
	dw	(offset jxx_near_up		 -		offset _table_)	;16		;17     	
	dw	(offset jmp_short		 -		offset _table_)	;17		;18            	
	dw	(offset jmp_near		 -		offset _table_)	;18		;19	
	dw	(offset call_near		 -		offset _table_)	;19		;20
    dw	(offset loopx_r32		 -		offset _table_)	;20		;21     	
	dw	(offset three_byte_r	 -		offset _table_)	;21		;22
	dw	(offset cmovx_r32		 -		offset _table_)	;22		;23	
	dw	(offset bswap_r32		 -		offset _table_)	;23		;24	
	dw	(offset mov_lea_esp		 -		offset _table_)	;24		;25        	
	dw	(offset cmp_esp			 -		offset _table_)	;25		;26	
	dw	(offset mov_lea_addr	 -		offset _table_)	;26		;27	
	dw	(offset cmp_addr		 -		offset _table_)	;27		;28	
	dw	(offset fpux 			 -		offset _table_)	;28		;29 	
	dw	(offset mmxx			 -		offset _table_)	;29		;30 	
	dw	(offset ssex			 -		offset _table_)	;30		;31
;--------------------------------------------------------------------------------------------------------
	dw	(offset one_byte		 -		offset _table_)	;0		;1
	dw	(offset setx_r8			 -		offset _table_)	;1		;2  		               

	dw	(offset prolog1			 -		offset _table_)	;2		;3 
	dw	(offset epilog1			 -		offset _table_)	;3		;4 
	dw	(offset fakeapi			 -		offset _table_)	;4		;5 
	dw	(offset mov_lea_ebp		 -		offset _table_)	;5		;6       	
	dw	(offset cmp_ebp			 -		offset _table_)	;6		;7
	dw	(offset add_sub_ebp		 -		offset _table_)	;7		;8  	 

;========================================================================================================





;===================================[ INC/DEC reg32 ]====================================================
inc_dec_r32:
	test 	ecx,ecx								;���� �� ���� 㦥 ����ᠭ
	je 		end_trash							;�᫨ ��, � �४�頥� �����஢��� �������
	push	2                       			
	call	[ebp].rgen_addr						;�� �㤥� �������: INC/DEC ?
	shl		eax,3								;���� ����ਬ INC/DEC
	add		al,40h
	xchg	eax,edx	
	call 	free_reg							;��뢠�� �㭪�� �����樨 ᢮������� ॣ���� (32-ࠧ�來�)                                            
	add		al,dl
	stosb										;��堥� ᣥ���஢���� ����� � ����
	dec		ecx									;㬥��蠥� ���稪 �� ࠧ��� ⮫쪮 �� ᣥ��७��� �������
	ret											;�� ��室, ⮢���:)!
;===================================[ INC/DEC reg32 ]====================================================





;===============================[ AAS/AAD/NOP/CLC/CLD/etc ]==============================================
one_byte:
	test	ecx,ecx
	je		end_trash 

	lea		esi,[ebx+(one_byte_opcode - _delta_trash_)]	;������ �ﭥ� � ⠡��窨 							   		
	call	rnd_reg								;� ������ ��砥 �㭪�� �ᯮ������ ��� ��� [0;7]
	add		esi,eax
	mov		eax,[ebp].regs						;� EAX ������ ������ ॣ����� 
	test	ah,ah								;�஢��塞, 1-� ������ ॣ���� �� EAX? (bh==0 ?) 
	je		@F									;�᫨ ��, � �����஢��� ⠪�� ������� ��� AAA �����, ��९�루���� 
	test	al,al								;�஢��塞, 2-�� ������ ॣ���� �� EAX? (bl==0 ?) 					
	je		@F									;etc
	bt		eax,31								;�����, ᬮ�ਬ, ��⠭����� �� �� � 3-�� ������ ॣ����?						
	jnc		_2half_								;�᫨ ���, � ⥯��� �筮 ����� ������� ⠪�� ������� ��� AAA
	shr		eax,16
	cmp		al,0
	je		@F

_2half_:
	push	7;6									;����� ������� ������� AAA,AAS etc (�.�. �, ����� ������ �� EAX)
	call	[ebp].rgen_addr						;��뢠�� ��� 
	add		esi,eax		                			                                                     
@@:
	movsb										;��堥� � ���� ����祭�� �����
	dec 	ecx									;���稪--
_1bret_:
	ret											;������
;===============================[ AAS/AAD/NOP/CLC/CLD/etc ]==============================================





;=======================================[ NOT/NEG reg32 ]================================================
not_neg_r32:
	cmp 	ecx,2								;�஢�ઠ
	jl		inc_dec_r32							;�᫨ �� ����ᠭ�, ��室��
	mov 	al,0F7h								;���� ������㥬 �������� NOT/NEG reg32                                      
	stosb                                               
	call 	free_reg							;����砥� ᢮����� ॣ���� (32 ࠧ�鸞)
	add		al,0D0h
	xchg	eax,edx                            		
	push	2
	call	[ebp].rgen_addr						;����ਬ ��
	shl 	al,3
	add 	al,dl
	stosb										;��堥� � ����
	dec	ecx										;���稪-=2
	dec	ecx
	ret											;��室��
;=======================================[ NOT/NEG reg32 ]================================================





;===================[ (LEA REG32,[VALUE32])/(LEA REG32,[REG32+VALUE32]) ]================================
lea_r32_mem32:
	cmp 	ecx,6								;�஢�ઠ (6 ���� �㤥� �������� ⠪�� ���ୠ� �������)
	jl		_lret_
	mov 	al,8Dh								;�᫨ �஢�ઠ �ᯥ譮, �ன���� - ����ਬ ������ ������� (����� �������筮 ��)
	stosb										;�����뢠�� 1-� ���� �������                                      
	push	2
	call	[ebp].rgen_addr						;����� ��砩�� ��।��塞, ����� �� 2-� ��ਠ�⮢ ������� �㤥� ���������? 
	shl		eax,7
	xchg	edx,eax	
	call 	free_reg							;����砥� ᢮����� ॣ���� (32-ࠧ�來�)
	shl 	al,3
	test	edx,edx
	je		_lmem_
	add		edx,eax
	call	free_reg
	add		eax,edx
	jmp		@F
_lmem_:
	add 	al,5 
@@:
	stosb                            
	push	-1
	call	[ebp].rgen_addr                            
	stosd                              	                                                        
	sub 	ecx,6								;���⠥� ����� ⮫쪮 �� ᣥ���஢����� ������� LEA (6 ����)
_lret_:
	ret											;��室��
;===================[ (LEA REG32,[VALUE32])/(LEA REG32,[REG32+VALUE32]) ]================================





;==================================[ MOV/XCHG REG32,REG32 ]==============================================  
mov_xchg_r32:
	cmp		ecx,2								;�᫨ ����� ������㥬�� ������� 
	jl		inc_dec_r32							;����� 2, � ��室�� �� �㭪樨 
    push	6									;����,
	call	[ebp].rgen_addr						;�롨ࠥ�, �� �㤥� ���������? MOV(0x8B ��� 0x89) ��� XCHG ?  
	cmp		al,1
	jg		_0x8B_
	shl		eax,1
	add		al,87h
	jmp		_0x87_0x89_								
_0x8B_:
	mov		al,8bh						
_0x87_0x89_:
	stosb							
	call	free_reg			
	shl		eax,3				
	add		al,0c0h		
	xchg	edx,eax			
	call	free_reg			
	add		al,dl			
	stosb					
	dec		ecx									;���稪-=2
	dec		ecx
	ret											;�� ��室
;==================================[ MOV/XCHG REG32,REG32 ]============================================== 





;===========================[ (MOV REG8,REG8/IMM8)/(XCHG REG8,REG8) ]====================================
mov_xchg_r8:
	cmp		ecx,2								;etc 
	jl		inc_dec_r32
	push	7
	call	[ebp].rgen_addr
	cmp		al,6
	je		_0xB0_
	cmp		al,1
	jg		_0x8A_
	shl		eax,1
	add		al,86h
	jmp		_0x86_0x88_
_0x8A_:
	mov		al,8Ah
_0x86_0x88_:
	stosb
	call	free_reg_r8							;����� ��뢠�� �㭪�� ������� 8-ࠧ�來��� ॣ���� 	
	shl		eax,3
	add		al,0C0h
	xchg	eax,esi
	call	free_reg_r8
	add		eax,esi
	stosb
	jmp		_mret_
;--------------------------------------------------------------------------------------------------------
_0xB0_:
	call	free_reg_r8
	add		al,0B0h
	stosb
	push	256
	call	[ebp].rgen_addr
	stosb
;--------------------------------------------------------------------------------------------------------
_mret_:	
	dec		ecx
	dec		ecx
	ret
;===========================[ (MOV REG8,REG8/IMM8)/(XCHG REG8,REG8) ]====================================





;================================[ MOV REG32/REG16,IMM32/IMM16 ]========================================= 
mov_r_imm:
	cmp		ecx,5
	jl		_m2ret_			
    push	4
	call	[ebp].rgen_addr						;�㤥� ������� 0x66  � ����⭮��� 1/4
	cdq
    test	eax,eax                           
    jne		_m2r32_
;--------------------------------------------------------------------------------------------------------
	mov		al,066h								;�����뢠�� ��䨪�				
	stosb						
	xchg	eax,edx								;edx=0x66
	inc		ecx									;���४�஢�� ���稪�  
;--------------------------------------------------------------------------------------------------------
_m2r32_:
	call	free_reg							;����砥� ᢮����� 32-ࠧ�來� ॣ����
	add		al,0b8h						
	stosb						
	push	-1
	call	[ebp].rgen_addr						;����ਬ �� � ��������� [0;0xffffffff)
	stosw										;� ����頥� ��� � ����
	cmp		dl,066h
	je		@F					
	db		0fh,0c8h							;bswap	eax			
	stosw							
@@:	        
	sub		ecx,5								;�����蠥� ����稪 �� 4
_m2ret_:
	ret											;��室��
;================================[ MOV REG32/REG16,IMM32/IMM16 ]=========================================





;====================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG32/REG16,REG32/REG16 ]==============================              
add_sub_r:                              	
	cmp		ecx,03h								;������� �� ?
	jl		_aret_                                        	                                                        
	push	02h
	call	[ebp].rgen_addr						;��
	test	eax,eax								;�����஢��� �� ⠪�� 0x66?
	je		_ar32_                                         
;--------------------------------------------------------------------------------------------------------
	mov		al,66h								;��⨬:)!
	stosb										;������ � ����
	dec		ecx									;���४�஢�� ���稪�
;--------------------------------------------------------------------------------------------------------	                                                        
_ar32_:                                            
    push	7;4									;����ਬ 㦥 ᠬ� �������
	call	[ebp].rgen_addr
	shl		eax,3;04h							;� ⠪�� �� �ᯥ宬 ����� �뫮 � ������ cmp, �� �� ���, ���⮬� �ய�᪠��  
	xchg	eax,edx
	push	4
	call	[ebp].rgen_addr
	or		al,1								;�����쪠� ������ :)!
	add		al,dl
	stosb                                                   
	call	free_reg							;����砥� ᢮����� ॣ���� (32 ࠧ�鸞)
	shl		al,03h                              
	xchg	edx,eax
	add		dl,0C0h
	call	free_reg							;����砥� 2-�� ᢮����� ॣ����
	add		al,dl                          
	stosb										;��堥� � ����
	dec		ecx                      
	dec		ecx									;㬥��蠥� ���稪 �� 2 � ��室��      
_aret_:
	ret	                                   
;====================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG32/REG16,REG32/REG16 ]==============================              





;===========================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG8,REG8 ]=====================================              
add_sub_r8:                              	
	cmp		ecx,02h								;������� �� ?
	jl		inc_dec_r32                                        	                                                        
    push	7;4									;����ਬ 㦥 ᠬ� ������� (ᬮ�� ���, �������筮)
	call	[ebp].rgen_addr
	shl		eax,3;04h                              
	xchg	eax,edx
	push	4
	call	[ebp].rgen_addr
	and		al,2								;�� ���� �����쪠� ������ ;)
	add		al,dl
	stosb                                                   
	call	free_reg_r8							;����砥� ᢮����� ॣ����
	shl		al,03h                  
	add		al,0C0h                                           
	xchg	eax,esi
	call	free_reg_r8							;����砥� 2-�� ᢮����� ॣ����
	add		eax,esi
	stosb										;��堥� � ����
	dec		ecx       
	dec		ecx                
	ret											;㬥��蠥� ���稪 �� 2 � ��室��
;===========================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG8,REG8 ]=====================================              





;==========================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG32,IMM32 ]====================================              
add_sub_r32_imm:;+imm8
	cmp		ecx,6								;᭮�� �஢�ઠ
	jl		_a3ret_
	push	2
	call	[ebp].rgen_addr
	mov		esi,eax
	shl		eax,1
	add		al,81h                     			
	stosb
	push	7
	call	[ebp].rgen_addr                            			 
	shl		al,3;4 == CMP	
	xchg	edx,eax
	add		dl,0C0h
	call	free_reg							;etc 
	add		al,dl                      			
	stosb                             
	push	-1
	call	[ebp].rgen_addr                         
	test	esi,esi
	je		_a3imm32_
	stosb
	sub		ecx,3
	ret
	;add		ecx,3
	;jmp		@F 
_a3imm32_:
	stosd                              			
@@:					 
	sub		ecx,6								;�����蠥� ����稪 �� 6
_a3ret_:
	ret											;��室��
;==========================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG32,IMM32 ]====================================              





;======================[ RLC/RCR/ROL/ROR/SAL/SAR/SHL/SHR REG32/REG8,IMM8 ]===============================
shl_shr_r_imm8:
	cmp 	ecx,3								;�஢�ઠ
	jl 		inc_dec_r32 
	push	2									;����� "��砩��" ��।��塞, ����� ॣ���� (8 ��� 32) �㤥� ���������
	call	[ebp].rgen_addr
	mov		esi,eax
	add 	al,0c0h
	stosb										;� ��稭��� ������� ������ �������
	call 	rnd_reg								;� ������ ��砥 ����砥� ��砩��� �᫮ [0..7]
												;��� ��� �㦭� ��� ⮣�, �⮡� ����ந�� ��� RCL, ��� SHR etc
	shl		al,3								;
	add		al,0c0h
	push	eax
	test	esi,esi								;�᫨ �믠�� ������� ������� � 8-ࠧ�來� ॣ���஬,
	jne		_sr32_
	call	free_reg_r8							;� ����稬 ᢮����� 8-ࠧ�來� ॣ���� 
	jmp		@F
_sr32_:
	call	free_reg							;���� ����稬 ᢮����� 32-ࠧ�來� ॣ���� 
@@:
	pop		edx		
	add 	al,dl
	stosb										;�����뢠�� ��।��� ���� �������
	push	31 ;32;-1							;����ਬ ��砩�� ���� 
	call	[ebp].rgen_addr                                
	inc		eax									;!��� ���������� ������ �������  
	stosb										;� ��堥� ��� � ����
	sub 	ecx,3								;㬥��蠥� ���稪 �� 3
	ret											;��室��
;======================[ RLC/RCR/ROL/ROR/SAL/SAR/SHL/SHR REG32/REG8,IMM8 ]===============================





;======================[ PUSH REG32/IMM8/IMM32/[esp+x] POP REG32/[esp-x] ]===============================  
push_pop_r32_imm:
	push	30									;����ਬ ��砩��� �᫮
	call	[ebp].rgen_addr
	mov		edx,eax	
	add		al,9								;������塞 9 (���ᨬ��쭮� �� ��������� ��ਪ��)  
	cmp		eax,ecx								;�᫨ ����� ������㥬��
	jg		_pret_								;������権 �����, 祬 ᪮�쪮 ����� ������, � �� ��室
    push	10									;᭮�� ����ਬ ��砩��� �᫮ 						
    call	[ebp].rgen_addr  
	cmp		eax,2								;�롨ࠥ�, ����� ��� �����:)
	jl		_0x6A_
	je		_0x68_
	cmp		eax,4
	jl		_0xFFesp_
	je		_0xFF_
;--------------------------------------------------------------------------------------------------------
_0x50_:
	call	rnd_reg
	add		al,50h								;push reg (0x50)
	stosb                               
	jmp		@F									;��룠�� ����� 
;--------------------------------------------------------------------------------------------------------
_0x6A_:
	mov		al,6ah								;push imm8 (0�6� 0xXX)
	stosb		
	push	-1
	call	[ebp].rgen_addr					
	stosb										;����� � ����
	dec		ecx									;���४��㥬 ����� ॠ�쭮 �����뢠���� ���� 
	jmp		@F					

;--------------------------------------------------------------------------------------------------------
_0x68_:                                                   
	mov		al,68h								;push imm32 (0x68 0xXX 0xXX 0xXX 0xXX)                                           
	stosb
	push	-1
	call	[ebp].rgen_addr
	stosd
	sub		ecx,4								;���४��㥬
	jmp		@F
;--------------------------------------------------------------------------------------------------------
_0xFFesp_:
	mov		ax,074FFh							;push dword ptr [esp+0xXX]
	stosw
	mov		al,24h
	stosb
	push	11h
	call	[ebp].rgen_addr
	lea		esi,[eax+4]							;����� ������ �᫮ ���� 4
	and		eax,3
	sub		esi,eax
	xchg	eax,esi 
	stosb
	sub		ecx,3
	jmp		@F 
;--------------------------------------------------------------------------------------------------------
_0xFF_:
	mov		al,0ffh								;push reg (0xff 0xf0+r) 
	stosb						
	call	rnd_reg 
	add		al,0f0h			
	stosb			
	dec		ecx
;--------------------------------------------------------------------------------------------------------
@@:                                                                         
	push	[ebp].buf_for_trash					;⠪ ��� ��।����� �������� �� ������ �� �㤥�, ���⮬� ᭠砫� ��࠭�� ���� ���祭��, � ���� ����襬 
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp									;��।��� ���� �������� 		
	call	xTG									;����ਬ ����� ���� (४����)
	pop		[ebp].size_trash					;����⠭���� ࠭�� ��࠭���� ���祭�� 
	pop		[ebp].buf_for_trash
	xchg	eax,edi
;--------------------------------------------------------------------------------------------------------
	call	rnd_reg								;����� "��砩��" ��थ�塞, ����� ��� ������� 
	test	eax,eax
	jne		_0x58pop_
	mov		eax,0FC24448Fh						;pop dword ptr [esp-XX]
	stosd
	sub		ecx,3
	jmp		@F									;���	
;--------------------------------------------------------------------------------------------------------
_0x58pop_:	
	call	free_reg							;pop reg 	
	add		al,58h	
	stosb		
@@: 
	sub		ecx,edx								;�����蠥� ����稪 �� edx
	dec		ecx
	dec		ecx									;�� 㬥��蠥� ���稪 
_pret_:
	ret											;��室��
;======================[ PUSH REG32/IMM8/IMM32/[esp+x] POP REG32/[esp-x] ]=============================== 

 



;===================================[ CMP REG8/IMM8/REG32 ]==============================================
cmp_r_imm:
	cmp 	ecx,54								;54 ���� = 50 ���� ���� ��� jxx + 2 ���� ��� jxx + 2 ���� ��� cmp
	jl 		_cret_								;�᫨ ��⠢���� ��� ����� ���� �� �����筮, � ��室�� 	 
	push	3									;���� ��稭��� ������� �������
	call	[ebp].rgen_addr				
	add 	al,3ah
	stosb                                              
	call 	rnd_reg                                    
	add		al,0C0h
	xchg	eax,edx 
	call 	rnd_reg                           
	shl 	al,3                                
	add 	al,dl                               
	stosb                                              
	dec		ecx                                        
	dec		ecx
	jmp 	jxx_short_down						;��᫥ ⮣�, ��� ������� ����஥��, ���室�� �� ������� jxx (�.�. cmp ��� jxx - �� �।��) 
_cret_:
	ret                               
;===================================[ CMP REG8/IMM8/REG32 ]============================================== 
	                                        	 




;=====================================[ TEST REG8/REG32 ]================================================
test_r:
	cmp 	ecx,54								;ᬮ�� ���
	jl 		_tret_	 	                        
	push	2
	call	[ebp].rgen_addr						;��।��塞, ����� �� ॣ���஢ ���� �ᯮ�짮������ (�.�. 8 ��� 32 �ࠧ�來�) 
	add 	al,84h
	stosb                                          
	call 	rnd_reg                                 
	add		al,0C0h
	xchg	eax,edx 
	call 	rnd_reg                                     
	shl 	al,3                                     
	add 	al,dl                                       
	stosb                                               
	dec		ecx                                       
    dec		ecx
	jmp 	jxx_short_down						;�������筮, ᬮ�� ���
_tret_:	                                         
	ret                                          
;=====================================[ TEST REG8/REG32 ]================================================
	                                                      
	                                                 

 

;=====================================[ JXX SHORT IMM8 ]=================================================  
jxx_short_down:									;��������� JXX SHORT ��룠�饣� ���� (�� ����訩 ����)          
	push	50									;������㥬 ��砩��� �᫮
	call	[ebp].rgen_addr
	mov		edx,eax   							                                           
	inc		eax									;������塞 ����� ������㥬�� ������� (� ������ ��砥 �� ���⪨� (2 ����) jmp)
	inc		eax									;��� �������� ��砥� �������筮 (⮫쪮 ���-�� ���⮢ ����� ���� ���᭮ ��㣨�) 
	cmp		eax,ecx								;�஢��塞, ������ ��? 						
	jg		_jxxsdret_							;�᫨ ���, � ��室��
;--------------------------------------------------------------------------------------------------------	    	
	push	16									;���ᨬ� ���� ⮫쪮 16 ⠪�� ���⪨� jmp'�� 						
	call	[ebp].rgen_addr
	add		al,70h	
	stosb				
	mov		eax,edx
	stosb							
;-------------------------------------------------------------------------------------------------------- 
	push	[ebp].buf_for_trash					;�������筮, ᬮ�� ��� 
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp		
	
	call	xTG									;������㥬 ��।��� ����� ���� (���� ����� ���室��) 
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi
	dec		ecx									;�����蠥� ����稪 �� 2
	dec		ecx
	sub		ecx,edx
_jxxsdret_:
	ret											;��᪠������
;=====================================[ JXX SHORT IMM8 ]=================================================





;============[ (PUSH 0xXX POP REG32)/(MOV REG32,0xXXXXXXXX) DEC REG32 JXX SHORT IMM8 ]=================== 
jxx_short_up:									;��������� JXX SHORT ��룠�騩 ����� (�� ����訩 ����)   
	push	60h									;������㥬 ��砩��� �᫮ 
	call	[ebp].rgen_addr
	mov		edx,eax
	add		eax,2+1+5							;mov reg,value (5 byte) + dec reg (1 byte) + jxx short (2 byte) 			 
	cmp		eax,ecx								;�஢��塞, ������ ��? 											
	jg		_jxxsuret_							;�᫨ ���, � ��室��
;--------------------------------------------------------------------------------------------------------
	push	200h								;㧭���, �� ����� ����� ��룭�� jxx short
	call	[ebp].rgen_addr 
	xchg	eax,esi
	cmp		esi,7Fh								;� �᫨ �� ����� ����� 0x80, ⮣�� ᣥ��ਬ push 0xXX pop reg
	jl		_jxxsupushpop_
;--------------------------------------------------------------------------------------------------------
_jxxsumov_:										;���� mov reg,0xXXXXXXXX 
	call	free_reg
	push	eax
	add		al,0b8h								;MOV REG32,0xXXXXXXXX
	stosb
	xchg	eax,esi
	inc		eax	
	stosd
	dec		ecx
	dec		ecx
	jmp		@F 
;--------------------------------------------------------------------------------------------------------
_jxxsupushpop_:
	mov		al,6Ah								;PUSH 0xXX POP REG32
	stosb
	xchg	eax,esi
	inc		eax
	stosb
	call	free_reg
	push	eax
	add		eax,58h
	stosb
;--------------------------------------------------------------------------------------------------------	
@@:												;� ������ ��� ���� ������ ������!	                      
	pop		eax
	push	eax									;optimazation!
	shl		eax,16								;�.�. 2 ॣ���� � ⠪ �ண��� ����� (��� ���� �ᯮ�짮���� � ���ਯ��), 
	add		eax,[ebp].regs						;� ��� �㦥� �� ���� ॣ����, ����� �ண��� (�६����) ����� �㤥�. 
												;��� ᠬ� ॣ���� � �㤥� �ᯮ�짮������ ��� ������ ����� (�.�. mov reg32,0xXXXXXXXX dec reg jxx short)
	bts		eax,31								;� ⠪��, �⮡� �� ��稫��� ��� �� ४��ᨨ, �� �६���� ����頥� ������� � ४��ᨨ ��� ���������. 
												;��⮬� ��, �� ४��ᨨ, �᫨ �믠��� ������� �⮩ �� ����� (� �������� ������ ����!), 
												;� ��� ᭮�� ���� �㤥� ⮣�� ���� �� ���� ॣ����, � ��� 㦥 � �����뢠�� ���㤠 (���� �� ���� �।��騩 ॣ����), � 
												;�᫨ �� ���쬥� �� ���� ॣ����, � ���� �� � �����樥� ��㣨� ������ - ������� ����� ���������� ⠪, �� 
												;ॣ��⮢ ᢮������ �� �������� � �㤥� ��᪮���� 横� � �.�. 
													 
	mov		esi,[ebp].xmask1
	and		esi,11111111111011101011111111111111b 	;��� ���⮬� � �⠢�� �६���� ����� �� ������� � ४��ᨨ �������� �������権 (����� ���㫥���� �㦭�� ���, 
												;����� � �⢥��� �� ������� �������樨). ����� :)! 
	;btr		esi,15;+1=16
	;btr		esi,17
	;btr		esi,23
;--------------------------------------------------------------------------------------------------------
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	push	[ebp].regs
	push	[ebp].xmask1
	push	[ebp].xmask2
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	mov		[ebp].regs,eax
	mov		[ebp].xmask1,esi
	mov		esi,[ebp].xmask2
	and		esi,11111111111111111111111111101111b	;⠪�� �⠢�� �६���� ����� �� ������� ������ ���襪 (�᫨ ��� ࠧ�襭�) 
	mov		[ebp].xmask2,esi 
	push	ebp		
			
	call	xTG									;������㥬 ����� ���� 
	pop		[ebp].xmask2 
	pop		[ebp].xmask1
	pop		[ebp].regs
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi
;-------------------------------------------------------------------------------------------------------- 
	pop		eax                                                                           
	add		al,48h								;DEC REG32 
	stosb
;--------------------------------------------------------------------------------------------------------
	sub		ecx,6								;㬥��蠥� ���稪
	sub		ecx,edx								;etc
;--------------------------------------------------------------------------------------------------------
	add		edx,3								;+ 3 byte ( jxx short (2 byte) + dec reg32 (1 byte) )
	neg		edx									;����� � ������� ����ன ���� ����塞 ����, �㤠 ������ 㪠�뢠�� jxx short  
;--------------------------------------------------------------------------------------------------------
	push	2									;�⮡� �� �뫮 ⨯-⮯, �㤥� ������� ⮫쪮 JNE/JE 	 
	call	[ebp].rgen_addr
	add		al,74h
	stosb	
	xchg	eax,edx 
	stosb							
_jxxsuret_:
	ret
;============[ (PUSH 0xXX POP REG32)/(MOV REG32,0xXXXXXXXX) DEC REG32 JXX SHORT IMM8 ]===================  





;=====================================[ JXX NEAR IMM32 ]================================================= 
jxx_near_down:									;��������� JXX NEAR ���� (� ��஭� ������ ���ᮢ)
	push	0B0h								;�������筮 ������, ᬮ�� ��� 
	call	[ebp].rgen_addr
	cmp		al,80h								;ᯥ樠�쭮 ��� jxx near (���� �� ����襬 ������ ���筮 �����஢����� jxx short) 
	jb		jxx_near_down;jl					;⨯� �ࠢ��������� ;)
	mov		edx,eax						
	add		eax,6                                        
	cmp		eax,ecx				 						
	jg		_jxxndret_	
;--------------------------------------------------------------------------------------------------------	
	mov		al,0fh								;���� 6 ���� (0x0f 0x8x imm32)
	stosb										;� ��稭��� ����娢��� � ���� 
	push	16									;etc (ᬮ�� ���) 						
	call	[ebp].rgen_addr
	add		al,80h			                
	stosb						
	mov		eax,edx
	stosd						
;-------------------------------------------------------------------------------------------------------- 		
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp		

	call	xTG									;���� ����� ���室��
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi
	sub		ecx,6								;㬥��蠥� ���稪 (���४�� ���)
	sub		ecx,edx
_jxxndret_:
	ret											;��᪠������
;=====================================[ JXX NEAR IMM32 ]================================================= 




 
;============[ (PUSH 0xXX POP REG32)/(MOV REG32,0xXXXXXXXX) DEC REG32 JXX NEAR IMM32 ]===================  
jxx_near_up:									;��������� JXX NEAR ����� (� ��஭� ������ ���ᮢ) 
	push	0B0h								;�������筮, ᬮ�� ��� 
	call	[ebp].rgen_addr
	cmp		al,80h
	jb		jxx_near_up;jl
	mov		edx,eax						
	add		eax,12								;mov reg32,0xXXXXXXXX (5 byte) + dec reg32 (1 byte) + jxx near (6 byte) 
	cmp		eax,ecx				 
	jg		_jxxnuret_				 
;--------------------------------------------------------------------------------------------------------
	push	200h
	call	[ebp].rgen_addr
	xchg	esi,eax
	cmp		esi,7Fh
	jl		_jxxnupushpop_;jb 
;--------------------------------------------------------------------------------------------------------
_jxxnumov_:
	call	free_reg
	push	eax
	add		al,0B8h								;MOV REG32,0xXXXXXXXX
	stosb
	xchg	eax,esi
	inc		eax
	stosd
	dec		ecx
	dec		ecx
	jmp		@F 
;--------------------------------------------------------------------------------------------------------
_jxxnupushpop_:
	mov		al,6Ah
	stosb										;PUSH 0xXX POP REG32 
	xchg	eax,esi    
	inc		eax
	stosb
	call	free_reg
	push	eax
	add		al,58h
	stosb
;--------------------------------------------------------------------------------------------------------	
@@:
	pop		eax
	push	eax
	shl		eax,16
	add		eax,[ebp].regs;dword ptr [ebp+30h]
	bts		eax,31

	mov		esi,[ebp].xmask1
	and		esi,11111111111011101011111111111111b
	;btr		esi,17;+1=16
	;btr		esi,15
	;btr		esi,23
;--------------------------------------------------------------------------------------------------------			
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	push	[ebp].regs
	push	[ebp].xmask1
	push	[ebp].xmask2 
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	mov		[ebp].regs,eax
	mov		[ebp].xmask1,esi  
	mov		esi,[ebp].xmask2
	and		esi,11111111111111111111111111101111b	;⠪�� �⠢�� �६���� ����� �� ������� ������ ���襪 (�᫨ ��� ࠧ�襭�) 
	mov		[ebp].xmask2,esi 
	push	ebp		

	call	xTG									;���� ����� ���室��
	pop		[ebp].xmask2 
	pop		[ebp].xmask1
	pop		[ebp].regs
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi
;-------------------------------------------------------------------------------------------------------- 
	pop		eax
	add		al,48h								;DEC REG32
	stosb
;--------------------------------------------------------------------------------------------------------
	sub		ecx,10
	sub		ecx,edx
;--------------------------------------------------------------------------------------------------------
	add		edx,7
	neg		edx
;--------------------------------------------------------------------------------------------------------
	mov		al,0fh								;JXX NEAR                 
	stosb  
	push	2						
	call	[ebp].rgen_addr
	add		al,84h
	stosb	
	xchg	eax,edx
	stosd							
;--------------------------------------------------------------------------------------------------------        
_jxxnuret_:
	ret											;��᪠������
;============[ (PUSH 0xXX POP REG32)/(MOV REG32,0xXXXXXXXX) DEC REG32 JXX NEAR IMM32 ]===================  





;======================================[ JMP SHORT IMM8 ]================================================ 
jmp_short:
	push	50									;�������筮, ᬮ�� ���!					
	call	[ebp].rgen_addr
	inc		eax
	mov		edx,eax
	inc		eax
	inc		eax
	cmp		eax,ecx							
	jg		_jmpsret_			
;-------------------------------------------------------------------------------------------------------- 		
	mov		al,0ebh								;� ����襬 ���⪨� jmp  						
	stosb							
	mov		eax,edx
	stosb					
;-------------------------------------------------------------------------------------------------------- 
	bt		[ebp].xmask1,31						;� ��� �� ������ ��:)! 
	jnc		_jmpsnomask_						;᭠砫� ᬮ�ਬ �� ��᪥, ࠧ�襭� �� ��� �� �ਬ����� 
	push	-1									;�᫨ ��, �...���� � ᫥���饬: �ࠧ� ��᫥ ������ �⠢�� �� ���� � ����� 
	call	[ebp].rgen_addr						;�� �筮 ⠪��: ����ਬ ᠬ jmp + ��।��� ����� ����. 
	stosb										;� ��������� �⮬� ����� ᮧ������ ����, �� ��������� ࠧ�� �������. ��� ⠪. 
	dec		ecx
	dec		edx
_jmpsnomask_:	
;--------------------------------------------------------------------------------------------------------			
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp		

	call	xTG									;���� ����� ���室��
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi
;--------------------------------------------------------------------------------------------------------
	dec		ecx
	dec		ecx									;㬥��蠥� ���稪 �� ࠧ��� jmp short (2 byte) 
	sub		ecx,edx								;� �� ࠧ��� ���樨 ����
_jmpsret_:							
	ret											;exit
;======================================[ JMP SHORT IMM8 ]================================================




 
;======================================[ JMP NEAR IMM32 ]================================================
jmp_near:
	push	0B0h								;��, �������筮, ᬮ�� ��� 
	call	[ebp].rgen_addr
	cmp		al,7Dh
	jb		jmp_near;jl
	inc		eax
	mov		edx,eax
	add		eax,5								;JMP NEAR (0xE9 0xXX 0xXX 0xXX 0xXX = 5 byte)                                      
	cmp		eax,ecx								;ᬮਬ, 墠⠥� �� � ��� ���� ��� �����樨 ������ ������� + ���樨 ���� ��� ��� 	 
	jg		_jmpnret_				
;--------------------------------------------------------------------------------------------------------            
	mov		al,0e9h								;����ਬ � ��堥� � ���� ᢦ��ᯥ祭�� jmp near 	 
	stosb
	mov		eax,edx							
	stosd							
;--------------------------------------------------------------------------------------------------------
	bt		[ebp].xmask1,31						;ᬮ�� ���
	jnc		_jmpnnomask_
	push	-1
	call	[ebp].rgen_addr
	stosb
	dec		ecx
	dec		edx
_jmpnnomask_:	
;-------------------------------------------------------------------------------------------------------- 		
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp		

	call	xTG									;������㥬 ����� ���� 					
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash
	xchg	eax,edi
;--------------------------------------------------------------------------------------------------------
	sub		ecx,5				
	sub		ecx,edx				
_jmpnret_:					
	ret						
;======================================[ JMP NEAR IMM32 ]================================================





;======================================[ CALL NEAR IMM32 ]===============================================
call_near:
	push	50									;�������筮, ᬮ�� ��� 
	call	[ebp].rgen_addr
	mov		edx,eax								;��࠭塞 ࠧ��� ��ࢮ� ���樨 ����  
	push	50					
	call	[ebp].rgen_addr
	inc		eax									;+1 ���� ��� �� (�⮡� ⨯� :) ᮧ�������� ࠧ�� ������� ��᫥ call'� 
	mov		esi,eax								;��࠭�� ࠧ��� ��ன ���樨 ���� 
	lea		eax,[eax+edx+10]					;10 byte = call near (5 byte) + push ebp (1 byte) + mov ebp,esp (2 byte) + pop ebp (1 byte) + pop reg (1 byte) 
	cmp		eax,ecx					
	jg		_callnret_
;-------------------------------------------------------------------------------------------------------- 			
	mov		al,0e8h								;������㥬 � �����뢠�� call near imm32 						
	stosb						
	mov		eax,esi
	stosd						
;--------------------------------------------------------------------------------------------------------
	bt		[ebp].xmask1,31						;᭮�� �� �� � ���⮬ 
	jnc		_callnnomask_
	push	-1
	call	[ebp].rgen_addr
	stosb
	dec		ecx									;���४��㥬 ���稪 � ࠧ��� ���� (�.�. ����ᠫ� ��� 1 ����) 
	dec		esi
_callnnomask_:
;-------------------------------------------------------------------------------------------------------- 			
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,esi
	push	ebp		

	call	xTG									;���� ����� ���室�� - ����ਬ ४��ᨢ��
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi					
;--------------------------------------------------------------------------------------------------------    
	mov		al,55h						 
	stosb										;PUSH EBP
	mov		ax,0ec8bh							;MOV EBP,ESP  
	stosw								
;--------------------------------------------------------------------------------------------------------	
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	push	ebp		

	call	xTG									;-||-	-||-	-||-
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash 
	xchg	eax,edi						
;-------------------------------------------------------------------------------------------------------- 
	mov		al,5dh								;POP EBP 
	stosb							 
 
	call	free_reg							;����砥� ᢮����� ॣ����
	add		al,58h								;������塞 ������ ॣ���� 0x58
	stosb										;POP REG32 							
;--------------------------------------------------------------------------------------------------------  
	sub		ecx,10								;�����蠥� ����稪 �� 10
	sub		ecx,edx								;�����蠥� �� ࠧ��� ���樨 ������ ������
	sub		ecx,esi								;�����蠥� �� ࠧ��� ���樨 ���� 
_callnret_:							
	ret											;�� ��室:)!
;======================================[ CALL NEAR IMM32 ]=============================================== 

           
      


;======================================[ LOOP SHORT IMM8 ]===============================================
loopx_r32:										;�������筮, ᬮ�� ��� ;)!       
	mov		eax,[ebp].regs
	cmp		al,1								;᭠砫� ᬮ�ਬ, ���� �� �।� �᭮���� ॣ���஢ (�.�. ��, �� �ᯮ������� � ���ਯ��) ECX? 				
	je		_loopxret_							;�᫨ ����, � ������ ������� ������� �� �㤥�, � ��室�� 
	cmp		ah,1  
	je		_loopxret_
	push	50h									;���� ���堫�! 
	call	[ebp].rgen_addr
	mov		edx,eax
	add		eax,2+5								;7 byte = mov ecx,0xXXXXXX (5 byte) + loop (2 byte)  
	cmp		eax,ecx								;�஢��塞, ������ ��? 						
	jg		_loopxret_							;�᫨ ���, � �� ��室 ��䨣 
;--------------------------------------------------------------------------------------------------------
	push	200h
	call	[ebp].rgen_addr
	xchg	esi,eax
	cmp		esi,7Fh
	jl		_loopxpushpop_;jb
;--------------------------------------------------------------------------------------------------------
	mov		al,0b9h;ecx							;MOV ECX,0xXXXXXXXX
	stosb
	xchg	eax,esi
	inc		eax	
	stosd
	dec		ecx
	dec		ecx
	jmp		@F 
;--------------------------------------------------------------------------------------------------------
_loopxpushpop_:
	mov		al,6Ah								;PUSH 0xXX POP ECX           
	stosb
	xchg	eax,esi
	inc		eax
	stosb
	mov		al,59h
	stosb
;--------------------------------------------------------------------------------------------------------		
@@:	
	mov		eax,80010000h
	add		eax,[ebp].regs 
	;bts		eax,31
	mov		esi,[ebp].xmask1
	and		esi,11111111111011101011111111111111b
	;btr		esi,15;+1=16
	;btr		esi,17
	;btr		esi,23
;--------------------------------------------------------------------------------------------------------			
	push	[ebp].buf_for_trash
	push	[ebp].size_trash
	push	[ebp].regs
	push	[ebp].xmask1
	push	[ebp].xmask2
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,edx
	mov		[ebp].regs,eax
	mov		[ebp].xmask1,esi
	mov		esi,[ebp].xmask2
	and		esi,11111111111111111111111111101111b	;⠪�� �⠢�� �६���� ����� �� ������� ������ ���襪 (�᫨ ��� ࠧ�襭�) 
	mov		[ebp].xmask2,esi  
	push	ebp		

	call	xTG									;������� ������ ������ 
	pop		[ebp].xmask2 
	pop		[ebp].xmask1
	pop		[ebp].regs 
	pop		[ebp].size_trash
	pop		[ebp].buf_for_trash
	xchg	eax,edi 
;--------------------------------------------------------------------------------------------------------
	sub		ecx,5
	sub		ecx,edx
;--------------------------------------------------------------------------------------------------------
	inc		edx
	inc		edx
	neg		edx
;--------------------------------------------------------------------------------------------------------
	push	3
	call	[ebp].rgen_addr
	add		al,0E0h
	stosb										;����ਬ LOOP SHORT IMM8 
	xchg	eax,edx
	stosb							
_loopxret_:
	ret
;======================================[ LOOP SHORT IMM8 ]===============================================





;================================[ BSF/BTR/IMUL etc REG32,REG32 ]========================================
three_byte_r:
	cmp		ecx,3								;�஢�ઠ: ���� ���⨪� ��� ����� ������ �������?
	jl		_3bret_								;��㤠筮? ⮣�� �� ��室
	mov		al,0fh								;� ��稭��� ������� � �����뢠�� ������ ������� 
	stosb                              			
	lea		esi,[ebx+(three_byte_opcode - _delta_trash_)]	;� esi - 㪠��⥫� ��
												;⠡���� ��� �����樨 3-� ������ ������						   		
	push	16
	call	[ebp].rgen_addr                                       
	add		esi,eax                    			
	movsb                              			                    	
	call	free_reg                   
	shl		eax,3			   		
	add		al,0C0h
	xchg	eax,edx 
	call	free_reg                   	
	add		al,dl                      	
	stosb                              
	sub		ecx,3								;���稪-=3
_3bret_:
	ret											;��室��:)!
;================================[ BSF/BTR/IMUL etc REG32,REG32 ]======================================== 





;====================================[ CMOVX REG32,REG32 ]===============================================  
cmovx_r32:
	cmp		ecx,3								;�஢�ઠ
	jl		_cmovxret_						
	mov		al,0fh						
	stosb							
	push	16
	call	[ebp].rgen_addr                                   
	add		al,40h						
	stosb							
	call	free_reg							;����砥� ᢮����� ॣ����
	shl		eax,3								;�������� ��� �� 8
	add		al,0c0h				
	xchg	eax,edx 					
	call	rnd_reg								;����砥� ��砩�� ॣ���� 							
	add		al,dl						
	stosb							
	sub		ecx,3								;�����蠥� ����稪 �� 3
_cmovxret_:
	ret											;�����頥��� 
;====================================[ CMOVX REG32,REG32 ]=============================================== 





;====================================[ BSWAP REG32,REG32 ]=============================================== 
bswap_r32:
	cmp		ecx,2
	jl		inc_dec_r32
	mov		al,0Fh
	stosb
	call	free_reg
	add		al,0C8h
	stosb
	dec		ecx
	dec		ecx
	ret
;====================================[ BSWAP REG32,REG32 ]=============================================== 





;========================[ MOV/XCHG/LEA REG8/REG32,[ESP +(-) 0xXX] ]===================================== 
mov_lea_esp:									;����� �������������� � �������� ������������������ ������ 
	cmp		ecx,4								;�஢�ઠ, ���� �� �� ��ਪ ������� � ��� �������?
	jl		_mleret_							;�᫨ �����, � ���� ���
	push	1Ch									;���� ��稭��� �����஢��� ���� �� ���⮬ )
	call	[ebp].rgen_addr
	lea		esi,[eax+4]							;����砥� ��砩��� �᫮, ��⭮� 4
	and		eax,3
	sub		esi,eax
;--------------------------------------------------------------------------------------------------------	
	push	2									;����� ��砩�� ��।��塞, ������� � ����� ࠧ�來� (8 ��� 32) ॣ���஬ �������?
	call	[ebp].rgen_addr
	mov		edx,eax								;१��� ��࠭塞 � edx (1 - 32-ࠧ�來� ॣ����, ���� 8-ࠧ�來�)   	
	add		eax,3
	push	eax;4								;��᫥ ᬮ�ਬ, ����� ᬥ饭�� ������ ���� � esp (�.�. [esp+0xXX] ��� [esp-0xXX])
	call	[ebp].rgen_addr						;���᭮, ��� ⠪�� ������ ��� ���ਬ�� xchg dword ptr [esp+0x14],edx - ����� ������ +0x14, � ����� ⮫쪮 -0x14
	shl		eax,1								;���� ������� ����� ��� ��� ���祭�� � ��� 
	cmp		eax,3
	jl		@F
;--------------------------------------------------------------------------------------------------------
	push	eax
	push	2
	call	[ebp].rgen_addr						;� ��� ⠪�� ������ ��� lea edx,dword ptr [esp+(-)0x14] - �롨ࠥ� ࠭����� ���� ��� ᬥ饭��, �.�. �� ஫� �� ��ࠥ� 
	test	eax,eax
	pop		eax
	jne		_mlenoneg_
@@:
	neg		esi									;� ���塞 ���� � ⮫쪮 �� ᣥ���஢������ ᬥ饭�� (�� �� 1 ����) 
;--------------------------------------------------------------------------------------------------------
_mlenoneg_:
	add		al,086h;087h						;�த������ ��ந�� � �����뢠�� �������
	add		al,dl
	stosb
	test	edx,edx
	jne		_mler32_
	call	free_reg_r8
	jmp		@F
_mler32_:
	call	free_reg
@@:	
	shl		eax,3
	add		al,44h
	stosb
	mov		al,24h
	stosb
	xchg	eax,esi
	stosb
;--------------------------------------------------------------------------------------------------------
	sub		ecx,4
_mleret_:
	ret
;========================[ MOV/XCHG/LEA REG8/REG32,[ESP +(-) 0xXX] ]===================================== 





;=================================[ CMP REG8/REG32,[ESP +(-) 0xXX] ]===================================== 
cmp_esp:										;����� �������������� � �������� ������������������ ������ 
	cmp		ecx,50+4+2							;�஢��塞, ���� �� �� ���� ��� ����� ������ ������� (4 ����) 												
	jl		_cmpespret_							;+ jxx short (2 byte) + ��� �⮣� ���室� ����� ���� (max 50 byte)   
	push	4									;�᫨ �� ⨯-⮯, � ��稭��� ������� � �����뢠�� 
	call	[ebp].rgen_addr
	add		al,38h
	stosb
	call	rnd_reg								;�������筮, ᬮ�� ��� 
	shl		eax,3
	add		al,44h
	stosb
	mov		al,24h
	stosb
	push	1Ch
	call	[ebp].rgen_addr
	lea		esi,[eax+4]
	and		eax,3
	sub		esi,eax                                                                                   
	push	2
	call	[ebp].rgen_addr
	test	eax,eax
	jne		@F
	neg		esi
@@: 
	xchg	eax,esi
	stosb
	sub		ecx,4
	jmp		jxx_short_down
_cmpespret_:
	ret
;=================================[ CMP REG8/REG32,[ESP +(-) 0xXX] ]===================================== 





;=================================[ MOV/XCHG/LEA  REG8/REG32,[ADDRESS] ]=================================
mov_lea_addr:  									;����� �������������� � �������� ������������������ ������ 
	cmp		[ebp].beg_addr,0					;᭠砫� �஢�ਬ, � �㦭�� ��ࠬ���� �㫨? �᫨ ��, � ����� ����� ������� ������� �� ���� � ��室�� 				
	je		_mlaret_
	cmp		[ebp].end_addr,0
	je		_mlaret_
	mov		esi,[ebp].end_addr					;⠪�� �஢�ਬ, �⮡� ࠧ��� ����� ����訬 � ����訬 ���ᮬ �뫠 >=4 � 
	sub		esi,[ebp].beg_addr					;�⮡� ����� �뫮 ���짮������ �⨬ ���⮬ :) 
	sub		esi,4
	jc		_mlaret_
	cmp		ecx,6								;�᫨ �� ��, ⥯��� �஢�ਬ, ���� �� ���� � ���� (��� ��� ⠬) ��� ����� �⮩ �������? 
	jl		_mlaret_
;--------------------------------------------------------------------------------------------------------   
	push	2									;�᫨ � ��� �ப�⨫�, ����㯨� ;)! 
	call	[ebp].rgen_addr						;�������筮, ᬮ�� ��� 
	mov		edx,eax	
	add		eax,3
	push	eax;4
	call	[ebp].rgen_addr
	shl		eax,1 
	add		al,086h;087h
	add		al,dl
	stosb
	test	edx,edx
	jne		_mlar32_
	call	free_reg_r8
	jmp		@F
_mlar32_:
	call	free_reg
@@:	
	shl		eax,3
	add		al,5h
	stosb
	push	esi
	call	[ebp].rgen_addr
	add		eax,[ebp].beg_addr  
	stosd
	sub		ecx,6 
_mlaret_:
	ret
;=================================[ MOV/XCHG/LEA  REG8/REG32,[ADDRESS] ]=================================





;====================================[ CMP REG8/REG32,[ADDRESS] ]======================================== 
cmp_addr:										;����� �������������� � �������� ������������������ ������ 
	cmp		[ebp].end_addr,0					;����������, ������ ����! 				
	je		_cmpaddrret_
	cmp		[ebp].beg_addr,0
	je		_cmpaddrret_
	mov		esi,[ebp].end_addr
	sub		esi,[ebp].beg_addr  
	sub		esi,4
	jc		_cmpaddrret_	
	cmp		ecx,50+6+2
	jl		_cmpaddrret_
;--------------------------------------------------------------------------------------------------------
	push	4
	call	[ebp].rgen_addr
	add		al,38h
	stosb
	call	rnd_reg
	shl		eax,3
	add		al,05h
	stosb
	push	esi
	call	[ebp].rgen_addr
	add		eax,[ebp].beg_addr 
	stosd
	sub		ecx,6
	jmp		jxx_short_down
_cmpaddrret_:
	ret
;====================================[ CMP REG8/REG32,[ADDRESS] ]======================================== 





;=======================================[ FPU (x87) COMMAND ]============================================ 
fpux:											;��������� FPU ����������
	cmp		ecx,2
	jl		inc_dec_r32
	push	8
	call	[ebp].rgen_addr
	add		al,0D8h								;�� � ), ���� ᬮ�� � ���� �� �⨬ �������� + �⫠�稪 + ��-� �� 
	stosb
	cmp		al,0D8h
	je		_0xD8_0xDC_
	cmp		al,0DCh
	je		_0xD8_0xDC_ 
	cmp		al,0D9h
	je		_0xD9_0xDE_
	cmp		al,0DEh
	je		_0xD9_0xDE_
;--------------------------------------------------------------------------------------------------------
	push	20h
	call	[ebp].rgen_addr
	add		al,0C0h
	stosb
	jmp		_fpuxret_  
;--------------------------------------------------------------------------------------------------------
_0xD8_0xDC_:
	push	40h
	call	[ebp].rgen_addr
	add		al,0C0h
	stosb
	jmp		_fpuxret_
;--------------------------------------------------------------------------------------------------------
_0xD9_0xDE_:
	push	2
	call	[ebp].rgen_addr
	imul	eax,eax,3
	shl		eax,4
	xchg	eax,edx 	
	push	10h
	call	[ebp].rgen_addr
	add		eax,edx
	add		al,0C0h
	stosb
;--------------------------------------------------------------------------------------------------------		
_fpuxret_: 
	dec		ecx
	dec		ecx
	ret
;=======================================[ FPU (x87) COMMAND ]============================================ 





;==========================================[ MMX COMMAND ]=============================================== 
mmxx:											;��������� MMX ����������
	cmp		ecx,3								;�������筮, ᬮ�� ��� 
	jl		_mmxxret_
	mov		al,0Fh
	stosb
	push	2
	call	[ebp].rgen_addr
	test	eax,eax
	jne		_mmxx_opc_from_table_
	push	12;0Ch								;������� ������� �㤥� ⠪ �������
	call	[ebp].rgen_addr
	add		al,60h
	stosb
	jmp		@F		
;--------------------------------------------------------------------------------------------------------			
_mmxx_opc_from_table_:							;� ��㣨� (��� 㤮��⢠) �१ ⠡���� �� ���� 
	lea		esi,[ebx+(mmx_opcode - _delta_trash_)] 
	push	36
	call	[ebp].rgen_addr
	add		esi,eax
	movsb
;--------------------------------------------------------------------------------------------------------
@@: 
	call	free_reg							;�⮨� �⬥���, ��� ᢮����� (�� ��, � ᢮�����!) ॣ���� � �⫨稥 �� ��㣨� ������   
	add		al,0C0h								;� ��� (mmx) �⮨� �� ��㣮� ����
	xchg	eax,edx
	call	rnd_reg
	shl		eax,3 
	add		al,dl
	stosb
;-------------------------------------------------------------------------------------------------------- 
	sub		ecx,3
_mmxxret_:
	ret
;==========================================[ MMX COMMAND ]=============================================== 





;==========================================[ SSE COMMANDS ]==============================================
ssex:											;�������筮, ᬮ�� ��� 
	cmp		ecx,3
	jl		_ssexret_
	mov		al,0Fh
	stosb
	push	2
	call	[ebp].rgen_addr
	test	eax,eax
	jne		_ssex_opc_from_table_
	push	0Ah;0Ch
	call	[ebp].rgen_addr
	add		al,50h
	stosb
	jmp		@F		
;--------------------------------------------------------------------------------------------------------			

_ssex_opc_from_table_:
	lea		esi,[ebx+(sse_opcode - _delta_trash_)]	
	push	26
	call	[ebp].rgen_addr
	add		esi,eax        
	movsb
;-------------------------------------------------------------------------------------------------------- 
@@:
	call	free_reg
	shl		eax,3
	add		al,0C0h
	xchg	eax,edx
	call	rnd_reg
	add		al,dl
	stosb
;--------------------------------------------------------------------------------------------------------       	 
	sub		ecx,3
_ssexret_:
	ret
;==========================================[ SSE COMMANDS ]==============================================  





;===========================================[ SETX REG8 ]================================================
setx_r8:
	cmp		ecx,3
	jl		_setxret_
	mov		al,0Fh
	stosb
	push	16
	call	[ebp].rgen_addr						;��� 
	add		al,90h
	stosb
	call	free_reg_r8
	add		al,0C0h
	stosb 
	sub		ecx,3 
_setxret_:
	ret
;===========================================[ SETX REG8 ]================================================		 





;==============================[ PUSH EBP/MOV EBP,ESP (+ SUB ESP,XX) ]=================================== 
prolog1:
	cmp		ecx,6  
	jl		inc_dec_r32 
	mov		al,55h 
	stosb
	mov		ax,0EC8Bh
	stosw
	mov		ax,0EC83h
	stosw
	push	(60h - FOREBP)  
	call	[ebp].rgen_addr 
	lea		esi,[eax + FOREBP + 8] 
	and		eax,3
	sub		esi,eax
	xchg	eax,esi
	stosb                                                                                         
 	sub		ecx,6  
_prol1ret_: 
	ret
;==============================[ PUSH EBP/MOV EBP,ESP (+ SUB ESP,XX) ]=================================== 





;================================[ (MOV EBP,ESP/POP EBP) (LEAVE) ]=======================================   
epilog1:
	cmp		ecx,3
	jl		inc_dec_r32 
	dec		ecx    
	mov		ax,0E58Bh
	stosw
	mov		al,5Dh
	stosb 
	dec		ecx
	dec		ecx   
_epil1ret_: 
	ret 
;================================[ (MOV EBP,ESP/POP EBP) (LEAVE) ]=======================================  


                  


;========================[ MOV/XCHG/LEA REG8/REG32,[EBP +(-) 0xXX] ]===================================== 
mov_lea_ebp:									;����� �������������� � �������� ������������������ ������ 
												;�� ������� ����� ��ꥤ����� � ���� ⠪�� �� �㭪樥� (mo_lea_esp) 	
	cmp		ecx,3								;�஢�ઠ, ���� �� �� ��ਪ ������� � ��� �������?
	jl		_mlebpret_							;�᫨ �����, � ���� ���
	push	FOREBP								;���� ��稭��� �����஢��� ���� �� ���⮬ )
	call	[ebp].rgen_addr
	lea		esi,[eax+4]							;����砥� ��砩��� �᫮, ��⭮� 4
	and		eax,3
	sub		esi,eax
;--------------------------------------------------------------------------------------------------------	
	push	2									;����� ��砩�� ��।��塞, ������� � ����� ࠧ�來� (8 ��� 32) ॣ���஬ �������?
	call	[ebp].rgen_addr
	mov		edx,eax								;१��� ��࠭塞 � edx (1 - 32-ࠧ�來� ॣ����, ���� 8-ࠧ�來�)   	
	add		eax,3
	push	eax;4								;��᫥ ᬮ�ਬ, ����� ᬥ饭�� ������ ���� � ebp (�.�. [ebp+0xXX] ��� [ebp-0xXX])
	call	[ebp].rgen_addr						;���᭮, ��� ⠪�� ������ ��� ���ਬ�� xchg dword ptr [ebp+0x14],edx - ����� ������ +0x14, � ����� ⮫쪮 -0x14
	shl		eax,1								;���� ������� ����� ��� ��� ���祭�� � ��� 
	cmp		eax,3
	jl		@F
;--------------------------------------------------------------------------------------------------------
	push	eax
	push	2
	call	[ebp].rgen_addr						;� ��� ⠪�� ������ ��� lea edx,dword ptr [ebp+(-)0x14] - �롨ࠥ� ࠭����� ���� ��� ᬥ饭��, �.�. �� ஫� �� ��ࠥ� 
	test	eax,eax
	pop		eax
	jne		_mlebpnoneg_
@@:
	neg		esi									;� ���塞 ���� � ⮫쪮 �� ᣥ���஢������ ᬥ饭�� (�� �� 1 ����) 
;--------------------------------------------------------------------------------------------------------
_mlebpnoneg_:
	add		al,086h;087h						;�த������ ��ந�� � �����뢠�� �������
	add		al,dl
	stosb
	test	edx,edx
	jne		_mlebpr32_
	call	free_reg_r8
	jmp		@F
_mlebpr32_:
	call	free_reg
@@:	
	shl		eax,3
	add		al,45h 
	stosb
	xchg	eax,esi
	stosb
;--------------------------------------------------------------------------------------------------------
	sub		ecx,3 
_mlebpret_:
	ret
;========================[ MOV/XCHG/LEA REG8/REG32,[EBP +(-) 0xXX] ]=====================================  


                        


;=================================[ CMP REG8/REG32,[EBP +(-) 0xXX] ]===================================== 
cmp_ebp:										;����� �������������� � �������� ������������������ ������ 
												;�� ������� ����� ��ꥤ����� � ���� ⠪�� �� �㭪樥� (cmp_esp)	 
	cmp		ecx,50+3+2							;�஢��塞, ���� �� �� ���� ��� ����� ������ ������� (3 ����) 												
	jl		_cmpebpret_							;+ jxx short (2 byte) + ��� �⮣� ���室� ����� ���� (max 50 byte)   
	push	4									;�᫨ �� ⨯-⮯, � ��稭��� ������� � �����뢠�� 
	call	[ebp].rgen_addr
	add		al,38h
	stosb
	call	rnd_reg								;�������筮, ᬮ�� ��� 
	shl		eax,3
	add		al,45h 
	stosb
	push	FOREBP 
	call	[ebp].rgen_addr
	lea		esi,[eax+4]
	and		eax,3
	sub		esi,eax                                                                                   
	push	2
	call	[ebp].rgen_addr
	test	eax,eax
	jne		@F
	neg		esi
@@: 
	xchg	eax,esi
	stosb
	sub		ecx,3 
	jmp		jxx_short_down
_cmpebpret_:
	ret
;=================================[ CMP REG8/REG32,[EBP +(-) 0xXX] ]=====================================  





;=====================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG8/REG32,[EBP+(-) 0xXX] ]===========================               
add_sub_ebp:                              	          
	cmp		ecx,03h								;������� �� ?
	jl		_asebpret_                                        	                                                        
	push	FOREBP 
	call	[ebp].rgen_addr
	lea		esi,[eax+4]
	and		eax,3
	sub		esi,eax                                                                                                                       
    push	7;4									;����ਬ 㦥 ᠬ� �������
	call	[ebp].rgen_addr
	shl		eax,3;04h							;� ⠪�� �� �ᯥ宬 ����� �뫮 � ������ cmp, �� �� ���, ���⮬� �ய�᪠��  
	xchg	eax,edx
	push	4
	call	[ebp].rgen_addr
	add		al,dl
	stosb    
	xchg	eax,edx 
	test	dl,2  
	je		@F  
	push	2
	call	[ebp].rgen_addr
	test	eax,eax
	jne		_asebpnoneg_ 
@@: 
	neg		esi
_asebpnoneg_: 
	test	dl,1 
	je		@F 
	call	free_reg							;����砥� ᢮����� ॣ���� (32 ࠧ�鸞)
	jmp		_asebpregok_
@@: 
	call	free_reg_r8
_asebpregok_: 	         
	shl		al,03h                              
	add		al,45h                            
	stosb										;��堥� � ����
	xchg	eax,esi
	stosb 
	sub		ecx,3       
_asebpret_:
	ret
;=====================[ ADC/ADD/AND/OR/SBB/SUB/XOR REG8/REG32,[EBP+(-) 0xXX] ]===========================
 
 



;===============================[ CALL DWORD PTR [<address>] etc ]======================================= 
;--------------------------------------------------------------------------------------------------------
;�⮡� �뫠 ����������� ������� ����� ���誨, ���� �᪮������ ��� ����㭪�� 
;-------------------------------------------------------------------------------------------------------- 
fakeapi:										;������� ������ ���襪 
;comment !	 
	jmp		_genfakeapi_ 						;��뢠�� ������ ����㭪� ⮫쪮 ⮣��, ����� ������ ॣ����� �� EAX,ECX,EDX, � ��㣨� - ⠪ ��� ��᫥ �맮�� ���襪 ���祭�� ��� ॣ���஢ ����� ����������. ��� �ਤ㬠�� ��㣮� 
include		faka.asm							;������砥� ᯥ樠��� ����� ��� �⮣� 
_genfakeapi_:
	cmp		ecx,15 								;��易⥫쭮 ���४�஢��� �� ���祭��, �᫨ ����������� � �.�. ���� ����� ���誨 etc  
	jl		_fakeapiret_ 
	cmp		[ebp].mapped_addr,0					;�᫨ ������ ���� =0, � �� ��室  
	je		_fakeapiret_ 	 	
	xor		eax,eax 
	push	eax									;reserved1 
	push	eax									;api_va
	push	eax									;api_hash 
	push	edi									;buf_for_api
	push	[ebp].mapped_addr					;mapped_addr
	push	[ebp].rgen_addr						;rgen_addr 
	mov		edx,esp 
	assume	edx:ptr FAKEAPIGEN 		
	push	edx
	call	FAKA								;� ��뢠�� �㭪� �����樨 ������ ���襪 
	add		esp,6*4
	mov		edi,eax								;᪮�४��㥬 ���� ��� ����� ���쭥�襣� ����  
	sub		eax,[edx].buf_for_api				;㧭���, ᪮�쪮 ���� �� ⮫쪮 �� ����ᠫ� 
	sub		ecx,eax      						;᪮�४��㥬 
_fakeapiret_: 
		;! 	
	ret 
;===============================[ CALL DWORD PTR [<address>] etc ]=======================================

             




         
;========================================================================================================
;����� �� ���������� ������ 
;========================================================================================================

end_trash:										;��室�� �� �������
	pop 	eax                                    		                  
	mov		dword ptr [esp+1Ch],edi				;��࠭塞 � EAX ���祭�� EDI (����, �㤠 ����� �����뢠��) 
	popad
	ret		4                                         		
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 xTG
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx





comment %   	
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� swap_elem
;��६�訢���� ����⮢ � ���ᨢ� ��砩�� ��ࠧ�� 
;���� (stdcall) (swap_elem(DWORD *pMas,DWORD num_elem)):
;	pMas     - ���ᨢ, ������ ���ண� � ���� ��६���� ��砩�� ��ࠧ��; 
;	num_elem - ������⢮ ����⮢ � ���ᨢ�;
;�����:
;	(+) ������ �⫨筮 ��६�蠭�; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  
swap_elem:
	pushad
	mov		ecx,dword ptr [esp+28h]
	mov		esi,dword ptr [esp+24h]
	xor		edx,edx
_cycleswap_: 
	push	ecx
	call	[ebp].rgen_addr  
	push	dword ptr [esi+edx*4]
	push	dword ptr [esi+eax*4]
	pop		dword ptr [esi+edx*4]
	pop		dword ptr [esi+eax*4]
	inc		edx
	cmp		edx,ecx
	jne		_cycleswap_
	popad
	ret		4*2
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 swap_elem 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
		;%  





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� free_reg
;������� ᢮������� ॣ���� (32-� ࠧ�來��� �� ��䮫��) 
;��室:
;eax (al) - ����� ᢮������� ॣ����
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
free_reg:
	push	edx
	mov		edx,[ebp].regs						;� EDX ��࠭塞 ॣ����� ������ 
_getfr_:	                                     		
	call 	rnd_reg								;��뢠�� �㭪� �����樨 ��� ॣ����                              		
	cmp 	al,dh								;ᬮ�ਬ, ��� ॣ���� 㦥 ����� (���ਬ�� ���ਯ�஬)                                  		
	je 		_getfr_                                   	
	cmp 	al,dl								;�� ���� ⠪�� �஢�ઠ                                  		
	je 		_getfr_                                   	
	cmp 	al,4;esp							;⠪�� ����祭�� ⮫쪮 �� ॣ���� �� ������ ���� ESP & EBP                                		
	je 		_getfr_                                   	
	cmp 	al,5;ebp                                   		
	je 		_getfr_
	bt		edx,31								;⠪�� �஢��塞, ������ 2 (��� ���ਯ��) ��� 3 ॣ����? (3-�� ��� �����樨 �������� ������/�������権) 
	jnc		_frret_								;�� �� ������� ᬮ�� ��� 
	push	edx
	shr		edx,16
	cmp		al,dl								;�᫨ �� ������ 3 ॣ����, � �஢��塞 �� � ���, ⮫쪮 �� ����祭�� ॣ���� �����?
	pop		edx 
	je		_getfr_
_frret_:										;�᫨ ���, � � EAX ��� ॣ���� � ��室�� 	                                 	
	pop		edx
	ret                                        		
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 free_reg
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx







;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� rnd_reg
;������� ��砩���� ॣ����
;��室:
;eax (al) - ����� ��砩���� ॣ����
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
rnd_reg:                                          		
	push	8                                  		
	call	[ebp].rgen_addr						;��뢠�� ���                              		
	ret                                        		
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 rnd_reg
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 







;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� free_reg_r8
;������� ᢮������� ॣ���� (8-�� ࠧ�來���) 
;�����:
;EAX (al) - ����� ᢮������� ॣ����
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
free_reg_r8:
	push	ebx
	mov		ebx,[ebp].regs
_getfr8_:
	call	rnd_reg								;�������筮, ᬮ�� ��� 
	mov		dl,al
	cmp		al,4								;ᬮ�ਬ, al>=4 ? �᫨ ��, � ���⠥� 4. ��� �㦭� ��⮬� ���� ⮫쪮 al,cl,dl,bl,ah,ch,dh,bh
	jl		_al_etc_							;� ���ਬ�� al & ah - ����� ����� 0 � 4 ᮮ⢥��⢥��� � ����� ����� ������ ����讣� ॣ���� EAX (AX) 
	sub		dl,4
_al_etc_:
	cmp		dl,bh
	je		_getfr8_
	cmp		dl,bl
	je		_getfr8_
	bt		ebx,31
	jnc		_frr8ret_
	push	ebx
	shr		ebx,16
	cmp		dl,bl
	pop		ebx 
	je		_getfr8_  

_frr8ret_:
	pop		ebx 
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 free_reg_r8 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	









                          	
	                                       

;========================================================================================================			                           
;ETC 
;========================================================================================================
one_byte_opcode:								;⠡��窠 ��� ����஥��� �������⮢�� ������ 
	std                               
	cld                                
	nop                                
	clc                                			
	stc                                			
	cmc                                			
	db	0f2h									;rep
	db	0f3h									;repnz
	aaa
	aas
	cwde
	daa
	das
	lahf
;========================================================================================================
three_byte_opcode:								;⠡��窠 ��� ����஥��� ��塠�⮢�� ������ 
	db	002h,003h,0a3h,0a5h,0abh,0adh,0afh,0b3h 
	db	0b6h,0b7h,0bbh,0bch,0bdh,0beh,0bfh,0c1h 		 
;========================================================================================================
mmx_opcode:										;⠡��窠 ��� ����஥��� MMX ������ 
	db	06Eh,06Fh,074h,075h,076h,07Eh,07Fh,0D1h,0D2h
	db	0D3h,0D5h,0D8h,0D9h,0DBh,0DCh,0DDh,0DFh,0E1h
	db	0E2h,0E5h,0E8h,0E9h,0EBh,0ECh,0EDh,0EFh,0F1h
	db	0F2h,0F3h,0F5h,0F8h,0F9h,0FAh,0FCh,0FDh,0FEh
;========================================================================================================
sse_opcode:										;⠡��窠 ��� ����஥��� SSE ������ 
	db	010h,011h,012h,014h,015h,016h,028h,029h,02Ah,02Ch,02Dh,02Eh,02Fh
	db	05Ch,05Dh,05Eh,05Fh,0D7h,0DAh,0DEh,0E0h,0E3h,0E4h,0EAh,0EEh,0F6h 
;========================================================================================================







;========================================================================================================
;��� �������� :)! 
;======================================================================================================== 
SizeTrash			equ		$-xTG				;ࠧ��� ������� ����
;======================================================================================================== 

;��� ᨫ�� - ᫠�� �ᥣ�� �� �����!
