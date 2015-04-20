;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;                                                                                  ;
;                                                                                  ;
;                                                                      ###         ;
;                                                                        ###       ;
;             ###        ####################################################      ;
;             ###        ####################################################      ;
;             ###                      	 ###                             ###       ;
;             ###             ###    	 ###           #########       ###         ;
;             ###             ###    	 ###          ###########                  ;
;             ###                    	 ###         ##         ##                 ;
;             ###             ###    	 ###         ##         ##                 ;
;             ###             ###    	 ###         ##         ##                 ;
;             ###      ###    ###    	 ###         ##         ##                 ;
;             ###      ###    ###    	 ###         ##         ##                 ;
;             ############    ###    	 ###          ###########                  ;
;             ############    ###    	 ###           #########                   ;
;                                                                                  ;
;                                                                                  ;                                                                          
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;                                                                                  ;
;             			Length dIsassembler moTOr:)                        ;                  
;                                                                                  ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;                                                                                  ; 
;                                   ����� 1.1					   ;                                                
;                                                                                  ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;�㭪�� LiTo                                                                      ;
;��।������ ����� ��設��� �������                                                ;
;�室:                                                                             ;
;esi - ���� ࠧ��ࠥ��� ��設��� �������                                          ;
;��室:                                                                            ;
;� eax - ����� ��設��� �������.                                                   ;
;����⪨:                                                                          ;
;(�) ���������� (����) ⮫쪮 general purpose & fpu instructions                   ;
;    (��⠫�� - � ⮯��:)!                                                       ;
;(�) ��� �஢�ન �� ���ᨬ����� ����� ������樨 (15 ����) (���७)              ;
;(�) ��� ����஥�� �� ⠡��窨:                                                   ;
;	����� ������: ⠪ ��� � �⮬ ����ᬥ ���� �ᯮ������� 䫠�� � �᫮��    ;
;	������祭��� <=8, � ��� ������ 䫠�� �����筮 ���� � �������� ����    ;
;	(���ᨬ��쭮� �᫮ =8 (B_PREFIX6X) - � ����筮� �।�⠢����� =1000b).    ;
;	���� ��, ���� �㯮 � ���� ���� ����娢��� 2 䫠�� - ��� � ��. �����    ;
;	��ࠧ��, ������ ⠡��窠 � 256 ���� �१����� �� 128.                      ;                            
;(�) ��� 32-��⭮�� �ᯮ��塞��� ����.						   ;
;(�) �� ���, ����� ��䨣 ᠬ � �������� ��⠫�� ������� � ��直� ⠬         ;
;    �஢�ન.                                                                     ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				����:                                              ;
;(+) ����������ᨬ����								   ;
;(+) 㯠������� ⠡��窨							   ;                                           
;                                                                                  ;
;(-) ᬮ�� ���								   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				�������������:                                     ;
;1)������祭��:                                                                    ;
;	lito.asm                                                                   ;
;2)�맮�:(�ਬ��)                                                                  ;
;	lea	esi,XXXXXXXXh	;���� �������, ��� ����� ���� 㧭���		   ;              
;	call	LiTo                                                               ;                                                                                                                  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   
;ࠧ��� ������ = xxx ���� 

									;m1x
							           ;pr0mix@mail.ru	

LiTo:
	pushad
	call	_delta_lito_
;===================================================================================

;��ப� ��䨪ᮢ
pfx:
db 66h,67h,2Eh,36h,3Eh,26h,64h,65h,0F2h,0F3h,0F0h

SizePfx		equ $-pfx					;����� pfx

;===================================================================================

;⠡�樠 䫠��� ��� ���������� �������
TableFlags1:

;  01  23  45  67  89  AB  CD  EF
db 11h,11h,28h,00h,11h,11h,28h,00h	;00
db 11h,11h,28h,00h,11h,11h,28h,00h      ;01
db 11h,11h,28h,00h,11h,11h,28h,00h      ;02
db 11h,11h,28h,00h,11h,11h,28h,00h      ;03
db 00h,00h,00h,00h,00h,00h,00h,00h	;04
db 00h,00h,00h,00h,00h,00h,00h,00h	;05
db 00h,11h,00h,00h,89h,23h,00h,00h	;06
db 22h,22h,22h,22h,22h,22h,22h,22h	;07
db 39h,33h,11h,11h,11h,11h,11h,11h	;08
db 00h,00h,00h,00h,00h,0C0h,00h,00h	;09
db 88h,88h,00h,00h,28h,00h,00h,00h	;0A
db 22h,22h,22h,22h,88h,88h,88h,88h	;0B
db 33h,40h,11h,39h,60h,40h,02h,00h	;0C
db 11h,11h,22h,00h,11h,11h,11h,11h	;0D
db 22h,22h,22h,22h,88h,0C2h,00h,00h	;0E
db 00h,00h,00h,11h,00h,00h,00h,11h	;0F


;===================================================================================

;⠡�樠 䫠��� ��� ���塠���� �������
TableFlags2:

;  01  23  45  67  89  AB  CD  EF
db 11h,11h,00h,00h,00h,00h,01h,00h	;00
db 00h,00h,00h,00h,00h,00h,00h,01h	;01
db 11h,11h,00h,00h,00h,00h,00h,00h	;02
db 00h,00h,00h,00h,00h,00h,00h,00h	;03
db 11h,11h,11h,11h,11h,11h,11h,11h	;04
db 00h,00h,00h,00h,00h,00h,00h,00h	;05
db 00h,00h,00h,00h,00h,00h,00h,00h	;06
db 00h,00h,00h,00h,00h,00h,00h,00h	;07
db 88h,88h,88h,88h,88h,88h,88h,88h	;08
db 11h,11h,11h,11h,11h,11h,11h,11h	;09
db 00h,01h,31h,00h,00h,01h,31h,01h	;0A
db 11h,11h,11h,11h,00h,31h,11h,11h	;0B
db 11h,00h,00h,01h,00h,00h,00h,00h	;0C
db 00h,00h,00h,00h,00h,00h,00h,00h	;0D
db 00h,00h,00h,00h,00h,00h,00h,00h	;0E
db 00h,00h,00h,00h,00h,00h,00h,00h	;0F   
;===================================================================================

SizeTbl		equ $-pfx
;===================================================================================
;䫠��
;-----------------------------------------------------------------------------------
B_NONE		equ	00h					;
B_MODRM		equ	01h                                     ;������⢨� ���� MODRM
B_DATA8		equ	02h                                     ;������⢨� ���� imm8,rel8, etc
B_DATA16	equ	04h                                     ;������⢨� ���� imm16,rel16, etc
B_PREFIX6X	equ	08h                                     ;� ������� imm16/imm32 (���/���)
B_RELX		equ	10h                                     ;����� �� �ᯮ������
;===================================================================================

_delta_lito_:
	pop	ebp
	cld
	xor	eax,eax
	cdq				        		;� edx: dl(0/1) - ���/���� ��䨪� 0x66
	                                                        ;	dh(0/1) - ���/���� ��䨪� 0x67
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG ���� ��䨪ᮢxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_nextpfx_:					
	lodsb                                			;����砥� ��।��� ���� �������
	lea	edi,[ebp+(pfx-_delta_lito_+SizeTbl)]            ;� edi - ���� ��ப� ��䨪ᮢ
	db	6Ah,SizePfx
	pop	ecx
	repne	scasb                                           ;���� �� � ࠧ��ࠥ��� ������� ��䨪��?
	jne	_endpfx_                                        ;���? - �� ��室
	sub	al,66h                                          ;���� ᬮ�ਬ, �� 0x66?
	jne	_67_
	mov	dl,1                                            ;�᫨ ��, � ��⠭�������� dl=1
_67_:
	dec	al                                             	;����, �� 0x67?
	jnz	_nextpfx_                                       ;�᫨ ���, � �饬 ��㣨� ��䨪��
	mov	dh,1                                            ;���� dh=1
	jmp	_nextpfx_                                       ;�த������ ����
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND ���� ��䨪ᮢxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endpfx_:	
	cmp	al,0Fh                                        	;����� ��⮨� �� 2-� ����?
	jne	_opcode_
	lodsb                                                   ;�᫨ ��, � ��६ 2-�� ���� ������
	mov	cl,80h                                          ;� 㢥��稢��� cl=80h
;-----------------------------------------------------------------------------------
_opcode_:
	lea	edi,[ebp+ecx+(TableFlags1-_delta_lito_+SizeTbl)];� edi - ���� �㦭�� ⠡���� 䫠���(��-�)
	cmp	al,0A0h                                         ;�᫨ �����>=0xA0 � �����<=A3,
	jl	_01_;jb                                            ;
	cmp	al,0A3h
	jg	_01_
	test	cl,cl
	jne	_01_;je                                 	;� dl=dh
	mov	dl,dh						;mov	dl,dh
;-----------------------------------------------------------------------------------
_01_:
	mov	ebx,eax                           		;���� bl=opcode
	shr	eax,1
	mov	cl,byte ptr [edi+eax]				;� cl - 䫠�� �������
	jc	_noCF_
	shr	cl,4
_noCF_:
        and	cl,0Fh
	xor	ebp,ebp				        	;� ebp - �㤥� �࠭����� ����� ᬥ饭��(offset)

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG ࠧ��� MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

	test	cl,B_MODRM                                      ;��������� �� ���� modrm?
	je	_endmodrm_                                      ;���? �� ��室
	lodsb                 	  				;al=modrm
	mov	ah,al
;-----------------------------------------------------------------------------------
	shr	ah,6   						;ah=mod
;-----------------------------------------------------------------------------------	
        test	al,38h                                          ;����� ᬮ�ਬ, ࠢ�� �� ���� reg==0?    					
	jne	_03_
	sub	bl,0F6h;sub bl,0F6h                             ;�᫨ ��, � ᬮ�ਬ �� �����:
	jne	_02_                                            ;ࠢ�� �� �� 0xF6 ��� 0xF7(test)?
	or	cl,B_DATA8                                      ;�᫨ ��, � ��⠭�������� �㦭� 䫠�
_02_:
	dec	ebx
	jne	_03_
	or	cl,B_PREFIX6X
;-----------------------------------------------------------------------------------	
_03_:
	and	al,7                                            ;al = rm
	mov	bl,byte ptr[esi]                                ;bl=sib
	mov	ch,ah                           		;ch=mod

	xor	edi,edi                                         ;edi �⢥砥� �� ������⢨� ���� sib
	cmp	dh,1                            		;���� �� � ࠧ��ࠥ��� ������� ��䨪� 0x67?
	je	_mod00_                                         ;�᫨ ��, � ���᪠������
	cmp	al,4                                            ;���� �஢��塞,ࠢ�� �� ���� rm==4?
	jne	_mod00_
	inc	edi                                             ;�᫨ ��, � �������� ���� sib
;-----------------------------------------------------------------------------------
_mod00_:
	test	ah,ah                                           ;���� mod==0?
	jne	_mod01_
	dec	dh						;ᮤ�ন� �� ������� 0x67?
	jne	_nop67_	                                        ;���? ���᪠������
	cmp	al,6                                            ;�᫨ ��, � rm==6?
	jne	_sib_
	inc	esi                                             ;�᫨ ��, � ����� ᬥ饭��=2(16 bit)
	inc	esi
_nop67_:
	cmp	al,5                                            ;����, rm==5?
	jne	_sib_
	lodsd                                                   ;�᫨ ��, � ����� �����=4 (32 bit)                                           
	jmp	_sib_                                           ;���� �����
;-----------------------------------------------------------------------------------		
_mod01_:		                                        ;mod==1?
	dec	ah                                              
	jne	_mod02_
	inc	esi
	jmp	_sib_		
;-----------------------------------------------------------------------------------	                        
_mod02_:                                    			;mod==2?
	dec	ah
	jne	_mod03_
	inc	esi
	inc	esi
	dec	dh                                              ;�᫨ ��� ��䨪� 0x67,
	je	_sib_
	inc	esi
	inc	esi          	
	inc	edi
;-----------------------------------------------------------------------------------
_mod03_:                                                        ;mod==3?
        dec	edi                                             ;�᫨ ��, ⮣�� sib'� �筮 ���!
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND ࠧ��� MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG ����祭�� SIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_sib_:
        xchg	eax,ebx
	dec	edi                                             ;���� �� ���� sib?
	jne	_endmodrm_
	inc	esi                                             ;�᫨ ��, � � al ⥯��� ����� sib(al=sib)                                                    
	and	al,7                                            ;�����, 
	cmp	al,5                                            ;al==5?
	jne	_endmodrm_
	test	ch,ch                                           ;�᫨ ��, � ᬮ�ਬ, ���� mod==0?
	jne	_endmodrm_
	lodsd                                                   ;�᫨ ��, � ���� 4-���⮢�� ᬥ饭��
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND ����祭�� SIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG 䫠��xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

_endmodrm_:
	test	cl,B_DATA8+B_DATA16+B_PREFIX6X                  ;
	je	_endflag_
	dec	ecx
	dec	ecx
	inc	esi;lodsb
	dec	dl
	jne	_endmodrm_                                      ;�᫨ ���� 0x66
	sub	ecx,4
	jmp	_endmodrm_

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND 䫠��xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endflag_:	
	sub	esi,dword ptr [esp+4];eax
	mov	dword ptr [esp+7*4],esi                         ;��࠭塞 ࠧ��� � ���
	popad
	ret	                                               	;��室��:)
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 LiTo
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx


SizeOfLiTo	equ $-LiTo					;ࠧ��� ������  
