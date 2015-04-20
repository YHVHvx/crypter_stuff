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
;                                 ����� 1.3					   ;                                                 
;                                                                                  ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;�㭪�� LiTo                                                                      ;
;��।������ ����� ��設��� �������                                                ;
;�室:                                                                             ;
;esi - ���� �������, ��� ����� ���� 㧭���					   ;
;��室:                                                                            ;
;� eax - ����� ��設��� �������.                                                   ;
;����⪨:                                                                          ;
;(�) ���������� (����) ⮫쪮 general purpose & fpu instructions                   ;
;    (��⠫�� - � ⮯��:)!                                                       ;
;(�) ��� �஢�ન �� ���ᨬ����� ����� ������樨 (15 ����) (���७)              ;
;(�) ��� 㯠������ �� ⠡��窨:                                                   ;
;    	����� ⠪, ᬮ�ਬ �� ���� ���� TableFlags1 = 0x41. ��ࢠ� ��� (4)    ;
;	����砥�, ᪮�쪮 ����������� 䫠��� ���� �����. � ���� (1) -         ;
;	ᮡ�⢥���, �� �� �� 䫠� (��� ������� �ਬ�� - �� B_MODRM). � �.�.    ;
;(�) ��� 32-��⭮�� �ᯮ��塞��� ����.						   ;
;(�) ����� ����� ���� �� ����ᠭ � 楫�� ���⮫����� ��᫥����⥫�� ��          ;
;    ���� ���� �� ᮧ����� ᢮��� ����ᬠ.                                        ;           
;                                                                                  ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				����:                                              ;
;(+) ����������ᨬ����								   ;
;(+) 㯠������� ⠡��窨							   ;                                           
;                                                                                  ;
;(-) ���୮ ��������� ���� ������樨						   ;                                                                                                                                                   
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				�������������:                                     ;
;1)������祭��:                                                                    ;
;	lito.asm                                                                   ;
;2)�맮�:(�ਬ��)                                                                  ;
;	lea	esi,XXXXXXXXh	;���� �������, ��� ����� ���� 㧭���              ;
;	call	LiTo                                                               ;                                                                                                                  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;ࠧ��� �ᥣ� ����ᬠ (����� � ⠡��窠��) = 334 ����                                                                                   

									;m1x
							           ;pr0mix@mail.ru	

;===================================================================================

LiTo:
	pushad
	call	_delta_lito_

;===================================================================================

;⠡�樠 䫠��� ��� ���������� �������
TableFlags1:

db 041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h
db 041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h
db 0F0h,0F0h,040h,021h,040h,018h,019h,012h,013h,040h,0F2h,012h,013h,019h,023h,0C1h
db 0A0h,01Ch,050h,048h,040h,012h,018h,060h,082h,088h,023h,014h,010h,021h,013h,019h
db 016h,010h,014h,020h,012h,020h,041h,022h,020h,081h,082h,028h,01Ch,012h,0A0h,021h
db 060h,021h
;===================================================================================

;⠡�樠 䫠��� ��� ���塠���� �������
TableFlags2:

db 041h,090h,011h,0F0h,020h,051h,0F0h,0D0h,0F1h,011h,0F0h,0F0h,0F0h,030h,0F8h,018h
db 0F1h,011h,030h,011h,013h,011h,050h,011h,013h,011h,010h,091h,020h,013h,071h,050h
db 011h,0F0h;,0F0h,0F0h,0B0h 

;===================================================================================

;��ப� ��䨪ᮢ
pfx:
db 2Eh,36h,3Eh,26h,64h,65h,0F2h,0F3h,0F0h,67h,66h

SizePfx		equ $-pfx					;����� pfx
SizeTbl		equ $-TableFlags1
;===================================================================================
;䫠��
;-----------------------------------------------------------------------------------
B_NONE		equ	00h
B_MODRM		equ	01h
B_DATA8		equ	02h
B_DATA16	equ	04h
B_PREFIX6X	equ	08h
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
	test	ecx,ecx                                         ;���� ᬮ�ਬ, �� 0x66?                                          
	jne	_67_
	mov	dl,1                                            ;�᫨ ��, � ��⠭�������� dl=1
_67_:
	dec	ecx                                             ;����, �� 0x67?
	jne	_nextpfx_                                       ;�᫨ ���, � �饬 ��㣨� ��䨪��
	mov	dh,1                                            ;���� dh=1
	jmp	_nextpfx_                                       ;�த������ ����
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND ���� ��䨪ᮢxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endpfx_:	
	cmp	al,0Fh                                        	;����� ��⮨� �� 2-� ����?
	jne	_opcode_
	lodsb                                                   ;�᫨ ��, � ��६ 2-�� ���� ������
	mov	cl,82                                           ;� 㢥��稢��� cl=82
;-----------------------------------------------------------------------------------
_opcode_:
	lea	edi,[ebp+ecx+(TableFlags1-_delta_lito_+SizeTbl)];� edi - ���� �㦭�� ⠡���� 䫠���(��-�)
	mov	ch,al						;ch=opcode

	test	cl,cl
				                         	;� ����� ��⮨� �� ������ ����,
	jne	_01_;je                                 	;� dl=dh

	and	al,0FCh
	cmp	al,0A0h
	jne	_01_                                            ;�᫨ �����>=0xA0 � �����<=A3,
	mov	dl,dh
;-----------------------------------------------------------------------------------
_01_:
	xor	ebx,ebx
	dec	ebx 						;����室��� =-1 ��� ���४⭮� ࠡ��� (���� ᬮ�� ����:)!
_nxtf_:
	mov	al,byte ptr [edi]
	inc	edi
	db	0D4h,10h					;AAM 10h
	add	bl,ah
	cmp	bl,ch
	jb	_nxtf_
	mov	cl,al                                           ;cl - ᮤ�ন� ⥯��� 䫠�� (�ࠪ���⨪�)

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG ࠧ��� MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

	test	al,B_MODRM                                      ;��������� �� ���� modrm?
	je	_endmodrm_                                      ;���? �� ��室
	lodsb                 	  				;al=modrm
	mov	ah,al
;-----------------------------------------------------------------------------------
	shr	ah,6   						;ah=mod
;-----------------------------------------------------------------------------------	
        test	al,38h                                          ;����� ᬮ�ਬ, ࠢ�� �� ���� reg==0?    					
	jne	_03_
	sub	ch,0F6h                                         ;�᫨ ��, � ᬮ�ਬ �� �����:
	jne	_02_                                            ;ࠢ�� �� �� 0xF6 ��� 0xF7(test)?
	or	cl,B_DATA8                                      ;�᫨ ��, � ��⠭�������� �㦭� 䫠�
_02_:
	dec	ch
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
	lodsb
	jmp	_sib_		
;-----------------------------------------------------------------------------------	                        
_mod02_:                                    			;mod==2?
	dec	ah
	jne	_mod03_
	lodsw
	dec	dh                                              ;�᫨ ��� ��䨪� 0x67,
	je	_sib_
	lodsw          	
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
	lodsb
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


SizeOfLiTo	equ $-LiTo					;ࠧ��� �㭪樨 LiTo
