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
;                                   Версия 1.1					   ;                                                
;                                                                                  ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;функция LiTo                                                                      ;
;определение длины машинной команды                                                ;
;Вход:                                                                             ;
;esi - адрес разбираемой машинной команды                                          ;
;Выход:                                                                            ;
;в eax - длина машинной команды.                                                   ;
;Заметки:                                                                          ;
;(х) понимаются (пока) только general purpose & fpu instructions                   ;
;    (остальные - в топку:)!                                                       ;
;(х) нет проверки на максимальную длину инструкции (15 байт) (нахрен)              ;
;(х) Как построены эти таблички:                                                   ;
;	ОЧЕНЬ ПРОСТО: так как в этом дизасме длин используются флаги с числовым    ;
;	обозначением <=8, то для одного флага достаточно места в половину байта    ;
;	(максимальное число =8 (B_PREFIX6X) - в двоичном представлении =1000b).    ;
;	Зная это, просто тупо в один байт запихиваем 2 флага - вот и все. Таким    ;
;	образом, каждая табличка в 256 байт урезается до 128.                      ;                            
;(х) Для 32-битного исполняемого кода.						   ;
;(х) Кто хочет, пусть нафиг сам и добавляет остальные команды и всякие там         ;
;    проверки.                                                                     ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				ФИЧИ:                                              ;
;(+) базонезависимость								   ;
;(+) упакованные таблички							   ;                                           
;                                                                                  ;
;(-) смотри выше								   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				ИСПОЛЬЗОВАНИЕ:                                     ;
;1)Подключение:                                                                    ;
;	lito.asm                                                                   ;
;2)Вызов:(пример)                                                                  ;
;	lea	esi,XXXXXXXXh	;адрес команды, чью длину надо узнать		   ;              
;	call	LiTo                                                               ;                                                                                                                  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   
;размер движка = xxx байт 

									;m1x
							           ;pr0mix@mail.ru	

LiTo:
	pushad
	call	_delta_lito_
;===================================================================================

;строка префиксов
pfx:
db 66h,67h,2Eh,36h,3Eh,26h,64h,65h,0F2h,0F3h,0F0h

SizePfx		equ $-pfx					;длина pfx

;===================================================================================

;таблциа флагов для однобайтных опкодов
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

;таблциа флагов для двухбайтных опкодов
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
;флаги
;-----------------------------------------------------------------------------------
B_NONE		equ	00h					;
B_MODRM		equ	01h                                     ;присутствие байта MODRM
B_DATA8		equ	02h                                     ;присутствие байта imm8,rel8, etc
B_DATA16	equ	04h                                     ;присутствие байта imm16,rel16, etc
B_PREFIX6X	equ	08h                                     ;в команде imm16/imm32 (или/или)
B_RELX		equ	10h                                     ;здесь не используется
;===================================================================================

_delta_lito_:
	pop	ebp
	cld
	xor	eax,eax
	cdq				        		;в edx: dl(0/1) - нет/есть префикс 0x66
	                                                        ;	dh(0/1) - нет/есть префикс 0x67
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG поиск префиксовxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_nextpfx_:					
	lodsb                                			;получаем очередной байт команды
	lea	edi,[ebp+(pfx-_delta_lito_+SizeTbl)]            ;в edi - адрес строки префиксов
	db	6Ah,SizePfx
	pop	ecx
	repne	scasb                                           ;есть ли в разбираемой команде префиксы?
	jne	_endpfx_                                        ;нет? - на выход
	sub	al,66h                                          ;иначе смотрим, это 0x66?
	jne	_67_
	mov	dl,1                                            ;если да, то устанавливаем dl=1
_67_:
	dec	al                                             	;иначе, это 0x67?
	jnz	_nextpfx_                                       ;если нет, то ищем другие префиксы
	mov	dh,1                                            ;иначе dh=1
	jmp	_nextpfx_                                       ;продолжаем поиск
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND поиск префиксовxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endpfx_:	
	cmp	al,0Fh                                        	;опкод состоит из 2-х байт?
	jne	_opcode_
	lodsb                                                   ;если да, то берем 2-ой байт опкода
	mov	cl,80h                                          ;и увеличиваем cl=80h
;-----------------------------------------------------------------------------------
_opcode_:
	lea	edi,[ebp+ecx+(TableFlags1-_delta_lito_+SizeTbl)];в edi - адрес нужной таблицы флагов(хар-к)
	cmp	al,0A0h                                         ;если опкод>=0xA0 и опкод<=A3,
	jl	_01_;jb                                            ;
	cmp	al,0A3h
	jg	_01_
	test	cl,cl
	jne	_01_;je                                 	;то dl=dh
	mov	dl,dh						;mov	dl,dh
;-----------------------------------------------------------------------------------
_01_:
	mov	ebx,eax                           		;иначе bl=opcode
	shr	eax,1
	mov	cl,byte ptr [edi+eax]				;в cl - флаги команды
	jc	_noCF_
	shr	cl,4
_noCF_:
        and	cl,0Fh
	xor	ebp,ebp				        	;в ebp - будет храниться длина смещения(offset)

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG разбор MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

	test	cl,B_MODRM                                      ;присутствует ли байт modrm?
	je	_endmodrm_                                      ;нет? на выход
	lodsb                 	  				;al=modrm
	mov	ah,al
;-----------------------------------------------------------------------------------
	shr	ah,6   						;ah=mod
;-----------------------------------------------------------------------------------	
        test	al,38h                                          ;далее смотрим, равно ли поле reg==0?    					
	jne	_03_
	sub	bl,0F6h;sub bl,0F6h                             ;если да, то смотрим на опкод:
	jne	_02_                                            ;равен ли он 0xF6 или 0xF7(test)?
	or	cl,B_DATA8                                      ;если да, то устанавливаем нужный флаг
_02_:
	dec	ebx
	jne	_03_
	or	cl,B_PREFIX6X
;-----------------------------------------------------------------------------------	
_03_:
	and	al,7                                            ;al = rm
	mov	bl,byte ptr[esi]                                ;bl=sib
	mov	ch,ah                           		;ch=mod

	xor	edi,edi                                         ;edi отвечает за присутствие байта sib
	cmp	dh,1                            		;есть ли в разбираемой команде префикс 0x67?
	je	_mod00_                                         ;если да, то перескакиваем
	cmp	al,4                                            ;иначе проверяем,равно ли поле rm==4?
	jne	_mod00_
	inc	edi                                             ;если да, то возможно есть sib
;-----------------------------------------------------------------------------------
_mod00_:
	test	ah,ah                                           ;поле mod==0?
	jne	_mod01_
	dec	dh						;содержит ли команда 0x67?
	jne	_nop67_	                                        ;нет? перескакиваем
	cmp	al,6                                            ;если да, то rm==6?
	jne	_sib_
	inc	esi                                             ;если да, то длина смещения=2(16 bit)
	inc	esi
_nop67_:
	cmp	al,5                                            ;иначе, rm==5?
	jne	_sib_
	lodsd                                                   ;если да, то длина оффсета=4 (32 bit)                                           
	jmp	_sib_                                           ;идем дальше
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
	dec	dh                                              ;если нет префикса 0x67,
	je	_sib_
	inc	esi
	inc	esi          	
	inc	edi
;-----------------------------------------------------------------------------------
_mod03_:                                                        ;mod==3?
        dec	edi                                             ;если да, тогда sib'а точно нет!
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND разбор MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG получение SIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_sib_:
        xchg	eax,ebx
	dec	edi                                             ;есть ли байт sib?
	jne	_endmodrm_
	inc	esi                                             ;если да, то в al теперь лежит sib(al=sib)                                                    
	and	al,7                                            ;далее, 
	cmp	al,5                                            ;al==5?
	jne	_endmodrm_
	test	ch,ch                                           ;если да, то смотрим, поле mod==0?
	jne	_endmodrm_
	lodsd                                                   ;если да, то есть 4-байтовое смещение
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND получение SIBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG флагиxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

_endmodrm_:
	test	cl,B_DATA8+B_DATA16+B_PREFIX6X                  ;
	je	_endflag_
	dec	ecx
	dec	ecx
	inc	esi;lodsb
	dec	dl
	jne	_endmodrm_                                      ;если есть 0x66
	sub	ecx,4
	jmp	_endmodrm_

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND флагиxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endflag_:	
	sub	esi,dword ptr [esp+4];eax
	mov	dword ptr [esp+7*4],esi                         ;сохраняем размер в еах
	popad
	ret	                                               	;выходим:)
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;Конец функции LiTo
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx


SizeOfLiTo	equ $-LiTo					;размер движка  
