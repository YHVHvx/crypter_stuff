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
;                                 Версия 1.3					   ;                                                 
;                                                                                  ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;функция LiTo                                                                      ;
;определение длины машинной команды                                                ;
;Вход:                                                                             ;
;esi - адрес команды, чью длину надо узнать					   ;
;Выход:                                                                            ;
;в eax - длина машинной команды.                                                   ;
;Заметки:                                                                          ;
;(х) понимаются (пока) только general purpose & fpu instructions                   ;
;    (остальные - в топку:)!                                                       ;
;(х) нет проверки на максимальную длину инструкции (15 байт) (нахрен)              ;
;(х) Как упакованы эти таблички:                                                   ;
;    	Значит так, смотрим на первый байт TableFlags1 = 0x41. Первая цифра (4)    ;
;	означает, сколько повторяющихся флагов идут подряд. А вторая (1) -         ;
;	собственно, что это за флаг (для данного примера - это B_MODRM). И т.д.    ;
;(х) Для 32-битного исполняемого кода.						   ;
;(х) Данный дизасм длин был написан с целью подтолкнуть исследователей на          ;
;    новые идеи по созданию своего дизасма.                                        ;           
;                                                                                  ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				ФИЧИ:                                              ;
;(+) базонезависимость								   ;
;(+) упакованные таблички							   ;                                           
;                                                                                  ;
;(-) муторно добавлять новые инструкции						   ;                                                                                                                                                   
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
                                                                                   ;
                                                                                   ;
                                                                                   ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;				ИСПОЛЬЗОВАНИЕ:                                     ;
;1)Подключение:                                                                    ;
;	lito.asm                                                                   ;
;2)Вызов:(пример)                                                                  ;
;	lea	esi,XXXXXXXXh	;адрес команды, чью длину надо узнать              ;
;	call	LiTo                                                               ;                                                                                                                  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;размер всего дизасма (вместе с табличками) = 334 байта                                                                                   

									;m1x
							           ;pr0mix@mail.ru	

;===================================================================================

LiTo:
	pushad
	call	_delta_lito_

;===================================================================================

;таблциа флагов для однобайтных опкодов
TableFlags1:

db 041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h
db 041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h,041h,012h,018h,020h
db 0F0h,0F0h,040h,021h,040h,018h,019h,012h,013h,040h,0F2h,012h,013h,019h,023h,0C1h
db 0A0h,01Ch,050h,048h,040h,012h,018h,060h,082h,088h,023h,014h,010h,021h,013h,019h
db 016h,010h,014h,020h,012h,020h,041h,022h,020h,081h,082h,028h,01Ch,012h,0A0h,021h
db 060h,021h
;===================================================================================

;таблциа флагов для двухбайтных опкодов
TableFlags2:

db 041h,090h,011h,0F0h,020h,051h,0F0h,0D0h,0F1h,011h,0F0h,0F0h,0F0h,030h,0F8h,018h
db 0F1h,011h,030h,011h,013h,011h,050h,011h,013h,011h,010h,091h,020h,013h,071h,050h
db 011h,0F0h;,0F0h,0F0h,0B0h 

;===================================================================================

;строка префиксов
pfx:
db 2Eh,36h,3Eh,26h,64h,65h,0F2h,0F3h,0F0h,67h,66h

SizePfx		equ $-pfx					;длина pfx
SizeTbl		equ $-TableFlags1
;===================================================================================
;флаги
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
	test	ecx,ecx                                         ;иначе смотрим, это 0x66?                                          
	jne	_67_
	mov	dl,1                                            ;если да, то устанавливаем dl=1
_67_:
	dec	ecx                                             ;иначе, это 0x67?
	jne	_nextpfx_                                       ;если нет, то ищем другие префиксы
	mov	dh,1                                            ;иначе dh=1
	jmp	_nextpfx_                                       ;продолжаем поиск
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxEND поиск префиксовxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
_endpfx_:	
	cmp	al,0Fh                                        	;опкод состоит из 2-х байт?
	jne	_opcode_
	lodsb                                                   ;если да, то берем 2-ой байт опкода
	mov	cl,82                                           ;и увеличиваем cl=82
;-----------------------------------------------------------------------------------
_opcode_:
	lea	edi,[ebp+ecx+(TableFlags1-_delta_lito_+SizeTbl)];в edi - адрес нужной таблицы флагов(хар-к)
	mov	ch,al						;ch=opcode

	test	cl,cl
				                         	;и опкод состоит из одного байта,
	jne	_01_;je                                 	;то dl=dh

	and	al,0FCh
	cmp	al,0A0h
	jne	_01_                                            ;если опкод>=0xA0 и опкод<=A3,
	mov	dl,dh
;-----------------------------------------------------------------------------------
_01_:
	xor	ebx,ebx
	dec	ebx 						;необходимо =-1 для корректной работы (короче смотри сорцы:)!
_nxtf_:
	mov	al,byte ptr [edi]
	inc	edi
	db	0D4h,10h					;AAM 10h
	add	bl,ah
	cmp	bl,ch
	jb	_nxtf_
	mov	cl,al                                           ;cl - содержит теперь флаги (характеристики)

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxBEG разбор MODRMxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

	test	al,B_MODRM                                      ;присутствует ли байт modrm?
	je	_endmodrm_                                      ;нет? на выход
	lodsb                 	  				;al=modrm
	mov	ah,al
;-----------------------------------------------------------------------------------
	shr	ah,6   						;ah=mod
;-----------------------------------------------------------------------------------	
        test	al,38h                                          ;далее смотрим, равно ли поле reg==0?    					
	jne	_03_
	sub	ch,0F6h                                         ;если да, то смотрим на опкод:
	jne	_02_                                            ;равен ли он 0xF6 или 0xF7(test)?
	or	cl,B_DATA8                                      ;если да, то устанавливаем нужный флаг
_02_:
	dec	ch
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
	lodsb
	jmp	_sib_		
;-----------------------------------------------------------------------------------	                        
_mod02_:                                    			;mod==2?
	dec	ah
	jne	_mod03_
	lodsw
	dec	dh                                              ;если нет префикса 0x67,
	je	_sib_
	lodsw          	
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
	lodsb
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


SizeOfLiTo	equ $-LiTo					;размер функции LiTo
