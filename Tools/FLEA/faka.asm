;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;                                                                                                   
;                                                                                                      	 ;
;                                                                                                    	 ;
;                  xxxxxxxxxxxx     xxxxxxxxx     xxxx    xxxx     xxxxxxxxx							 ; 
;                  xxxxxxxxxxxx    xxxx   xxxx    xxxx   xxxx     xxxx   xxxx							 ;
;                  xxxx           xxxx     xxxx   xxxx  xxxx     xxxx     xxxx							 ;
;                  xxxx           xxxx     xxxx   xxxx xxxx      xxxx     xxxx							 ;
;                  xxxxxxxxxx     xxxx     xxxx   xxxxxxxx       xxxx     xxxx							 ;
;                  xxxxxxxxxx     xxxx xxx xxxx   xxxxxxxx       xxxx xxx xxxx							 ;
;                  xxxx           xxxx xxx xxxx   xxxx xxxx      xxxx xxx xxxx							 ;
;                  xxxx           xxxx     xxxx   xxxx  xxxx     xxxx     xxxx							 ;
;                  xxxx           xxxx     xxxx   xxxx   xxxx    xxxx     xxxx							 ;
;                  xxxx           xxxx     xxxx   xxxx    xxxx   xxxx     xxxx							 ;
;																										 ; 
;            																							 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ; 
;										FAKe Api generator												 ; 
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										     :)!														 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									    �㭪�� FAKA													 ; 
;							  ��������� (��������) �������� ������										 ;   
;																										 ;
;																										 ;
;����:																									 ;
;1 ��ࠬ��� - (� �����⢥���) ���� �������� FAKEAPIGEN (�� ���ᠭ�� ᬮ�� ����)						 ;  
;--------------------------------------------------------------------------------------------------------;
;�����:																									 ;
;EAX - ���� ��� ���쭥�襩 ����� ���� (�᫨ ⠪���� �����������).  									 ; 
;+   - ���祭��, ��।���� � ᯥ樠��� ���� �������� ( [ api_va ] )									 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									  	y0p!															 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									  �������															 ;
;																										 ; 
;�㭪�� xCRC32A ��室���� � ���㫥 xBase.asm. ����� ��� ����� ���� ⠪�� ���������, ���� ⮣��       ;
;�뭥�� �㦭� �㭪樨 � ��� �����. ���� ��᪮����஢��� � ���� �⮣� ��室���� �㦭� �㭪�.  	 ;   
;--------------------------------------------------------------------------------------------------------;
;��� ����稫��� �㭪樥� xCRC32A(char *pszFuncName). ����� �������� ������ ������ �㭪樨, � ⠪��    ;
;��砥 ������� ᭮�� ��� �� ���� ������ �㭪権, � �������� �⨬� ��蠬� ���� ���, ��   		 ;  
;�ᯮ������� � ������ ������. 																			 ; 
;--------------------------------------------------------------------------------------------------------; 
;����� �����c���� ⮫쪮 ��᪮�쪨� ���襪 - ��⠫�� � ��������� ����� �������� ᠬ���.				 ; 
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;         
;																										 ;
;										y0p!															 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									�������� ���������													 ;
;										FAKEAPIGEN														 ; 
;																										 ;
;																										 ;
;FAKEAPIGEN	struct																						 ;
;	rgen_addr		dd	?		;���� ���   															 ; 
;	mapped_addr		dd	?		;���� ������ (���� 䠩�� � ����� (MapViewOfFile))					 ;
;	buf_for_api		dd	?		;����, �㤠 �����뢠�� ᣥ���஢����� ������ �����					 ;
;	api_hash		dd	?		;��� �� ��� (���� 0, ���� !=0 ���祭��)									 ;
;	api_va			dd	?   	;VirtualAddress, �� ���஬� �㤥� ������ ���� �㦭�� ���誨 (� IAT)  	 ;
;	reserved1		dd	?		;��१�ࢨ஢��� (���� ��)   											 ;
;FAKEAPIGEN	ends   																						 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										y0p!															 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;						��������� � ����� ��������� FAKEAPIGEN											 ;
;																										 ; 
;																										 ;
;[   rgen_addr   ]  : 																					 ; 
;					  ⠪ ��� ����� ������ (FAKA) ࠧࠡ�⠭ ��� �ਢ離� � ������-���� ��㣮�� �����, ; 
;					  � ��� �����樨 ���� (� �������� ��㣨� ��) ����� ���, ���⮬� ���� ��� 		 ; 
;					  �࠭���� � (������) ���� ��������. 		 										 ;
;					  �����: �᫨ ���� FAKA �㤥� �ᯮ�짮���� ��㣮� ��� (� �� ��, ����� 	 		 ;
;					  ���� � ��� � ��������), ����, �⮡� ��� ��㣮� ��� �ਭ���� � ����⢥ 1-�� 	 ;
;					  (� �����⢥�����!) ��ࠬ��� � ��� �᫮ (������� ��� N), ⠪ ��� ���� �㤥� �  ;
;					  ��������� [0..n-1]. � �� ��室� ��㣮� ���	������ �������� � EAX ��砩��� 	 ;
;					  �᫮. ��⠫�� ॣ����� ������ ������� ��������묨. ��. 	 					 ; 
;--------------------------------------------------------------------------------------------------------; 
;[ mapped_addr ]	: 																					 ; 
;					  � �⮬ ���� �࠭���� ���� ����� 䠩�� (१��� �� �㭪� MapViewOfFile)  			 ; 
;					  aka ���� 䠩�� � �����. 														 ; 
;--------------------------------------------------------------------------------------------------------;
;[ buf_for_api ]	: 																					 ;
;					  ���� ����, �㤠 �����뢠�� ������㥬� ����� ���誨. � ����� ���� ��祣�  ;
;					  �� ������ (� ������ ������) ⮫쪮 � 1 ��砥: 									 ;
;					  	1) �᫨ �� ����� �������饩 ��� ���誨 �� ������� � 䠩��, ����� 		 	 ; 
;						   �஥�஢�� � ������; 														 ; 
;--------------------------------------------------------------------------------------------------------;
;[  api_hash   ]	:																					 ; 
;					  ���� ���襪 �ந�室�� �� ���� �� ����� �㦭�� ���誨. �᫨ �� ���� !=0, ⮣�� 	 ; 
;					  �㤥� ���� ������ �⮩ ���誨, ��� �� ����� ���ன 㪠���. � �᫨ ���誠 ������� ;
;					  � 䠩��, ����� �஥�஢�� � ������, ⮣�� � ���� [ api_va ] ��୥��� 			 ;
;					  VirtualAddress, �� ���஬� � �㤥� ������ ���� �������饩 ��� ���誨 (���� �  ;
;					  IAT). �᫨ �� 㪠����� ��� �� ��室���� � � ��࠭�� �����⮠������ (� ���) 	 ;
;					  ⠡��窥 ��襩, � �㤥� ᣥ��७� � ����᭠ � ���� ( [ buf_for_api ] ) 			 ;
;					  ��������� ���誠. �᫨ �� ��� �� �뫮 � ⠡��窥, � �����樨 �� �㤥�. �� ����� ;
;					  �㤥� ᤥ���� ᠬ��� (�ᯮ�짮��� ���� � ���� [ api_va ] ).						 ;
;					  �᫨ ���� [ api_hash] =0, ⮣�� �㤥� ���� ��࠭�� �����⮢������ ��襩. ������ 	 ;
;					  ��� ��� �������祭 (⮫쪮 �� ����ᠭ). 											 ; 
;--------------------------------------------------------------------------------------------------------;
;[   api_va    ]	: 																					 ; 
;					  �᫨ ��������� ��� ���誠 ������� (ᮢ���� ���), � ����� ( [ api_va ] ) 		 ;
;					  �������� VirtualAddress, �� ���஬� �㤥� ������ ���� �������饩 ��� ���誨.   ;
;					  � ���� ��� ��室���� � IAT. �᫨ ��������� ��� ���誠 �� �������, ⮣�� 		 ;
;					  � �⮬ ���� 0.   	 								        						 ; 
;							  																			 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									  	����															 ;
;																										 ;
;(+) ����������ᨬ����																					 ;
;(+) ��� delta-offset � ������ (��� ���樨 ᠬ�� ����᭮�)  											 ;  
;(+) ���� � �ᯮ�짮�����																				 ;   
;(+) �� �ᯮ���� WinApi'襪 																			 ;    
;(+) ��� �ਢ離� � ��㣨� �������. ����������� �����. ����� �ᯮ�짮������ (� �����������) 		 ;
;	 	�⤥�쭮. �⫨筮 ���室�� ��� ������� ����.												 ;
;(+) ������� ࠧ��� ������ �㭪権. ���� ��������� ���� ���誨.  									 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									�������������: 														 ;
;																										 ;
;1) ������祭��:																						 ;
;		xbase.asm, faka.asm						;���� ��������� ⮫쪮 faka.asm, �� � ⠪�� ��砥 	 ; 
;												;����室��� �㭪� (�� �����) �᪮������				 ; 
;2) �맮� (�ਬ�� stdcall):																				 ;
;																										 ;
;	������ #1																							 ;
;		...																								 ;
;		bBuf1	db 100 dup (00h)				;sizeof FAKEAPIGEN										 ;
;		bBuf2	db 500 dup (00h)				;													 	 ;
;		...																								 ;
;		lea		ecx,bBuf1						;���� ��� ��������									 ;
;		lea		edx,bBuf2						;� ���� ����ᠭ� ᣥ���஢���� fake winapi func	 ;
;		assume	ecx:ptr FAKEAPIGEN 																		 ;
;		mov		[ecx].mapped_addr,330000h		;����� ��।��� ���� 䠩�� � ����� 					 ;
;		mov		[ecx].buf_for_api,edx			;														 ;
;		mov		[ecx].api_hash,0				;�� ���� ������㥬. ����� �㤥� �ந������ ���� 	 ;
;												;��࠭�� �����⮢������ (� �⮬ ���㫥) ���襪. � �᫨ 	 ;
;												;�����-���� �� ��� �㤥� �������, � ��� ᣥ������ � 	 ;
;												;� �������� � 㪠����� ��� ����.					 ;
;		mov		[ecx].api_va,0					;���� ����������. ��� ����� ���� � �� ���������.		 ;
;		push	ecx																						 ;
;		call	FAKA							;��뢠�� �㭪� �����樨 � ����� fake WinApi func. 	 ;
;												;⥯��� � ���� bBuf2 � ��� ����ᠭ� ��������� 		 ;
;												;fake winapi function. 									 ; 
;--------------------------------------------------------------------------------------------------------; 
;	������ #2																							 ;
;		...																								 ;
;		bBuf1	db 100 dup (00h)				;sizeof FAKEAPIGEN										 ;
;		bBuf2	db 500 dup (00h)				;														 ;
;		...																								 ;
;		lea		ecx,bBuf1						;���� ��� ��������									 ;
;		lea		edx,bBuf2						;� ���� ����ᠭ� ᣥ���஢���� fake winapi func	 ;
;		assume	ecx:ptr FAKEAPIGEN 																		 ;
;		mov		[ecx].mapped_addr,330000h		;����� ��।��� ���� 䠩�� � ����� 					 ;
;		mov		[ecx].buf_for_api,edx			;														 ; 
;		mov		[ecx].api_hash,19886E42h		;� �� ���� ⥯��� ������ ��� �� ����� �㭪� GetVersion. ;
;		push	ecx																						 ; 
;		call	FAKA							;��뢠�� �㭪� �����樨 � ����� fake WinApi func. 	 ;
;																										 ;
;		cmp		[ecx].api_va,0 					;�஢�ਬ, ��諨 �� �� �㦭�� ��� �����?				 ;
;		je		_ret_																					 ;
;		sub		eax,[ecx].buf_for_api																	 ;
;		test	eax,eax							;�᫨ ���誠 �������, � �� ��� �� � ��࠭�� 			 ;
;		jne		_ret_							;�����⮢������ ⠡��窥, � �� ��� ᣥ��ਫ���.		 ; 
;		mov		word ptr [eax],15FFh			;���� ᠬ� � ᣥ��ਬ ���������� ��� �����. 		 ;  
;		push	dword ptr [ecx].api_va																	 ;
;		pop		dword ptr [eax+2]																		 ;
;_ret_: 																								 ; 
;																										 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;v1.0


													;m1x
												;pr0mix@mail.ru
											;EOF 




;========================================================================================================
;������� FAKEAPIGEN 
;========================================================================================================
FAKEAPIGEN	struct
	rgen_addr		dd	?   
	mapped_addr		dd	?
	buf_for_api		dd	?
	api_hash		dd	?
	api_va			dd	?   
	reserved1		dd	?  
FAKEAPIGEN	ends  
;======================================================================================================== 


fNTHeaders		equ		dword ptr [ebp-04] 		;㪠��⥫� �� IMAGE_NT_HEADERS 
fBase			equ		dword ptr [ebp-08]		;ImageBase 
NUM_HASH		equ		7						;���-�� ��࠭�� �����⮢������ ��襩 �� ���� ���襪 (�� ���������� ᢮��� ��� 㢥����� �� ���祭��)    
    



 
FAKA:											;�㭪�� FAKA 
	pushad										;��࠭塞 ॣ����� 
	mov		ebp,esp								;[ebp+00] 	
	mov		edi,dword ptr [ebp+24h] 
	assume	edi:ptr FAKEAPIGEN					;edi - 㪠��⥫� �� �������� FAKEAPIGEN  
	mov		esi,[edi].mapped_addr 
	assume	esi:ptr IMAGE_DOS_HEADER 
	add		esi,[esi].e_lfanew
	assume	esi:ptr IMAGE_NT_HEADERS 
	and		dword ptr [edi].api_va,0			;����塞 ������ ����      
	push	esi									;[ebp-04] ;ImageBase   
	push	[esi].OptionalHeader.ImageBase		;[ebp-08] ;IMAGE_NT_HEADERS
	
	push	000000000h							;[ebp-12] ;������稬 ����� ⠡��窨 ��襩 ��᫥���� �㫥�� ����⮬  
 
	cmp		[edi].api_hash,0
	jne		_searchapi_
;--------------------------------------------------------------------------------------------------------
;				� ��� � ���� �������� ����� (�࠭���� � ���) (�⮡� ������� � ��㣨� ���誨, ⠪�� �������� � � ᢮� ���)     
;--------------------------------------------------------------------------------------------------------  
	push	0B1866570h 							;GetModuleHandleA 
	push	03FC1BD8Dh 							;LoadLibraryA 
	push	04CCF1A0Fh 							;GetVersion 
	push	02D66B1C5h 							;GetCommandLineA 
	push	0D9B20494h 							;GetCommandLineW
	push	0D0861AA4h 							;GetCurrentProcess
	push	0C97C1FFFh 							;GetProcAddress
;-------------------------------------------------------------------------------------------------------- 
	mov		edx,esp
	push	NUM_HASH 
	push	edx  
	call	swap_elem							;��砩�� ��ࠧ�� ࠧ��蠥� ������ � ⠡��窥 (⠡��窥 ��襩) 
_cycle_sa_:	
	pop		ecx									;��⥬ �롨ࠥ� ��।��� ��� (�� ⠡��窨 (�� ���)) 
	test	ecx,ecx								;��� �����稫���? 
	je		_apinotfound_						;�᫨ ��, � �� ��室         
	mov		[edi].api_hash,ecx					;���� �����⨬ ��࠭�� ��� � ��।������� ��� ���� ����  
_searchapi_:  
    call	search_api							;��뢠�� �ᯮ����⥫��� �㭪�� ���᪠ �㦭�� ���誨 �� �� ���� 
    											;� ����⢥ १��� �⮩ �㭪� ��୥��� VirtualAddress (� ���� [ api_va ] ), 
    											;�� ���஬� � �㤥� ������ ���� �㦭�� ���誨 � IAT 
    cmp		[edi].api_va,0						;�᫨ �㦭�� ���誠 �� �������, � �롥६ ��� �� ��㣮� ���誨, � �㤥� �᪠�� 㦥 �� ���� 
    je		_cycle_sa_  
;--------------------------------------------------------------------------------------------------------   
;�⮡� ������� � ��㣨� ���誨, ⠪�� �������� � � ᢮� �஢��� 
;-------------------------------------------------------------------------------------------------------- 
    											;���� 㧭���, ��� �� ����� �㭪� �� ��諨? � � ��砥 ᮢ�������, ᣥ��ਬ (����襬) �㦭�� ����� 
    cmp		[edi].api_hash,0B1866570h			;GetModuleHandleA
    je		_f01_
    cmp		[edi].api_hash,03FC1BD8Dh			;LoadLibraryA          
    jne		_n01_
_f01_:
	call	fGetModuleHandleA
	jmp		_fakaend_  

_n01_: 
	cmp		[edi].api_hash,04CCF1A0Fh			;GetVersion
	je		_f02_ 
	cmp		[edi].api_hash,02D66B1C5h			;GetCommandLineA  
	je		_f02_ 
	cmp		[edi].api_hash,0D9B20494h			;GetCommandLineW 
	je		_f02_ 
	cmp		[edi].api_hash,0D0861AA4h			;GetCurrentProcess
	jne		_n02_ 
_f02_: 
	call	fGetVersion
	jmp		_fakaend_
_n02_: 	 
	cmp		[edi].api_hash,0C97C1FFFh			;GetProcAddress 
	jne		_n03_ 
_f03_:
	call	fGetProcAddress 
	jmp		_fakaend_
_n03_: 	 
	jmp		_cycle_sa_  
;-------------------------------------------------------------------------------------------------------- 
_apinotfound_:      
	mov		edi,[edi].buf_for_api 
_fakaend_: 
    mov		esp,ebp       
	mov		dword ptr [ebp+1Ch],edi				;EAX = EDI      
	popad
	ret		4									;��室��

;========================================================================================================
;����㭪�� search_api 
;========================================================================================================

search_api: 	
	push	esi 
	mov		edx,[esi].OptionalHeader.DataDirectory[1*8].VirtualAddress
	test	edx,edx								;�஢��塞, ���� �� ⠡��窠 ������ (��) � 䠩��, ����� � ����� ?        
	je		_searchapiret_						;�᫨ ��� ��, � �� ��室. ���� �த������ 
	push	edx 								;������ RVA �� 
	push	esi 								;� ���� IMAGE_NT_HEADERS 
	call	fRvaToRaw 							;� ��뢠�� �㭪�, ����� �� RVA ����砥� ��� RAW ᬥ饭�� � 䠩�� 
	mov		esi,eax								;��࠭塞 ����祭��� RAW ᬥ饭�� � ESI 
	add		esi,[edi].mapped_addr				;� �ਡ���塞 ���� ����� 
	assume	esi:ptr IMAGE_IMPORT_DESCRIPTOR		;ESI - 㪠��⥫� �� IMAGE_IMPORT_DESCRIPTOR   
;-------------------------------------------------------------------------------------------------------- 
_cycleIID_: 
	mov		edx,[esi].OriginalFirstThunk
	mov		ebx,[esi].FirstThunk 
	test	edx,edx								;�᫨ ���� OriginalFirstThunk = 0 (⠪�� �뢠�� � ��ૠ�᪨� �ண��), �  
	jne		_oft_ 
	mov		edx,ebx								;������ ����� OriginalFirstThunk RVA ���� FirstThunk  
_oft_: 
	push	edx
	push	fNTHeaders 
	call	fRvaToRaw							;����砥� RAW ᬥ饭�� �� ��।������ RVA 
	mov		edx,eax
	add		edx,[edi].mapped_addr 
	assume	edx:ptr IMAGE_THUNK_DATA32
	push	ebx
	push	fNTHeaders
	call	fRvaToRaw							;etc 
	mov		ebx,eax
	add		ebx,[edi].mapped_addr  
	assume	ebx:ptr IMAGE_THUNK_DATA32
	test	ecx,ecx								;� ECX - IMAGE_SECTION_HEADER �㦭��� ����� � ⠡��窥 ᥪ権. 
	jne		_sechdr_							;�᫨ RVA ��室���� � �।���� ��������� 䠩��, � � ��� ������ �㫨 
	push	0
	push	0
	jmp		_cycleITD32_ 
_sechdr_: 
	assume	ecx:ptr IMAGE_SECTION_HEADER
	push	[ecx].VirtualAddress				;���� ������ � ��� VirtualAddress & PointerToRawData 
	push	[ecx].PointerToRawData  
;--------------------------------------------------------------------------------------------------------
_cycleITD32_:   
	push	[edx].u1.AddressOfData
	push	fNTHeaders
	call	fRvaToRaw
	bt		eax,31 
	jc		_ordinalok_ 
	add		eax,[edi].mapped_addr 
	;assume	eax:ptr IMAGE_IMPORT_BY_NAME
	inc		eax
	inc		eax   
	push	eax   
	call	xCRC32A 							;����� ����砥� ��� �� ����� �㭪樨   
	mov		ecx,ebx
	sub		ecx,[edi].mapped_addr				;map_addr  
	sub		ecx,dword ptr [esp] 				;PointerToRawData
	add		ecx,dword ptr [esp+04]				;VirtualAddress
	add		ecx,fBase 							;ImageBase
												;� ECX VirtualAddress, �� ���஬� ����� ���� ��।��� ������ �㭪樨    

	cmp		eax,[edi].api_hash 					;�� ��諨 �㦭�� �����? (��� ᮢ����?)  
	jne		_nxtITD32_							;�᫨ ���, � �த������ ����
	mov		[edi].api_va,ecx					;�᫨ ��, � ��࠭�� ���᫥��� VA � ���� [ api_va ] 
	pop		eax									;���४�஢�� ��� 
	pop		eax 
	jmp		_api_hash_ok_						;� �� ��室   		
;--------------------------------------------------------------------------------------------------------    
_nxtITD32_:
_ordinalok_: 		  
	add		edx,sizeof IMAGE_THUNK_DATA32		;���室�� � ᫥���饬� ������ IMAGE_THUNK_DATA32    
	add		ebx,sizeof IMAGE_THUNK_DATA32 
	cmp		[edx].u1.AddressOfData,0			;�� ��᫥���� �� ����� ?
	jne		_cycleITD32_
	pop		eax									;���४��㥬 ��� 
	pop		eax 
	add		esi,sizeof IMAGE_IMPORT_DESCRIPTOR	;���室�� � ᫥���饬� ������ IMAGE_IMPORT_DESCRIPTOR 
	cmp		[esi].FirstThunk,0					;�� �� ��᫥���� ����� ? 
	jne		_cycleIID_
_notapi_:
_api_hash_ok_:      
_searchapiret_: 
	pop		esi 
	ret											;��室��
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 FAKA 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	   





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� fRvaToRaw
;����祭�� RAW ᬥ饭�� �� ��������� RVA 
;���� (fRvaToRaw(IMAGE_NT_HEADERS *imNTh, DWORD RVA)):
;	imNTh - 㪠��⥫� �� IMAGE_NT_HEADERS 
;	RVA   - RVA, RAW ᬥ饭�� ���ண� ���� ���� 
;�����:
;	EAX   - RAW ᬥ饭��
; 	ECX   - 㪠��⥫� �� IMAGE_SECTION_HEADER �㦭��� ����� � ⠡��窥 ᥪ権, ���� 0. 
;�������:
;	�᫨ ECX != 0, � � ECX - 㪠��⥫� �� IMAGE_SECTION_HEADER. ��� ����� ᮤ�ন� ����� ⮩ 
;	ᥪ樨, � �।���� ���ன �ᯮ����� RVA. 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
fRvaToRaw:
	pushad
	mov		ebp,esp
	mov		esi,dword ptr [ebp+24h]				;ESI - 㪠��⥫� �� IMAGE_NT_HEADERS  
	mov		ebx,dword ptr [ebp+28h]				;EBX - RVA              
	assume	esi:ptr IMAGE_NT_HEADERS 
	movzx	ecx,[esi].FileHeader.NumberOfSections 
	movzx	edx,[esi].FileHeader.SizeOfOptionalHeader
	lea		esi,dword ptr [ edx + esi + 4 + sizeof(IMAGE_FILE_HEADER) ]
	assume	esi:ptr IMAGE_SECTION_HEADER
_cyclenxtsec_: 
  	mov		edx,[esi].VirtualAddress
  	cmp		ebx,edx 
  	jb		_nxtsection_
  	cmp		[esi].Misc.VirtualSize,0
  	je		_phsizeok01_
  	add		edx,[esi].Misc.VirtualSize
  	jmp		_sizeok01_
_phsizeok01_:
	add		edx,[esi].SizeOfRawData
_sizeok01_: 	   
  	cmp		ebx,edx
  	jae		_nxtsection_
  	sub		ebx,[esi].VirtualAddress
  	add		ebx,[esi].PointerToRawData
  	jmp		_rawok_
_nxtsection_:  
 	add		esi,sizeof IMAGE_SECTION_HEADER 
  	loop	_cyclenxtsec_
  	xor		esi,esi
_rawok_:
	mov		dword ptr [ebp+1Ch],ebx
	mov		dword ptr [ebp+18h],esi     	 
	popad
	ret		4*2
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 fRvaToRaw 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	 





;comment %   	
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
	call	[edi].rgen_addr 
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





comment %     
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� xstrlen
;���� ����� ��ப�
;���� ( xstrlen(char *pszStr) ):
;pszStr - 㪠��⥫� �� ��ப�, ��� ����� ���� ������� 
;�����:
;EAX    - ����� ��ப� (� �����) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xstrlen:
	push	edi		 
	mov		edi,dword ptr [esp+08]
	push	edi  
	xor		eax,eax
_numsymbol_: 
	scasb
	jne		_numsymbol_
	xchg	eax,edi
	dec		eax
	pop		edi
	sub		eax,edi
	pop		edi  
	ret		4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 xstrlen 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� xCRC32A
;���᫥��� CRC ��ப�
;���� (stdcall) (xCRC32A(char *pszStr)):
;	pszStr - ��ப�, 祩 ��� ���� ������� 
;�����:
;	(+) EAX - ��� �� ��ப� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xCRC32A:
	push	ecx
	mov		ecx,dword ptr [esp+08]   
	push	ecx
	call	xstrlen
	test	eax,eax
	je		_xcrc32aret_
	push	eax
	push	ecx 
	call	xCRC32
_xcrc32aret_: 
	pop		ecx 
	ret		4 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 xCRC32A 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 			




	 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� xCRC32
;������ CRC32 
;���� (stdcall) (xCRC32(BYTE *pBuffer,DWORD dwSize)):
;	pBuffer - ����, � ���஬ ���, 祩 crc32 ���� �������
;	dwSize  - ᪮�쪮 ���� ������� ? (+) 
;�����:
;	(+) EAX - CRC32 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xCRC32:
	pushad
	mov		ebp,esp
	xor		eax,eax
	mov		edx,dword ptr [ebp+24h]
	mov		ecx,dword ptr [ebp+28h]
	jecxz	@4 
	dec		eax 
@1:
	xor		al,byte ptr [edx]
	inc		edx
	push	08
	pop		ebx
@2:
	shr		eax,1
	jnc		@3
	xor		eax,0EDB88320h
@3:
	dec		ebx 
	jnz		@2
	loop	@1
	not		eax
@4:
	mov		dword ptr [ebp+1Ch],eax 
	popad
	ret		4*2 							
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx		
;����� �㭪樨 xCRC32 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	
		;%  





;========================================================================================================
;������� ���襪
;����:  
;	EDI - 㪠��⥫� �� �������� FAKEAPIGEN (���� [edi].api_va ������ ���� �ࠢ���� (������ �㦭� VirtualAddress)  
;======================================================================================================== 	

fGetModuleHandleA:
fLoadLibraryA:
	mov		ax,006Ah
	push	[edi].api_va 
	mov		edi,[edi].buf_for_api 
	stosw 
	mov		ax,15FFh
	stosw
	pop		eax     
	stosd  
	ret
;-------------------------------------------------------------------------------------------------------- 
fGetVersion:
fGetCommandLineA:
fGetCommandLineW:  
fGetCurrentProcess: 
	mov		ax,15FFh
	push	[edi].api_va  
	mov		edi,[edi].buf_for_api
	stosw
	pop		eax 
	stosd
	ret   
;-------------------------------------------------------------------------------------------------------- 
fGetProcAddress:
	mov		eax,006A006Ah
	push	[edi].api_va  
	mov		edi,[edi].buf_for_api  
	stosd 
	mov		ax,15FFh
	stosw
	pop		eax 
	stosd 
	ret
;-------------------------------------------------------------------------------------------------------- 




 
;========================================================================================================
;XD 
