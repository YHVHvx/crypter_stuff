;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ; 
;											rsrc														 ; 
;																										 ; 
;									  re_rsrc, x_align 													 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;                    
;																										 ;
;										  �������:														 ;
;																										 ; 
;����� ��� ��᪠���� ��� ��: 																		 ; 
;	1) �� �����業��� �㭪�� (��� ���� �� �㭪樨 ������� ����쪠), ���⮬� �� ����� ᢮����� 		 ; 
;	   �ਪ��稢��� � � ��㣨� �����-���� ⥬��, ���� ������稢 ����� ����� � �맢�� � ��ࠬ��ࠬ� 	 ; 
;	   ������ �㭪�. � ⠪�� �� �㭪� (��� ���� �� �㭪� ������� ����쪠) ����� ����� ���� �맢��� 	 ; 
;	   � �ਬ��� �� �++ (stdcall). ��� ��� ��ࠬ���� ��।����� �१ ���. ���� ᬮ�� � ���� :)! 	 ; 
;	2) ᫥��� ����� ᥡ� �� ������, ������ - �� �������� ��������������� ������, � ... (����� 		 ; 
;	   ��������� ���� �㩭� ⠬ �� �஢�� � ��㣮�), � ⠪�� �� � ����� �ᯮ������ ⮫쪮 3 	 ; 
;	   ������ (����� �㩭�, ����� �� �஢��). ������� �� ���������� � ��� ��� ������, �� ��ࠧ�� 		 ; 
;	   �����砥� ������ � ����ᠬ�.  																	 ; 
;	3) ������ �㭪�� �����ࠨ���� ������ ������ ��������! �� ����, ��� 䨧��᪨ � 䠩�� ��६�頥�    ;
;	   ��, ���४���� ���� �������� IMAGE_SECTION_HEADER ��� .rsrc, � ⠪�� ���४���� 			 ;    
;	   OptionalHeader.DataDirectory[2].VirtualAddress. ��⠫�� ���� (��㣮� ᥪ樨, � ⠪�� 			 ; 
;	   SizeOfImage) ������ ᪮�४�஢��� �� ᠬ�.														 ;  
;	4) � ��祥, ᬮ�� � ��室���� 																	 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 




	             


;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� re_rsrc
;�����ன�� ����ᮢ
;���� (stdcall) (re_rsrc(LPVOID pExe, IMAGE_SECTION_HEADER *imSh, DWORD Size)):
;	pExe   - ���� ����� 
;	imSh   - 㪠��⥫� � ⠡��窥 ᥪ権 �� ����� ᥪ樨 ����ᮢ
;	Size   - �᫮ (ࠧ��� ����) (�㤥� ��஢���� � �⮩ �㭪�), �� ���஥ ���� ��।������ ᥪ�� 
;			 ����ᮢ ���।, � ⠪�� �� �᫮ �ᯮ������ ��� ���४�஢�� �㦭�� rva � ᥪ樨 
;			 ����ᮢ (.rsrc)
;�����:
;	(+)
;	EAX    - 䨧��᪨� ���� ��।����⮩ ᥪ樨 ����ᮢ  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
re_rsrc:          
	pushad
	mov		ebp,esp								;[ebp+00] 
	mov		edx,dword ptr [ebp+28h]				;EDX - IMAGE_SECTION_HEADER 
	assume	edx:ptr IMAGE_SECTION_HEADER  
	mov		ebx,dword ptr [ebp+24h]				;EBX - IMAGE_DOS_HEADER 
	assume	ebx:ptr IMAGE_DOS_HEADER 
	mov		esi,ebx 
	add		esi,[edx].PointerToRawData
	add		esi,[edx].SizeOfRawData
	dec		esi  
	add		ebx,[ebx].e_lfanew
	assume	ebx:ptr IMAGE_NT_HEADERS
	push	[ebx].OptionalHeader.FileAlignment
	call	x_align								;EAX - ��஢����� �� FileAlignment ��।���� ࠧ��� ���� 
	lea		edi,dword ptr [esi+eax] 
	mov		ecx,[edx].SizeOfRawData 
	std
	rep		movsb								;��।������ ᥪ�� ����ᮢ 䨧��᪨ � 䠩�� 
	cld 
	inc		edi									;᪮�४��㥬 EDI - �� ��砫� ��।����⮩ ᥪ樨 ����ᮢ � 䠩��  
 	add		[edx].PointerToRawData,eax			;᪮�४��㥬 (㢥��稬) 䨧��᪨� ���� (offset) ����ᮢ � IMAGE_SECTION_HEADER
 	push	[ebx].OptionalHeader.SectionAlignment
 	call	x_align								;EAX - ��஢����� �� SectionAlignment ��।���� ࠧ��� ���� 
 	add		[edx].VirtualAddress,eax			;᪮�४��㥬 (㢥��稬) ����㠫�� ���� (rva) ����ᮢ � IMAGE_SECTION_HEADER   
 	add		[ebx].OptionalHeader.DataDirectory[2*8].VirtualAddress,eax	;᪮�४��㥬 (㢥��稬) ����㠫�� ���� (rva) ����ᮢ � IMAGE_SECTION_HEADER     
	assume	edi:ptr IMAGE_RESOURCE_DIRECTORY
	movzx	edx,[edi].NumberOfNamedEntries		
	movzx	ecx,[edi].NumberOfIdEntries
	add		ecx,edx								;������⢮ ����⮢ � ���ᨢ� ������� IMAGE_RESOURCE_DIRECTORY_ENTRY (1 �஢���)  
	push	edi									;[ebp-04]  
	add		edi,sizeof (IMAGE_RESOURCE_DIRECTORY)
	assume	edi:ptr IMAGE_RESOURCE_DIRECTORY_ENTRY  
	push	edi									;[ebp-08]
	push	eax 								;[ebp-12]
;--------------------------------------------------------------------------------------------------------
_cycle_IRDE_1_:
	mov		edx,[edi].OffsetToData 
	btr		edx,31								;�� ��ࢮ� �஢�� �ᥣ�� �⮨� ���訩 ���, ��� ���� ������� 
	add		edx,dword ptr [ebp-08] 
	assume	edx:ptr IMAGE_RESOURCE_DIRECTORY_ENTRY 
	push	ecx									;[ebp-16]	  
    lea		ebx,dword ptr [edx - sizeof(IMAGE_RESOURCE_DIRECTORY)]  
	assume	ebx:ptr IMAGE_RESOURCE_DIRECTORY
	movzx	eax,[ebx].NumberOfNamedEntries
	movzx	ecx,[ebx].NumberOfIdEntries
	add		ecx,eax								;������⢮ ����⮢ � ���ᨢ� ������� IMAGE_RESOURCE_DIRECTORY_ENTRY (2 �஢���)
;-------------------------------------------------------------------------------------------------------- 
_cycle_IRDE_2_: 
	push	edx 		 						;[ebp-20]
	push	ecx									;[ebp-24]         
	mov		edx,[edx].OffsetToData
	btr		edx,31
	add		edx,dword ptr [ebp-08]                          
    lea		ebx,dword ptr [edx - sizeof(IMAGE_RESOURCE_DIRECTORY)]  
	movzx	eax,[ebx].NumberOfNamedEntries		;������⢮ ����⮢ � ���ᨢ� ������� IMAGE_RESOURCE_DIRECTORY_ENTRY (3 �஢���)   
	movzx	ecx,[ebx].NumberOfIdEntries
	add		ecx,eax   
;-------------------------------------------------------------------------------------------------------- 
_cycle_IRDE_3_: 
	mov		esi,[edx].OffsetToData
	add		esi,dword ptr [ebp-04]
	assume	esi:ptr IMAGE_RESOURCE_DATA_ENTRY
	mov		eax,dword ptr [ebp-12]   
	add		[esi].OffsetToData,eax				;� ��� �� ���ࠫ��� �� rva - ���稬 ��   	                 
  	add		edx,sizeof (IMAGE_RESOURCE_DIRECTORY_ENTRY)
  	loop	_cycle_IRDE_3_
;--------------------------------------------------------------------------------------------------------
  	pop		ecx 
	pop		edx
	add		edx,sizeof (IMAGE_RESOURCE_DIRECTORY_ENTRY) 
	loop	_cycle_IRDE_2_ 
;-------------------------------------------------------------------------------------------------------- 
	pop		ecx      
	add		edi,sizeof (IMAGE_RESOURCE_DIRECTORY_ENTRY) 
	loop	_cycle_IRDE_1_ 
;-------------------------------------------------------------------------------------------------------- 
	mov		esp,ebp
	push	dword ptr [ebp+04]
	pop		dword ptr [ebp+1Ch]					;EAX - 䨧��᪨� ���� ��।����⮩ ᥪ樨 ����ᮢ 
	popad
	ret		4*3
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪� re_rsrc 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�ᯮ����⥫쭠� �㭪� x_align
;��ࠢ������� �᫠ (� ������ ��砥 ࠧ��� ����)
;� ��ਪ: ALIGN_UP ((x+(y-1)) & (~(y-1)))
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	
x_align: 
	mov		eax,dword ptr [ebp+2Ch]				;ࠧ��� ����, ����� ���� ��஢���� 
	mov		ecx,dword ptr [esp+04]				;��ࠢ�����饥 ���祭�� Alignment 
	dec		ecx
	add		eax,ecx
	not		ecx
	and		eax,ecx
	ret		4 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪樨 x_align 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;XD!
	 