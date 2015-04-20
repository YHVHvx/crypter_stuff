;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;											search														 ;
;																										 ;
;										    FindPE														 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;  





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� FindPE
;���� 䠩��� �� ��᪥
;���� ( FindPE(char *szDir,char *szMask, DWORD num_files,PVOID xFunc) ): 
;szDir     - ���� (��४���), ��� ᫥��� �᪠�� 䠩�� (�ਬ�� 'C:\Games')
;szMask    - ��᪠, �� ���ன �᪠�� 䠩�� (�ਬ�� '\*.*', ��� '\.exe')
;num_files - ᪮�쪮 䠩��� �㤥� �᪠��
;xFunc	   - ���� �㭪樨 ���� xFunc(char *szPath, WIN32_FIND_DATA *wfd /*���� �㫨*/), ����� �㤥� 
;			 �맢��� �� �������� �㦭��� 䠩�� 
;�����:
;�� ⨯-⮯ :)! 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
szFullName		equ		dword ptr [ebp-MAX_LEN]
dwAddrWFD		equ		dword ptr [ebp-MAX_LEN-SIZE_WFD]
FindPE:
	pushad
	cld 
	mov		ebp,esp              
	sub		esp,(MAX_LEN+SIZE_WFD)				;�뤥�塞 ���� � ��� ��� �࠭���� �������� WIN32_FIND_DATA & ��� ��४�ਨ + ��᪠  
	lea		edi,szFullName  
	lea		ebx,dwAddrWFD 
	assume	ebx: ptr WIN32_FIND_DATA
	mov		esi,dword ptr [ebp+24h]
	push	edi 
	push	esi
	call	xstrlen								;��뢠�� �㭪� ���᪠ ����� ��ப� 	
	xchg	eax,ecx
	rep		movsb								;᭠砫� ᪮���㥬 ���� ��४�ਨ ��� ���᪠
	mov		esi,dword ptr [ebp+28h]
	push	esi
	call	xstrlen
	xchg	eax,ecx
	rep		movsb								;� ��᫥ � ��४�ਨ �ਡ���� ����
	and		byte ptr [edi],0					;������稬 ����� ��ப�  
	pop		edi
	push	ebx  
	push	edi
	call	xFindFirstFileA1					;��稭��� ���� 
	inc		eax 
	je		_fpexit_
	dec		eax
;-------------------------------------------------------------------------------------------------------- 
_dir_: 	
	push	eax 
	cmp		dword ptr [ebp+2Ch],0				;�᫨ �㦭�� ���-�� 䠩��� ����䥪⨫���, � �� ��室   
	je		_findnext_    
	lea		esi,[ebx].cFileName

	call	search_slash						;��뢠�� �㭪�� ���᪠ ᠬ��� ��᫥����� ���, �⮡� ����� ���� � �������� ��� ���������� 䠩��/��४�ਨ 
	  
	test	[ebx].dwFileAttributes,FILE_ATTRIBUTE_DIRECTORY	;�� ��諨 ��४���?  
	je		_pefile_							;���� �� ��諨 䠩�, � ���室�� 
	cmp		byte ptr [esi],'.'					;�஢�ਬ, �� ��४��� '.' or '..' ?   
	je		_findnext_							;�᫨ ��, � �饬 ��㣨� 䠩��/�����  
;--------------------------------------------------------------------------------------------------------
	dec		dword ptr [ebp+2Ch]					;㬥��蠥� ���稪       

	push	esi
	call	xstrlen
	xchg	eax,ecx
	rep		movsb								;����� ��᪨ � ��� ������� ��� ⮫쪮 �� ��������� ����� 
	and		byte ptr [edi],0
	lea		edi,szFullName 
	push	dword ptr [ebp+30h]
	push	dword ptr [ebp+2Ch]
	push	dword ptr [ebp+28h]
	push	edi									; 
	call	FindPE								;�맮��� �㭪�� ���᪠ 䠩���/����� (४����)

    call	search_slash						;��६ ��� ⮫쪮 �� ���᪠���� ��४�ਨ  
    and		byte ptr [edi],0 
    jmp		_findnext_  
;--------------------------------------------------------------------------------------------------------
_pefile_:										;�᫨ �� ��諨 䠩� 
	push	esi
	call	xstrlen
	push	esi  
	lea		esi,dword ptr [esi+eax-4]
	xchg	eax,ecx   
	push	esi 
	call	small_symbol 
	cmp		dword ptr [esi],'exe.'				;㧭���, �� exe-䠩�? 
	pop		esi    
	jne		_findnext_							;�᫨ ���, � �த������ ����

	rep		movsb
	and		byte ptr [edi],0
 
	lea		edi,szFullName  
	push	ebx
	push	edi
	call	dword ptr [ebp+30h]					;���� ��뢠�� �㭪��, ����� ������ �믮������� �� ��������� �㦭�� 䠩��� 
	test	eax,eax
	je		_constcounter_	
	dec		dword ptr [ebp+2Ch]					;㬥��蠥� ���稪 
_constcounter_:	   
	call	search_slash
	and		byte ptr [edi],0 
;-------------------------------------------------------------------------------------------------------- 
_findnext_:
	lea		edi,szFullName 
	pop		eax
	push	eax 
	push	ebx
	push	eax
	call	xFindNextFileA1						;�த������ ���� 
	test	eax,eax
	pop		eax 
	jne		_dir_
;--------------------------------------------------------------------------------------------------------
	push	eax 
	call	xFindClose1      
	 
_fpexit_: 
	mov		esp,ebp 
	popad 
	ret		4*4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 FindPE 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�ᯮ����⥫쭠� �㭪� search_slash
;��� ᠬ� �ࠩ��� �ࠢ� ��� (�⮡� ��᫥ �����/�������� ��� �����/䠩�� � ������� ���)
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
search_slash:
	push	edi
	call	xstrlen  
	add		edi,eax
	mov		al,'\'  
	std 
_ssl_:
	scasb	 
	jne		_ssl_
	inc		edi 
	inc		edi
	cld
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 search_slash 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx	   

