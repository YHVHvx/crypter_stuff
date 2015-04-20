;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ; 
;											armour														 ; 
;																										 ; 
;			regSS, xIsDebuggerPresent, xNtGlobalFlag, xsehhandler, detect_bpx_api & 					 ; 
;											 etc														 ; 
;																										 ;  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
 
;ARM:
	;assume	fs:flat 
	;pushad
	;popad
	;ret  




	   
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� regSS
;�஢�ઠ �� �⫠���   
;�஢�ઠ 䫠�� TF
;	push	ss
;	pop		ss									;��� ��᫥ �⮩ ������� ��쪠, ���ਬ�� �� ��ࠥ� 䫠� TF, 
;	pushfd										;祬 �� � ��ᯮ��㥬�� 
;	pop		eax
;	test	ah,1
;	jne		_dermo_
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
regSS:
	jmp		$+04    
	mov		dword ptr [esi+9C174016h],2EB5848h
	lea		eax,dword ptr [esi+esi*8+0EF7501C4h] 
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 regSS
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx	 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� xIsDebuggerPresent 
;�஢�ઠ �� �⫠���
;�஢�ઠ ���� Peb.BeingDebugger (1 - �᫨ ��� �⫠������, ���� 0) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xIsDebuggerPresent:
	mov		eax,dword ptr fs:[30h]
	cmp		byte ptr [eax+02],0
	je		_xidpret_
	jmp		eax
_xidpret_:
	ret 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪� xIsDebuggerPresent 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪� xNtGlobalFlag 
;�஢�ઠ �� �⫠���
;�஢�ઠ ���� Peb.NtGlobalFlag �� ����稥 ���� ������ �� 䫠��� �⫠���:
;	FLG_HEAP_ENABLE_TAIL_CHECK   (0x10) 
;	FLG_HEAP_ENABLE_FREE_CHECK   (0x20)  
;	FLG_HEAP_VALIDATE_PARAMETERS (0x40)
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xNtGlobalFlag:
	mov		eax,dword ptr fs:[30h]
	test	dword ptr [eax+68h],70h
	je		_xngfret_
	jmp		eax
_xngfret_:
	ret 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 xNtGlobalFlag  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;func seh-handler 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
XSH		equ		59h
xsehhandler:
	mov		ecx,dword ptr [esp+0Ch]
	assume	ecx:ptr CONTEXT 
	mov		edx,[ecx].regEip 
	mov		al,byte ptr [edx]
	xor		al,XSH  
	cmp		al,0CCh xor XSH						;int3  
	jne		_nb1_
	add		[ecx].regEip,2 
_nb1_:
	cmp		al,08Eh xor XSH						;mov ds,dx   ret
	jne		_nb2_
	add		[ecx].regEip,3						;2 + 1 = 3
_nb2_:
	cmp		al,0E8h xor XSH						;call near 
	jne		_nb3_
	add		[ecx].regEip,7						;   
_nb3_: 
	cmp		al,0EDh xor XSH
	jne		_nb4_
	add		[ecx].regEip,SizeVMh1				;SizeVMh1       
_nb4_:
	sub		edx,[ecx].regEip 
	jne		_xshret_   
	push	100
	push	[ecx].regEip
	call	xCRC32  
	add		[ecx].regEip,150    
_xshret_: 
	mov		[ecx].iDr0,edx             
	mov		[ecx].iDr1,edx
	mov		[ecx].iDr2,edx
	mov		[ecx].iDr3,edx           
	mov		[ecx].iDr6,edx
	mov		[ecx].iDr7,edx      
	xor		eax,eax  
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪� seh-handler'a 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
	 




;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� detect_bpx_api
;��⥪� bpx � ��祩 ����  � ��砫� ���襪    
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
DBA		equ		55h 
;mov	edi,edi
;push	ebp                                        
;mov	ebp,esp 
detect_bpx_api:                          		;0x8B 0xFF 0x55 0x8B 0xEC
	pushad
	mov		esi,dword ptr [esp+24h]
	push	03h;05								;in winxp 5 bytes = ok, but in w2k only 3 bytes! 
	pop		ecx 
_cycledba_:
	lodsb
	xor		al,DBA       
	cmp		al,090h xor DBA						;nop
	je		_detect_bpx_
	cmp		al,0CCh xor DBA						;int3
	je		_detect_bpx_
	cmp		al,0CDh xor DBA						;int x 
	je		_detect_bpx_  
	cmp		al,0E8h xor DBA						;call near
	je		_detect_bpx_
	cmp		al,0E9h xor DBA						;jmp near
	je		_detect_bpx_
	cmp		al,0EBh xor DBA                		;jmp short 
	je		_detect_bpx_   
	cmp		al,0F4h xor DBA						;hlt 
	je		_detect_bpx_
	cmp		al,0FAh xor DBA						;cli 
	je		_detect_bpx_
	cmp		al,0FBh xor DBA						;sti 
	je		_detect_bpx_
	cmp		al,00Fh xor DBA						;UD2 etc 
	je		_detect_bpx_  
	loop	_cycledba_ 
_detect_bpx_:
_dbaret_:
	mov		dword ptr [esp+1Ch],ecx     
	popad
	ret		4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪� detect_bpx_api 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx	 	




  
comment @
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�㭪�� idp_hb_marker
;�஢�ઠ � �뤥������ ������ �����, �� � ��� �୨ ababa.... �᫨ ⠪���� ����, ����� �� ��� �⫠����. 
;⠪�� �஢�ઠ � ᢮������ ������ �୨ feeefeee... etc
;� ������ �ਬ�� �஢������� ����� ����� ��� PEB_LDR_DATA. � ⥬ �� �ᯥ宬 ����� �஢���� ����� � ��㣨� ���.
;
;������� ��������� �����:
;
;HeapBlockHeader		struct
;  ThisSize8		dw	?		;-08  ��騩 ࠧ��� ������� ����� � ������� 8 ����
;  PrevSize8		dw	?		;-06  ��騩 ࠧ��� �।��饣� ����� � ������� 8 ����
;  Tag1				db	?		;-04
;  Flags			db	?		;-03  䫠��
;  ExtraBytes		db	?		;-02  ��� ����⮣� ����� - �᫮ �㦥���� ����, ������ ��������� � 墮��
;  Tag2				db	?		;-01
;HeapBlockHeader		ends	;+00  <-- 㪠��⥫�, �����頥�� HeapAlloc ��� GlobalAlloc
;--------------------------------------------------------------------------------------------------------
;����஢�� 䫠���:
;01h - used
;02h - tail_checking (�⫠���)
;04h - free_checking (�⫠���)
;10h - last_block
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx  
idp_hb_marker:									;IsDebuggerPresent heap block marker 
	pushad 
	mov		eax,dword ptr fs:[30h]				;PEB 
	mov		eax,dword ptr [eax+0Ch]				;PEB_LDR_DATA (heap block) - ����� ���� ldr 
_cycleheap_: 
	test	byte ptr [eax-03],10h				;ldr.Flags
	jne		_nextcheckihm_
	movzx	ecx,word ptr [eax-08]				;ldr.ThisSize8 
	movzx	edx,byte ptr [eax-02]				;ldr.ExtraBytes
	lea		eax,dword ptr [eax+ecx*8]			;᫥���騩 ���� � ���
	neg		edx
	mov		edx,dword ptr [eax+edx]				;�⭨���� �᫮ �㦥���� ����  
	xor		edx,0ABABABABh						;� �᫨ ����� ����, ����� �� ��� �⫠����!   
	jne		_cycleheap_							;�᫨ �� ��� �⫠����, � ���室�� � �஢�થ ᫥���饣� ����� ����� � ���    
	jmp		eax									;���� ��।��� �ࠢ����� � ����� (����� ����� � ᢮� ����� 㪠����)   
_nextcheckihm_:
	push	100									;����� �஢�ਬ, �᫨ ᢮����� ����� ��稭��� �७�� 䥥��..., ⮣�� �� ��� �⫠���� :)! 
	pop		ecx
_cyclemFE_:  
	cmp		dword ptr [eax],0FEEEFEEEh
	jne		_nxtcFE_
	jmp		eax 
_nxtcFE_: 
	inc		eax
	loop	_cyclemFE_      
	popad 
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 idp_hb_marker
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx	  		

    


 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� idp_hb_flag 
;�஢�ઠ 䫠��� �⫠��� � ������ �����, ����� ��室���� � ��� PEB_LDR_DATA 
;����� ⠪�� ����� �࣠�������� 横�, � ���஬ �㤥� �஢�ઠ 䫠��� �� �ᥬ ������ ������ ���, 
;��� � �㭪� idp_hb_marker 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
idp_hb_flag: 
	mov		eax,dword ptr fs:[30h]
	mov		eax,dword ptr [eax+0Ch] 
	test	byte ptr [eax-03],2+4				;tail_checking + free_checking
	je		_ihfret_ 
	jmp		eax
_ihfret_: 
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� �㭪樨 idp_hb_flag 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 

            



;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� idp_heap_flag 
;�஢�ઠ 䫠��� ��� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
idp_heap_flag:
	pushad
	mov		esi,dword ptr fs:[30h]				;PEB 
	mov		ecx,dword ptr [esi+88h]				;Peb.NumberOfHeaps
	mov		esi,dword ptr [esi+90h] 			;Peb.ProcessHeaps  
_cyclenxtheap_:
	lodsd
	cmp		dword ptr [eax+10h],0				;if flags != 0, it is �࠭� ������� (0x40000060)  
	je		_nxtheap_
	jmp		eax 
_nxtheap_: 
	loop	_cyclenxtheap_
	popad
	ret
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;����� idp_heap_flag 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 	 
		@







 