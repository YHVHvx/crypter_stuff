
MODE_CAPT 			EQU 0
MODE_STAT 			EQU 1
MODE_MON  			EQU 2
PCAP_VERSION_MAJOR	EQU 2
PCAP_VERSION_MINOR	EQU 4
PCAP_ERRBUF_SIZE 	EQU 256
PCAP_IF_LOOPBACK	EQU 1	; interface is loopback
PCAP_FDDIPAD 		EQU 3

	bpf_int32		typedef	DWORD	; int
	bpf_u_int32	typedef	DWORD	; u_int 

;	char 			typedef BYTE;
;	short 			typedef WORD;
;	long 			typedef DWORD;
	lpcap_pkthdr 	typedef ptr pcap_pkthdr
	pcap_dumper_t 	typedef ptr pcap_dumper
	pcap_t 		typedef ptr pcap
	pcap_addr_t 	typedef ptr pcap_addr
	pcap_if_t 	typedef ptr pcap_if
	ip_address_t 	typedef ptr ip_address
	mac_address_t 	typedef ptr mac_address
	
iphdr struct; // structure IP Header
									; //Pour processeur de type little-endian
	ihl 	db [4] dup (?)			; // IP header length
	version db [4] dup (?)			;	
	tos			BYTE 	?			; // Type of service
	tot_len  	WORD 	?			; // Total length
	id 			WORD 	?			; // Identification
	frag_off 	WORD 	?			; // Fragment Offset + Flags
	ttl 		BYTE 	?			; // Time to life
	protocol 	BYTE 	?			;
	check		WORD	?			; // Checksum
	saddr		DWORD	?			; // Source address
	daddr		DWORD 	?			; // Destination address
iphdr ends

; 4 bytes IP address  
ip_address struct
    byte1 	BYTE 	?
    byte2 	BYTE 	?
    byte3 	BYTE 	?
    byte4 	BYTE 	?
ip_address ends

; 5 bytes Mac address
mac_address struct
	byte1 		BYTE 			? 	
	byte2 		BYTE 			?
	byte3 		BYTE 			? 
	byte4 		BYTE 			?
	byte5 		BYTE 			? 
	byte6 		BYTE 			? 	
mac_address ends

; IPv4 header  
ip_header struct
   ver_ihl 					BYTE 	?		; // Version (4 bits) + Internet header length (4 bits)
   tos 						BYTE 	?		; // Type of service 
   tlen		   				WORD 	?		; // Total length 
   identification			WORD 	?		; // Identification
   eth_type					WORD 	?		; // EtherType
   flags_fo					WORD 	?		; // Flags (3 bits) + Fragment offset (13 bits)
   ttl 		   				BYTE 	?		; // Time to live
   protocole   				BYTE 	?		; // Protocol
   crc			   			WORD 	?		; // Header checksum
   sip 						ip_address 	<?>	; // Source address IP
   dip	 					ip_address 	<?>	; // Destination address IP
   smac 					mac_address <?>	; // Source address MAC
   dmac 					mac_address <?>	; // Destination address MAC
   op_pad 					DWORD 	?		; // Option + Padding
ip_header ends

; UDP header 
udp_header struct
	sport					WORD 	?		; // Source port
	dport					WORD 	?		; // Destination port
	len			    		WORD 	?		; // Datagram length
	crc			   			WORD 	?		; // Checksum
udp_header ends


pcap_file_header struct
	magic  				DWORD ?			;
	version_major  		DWORD ?			;
	version_minor     	DWORD ?     	;
	thiszone	      	DWORD ?     	; /* gmt to local correction */
	sigfigs		     	DWORD ?     	; /* accuracy of timestamps */
	snaplen	    		DWORD ?     	; /* max length saved portion of each pkt */
	linktype		    DWORD ?     	; /* data link type (LINKTYPE_*) */
pcap_file_header ends
	
; typedef enum {PCAP_D_INOUT = 0,PCAP_D_IN,PCAP_D_OUT} pcap_direction_t;

timeval struct
	tv_sec 	DWORD ?
	tv_usec DWORD ?
timeval ends

pcap_pkthdr struct
	 ts		timeval 	<>
	 caplen bpf_u_int32 ?
	 len 	bpf_u_int32 ?
pcap_pkthdr ends


pcap_stat struct
	ps_recv 	DWORD ? ;		/* number of packets received */
	ps_drop 	DWORD ? ;		/* number of packets dropped */
	ps_ifdrop 	DWORD ? ;		/* drops by interface XXX not yet supported */
	ps_capt 	DWORD ? ;		/* number of packets that are received by the application; please get rid off the Win32 ifdef */
	ps_sent 	DWORD ? ;		/* number of packets sent by the server on the network */
	ps_netdrop 	DWORD ? ;		/* number of packets lost on the network */
pcap_stat ends


pcap_stat_ex struct
	rx_packets     	DWORD ? ;       /* total packets received       */
	tx_packets     	DWORD ? ;       /* total packets transmitted    */
	rx_bytes    	DWORD ? ;       /* total bytes received         */
	tx_bytes		DWORD ? ;       /* total bytes transmitted      */
	rx_errors     	DWORD ? ;       /* bad packets received         */
	tx_errors     	DWORD ? ;       /* packet transmit problems     */
	rx_dropped     	DWORD ? ;		/* no space in Rx buffers       */
	tx_dropped     	DWORD ? ;       /* no space available for Tx    */
	multicast     	DWORD ? ;       /* multicast packets received   */
	collisions     	DWORD ? ;
	
	rx_length_errors	DWORD ? ;
	rx_over_errors     	DWORD ? ;   /* receiver ring buff overflow  */
	rx_crc_errors     	DWORD ? ;   /* recv'd pkt with crc error    */
	rx_frame_errors     DWORD ? ;   /* recv'd frame alignment error */
	rx_fifo_errors     	DWORD ? ;   /* recv'r fifo overrun          */
	rx_missed_errors	DWORD ? ;  	/* recv'r missed packet         */
	
	tx_aborted_errors	DWORD ? ;
	tx_carrier_errors	DWORD ? ;
	tx_fifo_errors		DWORD ? ;
	tx_heartbeat_errors	DWORD ? ;
	tx_window_errors	DWORD ? ;
pcap_stat_ex ends


pcap_if struct
	next 		pcap_if_t 		<>		;	
	_name 		DWORD 			? 		;	/* name to hand to "pcap_open_live()" */
	description DWORD 			? 		;	/* textual description of interface, or NULL */
	address 	pcap_addr_t		<>
	flags 		bpf_u_int32 	?		;   /* PCAP_IF_ interface flags */
pcap_if ends 

udp_header struct
    sport 	Word 			?	;          // Source port
    dport 	Word 			?	;          // Destination port
    len		Word 			?	; 		   // Datagram length
    crc		Word 			?	;          // Checksum
udp_header ends 


pcap_addr struct
	next  		pcap_addr_t	<>
	adress 		sockaddr 	<>	;	/* address */
	netmask 		sockaddr 	<>	;	/* netmask for that address */
	broadaddr 	sockaddr 	<>	;	/* broadcast address for that address */
	dstaddr 		sockaddr 	<>	;	/* P2P destination address for that address */
pcap_addr ends 	

; typedef void (*pcap_handler)(u_char *, const struct pcap_pkthdr *,const u_char *);

;pcap_handler	EQU DWORD + SIZEOFtimeval + SIZEOF bpf_u_int32 + SIZEOF bpf_u_int32 + DWORD
;void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

;pcap_handler 	EQU param:DWORD,header:pcap_pkthdr,pkt_data:DWORD

bpf_program struct 
       bf_len 	DWORD ?		;
       bf_insns bpf_insn <>	;
bpf_program ends


;bpf_insn struct
;	code DWORD 	?		;
;	jt 	DWORD 	?		;
;	jf 	DWORD 	?		;
;	k 	DWORD 	?		;
;bpf_insn ends

pcap_sf struct
        rfile			DWORD ? ;
        swapped			DWORD ? ;
        hdrsize			DWORD ? ;
        version_major	DWORD ? ;
        version_minor	DWORD ? ;
        base			DWORD ? ;
pcap_sf ends 


pcap_md struct
        stat 		pcap_stat <>	;
        use_bpf		DWORD ? ;            /* using kernel filter */
        TotPkts		DWORD ? ;        /* can't oflow for 79 hrs on ether */
        TotAccepted	DWORD ? ;    /* count accepted by filter */
        TotDrops	DWORD ? ;       /* count of dropped packets */
        TotMissed	DWORD ? ;      /* missed by i/f during this run */
        OrigMissed	DWORD ? ;     /* missed by i/f before this run */
pcap_md ends


pcap struct
        fd			DWORD ? 	;
        snapshot	DWORD ? 	;
        linktype	DWORD ? 	;
        tzoff		DWORD ? 	;		/* timezone offset */
        _offset		DWORD ? 	;		/* offset for proper alignment */  ????? Problème avec le nom "offset" impossible de l'utiliser
        						;		offset => _offset
        sf 			pcap_sf <>	;
        md 			pcap_md <>	;

	;	Read buffer.
        bufsize		DWORD ? ;
        buffer		DWORD ? ;
        _bp			DWORD ? ;			????? Problème avec le nom "bp" impossible d'utiliser le nom de registre ! bp => _bp
        cc			DWORD ? ;
        pkt			DWORD ? ;
        fcode bpf_program <>;
        errbuf db [PCAP_ERRBUF_SIZE] dup (?);
pcap ends


pcap_timeval struct
     tv_sec 	bpf_int32	?;          /* seconds */
     tv_usec 	bpf_int32  	?;          /* microseconds */
pcap_timeval ends


pcap_sf_pkthdr struct
    ts 		pcap_timeval 	<>	;     		/* time stamp */
    caplen 	bpf_u_int32 	? 	;          	/* length of portion present */
    len 	bpf_u_int32		?	;	        /* length this packet (off wire) */
pcap_sf_pkthdr ends


tm struct
	tm_sec		DWORD ?	;       /* Seconds: 0-59 (K&R says 0-61?) */
	tm_min		DWORD ?	;       /* Minutes: 0-59 */
	tm_hour		DWORD ?	;       /* Hours since midnight: 0-23 */
	tm_mday		DWORD ?	;		/* Day of the month: 1-31 */
	tm_mon		DWORD ?	;		/* Months *since* january: 0-11 */
	tm_year		DWORD ?	;       /* Years since 1900 */
	tm_wday		DWORD ?	;       /* Days since Sunday (0-6) */
	tm_yday		DWORD ?	;       /* Days since Jan. 1: 0-365 */
	tm_isdst	DWORD ?	;   /* +1 Daylight Savings Time, 0 No DST,
						;* -1 don't know */
tm ends


pcap_sf_patched_pkthdr struct
    ts pcap_timeval 	<>		;     /* time stamp */
    caplen bpf_u_int32 	?		;         /* length of portion present */
    len bpf_u_int32 	?		;            /* length this packet (off wire) */
    index 				DWORD ? ;
    protocol 			WORD  ?	;
    pkt_type 			BYTE  ?	;
pcap_sf_patched_pkthdr ends


	pcap_lookupdev 		PROTO STDCALL char:DWORD
	pcap_lookupnet 		PROTO STDCALL char:DWORD, bpf_u_int32:DWORD, bpf_u_int32:DWORD, char:DWORD
	pcap_open_live 		PROTO STDCALL char:DWORD, int1:DWORD, int2:DWORD, int3:DWORD, char:DWORD
	pcap_open_dead 		PROTO STDCALL int1:DWORD, int2:DWORD
	pcap_open_offline 	PROTO STDCALL char:DWORD, char:DWORD
	pcap_fopen_offline 	PROTO STDCALL FILE:DWORD, char:DWORD
	pcap_close 			PROTO STDCALL pcap_t:DWORD;
	pcap_loop			PROTO STDCALL pcap_t:DWORD, int1:DWORD, pcap_handler:DWORD, u_char:DWORD
	pcap_dispatch		PROTO STDCALL pcap_t:DWORD, int1:DWORD, pcap_handler:DWORD, u_char:DWORD
	pcap_next 			PROTO STDCALL pcap_t:DWORD, lppcap_pkthdr:DWORD
	;pcap_next_ex 		PROTO STDCALL pcap_t:DWORD, lppcap_pkthdr:DWORD, u_char:DWORD
	pcap_next_ex 		PROTO STDCALL p:DWORD, pkt_header:DWORD,pkt_data:DWORD
	pcap_breakloop 		PROTO STDCALL pcap_t:DWORD
	pcap_stats 			PROTO STDCALL pcap_t:DWORD, pcap_stat:DWORD
	pcap_setfilter 		PROTO STDCALL pcap_t:DWORD, bpf_program:DWORD
	pcap_setdirection 	PROTO STDCALL pcap_t:DWORD, pcap_direction_t:DWORD
	pcap_getnonblock 	PROTO STDCALL pcap_t:DWORD, char:DWORD
	pcap_setnonblock 	PROTO STDCALL pcap_t:DWORD, int1:DWORD, char:DWORD
	pcap_perror 		PROTO STDCALL pcap_t:DWORD, char:DWORD
	pcap_inject 		PROTO STDCALL pcap_t:DWORD, void:DWORD, size_t:DWORD
	pcap_sendpacket 	PROTO STDCALL pcap_t:DWORD, u_char:DWORD, int1:DWORD
	pcap_strerror 		PROTO STDCALL int1:DWORD
	pcap_geterr 		PROTO STDCALL pcap_t:DWORD
	pcap_compile 		PROTO STDCALL pcap_t:DWORD, bpf_program:DWORD, char:DWORD, int1:DWORD,bpf_u_int32:DWORD
	pcap_compile_nopcap PROTO STDCALL int1:DWORD, int2:DWORD, bpf_program:DWORD,char:DWORD, int3:DWORD, bpf_u_int32:DWORD
	pcap_freecode 		PROTO STDCALL bpf_program:DWORD
	pcap_datalink 		PROTO STDCALL pcap_t:DWORD
	pcap_list_datalinks PROTO STDCALL pcap_t:DWORD, int1:DWORD
	pcap_set_datalink 	PROTO STDCALL pcap_t:DWORD, int1:DWORD
	pcap_datalink_name_to_val 	PROTO STDCALL char:DWORD
	pcap_datalink_val_to_name 	PROTO STDCALL int1:DWORD
	pcap_datalink_val_to_description 	PROTO STDCALL int1:DWORD 
	pcap_snapshot 			PROTO STDCALL pcap_t:DWORD 
	pcap_is_swapped 		PROTO STDCALL pcap_t:DWORD
	pcap_major_version 		PROTO STDCALL pcap_t:DWORD
	pcap_minor_version 		PROTO STDCALL pcap_t:DWORD
	pcap_file 				PROTO STDCALL pcap_t:DWORD
	pcap_fileno 			PROTO STDCALL pcap_t:DWORD
	pcap_dump_open 			PROTO STDCALL pcap_t:DWORD, char:DWORD
	pcap_dump_fopen 		PROTO STDCALL pcap_t:DWORD, FILE:DWORD
	pcap_dump_file 			PROTO STDCALL pcap_dumper_t:DWORD
	pcap_dump_ftell 		PROTO STDCALL pcap_dumper_t:DWORD
	pcap_dump_flush 		PROTO STDCALL pcap_dumper_t:DWORD
	pcap_dump_close 		PROTO STDCALL pcap_dumper_t:DWORD
	pcap_dump 				PROTO STDCALL u_char:DWORD, lppcap_pkthdr:DWORD, u_char:DWORD
	pcap_findalldevs 		PROTO STDCALL pcap_if_t:DWORD, char:DWORD
	pcap_findalldevs_ex		PROTO STDCALL :DWORD, :DWORD, :DWORD, :DWORD
	pcap_freealldevs 		PROTO STDCALL pcap_if_t:DWORD
	bpf_filter 				PROTO STDCALL bpf_insn:DWORD, u_char:DWORD, u_int:DWORD, u_int:DWORD
	bpf_validate 			PROTO STDCALL bpf_insn:DWORD,len:DWORD
	bpf_image 				PROTO STDCALL bpf_insn:DWORD, int1:DWORD
	bpf_dump 				PROTO STDCALL bpf_program:DWORD, int1:DWORD
	pcap_setbuff			PROTO STDCALL pcap_t:DWORD, dim:DWORD
	pcap_setmode 			PROTO STDCALL pcap_t:DWORD, mode:DWORD
	pcap_setmintocopy 		PROTO STDCALL pcap_t:DWORD, size1:DWORD
	pcap_stats_ex 			PROTO STDCALL pcap_t:DWORD,pcap_stat_ex:DWORD
	pcap_set_wait			PROTO STDCALL pcap_t:DWORD, void:DWORD, int1:DWORD
	pcap_mac_packets 		PROTO STDCALL void:DWORD
	pcap_get_selectable_fd 	PROTO STDCALL pcap_t:DWORD

	yylex 					PROTO STDCALL void:DWORD
	pcap_offline_read 		PROTO STDCALL pcap_t:DWORD, int1:DWORD, Phandler:DWORD, u_char:DWORD
	pcap_read 				PROTO STDCALL pcap_t:DWORD,cnt:DWORD, Phandler:DWORD, u_char:DWORD
	
	; #define strlcpy(x, y, z) \(strncpy((x), (y), (z)), \((z) <= 0 ? 0 : ((x)[(z) - 1] = '\0')), \strlen((y)))
	
	pcap_fddipad 			PROTO STDCALL 
	install_bpf_program 	PROTO STDCALL pcap_t:DWORD, bpf_program:DWORD

