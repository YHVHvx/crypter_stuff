;  ; ===========================================
;  ; packet.inc copyright MASM32 1998 - 2003
;  ; ===========================================
;
;;PACKET_DllMain PROTO :DWORD,:DWORD,:DWORD
;
;;BOOLEAN PacketGetAdapterNames(PTSTR pStr,PULONG  BufferSize)
;PacketGetAdapterNames PROTO STDCALL :DWORD, :DWORD
;
;;LPADAPTER PacketOpenAdapter(LPTSTR AdapterName)
;PacketOpenAdapter PROTO STDCALL :DWORD 
;
;;LPPACKET PacketAllocatePacket(void)
;PacketAllocatePacket PROTO STDCALL
;
;;VOID PacketInitPacket(LPPACKET lpPacket,PVOID  Buffer,UINT  Length)
;PacketInitPacket PROTO STDCALL :DWORD, :DWORD, :DWORD
;
;;VOID PacketFreePacket(LPPACKET lpPacket)
;PacketFreePacket PROTO STDCALL :DWORD
;
;;BOOLEAN PacketSetNumWrites(LPADAPTER AdapterObject,int nwrites)
;PacketSetNumWrites PROTO STDCALL :DWORD, :DWORD
;
;;BOOLEAN PacketSendPacket(LPADAPTER AdapterObject,LPPACKET pPacket,BOOLEAN Sync);
;PacketSendPacket PROTO STDCALL :DWORD, :DWORD, :DWORD
;
;;VOID PacketCloseAdapter(LPADAPTER lpAdapter)
;PacketCloseAdapter PROTO STDCALL :DWORD




PacketGetVersion 			PROTO STDCALL 
PacketGetDriverVersion 		PROTO STDCALL 
PacketSetMinToCopy 			PROTO STDCALL AdapterObject:DWORD,nbytes:DWORD

PacketSetNumWrites 			PROTO STDCALL AdapterObject:DWORD,nwrites:DWORD
PacketSetMode 				PROTO STDCALL AdapterObject:DWORD,mode:DWORD
PacketSetReadTimeout 		PROTO STDCALL AdapterObject:DWORD,timeout:DWORD
PacketSetBpf 	   			PROTO STDCALL AdapterObject:DWORD,bpf_program:DWORD
PacketSetLoopbackBehavior 	PROTO STDCALL AdapterObject:DWORD,LoopbackBehavior:DWORD
PacketSetSnapLen 			PROTO STDCALL AdapterObject:DWORD,snaplen:DWORD
PacketGetStats 				PROTO STDCALL AdapterObject:DWORD,bpf_stat:DWORD
PacketGetStatsEx 			PROTO STDCALL AdapterObject:DWORD,bpf_stat:DWORD
PacketSetBuff 				PROTO STDCALL AdapterObject:DWORD,dim:DWORD
PacketGetNetType 			PROTO STDCALL AdapterObject:DWORD,NetType:DWORD
PacketOpenAdapter 			PROTO STDCALL AdapterName:DWORD
PacketSendPacket 			PROTO STDCALL AdapterObject:DWORD,pPacket:DWORD,Sync:DWORD
PacketSendPackets 			PROTO STDCALL AdapterObject:DWORD,PacketBuff:DWORD,SizeBuff:DWORD,Sync:DWORD
PacketAllocatePacket 		PROTO STDCALL
PacketInitPacket 			PROTO STDCALL lpPacket:DWORD,Buffer:DWORD,LengthBuff:DWORD
PacketFreePacket 			PROTO STDCALL lpPacket:DWORD
PacketReceivePacket 		PROTO STDCALL AdapterObject:DWORD,lpPacket:DWORD,Sync:DWORD
PacketSetHwFilter 			PROTO STDCALL AdapterObject:DWORD,Filter:DWORD
PacketGetAdapterNames 		PROTO STDCALL pStr:DWORD,BufferSize:DWORD
PacketGetNetInfoEx 			PROTO STDCALL AdapterName:DWORD,npf_if_addr:DWORD,NEntries:DWORD
PacketRequest				PROTO STDCALL AdapterObject:DWORD,Set:DWORD,OidData:DWORD
PacketGetReadEvent 			PROTO STDCALL AdapterObject:DWORD
PacketSetDumpName 			PROTO STDCALL AdapterObject:DWORD,nameDump:DWORD,len:DWORD
PacketSetDumpLimits 		PROTO STDCALL AdapterObject:DWORD,maxfilesize:DWORD, maxnpacks:DWORD
PacketIsDumpEnded 			PROTO STDCALL AdapterObject:DWORD,sync:DWORD
PacketStopDriver 			PROTO
PacketCloseAdapter 			PROTO STDCALL lpAdapter:DWORD
PacketStartOem 				PROTO STDCALL errorString:DWORD,errorStringLength:DWORD
PacketGetAirPcapHandle 		PROTO STDCALL AdapterObject:DWORD
QueryWinPcapRegistryStringA PROTO STDCALL SubKeyName:DWORD, Value:DWORD, pValueLen:DWORD, DefaultVal:DWORD
QueryWinPcapRegistryStringW PROTO STDCALL SubKeyName:DWORD,Value:DWORD,pValueLen:DWORD,DefaultVal:DWORD
GetARPReply					PROTO STDCALL lpPacketReply:DWORD, iptarget:DWORD, remotemac:DWORD

MAX_LINK_NAME_LENGTH equ 64

;ADAPTER struct 
;	hFile 			dd ?				
;	SymbolicLink 	db MAX_LINK_NAME_LENGTH dup(?) 
;	NumWrites 		dw ?							
;	ReadEvent 		dd ?								
;	ReadTimeOut 	dw ?			
;ADAPTER ends

ADAPTER   struct     
	hFile   			dd   ?     
	SymbolicLink   		db   MAX_LINK_NAME_LENGTH   dup(?)     
	NumWrites   		dd   ?     
	ReadEvent   		dd   ?     
	ReadTimeOut   		dd   ?     
ADAPTER   ends   
LPADAPTER typedef ptr ADAPTER


PACKET struct   
	hEvent 			dd ?		
	OverLapped 		OVERLAPPED <>	
	Buffer 			PVOID ?		
	Length_ 		dw ?	
	ulBytesReceived dd ?	
	bIoComplete 	BOOLEAN ?     	
PACKET ends
LPPACKET typedef ptr PACKET


PACKET_MODE_CAPT 		EQU 0x0 			; Capture mode
PACKET_MODE_STAT 		EQU 0x1 			; Statistical mode
PACKET_MODE_MON 		EQU 0x2 			; Monitoring mode
PACKET_MODE_DUMP 		EQU 0x10			; Dump mode

FILE_DEVICE_PROTOCOL 	EQU 0x8000

pBIOCSETBUFFERSIZE 		EQU 9592			; IOCTL code: set kernel buffer size.
pBIOCSETF 				EQU 9030			; IOCTL code: set packet filtering program.
pBIOCGSTATS 			EQU 9031			; IOCTL code: get the capture stats.
pBIOCSRTIMEOUT 			EQU 7416		   	; IOCTL code: set the read timeout.
pBIOCSMODE 				EQU 7412			; IOCTL code: set working mode.
pBIOCSWRITEREP 			EQU 7413			; IOCTL code: set number of physical repetions of every packet written by the app.
pBIOCSMINTOCOPY 		EQU 7414			; IOCTL code: set minimum amount of data in the kernel buffer that unlocks a read call.
pBIOCSETOID 			EQU 2147483648U		; IOCTL code: set an OID value.
pBIOCQUERYOID 			EQU 2147483652U		; IOCTL code: get an OID value.
pATTACHPROCESS 			EQU 7117			; IOCTL code: attach a process to the driver. Used in Win9x only.
pDETACHPROCESS 			EQU 7118			; IOCTL code: detach a process from the driver. Used in Win9x only.
pBIOCSETDUMPFILENAME 	EQU 9029			; IOCTL code: set the name of a the file used by kernel dump mode.
pBIOCEVNAME 			EQU 7415			; IOCTL code: get the name of the event that the driver signals when some data is present in the buffer.
pBIOCSENDPACKETSNOSYNC 	EQU 9032			; IOCTL code: Send a buffer containing multiple packets to the network, ignoring the timestamps associated with the packets.
pBIOCSENDPACKETSSYNC 	EQU 9033			; IOCTL code: Send a buffer containing multiple packets to the network, respecting the timestamps associated with the packets.
pBIOCSETDUMPLIMITS 		EQU 9034			; IOCTL code: Set the dump file limits. See the PacketSetDumpLimits() function.
pBIOCISDUMPENDED 		EQU 7411			; IOCTL code: Get the status of the kernel dump process. See the PacketIsDumpEnded() function.
pBIOCISETLOBBEH 		EQU 7410			; IOCTL code: Set the loopback behavior of the driver with packets sent by itself: capture or drop.
pBIOCSETEVENTHANDLE 	EQU 7920			; IOCTL code: Passes the read event HANDLE allocated by the user (packet.dll) to the kernel level driver.
pBIOCSTIMEZONE 			EQU 7471			; IOCTL code: set time zone. Used in Win9x only.

NdisMediumNull 			EQU -1				; Custom linktype: NDIS doesn't provide an equivalent
NdisMediumCHDLC 		EQU -2				; Custom linktype: NDIS doesn't provide an equivalent
NdisMediumPPPSerial 	EQU -3				; Custom linktype: NDIS doesn't provide an equivalent
NdisMediumBare80211 	EQU -4				; Custom linktype: NDIS doesn't provide an equivalent
NdisMediumRadio80211	EQU -5				; Custom linktype: NDIS doesn't provide an equivalent

NDIS_PACKET_TYPE_DIRECTED		EQU		1
NDIS_PACKET_TYPE_MULTICAST		EQU		2
NDIS_PACKET_TYPE_ALL_MULTICAST	EQU		4
NDIS_PACKET_TYPE_BROADCAST		EQU		8
NDIS_PACKET_TYPE_PROMISCUOUS	EQU		020h



NPF_DISABLE_LOOPBACK  	EQU 1	 			; Drop the packets sent by the NPF driver
NPF_ENABLE_LOOPBACK	  	EQU 2				; Capture the packets sent by the NPF driver

NetType struct   
	LinkType 	UINT 		?		
	LinkSpeed 	ULONGLONG 	?
NetType ends
LNetType typedef ptr NetType

;bpf_program struct   
;	bf_len 		UINT 		?		
;	bpf_insn1	bpf_insn 	<>
;bpf_program ends
;Lbpf_program typedef ptr bpf_program

bpf_insn struct   
	bf_len 	UINT 	?		
	code 	USHORT	?
	jt		UCHAR 	?						; Jump if true
	jf		UCHAR 	?						; Jump if false
	k 		DWORD 	?						;Generic field used for various purposes.
bpf_insn ends
Lbpf_insn typedef ptr bpf_insn




bpf_stat struct   
	bs_recv 	DWORD ?		; Number of packets that the driver received from the network adapter 
							; from the beginning of the current capture. This value includes the packets 
							; lost by the driver.
	bs_drop 	DWORD ?		; number of packets that the driver lost from the beginning of a capture. 
							; Basically, a packet is lost when the the buffer of the driver is full. 
							; In this situation the packet cannot be stored and the driver rejects it.
	ps_ifdrop 	DWORD ?		; drops by interface. XXX not yet supported
	bs_capt 	DWORD ?		; number of packets that pass the filter, find place in the kernel buffer and
							; thus reach the application.
bpf_stat ends
Lbpf_stat typedef ptr bpf_stat


bpf_hdr struct   
	bh_tstamp	timeval <>		; The timestamp associated with the captured packet. 
								; It is stored in a TimeVal structure.
	bh_caplen	DWORD ?			; Length of captured portion. The captured portion <b>can be different</b>
								; from the original packet, because it is possible (with a proper filter)
								; to instruct the driver to capture only a portion of the packets.
	bh_datalen	DWORD ?			; Original length of packet
	bh_hdrlen	DWORD ?				; Length of bpf header (this struct plus alignment padding). In some cases,
								; a padding could be added between the end of this structure and the packet
								; data for performance reasons. This filed can be used to retrieve the actual data 
								; of the packet.
bpf_hdr ends
Lbpf_hdr typedef ptr bpf_hdr

	
dump_bpf_hdr struct 
    ts timeval <>			; Time stamp of the packet
    caplen DWORD ?			; Length of captured portion. The captured portion can smaller than the 
							; the original packet, because it is possible (with a proper filter) to 
							; instruct the driver to capture only a portion of the packets. 
    len DWORD ?				; Length of the original packet (off wire).
dump_bpf_hdr ends
Ldump_bpf_hdr typedef ptr dump_bpf_hdr

;DOSNAMEPREFIX   TEXT("Packet_")	; Prefix added to the adapters device names to create the WinPcap devices
MAX_LINK_NAME_LENGTH 	EQU	64		; Maximum length of the devices symbolic links
NMAX_PACKET 			EQU 65535

;	
;	typedef struct npf_if_addr {
;		struct sockaddr_storage IPAddress;	///< IP address.
;		struct sockaddr_storage SubnetMask;	///< Netmask for that address.
;		struct sockaddr_storage Broadcast;	///< Broadcast address.
;	}npf_if_addr;
;	
;	
;	#define ADAPTER_NAME_LENGTH 256 + 12	///<  Maximum length for the name of an adapter. The value is the same used by the IP Helper API.
;	#define ADAPTER_DESC_LENGTH 128			///<  Maximum length for the description of an adapter. The value is the same used by the IP Helper API.
;	#define MAX_MAC_ADDR_LENGTH 8			///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.
;	#define MAX_NETWORK_ADDRESSES 16		///<  Maximum length for the link layer address of an adapter. The value is the same used by the IP Helper API.
;	
;	
;	typedef struct WAN_ADAPTER_INT WAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API
;	typedef WAN_ADAPTER *PWAN_ADAPTER; ///< Describes an opened wan (dialup, VPN...) network adapter using the NetMon API
;	
;	#define INFO_FLAG_NDIS_ADAPTER		0	///< Flag for ADAPTER_INFO: this is a traditional ndis adapter
;	#define INFO_FLAG_NDISWAN_ADAPTER	1	///< Flag for ADAPTER_INFO: this is a NdisWan adapter, and it's managed by WANPACKET
;	#define INFO_FLAG_DAG_CARD			2	///< Flag for ADAPTER_INFO: this is a DAG card
;	#define INFO_FLAG_DAG_FILE			6	///< Flag for ADAPTER_INFO: this is a DAG file
;	#define INFO_FLAG_DONT_EXPORT		8	///< Flag for ADAPTER_INFO: when this flag is set, the adapter will not be listed or openend by winpcap. This allows to prevent exporting broken network adapters, like for example FireWire ones.
;	#define INFO_FLAG_AIRPCAP_CARD		16	///< Flag for ADAPTER_INFO: this is an airpcap card
;	#define INFO_FLAG_NPFIM_DEVICE		32
;	/*!
;	  \brief Contains comprehensive information about a network adapter.
;	
;	  This structure is filled with all the accessory information that the user can need about an adapter installed
;	  on his system.
;	*/
;	typedef struct _ADAPTER_INFO  
;	{
;		struct _ADAPTER_INFO *Next;				///< Pointer to the next adapter in the list.
;		CHAR Name[ADAPTER_NAME_LENGTH + 1];		///< Name of the device representing the adapter.
;		CHAR Description[ADAPTER_DESC_LENGTH + 1];	///< Human understandable description of the adapter
;		UINT MacAddressLen;						///< Length of the link layer address.
;		UCHAR MacAddress[MAX_MAC_ADDR_LENGTH];	///< Link layer address.
;		NetType LinkLayer;						///< Physical characteristics of this adapter. This NetType structure contains the link type and the speed of the adapter.
;		INT NNetworkAddresses;					///< Number of network layer addresses of this adapter.
;		npf_if_addr *NetworkAddresses;			///< Pointer to an array of npf_if_addr, each of which specifies a network address of this adapter.
;		UINT Flags;								///< Adapter's flags. Tell if this adapter must be treated in a different way, using the Netmon API or the dagc API.
;	}
;	ADAPTER_INFO, *PADAPTER_INFO;
;	
;	/*!
;	  \brief Describes an opened network adapter.
;	
;	  This structure is the most important for the functioning of packet.dll, but the great part of its fields
;	  should be ignored by the user, since the library offers functions that avoid to cope with low-level parameters
;	*/
;	typedef struct _ADAPTER  { 
;		HANDLE hFile;				///< \internal Handle to an open instance of the NPF driver.
;		CHAR  SymbolicLink[MAX_LINK_NAME_LENGTH]; ///< \internal A string containing the name of the network adapter currently opened.
;		int NumWrites;				///< \internal Number of times a packets written on this adapter will be repeated 
;									///< on the wire.
;		HANDLE ReadEvent;			///< A notification event associated with the read calls on the adapter.
;									///< It can be passed to standard Win32 functions (like WaitForSingleObject
;									///< or WaitForMultipleObjects) to wait until the driver's buffer contains some 
;									///< data. It is particularly useful in GUI applications that need to wait 
;									///< concurrently on several events. In Windows NT/2000 the PacketSetMinToCopy()
;									///< function can be used to define the minimum amount of data in the kernel buffer
;									///< that will cause the event to be signalled. 
;		
;		UINT ReadTimeOut;			///< \internal The amount of time after which a read on the driver will be released and 
;									///< ReadEvent will be signaled, also if no packets were captured
;		CHAR Name[ADAPTER_NAME_LENGTH];
;		PWAN_ADAPTER pWanAdapter;
;		UINT Flags;					///< Adapter's flags. Tell if this adapter must be treated in a different way, using the Netmon API or the dagc API.
;	
;	#ifdef HAVE_AIRPCAP_API
;		PAirpcapHandle	AirpcapAd;
;	#endif // HAVE_AIRPCAP_API
;	
;	#ifdef HAVE_NPFIM_API
;		void* NpfImHandle;
;	#endif // HAVE_NPFIM_API
;	
;	#ifdef HAVE_DAG_API
;		dagc_t *pDagCard;			///< Pointer to the dagc API adapter descriptor for this adapter
;		PCHAR DagBuffer;			///< Pointer to the buffer with the packets that is received from the DAG card
;		struct timeval DagReadTimeout;	///< Read timeout. The dagc API requires a timeval structure
;		unsigned DagFcsLen;			///< Length of the frame check sequence attached to any packet by the card. Obtained from the registry
;		DWORD DagFastProcess;		///< True if the user requests fast capture processing on this card. Higher level applications can use this value to provide a faster but possibly unprecise capture (for example, libpcap doesn't convert the timestamps).
;	#endif // HAVE_DAG_API
;	}  ADAPTER, *LPADAPTER;
;	
;	/*!
;	  \brief Structure that contains a group of packets coming from the driver.
;	
;	  This structure defines the header associated with every packet delivered to the application.
;	*/
;	typedef struct _PACKET {  
;		HANDLE       hEvent;		///< \deprecated Still present for compatibility with old applications.
;		OVERLAPPED   OverLapped;	///< \deprecated Still present for compatibility with old applications.
;		PVOID        Buffer;		///< Buffer with containing the packets. See the PacketReceivePacket() for
;									///< details about the organization of the data in this buffer
;		UINT         Length;		///< Length of the buffer
;		DWORD        ulBytesReceived;	///< Number of valid bytes present in the buffer, i.e. amount of data
;										///< received by the last call to PacketReceivePacket()
;		BOOLEAN      bIoComplete;	///< \deprecated Still present for compatibility with old applications.
;	}  PACKET, *LPPACKET;
;	
;	/*!
;	  \brief Structure containing an OID request.
;	
;	  It is used by the PacketRequest() function to send an OID to the interface card driver. 
;	  It can be used, for example, to retrieve the status of the error counters on the adapter, its MAC address, 
;	  the list of the multicast groups defined on it, and so on.
;	*/
;	struct _PACKET_OID_DATA {
;	    ULONG Oid;					///< OID code. See the Microsoft DDK documentation or the file ntddndis.h
;									///< for a complete list of valid codes.
;	    ULONG Length;				///< Length of the data field
;	    UCHAR Data[1];				///< variable-lenght field that contains the information passed to or received 
;									///< from the adapter.
;	}; 
;	typedef struct _PACKET_OID_DATA PACKET_OID_DATA, *PPACKET_OID_DATA;
;	
;	#ifdef __cplusplus
;	extern "C" {
;	#endif
;	
;	
;	
