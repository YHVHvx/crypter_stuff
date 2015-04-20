#pragma once
#include <WinNT.h>

#pragma pack(push,1)
struct KUNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
};
#pragma pack(pop)


#pragma pack(push,1)
struct KSTRING {
	USHORT Length;
	USHORT MaximumLength;
	PCHAR Buffer;
};
#pragma pack(pop)


#pragma pack(push,1)
struct LDR_MODULE {
	_LIST_ENTRY		InLoadOrderModuleList;
	_LIST_ENTRY		InMemoryOrderModuleList;
	_LIST_ENTRY		InInitializationOrderModuleList;
	DWORD			BaseAddress;
	DWORD			EntryPoint;
	DWORD			SizeOfImage;
	KUNICODE_STRING	FullDllName;
	KUNICODE_STRING	BaseDllName;
	DWORD			Flags;
	SHORT			LoadCount;
	SHORT			TlsIndex;
	_LIST_ENTRY		HashTableEntry;
	ULONG			TimeDateStamp;
};
#pragma pack(pop)

#pragma pack(push,1)
struct KPEB_LDR_DATA{
/*+0x000*/	DWORD	Length;						//Uint4B
/*+0x004*/	DWORD	Initialized;				//UChar
/*+0x008*/	DWORD	SsHandle;					//Ptr32 Void
/*+0x00c*/	_LIST_ENTRY InLoadOrderModuleList;	//_LIST_ENTRY 
/*+0x014*/	_LIST_ENTRY InMemoryOrderModuleList;//_LIST_ENTRY
/*+0x01c*/	_LIST_ENTRY InInitializationOrderModuleList;//_LIST_ENTRY
/*+0x024*/	DWORD	EntryInProgress;			//Ptr32 Void
};
#pragma pack(pop)


#pragma pack(push,1)
struct KRTL_USER_PROCESS_PARAMETERS{
/*+0x000*/	DWORD	MaximumLength;	//Uint4B
/*+0x004*/	DWORD	Length;			//Uint4B
/*+0x008*/	DWORD	Flags;			//Uint4B
/*+0x00c*/	DWORD	DebugFlags;		//Uint4B
/*+0x010*/	DWORD	ConsoleHandle;	//Ptr32 Void
/*+0x014*/	DWORD	ConsoleFlags;	//Uint4B
/*+0x018*/	DWORD	StandardInput;	//Ptr32 Void
/*+0x01c*/	DWORD	StandardOutput;	//Ptr32 Void
/*+0x020*/	DWORD	StandardError;	//Ptr32 Void
/*+0x024*/	DWORD	reserved[3];	//CurrentDirectory;//_CURDIR
/*+0x030*/	KUNICODE_STRING DllPath;//_UNICODE_STRING
/*+0x038*/	KUNICODE_STRING ImagePathName;//_UNICODE_STRING
/*+0x040*/	KUNICODE_STRING CommandLine;//_UNICODE_STRING
/*+0x048*/	DWORD	Environment;	//Ptr32 Void
/*+0x04c*/	DWORD	StartingX;		//Uint4B
/*+0x050*/	DWORD	StartingY;		//Uint4B
/*+0x054*/	DWORD	CountX;			//Uint4B
/*+0x058*/	DWORD	CountY;			//Uint4B
/*+0x05c*/	DWORD	CountCharsX;	//Uint4B
/*+0x060*/	DWORD	CountCharsY;	//Uint4B
/*+0x064*/	DWORD	FillAttribute;	//Uint4B
/*+0x068*/	DWORD	WindowFlags;	//Uint4B
/*+0x06c*/	DWORD	ShowWindowFlags;//Uint4B
/*+0x070*/	KUNICODE_STRING WindowTitle;//_UNICODE_STRING
/*+0x078*/	KUNICODE_STRING DesktopInfo;//_UNICODE_STRING
/*+0x080*/	KUNICODE_STRING ShellInfo;//_UNICODE_STRING
/*+0x088*/	KUNICODE_STRING RuntimeData;//_UNICODE_STRING
//+0x090 CurrentDirectores : [32] _RTL_DRIVE_LETTER_CURDIR
};
#pragma pack(pop)

#pragma pack(push,1)
struct KPEB{//xpsp2
/*+0x000*/	BYTE	InheritedAddressSpace;		//UChar
/*+0x001*/	BYTE	ReadImageFileExecOptions;	//UChar
/*+0x002*/	BYTE	BeingDebugged;				//UChar
/*+0x003*/	BYTE	SpareBool;					//UChar
/*+0x004*/	DWORD	Mutant;						//Ptr32 Void
/*+0x008*/	DWORD	ImageBaseAddress;			//Ptr32 Void
/*+0x00c*/	KPEB_LDR_DATA*	Ldr;				//_PEB_LDR_DATA
/*+0x010*/	KRTL_USER_PROCESS_PARAMETERS*	ProcessParameters;			//Ptr32 _RTL_USER_PROCESS_PARAMETERS
/*+0x014*/	DWORD	SubSystemData;				//Ptr32 Void
/*+0x018*/	DWORD	ProcessHeap;				//Ptr32 Void
/*+0x01c*/	DWORD	FastPebLock;				//Ptr32 _RTL_CRITICAL_SECTION
/*+0x020*/	DWORD	FastPebLockRoutine;			//Ptr32 Void
/*+0x024*/	DWORD	FastPebUnlockRoutine;		//Ptr32 Void
/*+0x028*/	DWORD	EnvironmentUpdateCount;		//Uint4B
/*+0x02c*/	DWORD	KernelCallbackTable;		//Ptr32 Void
/*+0x030*/	DWORD	SystemReserved;				//[1] Uint4B
/*+0x034*/	DWORD	AtlThunkSListPtr32;			//Uint4B
/*+0x038*/	DWORD	FreeList;					//Ptr32 _PEB_FREE_BLOCK
/*+0x03c*/	DWORD	TlsExpansionCounter;		//Uint4B
/*+0x040*/	DWORD	TlsBitmap;					//Ptr32 Void
/*+0x044*/	DWORD	TlsBitmapBits[2];			//[2] Uint4B
/*+0x04c*/	DWORD	ReadOnlySharedMemoryBase;	//Ptr32 Void
/*+0x050*/	DWORD	ReadOnlySharedMemoryHeap;	//Ptr32 Void
/*+0x054*/	DWORD	ReadOnlyStaticServerData;	//Ptr32 Ptr32 Void
/*+0x058*/	DWORD	AnsiCodePageData;			//Ptr32 Void
/*+0x05c*/	DWORD	OemCodePageData;			//Ptr32 Void
/*+0x060*/	DWORD	UnicodeCaseTableData;		//Ptr32 Void
/*+0x064*/	DWORD	NumberOfProcessors;			//Uint4B
/*+0x068*/	DWORD	NtGlobalFlag[2];			//Uint4B
/*+0x070*/	DWORD	CriticalSectionTimeout[2];	//_LARGE_INTEGER
/*+0x078*/	DWORD	HeapSegmentReserve;			//Uint4B
/*+0x07c*/	DWORD	HeapSegmentCommit;			//Uint4B
/*+0x080*/	DWORD	HeapDeCommitTotalFreeThreshold;	//Uint4B
/*+0x084*/	DWORD	HeapDeCommitFreeBlockThreshold;//Uint4B
/*+0x088*/	DWORD	NumberOfHeaps;				//Uint4B
/*+0x08c*/	DWORD	MaximumNumberOfHeaps;		//Uint4B
/*+0x090*/	DWORD	ProcessHeaps;				//Ptr32 Ptr32 Void
/*+0x094*/	DWORD	GdiSharedHandleTable;		//Ptr32 Void
/*+0x098*/	DWORD	ProcessStarterHelper;		//Ptr32 Void
/*+0x09c*/	DWORD	GdiDCAttributeList;			//Uint4B
/*+0x0a0*/	DWORD	LoaderLock;					//Ptr32 Void
/*+0x0a4*/	DWORD	OSMajorVersion;				//Uint4B
/*+0x0a8*/	DWORD	OSMinorVersion;				//Uint4B
/*+0x0ac*/	WORD	OSBuildNumber;				//Uint2B
/*+0x0ae*/	WORD	OSCSDVersion;				//Uint2B
/*+0x0b0*/	DWORD	OSPlatformId;				//Uint4B
/*+0x0b4*/	DWORD	ImageSubsystem;				//Uint4B
/*+0x0b8*/	DWORD	ImageSubsystemMajorVersion;	//Uint4B
/*+0x0bc*/	DWORD	ImageSubsystemMinorVersion;	//Uint4B
/*+0x0c0*/	DWORD	ImageProcessAffinityMask;	//Uint4B
/*+0x0c4*/	DWORD	GdiHandleBuffer[34];		//[34] Uint4B
/*+0x14c*/	DWORD	PostProcessInitRoutine;		//Ptr32     void 
/*+0x150*/	DWORD	TlsExpansionBitmap;			//Ptr32 Void
/*+0x154*/	DWORD	TlsExpansionBitmapBits[32];	//[32] Uint4B
/*+0x1d4*/	DWORD	SessionId;					//Uint4B
/*+0x1d8*/	DWORD	AppCompatFlags[2];			//_ULARGE_INTEGER
/*+0x1e0*/	DWORD	AppCompatFlagsUser[2];		//_ULARGE_INTEGER
/*+0x1e8*/	DWORD	pShimData;					//Ptr32 Void
/*+0x1ec*/	DWORD	AppCompatInfo;				//Ptr32 Void
/*+0x1f0*/	DWORD	CSDVersion[2];				//_UNICODE_STRING
/*+0x1f8*/	DWORD	ActivationContextData;		//Ptr32 Void
/*+0x1fc*/	DWORD	ProcessAssemblyStorageMap;	//Ptr32 Void
/*+0x200*/	DWORD	SystemDefaultActivationContextData;//Ptr32 Void
/*+0x204*/	DWORD	SystemAssemblyStorageMap;	//Ptr32 Void
/*+0x208*/	DWORD	MinimumStackCommit;			//Uint4B
};
#pragma pack(pop)


typedef DWORD (__stdcall *PFN_RtlAnsiStringToUnicodeString)(KUNICODE_STRING* DestinationString, KSTRING* SourceString,BOOLEAN AllocateDestinationString);
typedef void (__stdcall *PFN_RtlFreeUnicodeString)(KUNICODE_STRING* UnicodeString);

//Prototypes
DWORD Init(char* , DWORD);

