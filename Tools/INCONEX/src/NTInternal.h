/*

  All the stuff here is just a convertion of ELiCZ's
  undoc.zip/NtStruct.inc into C.

  yoda

*/

#if !defined(__NTInternal_h__)
#define __NTInternal_h__

#include <windows.h>
#include <Ntsecapi.h>

#pragma pack(1)

//
// constants
//

// PEB.dwFlags
#define INHERITED_ADDRESS_SPACE         0x00000001
#define READ_IMAGEFILE_EXEC_OPTIONS     0x00000100
#define BEING_DEBUGGED                  0x00010000

// PEB_LDR_DATA.Flags
#define LDR_INITIALIZED                 0x00000001

// LDR_ENTRY.Flags
#define LDRP_STATIC_LINK                0x00000002
#define LDRP_IMAGE_DLL                  0x00000004
#define LDRP_LOAD_IN_PROGRESS           0x00001000
#define LDRP_UNLOAD_IN_PROGRESS         0x00002000
#define LDRP_ENTRY_PROCESSED            0x00004000
#define LDRP_ENTRY_INSERTED             0x00008000
#define LDRP_CURRENT_LOAD               0x00010000
#define LDRP_FAILED_BUILTIN_LOAD        0x00020000
#define LDRP_DONT_CALL_FOR_THREADS      0x00040000
#define LDRP_PROCESS_ATTACH_CALLED      0x00080000
#define LDRP_DEBUG_SYMBOLS_LOADED       0x00100000
#define LDRP_IMAGE_NOT_AT_BASE          0x00200000
#define LDRP_WX86_IGNORE_MACHINETYPE    0x00400000

// PROCESS_PARAMETERS.Flags
#define PROCESS_PARAMETERS_NORMALIZED   0x00000001 // pointers in structure are absolute

//
// structures
//
typedef struct _PEB
{
	DWORD          dwFlags; // 00
	DWORD          Unknown04; // 04
	DWORD          ImageBaseAddress; // 08
	DWORD          PebLdrData; // 0C  == *PEB_LDR_DATA
	DWORD          ProcessParameters; // 10  == *PROCESS_PARAMETERS
	DWORD          SubSystemData; // 14  == 0
	DWORD          ProgramHeap; // 18
	DWORD          LockingContext; // 1C  == FastPebLock
	DWORD          LockRoutine; // 20  == RtlEnterCriticalSection
	DWORD          UnlockRoutine; // 24  == RtlLeaveCriticalSection
	DWORD          DirChange; // 28  == 1
	DWORD          Unknown2C; // 2C  == apfnDispatch
	DWORD          Unknown30; // 30  == 0
	DWORD          Unknown34; // 34  == 0
	DWORD          Unknown38; // 38  == 0
	DWORD          Unknown3C; // 3C  == 0
	DWORD          Unknown40; // 40  == 0
	DWORD          Unknown44; // 44  == 0
	DWORD          Unknown48; // 48  == 0
	DWORD          ProgramHeap02; // 4C
	DWORD          ProgramHeap02a; // 50
	DWORD          InProgramHeap02; // 54
	DWORD          AnsiCodePage; // 58
	DWORD          OemCodePage; // 5C
	DWORD          UnicodeCodePage; // 60
	DWORD          NumberProcessors; // 64
	DWORD          GlobalFlag; // 68
	DWORD          Unknown6C; // 6C  == 0
	DWORD          CritSectTimeout; // 70
	DWORD          Unknown74; // 74
	DWORD          HeapSegmentReserve;// 78
	DWORD          HeapSegementCommit; // 7C
	DWORD          HeapDeCommitTotalFreeTreshold; // 80  == 10000H
	DWORD          HeapDeCommitFreeBlockTreshold; // 84  == 1000H
	DWORD          Unknown88; // 88
	DWORD          Unknown8C; // 8C  == 386H
	DWORD          Unknown90; // 90  == RtlpProcessHeapsListBuffer
	DWORD          Unknown94; // 94
	DWORD          Unknown98; // 98  == 0
	DWORD          Unknown9C; // 9C  == 14H
	DWORD          UnknownA0; // A0  == LoaderLock
	DWORD          dwMajorVersion; // A4
	DWORD          dwMinorVersion; // A8
	WORD           dwBuildNumber; // AC
	WORD           CSDVersion; // AE
	DWORD          dwPlatformId; // B0
	DWORD          Subsystem; // B4
	DWORD          MajorSusbsytemVersion; // B8
	DWORD          MinorSusbsytemVersion; // BC
	DWORD          ProcessAffinityMask; // C0
	DWORD          UnknownC4[0454]; // C4
	DWORD          SessionId; // 1D4
	DWORD          Unknown1D8; // 1D8
	DWORD          Unknown1DC; // 1DC
	DWORD          Unknown1E0; // 1E0
	DWORD          Unknown1E4; // 1E4
} PEB, *PPEB;

typedef struct _PEB_LDR_DATA
{
	DWORD          cbsize; // 00 == 24H
	DWORD          Flags; // 04
	DWORD          Unknown8; // 08
	DWORD          InLoadOrderModuleListHead; // 0C
	DWORD          PreviousInLoadOrderLdrEntry; // 10
	DWORD          InMemoryOrderModuleListHead; // 14
	DWORD          PreviousInMemoryOrderLdrEntry; // 18
	DWORD          InInitializationOrderModuleListHead; // 1C
	DWORD          PreviousInInitializationOrderLdrEntry; // 20
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_ENTRY
{
	DWORD          NextInLoadOrderLdrEntry; // 00
	DWORD          PreviousInLoadOrderLdrEntry; // 04
	DWORD          NextInMemoryOrderLdrEntry; // 08
	DWORD          PreviousInMemoryOrderLdrEntry; // 0C
	DWORD          NextInInitializationOrderLdrEntry; // 10
	DWORD          PreviousInInitializationOrderLdrEntry; // 14
	DWORD          ModuleBase; // 18
	DWORD          EntryPoint; // 1C
	DWORD          ModuleSize; // 20
	UNICODE_STRING ModuleFileName; // 24
	UNICODE_STRING ModuleBaseName; // 2C
	DWORD          Flags; // 34
	WORD           LoadCount; // 38
	WORD           TlsIndex; // 3A
	DWORD          LdrpHashTableEntry0; // 3C
	DWORD          LdrpHashTableEntry1; // 40
	DWORD          TimeStamp; // 44
} LDR_ENTRY, *PLDR_ENTRY;

typedef struct _PROCESS_PARAMETERS
{
	DWORD          Unknown00; // 00 == 1000H
	DWORD          Unknown04; // 04
	DWORD          Flags; // 08
	DWORD          Unknown0C; // 0C
	DWORD          CsrConsoleInfo; // 10  for Csr calls
	DWORD          Unknown14; // 14
	DWORD          StdInputHandle; // 18
	DWORD          StdOutputHandle; // 1C
	DWORD          StdErrorHandle; // 20
	UNICODE_STRING CurrentDirectory; // 24
	DWORD          DirectoryFlags; // 2C   == 18H
	UNICODE_STRING SearchPath; // 30
	UNICODE_STRING ImagePath; // 38
	UNICODE_STRING CommandLine; // 40
	DWORD          Environment; // 48
	DWORD          Unknown4C; // 4C
	DWORD          Unknown50; // 50
	DWORD          Unknown54; // 54
	DWORD          Unknown58; // 58
	DWORD          Unknown5C; // 5C
    DWORD          Unknown60; // 60
	DWORD          Unknown64; // 64
	DWORD          Unknown68; // 68
	DWORD          Unknown6C; // 6C
	UNICODE_STRING WindowTitle; // 70
	UNICODE_STRING WindowStation; // 78
	UNICODE_STRING CommandLine2; // 80  ??
	DWORD          Unknown88[0x82]; // 88
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

#pragma pack()

#endif // __NTInternal_h__
