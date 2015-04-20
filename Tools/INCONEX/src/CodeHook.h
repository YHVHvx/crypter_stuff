
#ifndef __CodeHook_h__
#define __CodeHook_h__

#include <windows.h>
#include "DynamicStructChain.h"
#include "VMMStuff.h"

//
// constants
//
#define LOC_REDIRECT_INSTR_LEN   5 + 5
//#define TARGET_INT_FOR_R0_SWITCH DWORD(4)
#define SIZEOF_PUSHFD_STRUCT     4

//
// types
//

//
// The user defined handler should return TRUE if the location
// should be executed.
// Order:
// - rewrite orginal bytes at the hooked location
// - call the user defined handler
// - if user defined handler returned TRUE, hooked location is executed
// - eventually execution of the location
// - if user set bRehook == TRUE then the location is rehooked
//
typedef BOOL (__stdcall* procLocHookCallBack)(struct _CH_LOC_HOOK_CALLBACK_INFO *pinfo);

//
// structures
//
#pragma pack(1)
typedef struct _CH_LOC_HOOK
{
	void*                 pHookAddr;
	BYTE                  byOrgBytes[LOC_REDIRECT_INSTR_LEN];
	procLocHookCallBack   handler;
} CH_LOC_HOOK, *PCH_LOC_HOOK;

typedef struct _CH_LOC_HOOK_CALLBACK_INFO
{
	IN  DWORD             cb;
	IN  void*             pHookedLoc;
	IN  BYTE              byOrgBytes[LOC_REDIRECT_INSTR_LEN];
	OUT BOOL              bRehook;
} CH_LOC_HOOK_CALLBACK_INFO, *PCH_LOC_HOOK_CALLBACK_INFO;

typedef struct PUSHA_STRUCT
{
	DWORD                  _EDI;
	DWORD                  _ESI;
	DWORD                  _EBP;
	DWORD                  _ESP;
	DWORD                  _EBX;
	DWORD                  _EDX;
	DWORD                  _ECX;
	DWORD                  _EAX;
} PUSHA_STRUCT, *PPUSHA_STRUCT;
#pragma pack()

//
// macros
//
#define _IsNT (BOOL)(GetVersion() < 0x80000000 ? TRUE : FALSE)

//
// CodeHook class
//
class CodeHook
{
public:
	CodeHook();
	~CodeHook();
    BOOL                  InstallLocationHook(void* pAddr, procLocHookCallBack handler);
	BOOL                  DeinstallLocationHook(void* pAddr);
	static BOOL           ObtainWriteAccessAtLocation(void* pAddr, DWORD dwc);
	static BOOL           RewriteOriginalBytes(PCH_LOC_HOOK phook);
	static BOOL           AssemblePushDW(void* pAddr, DWORD dwPushVal);
	static BOOL           AssembleJumpLong(void* pAddr, DWORD dwJmpTarget);
	static LONG           ObtainWriteAccessInSharedArea9x(void* pAddr, DWORD dwc);

private:
//	void*                 m_pVxDCall4;
//	void                  EnterRing09x();
//	void                  LeaveRing09x();

};

typedef CodeHook *PCodeHook;

//
// exported symbols
//
//extern DynamicStructChain    *g_pdscHookStructs;

#endif // __CodeHook_h__