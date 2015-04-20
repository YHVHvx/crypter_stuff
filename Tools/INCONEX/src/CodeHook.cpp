
#include "CodeHook.h"

//
// function prototypes
//
void CH_PremierHookHandler();

//
// global variables
//
DynamicStructChain    *g_pdscHookStructs;
DWORD                 g_dwOldIntHandler;

//
// Args:
// DWORD dwHookAddr - pushed on stack
//
void __declspec(naked) CH_PremierHookHandler()
{
	UINT                       i;
	PCH_LOC_HOOK               phook;
	CH_LOC_HOOK_CALLBACK_INFO  info;
	BOOL                       bUserRet;
	DWORD                      dwHookAddr;

	__asm
	{
//		INT     3
		PUSH    0                        // space needed to jump to target via RET
		PUSHAD
		PUSHFD
		SUB     EBP, 0x200               // make space for local vars
		PUSH    DWORD PTR [ESP + 0x20 + 4 + 4]
		POP     dwHookAddr
	}
	//
	// search fitting hook struct
	//
	if (!g_pdscHookStructs)
		goto RaiseExcpt;
	for (i = 0; i < g_pdscHookStructs->GetItemNum(); i++)
	{
		phook = (PCH_LOC_HOOK)g_pdscHookStructs->GetItem(i);
		if (!phook)
			continue;
		if ((DWORD)phook->pHookAddr == dwHookAddr)
		{
			//
			// found!
			//

			//
			// rewrite original bytes
			//
			if ( !CodeHook::RewriteOriginalBytes(phook) )
				break;

			//
			// fill information structure and call user handler
			//
			info.cb          = sizeof(info);
			memcpy(
				&info.byOrgBytes[0],
				&phook->byOrgBytes[0],
				sizeof(info.byOrgBytes));
			info.pHookedLoc  = phook->pHookAddr;
			info.bRehook     = FALSE;

			//
			// call user handler
			//
			bUserRet = phook->handler(&info);

			//
			// handle info.bRehook
			//

			// TODO

			//
			// execute hooked location
			//
			if (bUserRet == TRUE)
			{
				DWORD dwJumpTarget = (DWORD)phook->pHookAddr;
				__asm
				{
					PUSH    dwJumpTarget
					POP     DWORD PTR [ESP + 0x20 + 4] // pop ret value
					POPFD
					POPAD
					RET     // jump via ret
				}
			}			
		}
	}

RaiseExcpt:
	// ... this hook should never be reached !
	// -> raise an exception
	RaiseException(
		EXCEPTION_NONCONTINUABLE_EXCEPTION,
		EXCEPTION_NONCONTINUABLE_EXCEPTION,
		0,
		NULL);
}

CodeHook::CodeHook()
{
	//
	// init some vars
	//
	g_pdscHookStructs = NULL;

}

CodeHook::~CodeHook()
{
	// cleanup
	if (g_pdscHookStructs)
	{
		g_pdscHookStructs->Free();
	}
}

//
// Returns:
// FALSE    if there's already a location there or some bytes later
//          later hooked or the hook could not be installed
//
BOOL CodeHook::InstallLocationHook(void* pAddr,
								   procLocHookCallBack handler)
{
	CH_LOC_HOOK  hook;
	BOOL         bRet;

	// get access there
	ObtainWriteAccessAtLocation(pAddr, LOC_REDIRECT_INSTR_LEN);

	// fill CH_LOC_HOOK struct
	memcpy(
		&hook.byOrgBytes,
		pAddr,
		LOC_REDIRECT_INSTR_LEN);
	hook.pHookAddr = pAddr;
	hook.handler   = handler;

	// install redirection code there
//	__asm INT 3
	if (!_IsNT)
		if ( !ObtainWriteAccessInSharedArea9x(pAddr, LOC_REDIRECT_INSTR_LEN) )
			return FALSE; // ERR
	bRet = TRUE;
	bRet &= AssemblePushDW(pAddr, (DWORD)pAddr);
	bRet &= AssembleJumpLong(
		MakePtr(PVOID, pAddr, 5),
		(DWORD)&CH_PremierHookHandler);
	if (!bRet)
		return FALSE; // ERR

	// save CH_LOC_HOOK struct
	if (!g_pdscHookStructs)
		g_pdscHookStructs = new DynamicStructChain(sizeof(CH_LOC_HOOK));
	if ( !g_pdscHookStructs->AddItem(&hook) )
		return FALSE; // ERR

	return TRUE; // OK
}

BOOL CodeHook::DeinstallLocationHook(void* pAddr)
{
	UINT         u;
	CH_LOC_HOOK  *phook;
	BOOL         bFound;

	//
	// search corresponding struct
	//
	if (!g_pdscHookStructs)
		return FALSE; // ERR
	bFound = FALSE;
	for (u = 0; u < g_pdscHookStructs->GetItemNum(); u++)
	{
		phook = (PCH_LOC_HOOK)g_pdscHookStructs->GetItem(u);
		if (!phook)
			return FALSE; // ERR
		if (phook->pHookAddr == pAddr)
		{
			bFound = TRUE;
			break;
		}
	}
	if (!bFound)
		return FALSE; // ERR

	//
	// rewrite original bytes
	//
	if ( !RewriteOriginalBytes(phook) )
		return FALSE; // ERR

	//
	// free struct
	//
	g_pdscHookStructs->DeleteItem(u);	

	return TRUE; // OK
}

BOOL CodeHook::ObtainWriteAccessAtLocation(void* pAddr, DWORD dwc)
{
	MEMORY_BASIC_INFORMATION  mbi;
	DWORD                     dwSpecialAccess, dwBuff;

	if ( !VirtualQuery(pAddr, &mbi, sizeof(mbi)) )
		return FALSE; // ERR
	dwSpecialAccess = mbi.AllocationProtect & (PAGE_NOACCESS | PAGE_NOCACHE);

	return VirtualProtect(pAddr,
		dwc,
		dwSpecialAccess | PAGE_EXECUTE_READWRITE,
		&dwBuff);
}

//
//
//
BOOL CodeHook::RewriteOriginalBytes(PCH_LOC_HOOK phook)
{
	try
	{
		memcpy(
			phook->pHookAddr,
			&phook->byOrgBytes[0],
			LOC_REDIRECT_INSTR_LEN);
	}
	catch(...)
	{
		return FALSE; // ERR
	}

	return TRUE; // OK
}

/*
void CodeHook::EnterRing09x()
{
	__asm
	{
		// disable Ints
		PUSHFD
		CLI
		// get vector pointer
		SUB     ESP, 4
		SIDT    [ESP - 2]
		POP     ESI				// ESI -> IDT base
		SUB     EDX, EDX
		MOV     EAX, 8
		MOV     EBX, 4                  // EBX -> interrupt to hook
		MUL     EBX
		ADD     ESI, EAX			// ESI -> target Int vector
		// save current handler
		MOV     EDI, [EDI + 4]
		MOV     DI, WORD PTR [ESI]		// EDI -> old Int handler
		MOV     g_dwOldIntHandler, EDI
		// modify handler
		MOV     EBX, Ring0_X_start
		MOV     WORD PTR [ESI], BX
		ROL     EBX, 16
		MOV     WORD PTR [ESI + 6], BX
		// enable ints
		POPFD
		INT     4
Ring0_X_start:
	}

	return;
}

void CodeHook::LeaveRing09x()
{
	__asm
	{
		IRETD
	}

	return;
}
*/

BOOL CodeHook::AssemblePushDW(void* pAddr, DWORD dwPushVal)
{
	__try
	{
		__asm
		{
			MOV     EDI, pAddr
			MOV     BYTE PTR [EDI], 068h
			PUSH    dwPushVal
			POP     DWORD PTR [EDI + 1]
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE; // ERR
	}

	return TRUE; // OK
}

BOOL CodeHook::AssembleJumpLong(void* pAddr, DWORD dwJmpTarget)
{
	__try
	{
		__asm
		{
			MOV     EDI, pAddr
			MOV     BYTE PTR [EDI], 0E9h
			MOV     EAX, dwJmpTarget
	        SUB     EAX, EDI
			SUB     EAX, 5
			MOV     DWORD PTR [EDI + 1], EAX
		}
	}
	__except(EXCEPTION_EXECUTE_HANDLER)
	{
		return FALSE; // ERR
	}

	return TRUE; // OK
}

LONG CodeHook::ObtainWriteAccessInSharedArea9x(void* pAddr, DWORD dwc)
{
	DWORD dwRet, dwcPages;

	dwcPages = (dwc + 4096) >> 12;                                   // Z0MBiE
	dwRet = VxDCall4(
		_PageModifyPermissions,                                      // EliCZ
		((DWORD)pAddr >> 12),
		dwcPages,
		0, // AND mask
		PC_STATIC | PC_WRITEABLE | PC_USER); // OR mask

	return (LONG)dwRet;
}