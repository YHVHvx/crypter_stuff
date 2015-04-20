
#ifndef __VMMStuff_h__
#define __VMMStuff_h__

#include <windows.h>

#pragma comment(lib, "lib\\K32.lib")

//
// constants
//
#define VMM_ID                    0x00010000

// LONG _cdecl _PageModifyPermissions(ULONG page, ULONG npages, ULONG permand, ULONG permor);
#define _PageModifyPermissions    (VMM_ID | 0x0000000D)

/* PageCommit flags */
#define PC_FIXED    0x00000008	/* pages are permanently locked */
#define PC_LOCKED   0x00000080	/* pages are made present and locked*/
#define PC_LOCKEDIFDP	0x00000100  /* pages are locked if swap via DOS */
#define PC_WRITEABLE	0x00020000  /* make the pages writeable */
#define PC_USER     0x00040000	/* make the pages ring 3 accessible */
#define PC_INCR     0x40000000	/* increment "pagerdata" each page */
#define PC_PRESENT  0x80000000	/* make pages initially present */
#define PC_STATIC   0x20000000	/* allow commit in PR_STATIC object */
#define PC_DIRTY    0x08000000	/* make pages initially dirty */
#define PC_CACHEDIS 0x00100000  /* Allocate uncached pages - new for WDM */
#define PC_CACHEWT  0x00080000  /* Allocate write through cache pages - new for WDM */
#define PC_PAGEFLUSH 0x00008000 /* Touch device mapped pages on alloc - new for WDM */

//
// prototypes
//
extern "C"
{
	DWORD __stdcall VxDCall4(DWORD dwServiceID, DWORD dwArg1, DWORD dwArg2, DWORD dwArg3, DWORD dwArg4);
}

#endif // __VMMStuff_h__