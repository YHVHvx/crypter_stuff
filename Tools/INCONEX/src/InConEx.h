
#if !defined(__InConEx_h__)
#define __InConEx_h__

#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <conio.h>
#include <FCNTL.h>

#include "OFN.h"
#include "FILE.h"
#include "PEImage.h"
#include "CThread.h"
#include "CodeHook.h"
#include "VMMStuff.h"
#include "NTInternal.h"
#include "9xInternal.h"
#include "CPathString.h"
#include "WideChar.h"

//
// macros
//
#define MakePtr( cast, ptr, addValue )   (cast)( (DWORD)(ptr) + (DWORD)(addValue))
#define ARRAY_ITEMS(name)                (sizeof(name) / sizeof(name[0]))
#define ZERO(strct)                      memset(&strct, 0, sizeof(strct));
#define TESTFLAG(val, flag)              (BOOL)((val & flag) == flag ? TRUE : FALSE)
#define TESTBIT(val, flag)               (BOOL)((val & flag) == 0 ? FALSE : TRUE)

#endif // __InConEx_h__