
#if !defined(__common_h__)
#define __common_h__

#include <windows.h>

//
// macros
//
#define _IsNT (BOOL)(GetVersion() < 0x80000000 ? TRUE : FALSE)

//
// exported symbols
//

#endif // __common_h__