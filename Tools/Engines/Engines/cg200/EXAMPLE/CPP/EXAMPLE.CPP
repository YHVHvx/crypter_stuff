
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <io.h>

#pragma hdrstop

#include "..\..\CODEGEN\CPP\cg_bin.hpp"
#include "..\..\CODEGEN\CPP\cg_bin.cpp"

#include "etg.hpp"
#include "etg.cpp"

DWORD randseed = GetTickCount();

DWORD __cdecl my_random(DWORD,DWORD range)
{
  return
    range == 0 ? 0 : (randseed = randseed * 214013 + 2531011) % range;
}

BYTE* __cdecl my_trash(DWORD userdata, BYTE* ptr, DWORD regfree)
{

//*ptr++ = 0x90;
//return ptr;

  DWORD etgsize;
  void* etg_ptr = &etg_bin;
  (*(etg_engine*)etg_ptr)
     (userdata,
      ETG_ALL-ETG_SEG,
      REG_ALL,
      regfree,
      &etgsize,
      3,                // #cmds
      1024,             // #bytes
      ptr,
      my_random);
  ptr += etgsize;
  return ptr;

}

BYTE buf[8192];
DWORD tmpsize;
DWORD bufsize = 0;

void codegen(DWORD x1,DWORD x2,DWORD x3,DWORD x4)
{
  void* cg_ptr = &cg_bin;
  (*(cg_engine*)cg_ptr)
        (0x12345678,
         &buf[bufsize],
         &tmpsize,
         0xCF,    // eax,ebx,ecx,edx,esi,edi
         NULL,
         my_trash,
         my_random,
         x1,x2,x3,x4);
  bufsize += tmpsize;
}

void main()
{

  DWORD a=1, b=2, c=0;

  codegen(cmd_v_v,cmd_mov,(DWORD)&c,(DWORD)&a);       // c=a
  codegen(cmd_v_v,cmd_xor,(DWORD)&c,(DWORD)&b);       // c^=b
  buf[bufsize++] = 0xC3;

//__emit__(0xcc);

  void* bufptr = &buf;
  (*(void(*)())bufptr) ();

  assert(c==3);
}
