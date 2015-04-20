
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <io.h>
#pragma hdrstop

DWORD op_files = 0;
DWORD op_count[256]={0};

#include "engine.hpp"
#include "engine.cpp"
#include "mutate.cpp"
//#include "sigman.cpp"

extern "C"
int __cdecl disasm_main(BYTE*);   // length-disassembler interface

int __cdecl my_disasm(DWORD,BYTE* x)
{
  return disasm_main(x);
}

void* __cdecl my_malloc(DWORD,DWORD size)
{
  void* t = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
  //GlobalAlloc(GPTR, size);
  assert(t);
  return t;
}

DWORD randseed = GetTickCount();

DWORD __cdecl my_random(DWORD,DWORD range)
{
  return
    range == 0 ? 0 : (randseed = randseed * 214013 + 2531011) % range;
}

void main(int argc, char* argv[])
{
  printf("PE_STAT  PE EXE/DLL Opcode Frequency Calculation   based on MISTFALL engine\n");
  if (argc!=2)
  {
    printf("syntax: PE_STAT filename<.EXE|.DLL>");
    exit(0);
  }

  char* ifile = argv[1];

  printf("þ reading %s\n", ifile);
  FILE*f=fopen(ifile,"rb");
  assert(f);
  DWORD bufsize = filelength(fileno(f));
  if (bufsize >= 5*1024*1024)
  {
    printf("ERROR: too big file\n");
    fclose(f);
    exit(0);
  }
  DWORD maxbufsize = bufsize * 2 + 131072;
  BYTE* buf = new BYTE[maxbufsize];
  assert(buf);
  fread(buf, 1,bufsize, f);
  fclose(f);

  f=fopen("_opcode.bin","rb");
  if (f==NULL)
  {
    op_files = 0;
    memset(op_count,0x00,256*4);
  }
  else
  {
    printf("þ reading _opcode.bin\n");
    assert(fread(&op_files,1,4,f)==4);
    assert(fread(op_count,1,1024,f)==1024);
    fclose(f);
  }

  int res;

  __try
  {
  res = engine(0x12345678,    // user-parameter
               buf,             // buffer
               bufsize,         // input buffer size
               &bufsize,        // ptr to output buffer size
               maxbufsize,      // maximal buffer size
               my_disasm,       // disassembler
               my_malloc,       // malloc
               my_random,       // random
               my_mutate,       // mutator
               NULL  /*my_sigman*/        // signature manager
              );
  }
  __except (1)
  {
  res = -1;
  }

  printf("  engine() returns %s (%i)\n",
    res == -1           ? "***EXCEPTION***" :
    res == ERR_SUCCESS  ? "success" :
    res == ERR_BADFILE  ? "ERR_BADFILE" :
    res == ERR_NOMEMORY ? "ERR_NOMEMORY" :
    res == ERR_SHORTSUX ? "ERR_SHORTSUX":
    res == ERR_MUTATE   ? "ERR_MUTATE" :
    res == ERR_DISASM   ? "ERR_DISASM" :
    "???",
    res);

  if (res==ERR_SUCCESS)
  {

    /*
    printf("þ writing %s\n", ofile);
    f=fopen(ofile,"wb");
    assert(f);
    fwrite(buf, 1,bufsize, f);
    fclose(f);
    */

  }

  if (res==666)
  {
    op_files++;

    printf("þ writing _opcode.bin\n");
    f=fopen("_opcode.bin","wb");
    assert(f);
    assert(fwrite(&op_files,1,4,f)==4);
    assert(fwrite(op_count,1,1024,f)==1024);
    fclose(f);

    printf("þ writing _opcode.lst\n");
    FILE*f=fopen("_opcode.lst","wb");
    assert(f);
    DWORD s=0;
    for(DWORD i=0; i<256; i++)
      s += op_count[i];
    fprintf(f,"#files   = %i\n", op_files);
    fprintf(f,"#opcodes = %i\n", s);
    if (s)
    {

      for(;;)
      {
        DWORD maxv=-1,maxi=-1;
        for(DWORD i=0; i<256; i++)
        if (op_count[i]!=-1)
        if ((maxv==-1)||(maxv<op_count[i]))
        {
          maxv=op_count[i];
          maxi=i;
        }
        if (maxv==-1) break;
        fprintf(f,"0x%02X  %-8i  %3i%%\n", maxi, op_count[maxi], op_count[maxi]*100/s);
        op_count[maxi]=-1;
      }//for

    }
    fclose(f);
  }

  printf("þ exiting\n");
}
