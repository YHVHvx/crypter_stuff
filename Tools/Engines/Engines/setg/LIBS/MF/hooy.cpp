
/*
  This file implements CHooyList class,
  which is used to manipulate
  with disassembly list entries of type HOOY.
*/

//#define LOG_HOOY

#include "hooy.hpp"

void __cdecl CHooyListOnFree(void* entry)
{
  HOOY*t = (HOOY*)entry;
  if ((t->flags & FL_HEADER)==0)
    ZFreeV((void**)&t->dataptr);
//  for(int i=0; i<MAXFILES; i++)
//  if (t->link[i] != NULL)
//    ZFreeV((void**)&t->link[i]);
//  ZFreeV((void**)&t->text);
} // CHooyList::OnFree()
