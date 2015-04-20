
/*
  This file implements CMistfall class,
  i.e. executable file parser/rebuilder.
*/

//#define DUMP_MSG

#include "hooy.cpp"

#include "mistfall.hpp"

CMistfall::CMistfall()
{

  error_count = 0;
  i_phys_len = 0;
  o_phys_len = 0;
  ovr_offs = 0;
  ovr_size = 0;

  i_phys_mem = NULL;
  o_phys_mem = NULL;
  edit_header = NULL;
  edit_mz = NULL;
  edit_pe = NULL;
  edit_oe = NULL;
  mz = NULL;
  pe = NULL;
  oe = NULL;
  memb = NULL;
  flag = NULL;
  arg1 = NULL;
  arg2 = NULL;
//  argt = NULL;
  fasthooy = NULL;

} // CMistfall::CMistfall()

CMistfall::~CMistfall()
{
//  if (pe != NULL && argt != NULL && i_phys_mem != NULL)
//  for(int i=0; i<=pe->pe_imagesize; i++)
//    ZFreeV((void**)&argt[i]);
//  ZFreeV( (void**)&argt );
  ZFreeV( (void**)&i_phys_mem );
  ZFreeV( (void**)&o_phys_mem );
  ZFreeV( (void**)&memb );
  ZFreeV( (void**)&flag );
  ZFreeV( (void**)&arg1 );
  ZFreeV( (void**)&arg2 );
  ZFreeV( (void**)&fasthooy );
  ZFreeV( (void**)&edit_header );
} // CMistfall::~CMistfall()

int CMistfall::LoadFile(char* fname)
{
  FILE* f = fopen(fname, "rb");
  if (f == NULL) return MF_ERR_CANTOPENFILE;

  i_phys_len = filelength(fileno(f));
  if ( (i_phys_len < MF_PHYSFILE_MIN_SIZE) ||
       (i_phys_len > MF_PHYSFILE_MAX_SIZE) )
  {
    fclose(f);
    return MF_ERR_BADFILESIZE;
  }

  i_phys_mem = (BYTE*)ZAlloc( i_phys_len+1 );
  if (i_phys_mem == NULL)
  {
    fclose(f);
    return MF_ERR_NOMEMORY;
  }

  fread(i_phys_mem, 1, i_phys_len, f);

  fclose(f);

  return MF_ERR_SUCCESS;
} // CMistfall::LoadFile()

int CMistfall::SaveFile(char* fname)
{
  if (o_phys_mem == NULL) return MF_ERR_NOTASSEMBLED;
  FILE* f = fopen(fname, "wb");
  if (f == NULL) return MF_ERR_CANTCREATEFILE;
  fwrite(o_phys_mem, 1, o_phys_len, f);
  fclose(f);
  return MF_ERR_SUCCESS;
} // CMistfall::LoadFile()

void CMistfall::process_import(DWORD addr)
{
  if (memd[addr] == 0) return;
  markrvadata(addr);
  addr = memd[addr];
  while (memd[addr])
  {
    if (memd[addr] < pe->pe_imagesize)
    {
//      if (argt[memd[addr]] == NULL)
//        settext(memd[addr], ";imported api '%s'<br>\n", memb+memd[addr]+2);
      flag[memd[addr]+0] |= FL_DATA;
      flag[memd[addr]+1] |= FL_DATA;
      markrvadata(addr);
    }
    addr += 4;
  } // while
} // CMistfall::process_import()

void CMistfall::process_rsrc(DWORD addr)
{
// 00h  DWord  Flags
// 04h  DWord  Time/Date Stamp
// 08h  Word   Major Version
// 0Ah  Word   Minor Version
// 0Ch  Word   Name Entry
// 0Eh  Word   ID_Num Entry
//
  DWORD c = memw[addr + 0x0C] + memw[addr + 0x0E];
  DWORD t = addr + 0x10;
  while (c--)
  {
    if (memd[t] & 0x80000000)
    {
      flag[t] |= FL_RES8;
      DWORD q = memd[t] & 0x7FFFFFFF;
      markdelta(t, pe->pe_resourcerva, q);
    }
    t += 4;
    if (memd[t] & 0x80000000)
    {
      flag[t] |= FL_RES8;
      DWORD q = memd[t] & 0x7FFFFFFF;
      markdelta(t, pe->pe_resourcerva, q);
      process_rsrc( pe->pe_resourcerva + q );
    }
    else
    {
      markdelta(t, pe->pe_resourcerva, memd[t]);
      markrvadata(pe->pe_resourcerva + memd[t]);
    }
    t += 4;
  } // while
} // CMistfall::process_rsrc()

//char* get_free_regs(DWORD regused)
//{
//  static char s[256];
//  if ((regused == 0) || (regused == 0xffffffff))
//    s[0] = 0;
//  else
//    xde_sprintset(s,  (regused ^ 0xffffffff) & (XSET_ALL32|XSET_FL) );
//  return s;
//}

//void CMistfall::DumpLog(int count,int this_n,char**filenames,FILE*f,char*title,CMistfall**M)
//{
//#ifdef DUMP_MSG
//  log("+ writing dump for %s\n", title);
//#endif // DUMP_MSG
//
//  fprintf(f,"<html>\n");
//  fprintf(f,"<head>\n");
//  fprintf(f,"<title>%s</title>\n",title);
//  fprintf(f,"</head>\n");
//  fprintf(f,"<body topmargin=0 border=0 leftmargin=0 rightmargin=0 marginwidth=0 marginheight=0 "
//            "text=#b0b0b0 bgcolor=#000000 link=#%s alink=#ffffff vlink=#%s>\n",
//    color_link [this_n % MAXFILES],
//    color_vlink[this_n % MAXFILES] );
//
////fprintf(f,"<style>\n");
////fprintf(f,"table, caption, tr, thead, tfoot, tbody, th, td {\n");
////fprintf(f,"font-family: Lucida Console, Courier;\n");
////fprintf(f,"font-size: 11px; }\n");
////fprintf(f,"</style>\n");
//  fprintf(f,"<STYLE>\n");
//  fprintf(f,"BODY\n");
//  fprintf(f,"{\n");
//  fprintf(f,"scrollbar-face-color:      #000000;\n");
//  fprintf(f,"scrollbar-shadow-color:    #%s;\n",color_vlink[this_n]);
//  fprintf(f,"scrollbar-highlight-color: #%s;\n",color_link[this_n]);
//  fprintf(f,"scrollbar-3dlight-color:   #%s;\n",color_vlink[this_n]);
//  fprintf(f,"scrollbar-darkshadow-color:#000000;\n");
//  fprintf(f,"scrollbar-track-color:     #000000;\n");
//  fprintf(f,"scrollbar-arrow-color:     #%s\n",color_vlink[this_n]);
//  fprintf(f,"}\n");
//  fprintf(f,".sc { SCROLLBAR-FACE-COLOR: #000000; SCROLLBAR-ARROW-COLOR: #%s }\n",
//    color_vlink[this_n] );
//  fprintf(f,"</STYLE>\n");
//
//  fprintf(f,"<font face=\"Lucida Console, Courier\" size=-2>\n");
//
////  fprintf(f,"<table width=100%% border=0 cellspacing=2 cellpadding=0>\n");
////  fprintf(f,"<tr><th>rva</th><th>type,flags,instr</th><th>links</th></tr>\n");
//
//  HOOY* h;
//  ForEachInList(HooyList, HOOY, h)
//  {
//    //fprintf(f,"%08X %08X %08X: ",h->oldrva,h->newrva,h->newofs);
////    fprintf(f,"<tr>\n");
//
//    if (h->flags & (FL_CPOINT|FL_LABEL|FL_HAVEREL|FL_FIXUP|FL_RVA|FL_SECTALIGN|FL_DELTA))
//    {
//    fprintf(f,"<a name=a%08x>\n",h->oldrva);
//    }
//
//    if (h->text)
//    {
//      fprintf(f,"<font color=#e0e0e0>%s</font>", h->text);
//    }
//
//// enable this if you wanna see xref's from other file versions
////    if (h->flags & FL_CPOINT)
////    {
////      for(int i=0; i<count; i++)
////      if (M[i] != NULL)
////      if (M[i] != this)
////      {
////        HOOY* h2;
////        ForEachInList(M[i]->HooyList, HOOY, h2)
////        {
////          if (h2->link_count[this_n] != 0)
////          for(int j=0; j<h2->link_count[this_n]; j++)
////          if (h2->link[this_n][j] == h)
////          {
////            fprintf(f," &nbsp; <== <a href=\"%s#a%08x\" target=\"f%d\"><font color=#%s>%08x</font></a><br>\n",
////              filenames[i],
////              h2->oldrva,
////              i,
////              color_link[i],
////              h2->oldrva );
////          }
////        }
////      }
////    }
//
//    if (h->flags & FL_LABEL)
//    {
//      HOOY* h2;
//      ForEachInList(HooyList, HOOY, h2)
//      {
//        if (h2->flags & (FL_HAVEREL|FL_RVA|FL_FIXUP))
//        if (h2->arg1 == h->oldrva || h2->arg2 == h->oldrva)
//        {
//          fprintf(f," &nbsp; <-- <a href=\"#a%08x\">%08x</a><br>\n",
//            h2->oldrva,
//            h2->oldrva );
//        }
//      }
//    }
//
////    if (h->flags & (FL_CPOINT|FL_LABEL))
////    {
////      fprintf(f,"<a href=\"#a%08x\">%08x</a>",
////                h->oldrva,
////                h->oldrva);
////    }
////    else
//    {
//      fprintf(f,"%08x:",
//                h->oldrva);
//    }
//    fprintf(f," &nbsp; ");
//
//    if (h->flags&FL_SECTALIGN)
//    {
//      fprintf(f,"SECTALIGN<br>\n");
//    }
//    else
//    if (h->flags&FL_LABEL)
//    {
//      fprintf(f,"LABEL");
//      if (h->flags&FL_CPOINT) fprintf(f,",CPOINT");
//      if (h->flags&FL_CREF) fprintf(f,",CREF");
//      if (h->flags&FL_DREF) fprintf(f,",DREF");
//      if (h->flags&FL_DATA) fprintf(f,",DATA");
//      fprintf(f,"<br>\n");
//    }
//    else
//    if (h->flags&FL_DELTA)
//    {
//      fprintf(f,"DELTA%s,<a href=\"#a%08x\">%08x</a>-<a href=\"#a%08x\">%08x</a><br>\n",
//        h->flags&FL_RES8?",RES8":"",
//        //*(DWORD*)h->dataptr,
//        h->arg2,
//        h->arg2,
//        h->arg1,
//        h->arg1);
//    }
//    else
//    if (h->flags&FL_RVA)
//    {
//      fprintf(f,"RVA,<a href=\"#a%08X\">%08x</a><br>\n", *(DWORD*)h->dataptr, *(DWORD*)h->dataptr);
//    }
//    else
//    if (h->flags&FL_OPCODE)
//    {
//
////      fprintf(f,"<td>");
////      DWORD i;
////      for (i=0; i<h->datalen; i++)
////        fprintf(f,"%s%02X",i==0?"":" ",h->dataptr[i]);
////      fprintf(f,"</td>");
//      //
//
//      char s[256];
//      dump_instr(h->dataptr, h->oldrva, s);
//
//      fprintf(f, "%s",s);
//
////      char*q = get_free_regs(h->regused);
////      if (q[0])
////        fprintf(f, "  # %s", q);
//
//    for(int i=0; i<MAXFILES; i++)
//      for(int j=0; j<h->link_count[i]; j++)
//      {
//        fprintf(f," ==> <a href=\"%s#a%08x\" target=\"f%d\"><font color=#%s>%08x</font></a>\n",
//          filenames[i],
//          h->link[i][j]->oldrva,
//          i,
//          color_link[i],
//          h->link[i][j]->oldrva );
//      }
//      fprintf(f,"<br>\n");
//
//      if (h->flags&FL_FIXUP)
//        fprintf(f," &nbsp; --> <a href=\"#a%08x\">FX:%08x</a><br>\n",h->arg1,h->arg1);
//      if (h->flags&FL_HAVEREL)
//        fprintf(f," &nbsp; --> <a href=\"#a%08x\">REL:%08x</a><br>\n",h->arg1,h->arg1);
//
//    }
//    else
//    if (h->flags&FL_FIXUP)
//    {
//      fprintf(f,"FIXUP,<a href=\"#a%08X\">%08x</a><br>\n",h->arg1,h->arg1);
//    }
//    else
//    if (h->flags&FL_DATA)
//    {
//      fprintf(f,"DATA(%d):",h->datalen);
//      for (DWORD i=0; i<MIN(h->datalen,8); i++)
//        fprintf(f,"%s%02X",i==0?"":" ",h->dataptr[i]);
//      if (h->datalen>8) fprintf(f," ...");
//      fprintf(f,"<br>\n");
//    }
//    else
//    //__emit__(0xcc)
//    ;
//
//  } // for h
//
////  fprintf(f,"</table>\n");
//  fprintf(f,"</body>\n");
//  fprintf(f,"</html>\n");
//
//} // CMistfall::DumpLog()

int CMistfall::Disasm(DWORD dflags)
{
  error_count = 0;
  can_patch   = 0;

  xde_instr diza;

#ifdef DUMP_MSG
  log("+ checking file format\n");
#endif // DUMP_MSG

  // check file format

  mz = (MZ_HEADER*) &i_phys_mem[0];

  if ( (mz->mz_id != 0x5A4D) ||
       (mz->mz_neptr & 3)  ||
       (mz->mz_neptr <  sizeof(MZ_HEADER)) ||
       (mz->mz_neptr + 1024 >= i_phys_len) )
  {
    error_count++;
    return MF_ERR_BADMZHDR;
  }

  pe = (PE_HEADER*) &i_phys_mem[ mz->mz_neptr ];

  if (pe->pe_id != 0x00004550)                // 'PE\0\0'
  {
    error_count++;
    return MF_ERR_BADPEHDR;
  }

  if (pe->pe_ntheadersize != 0xE0)
  {
    error_count++;
    return MF_ERR_BADPEHDR;
  }

  if ((pe->pe_fixuprva==0) || (pe->pe_flags & 1))
  {
    // if there is no fixups, check if fixups are required
    if ((dflags & DF_FIXUPSREQUIRED) == 0)
    {
      // there is no fixups, so we increment error_count to disallow file
      // reassembling, however "patch" mode remains available
      error_count++;
    }
    else
    {
      error_count++;
      return MF_ERR_NOFIXUPS;
    }
  }

  if ( (pe->pe_numofobjects == 0) ||
       (pe->pe_numofobjects > MF_PE_MAXSECTIONS) )
  {
    error_count++;
    return MF_ERR_BADNSECT;
  }

  if (pe->pe_headersize > MIN(i_phys_len, pe->pe_imagesize))
  {
    error_count++;
    return MF_ERR_BADPEHDR;
  }

  oe = (PE_OBJENTRY*) &i_phys_mem[ mz->mz_neptr + sizeof(PE_HEADER) ];

  DWORD n;
  for(n=0; n<(DWORD)pe->pe_numofobjects; n++)
  {
    if ( (oe[n].oe_physoffs == 0) ||
         (oe[n].oe_physsize == 0) ||
         (oe[n].oe_virtrva  == 0) ||
         (oe[n].oe_virtsize == 0) )
    {
      error_count++;
      return MF_ERR_BADOBJTABLE;
    }
    // force alignment
    oe[n].oe_virtsize = ALIGN(oe[n].oe_virtsize, pe->pe_objectalign);
    oe[n].oe_physsize = ALIGN(oe[n].oe_physsize, pe->pe_filealign);
  }

  // calc ovr. params
  DWORD t = pe->pe_numofobjects - 1;
  ovr_offs = oe[t].oe_physoffs + oe[t].oe_physsize;
  ovr_size = i_phys_len - ovr_offs;
  if ((signed)ovr_size < 0)
  {
    error_count++;
    return MF_ERR_BADOVRSIZE;
  }

  // check if overlay is just zero-bytes alignment at end of file
  t = 0;
  DWORD i;
  for (i=0; i<ovr_size; i++)
    t |= i_phys_mem[ovr_offs + i];
  if (t == 0)
    ovr_size = 0;

  if (dflags & DF_STDSECT)
  {
    DWORD n;
    for(n=0; n<(DWORD)pe->pe_numofobjects; n++)
    {
      DWORD t = ~( *(DWORD*)&oe[n].oe_name[0] ^      // 8 bytes
                   *(DWORD*)&oe[n].oe_name[4] );
#define mk1(x) if (t != ~((DWORD)(x)))
      mk1(0x45444F43)   //  'CODE'
      mk1(0x41544144)   //  'DATA'
      mk1(0x4F545541)   //  'AUTO'
      mk1(0x00535342)   //  'BSS\x00'
      mk1(0x00534C54)   //  'TLS\x00'
      mk1(0x7373622E)   //  '.bss'
      mk1(0x736C742E)   //  '.tls'
      mk1(0x5452432E)   //  '.CRT'
      mk1(0x494E497A)   //  '.INI'^'T\x00\x00\x00'
      mk1(0x7865745A)   //  '.tex'^'t\x00\x00\x00'
      mk1(0x7461644F)   //  '.dat'^'a\x00\x00\x00'
      mk1(0x7273724D)   //  '.rsr'^'c\x00\x00\x00'
      mk1(0x6C651141)   //  '.rel'^'oc\x00\x00'
      mk1(0x6164085A)   //  '.ida'^'ta\x00\x00'
      mk1(0x6164135A)   //  '.rda'^'ta\x00\x00'
      mk1(0x6164045A)   //  '.eda'^'ta\x00\x00'
      mk1(0x6265035B)   //  '.deb'^'ug\x00\x00'
      mk1(0x4F521711)   //  'DGRO'^'UP\x00\x00'
      {
        error_count++;
        return MF_ERR_BADSECTNAME;
      }
    } // for n
  } // DF_STDSECT

#ifdef DUMP_MSG
  log("+ allocating virtual memory\n");
#endif // DUMP_MSG

  // allocate virtual memory

  if (pe->pe_imagesize > MF_PE_MAXIMAGESIZE)
  {
    error_count++;
    return MF_ERR_BADIMAGESIZE;
  }

  t = pe->pe_imagesize + 1;  // +1 because we may have last virtual entry

  memb = (BYTE*)ZAlloc(t);
  if (memb == NULL)
  {
    error_count++;
    return MF_ERR_NOMEMORY;
  }

  t <<= 2; // now allocating DWORDs

  flag = (DWORD*)ZAlloc(t);
  if (flag == NULL)
  {
    error_count++;
    return MF_ERR_NOMEMORY;
  }

  arg1 = (DWORD*)ZAlloc(t);
  if (arg1 == NULL)
  {
    error_count++;
    return MF_ERR_NOMEMORY;
  }

  arg2 = (DWORD*)ZAlloc(t);
  if (arg2 == NULL)
  {
    error_count++;
    return MF_ERR_NOMEMORY;
  }

//  argt = (char**)ZAlloc(t);
//  if (argt == NULL)
//  {
//    error_count++;
//    return MF_ERR_NOMEMORY;
//  }

#ifdef DUMP_MSG
  log("+ loading into virtual addresses\n");
#endif // DUMP_MSG

  // load into virtual addresses

  memcpy(memb, i_phys_mem, pe->pe_headersize);
  for (i=0; i<pe->pe_headersize; i++)
    flag[i] |= FL_PRESENT | FL_VPRESENT;

//  settext(0, ";mz/pe headers<br>\n");

  for(n=0; n<(DWORD)pe->pe_numofobjects; n++)
  {
    // copy section image
//    settext(oe[n].oe_virtrva, ";section %d - start<br>\n", n);
    memcpy(&memb[ oe[n].oe_virtrva ],
           &i_phys_mem[ oe[n].oe_physoffs ],
           MIN(oe[n].oe_physsize, oe[n].oe_virtsize));
    // set presence flags
    for (i=0; i<oe[n].oe_physsize; i++)
      flag[oe[n].oe_virtrva + i] |= FL_PRESENT;
    for (i=0; i<oe[n].oe_virtsize; i++)
      flag[oe[n].oe_virtrva + i] |= FL_VPRESENT;

//    settext(oe[n].oe_virtrva+oe[n].oe_physsize, ";section %d - end of phys addrs<br>\n", n);
//    settext(oe[n].oe_virtrva+oe[n].oe_virtsize, ";section %d - end of virt addrs<br>\n", n);

  } // for n

  // analyze PE structure

#ifdef DUMP_MSG
  log("+ PE header\n");
#endif // DUMP_MSG

  // PE header

  t = mz->mz_neptr + sizeof(PE_HEADER);

  for (n=0; n<(DWORD)pe->pe_numofobjects; n++)
  {
//    settext(t, ";object entry %d, '%s'<br>\n", n, memb+t);   // buggy usage

    flag[t] |= FL_LABEL;
    for(i=0; i<8; i++)
      flag[t+i] |= FL_DATA;

    for(i=0x24; i<0x28; i++)
      flag[t+i] |= FL_DATA;

    flag[oe[n].oe_virtrva] |= FL_SECTALIGN;

    markdelta(t+0x08, oe[n].oe_virtrva, oe[n].oe_virtsize); // 08=virtsize

    markrva(t+0x0C);                                        // 0C=virtrva

    markdelta(t+0x10, oe[n].oe_virtrva, oe[n].oe_physsize); // 10=physsize
    flag[t+0x10] |= FL_PHYS | FL_FORCEFILEALIGN;            // 10=physsize

    flag[t+0x14] |= FL_PHYS | FL_RVA;                       // 14=physoffs
    arg1[t+0x14] = oe[n].oe_virtrva;                        // 14=physoffs

    t += sizeof(PE_OBJENTRY);
  }
//  settext(pe->pe_imagesize, ";end of virtual addresses<br>\n");
  flag[pe->pe_imagesize] |= FL_SECTALIGN;

  t = mz->mz_neptr;

  if (pe->pe_entrypointrva)
    markrva(t + 0x28);                 // EntryPointRVA

//  settext(pe->pe_entrypointrva, ";entry point<br>\n");

  markrva(t + 0x2C);                   // 2C=baseofcode
  markrva(t + 0x30);                   // 30=baseofdata

//  settext(pe->pe_baseofcode, ";base-of-code<br>\n");
//  settext(pe->pe_baseofcode, ";base-of-data<br>\n");

  markdelta(t+0x1C, pe->pe_baseofcode, pe->pe_sizeofcode); // 1C=sizeofcode
  flag[t+0x1C] |= FL_FORCEOBJALIGN;

//  settext(pe->pe_baseofcode+pe->pe_sizeofcode, ";end-of-code<br>\n");

//markdelta(t+0x20, pe->pe_baseofdata, pe->pe_sizeofidata);// 20=sizeofidata
//flag[t+0x20] |= FL_FORCEOBJALIGN;

  markrva(t + 0x50);                       // 50=imagesize
  markrvadata(t + 0x54);                   // 54=headersize

//  settext(pe->pe_headersize, ";end-of-headers<br>\n");

//  char* rvasznames[16] =
//  {
//    "+0x78:export",
//    "+0x80:import",
//    "+0x88:resource",
//    "+0x90:exception",
//    "+0x98:security",
//    "+0xA0:fixup",
//    "+0xA8:debug",
//    "+0xB0:description",
//    "+0xB8:machine",
//    "+0xC0:tls",
//    "+0xC8:loadconfig",
//    "+0xD0:reserved_1",
//    "+0xD8:iat",
//    "+0xE0:reserved_2",
//    "+0xE8:reserved_3",
//    "+0xF0:reserved_4"
//  };

  for(i=0; i<MIN(16,pe->pe_numofrvaandsizes); i++)
  {
    t = mz->mz_neptr + 0x78 + i * 8;              // rva/size #i
    if ( memd[t] )
    {
//      settext(memd[t], ";rvasize %d - begin (%s)<br>\n", i, rvasznames[i]);
//      settext(memd[t]+memd[t+4], ";rvasize %d - end (%s)<br>\n", i, rvasznames[i]);
      markrvadata(t);
      markdelta(t+4, memd[t], memd[t+4]);
      for (DWORD i=memd[t]; i<memd[t]+memd[t+4]; i++)
      if (i < pe->pe_imagesize)
        flag[i] |= FL_DATA;
      else
        error_count++;
    }
  }

  // import

  if (pe->pe_importrva)
  {
#ifdef DUMP_MSG
  log("+ imports\n");
#endif // DUMP_MSG

    DWORD imp0 = pe->pe_importrva;
//    settext(imp0, ";imports<br>\n");
    flag[imp0] |= FL_LABEL;
    while ( memd[imp0 + 0x10] )              // 10=addresstable
    {
      if (memd[imp0])
      {
//        settext(imp0+0x00,";import entry - ptr to lookup<br>\n");
//        settext(memd[imp0+0x00],";imports - lookup<br>\n");
      }
      process_import(imp0 + 0x00);           // 00=lookup

      if (memd[imp0+0x10])
      {
//        settext(imp0+0x10,";import entry - ptr to address table<br>\n");
//        settext(memd[imp0+0x10],";imports - address table<br>\n");
      }
      process_import(imp0 + 0x10);           // 10=addresstable

      if (memd[imp0+0x0c])
      {
//        settext(imp0+0x0C,";import entry - ptr to name<br>\n");
//        settext(memd[imp0+0x0C],";imports - dll name ('%s')<br>\n", memb+memd[imp0+0x0c]); // one more bug
      }

      markrvadata(imp0 + 0x0C);              // 0C=name

      imp0 += sizeof(PE_IMPORT);
    }
  }

  // export

  if (pe->pe_exportrva)
  {
#ifdef DUMP_MSG
    log("+ exports\n");
#endif // DUMP_MSG

    DWORD exp0 = pe->pe_exportrva;
//    settext(exp0, ";exports<br>\n");
    markrvadata(exp0+0x0C);           // 0C=namerva
    markrvadata(exp0+0x1C);           // 1C=addresstablerva
    markrvadata(exp0+0x20);           // 20=namepointersrva
    markrvadata(exp0+0x24);           // 24=ordinaltablerva
    PE_EXPORT *exp = (PE_EXPORT*) &memb[ exp0 ];

    exp0 = exp->ex_addresstablerva;
//    settext(exp0, ";exports - address table<br>\n");
    for(DWORD i = 0; i < exp->ex_numoffunctions; i++)
    {
      markrva(exp0 + i*4);
    }

    exp0 = exp->ex_namepointersrva;
//    settext(exp0, ";exports - name pointers<br>\n");
    for (i = 0; i < exp->ex_numofnamepointers; i++)
    {
      markrvadata(exp0 + i*4);

//      settext(memd[exp->ex_addresstablerva+ (memw[exp->ex_ordinaltablerva+i*2])*4 ],
//              ";EXPORT:%s<br>\n",
//              memb+memd[exp0+i*4] );
    }
  }

  // fixups

  if ((pe->pe_fixuprva) && ((pe->pe_flags & 1)==0))
  {
#ifdef DUMP_MSG
    log("+ fixups\n");
#endif // DUMP_MSG

    DWORD fixupcount = 0;

    PE_FIXUP* fx = (PE_FIXUP*) &memb[ pe->pe_fixuprva ];
    DWORD k = 0;
    while (k < pe->pe_fixupsize)
    {
      for (i = 0; i < (fx->fx_blocksize - 8) / 2; i++)
      {
        DWORD fxtype = fx->fx_typeoffs[i] >> 12;
        if (fxtype == 3)
        {
          fixupcount++;
          DWORD j = fx->fx_pagerva + (fx->fx_typeoffs[i] & 0x0FFF);
          if (j > pe->pe_imagesize)
          {
            error_count++;
            return MF_ERR_BADFIXUPS;
          }
          markfixup(j);
//#ifdef NEWBASE
//        memd[j] = memd[j] - pe->pe_imagebase + NEWBASE;
//#endif
        }
        else
        if (fxtype != 0)
        {
          error_count++;
          return MF_ERR_BADFIXUPS;
        }
      }
      k += fx->fx_blocksize;
      *(DWORD*)&fx += fx->fx_blocksize;
    }
//#ifdef NEWBASE
//  pe->pe_imagebase = NEWBASE;
//#endif

    if (fixupcount == 0)
    {
      error_count++;
      return MF_ERR_NOFIXUPS; // # fixups == 0
    }
  }

  // resources

  if (pe->pe_resourcerva)
  {
#ifdef DUMP_MSG
  log("+ resources\n");
#endif // DUMP_MSG

    process_rsrc( pe->pe_resourcerva );
  }

  // sigman-1

#ifdef DUMP_MSG
  log("+ analyzing code\n");
#endif // DUMP_MSG

  // analyze code

  DWORD code_start;
  DWORD code_end;
  if (dflags & DF_CODEFIRST)
  {
    code_start = oe[0].oe_virtrva;
    code_end   = oe[0].oe_virtrva + oe[0].oe_physsize;
  }
  else
  {
    code_start = pe->pe_headersize;
    code_end   = pe->pe_imagesize - 16;
  }

  if (pe->pe_entrypointrva)
    flag[ pe->pe_entrypointrva ] |= FL_NEXT;

  DWORD ip;

  // find & mark subroutines

  for (ip = code_start; ip < code_end; ip++)
  {
    if (~(memd[ip] & 0x00FFFFFF) == ~0x00EC8B55U) // to avoid fail on self
      flag[ip] |= FL_NEXT;
    if (memw[ip] == 0x8B55)
      if (flag[ip] & FL_DREF)
        flag[ip] |= FL_NEXT;
  } // for ip

  if ((dflags & DF_DISABLEDISASM)==0)
  {

#ifdef DUMP_MSG
    log("+ disassembling\n");
#endif // DUMP_MSG

    // disassemble

    for (;;)
    {

      for (ip = 0; ip < pe->pe_imagesize; ip++)
        if (flag[ip] & FL_NEXT)
          goto c1;

      if (dflags & DF_TRY_DREF)
      {
        for (ip = code_start; ip < code_end; ip++)
        if (flag[ip] & FL_DREF)
        if (!(flag[ip] & (FL_NEXT | FL_ANALYZED | FL_FIXUP | FL_DATA)))
        if (memb[ip] != 0x00)
        {

          flag[ip] |= FL_ANALYZED;

          DWORD j = ip;
          for (/*int opcount=0*/; j < pe->pe_imagesize - 16; /*opcount++*/)
          {
            DWORD len = xde_disasm( &memb[j], &diza );
            if (len==0) break;

            if (diza.flag & C_BAD) break;

            DWORD rel = NONE;
            if (diza.flag & C_REL)
            {
              if (diza.datasize == 1) rel = j + len + diza.data_c[0];
              if (diza.datasize == 2) rel = j + len + diza.data_s[0];
              if (diza.datasize == 4) rel = j + len + diza.data_l[0];
            }

            if (rel != NONE)
            {
              if (rel > code_end)
                break;
              if (flag[rel] & (FL_DATA | FL_FIXUP))
                break;
              if ( (flag[rel] & FL_CODE) && (!(flag[rel] & FL_OPCODE)) )
                break;
            }

            if (   (diza.flag & C_STOP) ||
                   (flag[j] & FL_OPCODE)   )
            {
    //        if (opcount < 2) break;
              flag[ip] |= FL_NEXT;
              goto c1;
            }

            if (flag[j] & (FL_DATA | FL_FIXUP))
              break;

            for (DWORD i=j+1; i<j+len; i++)
              if ( flag[i] & (FL_LABEL|FL_OPCODE|FL_DATA) )
                goto c2;

//            if (len>4)
//            for (DWORD i=j+len-3; i<j+len; i++)
//              if ( flag[i] & FL_FIXUP )
//                goto c2;

            j += len;

            if (j > code_end)
              break;

          }
    c2: ;
        } // FL_DREF
      } // DF_TRY_DREF

      if (dflags & DF_TRY_RELREF)
      {
        for (ip = code_start; ip < code_end; ip++)
        if (!(flag[ip] & FL_ANALYZED))
        {
          DWORD rel = NONE, arg = 0;
          BYTE o = memb[ip];
          WORD w = memw[ip];
          if ((w&0xF0FF)==0x800F)
          {
            arg = (long)(memd[ip + 2]);
            rel = ip + 6 + arg;
          }
          if ((o==0xE8)||(o==0xE9))
          {
            arg = (long)(memd[ip + 1]);
            rel = ip + 5 + arg;
          }
          if (rel != NONE)
          if (arg & 0x00)
          if (rel < code_end)
            if (flag[rel] & FL_OPCODE)
            {
              flag[ip] |= FL_NEXT;
              goto c1;
            }
        }
      } // DF_TRY_RELREF

      break;

  c1:

      for (;;)
      {
        flag[ip] &= ~FL_NEXT;
        flag[ip] |= FL_ANALYZED;

        if (ip == 0) break;

        DWORD len = xde_disasm( &memb[ip], &diza );
        if (len==0) break;

        //if (diza.flag & C_BAD) break;

        for (DWORD i = 1; i < len; i++)
          if (flag[ip + i] & (FL_LABEL | FL_CODE | FL_OPCODE | FL_ANALYZED))
          if (!(flag[ip + i] & (FL_FIXUP | FL_SIGNATURE)))    // ???????
          {
            error_count++;      // !!!
            if (dflags & DF_ENABLE_ERRDISASM)
            {
              return MF_ERR_DISASM;
            }
            else
            {
              flag[ip + i] |= FL_ERROR;
              goto c3;
            }
          }

        DWORD nxt = ip + len;
        DWORD rel = NONE;

        if (diza.flag & C_REL)
        {
          if (diza.datasize == 1) // jcc,jcxz,loop/z/nz,jmps
          {
            rel = nxt + diza.data_c[0];
            arg2[ip] = 1;
          }
          if (diza.datasize == 2) break;
          if (diza.datasize == 4) // jcc near,call,jmp
          {
            rel = nxt + diza.data_l[0];
            arg2[ip] = 4;
          }
        }

        if (diza.flag & C_STOP)
          nxt=NONE; // ret/ret#/retf/retf#/iret/jmp modrm

        if (rel != NONE)
        {
          if (rel > code_end)
          {
            break;
          }

          if (flag[rel] & (FL_DATA | FL_FIXUP)) break;
          if ( (flag[rel] & FL_CODE) && (!(flag[rel] & FL_OPCODE)) ) break;

          flag[ip] |= FL_HAVEREL;
          flag[rel] |= FL_LABEL | FL_CREF;
          if ((flag[rel] & FL_ANALYZED) == 0)
            flag[rel] |= FL_NEXT;
          arg1[ip] = rel;
        }

        for (i = 0; i < len; i++)
        {
          flag[ip + i] |= FL_CODE | FL_ANALYZED;
          flag[ip + i] &= ~(FL_OPCODE | FL_NEXT);
        }
        flag[ip] |= FL_OPCODE;

        if (nxt == NONE)
        {
          flag[ip] |= FL_STOP;
          break;
        }

        ip = nxt;

        if (ip > code_end)
          break;

        if (flag[ip] & FL_CODE) break;

      } // cycle until RET
  c3: ;
    } // main cycle

  } // DF_DISABLEDISASM

  // sigman-2

#ifdef DUMP_MSG
  log("+ building list\n");
#endif // DUMP_MSG

  // build list

  edit_header = (BYTE*)ZAlloc(pe->pe_headersize);
  if (edit_header == NULL)
  {
    error_count++;
    return MF_ERR_NOMEMORY;
  }
  memcpy(edit_header, memb, pe->pe_headersize);

  edit_mz = (MZ_HEADER*)   &edit_header[ 0 ];
  edit_pe = (PE_HEADER*)   &edit_header[ edit_mz->mz_neptr ];
  edit_oe = (PE_OBJENTRY*) &edit_header[ edit_mz->mz_neptr + sizeof(PE_HEADER) ];

  //assert(HooyList.entry_size !=0 );
  HooyList.Empty();

  for (  i = 0;
         (i < pe->pe_imagesize) || ((i == pe->pe_imagesize) && flag[i]);   )
  {

    DWORD l;
    int fix1 = 0, fix2 = -1;
    if (flag[i] & (FL_SECTALIGN | FL_LABEL))
      l = 0;
    else
    if (flag[i] & FL_OPCODE)
    {
      l = xde_disasm( &memb[i], &diza );
      for(int t=1; t<l; t++)
      {
        if (flag[i+t] & FL_FIXUP)
        {
          fix1 = arg1[i+t];
          fix2 = t;
        }
        if ((flag[i+t]&(~FL_FIXUP)) != (FL_CODE | FL_ANALYZED | FL_PRESENT | FL_VPRESENT))
        {
          error_count++;
          flag[i] |= FL_ERROR;
          l = t;
          break;
        }
      }
    }
    else
    if (flag[i] & (FL_RVA | FL_DELTA | FL_FIXUP))
      l = 4;
    else
    {
      for (l=1; (flag[i] == flag[i+l]) && (i+l < pe->pe_imagesize); l++) ;
      flag[i] |= FL_DATA;
    }

    HOOY* t = (HOOY*) HooyList.Alloc();
    if (t==NULL)
    {
      error_count++;
      return MF_ERR_NOMEMORY;
    }
//    t->parent = this;
    t->flags = flag[i];
    t->oldrva = i;
    t->datalen = l;
    if (l)
    {
      if (t->oldrva < pe->pe_headersize)
      {
        t->flags |= FL_HEADER;
        t->dataptr = &edit_header[i];
      }
      else
      {
        t->dataptr = (BYTE*) ZAlloc( l );
        if (t->dataptr==0)
        {
          error_count++;
          return MF_ERR_NOMEMORY;
        }
        memcpy(t->dataptr, &memb[i], l);
      }
    }
    else
      t->dataptr = NULL;
    t->arg1 = arg1[i];
    t->arg2 = arg2[i];
    t->next = NULL;
//    t->text = argt[i];
//    argt[i] = NULL;

    if (fix2 != -1)
    {
      t->flags |= FL_FIXUP;
      t->arg1  = fix1;
      t->arg2  = fix2;
    }

    if (flag[i] & FL_SECTALIGN)
    {
      t->flags &=   FL_SECTALIGN;
      flag[i]  &= ~(FL_SECTALIGN);
    }
    else
    if (flag[i] & FL_LABEL)
    {
      t->flags &=   FL_LABEL | FL_CREF | FL_DREF;
      flag[i]  &= ~(FL_LABEL | FL_CREF | FL_DREF);
    }

    HooyList.Attach(t);

    i += l;
  }

//  for(i=0; i<=pe->pe_imagesize; i++)
//    ZFreeV((void**)&argt[i]);
//  ZFreeV((void**)&argt);
  ZFreeV((void**)&memb);
  ZFreeV((void**)&flag);
  ZFreeV((void**)&arg1);
  ZFreeV((void**)&arg2);

  can_patch = 1;
  return MF_ERR_SUCCESS;

} // CMistfall::Disasm()

HOOY* CMistfall::hooybyoldrva(DWORD oldrva, DWORD needflags)
{
  HOOY* h;
  ForEachInList(HooyList, HOOY, h)
    if (h->flags & needflags)
    if (h->oldrva == oldrva)
      return h;
  return NULL;
} // hooybyoldrva

int CMistfall::N_Asm(int full)
{

  if (full == 0)
  {

    ;;

    return MF_ERR_SUCCESS;

  } // full == 0
  else
  { // full == 1

    // there were errors while disasm, so we cant reassemble file
//    if (error_count != 0)
//      return MF_ERR_CANT_REASSEMBLE;

    error_count = 0;

  #ifdef DUMP_MSG
    log("+ asm()\n");
  #endif // DUMP_MSG

    // its incorrect, because disallows moving PE/OE
    memcpy(mz, edit_mz, sizeof(MZ_STRUCT));
    memcpy(pe, edit_pe, sizeof(PE_STRUCT));
    memcpy(oe, edit_oe, sizeof(PE_OBJENTRY) * pe->pe_numofobjects);

    fasthooy = (HOOY**)ZAlloc( (pe->pe_imagesize+1)*4 );
    if (fasthooy == NULL)
    {
      error_count++;
      return MF_ERR_NOMEMORY;
    }

    // find entry that describes whole fixup structure
    HOOY* fxrva  = hooybyoldrva(pe->pe_fixuprva, FL_DATA);
    if (fxrva==NULL)
    {
      error_count++;
      return MF_ERR_INTERNAL1;
    }
//    HOOY* fxsize = hooybyoldrva(mz->mz_neptr+0xA4, FL_DELTA);   //A4=fixupsize
//    if (fxsize==NULL)
//    {
//      error_count++;
//      return MF_ERR_INTERNAL2;
//    }
//
//  re:
//    fxrva->dataptr = (BYTE*) ZReAlloc( fxrva->dataptr, fxrva->datalen );
//    if (fxrva->dataptr == NULL)
//    {
//      error_count++;
//      return MF_ERR_NOMEMORY;
//    }
//
  #ifdef DUMP_MSG
    log("+ recalculating addresses\n");
  #endif // DUMP_MSG
//
    // recalculate addresses

    memset(fasthooy, 0x00, (pe->pe_imagesize+1)*4);

    DWORD v = 1, p = 0;
    HOOY* h;
    ForEachInList(HooyList, HOOY, h)
    {
      if (h->flags & FL_LABEL)
        fasthooy[h->oldrva] = h;

      h->newrva = v;
      h->newofs = p;

      if (h->flags & FL_OPCODE)
//      {
//        v = ALIGN(v, pe->pe_objectalign);
//        p = ALIGN(p, pe->pe_filealign);
//      }
//      else
      {
//        if (h->flags & FL_VPRESENT) v += h->datalen;
//        if (h->flags & FL_PRESENT)  p += h->datalen;
        v++;
      }
    }
//
//  #ifdef DUMP_MSG
//    log("+ rebuilding fixup table\n");
//  #endif // DUMP_MSG
//
//    // rebuild fixup table
//
//    DWORD xptr = 0, o = 0, xbase;
//    ForEachInList(HooyList, HOOY, h)
//    {
//      if (h->flags & FL_FIXUP)
//      {
//        if (o == 0)
//        {
//  c7:
//          xbase = (h->newrva+h->arg2) & 0xFFFFF000;
//          if (xptr+0+4 > fxrva->datalen)
//          {
//            fxrva->datalen += 65536;
//            goto re;
//          }
//          *(DWORD*)&(fxrva->dataptr[xptr+0]) = xbase;
//          o = 8;
//        }
//        if ((h->newrva+h->arg2) - xbase > 0xFFF)
//        {
//          if (xptr+4+4 > fxrva->datalen)
//          {
//            fxrva->datalen += 65536;
//            goto re;
//          }
//          *(DWORD*)&(fxrva->dataptr[xptr+4]) = o;
//          xptr += o;
//          goto c7;
//        }
//        if (xptr+o+2 > fxrva->datalen)
//        {
//          fxrva->datalen += 65536;
//          goto re;
//        }
//        *(WORD*)&(fxrva->dataptr[xptr+o]) = ((h->newrva+h->arg2) - xbase) | 0x3000;
//        o += 2;
//      }
//    }
//    if (o != 0)
//    {
//      if (xptr+o > fxrva->datalen)
//      {
//        fxrva->datalen += 65536;
//        goto re;
//      }
//      *(DWORD*)&(fxrva->dataptr[xptr+4]) = o;
//      xptr += o;
//    }
//
//    if (xptr==0)
//    {
//      error_count++;
//      return MF_ERR_NOFIXUPS;         // new fixup table size == 0
//    }
//
//    fxrva->datalen = xptr;
//
//    if (*(DWORD*)fxsize->dataptr != xptr)
//    {
//      *(DWORD*)fxsize->dataptr = xptr;
//      goto re;
//    }

//  #ifdef DUMP_MSG
//    log("+ recalculating pointers\n");
//  #endif // DUMP_MSG
//
//    // recalc pointers
//
//    //int expanded = 0;
//
//#define SETHOOY(x,y)  HOOY* x = (y) <= pe->pe_imagesize ? fasthooy[ y ] : NULL;
//
//    ForEachInList(HooyList, HOOY, h)
//    {
////      if (h->flags & FL_RVA)
////      {
////        SETHOOY(h1, h->arg1);
////        if (h1)
////        if (h->flags & FL_PHYS)
////          *(DWORD*)h->dataptr = h1->newofs;
////        else
////          *(DWORD*)h->dataptr = h1->newrva;
////      }
////      if (h->flags & FL_FIXUP)
////      {
////        SETHOOY(h1, h->arg1);
////        if (h1)
////        *(DWORD*)&h->dataptr[h->arg2] = h1->newrva + pe->pe_imagebase;
////        // else error
////      }
////      if (h->flags & FL_DELTA)
////      {
////        SETHOOY(h1, h->arg1);
////        SETHOOY(h2, h->arg2);
////        if (h1)
////        if (h2)
////        if (h->flags & FL_PHYS)
////          *(DWORD*)h->dataptr = h2->newofs - h1->newofs;
////        else
////          *(DWORD*)h->dataptr = h2->newrva - h1->newrva;
////      }
////      if (h->flags & FL_RES8)
////      {
////        *(DWORD*)h->dataptr |= 0x80000000;
////      }
////      if (h->flags & FL_FORCEOBJALIGN)
////      {
////        *(DWORD*)h->dataptr = ALIGN(*(DWORD*)h->dataptr, pe->pe_objectalign);
////      }
////      if (h->flags & FL_FORCEFILEALIGN)
////      {
////        *(DWORD*)h->dataptr = ALIGN(*(DWORD*)h->dataptr, pe->pe_filealign);
////      }
//      if (h->flags & FL_HAVEREL)
//      {
//        SETHOOY(h1, h->arg1);
//        if (h1)
//        {
//          h->arg1 = h1->newrva;
////          DWORD t = h1->newrva - (h->newrva + h->datalen);
////
////          if (h->arg2 == 1)
////          {
////            if ((long)t != (char)t)
////            {
////              if (h->dataptr[0] == 0xEB)
////              {
////                h->dataptr[0]=0xE9;
////                h->datalen=5;
////              }
////              else
////              if ((h->dataptr[0] & 0xF0) == 0x70)
////              {
////                h->dataptr[1]=h->dataptr[0]^0x70^0x80;
////                h->dataptr[0]=0x0F;
////                h->datalen=6;
////              }
////              else
////              if (h->dataptr[0]==0xE3)
////              {
////                h->dataptr[0]=0x09;     // or ecx, ecx
////                h->dataptr[1]=0xC9;
////                h->dataptr[2]=0x0F;     // jz
////                h->dataptr[3]=0x84;
////                h->datalen=2+6;
////              }
////              else
////              if (h->dataptr[0]==0xE2)
////              {
////                h->dataptr[0]=0x49;     // dec ecx
////                h->dataptr[1]=0x0F;     // jnz
////                h->dataptr[2]=0x85;
////                h->datalen=1+6;
////              }
////              else
////              {
////                error_count++;
////                return MF_ERR_CANTEXPAND;
////              }
////              h->arg2 = 4;
////              expanded++;
////            }
////            else
////              h->dataptr[h->datalen-1] = t;
////          }
////
////          if (h->arg2 == 4)
////          {
////            *(DWORD*)&(h->dataptr[h->datalen-4]) = t;
////          }
//        }
//      }
//    } // for h
////
////    if (expanded)
////    {
////      // +pass
////      goto re;
////    }

//  #ifdef DUMP_MSG
//    log("+ assembling\n");
//  #endif // DUMP_MSG
//
//    // assembling
//
//    p = ALIGN( ((HOOY*)HooyList.tail)->newofs, pe->pe_filealign );
//
//    o_phys_len = p + ovr_size;
//    o_phys_mem = (BYTE*)ZReAlloc(o_phys_mem, o_phys_len);
//    if (o_phys_mem == NULL)
//    {
//      error_count++;
//      return MF_ERR_NOMEMORY;
//    }
//
//    ForEachInList(HooyList, HOOY, h)
//    if (h->flags & FL_PRESENT)
//      memcpy(&o_phys_mem[h->newofs], h->dataptr, h->datalen);
//
//    if (ovr_size > 0)
//      memcpy(&o_phys_mem[p], &i_phys_mem[ovr_offs], ovr_size);
//
  } // full == 1
//
//  // recalc csum
//
//  MZ_HEADER* tmz = (MZ_HEADER*) &o_phys_mem[0];
//  PE_HEADER* tpe = (PE_HEADER*) &o_phys_mem[ tmz->mz_neptr ];
//  if (tpe->pe_checksum != 0)
//  {
//    tpe->pe_checksum = 0;
//    tpe->pe_checksum = calc_pe_csum(o_phys_mem, o_phys_len);
//  }

  //ZFreeV((void**)&fasthooy);

  return MF_ERR_SUCCESS;

} // CMistfall::N_Asm()

//DWORD CMistfall::calc_pe_csum(BYTE* buf, DWORD size)
//{
//  DWORD csum = 0;
//  for (DWORD i=0; i<size; i+=2)
//  {
//    csum += *(WORD*)&buf[i];
//    if (csum & 0x10000)
//      csum = ((csum & 0xFFFF) + 1) & 0xffff;
//  }
//  return csum+size;
//} // CMistfall::calc_pe_csum()

void CMistfall::markrva(DWORD x)
{
  if (memd[x] <= pe->pe_imagesize)
  {
    flag[x] |= FL_RVA | FL_DATA;
    flag[memd[x]] |= FL_LABEL | FL_DREF;
    arg1[x] = memd[x];
  }
  else
  {
    error_count++;
    flag[ x ] |= FL_ERROR;
  }
} // CMistfall::markrva()

void CMistfall::markrvadata(DWORD x)
{
  if (memd[x] <= pe->pe_imagesize)
  {
    flag[x] |= FL_RVA | FL_DATA;
    flag[memd[x]] |= FL_LABEL | FL_DREF | FL_DATA;
    arg1[x] = memd[x];
  }
  else
  {
    error_count++;
    flag[ x ] |= FL_ERROR;
  }
} // CMistfall::markrvadata()

void CMistfall::markfixup(DWORD x)
{
  if ( (memd[x] >= pe->pe_imagebase) &&
       (memd[x] < pe->pe_imagebase+pe->pe_imagesize ) )
  {
    flag[ x ] |= FL_FIXUP;
    arg1[x] = memd[x] - pe->pe_imagebase;
    arg2[x] = 0;
    flag[ arg1[x] ] |= FL_LABEL | FL_DREF;
  }
  else
  {
    error_count++;
    flag[ x ] |= FL_ERROR;
  }
} // CMistfall::markfixup()

void CMistfall::markdelta(DWORD x,DWORD y,DWORD z)
{
  if ( (y <= pe->pe_imagesize) &&
       (z <= pe->pe_imagesize) &&
       ((y+z) <= pe->pe_imagesize) )
  {
    flag[x] |= FL_DELTA;
    arg1[x] = y;
    arg2[x] = y+z;
    flag[y]   |= FL_LABEL | FL_DREF;
    flag[y+z] |= FL_LABEL | FL_DREF;
  }
  else
  {
    error_count++;
    flag[ x ] |= FL_ERROR;
  }
} // CMistfall::markdelta()

//void CMistfall::settext(DWORD x, char* fmt, ...)
//{
//  if (x <= pe->pe_imagesize)
//  {
//    va_list va;
//    va_start(va, fmt);
//    char s[1024];
//    vsnprintf(s, sizeof(s)-1, fmt, va);
//    va_end(va);
//
//    char*q = argt[x];
//    argt[x] = (char*)ZAlloc( (q==NULL?0:strlen(q))+strlen(s)+1 );
//    if (argt[x] == NULL)
//    {
//      argt[x] = q;
//      return;
//    }
//    if (q != NULL)
//    {
//      strcpy(argt[x], q);
//      ZFreeV((void**)&q);
//    }
//    strcat(argt[x], s);
//  }
//} // CMistfall::settext
