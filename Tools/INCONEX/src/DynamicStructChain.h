
/*****************************************************************************

  DynamicStructChain
  ------------------

  Small class to handle dynamic memory buffers holding a structure array.

  by yoda

  WWW:      y0da.cjb.net
  E-mail:   LordPE@gmx.net

  You are allowed to use this class in your own projects if you keep this
  trademark.

*****************************************************************************/


#ifndef __DynamicStructChain_h__
#define __DynamicStructChain_h__

#include <windows.h>

//
// constants
//
#define DSC_MEM_START_ITEM_NUM    50   // XX*structsize                 = start memory size
#define DSC_MEM_ITEM_GROWTH_NUM   100  // XX*structsize + old mem size  = new memsize

//
// macros
//
#if !defined(MakePtr)
#define MakePtr( cast, ptr, addValue )   (cast)( (DWORD)(ptr) + (DWORD)(addValue))
#endif

//
// DynamicStructChain
//
class DynamicStructChain
{
public:
	DynamicStructChain();
	DynamicStructChain(DWORD dwStructureSize);
	~DynamicStructChain();
	void              SetStructSize(DWORD dwSize);
	void              SetMemStartItemNum(DWORD dwc);    // 0 -> set default
	void              SetMemGrowthItemNum(DWORD dwc);   // 0 -> set default
	DWORD             GetItemNum();
	BOOL              AddItem(void* pStruct);
	BOOL              DeleteItem(UINT index);
	void*             GetItem(UINT index);
	//void              ReInit();
	DWORD             GetStructSize();
	DWORD             GetCurrentMemSize();
	BOOL              Free();

private:
	DWORD             dwMemGrowthItemNum;
	DWORD             dwMemStartItemNum;
	DWORD             dwStructSize;
	DWORD             dwItemNum;
	void*             pMem;
	DWORD             dwMemSize;

	void              InitClass();
};


#endif