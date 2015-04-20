
#include "DynamicStructChain.h"

// initialization routine for all constructor functions
void DynamicStructChain::InitClass()
{
	dwMemSize   = 0;
	pMem        = NULL;
	dwItemNum   = 0;
	dwMemStartItemNum  = DSC_MEM_START_ITEM_NUM;
	dwMemGrowthItemNum = DSC_MEM_ITEM_GROWTH_NUM;

	return;
}

DynamicStructChain::DynamicStructChain()
{
	dwStructSize = 0;
	InitClass();
}

DynamicStructChain::DynamicStructChain(DWORD dwStructureSize)
{
	dwStructSize = dwStructureSize;
	InitClass();
}

DynamicStructChain::~DynamicStructChain()
{
	// cleanup
	if (dwMemSize)
		free(pMem);
}

void DynamicStructChain::SetStructSize(DWORD dwSize)
{
	dwStructSize = dwSize;

	return;
}

void DynamicStructChain::SetMemStartItemNum(DWORD dwc)
{
	if (dwc == 0)
		dwMemStartItemNum  = DSC_MEM_START_ITEM_NUM;
	else
		dwMemStartItemNum  = dwc;

	return;
}

void DynamicStructChain::SetMemGrowthItemNum(DWORD dwc)
{
	if (dwc == 0)
		dwMemGrowthItemNum = DSC_MEM_ITEM_GROWTH_NUM;
	else
		dwMemGrowthItemNum = dwc;

	return;
}

DWORD DynamicStructChain::GetItemNum()
{
	return dwItemNum;
}

//
// Adds an a item at the end of the structure chain memory
//
// returns:
// FALSE - not enough memory / dwStructSize not set
//
BOOL DynamicStructChain::AddItem(void* pStruct)
{
	DWORD dwNewMemSize;

	if (!dwStructSize)
		return FALSE;

	// handle memory size
	if ((dwItemNum + 1) * dwStructSize > dwMemSize)
	{
		// need to get more memory
		if (dwMemSize == 0)
		{
			// it's the first item
			dwNewMemSize = dwMemStartItemNum*dwStructSize;
			pMem = malloc(dwNewMemSize);
		}
		else
		{
			// isn't the first item
			dwNewMemSize = dwMemGrowthItemNum*dwStructSize + dwMemSize;
			pMem = realloc(pMem, dwNewMemSize);
		}

		if (!pMem)
			return FALSE;

		dwMemSize = dwNewMemSize;
	}

	// add the item
	memcpy(
		(void*)((DWORD)pMem + dwStructSize*dwItemNum),
		pStruct,
		dwStructSize);
	++dwItemNum;

	return TRUE;
}

//
// NOT FULLY TESTED !
//
// wipes the specified structure out of the structure chain memory
//
// returns:
// FALSE - error (not in list)
//
BOOL DynamicStructChain::DeleteItem(UINT index)
{
	// out of range ?
	if (index >= dwItemNum)
		return FALSE; // ERR
	// last item ?
	if (index == dwItemNum - 1)
	{
		--dwItemNum;
		return TRUE; // OK
	}
	//
	// move memory - overwrite the unwanted struct with the following
	//
	memcpy(
		MakePtr(PVOID, pMem, index * dwStructSize),
		MakePtr(PVOID, pMem, (index + 1) * dwStructSize),
		sizeof(dwStructSize) * (dwItemNum - 1 - index));
	--dwItemNum; // adjust member variables

	return TRUE;
}

//
// returns:
// NULL if the item marked by "index" doesn't exist
//
void* DynamicStructChain::GetItem(UINT index)
{
	if (index > dwItemNum)
		return NULL;

	return (void*)((DWORD)pMem + dwStructSize*index);
}

DWORD DynamicStructChain::GetStructSize()
{
	return dwStructSize;
}

DWORD DynamicStructChain::GetCurrentMemSize()
{
	return dwMemSize;
}

//
// Set the whole class to intialize state BUT "dwStructSize" is hold
//
BOOL DynamicStructChain::Free()
{
	if (dwMemSize)
	{
		free(pMem);
		InitClass();
		return TRUE;
	}

	return FALSE;
}