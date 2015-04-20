
#include "PEImage.h"
#include <imagehlp.h>
#pragma  comment(lib, "imagehlp.lib")

PE_IMAGE::PE_IMAGE(void *pImage, PIModes mode)
{
	m_bAssigned = Assign(pImage, mode);
}

PE_IMAGE::~PE_IMAGE()
{}

BOOL PE_IMAGE::Assign(void* pImage, PIModes mode)
{
	m_bAssigned = FALSE;

	// mode valid ?
	if (mode != PI_MODE_VIRTUAL && mode != PI_MODE_RAW)
		return FALSE; // ERR

	// get ptr to NT hdrs
	m_pNT = ImageNtHeader(pImage);
	if (!m_pNT)
		return FALSE; // ERR

	// set some member vars
	m_pDH       = (PIMAGE_DOS_HEADER)pImage;
	m_bPE32Plus = IsPE32Plus(m_pNT);
	if (m_bPE32Plus)
	{
		m_pNT64     = (PIMAGE_NT_HEADERS64)m_pNT;
		m_pSHT      = IMAGE_FIRST_SECTION64(m_pNT64);
	}
	else
	{
		m_pSHT      = IMAGE_FIRST_SECTION32(m_pNT);
	}
	m_pBase = pImage;

	m_bAssigned = TRUE;
	return TRUE; // OK
}

BOOL PE_IMAGE::IsPE32Plus(PIMAGE_NT_HEADERS pNT)
{
	return pNT->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC ? TRUE : FALSE;
}

//
// Returns: -1 (error)
//
DWORD PE_IMAGE::GetRealSizeOfHeader()
{
	DWORD                  dwHSize;
	UINT                   i;
	IMAGE_SECTION_HEADER   *pS;

	if (!m_bAssigned)
		return -1; // ERR

	// find real size of headers my finding the lowest RO
	dwHSize = 0xFFFFFFFF;
	pS = m_pSHT;
	for (i = 0; i < m_pNT->FileHeader.NumberOfSections; i++)
	{
		if (pS->PointerToRawData) // Watcom C/C++ hits an other time :)
			dwHSize = __min(dwHSize, pS->PointerToRawData);
		++pS;
	}

	return dwHSize;
}

//
// Returns: NULL (error)
//
PIMAGE_DATA_DIRECTORY PE_IMAGE::GetDataDirectoryPtr(UINT iIndex)
{
	if ( !m_bAssigned )
		return FALSE; // ERR

	if (m_mode == PI_MODE_RAW)
	{
		// RAW MODE
		// TODO
		return FALSE;
	}
	else
	{
		// VIRTUAL MODE
		if (m_bPE32Plus)
		{
			if (iIndex >= m_pNT64->OptionalHeader.NumberOfRvaAndSizes) // out of range ?
				return NULL;
			return &m_pNT64->OptionalHeader.DataDirectory[iIndex];
		}
		else
		{
			if (iIndex >= m_pNT->OptionalHeader.NumberOfRvaAndSizes) // out of range ?
				return NULL;
			return &m_pNT->OptionalHeader.DataDirectory[iIndex];
		}
	}
}

//
// Returns: NULL (error)
//
void* PE_IMAGE::GetDataDirectoryEntryPtr(UINT iIndex)
{
	PIMAGE_DATA_DIRECTORY pIDD;

	if (!m_bAssigned)
		return NULL; // ERR

	pIDD = GetDataDirectoryPtr(iIndex);
	if (!pIDD)
		return NULL; // ERR

	if (m_mode == PI_MODE_RAW)
	{
		// RAW MODE
		// TODO
		return NULL;
	}
	else
	{
		// VIRTUAL MODE
		return MakePtr(PVOID, m_pBase, pIDD->VirtualAddress);
	}	
}

//
// Returns: NULL (error)
//
void* PE_IMAGE::RvaToVa(DWORD dwRva)
{
	if (!m_bAssigned)
		return NULL; // ERR

	if (m_mode == PI_MODE_RAW)
	{
		// RAW MODE
		// TODO
		return NULL;
	}
	else
	{
		// VIRTUAL MODE
		return MakePtr(PVOID, m_pBase, dwRva);
	}	
}