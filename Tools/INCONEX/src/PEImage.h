
#if !defined(__PEImage_h__)
#define __PEImage_h__

#include <windows.h>

//
// types
//
enum PIModes
{
	PI_MODE_VIRTUAL,
	PI_MODE_RAW
};

//
// macros
//
#if !defined(MakePtr)
#define MakePtr( cast, ptr, addValue )   (cast)( (DWORD)(ptr) + (DWORD)(addValue))
#endif

//
// PE_IMAGE class
//
class PE_IMAGE
{
public:
	IMAGE_DOS_HEADER         *m_pDH;
	IMAGE_NT_HEADERS         *m_pNT;   // always initialized
	IMAGE_NT_HEADERS64       *m_pNT64; // only initalized in case of 64bit PEs
	IMAGE_SECTION_HEADER     *m_pSHT;

	                         PE_IMAGE(void *pImage, PIModes mode);
	                         ~PE_IMAGE();
	BOOL                     Assign(void* pImage, PIModes mode);
	BOOL                     IsPE32Plus() { return m_bPE32Plus; }
	static BOOL              IsPE32Plus(PIMAGE_NT_HEADERS pNT);
	BOOL                     IsAssigned() { return m_bAssigned; }
	DWORD                    GetRealSizeOfHeader();
	PIMAGE_DATA_DIRECTORY    GetDataDirectoryPtr(UINT iIndex);
	void*                    GetDataDirectoryEntryPtr(UINT iIndex);
	void*                    RvaToVa(DWORD dwRva);

private:
	PIModes                  m_mode;
	void*                    m_pBase;
	BOOL                     m_bPE32Plus;
	BOOL                     m_bAssigned;
};

typedef PE_IMAGE *PPE_IMAGE;

#endif // __PEImage_h__