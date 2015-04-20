
#ifndef __OFN_h__
#define __OFN_h__

#include <windows.h>
#include <commdlg.h>

//
// constants
//
#define DEFAULT_OFN_SAVE    OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT
#define DEFAULT_OFN_OPEN    OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY

//
// OFN
//
class OFN
{
public:
	OPENFILENAME  ofnOpen;
	OPENFILENAME  ofnSave;
	char          cPathOpen[MAX_PATH], cPathSave[MAX_PATH];

	OFN();
	~OFN();
	BOOL          GetOpenFilePath();
	BOOL          GetSaveFilePath();
};

#endif