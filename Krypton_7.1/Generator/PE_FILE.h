#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD)) 

#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a +  \
	((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
PIMAGE_FILE_HEADER   pfh;


/* ��������� �������� �� MZ ��������� MS-DOS. */
BOOL WINAPI GetDosHeader (LPVOID, PIMAGE_DOS_HEADER);

/* ���������� ��� .EXE �����. */
DWORD WINAPI ImageFileType (LPVOID);

/* ��������� �������� �� ��������� PE �����. */
BOOL WINAPI GetPEFileHeader (LPVOID, PIMAGE_FILE_HEADER);

/* ��������� �������� �� ������������ ��������� .*/
BOOL WINAPI GetPEOptionalHeader (LPVOID,
                                  PIMAGE_OPTIONAL_HEADER);

/* ���������� ����� ����� �����. */
LPVOID WINAPI GetModuleEntryPoint (LPVOID);

/* ���������� ���������� ��������� � �����. */
int  WINAPI NumOfSections (LPVOID);

/* ���������� ���������������� ������� ����� �����������
   ����� ��� ��� �������� � �������� ������������ ��������. */
LPVOID WINAPI GetImageBase (LPVOID);

/* ���������� �������������� � ���������� ����� ����������
   �������� ������. */
LPVOID WINAPI ImageDirectoryOffset (LPVOID, DWORD);

/* ��������� ����� ���� ��������� �����. */
int WINAPI GetSectionNames (LPVOID, HANDLE, char **);

/* �������� ��������� ���������� ��������. */
BOOL WINAPI GetSectionHdrByName (LPVOID,
                                  PIMAGE_SECTION_HEADER, char *);

/* ���������� ������ ���� ������������� �������,
   ����������� ������� ��������. */
int WINAPI GetImportModuleNames (LPVOID, HANDLE, char  **);

/* ���������� ������ ���� ������������� �� ����������
   ������ �������, ����������� ������� ��������. */
int WINAPI GetImportFunctionNamesByModule (LPVOID, HANDLE,
                                           char *, char  **);

/* ���������� ������ ���� �������������� �������,
   ����������� ������� ��������. */
int WINAPI GetExportFunctionNames (LPVOID, HANDLE, char **);

/* ���������� ���������� �������������� �������. */
int WINAPI GetNumberOfExportedFunctions (LPVOID);

/* ���������� ������ ����������� ������� �������������� �������. */
LPVOID WINAPI GetExportFunctionEntryPoints (LPVOID);

/* ���������� ������ ������� �������������� �������. */
LPVOID WINAPI GetExportFunctionOrdinals (LPVOID);

/* ���������� ����� ����� �������� ��������. */
int WINAPI GetNumberOfResources (LPVOID);

/* ���������� ������ ���� ����� ��������,
   ������������ � ������. */
int WINAPI GetListOfResourceTypes (LPVOID, HANDLE, char **);

/* ����������, ������� �� �� ����������� �����
   ���������� ����������. */
BOOL WINAPI IsDebugInfoStripped (LPVOID);

/* ���������� ��� ����������� �����. */
int WINAPI RetrieveModuleName (LPVOID, HANDLE, char **);

/* ����������, �������� �� ���� ���������� ���������� ������. */
BOOL WINAPI IsDebugFile (LPVOID);

/* ���������� ���������� ��������� ��
   ����������� �����. */
BOOL WINAPI GetSeparateDebugHeader(LPVOID,
                                   PIMAGE_SEPARATE_DEBUG_HEADER);
  

//� ���������� � ��������������� ��������, ��� �������, ������������� �����, ����� ���������� � ����� ���������� PEFILE.H. ��� �� ������ ������:
/* �������� �� ��������� PE �����                           */
#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a                +  \
                        ((PIMAGE_DOS_HEADER)a)->e_lfanew))

/* ������������ ������� MS �������������� PE ����� �� ���������
   �������� dword; ��������� PE ����� ���������� ���������������
   ����� ����� dword					     */
#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                             SIZE_OF_NT_SIGNATURE))

/* ������������ ��������� - ����� ����� ��������� PE �����   */
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                           SIZE_OF_NT_SIGNATURE           +  \
                           sizeof (IMAGE_FILE_HEADER)))

/* ��������� ��������� - ����� ����� ������������� ��������� */
#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                           SIZE_OF_NT_SIGNATURE           +  \
                           sizeof (IMAGE_FILE_HEADER)     +  \
                           sizeof (IMAGE_OPTIONAL_HEADER)))

//************************************************************************************
int   WINAPI NumOfSections (LPVOID lpFile)
{
	/* ����� ��������� �� ��������� PE �����. */
	return ((int)(((PIMAGE_FILE_HEADER)(PEFHDROFFSET(lpFile)))->NumberOfSections));
}
//*********************
LPVOID  WINAPI ImageDirectoryOffset (
	LPVOID    lpFile,
	DWORD     dwIMAGE_DIRECTORY)
{
	PIMAGE_OPTIONAL_HEADER   poh;
	PIMAGE_SECTION_HEADER    psh;
	int                      nSections = NumOfSections (lpFile);
	int                      i = 0;
	LPVOID                   VAImageDir;

	/* ������ ���� �� 0 �� (NumberOfRvaAndSizes-1). */
	if (dwIMAGE_DIRECTORY >= poh->NumberOfRvaAndSizes)
		return NULL;

	/* ������� �������� ������������� ��������� � ��������� �������� */
	poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET (lpFile);
	psh = (PIMAGE_SECTION_HEADER)SECHDROFFSET (lpFile);

	/* ������ ������������� ����������� ����� �������� */
	VAImageDir = (LPVOID)poh->DataDirectory
		[dwIMAGE_DIRECTORY].VirtualAddress;

	/* ������ �������, ���������� ������ ������� */
	while (i++<nSections)
	{
		if (psh->VirtualAddress <= (DWORD)VAImageDir &&
			psh->VirtualAddress +
			psh->SizeOfRawData > (DWORD)VAImageDir)
			break;
		psh++;
	}

	if (i > nSections)
		return NULL;

	/* ������ �������� �� ������� ������ */
	return (LPVOID)(((int)lpFile +
		(int)VAImageDir - psh->VirtualAddress) +
		(int)psh->PointerToRawData);
}