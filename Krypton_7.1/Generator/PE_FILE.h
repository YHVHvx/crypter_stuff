#define SIZE_OF_NT_SIGNATURE (sizeof(DWORD)) 

#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a +  \
	((PIMAGE_DOS_HEADER)a)->e_lfanew + SIZE_OF_NT_SIGNATURE))
PIMAGE_FILE_HEADER   pfh;


/* Вычисляет смещение на MZ заголовок MS-DOS. */
BOOL WINAPI GetDosHeader (LPVOID, PIMAGE_DOS_HEADER);

/* Определяет тип .EXE файла. */
DWORD WINAPI ImageFileType (LPVOID);

/* Вычисляет смещение на заголовок PE файла. */
BOOL WINAPI GetPEFileHeader (LPVOID, PIMAGE_FILE_HEADER);

/* Вычисляет смещение на опциональный заголовок .*/
BOOL WINAPI GetPEOptionalHeader (LPVOID,
                                  PIMAGE_OPTIONAL_HEADER);

/* Возвращает адрес точки входа. */
LPVOID WINAPI GetModuleEntryPoint (LPVOID);

/* Возвращает количество сегментов в файле. */
int  WINAPI NumOfSections (LPVOID);

/* Возвращает предпочтительный базовый адрес исполнимого
   файла при его загрузке в адресное пространство процесса. */
LPVOID WINAPI GetImageBase (LPVOID);

/* Определяет местоположение в исполнимом файле указанного
   каталога данных. */
LPVOID WINAPI ImageDirectoryOffset (LPVOID, DWORD);

/* Извлекает имена всех сегментов файла. */
int WINAPI GetSectionNames (LPVOID, HANDLE, char **);

/* Копирует заголовок указанного сегмента. */
BOOL WINAPI GetSectionHdrByName (LPVOID,
                                  PIMAGE_SECTION_HEADER, char *);

/* Возвращает список имен импортируемых модулей,
   разделенных нулевым символом. */
int WINAPI GetImportModuleNames (LPVOID, HANDLE, char  **);

/* Возвращает список имен импортируемых из указанного
   модуля функций, разделенных нулевым символом. */
int WINAPI GetImportFunctionNamesByModule (LPVOID, HANDLE,
                                           char *, char  **);

/* Возвращает список имен экспортируемых функций,
   разделенных нулевым символом. */
int WINAPI GetExportFunctionNames (LPVOID, HANDLE, char **);

/* Возвращает количество экспортируемых функций. */
int WINAPI GetNumberOfExportedFunctions (LPVOID);

/* Возвращает список виртуальных адресов экспортируемых функций. */
LPVOID WINAPI GetExportFunctionEntryPoints (LPVOID);

/* Возвращает список номеров экспортируемых функций. */
LPVOID WINAPI GetExportFunctionOrdinals (LPVOID);

/* Опрелеляет общее число объектов ресурсов. */
int WINAPI GetNumberOfResources (LPVOID);

/* Возвращает список всех типов ресурсов,
   используемых в модуле. */
int WINAPI GetListOfResourceTypes (LPVOID, HANDLE, char **);

/* Определяет, удалена ли из исполнимого файла
   отладочная информация. */
BOOL WINAPI IsDebugInfoStripped (LPVOID);

/* Возвращает имя исполнимого файла. */
int WINAPI RetrieveModuleName (LPVOID, HANDLE, char **);

/* Определяет, является ли файл правильным отладочным файлом. */
BOOL WINAPI IsDebugFile (LPVOID);

/* Возвращает отладочный заголовок из
   отладочного файла. */
BOOL WINAPI GetSeparateDebugHeader(LPVOID,
                                   PIMAGE_SEPARATE_DEBUG_HEADER);
  

//В дополнение к вышеприведенным функциям, все макросы, упоминавшиеся ранее, также определены в файле заголовков PEFILE.H. Вот их полный список:
/* Смещение на сигнатуру PE файла                           */
#define NTSIGNATURE(a) ((LPVOID)((BYTE *)a                +  \
                        ((PIMAGE_DOS_HEADER)a)->e_lfanew))

/* Операционные системы MS идентифицируют PE файлы по сигнатуре
   размером dword; заголовок PE файла расположен непосредственно
   после этого dword					     */
#define PEFHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                             SIZE_OF_NT_SIGNATURE))

/* Опциональный заголовок - сразу после заголовка PE файла   */
#define OPTHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                           SIZE_OF_NT_SIGNATURE           +  \
                           sizeof (IMAGE_FILE_HEADER)))

/* Заголовки сегментов - сразу после опционального заголовка */
#define SECHDROFFSET(a) ((LPVOID)((BYTE *)a               +  \
                         ((PIMAGE_DOS_HEADER)a)->e_lfanew +  \
                           SIZE_OF_NT_SIGNATURE           +  \
                           sizeof (IMAGE_FILE_HEADER)     +  \
                           sizeof (IMAGE_OPTIONAL_HEADER)))

//************************************************************************************
int   WINAPI NumOfSections (LPVOID lpFile)
{
	/* Число сегментов из заголовка PE файла. */
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

	/* должен быть от 0 до (NumberOfRvaAndSizes-1). */
	if (dwIMAGE_DIRECTORY >= poh->NumberOfRvaAndSizes)
		return NULL;

	/* Получим смещения опционального заголовка и заголовка сегмента */
	poh = (PIMAGE_OPTIONAL_HEADER)OPTHDROFFSET (lpFile);
	psh = (PIMAGE_SECTION_HEADER)SECHDROFFSET (lpFile);

	/* Найдем относительный виртуальный адрес каталога */
	VAImageDir = (LPVOID)poh->DataDirectory
		[dwIMAGE_DIRECTORY].VirtualAddress;

	/* Найдем сегмент, содержащий нужный каталог */
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

	/* Вернем смещение на каталог данных */
	return (LPVOID)(((int)lpFile +
		(int)VAImageDir - psh->VirtualAddress) +
		(int)psh->PointerToRawData);
}