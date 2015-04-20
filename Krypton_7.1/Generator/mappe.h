#pragma once

#define ALIGN_DOWN(x, align)	(x & ~(align-1))
#define ALIGN_UP(x, align)		((x & (align-1)) ?ALIGN_DOWN(x, align) + align:x)
#define MIN(x1, x2)				(x1<x2)?x1:x2


DWORD ProcessImports(DWORD ImageBase, IMAGE_IMPORT_DESCRIPTOR* pImport);
DWORD MapPE(char* szExeFile, DWORD* Entry);
