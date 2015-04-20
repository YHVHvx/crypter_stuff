#include <Windows.h>

#include "klog.h"

extern KLOG* pLog;

void *MemAlloc(DWORD size){
	return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
}

void MemFree(void *p){
	if(!p) return;
	HeapFree(GetProcessHeap(), 0, p);
}

void Log(PCHAR fmt, ...){
	char buffer[1024];

	va_list ap;
	va_start(ap, fmt);
	VsPrintf(buffer, fmt, ap);
	pLog->Output(buffer);
	va_end(ap);
}
