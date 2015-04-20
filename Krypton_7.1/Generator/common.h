#pragma once

void *MemAlloc(DWORD size);
void MemFree(void *p);
void Log(PCHAR fmt, ...);
