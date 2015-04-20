.386
.model flat, stdcall
option casemap:none

include windows.inc
include kernel32.inc
include user32.inc
include gdi32.inc

includelib kernel32.lib
includelib user32.lib
includelib gdi32.lib





.code

engines:
include		rang32.asm												
include		xtg.inc	
include		xtg.asm
include		faka.asm
include		logic.asm

LibMain proc instance:DWORD,reason:DWORD,unused:DWORD 
    
	.if reason == DLL_PROCESS_ATTACH 
      mov eax, TRUE

    .elseif reason == DLL_PROCESS_DETACH 
      ; --------------------------------------- 
      ; perform any exit code you require here 
      ; ---------------------------------------

    .elseif reason == DLL_THREAD_ATTACH

    .elseif reason == DLL_THREAD_DETACH

    .endif

    ret

LibMain endp

END LibMain