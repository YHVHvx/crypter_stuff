@echo off

\masm32\bin\ml /c /coff ldr.asm
\masm32\bin\Link /SUBSYSTEM:WINDOWS /SECTION:.text,ERW lwe.obj ldr.obj 
pause
