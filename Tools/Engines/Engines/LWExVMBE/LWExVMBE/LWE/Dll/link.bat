@echo off
\masm32\bin\ml /c /coff 123.asm
\masm32\bin\Link /SUBSYSTEM:WINDOWS /DLL /DEF:123.def 123.obj
dir 123.*
pause
