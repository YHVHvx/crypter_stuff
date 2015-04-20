@echo	off
C:\masm32\bin\ml.exe /c /coff /nologo /I C:\masm32\include test.asm
C:\masm32\bin\link.exe /subsystem:windows /DEF:test.def /DLL test.obj /libpath:C:\masm32\lib
:0 
del		test.obj
if		exist test.obj goto 0 
pause
cls
 