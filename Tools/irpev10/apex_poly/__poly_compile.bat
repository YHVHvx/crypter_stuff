@echo	off
C:\masm32\bin\ml.exe /c /coff /nologo /I C:\masm32\include poly.asm
C:\masm32\bin\link.exe /subsystem:windows /DLL  /DEF:poly.def /section:.text,RWE /nologo poly.obj /libpath:C:\masm32\lib
:0 
del		poly.obj
if		exist poly.obj goto 0 
pause
cls
 