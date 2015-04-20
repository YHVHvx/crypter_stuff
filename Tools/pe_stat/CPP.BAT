@echo off
%BCC55%bin\bcc32.exe -lap -5 -C -P -pr -ff -O2 -Tm5 -lH:16777216 -I%BCC55%include -L%BCC55%lib -H -H=%TEMP%\pe_stat.csm pe_stat.cpp lde32.obj
del pe_stat.tds
del pe_stat.obj
