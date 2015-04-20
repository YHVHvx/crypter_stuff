use32

format PE GUI 4.0

include 'win32a.inc'
include 'pe.inc'

entry start

section '.code' code readable writeable executable
RunPE:
file 'RunPE.bin'
start:
stdcall RunPE, PEFILE
PEFILE:
file 'stored_exe.bin'