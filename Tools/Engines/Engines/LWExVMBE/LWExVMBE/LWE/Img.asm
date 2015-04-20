; +
;Проверяет валидность заголовка модуля.
;
LdrImageNtHeader proc ImageBase:PVOID, ImageHeader:PIMAGE_NT_HEADERS
	mov edx,ImageBase
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	assume edx:PIMAGE_DOS_HEADER
	cmp [edx].e_magic,'ZM'
	jne @f
	add edx,[edx].e_lfanew
	assume edx:PIMAGE_NT_HEADERS
	cmp [edx].Signature,'EP'
	jne @f
	cmp [edx].FileHeader.SizeOfOptionalHeader,sizeof(IMAGE_OPTIONAL_HEADER32)
	jne @f
	cmp [edx].FileHeader.Machine,IMAGE_FILE_MACHINE_I386	
	jne @f
	test [edx].FileHeader.Characteristics,IMAGE_FILE_32BIT_MACHINE
	je @f
	mov ecx,ImageHeader
	xor eax,eax
	mov dword ptr [ecx],edx
@@:
	ret
LdrImageNtHeader endp

; +
;
CompareAsciizString proc uses ebx String1:PSTR, String2:PSTR
    mov ecx,String1
    mov edx,String2
    xor ebx,ebx
@@:
    mov al,byte ptr [ecx + ebx]
    cmp byte ptr [edx + ebx],al
    jne @f
    inc ebx
    test al,al
    jne @b
@@:
    ret
CompareAsciizString endp

xLdrCalculateHash:
	%GET_CURRENT_GRAPH_ENTRY
LdrCalculateHash proc uses ebx esi PartialHash:ULONG, StrName:PCHAR, NameLength:ULONG
	xor eax,eax
	mov ecx,NameLength
	mov esi,StrName
	mov ebx,PartialHash
	cld
@@:
	lodsb
	xor ebx,eax
	xor ebx,ecx
	rol ebx,cl
	dec ecx
	jnz @b
	mov eax,ebx
	ret
LdrCalculateHash endp

; +
; Поиск функции по имени/хэшу в экспорте.
;
LdrImageQueryEntryFromHash proc uses ebx esi edi ImageBase:PVOID, HashOrFunctionName:DWORD, pComputeHashRoutine:PVOID, PartialHash:ULONG, Function:PVOID
Local ExportDirectory:PIMAGE_EXPORT_DIRECTORY
Local ImageHeader:PIMAGE_NT_HEADERS
Local NumberOfNames:ULONG
	mov ebx,ImageBase
	.if !Ebx
		mov eax,fs:[TEB.Peb]
		mov eax,PEB.Ldr[eax]
		mov eax,PEB_LDR_DATA.InLoadOrderModuleList.Flink[eax]
		mov eax,LDR_DATA_TABLE_ENTRY.InLoadOrderModuleList.Flink[eax]
		mov ebx,LDR_DATA_TABLE_ENTRY.DllBase[eax]	; ntdll.dll
	.endif
	invoke LdrImageNtHeader, Ebx, addr ImageHeader
	test eax,eax
	mov edx,ImageHeader
	jnz Exit
	assume edx:PIMAGE_NT_HEADERS
	mov eax,[edx].OptionalHeader.DataDirectory.VirtualAddress
	test eax,eax
	jz ErrImage	
	add eax,ebx
	assume eax:PIMAGE_EXPORT_DIRECTORY	
	mov ExportDirectory,eax
	mov esi,[eax].AddressOfNames	
	test esi,esi
	jz ErrTable
	mov eax,[eax].NumberOfNames
	test eax,eax
	jz ErrTable
	mov NumberOfNames,eax
	add esi,ebx
	xor edi,edi
	cld
Next:	
	mov eax,dword ptr [esi]
	add eax,ebx
	.if pComputeHashRoutine != NULL
		push edi
		mov edi,eax
		mov ecx,MAX_PATH
		mov edx,edi
		xor eax,eax
		repne scasb
		not ecx
		pop edi
		add ecx,MAX_PATH
		push ecx
		push edx
		push PartialHash
		Call pComputeHashRoutine
		cmp HashOrFunctionName,eax
	.else
		invoke CompareAsciizString, HashOrFunctionName, Eax
	.endif
	jnz @f
	mov ecx,ExportDirectory		
	assume ecx:PIMAGE_EXPORT_DIRECTORY
	mov eax,[ecx].AddressOfNameOrdinals
	add eax,ebx
	movzx edi,word ptr [2*edi+eax]
	.if edi
		.if edi >= [ecx]._Base
			sub edi,[ecx]._Base
  		.endif
		inc edi
	.endif
	mov esi,[ecx].AddressOfFunctions
	add esi,ebx
	mov ecx,dword ptr [4*edi + esi]
	test ecx,ecx
	mov edx,Function
	jz ErrImage
	add ecx,ebx
	xor eax,eax
	mov dword ptr [edx],ecx
	jmp Exit
@@:
	add esi,4
	inc edi
	dec NumberOfNames
	jnz Next
	mov eax,STATUS_PROCEDURE_NOT_FOUND
Exit:
	ret
ErrImage:
	mov eax,STATUS_INVALID_IMAGE_FORMAT
	jmp Exit
ErrTable:
	mov eax,STATUS_BAD_FUNCTION_TABLE
	jmp Exit
LdrImageQueryEntryFromHash endp

; +
; Находит список функций по их хэшам.
;
LdrEncodeEntriesList proc uses ebx esi edi ImageBase:PVOID, EntriesList:PVOID
	%GET_GRAPH_ENTRY xLdrCalculateHash
	mov esi,EntriesList
	mov ebx,eax
	mov edi,esi
	lodsd
	.repeat
		invoke LdrImageQueryEntryFromHash, ImageBase, Eax, Ebx, 0, Edi
		test eax,eax
		jnz Exit
		lodsd
		add edi,4
	.until !Eax
Exit:
	ret
LdrEncodeEntriesList endp

; +
; Конвертирует образ файла в образ файловой секции, выравнивая размер файловых секций в памяти.
;
LdrConvertFileToImage proc uses ebx esi edi ImageBase:PVOID, MapAddress:PVOID
Local SystemInformation:SYSTEM_BASIC_INFORMATION
Local ImageHeader:PIMAGE_NT_HEADERS
	mov edi,MapAddress
	mov esi,ImageBase
	lea eax,SystemInformation
	push NULL
	push sizeof(SYSTEM_BASIC_INFORMATION)
	push eax
	push SystemBasicInformation
	Call [Ebx].pZwQuerySystemInformation
	test eax,eax
	jnz Exit
	invoke LdrImageNtHeader, ImageBase, addr ImageHeader
	test eax,eax
	mov ebx,ImageHeader
	jnz Exit
	assume ebx:PIMAGE_NT_HEADERS
	mov edx,[ebx].OptionalHeader.SectionAlignment
	cmp SystemInformation.PageSize,edx
	mov eax,STATUS_MAPPED_ALIGNMENT
	jne Exit
	mov ecx,[ebx].OptionalHeader.SizeOfHeaders
	cld
	rep movsb
	lea edi,[ebx + sizeof(IMAGE_NT_HEADERS) - sizeof(IMAGE_SECTION_HEADER)]
	assume edi:PIMAGE_SECTION_HEADER
	movzx ebx,IMAGE_NT_HEADERS.FileHeader.NumberOfSections[ebx]
@@:
	add edi,sizeof(IMAGE_SECTION_HEADER)
	mov ecx,[edi].SizeOfRawData
	mov eax,edi
	mov esi,[edi].PointerToRawData
	mov edi,[edi].VirtualAddress
	add esi,ImageBase
	add edi,MapAddress
	rep movsb
	mov edi,eax
	dec ebx
	jnz @b
	xor eax,eax
Exit:
	ret		
LdrConvertFileToImage endp

; +
; Создаёт секцию из образа модуля.
;
LdrCreateImageSection proc uses ebx Env:PUENV, SectionHandle:PHANDLE, ImageBase:PVOID, SectionName:PSTR
Local ObjAttr:OBJECT_ATTRIBUTES
Local LHandle:HANDLE
Local SectionSize:LARGE_INTEGER, ViewSize:ULONG
Local MapAddress:PVOID, SectionOffset:LARGE_INTEGER
Local ImageHeader:PIMAGE_NT_HEADERS
	mov ebx,Env
	assume ebx:PUENV
	invoke LdrImageNtHeader, ImageBase, addr ImageHeader
	test eax,eax
	mov ecx,ImageHeader
	jnz Exit
	mov ecx,IMAGE_NT_HEADERS.OptionalHeader.SizeOfImage[ecx]
	mov ObjAttr.uLength,sizeof(OBJECT_ATTRIBUTES)
	mov dword ptr [SectionSize + 4],eax
	mov dword ptr [SectionSize],ecx
	mov ViewSize,ecx
	mov ObjAttr.hRootDirectory,eax
	mov ObjAttr.uAttributes,eax
	mov ObjAttr.pSecurityDescriptor,eax
	mov ObjAttr.pSecurityQualityOfService,eax
	mov ObjAttr.pObjectName,eax
	lea ecx,SectionSize
	lea edx,ObjAttr
	push eax
	push SEC_COMMIT
	push PAGE_EXECUTE_READWRITE
	lea eax,LHandle
	push ecx
	push edx
	push SECTION_ALL_ACCESS
	push eax
	Call [Ebx].pZwCreateSection
	test eax,eax
	jnz Exit
	mov MapAddress,eax
	mov dword ptr [SectionOffset],eax
	mov dword ptr [SectionOffset + 4],eax
	lea ecx,ViewSize
	lea edx,SectionOffset
	push PAGE_READWRITE
	push NULL
	push ViewShare
	push ecx
	push edx
	lea ecx,MapAddress
	push eax
	push eax
	push ecx
	push NtCurrentProcess
	push LHandle
	Call [Ebx].pZwMapViewOfSection
	test eax,eax
	jnz Close
	invoke LdrConvertFileToImage, ImageBase, MapAddress
	push eax
	push MapAddress
	push NtCurrentProcess
	Call [Ebx].pZwUnmapViewOfSection
	pop eax
	mov edx,LHandle
	test eax,eax
	mov ecx,SectionHandle
	jnz Close
	mov dword ptr [ecx],edx
	jmp Exit
Close:
	push eax
	push LHandle
	Call [Ebx].pZwClose
	pop eax
Exit:
	ret
LdrCreateImageSection endp