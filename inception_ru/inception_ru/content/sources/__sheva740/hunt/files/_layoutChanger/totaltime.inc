.data
szResultFormat        BYTE        'Use time:%d hour(s) %d minute(s) %d.%03d second(s),average speed: %d times/s.',0dh,0ah,0
.code
totaltime        proc        _lpBuf,_dwTotalTime,_dwThingsHappend,_FutrueExtention

local        @dwStart:DWORD,\
        @dwMilliseconds:DWORD,\
        @dwSecond:DWORD,\
        @dwMinute:DWORD,\
        @dwHour:DWORD,\
        @dwSus:DWORD,\
        @AVGSpeed:DWORD

        mov        eax,_dwTotalTime

        xor        edx,edx
        mov        ebx,1000
        div        ebx
        mov        @dwMilliseconds,edx

  xor        edx,edx
        mov        ebx,60
        div        ebx
        mov        @dwSecond,edx
              
        xor        edx,edx
        mov        ebx,60
        div        ebx
        mov        @dwMinute,edx
              
        xor        edx,edx
        mov        ebx,24
        div        ebx
        mov        @dwHour,edx
      

        xor        edx,edx

        mov        eax,_dwThingsHappend
        mov        ebx,1000
        mul        ebx

        mov        ebx,_dwTotalTime
        .if        ebx!=0
                div        ebx
                mov        @AVGSpeed,eax
        .else

                push        _dwThingsHappend
                pop        @AVGSpeed
        .endif

        invoke        wsprintf,_lpBuf,\
                        offset szResultFormat,\
                        @dwHour,\
                        @dwMinute,\
                        @dwSecond,\
                        @dwMilliseconds,\
                        @AVGSpeed

        xor        eax,eax
        inc        eax
        ret
totaltime        endp