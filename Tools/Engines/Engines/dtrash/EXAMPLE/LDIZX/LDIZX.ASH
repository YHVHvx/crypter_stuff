
;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께
;OUTPUT
;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께
cmd             struc

                lc_size          db      ?       ;command size
                lc_psize         db      ?       ;prefixes size

                lc_flags         dd      ?       ;prefix flags & other

                lc_tttn          db      ?       ;tttn

                lc_sib           db      ?       ;sib
                lc_modrm         db      ?       ;modrm

		lc_reg		 db	 ? 	 ;reg
                lc_mod           db      ?       ;mod
                lc_ro            db      ?       ;r/o
                lc_rm            db      ?       ;r/m

                lc_base          db      ?       ;base
                lc_index         db      ?       ;index
                lc_scale         db      ?       ;scale

                lc_offset        dd      ?       ;offset

                lc_operand       db      6 dup(?);operand

                lc_soffset       db      ?       ;offset's size
                lc_soperand      db      ?       ;operand's size

		lc_mask1 	 db	 ?       ;command mask
		lc_mask2	 db	 ?       ;

                ends




;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께
;LC_FLAGS:
;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께


;       1.     PREFIXES

LF_PCS           equ       00000000000000000000000000000001b
LF_PDS           equ       00000000000000000000000000000010b
LF_PES           equ       00000000000000000000000000000100b
LF_PSS           equ       00000000000000000000000000001000b
LF_PFS           equ       00000000000000000000000000010000b
LF_PGS           equ       00000000000000000000000000100000b
LF_POP           equ       00000000000000000000000001000000b
LF_POF           equ       00000000000000000000000010000000b
LF_PLOCK         equ       00000000000000000000000100000000b
LF_PREPZ         equ       00000000000000000000001000000000b
LF_PREPNZ        equ       00000000000000000000010000000000b

LF_MODRM         equ       10000000000000000000000000000000b
LF_SIB           equ       01000000000000000000000000000000b
LF_OFFSET        equ       00100000000000000000000000000000b
LF_OPERAND       equ       00010000000000000000000000000000b

LF_REG           equ       00001000000000000000000000000000b
LF_REG1          equ       00000100000000000000000000000000b
LF_REG2          equ       00000010000000000000000000000000b
LF_BASE          equ       00000001000000000000000000000000b
LF_INDEX         equ       00000000100000000000000000000000b

LF_MEM           equ       00000000010000000000000000000000b
LF_TTTN          equ       00000000001000000000000000000000b
LF_RAW	         equ       00000000000100000000000000000000b

LF_D	         equ       00000000000000001000000000000000b
LF_S	         equ       00000000000000000100000000000000b
LF_SDV           equ       00000000000000000010000000000000b    ;(d=1  mem->reg  /d=0  mem<-reg  )
LF_W             equ       00000000000000000001000000000000b
LF_WV            equ       00000000000000000000100000000000b    ;(0-work with bytes /1-work with dwords/words)


;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께
;DESCRIPTOR FORMAT
;께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께께
;        旼컴컴컴컴쩡컴쩡컴쩡컴쩡컴쩡컴崙컴쩡컴쩡컴컴컴컴컴쩡컴쩡컴쩡컴�
;        �         �   �   �   �   �   �   �   �           �   �   �   �
;        � 7  6  5 � 4 � 3 � 2 � 1 � 0 � 7 � 6 � 5   4   3 � 2 � 1 � 0 �
;        �         �   �   �   �   �   �   �   �           �   �   �   �
;        읕컴컫컴컴좔쩡좔쩡좔쩡좔쩡좔컴崙쩡좔쩡좔컴컴쩡컴컴좔쩡좔쩡좔쩡�
;             �      �   �   �   �       �   �       �       �   �   �
;             �      �   �   �   �       �   �       �       �   �   �
;             �      �   �   �   �       �   �       �       �   �   �
;LFD_MASKX   켸      �   �   �   �       �   �       �       �   �   �
;LFD_MODRM   컴컴컴컴�   �   �   �       �   �       �       �   �   �
;                        �   �   �       �   �       �       �   �   �
;LFD_COP_ART 컴컴컴컴컴컴�   �   �       �   �       �       �   �   �
;LFD_COP_F   컴컴컴컴컴컴컴컴�   �       �   �       �       �   �   �
;LFD_0F      컴컴컴컴컴컴컴컴컴컴�       �   �       �       �   �   �
;                                        �   �       �       �   �   �
;LFD_D       컴컴컴컴컴컴컴컴컴컴컴컴컴컴�   �       �       �   �   �
;LFD_CFLAGS  컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�       �       �   �   �
;                                                    �       �   �   �
;LFD_OP_V    컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�       �   �   �
;LFD_OP_MEM  컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�   �   �
;LFD_PREFIX  컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�   �
;LFD_TTTN    컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴컴�
                                                                     
LFD_MASK4                       equ             0110000000000000b
LFD_MASK5                       equ             1000000000000000b
LFD_MASK6                       equ             1010000000000000b
LFD_MASK7                       equ             1100000000000000b
LFD_MASK8                       equ             1110000000000000b

LFD_MODRM                       equ             0001000000000000b

LFD_COP_ART                     equ             0000100000000000b
LFD_COP_F                       equ             0000010000000000b
LFD_0F                          equ             0000001000000000b

LFD_S                           equ             0000000000000000b	; 0 - S
LFD_D                           equ             0000000010000000b	; 1 - D
LFD_CFLAGS                      equ             0000000001000000b

LFD_OP_V1                       equ             0000000000001000b
LFD_OP_V2                       equ             0000000000010000b
LFD_OP_V3                       equ             0000000000011000b
LFD_OP_V4                       equ             0000000000100000b
LFD_OP_V6                       equ             0000000000110000b
LFD_OP_VX                       equ             0000000000111000b

LFD_OFF                         equ             0000000000000100b
LFD_PREFIX                      equ             0000000000000010b
LFD_TTTN                        equ             0000000000000001b

