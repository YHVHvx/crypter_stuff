;===============================================================================;
; DOCUMENTATION KPASM                                                           ;
; 16/02/2007                                                                    ;
;                                                                               ;
; Deuxi�me exemple d'utilisation de kpasm : empilement de deux constantes       ;
; regles.                                                                       ;
;                                                                               ;
; Pour compiler l'exemple, lancez "comp.bat"                                    ;
;===============================================================================;



.386p
.model flat,STDCALL


include poly_defines.inc   ; g�n�r� par kpasm

NB_CASES_MEMOIRE EQU 100

.data
;======================================= DATA ==================================

pseudo_code:
        mov_reg_cst REG_EAX 0DEADBEEFh
        FIN_DECRYPTEUR
        
memoire dd NB_CASES_MEMOIRE dup (?)

;======================================= CODE =================================
.code
include poly_assembleur.asm    ;g�n�r� par kpasm

start:
        lea edi,code_genere
        mov ecx,4000
        mov al,90h
        rep stosb

        xor ebp,ebp
        lea esi,pseudo_code    ;pseudo-code � polymorphiser
        lea edi,code_genere    ;o� stoker le code g�n�r�
	mov ecx,edi            ;le code sera execut� sur place 
        mov edx,4000             ;taille max du code g�n�r� *par pseudo-opcode*
        lea eax,[ebp+memoire]  ; dans notre cas, future adresse memoire = adresse courante memoire
        lea ebx,[ebp+memoire]
        call poly_asm

        int 3
        ;execution du code genere:
code_genere:
        db 4000 dup (090h)
        jmp start
        int 3

        ;exit
        ret
end start