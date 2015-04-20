;===============================================================================;
; DOCUMENTATION KPASM                                                           ;
; 16/02/2007                                                                    ;
;                                                                               ;
; Deuxième exemple d'utilisation de kpasm : empilement de deux constantes       ;
; regles.                                                                       ;
;                                                                               ;
; Pour compiler l'exemple, lancez "comp.bat"                                    ;
;===============================================================================;



.386p
.model flat,STDCALL


include poly_defines.inc   ; généré par kpasm

NB_CASES_MEMOIRE EQU 100

.data
;======================================= DATA ==================================

pseudo_code:
        init REG_EBX 5 6  ; on va multiplier ebx par 3 = 5*6 = 30
        ajoute
        dec_compteur
        boucle
        FIN_DECRYPTEUR

;======================================= CODE =================================
.code
include poly_assembleur.asm    ;généré par kpasm

start:
        lea edi,code_genere
        mov ecx,4000
        mov al,090h
        rep stosb

        xor ebp,ebp
        lea esi,pseudo_code    ;pseudo-code à polymorphiser
        lea edi,code_genere    ;où stoker le code généré
	mov ecx,edi            ;le code sera executé sur place 
        mov edx,100             ;taille max du code généré *par pseudo-opcode*
        xor eax,eax            ;pas d'utilisation de la mémoire
        xor ebx,ebx            ;pas d'utilisation de la mémoire
        call poly_asm

        int 3
        ;execution du code genere:
code_genere:
        db 4000 dup (090h)
        int 3
        jmp start
        int 3

        ;exit
        ret
end start