;===============================================================================;
; DOCUMENTATION KPASM                                                           ;
; 16/02/2007                                                                    ;
;                                                                               ;
; 8�me exemple d'utilisation de kpasm : moulte moulte layers                    ;
;                                                                               ;
;===============================================================================;



.386p
.model flat,STDCALL


include poly_defines.inc   ; g�n�r� par kpasm

NB_CASES_MEMOIRE        EQU 200
TAILLE_CODE_GENERE      EQU 100000

extrn ExitProcess:PROC
extrn MessageBoxA:PROC
extrn GetTickCount:PROC

.data
;======================================= DATA ==================================

pseudo_code:
        moulte_layers
        FIN_DECRYPTEUR

memoire dd NB_CASES_MEMOIRE dup (?)     ; la memoire utiliis�e dans le d�crypteur

message db "kikoolol",0
nb_layers dd 0                          ; compteur de layer
cle dd 012345678h

;======================================= CODE =================================



.code
include poly_assembleur.asm    ;g�n�r� par kpasm

start:
        mov nb_layers,0
        call GetTickCount
        mov poly_rand_seed,eax

        lea edi,code_genere
        mov ecx,TAILLE_CODE_GENERE
        mov al,90h
        rep stosb

        ;encryption du code exemple
        lea esi,code_messagebox
        mov edi,esi
        mov ecx,taille_code_messagebox
        mov ebx,cle
boucle: lodsd
        add eax,ebx
        stosd
        loop boucle

        ;polymorphise
        xor ebp,ebp
        lea esi,pseudo_code    ;pseudo-code � polymorphiser
        lea edi,code_genere    ;o� stoker le code g�n�r�
    	mov ecx,edi            ;le code sera execut� sur place
        mov edx,TAILLE_CODE_GENERE           ;taille max du code g�n�r� *par pseudo-opcode*
        lea eax,[ebp+memoire]  ; dans notre cas, future adresse memoire = adresse courante memoire
        lea ebx,[ebp+memoire]
        call poly_asm
        mov ebx,nb_layers
        int 3

        ;execution du code genere:
code_genere:
        db TAILLE_CODE_GENERE dup (090h)

        ;code exemple
code_messagebox:
        call MessageBoxA, 0,offset message, offset message, 0

ALIGN 4
taille_code_messagebox equ ($ - code_messagebox)/4

        jmp start   ; on recommence pour voir un nouvel echantillon de poly


        ;exit
        call ExitProcess, 0
end start