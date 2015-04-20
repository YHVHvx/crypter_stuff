;===============================================================================;
; DOCUMENTATION KPASM                                                           ;
; 16/02/2007                                                                    ;
;                                                                               ;
; 7ème exemple d'utilisation de kpasm : decryption d'un bout de code (MB)       ;
;                                                                               ;
;===============================================================================;



.386p
.model flat,STDCALL


include poly_defines.inc   ; généré par kpasm

NB_CASES_MEMOIRE EQU 200
TAILLE_CODE_GENERE      EQU 10000

extrn ExitProcess:PROC
extrn MessageBoxA:PROC

.data
;======================================= DATA ==================================

pseudo_code:
        decrypteur
        FIN_DECRYPTEUR

memoire dd NB_CASES_MEMOIRE dup (?)     ; la memoire utiliisée dans le décrypteur

message db "kikoolol",0
cle dd 012345678h
adresse_code_virus dd offset code_virus

;======================================= CODE =================================
.code
include poly_assembleur.asm    ;généré par kpasm

start:
        mov eax,fs:[18h]
        mov eax,[eax+30h]

        lea edi,code_genere
        mov ecx,100000
        mov al,90h
        rep stosb
        
        ;encryption du code exemple
        lea esi,code_virus
        mov edi,esi
        mov ecx,taille_code_virus
        mov ebx,cle
boucle: lodsd
        add eax,ebx
        stosd
        loop boucle

        ;polymorphise
        xor ebp,ebp
        lea esi,pseudo_code    ;pseudo-code à polymorphiser
        lea edi,code_genere    ;où stoker le code généré
	    mov ecx,edi            ;le code sera executé sur place
        mov edx,100000            ;taille max du code généré *par pseudo-opcode*
        lea eax,[ebp+memoire]  ; dans notre cas, future adresse memoire = adresse courante memoire
        lea ebx,[ebp+memoire]
        call poly_asm




        int 3
        ;execution du code genere:
code_genere:
        db 100000 dup (090h)

        ;code exemple
code_virus:
        call MessageBoxA, 0,offset message, offset message, 0
        
ALIGN 4
taille_code_virus equ ($ - code_virus)/4

        jmp start   ; on recommence pour voir un nouvel echantillon de poly


        ;exit
        call ExitProcess, 0
end start