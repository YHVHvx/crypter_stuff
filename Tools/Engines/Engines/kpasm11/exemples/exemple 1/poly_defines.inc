;=================================== MACROS =====================================
; Ces macros sont les pseudos-opcodes qui composeront votre decrypteur.
;================================================================================
FIN_DECRYPTEUR macro  
	 db OP_FIN_DECRYPTEUR
endm

raz_registre macro reg

	db OP_raz_registre
	db OP_raz_registre_NB_ARGS
	db TYPE_REGISTRE
	dd reg
endm




;=============================== DEFINES DES OPCODES ============================
OP_FIN_DECRYPTEUR EQU 0

OP_raz_registre EQU 1
OP_raz_registre_NB_ARGS EQU 1




;=============================== DEFINES DES REGISTRES ==========================
REG_EAX EQU 00
REG_ECX EQU 01
REG_EDX EQU 02
REG_EBX EQU 03
REG_ESP EQU 04
REG_EBP EQU 05
REG_ESI EQU 06
REG_EDI EQU 07

TYPE_REGISTRE EQU 0
TYPE_ADRESSE EQU 1
TYPE_ENTIER EQU 2
