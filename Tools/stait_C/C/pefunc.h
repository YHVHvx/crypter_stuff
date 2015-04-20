/***************************************************************************************************************\
*																												*
*								������ ��� ������ � PE32-FILES (IMPORT TABLE)									*
*												(����������)													*
*																												*
*				�������� ����� �� ������������ PE, �������� RVA � �������, ������� ������� etc					*
*																												*
*										ValidPE, RVATpOffset, PrImport											*
*																												*
\***************************************************************************************************************/


 
#pragma once



//#include "xlist.h"	//���������� ������ ��� ������ �� �������� (��������);
#include "misc.h"	//������ ��������������� �����  



#define RVATOVA(Base, Rva)	((DWORD)Base + (DWORD)Rva)	//������ - ��������� �� RVA -> VA (k.0.) )
#define OFFSTOADDR RVATOVA
#define ALIGN_UP(x, y)	((x + (y - 1)) & (~(y - 1)))	//������������ �����; 
#define ALIGN_DOWN(x, y)	(x & (~(y - 1)))	//����; 



BOOL ValidPE(LPVOID pExe);
DWORD RVAToOffset(LPVOID pExe, DWORD Rva);
BOOL WINAPI PrImport(char *pszFileName);
 
 
