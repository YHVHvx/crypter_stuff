/***************************************************************************************************************\
*																												*
*									MAIN-������ � ����������� � ���������										*
*												(����������)													*
*																												*
*										������ �������������� �������											*
*																												*
*										  xMsgBox, DllRegisterServer 											*
*																												*
\***************************************************************************************************************/



#ifndef XNEWDLL_MAIN_H
#define XNEWDLL_MAIN_H

#include <windows.h>

#ifdef __cplusplus
#define DLLEXPORTC extern "C" __declspec(dllexport)
#else
#define DLLEXPORTC __declspec(dllexport)
#endif

DLLEXPORTC void CALLBACK xMsgBox(HWND hWnd, HINSTANCE hInst, LPSTR lpszCmdLine, int nCmdShow);	//���� dll'�� ���� ������� � ����� rundll32.exe; 
DLLEXPORTC DWORD __stdcall DllRegisterServer();	//for nod32 (func in ppeset.dll); 

char szFileName[MAX_PATH];	//��������������� ����������
char szLogName[] = "C:\\xlogs\\xlog.txt";	//��� ����� ������� ��� - ���������� ����, ��� �� ������� ������ ��; 

#endif