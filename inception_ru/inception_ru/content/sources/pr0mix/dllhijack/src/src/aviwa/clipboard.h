/***************************************************************************************************************\
*																												*
*									������ ��� ������ � ������� ������ (��)										*
*												(����������)													*
*																												*
*					����������� (������ ��� ������) ������ � ��, ��������� ������ �� ��, 						*
*					����������� ���� �������� � ������� � ��, ��������� ������ �� �� �� ����					*
*																												*
*			CopyPasteFileToClipboard, GetDataFromClipboard, ClipboardOperationType, CopyPasteFileToDisk			*
*																												*
\***************************************************************************************************************/



#pragma once

#include <windows.h>
#include <shlobj.h>



BOOL CopyPasteFileToClipboard(HWND hWnd, char *pszFileName, DWORD de_action);
char **GetDataFromClipboard(HWND hWnd);
int ClipboardOperationType(HWND hWnd);
int CopyPasteFileToDisk(char *pszFrom, char *pszTo, DWORD op_type);
