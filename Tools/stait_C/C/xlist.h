/***************************************************************************************************************\
*																												*
*							������ ��� ������ �� ���������������� ������� �������								*
*												(����������)													*
*																												*
*		������ ������������ ��� ��������/����������/etc ������, ������ � ������ ������� ������ PE-������		*
*																												*
*	InitList, ShowListAll, DestroyListAll, AddElemDll, AddElemFunc, GetInfoAll, FindElem, SwapElem, BubbleSort	*
*																												*
\***************************************************************************************************************/



#pragma once	//���������� ���� ������ ���� ��� (���� �������� ��������������, ����� �������� ��� ������, � ������ ��� ����������� include-guard (�����, ������� ��-������));  



#include <windows.h>
#include <stdio.h>
#include <conio.h> 



#define FindElemDll				FindElem<list_dll_node, list_dll>
#define FindElemFunc			FindElem<list_func_node, list_dll_node>
#define BubbleSortDll			BubbleSort<list_dll, list_dll_node>
#define BubbleSortFunc			BubbleSort<list_dll_node, list_func_node>

#define	MAX_PER	100.0



//��������� ��� ����� ������ �� ������;
typedef struct get_info_from_list
{
	int num_dll;		//����� ���� ���������� ��� (�� ���� ����� ���� ��� ��� ����������);
	int num_func;		//����� ���� ���������� ������� �� ���� ���(����� ���� list_dll_node.num_func); 
	int num_all_dll;	//����� ���� ���, ������� ���������� (����� ���� list_dll_node.count);
	int num_all_func;	//����� ���� �������, ������� ����������, �� ���� ��� (����� ���� list_dll_node.num_all_func); 
}GIFL;

 
//��������� ��� �������� ������ �������; 
typedef struct list_func_node
{
	char *pName;			//��� ��������� �������;
	int count;				//���-�� ���������� �������;
	list_func_node *pNext;	//��������� �� ��������� ������� ������ (�� ��������� ������ ������ �����); 
}LFN;


//��������� ��� �������� ������ ��� � ������ �������, ������������� (�������������) ������ ���;
typedef struct list_dll_node
{
	char *pName;			//��� dll; 
	int count;				//����� ���������� ������ dll; 
	int num_func;			//���-�� ���������� (���������) ������� � ������ ��� (�� ���� ���-�� ������� ��� ���������� � ������ ���);
	int num_all_func;		//���-�� ���� �������, ������� ����������, ��� ������ ���;
	list_func_node *pFirst;	//��������� �� ������ ������ list_func_node (���, ��� �������� ������ �� ������ �����, ������������� ������ ���);
	list_dll_node *pNext;	//��������� �� ��������� ������� ������; 
}LDN;


//��������� ��� �������� ������ ������ list_dll_node;
typedef struct
{
	list_dll_node *pFirst;	//��������� �� ������ ������ list_dll_node;
}list_dll;



void InitList(list_dll *p);
void WriteListAll(list_dll *p, FILE *file, GIFL *pgifl);
void DestroyListAll(list_dll *p);
BOOL AddElemDll(list_dll *p, char *pszDllName); 
BOOL AddElemFunc(list_dll *p, char *pszDllName, char *pszFuncName);
GIFL *GetInfoAll(list_dll *p, GIFL *pgifl); 

template <class A, class B>
A *FindElem(B *p, char *pszName, int *fl);

template <class A, class B>
A *SwapElem(B *p, A *pPrev, A *pCur, A *pNext);

template <class A, class B>
DWORD BubbleSort(A *p); 

DWORD BubbleSortAll(list_dll *p); 



extern list_dll ld;	//(�������) ���������� ����������, ������� ����� ��� ���� ������ ��������� (�� ����������� ������������������ �������������, �� ��� ����� ); 
 







 








 