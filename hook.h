#ifndef HOOK_H
#define HOOK_H

#include <Windows.h>

bool IATPatch(HMODULE);
using MessageBoxAPtr = int(WINAPI*)(HWND, LPCSTR, LPCSTR, UINT);
extern MessageBoxAPtr pMessageBoxA;  
extern int WINAPI pHookedMessageBoxA(HWND, LPCSTR, LPCSTR, UINT);  

#endif
