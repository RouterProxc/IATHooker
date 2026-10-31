#include "hook.h"
bool IATPatch(HMODULE);

using MessageBoxAPtr = int(WINAPI*) (HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType);

MessageBoxAPtr pMessageBoxA = nullptr;

int WINAPI pHookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)
{
	if (pMessageBoxA) {
		return 0;
	}
	return 0;  // Fallback
}


bool IATPatch(HMODULE hModule)
{
	LPVOID pBase = hModule;
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBase;

	if (pDos->e_magic != IMAGE_DOS_SIGNATURE) {
		MessageBoxA(NULL, "Bad DOS", "ERROR", MB_OK);
		return false;
	}

	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + pDos->e_lfanew);

	DWORD importRVA = pNt->OptionalHeader.DataDirectory[1].VirtualAddress;

	PIMAGE_IMPORT_DESCRIPTOR pDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pBase + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (; pDesc->Name; pDesc++)
	{
		char* pNameDll = (char*)((BYTE*)pBase + pDesc->Name);
		MessageBoxA(NULL, pNameDll, "DLL found", MB_OK);  // show all dlls (optional line)
		if (_stricmp(pNameDll, "USER32.dll") == 0)
		{
			MessageBoxA(NULL, pNameDll, "user32 FOUND", MB_OK);
			PIMAGE_THUNK_DATA pThunkNames = pDesc->OriginalFirstThunk
				? (PIMAGE_THUNK_DATA)((BYTE*)pBase + pDesc->OriginalFirstThunk)
				: (PIMAGE_THUNK_DATA)((BYTE*)pBase + pDesc->FirstThunk);

			PIMAGE_THUNK_DATA pThunkAddress = (PIMAGE_THUNK_DATA)((BYTE*)pBase + pDesc->FirstThunk);

			for (; pThunkNames->u1.AddressOfData; pThunkNames++, pThunkAddress++)
			{
				if (IMAGE_SNAP_BY_ORDINAL(pThunkNames->u1.Ordinal))
					continue;

				PIMAGE_IMPORT_BY_NAME pNameFunction =
					(PIMAGE_IMPORT_BY_NAME)((BYTE*)pBase + pThunkNames->u1.AddressOfData);

				if (_stricmp((char*)pNameFunction->Name, "MessageBoxA") == 0)
				{
					DWORD oldProtect;
					VirtualProtect(&pThunkAddress->u1.Function, sizeof(DWORD_PTR),
						PAGE_EXECUTE_READWRITE, &oldProtect);

					pMessageBoxA = (MessageBoxAPtr)pThunkAddress->u1.Function;
					pThunkAddress->u1.Function = (DWORD_PTR)pHookedMessageBoxA; // patched

					VirtualProtect(&pThunkAddress->u1.Function, sizeof(DWORD_PTR),
						oldProtect, &oldProtect);

					return true;
				}
			}
		}
	}
	MessageBoxA(NULL, "MessageBoxA NOT FOUND", "FAIL", MB_OK);
	return false;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
		if (IATPatch((HMODULE)GetModuleHandle(NULL))) {
			MessageBoxA(NULL, "IAT Hook SUCCESS", "OK", MB_OK);
		}
		
        break;

    case DLL_THREAD_ATTACH:
        break;

    case DLL_THREAD_DETACH:
        break;

    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE; 
} 
