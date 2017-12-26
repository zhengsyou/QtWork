#include <Windows.h>
#include <TlHelp32.h>
#include <tchar.h>
#include "HOOK/HookAPIX.h"

XLIB::CXHookAPI g_hookLog;
XLIB::CXHookAPI g_hookMacFunc;
XLIB::CXHookAPI g_hookProcess32First;
XLIB::CXHookAPI g_hookProcess32FirstW;
int __cdecl Log(char *x1, int x2, int x3, char x4);

extern "C" __declspec(dllexport) void TestFuction()
{
	////do anything here////
}

BOOL
WINAPI
FakeProcess32FirstW(
HANDLE hSnapshot,
LPPROCESSENTRY32W lppe
)
{
	return FALSE;
}

BOOL
WINAPI
FakeProcess32First(
HANDLE hSnapshot,
LPPROCESSENTRY32 lppe
)
{
	return FALSE;
	//return g_hookProcess32First.CallFunction(2, hSnapshot, lppe);
}


LPVOID QueryVMPCodeMemory()
{
	MEMORY_BASIC_INFORMATION tagMemInfo = { 0 };
	for (DWORD i = 0x2000000; i < 0x40000000; )
	{
		if (VirtualQuery((LPVOID)i, &tagMemInfo, sizeof(MEMORY_BASIC_INFORMATION)))
		{
			if (0x0b000 == tagMemInfo.RegionSize
				&& PAGE_EXECUTE_READWRITE == tagMemInfo.AllocationProtect
				&& MEM_COMMIT == tagMemInfo.State
				&& PAGE_EXECUTE_READ == tagMemInfo.Protect
				&& MEM_MAPPED == tagMemInfo.Type
				&& 0x6a406a == *(PDWORD)((PBYTE)i+0x6bb5))
			{
				return (LPVOID)i;
			}

			i += tagMemInfo.RegionSize;
		}
		else
		{
			i += 0x1000;
		}
	}
	return NULL;
}

VOID __cdecl FakeFilter(XLIB::CStack_ESP *pStack)
{
	PBYTE pData = (PBYTE)(*(PDWORD)pStack->ESP);
	PBYTE pDataMark = (PBYTE)(*(PDWORD)(pStack->ESP + 4));
	BYTE aryData[] = {
		0x37, 0x83, 0x62, 0xb4, 0xf0, 0xf8, 0x1f, 0xd9, 0x48, 0x59, 0x07, 0xea, 0xa9, 0xee, 0x3a, 0x3d
	}; 
	
	BYTE aryMark[16] = {0};

	if (memcmp(pDataMark, aryMark, sizeof(aryMark)) == 0
		|| 3 == pData[17]
		|| memcmp(pDataMark + 8, aryMark, 8) == 0)
	{
		memcpy(pData, aryData, sizeof(aryData));
	}
}

int __cdecl FakeLog(char *x1, int x2, int x3, char x4)
{
	if (!g_hookMacFunc.IsHooked())
	{
		LPVOID lpVmpMem = QueryVMPCodeMemory();
		if(NULL != lpVmpMem)
		{
			LPVOID lpMacFunc = (PBYTE)lpVmpMem + 0x6bb5;
			if (g_hookMacFunc.InlineHookAddress(lpMacFunc, FakeFilter))
			{
				g_hookLog.UnHook();
			}
		}
	}

	return g_hookLog.CallFunction(4, x1, x2, x3, x4);
}

void Init()
{
	HMODULE hModule = LoadLibrary(_T("Utility.dll"));
	if (NULL == hModule)
	{
		MessageBox(NULL, _T("∆∆Ω‚ ß∞‹1"), _T("¥ÌŒÛ"), MB_OK);
		return;
	}

	LPVOID pFuncLog = GetProcAddress(hModule, "Log");
	if (NULL == pFuncLog)
	{
		FreeLibrary(hModule);
		MessageBox(NULL, _T("∆∆Ω‚ ß∞‹2"), _T("¥ÌŒÛ"), MB_OK);
		return;
	}

	HMODULE hKernel32 = LoadLibrary(_T("Kernel32.dll"));
	LPVOID lpProcess32First = GetProcAddress(hKernel32, "Process32First");
	LPVOID lpProcess32FirstW = GetProcAddress(hKernel32, "Process32FirstW");
	g_hookProcess32First.InlineHookFunction(lpProcess32First, FakeProcess32First);
	g_hookProcess32FirstW.InlineHookFunction(lpProcess32FirstW, FakeProcess32FirstW);

	if (!g_hookLog.IsHooked())
	{
		if (!g_hookLog.InlineHookFunction(pFuncLog, FakeLog))
		{
			FreeLibrary(hModule);
			MessageBox(NULL, _T("∆∆Ω‚ ß∞‹3"), _T("¥ÌŒÛ"), MB_OK);
		}
	}
}

BOOL WINAPI DllMain(
	_Out_ HINSTANCE hInstance,
	_In_  ULONG     ulReason,
	LPVOID    Reserved
	)
{
	switch (ulReason)
	{
		case DLL_PROCESS_ATTACH:
			Init();
			break;
		default:
			break;
	}

	return TRUE;
}