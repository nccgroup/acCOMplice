// Copyright (c) 2019, NCC Group. All rights reserved.
// Licensed under BSD 3-Clause License per LICENSE file

#include "windows.h"
#include <stdio.h>
#include <string>
#include <sstream>

std::wstring path;		//variable set globally so DllCanUnloadNow has name
LPOLESTR lplpsz;		//GUID, set in DllGetClassObject
HMODULE hCurrent;		//handle to current loaded DLL, set in DllMain
HANDLE hDllMainThread;  //handle to thread started from DllMain
HANDLE hClassObjThread; //handle to thread started from DllGetClassObject
bool isRunning = false;
//helper function for retrieving error messages
std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

DWORD WINAPI LogThreadActivity(std::wstring fileName) {
	isRunning = true;
	HANDLE hFile = NULL;
	hFile = CreateFile(fileName.c_str(),	// name of the file
		GENERIC_WRITE,						// open for writing
		0,									// do not share
		NULL,								// default security
		CREATE_ALWAYS,						// create new file only
		FILE_ATTRIBUTE_NORMAL,				// normal file
		NULL);								// no attr. template
	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Terminal failure: Unable to open file for write.\n");
	}
	CloseHandle(hFile);

	//in a loop, write a number to the log file
	int i = 0;
	while (1) {
		hFile = CreateFile(fileName.c_str(),	// name of the file
			FILE_APPEND_DATA,					// append data
			0,									// do not share
			NULL,								// default security
			OPEN_EXISTING,						// open existing file
			FILE_ATTRIBUTE_NORMAL,				// normal file
			NULL);								// no template

		DWORD bytesWritten;
		std::string s = std::to_string(i);
		const char *number = s.c_str();
		if (hFile) {
			WriteFile(hFile, number, strlen(number), &bytesWritten, NULL);
			WriteFile(hFile, "\n", strlen("\n"), &bytesWritten, NULL);
			CloseHandle(hFile);
		} else {
			printf("Terminal failure: Unable to open file  for write.\n");
		}

		Sleep(1000);
		i++;
	}
	isRunning = false;
}

DWORD WINAPI DllMainThread(LPVOID lpParam)
{ 
	wchar_t szFileName[MAX_PATH];
	//get the name of the DLL thats being loaded from the handle
	GetModuleFileName(hCurrent, szFileName, MAX_PATH);
	// get a handle to ourselves using GetModuleHandleEx function
	// so we can use GET_MODULE_HANDLE_EX_FLAG_PIN to prevent LoadLibrary from being used
	HMODULE self;
	bool result = GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_PIN, szFileName, &self);
	path = szFileName;
	path = path.substr(path.find_last_of(L"/\\") + 1);
	size_t dot_i = path.find_last_of('.');
	// convert thread handle to string
	std::wostringstream str;
	str << hDllMainThread;
	std::wstring threadHandleStr = str.str();
	//unique file to track progress of thread
	std::wstring fileName = L"C:\\COM\\logDllMainThread-" + threadHandleStr + L"-" + path.substr(0, dot_i) + L".txt";
	LogThreadActivity(fileName);
	return 0;
}

DWORD WINAPI ClassObjThread(LPVOID lpParam)
{	
	//get GUID set when DllGetClassObject was called
	std::wstring guid = lplpsz;
	//remove { and } from GUID
	guid.erase(0, 1);
	guid.erase(guid.size() - 1);
	// convert thread handle to string
	std::wostringstream str;
	str << hClassObjThread;
	std::wstring threadHandleStr = str.str();
	//unique file to track progress of thread
	std::wstring fileName = L"C:\\COM\\logGetClassObjThread-" + threadHandleStr + L"-" + guid + L".txt";
	LogThreadActivity(fileName);
	return 0;
}

HRESULT DllRegisterServer(void) {
	//MessageBox(NULL, L"DllRegisterServer", L"Hello", NULL);
	return 0;
}

HRESULT DllUnregisterServer(void) {
	//MessageBox(NULL, L"DllUnregisterServer", L"Hello", NULL);
	return 0;
}

HRESULT DllGetClassObject(REFCLSID rclsid, REFIID iid, LPVOID*ppv) {
	DWORD dwThread;
	HRESULT hResult = StringFromCLSID(rclsid, &lplpsz);
	hClassObjThread = CreateThread(NULL, 0, ClassObjThread, NULL, 0, &dwThread);
	return 0;
}

HRESULT DllCanUnloadNow(void) {
	if (isRunning) {
		return S_FALSE;
	}
	return S_OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		hCurrent = hModule; //set global handle for self
		DWORD dwThread;
		hDllMainThread = CreateThread(NULL, 0, DllMainThread, NULL, 0, &dwThread);
		break;
	}
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;

}