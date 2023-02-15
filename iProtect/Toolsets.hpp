#include <Windows.h>

#include <Psapi.h>

#include <iostream>
#include <string>

#include <vector>


#define DLLAPI extern "C" __declspec(dllexport)
#define ROUTINE DLLAPI DWORD WINAPI

typedef DWORD(WINAPI* Routine)(LPVOID);

std::vector<HMODULE> EnumModules(DWORD ProceeID)
{
	std::vector<HMODULE> r;

	DWORD cbNeeds = 0;
	HMODULE* pModules = NULL;

	HANDLE hProcess =
		OpenProcess(
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			FALSE,
			ProceeID
		);

	EnumProcessModules(hProcess, nullptr, 0, &cbNeeds);
	pModules = new HMODULE[cbNeeds / sizeof(HMODULE)];
	if (!EnumProcessModules(hProcess, pModules, cbNeeds, &cbNeeds))
	{
		delete[] pModules;
		CloseHandle(hProcess);
		return r;
	}

	for (int i = 0; i < cbNeeds / sizeof(HMODULE); i++)
	{
		r.push_back(pModules[i]);
	}
	delete[] pModules;
	CloseHandle(hProcess);
	return r;
}