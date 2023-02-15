
#include <iostream>
#include <vector>

#include <string>
#include <Windows.h>
#include <TlHelp32.h>
#include "RemoteCode.hpp"

using namespace std;

typedef void(*ProcessAction)(DWORD Pid, WCHAR*);

HMODULE hPatch = NULL;

int ccount = 0;


class iProtect
{
private:

	BOOL EnumProcess(ProcessAction Action)
	{
		PROCESSENTRY32 pe32 = { 0 };
		pe32.dwSize = sizeof(PROCESSENTRY32);
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (INVALID_HANDLE_VALUE == hProcessSnap)
		{
			return FALSE;
		}
		BOOL bRet = ::Process32First(hProcessSnap, &pe32);
		while (bRet)
		{
			Action(pe32.th32ProcessID, pe32.szExeFile);
			bRet = ::Process32Next(hProcessSnap, &pe32);
		}

		::CloseHandle(hProcessSnap);
		return TRUE;
	}
public:

	int main(vector<string> args)
	{
		if (args.size() != 2)
		{
			cout << "Syntax Error." << endl;
			return -1;
		}
		PROCESS_INFORMATION pi;
		STARTUPINFOA si;

		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		ZeroMemory(&si, sizeof(STARTUPINFOA));

		if (!CreateProcessA(
			NULL,
			(LPSTR)args[1].c_str(),
			NULL,
			NULL,
			FALSE,
			NULL,
			NULL,
			NULL,
			&si,
			&pi
		)) {
			cout << "Fail with " << GetLastError() << "." << endl;
			return -1;
		}
		
		hPatch = LoadLibraryW(L"patch.dll");
		(*(DWORD*)GetProcAddress(hPatch, "ProtectedPID")) = pi.dwProcessId;
		
		ShowWindow(
			GetConsoleWindow(), SW_HIDE);
		while (1)
		{
			DWORD returnCode;
			if (GetExitCodeProcess(pi.hProcess, &returnCode))
				if (returnCode != STILL_ACTIVE) {
					break;
				}
			EnumProcess([](DWORD Pid, WCHAR* Name)
				{

					if (lstrcmpW(Name, L"Taskmgr.exe"))
					return;
			if (RemoteCode::check(Pid, hPatch))return;


			RemoteCode rc(Pid, hPatch);
			rc.startinvoke("LocalBanProcessOperation", NULL);
			cout << ccount << ":" << Pid << endl;
			ccount++;

				});

			Sleep(250);
		}

		
		return 0;
	}
};

int main(int argc, char** argv)
{
    iProtect* i = new  iProtect;
    vector<string> args;

    for (int i = 0; i < argc; i++)
    {
        args.push_back(argv[i]);
    }

    int r = i->main(args);

    delete i;
    return r;
}