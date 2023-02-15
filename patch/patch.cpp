#include "pch.h"
#include "patch.h"
#include <vector>
#include <Psapi.h>
#include "detours/detours.h"
#pragma comment(lib,"detours.lib")

#pragma data_seg("SHARED")

using namespace std;

DLLAPI DWORD ProtectedPID = 17492;

#pragma data_seg()
#pragma comment(linker, "/section:SHARED,rws")

extern HMODULE m_hModule;

std::vector<HMODULE> EnumModules(HANDLE hProcess)
{
    std::vector<HMODULE> r;

    DWORD cbNeeds = 0;
    HMODULE* pModules = NULL;


    EnumProcessModules(hProcess, nullptr, 0, &cbNeeds);
    pModules = new HMODULE[cbNeeds / sizeof(HMODULE)];
    if (!EnumProcessModules(hProcess, pModules, cbNeeds, &cbNeeds))
    {
        delete[] pModules;
        return r;
    }

    for (int i = 0; i < cbNeeds / sizeof(HMODULE); i++)
    {
        r.push_back(pModules[i]);
    }
    delete[] pModules;
    return r;
}

static HMODULE InjectDLL(HANDLE hProcess, HMODULE hModule, LPCSTR lPAction = NULL, LPVOID Param = NULL, SIZE_T ParamSize = 0)
{
    if (!hProcess)return NULL;
    WCHAR dllPath[512];
    GetModuleFileNameW(hModule, dllPath, 512);   //获取Dll的全路径

    int cb = (1 + lstrlenW(dllPath)) * sizeof(wchar_t);
    LPWSTR PszLibFileRemote = (LPWSTR)VirtualAllocEx(hProcess, NULL, cb, MEM_COMMIT, PAGE_READWRITE);   //在目标进程内申请一块内存，用于保存参数
    if (!PszLibFileRemote)return NULL;

    WriteProcessMemory(hProcess, PszLibFileRemote, (LPVOID)dllPath, cb, NULL);  //向目标进程内写入参数

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)LoadLibrary, PszLibFileRemote, 0, NULL);  //创建远程线程

    if (!hThread)return NULL;
    WaitForSingleObject(hThread, INFINITE);

    //收尾工作
    VirtualFreeEx(hProcess, PszLibFileRemote, 0, MEM_RELEASE);

    HMODULE r = NULL;
    for (HMODULE i : EnumModules(hProcess)) //遍历目标进程的模块，找到刚刚注入的
    {
        WCHAR remotedllPath[512];
        GetModuleFileNameW(i, remotedllPath, 512);
        if (lstrcmpW(remotedllPath, dllPath) == 0)  //如果遍历到的模块是我们注入的
        {
            r = i;
            if (lPAction)
            {
                ULONG64 pProc = (ULONG64)GetProcAddress(hModule, lPAction);
                ULONG64 RVA = pProc - (ULONG64)hModule;
                LPVOID rParam = NULL;

                if (Param)
                {
                    //申请参数的内存空间
                    rParam = VirtualAllocEx(hProcess, NULL, ParamSize, MEM_COMMIT, PAGE_READWRITE);
                    if (!rParam)break;

                    WriteProcessMemory(hProcess, rParam, (LPVOID)Param, ParamSize, NULL);
                }

                HANDLE hrAction = CreateRemoteThread(hProcess, NULL, 0, (PTHREAD_START_ROUTINE)(RVA + (ULONG64)i), rParam, 0, NULL);
                if (!hrAction) break;
                WaitForSingleObject(hrAction, INFINITE);

                if (rParam) VirtualFreeEx(hProcess, rParam, 0, MEM_RELEASE);
                CloseHandle(hrAction);
            }
            break;
        }
    }

    CloseHandle(hThread);
    return r;
}

static PTHREAD_START_ROUTINE GetRemoteRoutine(HMODULE rhModule, HMODULE lhModule, LPCSTR Name)
{
    ULONG64 l_Routine = (ULONG64)::GetProcAddress(lhModule, Name);

    ULONG64 RVA = l_Routine - (ULONG64)lhModule;

    return (PTHREAD_START_ROUTINE)((ULONG64)rhModule + RVA);
}

static HANDLE InvokeRoutine(HANDLE hProcess, PTHREAD_START_ROUTINE Entry, LPVOID Param = NULL)
{
    HANDLE hrAction = CreateRemoteThread(hProcess, NULL, 0, Entry, Param, 0, NULL);
    if (!hrAction) return INVALID_HANDLE_VALUE;

    return hrAction;
}



__ROUTINE(ExitWhenNoTarget)
{
    HANDLE hTarget = pOpenProcess(PROCESS_ALL_ACCESS, FALSE, ProtectedPID);

    while (1)
    {
        DWORD returnCode;
        if (GetExitCodeProcess(hTarget, &returnCode))
            if (returnCode != STILL_ACTIVE) {
                LocalUnBanProcessOperation(NULL);
                FreeLibraryAndExitThread(m_hModule, 0);
                break;
            }
        Sleep(1000);
    }
    return 0;
}

HANDLE WINAPI fakeOpenProcess(DWORD a, BOOL isi, DWORD pid)
{
    if (pid != ProtectedPID)return pOpenProcess(a, isi, pid);
    
    if (a & (PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME | PROCESS_QUERY_INFORMATION)) 
    {
        SetLastError(156);
        return INVALID_HANDLE_VALUE;
    }
    return pOpenProcess(a, isi, pid);
}

BOOL WINAPI fakeCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    //IsWow64Process

    BOOL r =  pCreateProcessW(
        lpApplicationName,
        lpCommandLine, 
        lpProcessAttributes, 
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
    
    BOOL isWow64 = FALSE;
    IsWow64Process(lpProcessInformation->hProcess, &isWow64);
    if (isWow64)
    {
        return r;
    }
    
    HMODULE hm = InjectDLL(lpProcessInformation->hProcess, m_hModule);
    LPVOID c= GetRemoteRoutine(hm, m_hModule, "LocalBanProcessOperation");
    InvokeRoutine(lpProcessInformation->hProcess, (PTHREAD_START_ROUTINE)c);
 
    return r;
}

BOOL WINAPI fakeCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    return pCreateProcessA(
        lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation
    );
}

__ROUTINE (LocalBanProcessOperation)
{
    CreateThread(nullptr, 0, ExitWhenNoTarget, nullptr, 0, nullptr);

    DetourRestoreAfterWith();
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)pOpenProcess, fakeOpenProcess);
    //DetourAttach(&(PVOID&)pCreateProcessA, fakeCreateProcessA);
    //DetourAttach(&(PVOID&)pCreateProcessW, fakeCreateProcessW);
    DetourTransactionCommit();

    return 0;
}

__ROUTINE(LocalUnBanProcessOperation)
{
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourDetach(&(PVOID&)pOpenProcess, fakeOpenProcess);
    //DetourDetach(&(PVOID&)pCreateProcessA, fakeCreateProcessA);
    //DetourDetach(&(PVOID&)pCreateProcessW, fakeCreateProcessW);
    DetourTransactionCommit();

    return 0;
}
