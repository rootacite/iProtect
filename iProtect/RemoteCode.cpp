
#include "Toolsets.hpp"
#include "RemoteCode.hpp"


static HMODULE InjectDLL(DWORD ProcessID, HMODULE hModule, LPCSTR lPAction = NULL, LPVOID Param = NULL, SIZE_T ParamSize = 0)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, ProcessID);
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
    for (HMODULE i : EnumModules(ProcessID)) //遍历目标进程的模块，找到刚刚注入的
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

    CloseHandle(hProcess);
    CloseHandle(hThread);
    return r;
}

static PTHREAD_START_ROUTINE GetRemoteRoutine(HMODULE rhModule, HMODULE lhModule, LPCSTR Name)
{
    ULONG64 l_Routine = (ULONG64)::GetProcAddress(lhModule, Name);

    ULONG64 RVA = l_Routine - (ULONG64)lhModule;

    return (PTHREAD_START_ROUTINE)((ULONG64)rhModule + RVA);
}

static LPVOID WriteData(DWORD ProcessID, LPVOID Data, SIZE_T Size)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ProcessID);

    LPVOID r = VirtualAllocEx(hProcess, NULL, Size, MEM_COMMIT, PAGE_READWRITE);
    if (!r)return NULL;

    WriteProcessMemory(hProcess, r, Data, Size, NULL);
    CloseHandle(hProcess);
    return r;
}

static VOID ReleaseMem(DWORD ProcessID, LPVOID p)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, ProcessID);
    VirtualFreeEx(hProcess, p, 0, MEM_RELEASE);
    CloseHandle(hProcess);
}

static HANDLE InvokeRoutine(DWORD ProcessID, PTHREAD_START_ROUTINE Entry, LPVOID Param = NULL)
{
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, ProcessID);

    HANDLE hrAction = CreateRemoteThread(hProcess, NULL, 0, Entry, Param, 0, NULL);
    if (!hrAction) return INVALID_HANDLE_VALUE;

    CloseHandle(hProcess);
    return hrAction;
}


RemoteCode::RemoteCode(DWORD ProcessId, HMODULE hModule)
{
    this->Id = ProcessId;
    this->l_Base = hModule;

    this->r_Base = InjectDLL(ProcessId, hModule);
}


template<typename T>
void* RemoteCode::write(T& data)
{
    LPVOID pdata = &data;
    SIZE_T size = sizeof(data);

    return WriteData(Id, pdata, size);
}

void RemoteCode::release(void* p)
{
    ReleaseMem(Id, p);
}

unsigned int RemoteCode::invoke(std::string name, void* param)
{
    auto routine = GetRemoteRoutine(r_Base, l_Base, name.c_str());
    HANDLE hThread = InvokeRoutine(Id, routine, param);

    WaitForSingleObject(hThread, INFINITE);
    DWORD dwCode;
    GetExitCodeThread(hThread, &dwCode);
    CloseHandle(hThread);

    return dwCode;
}

void RemoteCode::startinvoke(std::string name, void* param)
{
    auto routine = GetRemoteRoutine(r_Base, l_Base, name.c_str());
    HANDLE hThread = InvokeRoutine(Id, routine, param);
    CloseHandle(hThread);
}

bool RemoteCode::check(DWORD ProcessID, HMODULE hModule)
{
    WCHAR dllPath[512];
    GetModuleFileNameW(hModule, dllPath, 512);   //获取Dll的全路径

    for (HMODULE i : EnumModules(ProcessID)) //遍历目标进程的模块，找到刚刚注入的
    {
        WCHAR remotedllPath[512];
        GetModuleFileNameW(i, remotedllPath, 512);
        if (lstrcmpW(remotedllPath, dllPath) == 0)  //如果遍历到的模块是我们注入的
        {
            return true;
        }
    }

    return false;
}