#pragma once

#include <Windows.h>

#define DLLAPI extern "C" __declspec(dllexport)
#define ROUTINE DLLAPI DWORD WINAPI

typedef DWORD(WINAPI* Routine)(LPVOID);

#define __ROUTINE(X) ROUTINE X(LPVOID lParam)


/// <summary>
/// def of OpenProecss
/// </summary>
typedef HANDLE(WINAPI* POpenProcessType)(DWORD, BOOL, DWORD);
POpenProcessType pOpenProcess = OpenProcess;
HANDLE WINAPI fakeOpenProcess(DWORD a, BOOL isi, DWORD pid);

/// <summary>
/// def of CreateProcessW
/// </summary>

typedef BOOL(WINAPI* PCreateProcessWType)(
    LPCWSTR,
     LPWSTR,
     LPSECURITY_ATTRIBUTES,
     LPSECURITY_ATTRIBUTES,
     BOOL,
     DWORD,
     LPVOID,
     LPCWSTR,
     LPSTARTUPINFOW,
    LPPROCESS_INFORMATION
    );
PCreateProcessWType pCreateProcessW = CreateProcessW;
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
);

/// <summary>
/// def of CreateProcessA
/// </summary>

typedef BOOL(WINAPI* PCreateProcessAType)(
    LPCSTR,
    LPSTR,
    LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES,
    BOOL,
    DWORD,
    LPVOID,
    LPCSTR,
    LPSTARTUPINFOA,
    LPPROCESS_INFORMATION
    );
PCreateProcessAType pCreateProcessA = CreateProcessA;
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
);

__ROUTINE(LocalBanProcessOperation);
__ROUTINE(LocalUnBanProcessOperation);
