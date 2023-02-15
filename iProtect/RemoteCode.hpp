#pragma once

#ifndef REMOTECODE

#include <Windows.h>
#include <string>


class RemoteCode
{
private:
    DWORD Id;
    HMODULE l_Base;
    HMODULE r_Base;

public:
    RemoteCode(DWORD ProcessId, HMODULE hModule);

    template<typename T>
    void* write(T& data);

    void release(void* p);

    unsigned int invoke(std::string name, void* param);
    void startinvoke(std::string name, void* param);

    static bool check(DWORD ProcessID, HMODULE hModule);
    
};

#endif
#define REMOTECODE
