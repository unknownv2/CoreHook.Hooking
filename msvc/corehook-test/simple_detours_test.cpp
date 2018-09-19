#include "pch.h"
#include "simple_detours.h"

bool detoured_test = false;

// disable optimizations for test functions so they aren't inlined
#pragma optimize( "", off )

unsigned int OriginalFunction(unsigned int count) {
    return count + 1;
}
unsigned int OriginalFunction_Detour(unsigned int count) {
    detoured_test = true;

    return OriginalFunction(count);
}

#pragma optimize( "", on )
bool Detours::DetoursSimpleTest1() {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    LONG error = DetourInstallHook(
        OriginalFunction,
        OriginalFunction_Detour,
        &callback,
        &hookHandle);

    if (error == NO_ERROR) {
        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        OriginalFunction(1);

        DetourUninstallHook(&hookHandle);
    }

    return detoured_test;
}


CONST WCHAR* _detourFileName;

HANDLE WINAPI CreateFileW_Detour(
    LPCWSTR fileName,
    DWORD access,
    DWORD share,
    LPSECURITY_ATTRIBUTES a3,
    DWORD create,
    DWORD flags,
    HANDLE templateFile) {
    _detourFileName = fileName;

    return CreateFileW(fileName, access, share, a3, create, flags, templateFile);
}

// Detour CreateFileW and save the pointer to the first argument: 'lpFileName'
// The test file should not exist and so CreateFileW will return INVALID_HANDLE_VALUE
HANDLE Detours::DetoursSimpleTest2(LPCWSTR file, LPCWSTR* outFile) {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    LONG error = DetourInstallHook(
        CreateFileW,
        CreateFileW_Detour,
        &callback,
        &hookHandle);

    HANDLE hFile = NULL;

    if (error == NO_ERROR) {
        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        hFile = CreateFile(file,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        DetourUninstallHook(&hookHandle);

        *outFile = _detourFileName;
    }

    return hFile;
}
