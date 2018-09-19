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
bool DetoursSimpleTest1() {
    auto callback = std::make_unique<LONG>();
    auto hookHandle = std::make_unique<HOOK_TRACE_INFO>();

    auto threadIdList = std::make_unique<ULONG>();
    const LONG threadCount = 1;

    LONG error = DetourInstallHook(
        OriginalFunction,
        OriginalFunction_Detour,
        callback.get(),
        hookHandle.get());

    if (error == NO_ERROR) {
        DetourSetInclusiveACL(
            threadIdList.get(),
            threadCount,
            hookHandle.get());

        OriginalFunction(1);

        DetourUninstallHook(hookHandle.get());
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
HANDLE Detours::DetoursSimpleTest2(LPCWSTR file) {
    auto callback = std::make_unique<LONG>();
    auto hookHandle = std::make_unique<HOOK_TRACE_INFO>();

    auto threadIdList = std::make_unique<ULONG>();
    const LONG threadCount = 1;

    LONG error = DetourInstallHook(
        CreateFileW,
        CreateFileW_Detour,
        callback.get(),
        hookHandle.get());

    HANDLE hFile = NULL;

    if (error == NO_ERROR) {
        DetourSetInclusiveACL(
            threadIdList.get(),
            threadCount,
            hookHandle.get());

        hFile = CreateFile(file,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        DetourUninstallHook(hookHandle.get());

        _fileName = _detourFileName;
    }

    return hFile;
}
