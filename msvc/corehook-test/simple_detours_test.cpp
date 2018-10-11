#include "pch.h"
#include "simple_detours.h"

bool detoured_test = false;

// disable optimizations for test functions so they aren't inlined
#pragma optimize( "", off )

unsigned int UserFunction(unsigned int count) {
    return count + 1;
}
unsigned int UserFunction_Detour(unsigned int count) {
    detoured_test = true;

    return UserFunction(count);
}
unsigned int SimpleFunction() {
    return 0x12345678;
}
unsigned int SimpleFunction_Detour() {
    detoured_test = true;

    return SimpleFunction() + 1;
}
unsigned int WINAPI MoveFile_Detour(_In_ LPCTSTR lpExistingFileName,
                                    _In_ LPCTSTR lpNewFileName) {
    detoured_test = true;

    return SimpleFunction() + 1;
}
#pragma optimize( "", on )

bool Detours::DetourUserFunction() {
    detoured_test = false;
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    if(DetourInstallHook(
        UserFunction,
        UserFunction_Detour,
        &callback,
        &hookHandle) == NO_ERROR) {

        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        UserFunction(1);

        DetourUninstallHook(&hookHandle);
    }

    return detoured_test;
}

int Detours::ShouldBypassDetourFunction() {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    DWORD result = 0;
    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    typedef DWORD (STDMETHODCALLTYPE SimpleFunctionFp)();
    SimpleFunctionFp* pfnDelegate = NULL;

    if(DetourInstallHook(
        SimpleFunction,
        SimpleFunction_Detour,
        &callback,
        &hookHandle) == NO_ERROR)  {

        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        if (DetourGetHookBypassAddress(
            &hookHandle,
            (PVOID**)&pfnDelegate) == NO_ERROR)  {
            result = pfnDelegate();
        }

        DetourUninstallHook(&hookHandle);
    }

    return result;
}

LPCWSTR  _detourFileName;

HANDLE WINAPI CreateFileW_Detour(
    LPCWSTR fileName,
    DWORD access,
    DWORD share,
    LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD create,
    DWORD flags,
    HANDLE templateFile
    )
{
    _detourFileName = fileName;

    return CreateFileW(
        fileName,
        access,
        share,
        securityAttributes,
        create, 
        flags, 
        templateFile);
}

// Detour CreateFileW and save the pointer to the first argument: 'lpFileName'
LONG Detours::DetourExportedFunction(LPCWSTR file, LPCWSTR *outFile) {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    LONG error = ERROR_SUCCESS;

    if ((error = DetourInstallHook(
        CreateFileW,
        CreateFileW_Detour,
        &callback,
        &hookHandle)) == NO_ERROR) {

        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        CreateFile(file,
            GENERIC_READ,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        DetourUninstallHook(&hookHandle);

        *outFile = _detourFileName;
    }

    return error;
}

PVOID Detours::FindFunction(_In_ LPCSTR pszModule, _In_ LPCSTR pszFunction) {
    return DetourFindFunction(pszModule, pszFunction);
}

LONG Detours::DetourMoveFileWithUserFunction() {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    LONG error = ERROR_SUCCESS;

    if ((error = DetourInstallHook(
        MoveFile,
        MoveFile_Detour,
        &callback,
        &hookHandle)) == NO_ERROR) {

        DetourSetInclusiveACL(
            &threadIdList,
            threadCount,
            &hookHandle);

        error = MoveFile(nullptr, nullptr);

        DetourUninstallHook(&hookHandle);
    }

    return error;
}

// Installs a detour for a function 
LONG Detours::DetourInstallDetourFunction() {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };

    ULONG threadIdList = 0;
    const LONG threadCount = 1;

    LONG error = ERROR_SUCCESS;

    error = DetourInstallHook(
        MoveFile,
        MoveFile_Detour,
        &callback,
        &hookHandle);

    return error;
}