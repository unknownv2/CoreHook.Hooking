#define _CRT_STDIO_ARBITRARY_WIDE_SPECIFIERS 1

#pragma warning(disable : 4068) // unknown pragma (suppress)

#if _MSC_VER >= 1900
#pragma warning(push)
#pragma warning(disable : 4091) // empty typedef
#endif

#define _ARM_WINAPI_PARTITION_DESKTOP_SDK_AVAILABLE 1
#include <windows.h>
#include <aux_ulib.h>
#if (_MSC_VER < 1310)
#else
#pragma warning(push)
#if _MSC_VER > 1400
#pragma warning(disable : 6102 6103) // /analyze warnings
#endif
#include <strsafe.h>
#pragma warning(pop)
#endif

// #define DETOUR_DEBUG 1
#define DETOURS_INTERNAL
#include "detours.h"


#if DETOURS_VERSION != 0x4c0c1 // 0xMAJORcMINORcPATCH
#error detours.h version mismatch
#endif

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

// allocate at DLL Entry
HANDLE hCoreHookHeap = NULL;

BARRIER_UNIT Unit;

void RtlInitializeLock(RTL_SPIN_LOCK *OutLock)
{
    RtlZeroMemory(OutLock, sizeof(RTL_SPIN_LOCK));

    InitializeCriticalSection(&OutLock->Lock);
}

void RtlAcquireLock(RTL_SPIN_LOCK *InLock)
{
    EnterCriticalSection(&InLock->Lock);

    DETOUR_ASSERT(!InLock->IsOwned, L"barrier.cpp - !InLock->IsOwned");

    InLock->IsOwned = TRUE;
}

void RtlReleaseLock(RTL_SPIN_LOCK *InLock)
{
    DETOUR_ASSERT(InLock->IsOwned, L"barrier.cpp - InLock->IsOwned");

    InLock->IsOwned = FALSE;

    LeaveCriticalSection(&InLock->Lock);
}

void RtlDeleteLock(RTL_SPIN_LOCK *InLock)
{
    DETOUR_ASSERT(!InLock->IsOwned, L"barrier.cpp - InLock->IsOwned");

    DeleteCriticalSection(&InLock->Lock);
}

void RtlSleep(ULONG InTimeout)
{
    Sleep(InTimeout);
}

void RtlCopyMemory(
    PVOID InDest,
    PVOID InSource,
    ULONG InByteCount)
{
    ULONG Index;
    UCHAR *Dest = (UCHAR *)InDest;
    UCHAR *Src = (UCHAR *)InSource;

    for (Index = 0; Index < InByteCount; Index++)
    {
        *Dest = *Src;

        Dest++;
        Src++;
    }
}

void *RtlAllocateMemory(BOOL InZeroMemory, ULONG InSize)
{
    void *Result = HeapAlloc(hCoreHookHeap, 0, InSize);

    if (InZeroMemory && (Result != NULL)) {
        RtlZeroMemory(Result, InSize);
    }

    return Result;
}

#ifndef _DEBUG
#pragma optimize("", off) // suppress _memset
#endif
void RtlZeroMemory(
    PVOID InTarget,
    ULONG InByteCount)
{
    ULONG Index;
    UCHAR *Target = (UCHAR *)InTarget;

    for (Index = 0; Index < InByteCount; Index++)
    {
        *Target = 0;

        Target++;
    }
}
#ifndef _DEBUG
#pragma optimize("", on)
#endif

LONG RtlProtectMemory(void *InPointer, ULONG InSize, ULONG InNewProtection)
{
    DWORD OldProtect;
    LONG NtStatus;

    if (!VirtualProtect(InPointer, InSize, InNewProtection, &OldProtect))
    {
        THROW(STATUS_INVALID_PARAMETER, L"Unable to make memory executable.")
    }
    else
    {
        return STATUS_SUCCESS;
    }
THROW_OUTRO:

    return NtStatus;
}

void RtlFreeMemory(void *InPointer)
{
    DETOUR_ASSERT(InPointer != NULL, L"barrier.cpp - InPointer != NULL");

    HeapFree(hCoreHookHeap, 0, InPointer);
}

LONG RtlInterlockedIncrement(LONG *RefValue)
{
    return InterlockedIncrement(RefValue);
}

BOOL RtlIsValidPointer(PVOID InPtr, ULONG InSize)
{
    if ((InPtr == NULL) || (InPtr == (PVOID)~0)) {
        return FALSE;
    }

    DETOUR_ASSERT(!IsBadReadPtr(InPtr, InSize), L"barrier.cpp - !IsBadReadPtr(InPtr, InSize)");

    return TRUE;
}

// Error Handling
// Print status for exceptions
//
static LPCWSTR LastError = L"";
static ULONG LastErrorCode = 0;

#if _DEBUG
#define DEBUGMSG(...) do { WCHAR debugMsg[1024] = { 0 }; _snwprintf_s(debugMsg, 1024, _TRUNCATE, __VA_ARGS__); OutputDebugStringW(debugMsg); } while(0)
#else
#define DEBUGMSG
#endif

LPCWSTR RtlErrorCodeToString(LONG InCode)
{
    switch (InCode)
    {
    case STATUS_SUCCESS: return L"STATUS_SUCCESS";
    case STATUS_NOT_SUPPORTED: return L"STATUS_NOT_SUPPORTED";
    case STATUS_INTERNAL_ERROR: return L"STATUS_INTERNAL_ERROR";
    case STATUS_PROCEDURE_NOT_FOUND: return L"STATUS_PROCEDURE_NOT_FOUND";
    case STATUS_NOINTERFACE: return L"STATUS_NOINTERFACE";
    case STATUS_INFO_LENGTH_MISMATCH: return L"STATUS_INFO_LENGTH_MISMATCH";
    case STATUS_BUFFER_TOO_SMALL: return L"STATUS_BUFFER_TOO_SMALL";
    case STATUS_INVALID_PARAMETER: return L"STATUS_INVALID_PARAMETER";
    case STATUS_INSUFFICIENT_RESOURCES: return L"STATUS_INSUFFICIENT_RESOURCES";
    case STATUS_UNHANDLED_EXCEPTION: return L"STATUS_UNHANDLED_EXCEPTION";
    case STATUS_NOT_FOUND: return L"STATUS_NOT_FOUND";
    case STATUS_NOT_IMPLEMENTED: return L"STATUS_NOT_IMPLEMENTED";
    case STATUS_ACCESS_DENIED: return L"STATUS_ACCESS_DENIED";
    case STATUS_ALREADY_REGISTERED: return L"STATUS_ALREADY_REGISTERED";
    case STATUS_WOW_ASSERTION: return L"STATUS_WOW_ASSERTION";
    case STATUS_BUFFER_OVERFLOW: return L"STATUS_BUFFER_OVERFLOW";
    case STATUS_DLL_INIT_FAILED: return L"STATUS_DLL_INIT_FAILED";
    case STATUS_INVALID_PARAMETER_1: return L"STATUS_INVALID_PARAMETER_1";
    case STATUS_INVALID_PARAMETER_2: return L"STATUS_INVALID_PARAMETER_2";
    case STATUS_INVALID_PARAMETER_3: return L"STATUS_INVALID_PARAMETER_3";
    case STATUS_INVALID_PARAMETER_4: return L"STATUS_INVALID_PARAMETER_4";
    case STATUS_INVALID_PARAMETER_5: return L"STATUS_INVALID_PARAMETER_5";
    case STATUS_INVALID_PARAMETER_6: return L"STATUS_INVALID_PARAMETER_6";
    case STATUS_INVALID_PARAMETER_7: return L"STATUS_INVALID_PARAMETER_7";
    case STATUS_INVALID_PARAMETER_8: return L"STATUS_INVALID_PARAMETER_8";
    default: return L"UNKNOWN";
    }
}

void RtlSetLastError(LONG InCode, LONG InNtStatus, LPCWSTR InMessage)
{
    LastErrorCode = InCode;

    if (InMessage == NULL)
    {
        LastError = L"";
        (void)InNtStatus;
    }
    else
    {
#if _DEBUG
        if (lstrlenW(InMessage) > 0)
        {
            WCHAR msg[1024] = { 0 };
            WCHAR* lpMsgBuf = NULL;

            if (InNtStatus == STATUS_SUCCESS)
            {
                FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    InCode,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    lpMsgBuf,
                    0, NULL);
                _snwprintf_s(msg, 1024, _TRUNCATE, L"%s (%s)\n", InMessage, lpMsgBuf);
            }
            else
            {
                _snwprintf_s(msg, 1024, _TRUNCATE, L"%s (%s)\n", InMessage, RtlErrorCodeToString(InNtStatus));
            }
            DEBUGMSG(msg);

            if (lpMsgBuf != NULL)
            {
                LocalFree(lpMsgBuf);
            }
        }
#endif
        LastError = InMessage;
    }
}
void RtlAssert(BOOL InAssert, LPCWSTR lpMessageText)
{
    if (InAssert) {
        return;
    }

#ifdef _DEBUG
    DebugBreak();
#endif
    FatalAppExitW(0, lpMessageText);
}

LONG DetourSetGlobalInclusiveACL(
    ULONG *InThreadIdList,
    ULONG InThreadCount)
{
/*
Description:

    Sets an inclusive global ACL based on the given thread ID list.
    
Parameters:
    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    return DetourSetACL(DetourBarrierGetAcl(), FALSE, InThreadIdList, InThreadCount);
}

LONG DetourSetGlobalExclusiveACL(
    ULONG *InThreadIdList,
    ULONG InThreadCount)
{
/*
Description:

    Sets an exclusive global ACL based on the given thread ID list.
    
Parameters:
    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    return DetourSetACL(DetourBarrierGetAcl(), TRUE, InThreadIdList, InThreadCount);
}

BOOL DetourIsValidHandle(
    TRACED_HOOK_HANDLE InTracedHandle,
    PLOCAL_HOOK_INFO *OutHandle)
{

/*
Description:

    A handle is considered to be valid, if the whole structure
    points to valid memory AND the signature is valid AND the
    hook is installed!

*/

    if (!IsValidPointer(InTracedHandle, sizeof(HOOK_TRACE_INFO))) {
        return FALSE;
    }

    if (OutHandle != NULL) {
        *OutHandle = InTracedHandle->Link;
    }

    return TRUE;
}
LONG DetourSetACL(
    HOOK_ACL *InAcl,
    BOOL InIsExclusive,
    ULONG *InThreadIdList,
    ULONG InThreadCount)
{
/*
Description:

    This method is used internally to provide a generic interface to
    either the global or local hook ACLs.
    
Parameters:
    - InAcl
        NULL if you want to set the global ACL.
        Any LOCAL_HOOK_INFO::LocalACL to set the hook specific ACL.

    - InIsExclusive
        TRUE if all listed thread shall be excluded from interception,
        FALSE otherwise

    - InThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - InThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    ULONG Index;

    DETOUR_ASSERT(IsValidPointer(InAcl, sizeof(HOOK_ACL)), L"barrier.cpp - IsValidPointer(InAcl, sizeof(HOOK_ACL))");

    if (InThreadCount > MAX_ACE_COUNT) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (!IsValidPointer(InThreadIdList, InThreadCount * sizeof(ULONG))) {
        return STATUS_INVALID_PARAMETER_1;
    }

    for (Index = 0; Index < InThreadCount; Index++)
    {
        if (InThreadIdList[Index] == 0)
            InThreadIdList[Index] = GetCurrentThreadId();
    }
    DWORD dwOld;
    if (VirtualProtect(InAcl, sizeof(HOOK_ACL), PAGE_READWRITE, &dwOld))
    {
        // set ACL...
        InAcl->IsExclusive = InIsExclusive;
        InAcl->Count = InThreadCount;

        RtlCopyMemory(InAcl->Entries, InThreadIdList, InThreadCount * sizeof(ULONG));

        DWORD dwOld2;
        VirtualProtect(InAcl, sizeof(HOOK_ACL), dwOld, &dwOld2);
    }
    else
    {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

HOOK_ACL *DetourBarrierGetAcl()
{
    return &Unit.GlobalACL;
}

LONG DetourBarrierProcessAttach()
{
/*
Description:

    Will be called on DLL load and initializes all barrier structures.
*/

    RtlZeroMemory(&Unit, sizeof(Unit));

    // globally accept all threads...
    Unit.GlobalACL.IsExclusive = TRUE;

    // allocate private heap
    RtlInitializeLock(&Unit.TLS.ThreadSafe);

    Unit.IsInitialized = AuxUlibInitialize() ? TRUE : FALSE;

    hCoreHookHeap = HeapCreate(0, 0, 0);

    return STATUS_SUCCESS;
}

BOOL TlsGetCurrentValue(
    THREAD_LOCAL_STORAGE *InTls,
    THREAD_RUNTIME_INFO **OutValue)
{
/*
Description:

    Queries the THREAD_RUNTIME_INFO for the calling thread.
    The caller shall previously be added to the storage by
    using TlsAddCurrentThread().

Parameters:

    - InTls

        The storage where the caller is registered.

    - OutValue

        Is filled with a pointer to the caller's private storage entry.

Returns:

    FALSE if the caller was not registered in the storage, TRUE otherwise.
*/

    DWORD CurrentId = GetCurrentThreadId();

    LONG Index;

    for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
    {
        if (InTls->IdList[Index] == CurrentId)
        {
            *OutValue = &InTls->Entries[Index];

            return TRUE;
        }
    }

    return FALSE;
}
BOOL TlsAddCurrentThread(THREAD_LOCAL_STORAGE *InTls)
{
/*
Description:

    Tries to reserve a THREAD_RUNTIME_INFO entry for the calling thread.
    On success it may call TlsGetCurrentValue() to query a pointer to
    its private entry.

    This is a replacement for the Windows Thread Local Storage which seems
    to cause trouble when using it in Explorer.EXE for example.

    No parameter validation (for performance reasons).

    This method will raise an assertion if the thread was already added
    to the storage!

Parameters:
    - InTls

        The thread local storage to allocate from.

Returns:

    TRUE on success, FALSE otherwise.
*/

    ULONG CurrentId = GetCurrentThreadId();
    LONG Index = -1;
    LONG i;

    RtlAcquireLock(&InTls->ThreadSafe);

    // select Index AND check whether thread is already registered.
    for (i = 0; i < MAX_THREAD_COUNT; i++)
    {
        if ((InTls->IdList[i] == 0) && (Index == -1)) {
            Index = i;
        }

        DETOUR_ASSERT(InTls->IdList[i] != CurrentId, L"barrier.cpp - InTls->IdList[i] != CurrentId");
    }

    if (Index == -1)
    {
        RtlReleaseLock(&InTls->ThreadSafe);

        return FALSE;
    }

    InTls->IdList[Index] = CurrentId;
    RtlZeroMemory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));

    RtlReleaseLock(&InTls->ThreadSafe);

    return TRUE;
}

void TlsRemoveCurrentThread(THREAD_LOCAL_STORAGE *InTls)
{
/*
Description:

    Removes the caller from the local storage. If the caller
    is already removed, the method will do nothing.

Parameters:

    - InTls

        The storage from which the caller should be removed.
*/

    DWORD CurrentId = GetCurrentThreadId();
    ULONG Index;

    RtlAcquireLock(&InTls->ThreadSafe);

    for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
    {
        if (InTls->IdList[Index] == CurrentId)
        {
            InTls->IdList[Index] = 0;

            RtlZeroMemory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));
        }
    }

    RtlReleaseLock(&InTls->ThreadSafe);
}

void DetourBarrierProcessDetach()
{
/*
Description:

    Will be called on DLL unload.
*/

    ULONG Index;

    RtlDeleteLock(&Unit.TLS.ThreadSafe);

    // release thread specific resources
    for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
    {
        if (Unit.TLS.Entries[Index].Entries != NULL)
        {
            RtlFreeMemory(Unit.TLS.Entries[Index].Entries);
        }
    }

    RtlZeroMemory(&Unit, sizeof(Unit));

    HeapDestroy(hCoreHookHeap);
}

void DetourBarrierThreadDetach()
{
/*
Description:

    Will be called on thread termination and cleans up the TLS.
*/

    LPTHREAD_RUNTIME_INFO Info;

    if (TlsGetCurrentValue(&Unit.TLS, &Info))
    {
        if (Info->Entries != NULL)
        {
            RtlFreeMemory(Info->Entries);
        }

        Info->Entries = NULL;
    }

    TlsRemoveCurrentThread(&Unit.TLS);
}

RTL_SPIN_LOCK GlobalHookLock;

void DetourCriticalInitialize()
{
/*
Description:
    
    Fail safe initialization of global hooking structures...
*/

    RtlInitializeLock(&GlobalHookLock);
}

void DetourCriticalFinalize()
{
/*
Description:

    Will be called in the DLL_PROCESS_DETACH event and just uninstalls
    all hooks. If it is possible also their memory is released. 
*/

    RtlDeleteLock(&GlobalHookLock);
}

BOOL IsLoaderLock()
{
/*
Returns:

    TRUE if the current thread hols the OS loader lock, or the library was not initialized
    properly. In both cases a hook handler should not be executed!

    FALSE if it is safe to execute the hook handler.

*/

    BOOL IsLoaderLock = FALSE;

    return (!AuxUlibIsDLLSynchronizationHeld(&IsLoaderLock) || IsLoaderLock || !Unit.IsInitialized);
}

BOOL AcquireSelfProtection()
{
/*
Description:

    To provide more convenience for writing the TDB, this self protection
    will disable ALL hooks for the current thread until ReleaseSelfProtection() 
    is called. This allows one to call any API during TDB initialization
    without being intercepted...

Returns:

    TRUE if the caller's runtime info has been locked down.

    FALSE if the caller's runtime info already has been locked down
    or is not available. The hook handler should not be executed in
    this case!

*/

    LPTHREAD_RUNTIME_INFO Runtime = NULL;

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime) || Runtime->IsProtected) {
        return FALSE;
    }

    Runtime->IsProtected = TRUE;

    return TRUE;
}

void ReleaseSelfProtection()
{
/*
Description:

    Exists the TDB self protection. Refer to AcquireSelfProtection() for more
    information.

    An assertion is raised if the caller has not owned the self protection.
*/

    LPTHREAD_RUNTIME_INFO Runtime = NULL;

    DETOUR_ASSERT(TlsGetCurrentValue(&Unit.TLS, &Runtime) && Runtime->IsProtected, L"barrier.cpp - TlsGetCurrentValue(&Unit.TLS, &Runtime) && Runtime->IsProtected");

    Runtime->IsProtected = FALSE;
}

BOOL ACLContains(
    HOOK_ACL *InACL,
    ULONG InCheckID)
{
/*
Returns:

    TRUE if the given ACL contains the given ID, FALSE otherwise.
*/

    ULONG Index;

    for (Index = 0; Index < InACL->Count; Index++)
    {
        if (InACL->Entries[Index] == InCheckID)
            return TRUE;
    }

    return FALSE;
}

BOOL IsThreadIntercepted(
    HOOK_ACL *LocalACL,
    ULONG InThreadID)
{
/*
Description:

    Please refer to DetourIsThreadIntercepted() for more information.

Returns:

    TRUE if the given thread is intercepted by the global AND local ACL,
    FALSE otherwise.
*/

    ULONG CheckID;

    if (InThreadID == 0) {
        CheckID = GetCurrentThreadId();
    }
    else {
        CheckID = InThreadID;
    }

    if (ACLContains(&Unit.GlobalACL, CheckID))
    {
        if (ACLContains(LocalACL, CheckID))
        {
            if (LocalACL->IsExclusive) {
                return FALSE;
            }
        }
        else
        {
            if (!LocalACL->IsExclusive) {
                return FALSE;
            }
        }

        return !Unit.GlobalACL.IsExclusive;
    }
    else
    {
        if (ACLContains(LocalACL, CheckID))
        {
            if (LocalACL->IsExclusive) {
                return FALSE;
            }
        }
        else
        {
            if (!LocalACL->IsExclusive) {
                return FALSE;
            }
        }

        return Unit.GlobalACL.IsExclusive;
    }
}

LONG DetourBarrierGetCallback(PVOID *OutValue)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the callback initially passed to the related DetourInstallHook()
    call.

*/

    LONG                    NtStatus;
    LPTHREAD_RUNTIME_INFO   Runtime;


    if (!IsValidPointer(OutValue, sizeof(PVOID)))
    {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid result storage specified.");
    }
    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) 
    {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }
    if (Runtime->Current != NULL) 
    {
        *OutValue = Runtime->Callback;
    }
    else 
    { 
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourBarrierGetReturnAddress(PVOID* OutValue)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the return address of the hook handler. This is usually the
    instruction behind the "CALL" which invoked the hook.

    The calling module determination is based on this method.

*/

    LONG                        NtStatus;
    LPTHREAD_RUNTIME_INFO       Runtime;

    if (!IsValidPointer(OutValue, sizeof(PVOID))) {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid result storage specified.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    if (Runtime->Current != NULL) {
        *OutValue = Runtime->Current->RetAddress;
    }
    else {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}


LONG DetourBarrierGetAddressOfReturnAddress(PVOID** OutValue)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the address of the return address of the hook handler.
*/

    LPTHREAD_RUNTIME_INFO       Runtime;
    LONG                        NtStatus;

    if (OutValue == NULL) {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid storage specified.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    if (Runtime->Current != NULL) {
        *OutValue = Runtime->Current->AddrOfRetAddr;
    }
    else {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }
    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourBarrierBeginStackTrace(PVOID* OutBackup)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED.
    Temporarily restores the call stack to allow stack traces.

    You have to pass the stored backup pointer to
    DetourBarrierEndStackTrace() BEFORE leaving the handler, otherwise
    the application will be left in an unstable state!
*/

    LONG                        NtStatus;
    LPTHREAD_RUNTIME_INFO       Runtime;

    if (OutBackup == NULL) {
        THROW(STATUS_INVALID_PARAMETER, L"barrier.cpp - The given backup storage is invalid.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"barrier.cpp - The caller is not inside a hook handler.");
    }

    if (Runtime->Current == NULL) {
        THROW(STATUS_NOT_SUPPORTED, L"barrier.cpp - The caller is not inside a hook handler.");
    }

    *OutBackup = *Runtime->Current->AddrOfRetAddr;
    *Runtime->Current->AddrOfRetAddr = Runtime->Current->RetAddress;

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourBarrierEndStackTrace(PVOID InBackup)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED.

    You have to pass the backup pointer obtained with
    DetourBarrierBeginStackTrace().
*/

    LONG                NtStatus;
    PVOID*              AddrOfRetAddr;

    if (!IsValidPointer(InBackup, 1)) {
        THROW(STATUS_INVALID_PARAMETER, L"barrier.cpp - The given stack backup pointer is invalid.");
    }

    FORCE(DetourBarrierGetAddressOfReturnAddress(&AddrOfRetAddr));

    *AddrOfRetAddr = InBackup;

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG DetourBarrierCallStackTrace(
    PVOID* OutMethodArray,
    ULONG InMaxMethodCount,
    ULONG* OutMethodCount)
{
/*
Description:

    Creates a call stack trace and translates all method entries
    back into their owning modules.

Parameters:

    - OutMethodArray

        An array receiving the methods on the call stack.

    - InMaxMethodCount

        The length of the method array.

    - OutMethodCount

        The actual count of methods on the call stack. This will never
        be greater than 64.

Returns:

    STATUS_NOT_IMPLEMENTED

        Only supported since Windows XP.
*/
    
    LONG                    NtStatus;
    PVOID                   Backup = NULL;

    if (InMaxMethodCount > 64) {
        THROW(STATUS_INVALID_PARAMETER_2, L"barrier.cpp - At maximum 64 modules are supported.");
    }
    if (!IsValidPointer(OutMethodArray, InMaxMethodCount * sizeof(PVOID))) {
        THROW(STATUS_INVALID_PARAMETER_1, L"barrier.cpp - The given module buffer is invalid.");
    }

    if (!IsValidPointer(OutMethodCount, sizeof(ULONG))) {
        THROW(STATUS_INVALID_PARAMETER_3, L"barrier.cpp - Invalid module count storage.");
    }

    
    FORCE(DetourBarrierBeginStackTrace(&Backup));
    
    if (CaptureStackBackTrace == NULL) {
        THROW(STATUS_NOT_IMPLEMENTED, L"barrier.cpp - This method requires Windows XP or later.");
    }

    *OutMethodCount = CaptureStackBackTrace(1, 32, OutMethodArray, NULL);

    RETURN;
    
THROW_OUTRO:
FINALLY_OUTRO:
    {
        if (Backup != NULL) {
            DetourBarrierEndStackTrace(Backup);
        }
        return NtStatus;
    }
}