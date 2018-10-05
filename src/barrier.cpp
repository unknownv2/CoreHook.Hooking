/////////////////////////////////////////////////////////////////////////////
//
//  Trampoline Thread Barrier Functionality (barrier.cpp of detours.lib)
//
//


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
#include "barrier.h"

#if DETOURS_VERSION != 0x4c0c1 // 0xMAJORcMINORcPATCH
#error detours.h version mismatch
#endif

#if _MSC_VER >= 1900
#pragma warning(pop)
#endif

// allocate at DLL Entry
HANDLE hCoreHookHeap = NULL;

BARRIER_UNIT Unit;

void detour_sleep(_In_ DWORD milliSeconds)
{
    Sleep(milliSeconds);
}

static void detour_copy_memory(_Out_writes_bytes_all_(Size) PVOID  Dest,
                               _In_reads_bytes_(Size)       PVOID  Src,
                               _In_                         size_t Size)
{
    memcpy(Dest, Src, Size);
}

static void detour_zero_memory(_Out_writes_bytes_all_(Size) PVOID Dest,
    _In_                         size_t Size)
{
    memset(Dest, 0, Size);
}

void *detour_allocate_memory(_In_ BOOL   bZeroMemory,
                             _In_ size_t size)
{
    void *result = HeapAlloc(hCoreHookHeap, 0, size);

    if (bZeroMemory && (result != NULL)) {
        detour_zero_memory(result, size);
    }

    return result;
}

void detour_free_memory(void * pMemory)
{
    DETOUR_ASSERT(pMemory != NULL, L"barrier.cpp - pMemory != NULL");

    HeapFree(hCoreHookHeap, 0, pMemory);
}

BOOL detour_is_valid_pointer(_In_opt_ CONST VOID *Pointer,
                             _In_     UINT_PTR    Size)
{
    if ((Pointer == NULL) || (Pointer == (PVOID)~0)) {
        return FALSE;
    }
    (void)Size;
    return TRUE;
}

void detour_initialize_lock(_In_ RTL_SPIN_LOCK *pLock)
{
    detour_zero_memory(pLock, sizeof(RTL_SPIN_LOCK));

    InitializeCriticalSection(&pLock->Lock);
}

void detour_acquire_lock(_In_ RTL_SPIN_LOCK *pLock)
{
    EnterCriticalSection(&pLock->Lock);

    DETOUR_ASSERT(!pLock->IsOwned, L"barrier.cpp - !pLock->IsOwned");

    pLock->IsOwned = TRUE;
}

void detour_release_lock(_In_ RTL_SPIN_LOCK *pLock)
{
    DETOUR_ASSERT(pLock->IsOwned, L"barrier.cpp - pLock->IsOwned");

    pLock->IsOwned = FALSE;

    LeaveCriticalSection(&pLock->Lock);
}

void detour_delete_lock(_In_ RTL_SPIN_LOCK *pLock)
{
    DETOUR_ASSERT(!pLock->IsOwned, L"barrier.cpp - pLock->IsOwned");

    DeleteCriticalSection(&pLock->Lock);
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

LPCWSTR detour_error_code_to_string(_In_ LONG lCode)
{
    switch (lCode)
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

void detour_set_last_error(_In_ LONG lCode, _In_ LONG lStatus, _In_opt_ LPCWSTR lpMessage)
{
    LastErrorCode = lCode;

    if (lpMessage == NULL)
    {
        LastError = L"";
        (void)lStatus;
    }
    else
    {
#if _DEBUG
        if (lstrlenW(lpMessage) > 0)
        {
            WCHAR msg[1024] = { 0 };
            WCHAR* lpMsgBuf = NULL;

            if (lStatus == STATUS_SUCCESS)
            {
                FormatMessage(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    lCode,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    lpMsgBuf,
                    0, NULL);

                _snwprintf_s(msg, 1024,_TRUNCATE,
                            L"%s (%s)\n", lpMessage, lpMsgBuf);
            }
            else
            {
                _snwprintf_s(msg, 1024,_TRUNCATE, L"%s (%s)\n",
                            lpMessage, detour_error_code_to_string(lStatus));
            }

            DEBUGMSG(msg);

            if (lpMsgBuf != NULL)
            {
                LocalFree(lpMsgBuf);
            }
        }
#endif
        LastError = lpMessage;
    }
}

void detour_assert(_In_ BOOL bAssert, _In_ LPCWSTR lpMessageText)
{
    if (bAssert) {
        return;
    }

#ifdef _DEBUG
    DebugBreak();
#endif
    FatalAppExitW(0, lpMessageText);
}

LONG WINAPI DetourSetGlobalInclusiveACL(_In_ DWORD *dwThreadIdList,
                                        _In_ DWORD dwThreadCount)
{
/*
Description:

    Sets an inclusive global ACL based on the given thread ID list.
    
Parameters:
    - dwThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - dwThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    return detour_set_acl(detour_barrier_get_acl(), FALSE, dwThreadIdList, dwThreadCount);
}


BOOL detour_is_valid_handle(_In_  TRACED_HOOK_HANDLE pTracedHandle,
                            _Out_ PDETOUR_TRAMPOLINE   *pHandle)
{

/*
Description:

    A handle is considered to be valid, if the whole structure
    points to valid memory AND the signature is valid AND the
    hook is installed!

*/

    if (!IsValidPointer(pTracedHandle, sizeof(HOOK_TRACE_INFO))) {
        return FALSE;
    }

    if (pHandle != NULL) {
        *pHandle = pTracedHandle->Link;
    }

    return TRUE;
}

LONG detour_set_acl(_In_ HOOK_ACL *pAcl,
                    _In_ BOOL     bIsExclusive,
                    _In_ DWORD    *dwThreadIdList,
                    _In_ DWORD    dwThreadCount)
{
/*
Description:

    This method is used internally to provide a generic interface to
    either the global or local hook ACLs.
    
Parameters:
    - pAcl
        NULL if you want to set the global ACL.
        Any LOCAL_HOOK_INFO::LocalACL to set the hook specific ACL.

    - bIsExclusive
        TRUE if all listed thread shall be excluded from interception,
        FALSE otherwise

    - dwThreadIdList
        An array of thread IDs. If you specific zero for an entry in this array,
        it will be automatically replaced with the calling thread ID.

    - dwThreadCount
        The count of entries listed in the thread ID list. This value must not exceed
        MAX_ACE_COUNT! 
*/

    ULONG Index;

    DETOUR_ASSERT(IsValidPointer(pAcl, sizeof(HOOK_ACL)), L"barrier.cpp - IsValidPointer(InAcl, sizeof(HOOK_ACL))");

    if (dwThreadCount > MAX_ACE_COUNT) {
        return STATUS_INVALID_PARAMETER_2;
    }

    if (!IsValidPointer(dwThreadIdList, dwThreadCount * sizeof(ULONG))) {
        return STATUS_INVALID_PARAMETER_1;
    }

    for (Index = 0; Index < dwThreadCount; Index++)
    {
        if (dwThreadIdList[Index] == 0) {
            dwThreadIdList[Index] = GetCurrentThreadId();
        }
    }
    DWORD dwOld;
    if (VirtualProtect(pAcl, sizeof(HOOK_ACL), PAGE_READWRITE, &dwOld))
    {
        // set ACL...
        pAcl->IsExclusive = bIsExclusive;
        pAcl->Count = dwThreadCount;

        detour_copy_memory(pAcl->Entries, dwThreadIdList, dwThreadCount * sizeof(ULONG));

        DWORD dwOld2;
        VirtualProtect(pAcl, sizeof(HOOK_ACL), dwOld, &dwOld2);
    }
    else
    {
        return STATUS_ACCESS_DENIED;
    }

    return STATUS_SUCCESS;
}

HOOK_ACL *detour_barrier_get_acl()
{
    return &Unit.GlobalACL;
}

LONG DetourBarrierProcessAttach()
{
/*
Description:

    Will be called on DLL load and initializes all barrier structures.
*/

    detour_zero_memory(&Unit, sizeof(Unit));

    // globally accept all threads...
    Unit.GlobalACL.IsExclusive = TRUE;

    // allocate private heap
    detour_initialize_lock(&Unit.TLS.ThreadSafe);

    Unit.IsInitialized = AuxUlibInitialize() ? TRUE : FALSE;

    hCoreHookHeap = HeapCreate(0, 0, 0);

    return STATUS_SUCCESS;
}

BOOL TlsGetCurrentValue(_In_  THREAD_LOCAL_STORAGE *pTls,
                        _Outptr_ THREAD_RUNTIME_INFO  **OutValue)
{
/*
Description:

    Queries the THREAD_RUNTIME_INFO for the calling thread.
    The caller shall previously be added to the storage by
    using TlsAddCurrentThread().

Parameters:

    - pTls

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
        if (pTls->IdList[Index] == CurrentId)
        {
            *OutValue = &pTls->Entries[Index];

            return TRUE;
        }
    }

    return FALSE;
}
BOOL TlsAddCurrentThread(_In_ THREAD_LOCAL_STORAGE *pTls)
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
    - pTls

        The thread local storage to allocate from.

Returns:

    TRUE on success, FALSE otherwise.
*/

    ULONG CurrentId = GetCurrentThreadId();
    LONG Index = -1;
    LONG i;

    detour_acquire_lock(&pTls->ThreadSafe);

    // select Index AND check whether thread is already registered.
    for (i = 0; i < MAX_THREAD_COUNT; i++)
    {
        if ((pTls->IdList[i] == 0) && (Index == -1)) {
            Index = i;
        }

        DETOUR_ASSERT(pTls->IdList[i] != CurrentId, L"barrier.cpp - pTls->IdList[i] != CurrentId");
    }

    if (Index == -1)
    {
        detour_release_lock(&pTls->ThreadSafe);

        return FALSE;
    }

    pTls->IdList[Index] = CurrentId;
    detour_zero_memory(&pTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));

    detour_release_lock(&pTls->ThreadSafe);

    return TRUE;
}

void TlsRemoveCurrentThread(THREAD_LOCAL_STORAGE *InTls)
{
/*
Description:

    Removes the caller from the local storage. If the caller
    is already removed, the method will do nothing.

Parameters:

    - pTls

        The storage from which the caller should be removed.
*/

    DWORD CurrentId = GetCurrentThreadId();
    ULONG Index;

    detour_acquire_lock(&InTls->ThreadSafe);

    for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
    {
        if (InTls->IdList[Index] == CurrentId)
        {
            InTls->IdList[Index] = 0;

            detour_zero_memory(&InTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));
        }
    }

    detour_release_lock(&InTls->ThreadSafe);
}

void DetourBarrierProcessDetach()
{
/*
Description:

    Will be called on DLL unload.
*/

    ULONG Index;

    detour_delete_lock(&Unit.TLS.ThreadSafe);

    // release thread specific resources
    for (Index = 0; Index < MAX_THREAD_COUNT; Index++)
    {
        if (Unit.TLS.Entries[Index].Entries != NULL)
        {
            detour_free_memory(Unit.TLS.Entries[Index].Entries);
        }
    }

    detour_zero_memory(&Unit, sizeof(Unit));

    HeapDestroy(hCoreHookHeap);
}

void DetourBarrierThreadDetach()
{
/*
Description:

    Will be called on thread termination and cleans up the TLS.
*/

    PTHREAD_RUNTIME_INFO Info;

    if (TlsGetCurrentValue(&Unit.TLS, &Info))
    {
        if (Info->Entries != NULL)
        {
            detour_free_memory(Info->Entries);
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

    detour_initialize_lock(&GlobalHookLock);
}

void DetourCriticalFinalize()
{
/*
Description:

    Will be called in the DLL_PROCESS_DETACH event and just uninstalls
    all hooks. If it is possible also their memory is released. 
*/

    detour_delete_lock(&GlobalHookLock);
}

BOOL detour_is_loader_lock()
{
/*
Returns:

    TRUE if the current thread hols the OS loader lock, or the library was not initialized
    properly. In both cases a hook handler should not be executed!

    FALSE if it is safe to execute the hook handler.

*/

    BOOL bDetourIsLoaderLock = FALSE;

    return (
           !AuxUlibIsDLLSynchronizationHeld(&bDetourIsLoaderLock)
           || bDetourIsLoaderLock
           || !Unit.IsInitialized
           );
}

BOOL detour_acquire_self_protection()
{
/*
Description:

    To provide more convenience for writing the TDB, this self protection
    will disable ALL hooks for the current thread until detour_release_self_protection() 
    is called. This allows one to call any API during TDB initialization
    without being intercepted...

Returns:

    TRUE if the caller's runtime info has been locked down.

    FALSE if the caller's runtime info already has been locked down
    or is not available. The hook handler should not be executed in
    this case!

*/

    PTHREAD_RUNTIME_INFO Runtime = NULL;

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime) || Runtime->IsProtected) {
        return FALSE;
    }

    Runtime->IsProtected = TRUE;

    return TRUE;
}

void detour_release_self_protection()
{
/*
Description:

    Exists the TDB self protection. Refer to detour_acquire_self_protection() for more
    information.

    An assertion is raised if the caller has not owned the self protection.
*/

    PTHREAD_RUNTIME_INFO pRuntime = NULL;

    DETOUR_ASSERT(TlsGetCurrentValue(&Unit.TLS, &pRuntime) && pRuntime->IsProtected,
        L"barrier.cpp - TlsGetCurrentValue(&Unit.TLS, &Runtime) && Runtime->IsProtected");

    pRuntime->IsProtected = FALSE;
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

BOOL detour_is_thread_intercepted(_In_ HOOK_ACL *pLocalACL,
                                  _In_ DWORD    dwThreadId)
{
/*
Description:

    Please refer to DetourIsThreadIntercepted() for more information.

Returns:

    TRUE if the given thread is intercepted by the global AND local ACL,
    FALSE otherwise.
*/

    DWORD checkId;

    if (dwThreadId == 0)
    {
        checkId = GetCurrentThreadId();
    }
    else
    {
        checkId = dwThreadId;
    }

    if (ACLContains(&Unit.GlobalACL, checkId))
    {
        if (ACLContains(pLocalACL, checkId))
        {
            if (pLocalACL->IsExclusive) {
                return FALSE;
            }
        }
        else
        {
            if (!pLocalACL->IsExclusive) {
                return FALSE;
            }
        }

        return !Unit.GlobalACL.IsExclusive;
    }
    else
    {
        if (ACLContains(pLocalACL, checkId))
        {
            if (pLocalACL->IsExclusive) {
                return FALSE;
            }
        }
        else
        {
            if (!pLocalACL->IsExclusive) {
                return FALSE;
            }
        }

        return Unit.GlobalACL.IsExclusive;
    }
}

LONG WINAPI DetourBarrierGetCallback(_Outptr_ PVOID *ppCallback)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the callback initially passed to the related DetourInstallHook()
    call.

*/

    LONG NtStatus;
    PTHREAD_RUNTIME_INFO Runtime;

    if (!IsValidPointer(ppCallback, sizeof(PVOID)))
    {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid result storage specified.");
    }
    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) 
    {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }
    if (Runtime->Current != NULL) 
    {
        *ppCallback = Runtime->Callback;
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

LONG WINAPI DetourBarrierGetReturnAddress(_Outptr_ PVOID *ppReturnAddress)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the return address of the hook handler. This is usually the
    instruction behind the "CALL" which invoked the hook.

    The calling module determination is based on this method.

*/

    LONG NtStatus;
    PTHREAD_RUNTIME_INFO Runtime;

    if (!IsValidPointer(ppReturnAddress, sizeof(PVOID))) {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid result storage specified.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    if (Runtime->Current != NULL) {
        *ppReturnAddress = Runtime->Current->RetAddress;
    }
    else {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}


LONG WINAPI DetourBarrierGetAddressOfReturnAddress(_Outptr_ PVOID **pppAddressOfReturnAddress)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED. The method retrieves
    the address of the return address of the hook handler.
*/

    PTHREAD_RUNTIME_INFO Runtime;
    LONG NtStatus;

    if (pppAddressOfReturnAddress == NULL) {
        THROW(STATUS_INVALID_PARAMETER, L"Invalid storage specified.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }

    if (Runtime->Current != NULL) {
        *pppAddressOfReturnAddress = Runtime->Current->AddrOfRetAddr;
    }
    else {
        THROW(STATUS_NOT_SUPPORTED, L"The caller is not inside a hook handler.");
    }
    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG WINAPI DetourBarrierBeginStackTrace(_Outptr_ PVOID* ppBackup)
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

    LONG NtStatus;
    PTHREAD_RUNTIME_INFO Runtime;

    if (ppBackup == NULL) {
        THROW(STATUS_INVALID_PARAMETER, L"barrier.cpp - The given backup storage is invalid.");
    }

    if (!TlsGetCurrentValue(&Unit.TLS, &Runtime)) {
        THROW(STATUS_NOT_SUPPORTED, L"barrier.cpp - The caller is not inside a hook handler.");
    }

    if (Runtime->Current == NULL) {
        THROW(STATUS_NOT_SUPPORTED, L"barrier.cpp - The caller is not inside a hook handler.");
    }

    *ppBackup = *Runtime->Current->AddrOfRetAddr;
    *Runtime->Current->AddrOfRetAddr = Runtime->Current->RetAddress;

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG WINAPI DetourBarrierEndStackTrace(_In_ PVOID pBackup)
{
/*
Description:

    Is expected to be called inside a hook handler. Otherwise it
    will fail with STATUS_NOT_SUPPORTED.

    You have to pass the backup pointer obtained with
    DetourBarrierBeginStackTrace().
*/

    LONG NtStatus;
    PVOID *AddrOfRetAddr;

    if (!IsValidPointer(pBackup, 1)) {
        THROW(STATUS_INVALID_PARAMETER, L"barrier.cpp - The given stack backup pointer is invalid.");
    }

    FORCE(DetourBarrierGetAddressOfReturnAddress(&AddrOfRetAddr));

    *AddrOfRetAddr = pBackup;

    RETURN;

THROW_OUTRO:
FINALLY_OUTRO:
    return NtStatus;
}

LONG WINAPI DetourBarrierCallStackTrace(
    _Outptr_ PVOID *ppMethodArray,
    _In_ DWORD dwFramesToCapture,
    _Inout_ DWORD *pCapturedFramesCount)
{
/*
Description:

    Creates a call stack trace and translates all method entries
    back into their owning modules.

Parameters:

    - ppMethodArray

        An array receiving the methods on the call stack.

    - dwFramesToCapture

        The length of the method array.

    - pCapturedFramesCount

        The actual count of methods on the call stack. This will never
        be greater than 64.

Returns:

    STATUS_NOT_IMPLEMENTED

        Only supported since Windows XP.
*/
    
    LONG NtStatus;
    PVOID Backup = NULL;

    if (dwFramesToCapture > 64) {
        THROW(STATUS_INVALID_PARAMETER_2, L"barrier.cpp - At maximum 64 modules are supported.");
    }
    if (!IsValidPointer(ppMethodArray, dwFramesToCapture * sizeof(PVOID))) {
        THROW(STATUS_INVALID_PARAMETER_1, L"barrier.cpp - The given module buffer is invalid.");
    }

    if (!IsValidPointer(pCapturedFramesCount, sizeof(ULONG))) {
        THROW(STATUS_INVALID_PARAMETER_3, L"barrier.cpp - Invalid module count storage.");
    }

    
    FORCE(DetourBarrierBeginStackTrace(&Backup));
    
    if (CaptureStackBackTrace == NULL) {
        THROW(STATUS_NOT_IMPLEMENTED, L"barrier.cpp - This method requires Windows XP or later.");
    }

    *pCapturedFramesCount = CaptureStackBackTrace(1, 32, ppMethodArray, NULL);

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