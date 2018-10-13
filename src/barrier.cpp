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

// Allocate the Heap handle at DLL entry point
HANDLE g_hCoreHookHeap = NULL;

BARRIER_UNIT g_BarrierUnit;

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
    void *result = HeapAlloc(g_hCoreHookHeap, 0, size);

    if (bZeroMemory && (result != NULL)) {
        detour_zero_memory(result, size);
    }

    return result;
}

void detour_free_memory(void * pMemory)
{
    DETOUR_ASSERT(pMemory != NULL);

    HeapFree(g_hCoreHookHeap, 0, pMemory);
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

static void detour_initialize_lock(_In_ DETOUR_SPIN_LOCK *pLock)
{
    detour_zero_memory(pLock, sizeof(DETOUR_SPIN_LOCK));

    InitializeCriticalSection(&pLock->Lock);
}

void detour_delete_lock(_In_ DETOUR_SPIN_LOCK *pLock)
{
    DETOUR_ASSERT(!pLock->IsOwned);

    DeleteCriticalSection(&pLock->Lock);
}

void detour_acquire_lock(_In_ DETOUR_SPIN_LOCK *pLock)
{
    EnterCriticalSection(&pLock->Lock);

    DETOUR_ASSERT(!pLock->IsOwned);

    pLock->IsOwned = TRUE;
}

void detour_release_lock(_In_ DETOUR_SPIN_LOCK *pLock)
{
    DETOUR_ASSERT(pLock->IsOwned);

    pLock->IsOwned = FALSE;

    LeaveCriticalSection(&pLock->Lock);
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

VOID detour_assert(PCSTR pszMsg, LPCWSTR pszFile, ULONG nLine)
{
    DETOUR_TRACE(("DETOUR_ASSERT(%s) failed in %ws, line %d.\n", pszMsg, pszFile, nLine));
#ifdef _DEBUG
    DETOUR_BREAK();
#endif
    FatalAppExit(0, pszFile);
}

LONG WINAPI DetourSetGlobalInclusiveACL(_In_ DWORD *dwThreadIdList,
                                        _In_ DWORD dwThreadCount)
{
    return detour_set_acl(detour_barrier_get_acl(), FALSE, dwThreadIdList, dwThreadCount);
}


BOOL detour_is_valid_handle(_In_  TRACED_HOOK_HANDLE pTracedHandle,
                            _Out_ PDETOUR_TRAMPOLINE *pHandle)
{
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
    ASSERT(IsValidPointer(pAcl, sizeof(HOOK_ACL)));

    if (dwThreadCount > MAX_ACE_COUNT) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!IsValidPointer(dwThreadIdList, dwThreadCount * sizeof(ULONG))) {
        return ERROR_INVALID_PARAMETER;
    }

    for (DWORD index = 0; index < dwThreadCount; index++)
    {
        if (dwThreadIdList[index] == 0) {
            dwThreadIdList[index] = GetCurrentThreadId();
        }
    }

    DWORD dwOld;
    if (VirtualProtect(pAcl, sizeof(HOOK_ACL), PAGE_READWRITE, &dwOld))
    {
        // Set ACL.
        pAcl->IsExclusive = bIsExclusive;
        pAcl->Count = dwThreadCount;

        detour_copy_memory(pAcl->Entries, dwThreadIdList, dwThreadCount * sizeof(ULONG));

        DWORD dwOld2;
        VirtualProtect(pAcl, sizeof(HOOK_ACL), dwOld, &dwOld2);
    }
    else
    {
        return ERROR_ACCESS_DENIED;
    }

    return NO_ERROR;
}

HOOK_ACL *detour_barrier_get_acl()
{
    return &g_BarrierUnit.GlobalACL;
}

BOOL TlsGetCurrentValue(_In_  THREAD_LOCAL_STORAGE *pTls,
                        _Outptr_ THREAD_RUNTIME_INFO  **OutValue)
{
    DWORD dwThreadId = GetCurrentThreadId();

    for (auto index = 0; index < MAX_THREAD_COUNT; index++)
    {
        if (pTls->IdList[index] == dwThreadId)
        {
            *OutValue = &pTls->Entries[index];

            return TRUE;
        }
    }

    return FALSE;
}
BOOL TlsAddCurrentThread(_In_ THREAD_LOCAL_STORAGE *pTls)
{
    ULONG dwThreadId = GetCurrentThreadId();
    LONG Index = -1;
    LONG i;

    detour_acquire_lock(&pTls->ThreadSafe);

    // Select the index and check whether thread is already registered.
    for (i = 0; i < MAX_THREAD_COUNT; i++)
    {
        if ((pTls->IdList[i] == 0) && (Index == -1)) {
            Index = i;
        }

        DETOUR_ASSERT(pTls->IdList[i] != dwThreadId);
    }

    if (Index == -1)
    {
        detour_release_lock(&pTls->ThreadSafe);

        return FALSE;
    }

    pTls->IdList[Index] = dwThreadId;

    detour_zero_memory(&pTls->Entries[Index], sizeof(THREAD_RUNTIME_INFO));

    detour_release_lock(&pTls->ThreadSafe);

    return TRUE;
}

static void TlsRemoveCurrentThread(_In_ THREAD_LOCAL_STORAGE *pTls)
{
    DWORD dwThreadId = GetCurrentThreadId();

    detour_acquire_lock(&pTls->ThreadSafe);

    for (auto index = 0; index < MAX_THREAD_COUNT; index++)
    {
        if (pTls->IdList[index] == dwThreadId)
        {
            pTls->IdList[index] = 0;

            detour_zero_memory(&pTls->Entries[index], sizeof(THREAD_RUNTIME_INFO));
        }
    }

    detour_release_lock(&pTls->ThreadSafe);
}

LONG WINAPI DetourBarrierProcessAttach()
{
    detour_zero_memory(&g_BarrierUnit, sizeof(g_BarrierUnit));

    // Globally accept all threads.
    g_BarrierUnit.GlobalACL.IsExclusive = TRUE;

    // Allocate private heap.
    detour_initialize_lock(&g_BarrierUnit.TLS.ThreadSafe);

    g_BarrierUnit.IsInitialized = AuxUlibInitialize() ? TRUE : FALSE;

    g_hCoreHookHeap = HeapCreate(0, 0, 0);

    return NO_ERROR;
}

void WINAPI DetourBarrierProcessDetach()
{
    detour_delete_lock(&g_BarrierUnit.TLS.ThreadSafe);

    // Release thread specific resources.
    for (auto index = 0; index < MAX_THREAD_COUNT; index++)
    {
        if (g_BarrierUnit.TLS.Entries[index].Entries != NULL)
        {
            detour_free_memory(g_BarrierUnit.TLS.Entries[index].Entries);
        }
    }

    detour_zero_memory(&g_BarrierUnit, sizeof(g_BarrierUnit));

    HeapDestroy(g_hCoreHookHeap);
}

void WINAPI DetourBarrierThreadDetach()
{
    PTHREAD_RUNTIME_INFO pThreadRuntime;

    if (TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime))
    {
        if (pThreadRuntime->Entries != NULL)
        {
            detour_free_memory(pThreadRuntime->Entries);
        }

        pThreadRuntime->Entries = NULL;
    }

    TlsRemoveCurrentThread(&g_BarrierUnit.TLS);
}

DETOUR_SPIN_LOCK g_HookLock;

void WINAPI DetourCriticalInitialize()
{
    detour_initialize_lock(&g_HookLock);
}

void WINAPI DetourCriticalFinalize()
{
    detour_delete_lock(&g_HookLock);
}

BOOL detour_is_loader_lock()
{
    BOOL bDetourIsLoaderLock = FALSE;

    return (
           !AuxUlibIsDLLSynchronizationHeld(&bDetourIsLoaderLock)
           || bDetourIsLoaderLock
           || !g_BarrierUnit.IsInitialized
           );
}

BOOL detour_acquire_self_protection()
{
    PTHREAD_RUNTIME_INFO pThreadRuntimeInfo = NULL;

    if (!TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntimeInfo) || pThreadRuntimeInfo->IsProtected) {
        return FALSE;
    }

    pThreadRuntimeInfo->IsProtected = TRUE;

    return TRUE;
}

void detour_release_self_protection()
{
    PTHREAD_RUNTIME_INFO pThreadRuntime = NULL;

    DETOUR_ASSERT(TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime) && pThreadRuntime->IsProtected);

    pThreadRuntime->IsProtected = FALSE;
}

static BOOL detour_acl_contains(_In_ HOOK_ACL *pACL,
                                _In_ ULONG dwAcl)
{
    for (ULONG index = 0; index < pACL->Count; index++) {
        if (pACL->Entries[index] == dwAcl) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOL detour_is_thread_intercepted(_In_ HOOK_ACL *pLocalACL,
                                  _In_ DWORD    dwThreadId)
{
    DWORD checkId;

    if (dwThreadId == 0)
    {
        checkId = GetCurrentThreadId();
    }
    else
    {
        checkId = dwThreadId;
    }

    if (detour_acl_contains(&g_BarrierUnit.GlobalACL, checkId))
    {
        if (detour_acl_contains(pLocalACL, checkId))
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

        return !g_BarrierUnit.GlobalACL.IsExclusive;
    }
    else
    {
        if (detour_acl_contains(pLocalACL, checkId))
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

        return g_BarrierUnit.GlobalACL.IsExclusive;
    }
}

LONG WINAPI DetourBarrierGetCallback(_Outptr_ PVOID *ppCallback)
{
    PTHREAD_RUNTIME_INFO pThreadRuntime;

    if (!IsValidPointer(ppCallback, sizeof(PVOID))){
        return ERROR_INVALID_PARAMETER;
    }
    if (!TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime)) {
        return ERROR_NOT_SUPPORTED;
    }
    if (pThreadRuntime->Current != NULL){
        *ppCallback = pThreadRuntime->Callback;
    }
    else { 
        return ERROR_NOT_SUPPORTED;
    }

    return NO_ERROR;
}

LONG WINAPI DetourBarrierGetReturnAddress(_Outptr_ PVOID *ppReturnAddress)
{
    PTHREAD_RUNTIME_INFO pThreadRuntime;

    if (!IsValidPointer(ppReturnAddress, sizeof(PVOID))) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime)) {
        return ERROR_NOT_SUPPORTED;
    }

    if (pThreadRuntime->Current != NULL) {
        *ppReturnAddress = pThreadRuntime->Current->RetAddress;
    }
    else {
        return ERROR_NOT_SUPPORTED;
    }

    return NO_ERROR;
}


LONG WINAPI DetourBarrierGetAddressOfReturnAddress(_Outptr_ PVOID **pppAddressOfReturnAddress)
{
    PTHREAD_RUNTIME_INFO pThreadRuntime;

    if (pppAddressOfReturnAddress == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime)) {
        return ERROR_NOT_SUPPORTED;
    }

    if (pThreadRuntime->Current != NULL) {
        *pppAddressOfReturnAddress = pThreadRuntime->Current->AddrOfRetAddr;
    }
    else {
        return ERROR_NOT_SUPPORTED;
    }
    return NO_ERROR;
}

LONG WINAPI DetourBarrierBeginStackTrace(_Outptr_ PVOID* ppBackup)
{
    PTHREAD_RUNTIME_INFO pThreadRuntime;

    if (ppBackup == NULL) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!TlsGetCurrentValue(&g_BarrierUnit.TLS, &pThreadRuntime)) {
        return ERROR_NOT_SUPPORTED;
    }

    if (pThreadRuntime->Current == NULL) {
        return ERROR_NOT_SUPPORTED;
    }

    *ppBackup = *pThreadRuntime->Current->AddrOfRetAddr;
    *pThreadRuntime->Current->AddrOfRetAddr = pThreadRuntime->Current->RetAddress;

    return ERROR_SUCCESS;
}

LONG WINAPI DetourBarrierEndStackTrace(_In_ PVOID pBackup)
{
    PVOID *AddrOfRetAddr;

    if (!IsValidPointer(pBackup, 1)) {
        return ERROR_INVALID_PARAMETER;
    }

    LONG status = DetourBarrierGetAddressOfReturnAddress(&AddrOfRetAddr);

    *AddrOfRetAddr = pBackup;

    return status;
}

LONG WINAPI DetourBarrierCallStackTrace(_Outptr_ PVOID *ppMethodArray,
                                        _In_ DWORD dwFramesToCapture,
                                        _Inout_ DWORD *pCapturedFramesCount)
{
    PVOID Backup = NULL;

    if (dwFramesToCapture > 64) {
        return ERROR_INVALID_PARAMETER;
    }
    if (!IsValidPointer(ppMethodArray, dwFramesToCapture * sizeof(PVOID))) {
        return ERROR_INVALID_PARAMETER;
    }

    if (!IsValidPointer(pCapturedFramesCount, sizeof(ULONG))) {
        return ERROR_INVALID_PARAMETER;
    }

    auto status = DetourBarrierBeginStackTrace(&Backup);
    
    if (CaptureStackBackTrace == NULL) {
        return ERROR_INVALID_FUNCTION;
    }

    *pCapturedFramesCount = CaptureStackBackTrace(1, 32, ppMethodArray, NULL);

    if (Backup != NULL) {
        DetourBarrierEndStackTrace(Backup);
    }
    return status;
}