#pragma once
/////////////////////////////////////////////////////////////////////////////
//
//  Trampoline Thread Barrier Functionality (barrier.h of detours.lib)
//
//

BOOL detour_is_loader_lock();

BOOL detour_acquire_self_protection();
void detour_release_self_protection();

void detour_sleep(_In_ DWORD milliSeconds);

/////////////////////////////////////////// trampoline thread barrier definitions
//

#define MAX_HOOK_COUNT              1024
#define MAX_ACE_COUNT               128
#define MAX_THREAD_COUNT            128
#define MAX_PASSTHRU_SIZE           1024 * 64

typedef struct _HOOK_ACL_
{
    ULONG                   Count;
    BOOL                    IsExclusive;
    ULONG                   Entries[MAX_ACE_COUNT];
} HOOK_ACL;

typedef struct _RUNTIME_INFO_
{
    // "true" if the current thread is within the related hook handler
    BOOL            IsExecuting;
    // the hook this information entry belongs to... This allows a per thread and hook storage!
    DWORD           HLSIdent;
    // the return address of the current thread's hook handler...
    void*           RetAddress;
    // the address of the return address of the current thread's hook handler...
    void**          AddrOfRetAddr;
} RUNTIME_INFO;

typedef struct _THREAD_RUNTIME_INFO_
{
    RUNTIME_INFO*        Entries;
    RUNTIME_INFO*        Current;
    void*                Callback;
    BOOL                 IsProtected;
} THREAD_RUNTIME_INFO, *PTHREAD_RUNTIME_INFO;

typedef struct _RTL_SPIN_LOCK_
{
    CRITICAL_SECTION         Lock;
    BOOL                     IsOwned;
} DETOUR_SPIN_LOCK;

typedef struct _THREAD_LOCAL_STORAGE_
{
    THREAD_RUNTIME_INFO      Entries[MAX_THREAD_COUNT];
    DWORD                    IdList[MAX_THREAD_COUNT];
    DETOUR_SPIN_LOCK         ThreadSafe;
} THREAD_LOCAL_STORAGE;

typedef struct _BARRIER_UNIT_
{
    HOOK_ACL                GlobalACL;
    BOOL                    IsInitialized;
    THREAD_LOCAL_STORAGE    TLS;
} BARRIER_UNIT;

static void detour_initialize_lock(_In_ DETOUR_SPIN_LOCK *pLock);

static void detour_delete_lock(_In_ DETOUR_SPIN_LOCK *pLock);

void detour_acquire_lock(_In_ DETOUR_SPIN_LOCK *pLock);

void detour_release_lock(_In_ DETOUR_SPIN_LOCK *pLock);

BOOL detour_is_thread_intercepted(_In_ HOOK_ACL *pLocalACL,
                                  _In_ DWORD    dwThreadId);

LONG detour_set_acl(_In_ HOOK_ACL *pAcl,
                    _In_ BOOL bIsExclusive,
                    _In_ DWORD *dwThreadIdList,
                    _In_ DWORD dwThreadCount);

HOOK_ACL* detour_barrier_get_acl();

extern BARRIER_UNIT         g_BarrierUnit;
extern DETOUR_SPIN_LOCK     g_HookLock;

//////////////////////////////////////////////// Exception handling code
//

VOID detour_assert(const char* pszMsg, LPCWSTR pszFile, ULONG nLine);

void detour_set_last_error(_In_ LONG lCode,
    _In_ LONG lStatus,
    _In_opt_ LPCWSTR lpMessage);

#ifndef NDEBUG
#define ASSERT(expr)           ASSERT_ALWAYS(expr)
#else
#define ASSERT(expr)
#endif

#define WIDE2(x) L ##x
#define WIDE1(x) WIDE2(x)
#define WFILE WIDE1(__FILE__)

#define ASSERT_ALWAYS(expression)   \
    do {                                                                 \
    if (!(expression)) {                                                 \
            detour_assert(#expression, WFILE, __LINE__);                 \
    }                                                                    \
    } while (0)


#define DETOUR_ASSERT(expr)         ASSERT(expr)
#define THROW(code, Msg)            { NtStatus = (code); detour_set_last_error(GetLastError(), NtStatus, Msg); goto THROW_OUTRO; }

#define DETOUR_SUCCESS(ntstatus)    SUCCEEDED(ntstatus)

#define RETURN                      { detour_set_last_error(STATUS_SUCCESS, STATUS_SUCCESS, L""); NtStatus = STATUS_SUCCESS; goto FINALLY_OUTRO; }
#define FORCE(expr)                 { if(!DETOUR_SUCCESS(NtStatus = (expr))) goto THROW_OUTRO; }


//////////////////////////////////////////////// Memory validation code
//

#define IsValidPointer              detour_is_valid_pointer

BOOL detour_is_valid_pointer(_In_opt_ CONST VOID *Pointer,
                             _In_     UINT_PTR    Size);

/////////////////////////////////////////////////////////////
//
//  Thread Local Storage functions re-implemented to avoid
//  possible problems with native TLS functions when
//  detouring processes like explorer.exe
//

BOOL TlsGetCurrentValue(_In_  THREAD_LOCAL_STORAGE *pTls,
                        _Outptr_ THREAD_RUNTIME_INFO  **OutValue);

BOOL TlsAddCurrentThread(_In_ THREAD_LOCAL_STORAGE *pTls);


////////////////////////////////////////////////// Memory management functions

void  detour_free_memory(void *pMemory);

void* detour_allocate_memory(_In_ BOOL   bZeroMemory,
                             _In_ size_t size);


//////////////////////////////////////////////////////// NTSTATUS definitions

#define STATUS_SUCCESS                   0
#define STATUS_NOT_SUPPORTED             ((LONG)0xC00000BBL)
#define STATUS_INTERNAL_ERROR            ((LONG)0xC00000E5L)
#define STATUS_PROCEDURE_NOT_FOUND       ((LONG)0xC000007AL)
#define STATUS_NOINTERFACE               ((LONG)0xC00002B9L)
#define STATUS_INFO_LENGTH_MISMATCH      ((LONG)0xC0000004L)
#define STATUS_BUFFER_TOO_SMALL          ((LONG)0xC0000023L)
#define STATUS_INSUFFICIENT_RESOURCES    ((LONG)0xC000009AL)
#define STATUS_UNHANDLED_EXCEPTION       ((LONG)0xC0000144L)
#define STATUS_NOT_FOUND                 ((LONG)0xC0000225L)
#define STATUS_NOT_IMPLEMENTED           ((LONG)0xC0000002L)
#define STATUS_ACCESS_DENIED             ((LONG)0xC0000022L)
#define STATUS_ALREADY_REGISTERED        ((LONG)0xC0000718L)
#define STATUS_WOW_ASSERTION             ((LONG)0xC0009898L)
#define STATUS_BUFFER_OVERFLOW           ((LONG)0x80000005L)
#define STATUS_INVALID_PARAMETER_1       ((LONG)0xC00000EFL)
#define STATUS_INVALID_PARAMETER_2       ((LONG)0xC00000F0L)
#define STATUS_INVALID_PARAMETER_3       ((LONG)0xC00000F1L)
#define STATUS_INVALID_PARAMETER_4       ((LONG)0xC00000F2L)
#define STATUS_INVALID_PARAMETER_5       ((LONG)0xC00000F3L)
#define STATUS_INVALID_PARAMETER_6       ((LONG)0xC00000F4L)
#define STATUS_INVALID_PARAMETER_7       ((LONG)0xC00000F5L)
#define STATUS_INVALID_PARAMETER_8       ((LONG)0xC00000F6L)
