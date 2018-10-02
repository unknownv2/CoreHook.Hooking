#pragma once

BOOL detour_is_loader_lock();

BOOL detour_acquire_self_protection();
void detour_release_self_protection();



////////////////////////////////////////////////// Memory management functions

void  detour_free_memory(void *pMemory);

void* detour_allocate_memory(_In_ BOOL   bZeroMemory,
    _In_ size_t size);

void detour_copy_memory(_Out_writes_bytes_all_(Size) PVOID  Dest,
    _In_reads_bytes_(Size)       PVOID  Src,
    _In_                         size_t Size);

void detour_zero_memory(_Out_writes_bytes_all_(Size) PVOID Dest,
    _In_                         size_t Size);

//////////////////////////////////////////////////////// NTSTATUS definitions


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

