#include <windows.h>
#include "detours.h"

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        DetourBarrierProcessAttach();

        DetourCriticalInitialize();
    }
    else if (dwReason == DLL_THREAD_ATTACH) {
        DetourBarrierThreadDetach();
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourCriticalFinalize();
        
        DetourBarrierProcessDetach();
    }
    return TRUE;
}