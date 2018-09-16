#include "pch.h"
#include "detours.h"

bool detoured_test = false;

unsigned int OriginalFunction(unsigned int count) {
    return count + 1;
}
unsigned int DetourForOriginalFunction(unsigned int count) {
    detoured_test = true;

    return OriginalFunction(count);
}
bool HookTest()
{
    DetourBarrierProcessAttach();

    DetourCriticalInitialize();

    LONG callback = 0;
    TRACED_HOOK_HANDLE hookHandle = new HOOK_TRACE_INFO();

    DetourInstallHook((void*)OriginalFunction, (void*)DetourForOriginalFunction,
        &callback, hookHandle);

    DetourSetInclusiveACL(new ULONG(), 1, hookHandle);

    OriginalFunction(1);

    DetourUninstallHook(hookHandle);

    DetourBarrierProcessDetach();
    DetourCriticalFinalize();

    return detoured_test;
}
