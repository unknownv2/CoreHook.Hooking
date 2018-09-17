#include "pch.h"
#include "detours.h"

bool detoured_test = false;
#pragma optimize( "", off )
unsigned int OriginalFunction2(unsigned int count) {
    int testValue1 = count * 4;
    int testValue2 = count * 10;

    return (testValue2 *testValue1) + count + 1;
}
unsigned int OriginalFunction(unsigned int count) {
    void * mem = malloc(0x100);
    return (ULONG_PTR)mem + count + 1;
}
unsigned int DetourForOriginalFunction(unsigned int count) {
    detoured_test = true;

    return OriginalFunction(count);
}
#pragma optimize( "", on )

bool HookTest()
{
    DetourBarrierProcessAttach();

    DetourCriticalInitialize();

    LONG callback = 0;
    TRACED_HOOK_HANDLE hookHandle = new HOOK_TRACE_INFO();

   LONG error = DetourInstallHook((void*)OriginalFunction, (void*)DetourForOriginalFunction,
        &callback, hookHandle);
   if (error == NO_ERROR) {
       DetourSetInclusiveACL(new ULONG(), 1, hookHandle);

       OriginalFunction(1);

       DetourUninstallHook(hookHandle);

       DetourBarrierProcessDetach();
       DetourCriticalFinalize();
   }
   return detoured_test;
}
