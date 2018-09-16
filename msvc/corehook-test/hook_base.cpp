#include "pch.h"
#include "detours.h"

bool detoured_test = false;

unsigned int TestDetourB(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e)
{
    return seconds + 1;
}
unsigned int TestDetourA(unsigned int seconds, unsigned int a, unsigned int b, unsigned int c, unsigned int d, unsigned int e, unsigned int f, unsigned int g, unsigned int h)
{
    detoured_test = true;
    return TestDetourB(seconds + 2, a, b, c, d, e);
}
bool HookTest()
{
    LhBarrierProcessAttach();

    LhCriticalInitialize();

    LONG selfHandle = 0;
    TRACED_HOOK_HANDLE outHandle = new HOOK_TRACE_INFO();

    LhInstallHook((void*)TestDetourB, (void*)TestDetourA, &selfHandle, outHandle);

    LhSetInclusiveACL(new ULONG(), 1, outHandle);

    TestDetourB(1, 2, 3, 4, 5, 6);

    LhBarrierProcessDetach();
    LhCriticalFinalize();

    return detoured_test;
}
