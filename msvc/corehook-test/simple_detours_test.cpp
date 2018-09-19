#include "pch.h"
#include "simple_detours.h"

bool detoured_test = false;

// disable optimizations for test functions so they aren't inlined
#pragma optimize( "", off )

unsigned int OriginalFunction(unsigned int count) {
    return count + 1;
}
unsigned int OriginalFunction_Detour(unsigned int count) {
    detoured_test = true;

    return OriginalFunction(count);
}

#pragma optimize( "", on )
bool DetoursSimpleTest1() {
    auto callback = std::make_unique<LONG>();
    auto hookHandle = std::make_unique<HOOK_TRACE_INFO>();

    auto threadIdList = std::make_unique<ULONG>();
    const LONG threadCount = 1;

    LONG error = DetourInstallHook(
        OriginalFunction,
        OriginalFunction_Detour,
        callback.get(),
        hookHandle.get());

    if (error == NO_ERROR) {
        DetourSetInclusiveACL(
            threadIdList.get(),
            threadCount,
            hookHandle.get());

        OriginalFunction(1);

        DetourUninstallHook(hookHandle.get());
    }

    return detoured_test;
}