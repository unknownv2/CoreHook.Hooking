#pragma once
#include "detours.h"
#include <memory>

class Detours {

public:
    bool DetourUserFunction();
    LONG DetourExportedFunction(LPCWSTR file, LPCWSTR *outFile);
    int ShouldBypassDetourFunction();
    PVOID FindFunction(_In_ LPCSTR pszModule, _In_ LPCSTR pszFunction);
    LONG DetourMoveFileWithUserFunction();
    LONG DetourInstallDetourFunction();
};

class DetoursTest : public testing::Test {

protected:
    void SetUp() override
    {
        DetourBarrierProcessAttach();
        DetourCriticalInitialize();
    }

    void TearDown() override
    {
        DetourBarrierProcessDetach();
        DetourCriticalFinalize();
    }

    Detours _dt;
};
