#pragma once
#include "detours.h"
#include <memory>

class Detours
{
private:

public:
    bool DetourUserFunction();
    HANDLE DetourExportedFunction(LPCWSTR file, LPCWSTR* outFile);

};

class DetoursTest : public testing::Test {


protected:
    virtual void SetUp() {
        DetourBarrierProcessAttach();
        DetourCriticalInitialize();
    }
    virtual void TearDown() {
        DetourBarrierProcessDetach();
        DetourCriticalFinalize();
    }

    Detours _dt;
};



//bool DetoursSimpleTest1();
