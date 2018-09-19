#pragma once
#include "detours.h"
#include <memory>

class Detours
{
private:

public:
    bool DetoursSimpleTest1();
    HANDLE DetoursSimpleTest2(LPCWSTR file, LPCWSTR* outFile);

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
