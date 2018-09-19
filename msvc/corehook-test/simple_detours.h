#pragma once
#include "detours.h"
#include <memory>

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
};

class Detours
{
private:
    CONST WCHAR* _fileName;
public:
    HANDLE DetoursSimpleTest2(LPCWSTR file);
    LPCWSTR FileName() { return _fileName; }
};

bool DetoursSimpleTest1();
