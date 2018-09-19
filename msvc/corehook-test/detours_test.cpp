#include "pch.h"
#include "simple_detours.h"

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

TEST_F(DetoursTest, SimpleDetoursTest1) {
    EXPECT_EQ(true, DetoursSimpleTest1());
}
