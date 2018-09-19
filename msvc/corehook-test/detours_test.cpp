#include "pch.h"
#include "simple_detours.h"

// Detour a user-created function by setting a boolean value from false to true in our _Detour method
TEST_F(DetoursTest, SimpleDetoursTest1) {
    EXPECT_EQ(true, DetoursSimpleTest1());
}

// Detour CreateFileW with a non-existent file name
TEST_F(DetoursTest, SimpleDetoursTest2) {
    Detours dt;

    auto fileName = L"File.txt";

    EXPECT_EQ(INVALID_HANDLE_VALUE, dt.DetoursSimpleTest2(fileName));

    EXPECT_EQ(fileName, dt.FileName());

    ASSERT_STREQ(fileName, dt.FileName());
}