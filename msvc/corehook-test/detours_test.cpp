#include "pch.h"
#include "simple_detours.h"

// Detour a user-created function by setting a boolean value from false to true in our _Detour method
TEST_F(DetoursTest, SimpleDetoursUserFunctionTest) { 
    EXPECT_EQ(true, _dt.DetourUserFunction());
}

// Detour CreateFileW with a non-existent file name
TEST_F(DetoursTest, SimpleDetoursExportedFunctionTest) {
    const auto fileName = L"File.txt";
    LPCWSTR fileNamePtr = NULL;

    EXPECT_EQ(NO_ERROR, _dt.DetourExportedFunction(fileName, &fileNamePtr));

    EXPECT_EQ(fileName, fileNamePtr);
}

// Call the original function directly, skipping the detour function we set 
TEST_F(DetoursTest, ShouldBypassDetourFunctionTest) {
    EXPECT_EQ(0x12345678, _dt.ShouldBypassDetourFunction());
}

// Attempt to find a non existent function as part of an existing module
TEST_F(DetoursTest, ShouldFailToFindFunctionTest) {
    EXPECT_EQ(nullptr, _dt.FindFunction("kernel32.dll", "AFunctionThatDoesNotExist??"));
}

// Attempt to find a non existent function as part of an non existing module
TEST_F(DetoursTest, ShouldFailToFindModuleAndFunctionTest) {
    EXPECT_EQ(nullptr, _dt.FindFunction("kernelmoduledoesnotexist.dll", "AFunctionThatDoesNotExist??"));
}

// Attempt to find a public API exported function as part of an existing module,
// so the result should not be a NULL pointer
TEST_F(DetoursTest, ShouldFindFunctionTest) {
    EXPECT_NE(nullptr, _dt.FindFunction("kernel32.dll", "SleepEx"));
}

// FindFunction should return NULL if one of parameters is incorrect 
TEST_F(DetoursTest, FindFunctionNullTest) {
    EXPECT_EQ(nullptr, _dt.FindFunction("kernel32.dll", nullptr));
    EXPECT_EQ(nullptr, _dt.FindFunction(nullptr, "SleepEx"));
    EXPECT_EQ(nullptr, _dt.FindFunction(nullptr, nullptr));
}

TEST_F(DetoursTest, InstallInvalidHookParameterTest) {
    LONG callback = 0;
    HOOK_TRACE_INFO hookHandle = { 0 };
    void(*testFunction)(int) = [](int i) { (VOID)i; };

    EXPECT_NE(NO_ERROR, DetourInstallHook(nullptr, nullptr, nullptr, nullptr));
    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, nullptr, nullptr, nullptr));
    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, testFunction, nullptr, nullptr));
    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, testFunction, &callback, nullptr));

    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, nullptr, &callback, nullptr));
    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, nullptr, &callback, &hookHandle));

    EXPECT_NE(NO_ERROR, DetourInstallHook(CreateFileW, nullptr, nullptr, &hookHandle));

    EXPECT_NE(NO_ERROR, DetourInstallHook(nullptr, nullptr, nullptr, &hookHandle));
}

// MoveFile should return false with bad parameters but we detour it
// and return a non-zero value and verify that 
TEST_F(DetoursTest, DetourExportedFunctionWithUserFunctionTest) {
    EXPECT_EQ(FALSE, MoveFile(nullptr, nullptr));

    EXPECT_NE(FALSE, _dt.DetourMoveFileWithUserFunction());
}