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

    EXPECT_EQ(_dt.DetourExportedFunction(fileName, &fileNamePtr), NO_ERROR);

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