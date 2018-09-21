#include "pch.h"
#include "simple_detours.h"

// Detour a user-created function by setting a boolean value from false to true in our _Detour method
TEST_F(DetoursTest, SimpleDetoursUserFunctionTest) { 
    EXPECT_EQ(true, _dt.DetourUserFunction());
}

// Detour CreateFileW with a non-existent file name
TEST_F(DetoursTest, SimpleDetoursExportedFunctionTest) {
    auto fileName = L"File.txt";
    LPCWSTR fileNamePtr = NULL;

    EXPECT_EQ(INVALID_HANDLE_VALUE, _dt.DetourExportedFunction(fileName, &fileNamePtr));

    EXPECT_EQ(fileName, fileNamePtr);

    ASSERT_STREQ(fileName, fileNamePtr);
}