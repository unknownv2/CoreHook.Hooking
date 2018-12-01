cmake_minimum_required(VERSION 3.2)

project(detours)
set(TARGET detours)

enable_language(ASM_MASM)
   if (CMAKE_ASM_MASM_COMPILER_WORKS)
        if (NOT CMAKE_CL_64)
            set(CMAKE_ASM_MASM_FLAGS ${CMAKE_ASM_MASM_FLAGS} /safeseh)
        endif()
        set_property(SOURCE trampolinex64.asm PROPERTY LANGUAGE ASM_MASM)
    else()
        message(WARNING "Could not find working MASM assebler\n${ASM_FAILURE_MSG}")
    endif()
set(SOURCE_FILES 
    barrier.cpp
    creatwth.cpp
    detours.cpp
    disasm.cpp
    disolarm.cpp
    disolarm64.cpp
    disolia64.cpp
    disolx64.cpp
    disolx86.cpp
    image.cpp
    modules.cpp
    )

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
add_library(detours STATIC ${SOURCE_FILES})
install(TARGETS detours DESTINATION ${COREHOOK_INSTALL_BIN_DIR})