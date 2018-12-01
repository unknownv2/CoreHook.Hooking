cmake_minimum_required(VERSION 3.2)

set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR})

set(COREHOOK_INSTALL_INCLUDE_DIR ${PROJECT_SOURCE_DIR})
set(COREHOOK_INSTALL_BIN_DIR ${CMAKE_CURRENT_BINARY_DIR}/bin)
set(COREHOOK_INSTALL_LIB_DIR ${CMAKE_CURRENT_BINARY_DIR}/lib)

include_directories(${COREHOOK_INSTALL_INCLUDE_DIR})

project(corehook)
set(TARGET detours)

enable_language(ASM_MASM)
set(SOURCE_ASM
    src/trampolinex64.asm
    )

set(SOURCE_FILES 
    src/barrier.cpp
    src/creatwth.cpp
    src/detours.cpp
    src/disasm.cpp
    src/disolarm.cpp
    src/disolarm64.cpp
    src/disolia64.cpp
    src/disolx64.cpp
    src/disolx86.cpp
    src/image.cpp
    src/modules.cpp
    )

set(COREHOOK_SOURCES
    dll/corehook/corehook.cpp
    )

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    src
    )

add_library(detours STATIC ${SOURCE_FILES} ${SOURCE_ASM})

add_library(corehook SHARED ${COREHOOK_SOURCES})
target_link_libraries(corehook detours aux_ulib)

if("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "Win32")
    set_target_properties(corehook PROPERTIES OUTPUT_NAME corehook32)
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "x64")
    set_target_properties(corehook PROPERTIES OUTPUT_NAME corehook64)
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "ARM")
    set_target_properties(corehook PROPERTIES OUTPUT_NAME corehook32)
elseif("${CMAKE_VS_PLATFORM_NAME}" STREQUAL "ARM64")
    set_target_properties(corehook PROPERTIES OUTPUT_NAME corehook64)    
endif()

install(TARGETS detours DESTINATION ${COREHOOK_INSTALL_BIN_DIR})

