cmake_minimum_required(VERSION 3.2)
project(corehook)

add_subdirectory(../src)
set(SOURCE_FILES main.cpp)

add_executable(corehook ${SOURCE_FILES})
target_link_libraries(corehook division)
install(TARGETS corehook DESTINATION ${DIVISIBLE_INSTALL_BIN_DIR})