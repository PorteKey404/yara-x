cmake_minimum_required(VERSION 3.31)
project(aot VERSION 0.1 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)

set(EXEC_NAME "aot")
set(EXEC_NAME_TEST "EXECUTABLE_TEST")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "../bin")
file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.c")

add_executable(${EXEC_NAME} ${SOURCES})

target_compile_options(${EXEC_NAME} PRIVATE -Wall -Wextra -fdiagnostics-color=always -g)

target_include_directories(${EXEC_NAME} PRIVATE "../capi/include/")
target_link_directories(${EXEC_NAME} PRIVATE ../target/release/)
target_link_libraries(${EXEC_NAME} PRIVATE
    yara_x_capi
    Threads::Threads
    ${CMAKE_DL_LIBS}
    m util rt gcc_s pthread dl c
)
