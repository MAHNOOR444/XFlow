cmake_minimum_required(VERSION 3.20)
project(xflow_assignment VERSION 1.0.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler warnings and definitions
if(MSVC)
    add_compile_options(/W4 /EHsc)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -pedantic)
endif()

# Include directories
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite3
)

# -------------------------------------------------------------
# PCAP & Platform Dependencies
# -------------------------------------------------------------
if(WIN32)
    message(STATUS "Configuring for Windows...")
    set(PCAP_INCLUDE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/npcap-sdk/Include")
    set(PCAP_LIBRARY "${CMAKE_CURRENT_SOURCE_DIR}/third_party/npcap-sdk/Lib/x64/wpcap.lib")
    include_directories(${PCAP_INCLUDE_DIR})
    set(PLATFORM_LIBS ${PCAP_LIBRARY} ws2_32)
else()
    message(STATUS "Configuring for Linux/Unix...")
    find_library(PCAP_LIB NAMES pcap REQUIRED)
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h PATH_SUFFIXES pcap REQUIRED)
    include_directories(${PCAP_INCLUDE_DIR})
    set(PLATFORM_LIBS ${PCAP_LIB} pthread dl)
endif()

# -------------------------------------------------------------
# SQLite3 Target
# -------------------------------------------------------------
add_library(sqlite3_static STATIC
    third_party/sqlite3/sqlite3.c
)
target_include_directories(sqlite3_static PUBLIC third_party/sqlite3)
if(NOT WIN32)
    target_link_libraries(sqlite3_static PRIVATE pthread dl)
endif()

# -------------------------------------------------------------
# Core Library
# -------------------------------------------------------------
add_library(xflow_core STATIC
    src/sip_parser.cpp
    src/checksum.cpp
    src/pcap_processor.cpp
    src/database_manager.cpp
    src/network.cpp
)
target_include_directories(xflow_core PUBLIC 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party/sqlite3
)
target_link_libraries(xflow_core PUBLIC 
    sqlite3_static
    ${PLATFORM_LIBS}
)

# -------------------------------------------------------------
# Main Executables
# -------------------------------------------------------------

# Standalone PCAP Processor (Task 1)
add_executable(xflow_processor src/main.cpp)
target_link_libraries(xflow_processor PRIVATE xflow_core)

# Server (Task 2 & 3)
add_executable(xflow_server src/server_main.cpp)
target_link_libraries(xflow_server PRIVATE xflow_core)

# Client (Task 2)
add_executable(xflow_client src/client_main.cpp)
target_link_libraries(xflow_client PRIVATE xflow_core)

# -------------------------------------------------------------
# Task 4: Google Test Unit Tests
# -------------------------------------------------------------
include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(unit_tests
    tests/test_main.cpp
    tests/test_database.cpp
    tests/test_sip_parser.cpp
    tests/test_checksum.cpp
    tests/test_pcap_processor.cpp
)
target_link_libraries(unit_tests PRIVATE xflow_core gtest gtest_main)

# Copy test PCAP to build directory so unit tests can access it directly
add_custom_command(TARGET unit_tests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/sip-rtp-g729a.pcap"
    "$<TARGET_FILE_DIR:unit_tests>/sip-rtp-g729a.pcap"
)

# Also copy pcap for the main executables
add_custom_command(TARGET xflow_processor POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/sip-rtp-g729a.pcap"
    "$<TARGET_FILE_DIR:xflow_processor>/sip-rtp-g729a.pcap"
)

enable_testing()
add_test(NAME AllUnitTests COMMAND unit_tests)
