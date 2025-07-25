cmake_minimum_required(VERSION 3.15)
project(cef-cpp VERSION 0.1.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # if in standalone set default settings to ON
    option(CEF_CPP_BUILD_TESTS "Force tests to build" ON)
    option(CEF_CPP_BUILD_EXAMPLES "Build examples" ON)
else ()
    # if used as a library set default settings to OFF
    option(CEF_CPP_BUILD_TESTS "Force tests to build" OFF)
    option(CEF_CPP_BUILD_EXAMPLES "Build examples" OFF)
endif ()

find_package(Boost REQUIRED COMPONENTS system regex)
find_package(GTest REQUIRED)

# Create the CEF parser library
add_library(cef_cpp
        src/cef_parser.cpp
        src/cef_event.cpp
)

target_include_directories(cef_cpp
        PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
        PRIVATE
        src
)

target_link_libraries(cef_cpp
        PUBLIC
        Boost::regex
)

# Compiler-specific options for better debugging in CLion
target_compile_options(cef_cpp PRIVATE
        $<$<CXX_COMPILER_ID:MSVC>:/W4>
        $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -g>
)

# Set compiler definitions for debugging
target_compile_definitions(cef_cpp PRIVATE
        $<$<CONFIG:Debug>:DEBUG>
        $<$<CONFIG:Release>:NDEBUG>
)

if (CEF_CPP_BUILD_EXAMPLES)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/examples)
endif ()

if (CEF_CPP_BUILD_TESTS)
    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif ()
