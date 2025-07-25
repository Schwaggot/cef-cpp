# Enable testing
enable_testing()

find_package(GTest REQUIRED)

# Create test executable
add_executable(cef_tests
        main.cpp
        test_cef_parser.cpp
)

target_link_libraries(cef_tests
        PRIVATE
        cef_cpp
        gtest::gtest
)

target_compile_options(cef_tests PRIVATE -fno-access-control)

add_test(NAME cef_parser_tests COMMAND cef_tests)