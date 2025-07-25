# Create example executable
add_executable(cef_example
        main.cpp
)

target_link_libraries(cef_example
        PRIVATE
        cef_cpp
)