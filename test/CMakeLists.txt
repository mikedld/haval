add_executable(havaltest
    havaltest.cpp)

target_link_libraries(havaltest
    PRIVATE
        haval)

add_test(
    NAME havaltest
    COMMAND havaltest
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
