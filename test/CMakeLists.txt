add_executable(havaltest
    havaltest.cpp)

target_link_libraries(havaltest
    PRIVATE
        haval)

add_test(
    NAME havaltest
    COMMAND havaltest
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

if(HAVAL_ENABLE_QT)
    add_executable(havaltest_qt
        havaltest-qt.cpp)

    target_link_libraries(havaltest_qt
        PRIVATE
            haval_qt
            ${QT_CORE_TARGET})

    add_test(
        NAME havaltest_qt
        COMMAND havaltest_qt
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif()
