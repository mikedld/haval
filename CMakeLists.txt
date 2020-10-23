cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(haval VERSION 1.1 LANGUAGES C)

set(HAVAL_STANDALONE_BUILD OFF)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(HAVAL_STANDALONE_BUILD ON)
endif()

option(HAVAL_ENABLE_INSTALL "${PROJECT_NAME}: Enable install" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_ENABLE_TESTS "${PROJECT_NAME}: Enable tests" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_BUILD_PROGRAMS "${PROJECT_NAME}: Build programs" ${HAVAL_STANDALONE_BUILD})

set(HAVAL_PASS 3 CACHE STRING "Number of passes")
set(HAVAL_FPTLEN 256 CACHE STRING "Length of a fingerprint")
set(HAVAL_NUMBER_OF_BLOCKS 5000 CACHE STRING "Number of test blocks")
set(HAVAL_BLOCK_SIZE 5000 CACHE STRING "Test block size")

include(TestBigEndian)
if(HAVAL_ENABLE_INSTALL)
    include(CMakePackageConfigHelpers)
    include(GNUInstallDirs)
endif()

if(HAVAL_STANDALONE_BUILD)
    if(NOT CMAKE_C_STANDARD)
        set(CMAKE_C_STANDARD 90)
        set(CMAKE_C_STANDARD_REQUIRED ON)
        set(CMAKE_C_EXTENSIONS OFF)
    endif()

    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
            -Wall
            -Wextra
            -pedantic)
    elseif(CMAKE_C_COMPILER_ID STREQUAL "MSVC")
        add_compile_options(
            /W4)
    endif()
endif()

test_big_endian(HAVAL_BIG_ENDIAN)

add_compile_definitions(
    PASS=${HAVAL_PASS}
    FPTLEN=${HAVAL_FPTLEN}
    NUMBER_OF_BLOCKS=${HAVAL_NUMBER_OF_BLOCKS}
    BLOCK_SIZE=${HAVAL_BLOCK_SIZE}
    $<$<NOT:$<BOOL:${HAVAL_BIG_ENDIAN}>>:LITTLE_ENDIAN>)

add_library(haval
    haval.c
    haval.h)

if(NOT HAVAL_STANDALONE_BUILD)
    add_library(${PROJECT_NAME}::haval ALIAS haval)
endif()

target_include_directories(haval
    PUBLIC
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
    PRIVATE
        "${CMAKE_CURRENT_BINARY_DIR}")

if(HAVAL_ENABLE_INSTALL)
    install(
        TARGETS haval
        EXPORT ${PROJECT_NAME}-targets
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})

    install(
        FILES haval.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()

if(HAVAL_ENABLE_TESTS)
    enable_testing()

    add_executable(havaltest
        havaltest.c)

    target_link_libraries(havaltest
        PRIVATE
            haval)

    add_test(
        NAME havaltest
        COMMAND havaltest
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")
endif()

if(HAVAL_BUILD_PROGRAMS)
    add_executable(havalapp
        havalapp.c
        havalapp.h)

    if(NOT HAVAL_STANDALONE_BUILD)
        add_executable(${PROJECT_NAME}::havalapp ALIAS havalapp)
    endif()

    target_link_libraries(havalapp
        PRIVATE
            haval)

    set_target_properties(havalapp
        PROPERTIES
            OUTPUT_NAME haval)

    if(HAVAL_ENABLE_INSTALL)
        install(
            TARGETS havalapp
            EXPORT ${PROJECT_NAME}-targets
            DESTINATION ${CMAKE_INSTALL_BINDIR})
    endif()
endif()

if(HAVAL_ENABLE_INSTALL)
    install(
        EXPORT ${PROJECT_NAME}-targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        NAMESPACE ${PROJECT_NAME}::)

    configure_file(${PROJECT_NAME}-config.cmake.in ${PROJECT_NAME}-config.cmake @ONLY)

    write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
        COMPATIBILITY AnyNewerVersion)

    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake"
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME})
endif()
