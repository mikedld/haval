cmake_minimum_required(VERSION 3.12 FATAL_ERROR)
project(haval VERSION 1.2 LANGUAGES CXX)

set(HAVAL_STANDALONE_BUILD OFF)
if(PROJECT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
    set(HAVAL_STANDALONE_BUILD ON)
endif()

option(HAVAL_ENABLE_QT "${PROJECT_NAME}: Enable Qt wrapper" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_ENABLE_INSTALL "${PROJECT_NAME}: Enable install" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_ENABLE_TESTS "${PROJECT_NAME}: Enable tests" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_ENABLE_WERROR "${PROJECT_NAME}: Treat warnings as errors" ${HAVAL_STANDALONE_BUILD})
option(HAVAL_BUILD_PROGRAMS "${PROJECT_NAME}: Build programs" ${HAVAL_STANDALONE_BUILD})

set(HAVAL_QT_VERSION 5 CACHE STRING "${PROJECT_NAME}: Qt version for the wrapper")

if(HAVAL_ENABLE_INSTALL)
    include(GNUInstallDirs)
endif()

if(HAVAL_STANDALONE_BUILD)
    if(NOT CMAKE_CXX_STANDARD)
        set(CMAKE_CXX_STANDARD 14)
        set(CMAKE_CXX_STANDARD_REQUIRED ON)
        set(CMAKE_CXX_EXTENSIONS OFF)
    endif()

    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
            -Wall
            -Wextra
            -pedantic
            $<$<BOOL:${HAVAL_ENABLE_WERROR}>:-Werror>)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
        add_compile_options(
            /W4
            $<$<BOOL:${HAVAL_ENABLE_WERROR}>:/WX>)
    endif()
endif()

add_compile_definitions(
    $<$<CXX_COMPILER_ID:MSVC>:_CRT_SECURE_NO_WARNINGS>)

if(HAVAL_ENABLE_QT)
    if(HAVAL_QT_VERSION MATCHES "^([56])([.]|$)")
        set(HAVAL_QT_VERSION_MAJOR ${CMAKE_MATCH_1})
        find_package(Qt${HAVAL_QT_VERSION_MAJOR} ${HAVAL_QT_VERSION} REQUIRED COMPONENTS Core)
        if(HAVAL_QT_VERSION_MAJOR EQUAL 5)
            set(QT_CORE_TARGET Qt5::Core)
        else()
            set(QT_CORE_TARGET Qt::Core)
        endif()
    else()
        message(FATAL_ERROR "Qt version '${HAVAL_QT_VERSION}' is not supported")
    endif()
endif()

add_subdirectory(include)

if(HAVAL_ENABLE_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()

if(HAVAL_BUILD_PROGRAMS)
    add_subdirectory(src)
endif()

if(HAVAL_ENABLE_INSTALL)
    include(CMakePackageConfigHelpers)

    install(
        FILES
            ChangeLog
            haval-paper.pdf
            LICENSE
            README.md
        COMPONENT doc
        DESTINATION ${CMAKE_INSTALL_DOCDIR})

    install(
        EXPORT ${PROJECT_NAME}-targets-core
        COMPONENT core
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
        NAMESPACE ${PROJECT_NAME}::)

    if(HAVAL_ENABLE_QT)
        install(
            EXPORT ${PROJECT_NAME}-targets-qt
            COMPONENT qt
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
            NAMESPACE ${PROJECT_NAME}::)
    endif()

    if(HAVAL_BUILD_PROGRAMS)
        install(
            EXPORT ${PROJECT_NAME}-targets-app
            COMPONENT app
            DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}
            NAMESPACE ${PROJECT_NAME}::)
    endif()

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
