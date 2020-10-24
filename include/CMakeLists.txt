include(TestBigEndian)

test_big_endian(HAVAL_BIG_ENDIAN)

add_library(haval INTERFACE)

if(NOT HAVAL_STANDALONE_BUILD)
    add_library(${PROJECT_NAME}::haval ALIAS haval)
endif()

target_include_directories(haval
    INTERFACE
        "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>"
        "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>")

target_compile_definitions(haval
    INTERFACE
        $<$<NOT:$<BOOL:${HAVAL_BIG_ENDIAN}>>:HAVAL_LITTLE_ENDIAN>)

if(HAVAL_ENABLE_INSTALL)
    install(
        TARGETS haval
        EXPORT ${PROJECT_NAME}-targets)

    install(
        FILES
            haval.h
            haval.hpp
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
endif()
