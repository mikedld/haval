add_executable(havalapp
    havalapp.cpp)

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
