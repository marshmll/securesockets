cmake_minimum_required(VERSION 3.28)
project(securesockets VERSION 0.0.1 LANGUAGES CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Add option to enable/disable tests
option(BUILD_TESTS "Build the tests" ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

if(BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
    )
    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
    enable_testing()
endif()

# Create the library
add_library(securesockets STATIC
    src/securesockets/SecureTCPClient.cpp
    src/securesockets/SecureTCPServer.cpp
) 

target_link_libraries(securesockets PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(securesockets 
    PRIVATE 
        include
        src
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

set_target_properties(securesockets PROPERTIES 
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Auto-discover and add all test files if tests are enabled
if(BUILD_TESTS)
    file(GLOB TEST_SOURCES "test/*.cpp")
    foreach(TEST_SOURCE ${TEST_SOURCES})
        get_filename_component(TEST_NAME ${TEST_SOURCE} NAME_WE)
        add_executable(${TEST_NAME} ${TEST_SOURCE})
        target_link_libraries(${TEST_NAME} 
            PRIVATE 
                securesockets
                GTest::gtest_main
                OpenSSL::SSL 
                OpenSSL::Crypto
        )
        target_include_directories(${TEST_NAME} PRIVATE include)
        include(GoogleTest)
        gtest_discover_tests(${TEST_NAME})
    endforeach()
endif()

add_custom_target(copy_cert_key
    COMMAND ${CMAKE_COMMAND} -E copy_directory_if_different
        "${CMAKE_SOURCE_DIR}/examples/cert/"
        "${CMAKE_BINARY_DIR}/cert"
    COMMENT "Copying Assets folder"
)

add_dependencies(securesockets copy_cert_key)

# Installation configuration
include(GNUInstallDirs)

install(TARGETS securesockets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/securesockets
)

install(DIRECTORY include/securesockets
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Generate and install pkg-config file
configure_file(securesockets.pc.in securesockets.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/securesockets.pc 
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)