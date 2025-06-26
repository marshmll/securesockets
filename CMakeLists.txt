cmake_minimum_required(VERSION 3.28)
project(securesockets VERSION 0.0.1 LANGUAGES CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Create the library
add_library(securesockets STATIC
    src/securesockets/SecureTCPClient.cpp
    src/securesockets/SecureTCPServer.cpp
    src/securesockets/TCPSocket.cpp
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