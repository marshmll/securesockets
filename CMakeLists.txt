cmake_minimum_required(VERSION 3.28)
project(sockets VERSION 0.0.1 LANGUAGES CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

set(SRC
    ./src/sockets/Socket.cpp
)

if(WIN32)
    list(APPEND SRC ./src/sockets/Windows/SocketImpl.cpp)
else()
    list(APPEND SRC ./src/sockets/Unix/SocketImpl.cpp)
endif()

# Create the library
add_library(sockets STATIC ${SRC})

target_link_libraries(sockets PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(sockets 
    PRIVATE 
        include
        src
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

set_target_properties(sockets PROPERTIES 
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

# Installation configuration
include(GNUInstallDirs)

install(TARGETS sockets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/sockets
)

install(DIRECTORY include/sockets
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

# Generate and install pkg-config file
configure_file(sockets.pc.in sockets.pc @ONLY)
install(FILES ${CMAKE_BINARY_DIR}/sockets.pc 
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)