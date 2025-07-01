cmake_minimum_required(VERSION 3.28)
project(sockets VERSION 0.1.0 LANGUAGES CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(BUILD_TESTS "Build tests" OFF)

set(SRC
    ./src/sockets/IPAddress.cpp
    ./src/sockets/Socket.cpp
    ./src/sockets/TCPClientSocket.cpp
    ./src/sockets/TCPServerSocket.cpp
    ./src/sockets/UDPSocket.cpp
)

if(WIN32)
    list(APPEND SRC ./src/sockets/Windows/SocketImpl.cpp)
    list(APPEND SRC ./src/sockets/Windows/SSLSocketImpl.cpp)
else()
    list(APPEND SRC ./src/sockets/Unix/SocketImpl.cpp)
    list(APPEND SRC ./src/sockets/Unix/SSLSocketImpl.cpp)
endif()

# Create the library
add_library(sockets STATIC ${SRC})

add_subdirectory("./test")

if (WIN32)
    # find_library(crypt REQUIRED NAMES crypt32)
    target_link_libraries(sockets PRIVATE ws2_32)
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(sockets PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

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