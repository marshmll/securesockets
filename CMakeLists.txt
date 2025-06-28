cmake_minimum_required(VERSION 3.28)
project(sockets VERSION 0.0.2 LANGUAGES CXX)

# GoogleTest requires at least C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(SRC
    ./src/sockets/IPAddress.cpp
    ./src/sockets/Socket.cpp
    ./src/sockets/UDPSocket.cpp
    ./src/sockets/TCPClientSocket.cpp
    ./src/sockets/TCPServerSocket.cpp
)

if(WIN32)
    list(APPEND SRC ./src/sockets/Windows/SocketImpl.cpp)
    list(APPEND SRC ./src/sockets/Windows/defines.cpp)
else()
    list(APPEND SRC ./src/sockets/Unix/SocketImpl.cpp)
endif()

# Create the library
add_library(sockets SHARED ${SRC})

add_subdirectory("./test")

find_package(OpenSSL REQUIRED)

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