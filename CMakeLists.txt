cmake_minimum_required(VERSION 3.28)
project(securesockets VERSION 0.0.1 LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(securesockets STATIC
    src/securesockets/SecureTCPClient.cpp
    src/securesockets/SecureTCPServer.cpp
)

target_link_libraries(securesockets PUBLIC crypto ssl)

set_target_properties(securesockets PROPERTIES VERSION ${PROJECT_VERSION})
set_target_properties(securesockets PROPERTIES SOVERSION ${PROJECT_VERSION_MAJOR})

target_include_directories(securesockets PRIVATE include)
target_include_directories(securesockets PRIVATE src)

include(GNUInstallDirs)

install(TARGETS securesockets
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

configure_file(securesockets.pc.in securesockets.pc @ONLY)

install(FILES ${CMAKE_BINARY_DIR}/securesockets.pc DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)
