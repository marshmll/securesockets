cmake_minimum_required(VERSION 3.28)
project(securesockets LANGUAGES CXX)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(securesockets src/main.cpp)
add_subdirectory(src)
include_directories(include)

target_link_libraries(securesockets PRIVATE crypto ssl)

target_compile_features(securesockets PRIVATE cxx_std_17)