if (BUILD_TESTS)

include(FetchContent)
FetchContent_Declare(
    googletest
    URL https://github.com/google/googletest/archive/52eb8108c5bdec04579160ae17225d66034bd723.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

add_executable(SocketTest SocketTest.cpp)
target_include_directories(SocketTest PRIVATE ../include)
target_link_libraries(SocketTest PRIVATE GTest::gtest_main sockets)

add_executable(IPAddressTest IPAddressTest.cpp)
target_include_directories(IPAddressTest PRIVATE ../include)
target_link_libraries(IPAddressTest PRIVATE GTest::gtest_main sockets)

include(GoogleTest)
gtest_discover_tests(SocketTest)
gtest_discover_tests(IPAddressTest)

endif()