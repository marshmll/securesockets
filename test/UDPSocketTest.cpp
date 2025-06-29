#include <gtest/gtest.h>

#include "sockets/UDPSocket.hpp"

static const sck::SocketHandle invalidHandle = sck::impl::SocketImpl::invalidHandle();

TEST(UDPSocketTest, TypeTraits)
{
    ASSERT_TRUE(std::is_constructible_v<sck::UDPSocket>);
    ASSERT_FALSE(std::is_copy_constructible_v<sck::UDPSocket>);
    ASSERT_FALSE(std::is_copy_assignable_v<sck::UDPSocket>);
    ASSERT_TRUE(std::is_nothrow_move_constructible_v<sck::UDPSocket>);
    ASSERT_TRUE(std::is_nothrow_move_assignable_v<sck::UDPSocket>);
}
