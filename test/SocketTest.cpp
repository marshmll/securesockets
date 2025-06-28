#include <gtest/gtest.h>

#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

class MockSocket : public sck::Socket
{
  public:
    MockSocket() : sck::Socket(sck::Socket::Type::UDP) {};

    using sck::Socket::close;
    using sck::Socket::create;
    using sck::Socket::getSystemHandle;
};

static const sck::SocketHandle invalidHandle = sck::impl::SocketImpl::invalidHandle();

TEST(SocketTest, TypeTraits)
{
    ASSERT_FALSE(std::is_constructible_v<sck::Socket>);
    ASSERT_FALSE(std::is_copy_constructible_v<sck::Socket>);
    ASSERT_FALSE(std::is_copy_assignable_v<sck::Socket>);
    ASSERT_TRUE(std::is_nothrow_move_constructible_v<sck::Socket>);
    ASSERT_TRUE(std::is_nothrow_move_assignable_v<sck::Socket>);
}

TEST(SocketTest, Constants)
{
    ASSERT_EQ(sck::Socket::RandomPort, 0);
}

TEST(SocketTest, Instantiation)
{
    const MockSocket socket;
    EXPECT_TRUE(socket.isBlocking());
    EXPECT_EQ(socket.getSystemHandle(), invalidHandle);
}

TEST(SocketTest, SetGetBlocking)
{
    MockSocket socket;

    socket.setBlocking(false);
    EXPECT_FALSE(socket.isBlocking());
}

TEST(SocketTest, Creation)
{
    MockSocket socket;

    socket.create();
    EXPECT_NE(socket.getSystemHandle(), invalidHandle);

    // Nothing should change
    socket.create();
    EXPECT_NE(socket.getSystemHandle(), invalidHandle);
}

TEST(SocketTest, Closing)
{
    MockSocket socket;
    socket.create();

    EXPECT_TRUE(socket.isBlocking());
    EXPECT_NE(socket.getSystemHandle(), invalidHandle);

    socket.close();
    EXPECT_TRUE(socket.isBlocking());
    EXPECT_EQ(socket.getSystemHandle(), invalidHandle);

    // Nothing should change
    socket.close();
    EXPECT_TRUE(socket.isBlocking());
    EXPECT_EQ(socket.getSystemHandle(), invalidHandle);
}

TEST(SocketTest, ConstructorMoveSemantics)
{
    MockSocket r_socket;
    r_socket.setBlocking(false);
    r_socket.create();

    const MockSocket l_socket(std::move(r_socket));

    EXPECT_FALSE(l_socket.isBlocking());
    EXPECT_NE(l_socket.getSystemHandle(), invalidHandle);
}

TEST(SocketTest, AssignmentMoveSemantics)
{
    MockSocket r_socket;
    r_socket.setBlocking(false);
    r_socket.create();

    const MockSocket l_socket = std::move(r_socket);

    EXPECT_FALSE(l_socket.isBlocking());
    EXPECT_NE(l_socket.getSystemHandle(), invalidHandle);
}
