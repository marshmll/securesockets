#include <gtest/gtest.h>

#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#define TEST_NAME SocketTest

class TestingSocket : public sck::Socket
{
  public:
    TestingSocket() : sck::Socket(sck::Socket::Type::UDP) {};

    using sck::Socket::close;
    using sck::Socket::create;
    using sck::Socket::getSystemHandle;
};

static const sck::SocketHandle invalidHandle = sck::impl::SocketImpl::InvalidHandle;

TEST(TEST_NAME, TypeTraits)
{
    ASSERT_FALSE(std::is_constructible_v<sck::Socket>);
    ASSERT_FALSE(std::is_copy_constructible_v<sck::Socket>);
    ASSERT_FALSE(std::is_copy_assignable_v<sck::Socket>);
    ASSERT_TRUE(std::is_nothrow_move_constructible_v<sck::Socket>);
    ASSERT_TRUE(std::is_nothrow_move_assignable_v<sck::Socket>);
}

TEST(TEST_NAME, Constants)
{
    ASSERT_EQ(sck::Socket::RandomPort, 0);
}

TEST(TEST_NAME, Instantiation)
{
    const TestingSocket socket;
    EXPECT_TRUE(socket.isBlocking());
    EXPECT_EQ(socket.getSystemHandle(), invalidHandle);
}

TEST(TEST_NAME, SetGetBlocking)
{
    TestingSocket socket;

    socket.setBlocking(false);
    EXPECT_FALSE(socket.isBlocking());
}

TEST(TEST_NAME, Creation)
{
    TestingSocket socket;

    socket.create();
    EXPECT_NE(socket.getSystemHandle(), invalidHandle);

    // Nothing should change
    socket.create();
    EXPECT_NE(socket.getSystemHandle(), invalidHandle);
}

TEST(TEST_NAME, Closing)
{
    TestingSocket socket;
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

TEST(TEST_NAME, ConstructorMoveSemantics)
{
    TestingSocket r_socket;
    r_socket.setBlocking(false);
    r_socket.create();

    const TestingSocket l_socket(std::move(r_socket));

    EXPECT_FALSE(l_socket.isBlocking());
    EXPECT_NE(l_socket.getSystemHandle(), invalidHandle);
}

TEST(TEST_NAME, AssignmentMoveSemantics)
{
    TestingSocket r_socket;
    r_socket.setBlocking(false);
    r_socket.create();

    const TestingSocket l_socket = std::move(r_socket);

    EXPECT_FALSE(l_socket.isBlocking());
    EXPECT_NE(l_socket.getSystemHandle(), invalidHandle);
}
