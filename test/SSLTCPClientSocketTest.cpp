#include <gtest/gtest.h>

#include <sockets/SSLTCPClientSocket.hpp>

#define TEST_NAME SSLTCPClientSocketTest

class TestingSocket : public sck::SSLTCPClientSocket
{
  public:
    TestingSocket() : sck::SSLTCPClientSocket() {};

    using sck::SSLSocket::close;
    using sck::SSLSocket::create;
    using sck::SSLSocket::getSystemHandle;
};

static const sck::SocketHandle invalidHandle = sck::impl::SocketImpl::InvalidHandle;

TEST(TEST_NAME, TypeTraits)
{
    ASSERT_TRUE(std::is_constructible_v<sck::SSLTCPClientSocket>);
    ASSERT_FALSE(std::is_copy_constructible_v<sck::SSLTCPClientSocket>);
    ASSERT_FALSE(std::is_copy_assignable_v<sck::SSLTCPClientSocket>);
    ASSERT_TRUE(std::is_nothrow_move_constructible_v<sck::SSLTCPClientSocket>);
    ASSERT_TRUE(std::is_nothrow_move_assignable_v<sck::SSLTCPClientSocket>);
}

TEST(TEST_NAME, Instantiation)
{
    TestingSocket socket;

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
