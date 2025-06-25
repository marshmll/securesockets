#include <memory>

#include <gtest/gtest.h>

#include "securesockets/SecureTCPClient.hpp"
#include "securesockets/SecureTCPServer.hpp"

class TCPTest : public ::testing::Test
{
  protected:
    std::unique_ptr<sck::SecureTCPServer> server_one;
    std::unique_ptr<sck::SecureTCPServer> server_two;
    std::unique_ptr<sck::SecureTCPClient> client;

    virtual ~TCPTest()
    {
    }

    virtual void SetUp() override
    {
        server_one = std::make_unique<sck::SecureTCPServer>("cert/invalid_cert.pem", "cert/invalid_key.pem");
        server_two = std::make_unique<sck::SecureTCPServer>("cert/cert.pem", "cert/key.pem");
        client = std::make_unique<sck::SecureTCPClient>();
    }

    virtual void TearDown() override
    {
        server_one.reset();
        server_two.reset();
        client.reset();
    }
};

TEST_F(TCPTest, ForServerOneReturningFalseFromListenWithInvalidCertAndKey)
{
    EXPECT_FALSE(server_one->listen(8000));
}

TEST_F(TCPTest, ForServerTwoReturningTrueFromListenWithValidCertAndKey)
{
    EXPECT_TRUE(server_two->listen(5000));
}

TEST_F(TCPTest, ForClientReturningFalseWhenConnectionFails)
{
    EXPECT_FALSE(client->connect("127.0.0.1", 8000));
}

TEST_F(TCPTest, ForClientReturningTrueWhenConnectionSucceds)
{
    EXPECT_TRUE(client->connect("127.0.0.1", 5000));
}