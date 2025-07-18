#include <gtest/gtest.h>

#include "sockets/IPAddress.hpp"

#define TEST_NAME IPAddressTest

TEST(TEST_NAME, TypeTraits)
{
    ASSERT_TRUE(std::is_constructible_v<sck::IPAddress>);
    ASSERT_TRUE(std::is_copy_constructible_v<sck::IPAddress>);
    ASSERT_TRUE(std::is_copy_assignable_v<sck::IPAddress>);
    ASSERT_TRUE(std::is_nothrow_move_constructible_v<sck::IPAddress>);
    ASSERT_TRUE(std::is_nothrow_move_assignable_v<sck::IPAddress>);
}

TEST(TEST_NAME, Constants)
{
    // Any IP
    ASSERT_EQ(sck::IPAddress::Any.toString(), "0.0.0.0");
    ASSERT_EQ(sck::IPAddress::Any.toInteger(), 0);

    // LocalHost IP
    ASSERT_EQ(sck::IPAddress::LocalHost.toString(), "127.0.0.1");
    ASSERT_EQ(sck::IPAddress::LocalHost.toInteger(), 16777343);

    // Broadcast IP
    ASSERT_EQ(sck::IPAddress::Broadcast.toString(), "255.255.255.255");
    ASSERT_EQ(sck::IPAddress::Broadcast.toInteger(), 4294967295);
}

TEST(TEST_NAME, Instantiation)
{
    const sck::IPAddress address;

    EXPECT_TRUE(address == sck::IPAddress::Invalid);
}

TEST(TEST_NAME, IPAddressResolution)
{
    // LocalHost resolution
    const sck::IPAddress localhost("127.0.0.1");
    EXPECT_TRUE(localhost == sck::IPAddress::LocalHost);

    // Broadcast resolution
    const sck::IPAddress broadcast("255.255.255.255");
    EXPECT_TRUE(broadcast == sck::IPAddress::Broadcast);
}

TEST(TEST_NAME, HostnameResolution)
{
    // Test for Google Domain Name
    const sck::IPAddress google_address("www.gnu.org");
    EXPECT_TRUE(google_address != sck::IPAddress::Invalid);

    // Test for LocalHost hostname
    const sck::IPAddress localhost_address("localhost");
    EXPECT_TRUE(localhost_address.toString() == sck::IPAddress::LocalHost.toString());
}

TEST(TEST_NAME, EqualityComparison)
{
    sck::IPAddress first("127.0.0.1");
    sck::IPAddress second("localhost");

    EXPECT_TRUE(first == second);
    EXPECT_TRUE(second == first);
}

TEST(TEST_NAME, InequalityComparison)
{
    sck::IPAddress first("127.0.0.1");
    sck::IPAddress second("192.168.100.1");

    EXPECT_TRUE(first != second);
    EXPECT_TRUE(second != first);
}

TEST(TEST_NAME, ConstructorCopySemantics)
{
    sck::IPAddress address("www.gnu.org");

    sck::IPAddress copy(address);

    EXPECT_TRUE(address == copy);
}

TEST(TEST_NAME, AssignmentCopySemantics)
{
    sck::IPAddress address("www.gnu.org");

    sck::IPAddress copy = address;

    EXPECT_TRUE(address == copy);
}

TEST(TEST_NAME, ConstructorMoveSemantics)
{
    sck::IPAddress r_address("www.gnu.org");

    sck::IPAddress r_address_copy = r_address;

    const sck::IPAddress l_address(std::move(r_address));

    EXPECT_TRUE(l_address == r_address_copy);
}

TEST(TEST_NAME, AssignmentMoveSemantics)
{
    sck::IPAddress r_address("www.gnu.org");

    sck::IPAddress r_address_copy = r_address;

    const sck::IPAddress l_address = std::move(r_address);

    EXPECT_TRUE(l_address == r_address_copy);
}