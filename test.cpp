#include "sockets/IPAddress.hpp"

int main(void)
{
    sck::IPAddress test("www.google.com");

    std::cout << test.toString() << std::endl;
    std::cout << test.toInteger() << std::endl;

    return 0;
}