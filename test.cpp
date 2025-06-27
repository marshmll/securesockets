#include "sockets/IPAddress.hpp"

int main(void)
{
    sck::IPAddress test("127.0.0.1");

    std::cout << test.toString() << std::endl;
    std::cout << test.toInteger() << std::endl;

    return 0;
}