#include "securesockets/SecureTCPClient.hpp"

int main(void)
{
    sck::SecureTCPClient socket;

    if (!socket.connect("127.0.0.1", 8000))
    {
        std::cerr << "Failed to connect" << std::endl;
    }

    return 0;
}