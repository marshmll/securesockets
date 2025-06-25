#include "securesockets/SecureTCPClient.hpp"
#include <iostream>

int main(void)
{
    sck::SecureTCPClient client("cert/ca.crt");

    if (!client.connect("127.0.0.1", 8000))
    {
        std::cerr << "Failed to connect to server." << std::endl;
    }

    char buf[4096];
    memset(buf, 0, sizeof(buf));

    int received = client.recv(buf, sizeof(buf));

    std::cout << "[Client] Received " << received << " bytes: " << buf << std::endl;

    int sent = client.send("Client Hello!", sizeof("Client Hello!"));

    std::cout << "[Client] Sent " << sent << " bytes: Client Hello!" << std::endl;

    return 0;
}