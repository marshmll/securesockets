#include "securesockets/SecureTCPClient.hpp"
#include <iostream>
#include <vector>

int main(void)
{
    sck::SecureTCPClient client("cert/ca.crt");

    if (!client.connect("127.0.0.1", 8000))
    {
        std::cerr << "Failed to connect to server." << std::endl;
        return 1; // Exit with error code
    }

    std::cout << "Successfully connected to server!" << std::endl;

    // Send data first (typical client behavior)
    std::string message = "Client Hello!";
    int sent = client.send(message.data(), message.size());

    if (sent > 0)
    {
        std::cout << "[Client] Sent " << sent << " bytes: " << message << std::endl;
    }
    else if (sent == 0)
    {
        std::cerr << "[Client] Connection closed during send" << std::endl;
        return 1;
    }
    else
    {
        std::cerr << "[Client] Failed to send data" << std::endl;
        return 1;
    }

    // Wait for server response
    std::vector<char> buf(4096);

    int received = client.recv(buf.data(), buf.size());

    if (received > 0)
    {
        std::cout << "[Client] Received " << received << " bytes: " << buf.data() << std::endl;
    }
    else if (received == 0)
    {
        std::cout << "[Client] Connection closed by server" << std::endl;
    }
    else
    {
        std::cerr << "[Client] Failed to receive data" << std::endl;
        return 1;
    }

    std::cout << "[Client] Communication completed successfully" << std::endl;
    return 0;
}