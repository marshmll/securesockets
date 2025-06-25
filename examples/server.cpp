#include "securesockets/SecureTCPServer.hpp"

int main(void)
{
    sck::SecureTCPServer server("cert.pem", "key.pem");

    if (!server.listen(8000))
    {
        std::cerr << "[Server] Failed to listen on port 8000" << std::endl;
        return 1;
    }

    std::cout << "[Server] Waiting for connections..." << std::endl;

    if (!server.accept())
    {
        std::cerr << "[Server] Failed to accept connection" << std::endl;
        return 1;
    }

    std::cout << "[Server] Connection accepted" << std::endl;

    int sent = server.send("Server Hello!", sizeof("Server Hello!"));

    std::cout << "[Server] Sent " << sent << " bytes: Client Hello!" << std::endl;

    char buf[4096];
    memset(buf, 0, sizeof(buf));

    int received = server.recv(buf, sizeof(buf));

    std::cout << "[Server] Received " << received << " bytes: " << buf << std::endl;

    return 0;
}