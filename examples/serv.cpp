#include "sockets/TCPServerSocket.hpp"
#include <iostream>

int main()
{
    sck::TCPServerSocket server;
    const unsigned short port = 8000;

    auto status = server.listen(port, sck::IPAddress::Any);

    if (status != sck::Socket::Status::Good)
    {
        std::cerr << sck::Socket::getStatusMessage(status) << std::endl;
        return 1;
    }

    std::cout << "Server listening on port " << port << std::endl;

    while (true)
    {
        sck::TCPClientSocket client;
        sck::IPAddress client_ip;
        unsigned short client_port;

        // Accept with timeout
        auto accept_status = server.accept(client, 1000, &client_ip, &client_port);

        if (accept_status == sck::Socket::Status::Good)
        {
            std::cout << "Accepted connection from " << client_ip.toString() << ":" << client_port << std::endl;

            // Receive data
            char buffer[1024];
            size_t received = 0;
            auto recv_status = client.recv(buffer, sizeof(buffer), received, 5000);

            if (recv_status == sck::Socket::Status::Good)
            {
                buffer[received] = '\0';
                std::cout << "Received " << received << " bytes: " << buffer << std::endl;

                // Echo back
                size_t sent = 0;
                auto send_status = client.send(buffer, received, sent, 5000);

                if (send_status != sck::Socket::Status::Good)
                {
                    std::cerr << sck::Socket::getStatusMessage(send_status) << std::endl;
                }
                else
                {
                    std::cout << "Echoed back " << sent << " bytes" << std::endl;
                }
            }
            else if (recv_status == sck::Socket::Status::ConnectionReset)
            {
                std::cout << "Client disconnected" << std::endl;
            }
            else
            {
                std::cerr << sck::Socket::getStatusMessage(recv_status) << std::endl;
            }

            client.disconnect();
        }
        else if (accept_status != sck::Socket::Status::Timeout)
        {
            std::cerr << sck::Socket::getStatusMessage(accept_status) << std::endl;
        }
    }
}