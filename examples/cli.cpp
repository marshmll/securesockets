#include "sockets/TCPClientSocket.hpp"

int main()
{
    srand(time(nullptr));

    sck::TCPClientSocket socket;
    const unsigned short server_port = 8000;

    // Connect with timeout
    auto status = socket.connect(sck::IPAddress::LocalHost, server_port, 5000);

    if (status != sck::Socket::Status::Good)
    {
        std::cerr << sck::Socket::getStatusMessage(status) << std::endl;
        return 1;
    }

    std::cout << "Successfully connected to server" << std::endl;

    // Send message
    const std::string msg = "Hello Server! Nonce: " + std::to_string(rand() % INT16_MAX);
    size_t sent = 0;
    auto send_status = socket.send(msg.c_str(), msg.size(), sent, 5000);

    if (send_status != sck::Socket::Status::Good)
    {
        std::cerr << sck::Socket::getStatusMessage(send_status) << std::endl;
        return 1;
    }
    std::cout << "Sent " << sent << " bytes: " << msg << std::endl;

    // Receive response with proper timeout handling
    char buffer[1024];
    size_t received = 0;
    const unsigned int timeout_ms = 5000;

    while (true)
    {
        auto recv_status = socket.recv(buffer, sizeof(buffer), received, timeout_ms);

        // Handle successful receive
        if (recv_status == sck::Socket::Status::Good && received > 0)
        {
            buffer[received] = '\0';
            std::cout << "Received " << received << " bytes: " << buffer << std::endl;
            break;
        }
        // Handle disconnection
        else if (recv_status == sck::Socket::Status::ConnectionReset)
        {
            std::cerr << "Server disconnected" << std::endl;
            return 1;
        }
        // Handle timeout
        else if (recv_status == sck::Socket::Status::Timeout)
        {
            std::cerr << "Receive timeout" << std::endl;
            return 1;
        }
        // Handle other errors
        else
        {
            std::cerr << sck::Socket::getStatusMessage(recv_status) << std::endl;
            return 1;
        }
    }

    socket.disconnect();
    return 0;
}