#include "sockets/TCPClientSocket.hpp"
#include <chrono>
#include <iostream>
#include <thread>

int main()
{
    srand(time(nullptr));

    sck::TCPClientSocket socket;
    const unsigned short server_port = 8000;

    sck::Socket::Status status;

    status = socket.connect(sck::IPAddress::LocalHost, server_port, 5000);

    if (status == sck::Socket::Status::InProgress)
    {
        std::cerr << sck::Socket::getStatusMessage(status) << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    socket.setBlocking(false);

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

    char buffer[1024];
    size_t received = 0;

    while (true)
    {
        auto recv_status = socket.recv(buffer, sizeof(buffer), received);

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
        // Handle would-block (normal for non-blocking sockets)
        else if (recv_status == sck::Socket::Status::Partial)
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        // Handle other errors
        else if (recv_status != sck::Socket::Status::Partial)
        {
            std::cerr << sck::Socket::getStatusMessage(recv_status) << std::endl;
            return 1;
        }
    }

    socket.disconnect();
    return 0;
}