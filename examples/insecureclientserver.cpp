#include "securesockets/TCPSocket.hpp"
#include <iostream>
#include <thread>

using namespace std::chrono_literals;

void serverThread()
{
    sck::TCPSocket socket;

    if (!socket.good())
    {
        std::cerr << "Server socket failed to create: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    if (socket.bind(8000) == -1)
    {
        std::cerr << "Server failed to bind: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    if (socket.listen(5) == -1)
    {
        std::cerr << "Server failed to listen: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    if (socket.accept() == -1)
    {
        std::cerr << "Server failed to accept: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    char buf[1024];
    size_t recv = socket.recv(buf, sizeof(buf) - 1);
    buf[recv] = '\0';

    std::this_thread::sleep_for(500ms);

    std::cout << "Server received " << recv << " bytes: " << buf << std::endl;

    const char *msg = "Server Hello!";

    size_t sent = socket.send(msg, strlen(msg));

    std::cout << "Server sent " << sent << " bytes: " << msg << std::endl;

    socket.close();

    std::cout << "Server end" << std::endl;
}

void clientThread()
{
    sck::TCPSocket socket;

    if (!socket.good())
    {
        std::cerr << "Client socket failed to create: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    if (socket.connect("127.0.0.1", 8000) == -1)
    {
        std::cerr << "Client failed to connect: " << sck::TCPSocket::getErrorMsg() << std::endl;
        exit(1);
    }

    const char *msg = "Client Hello!";

    size_t sent = socket.send(msg, strlen(msg));

    std::this_thread::sleep_for(500ms);

    std::cout << "Client sent " << sent << " bytes: " << msg << std::endl;

    char buf[1024];
    size_t recv = socket.recv(buf, sizeof(buf) - 1);
    buf[recv] = '\0';

    std::cout << "Client received " << recv << " bytes: " << buf << std::endl;

    socket.close();

    std::cout << "Client end" << std::endl;
}

int main(void)
{
    std::thread server(serverThread);

    usleep(1000000);

    std::thread client(clientThread);

    server.join();
    client.join();
}