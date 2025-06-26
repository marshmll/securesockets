#include "securesockets/TCPSocket.hpp"

using namespace sck;

TCPSocket::TCPSocket() : Socket(AF_INET, SOCK_STREAM, 0), connFd(-1)
{
}

TCPSocket::~TCPSocket()
{
    this->close();
}

int TCPSocket::listen(const int n)
{
    return ::listen(sockFd, n);
}

int TCPSocket::connect(const std::string &host, const unsigned short port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    if (inet_pton(AF_INET, host.c_str(), &sa.sin_addr) <= 0)
    {
        return -1;
    }

    return ::connect(sockFd, (struct sockaddr *)&sa, sizeof(sa));
}

int TCPSocket::accept()
{
    struct sockaddr_in saPeer;
    socklen_t clientLen = sizeof(saPeer);

    connFd = ::accept(sockFd, (struct sockaddr *)&saPeer, &clientLen);
    return connFd;
}

ssize_t TCPSocket::send(const void *data, const size_t size, const int flags)
{
    if (connFd >= 0)
    {
        return write(connFd, data, size);
    }
    else
    {
        return write(sockFd, data, size);
    }
}

ssize_t TCPSocket::recv(void *const buf, const size_t size, const int flags)
{
    if (connFd >= 0)
    {
        return read(connFd, buf, size);
    }
    else
    {
        return read(sockFd, buf, size);
    }
}

void TCPSocket::close()
{
    if (connFd >= 0)
    {
        ::close(connFd);
        connFd = -1;
    }
    if (sockFd >= 0)
    {
        ::close(sockFd);
        sockFd = -1;
    }
}