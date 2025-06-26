#include "securesockets/TCPSocket.hpp"

using namespace sck;

TCPSocket::TCPSocket() : sockFd(-1), connFd(-1)
{
}

TCPSocket::~TCPSocket()
{
    if (connFd >= 0)
    {
        ::close(connFd);
    }

    if (sockFd >= 0)
    {
        ::close(sockFd);
    }
}

bool TCPSocket::init(const int protocol)
{
    int optval = 1;

    sockFd = socket(AF_INET, SOCK_STREAM, protocol);

    setOpt(SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    return sockFd != -1;
}

int TCPSocket::setOpt(const int level, const int optname, const void *optval, const socklen_t optlen)
{
    return setsockopt(sockFd, level, optname, &optval, optlen);
}

int TCPSocket::bind(const unsigned short port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);

    return ::bind(sockFd, (struct sockaddr *)&sa, sizeof(sa));
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

size_t TCPSocket::send(const void *data, const size_t size, const int flags)
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

size_t TCPSocket::recv(void *const buf, const size_t size, const int flags)
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
    if (sockFd >= 0)
    {
        ::close(sockFd);
    }
}

const std::string TCPSocket::getErrorMsg()
{
    return strerror(errno);
}
