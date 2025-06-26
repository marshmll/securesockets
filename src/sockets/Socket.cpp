#include "securesockets/Socket.hpp"

using namespace sck;

Socket::Socket(const int domain, const int type, const int protocol) : sockFd(-1)
{
    int optval = 1;
    sockFd = socket(domain, type, protocol);

    setOpt(SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
}

Socket::~Socket()
{
    this->close();
}

int Socket::setOpt(const int level, const int optname, const void *optval, const socklen_t optlen)
{
    return setsockopt(sockFd, level, optname, &optval, optlen);
}

int Socket::bind(const unsigned short port)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = INADDR_ANY;
    sa.sin_port = htons(port);

    return ::bind(sockFd, (struct sockaddr *)&sa, sizeof(sa));
}

bool Socket::good() const
{
    return sockFd >= 0;
}

void Socket::close()
{
    if (sockFd >= 0)
    {
        ::close(sockFd);
        sockFd = -1;
    }
}

const std::string Socket::getErrorMsg()
{
    return strerror(errno);
}
