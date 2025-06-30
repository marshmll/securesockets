#include "sockets/SocketImpl.hpp"

#include <cstring>
#include <fcntl.h>
#include <iostream>

namespace sck::impl
{

sockaddr_in SocketImpl::createAddress(const uint32_t addr, const unsigned short port)
{
    sockaddr_in sa = {};
    memset(&sa, 0, sizeof(sa));

    sa.sin_addr.s_addr = htonl(addr);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
#ifdef __APPLE__
    sa.sin_len = sizeof(sa);
#endif

    return sa;
}

bool SocketImpl::isValidHandle(SocketHandle handle)
{
    return handle != InvalidHandle;
}

void SocketImpl::close(SocketHandle handle)
{
    ::close(handle);
}

void SocketImpl::setBlocking(SocketHandle handle, const bool blocking)
{
    const int flags = fcntl(handle, F_GETFL);

    if (blocking)
    {
        if (fcntl(handle, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            std::cerr << "Failed to set socket to non-blocking mode" << std::endl;
        }
    }
    else
    {
        if (fcntl(handle, F_SETFL, flags & ~O_NONBLOCK) < 0)
        {
            std::cerr << "Failed to set socket to blocking mode" << std::endl;
        }
    }
}

int SocketImpl::waitRead(SocketHandle handle, const unsigned int timeout_ms)
{
    fd_set fds;
    int width;

    FD_ZERO(&fds);
    FD_SET(handle, &fds);
    width = handle + 1;

    timeval time = {};
    time.tv_sec = static_cast<time_t>(timeout_ms / 1000);
    time.tv_usec = 0;

    return select(width, &fds, nullptr, nullptr, &time);
}

int SocketImpl::waitWrite(SocketHandle handle, const unsigned int timeout_ms)
{
    fd_set fds;
    int width;

    FD_ZERO(&fds);
    FD_SET(handle, &fds);
    width = handle + 1;

    timeval time = {};
    time.tv_sec = static_cast<time_t>(timeout_ms / 1000);
    time.tv_usec = 0;

    return select(width, nullptr, &fds, nullptr, &time);
}

Socket::Status SocketImpl::getErrorStatus()
{
    if ((errno == EAGAIN) || (errno == EINPROGRESS))
        return Socket::Status::WouldBlock;

    switch (errno)
    {
    case EWOULDBLOCK:
        return Socket::Status::WouldBlock;
    case ECONNABORTED:
        return Socket::Status::Disconnected;
    case ECONNRESET:
        return Socket::Status::Disconnected;
    case ETIMEDOUT:
        return Socket::Status::Disconnected;
    case ENETRESET:
        return Socket::Status::Disconnected;
    case ENOTCONN:
        return Socket::Status::Disconnected;
    case EPIPE:
        return Socket::Status::Disconnected;
    default:
        return Socket::Status::Error;
    }
}

} // namespace sck::impl