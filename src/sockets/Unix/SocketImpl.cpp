#include "sockets/SocketImpl.hpp"

#include <cstring>
#include <fcntl.h>
#include <iostream>

using namespace sck;

sockaddr_in impl::SocketImpl::createAddress(const uint32_t addr, const unsigned short port)
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

SocketHandle impl::SocketImpl::invalidSocketHandle()
{
    return -1;
}

bool impl::SocketImpl::isValidHandle(SocketHandle handle)
{
    return handle != invalidSocketHandle();
}

void impl::SocketImpl::close(SocketHandle handle)
{
    ::close(handle);
}

void impl::SocketImpl::setBlocking(SocketHandle handle, const bool blocking)
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

Socket::Status impl::SocketImpl::getErrorStatus()
{
    if ((errno == EAGAIN) || (errno == EINPROGRESS))
        return Socket::Status::Blocked;

    switch (errno)
    {
    case EWOULDBLOCK:
        return Socket::Status::Blocked;
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