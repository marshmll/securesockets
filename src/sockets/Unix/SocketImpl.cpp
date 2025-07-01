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

    sa.sin_addr.s_addr = addr;
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
        if (fcntl(handle, F_SETFL, flags & ~O_NONBLOCK) < 0)
        {
            std::cerr << "Failed to set socket to blocking mode" << std::endl;
        }
    }
    else
    {
        if (fcntl(handle, F_SETFL, flags | O_NONBLOCK) < 0)
        {
            std::cerr << "Failed to set socket to non-blocking mode" << std::endl;
        }
    }
}

int SocketImpl::waitRead(SocketHandle handle, const unsigned int timeout_ms)
{
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(handle, &read_fds);

    timeval timeout = {};
    timeval *timeout_ptr = nullptr;

    if (timeout_ms > 0)
    {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        timeout_ptr = &timeout;
    }

    // Wait for read availability
    const int result = select(handle + 1, &read_fds, nullptr, nullptr, timeout_ptr);

    if (result < 0)
    {
        // Handle EINTR (interrupted system call)
        if (errno == EINTR)
        {
            return 0; // Treat as timeout
        }

        return -1;
    }

    return result; // 1 if ready, 0 if timeout
}

int SocketImpl::waitWrite(SocketHandle handle, const unsigned int timeout_ms)
{
    fd_set write_fds;
    FD_ZERO(&write_fds);
    FD_SET(handle, &write_fds);

    timeval timeout = {};
    timeval *timeout_ptr = nullptr;

    if (timeout_ms > 0)
    {
        timeout.tv_sec = timeout_ms / 1000;
        timeout.tv_usec = (timeout_ms % 1000) * 1000;
        timeout_ptr = &timeout;
    }

    // Wait for write availability
    const int result = select(handle + 1, nullptr, &write_fds, nullptr, timeout_ptr);

    if (result < 0)
    {
        // Handle EINTR (interrupted system call)
        if (errno == EINTR)
        {
            return 0; // Treat as timeout
        }

        return -1;
    }

    return result; // 1 if ready, 0 if timeout
}

Socket::Status SocketImpl::getLastStatus()
{
    if (errno == EWOULDBLOCK)
        return Socket::Status::WouldBlock;

    switch (errno)
    {
    case EAGAIN:
        return Socket::Status::Again;
    case EINPROGRESS:
        return Socket::Status::InProgress;
    case ECONNABORTED:
        return Socket::Status::ConnectionAborted;
    case ECONNRESET:
        return Socket::Status::ConnectionReset;
    case ETIMEDOUT:
        return Socket::Status::Timeout;
    case ENETRESET:
        return Socket::Status::NetworkReset;
    case ENOTCONN:
        return Socket::Status::NotConnected;
    case ECONNREFUSED:
        return Socket::Status::ConnectionRefused;
    case EPIPE:
        return Socket::Status::PipeError;
    default:
        return Socket::Status::Error;
    }
}

const char *SocketImpl::getLastError()
{
    return strerror(errno);
}

} // namespace sck::impl