#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#include <iostream>

namespace sck
{

Socket::Socket(Type type) : type(type), handle(impl::SocketImpl::InvalidHandle), blocking(true)
{
}

Socket::Socket(Type type, SocketHandle handle, bool blocking) : type(type), handle(handle), blocking(blocking)
{
}

Socket::~Socket()
{
    close();
}

Socket::Socket(Socket &&socket) noexcept : type(socket.type), handle(socket.handle), blocking(socket.blocking)
{
    socket.handle = impl::SocketImpl::InvalidHandle;
}

Socket &Socket::operator=(Socket &&socket) noexcept
{
    if (&socket == this)
        return *this;

    close();

    type = socket.type;
    handle = socket.handle;
    blocking = socket.blocking;

    socket.handle = impl::SocketImpl::InvalidHandle;

    return *this;
}

void Socket::setBlocking(const bool blocking)
{
    if (impl::SocketImpl::isValidHandle(handle))
        impl::SocketImpl::setBlocking(handle, blocking);

    this->blocking = blocking;
}

unsigned short Socket::getBoundPort() const
{
    if (impl::SocketImpl::isValidHandle(getSystemHandle()))
    {
        sockaddr_in sa = {};
        memset(&sa, 0, sizeof(sa));

        impl::SocketImpl::AddrLen size = sizeof(sa);

        if (getsockname(getSystemHandle(), reinterpret_cast<sockaddr *>(&sa), &size) >= 0)
        {
            return ntohs(sa.sin_port);
        }
    }

    return 0; // Failed to retrieve port
}

bool Socket::isBlocking() const
{
    return blocking;
}

Socket::Status Socket::getLastStatus() const
{
    return impl::SocketImpl::getLastStatus();
}

std::string Socket::getStatusMessage(const Status status)
{
    switch (status)
    {
        // clang-format off
    case Status::Good:              return "No error";
    case Status::Partial:           return "Partial transfer completed";
    case Status::Again:             return "Resource temporarily unavailable";
    case Status::WouldBlock:        return "Operation would block";
    case Status::InProgress:        return "Operation in progress";
    case Status::ConnectionAborted: return "Connection aborted";
    case Status::ConnectionReset:   return "Connection reset by peer";
    case Status::Timeout:           return "Operation timed out";
    case Status::NetworkReset:      return "Network dropped connection";
    case Status::NotConnected:      return "Socket is not connected";
    case Status::ConnectionRefused: return "Connection refused";
    case Status::PipeError:         return "Broken pipe";
    case Status::Error:             return "General socket error";
    default:                        return "Unknown error status";
        // clang-format on
    }
}

SocketHandle Socket::getSystemHandle() const
{
    return handle;
}

void Socket::create()
{
    if (!impl::SocketImpl::isValidHandle(this->handle))
    {
        const SocketHandle handle = socket(AF_INET, type == Type::TCP ? SOCK_STREAM : SOCK_DGRAM, 0);

        if (!impl::SocketImpl::isValidHandle(handle))
        {
            std::cerr << "Failed to create socket" << std::endl;
            return;
        }

        create(handle);
    }
}

void Socket::create(SocketHandle handle)
{
    if (!impl::SocketImpl::isValidHandle(this->handle))
    {
        this->handle = handle;

        setBlocking(blocking);

        if (type == Type::TCP)
        {
            // Disable TCP buffering
            int set_opt = 1;
            if (setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&set_opt), sizeof(set_opt)) < 0)
            {
                std::cerr << "Failed to set socket option \"TCP_NODELAY\". TCP packets will be buffered!" << std::endl;
            }

            // Disable SIGPIPE signal on disconnection for MACOSX
#ifdef __APPLE__
            if (setsockopt(m_socket, SOL_SOCKET, SO_NOSIGPIPE, &set_opt, sizeof(set_opt)) < 0)
            {
                std::cerr << "Failed to set socket option \"SO_NOSIGPIPE\"" << std::endl;
            }
#endif
        }
        else if (type == Type::UDP)
        {
            // Set broadcast opt by default for UDP sockets
            int set_opt = 1;
            if (setsockopt(handle, SOL_SOCKET, SO_BROADCAST, reinterpret_cast<char *>(&set_opt), sizeof(set_opt)) < 0)
            {
                std::cerr << "Failed to set socket option \"SO_BROADCAST\" for UDP socket" << std::endl;
            }
        }
    }
}

void Socket::close()
{
    if (impl::SocketImpl::isValidHandle(handle))
    {
        impl::SocketImpl::close(handle);
        handle = impl::SocketImpl::InvalidHandle;
    }
}

} // namespace sck