#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#include <iostream>

using namespace sck;

Socket::Socket(Type type) : type(type), handle(impl::SocketImpl::invalidSocketHandle())
{
}

Socket::~Socket()
{
    close();
}

Socket::Socket(Socket &&socket) noexcept : type(socket.type), handle(socket.handle), blocking(socket.blocking)
{
}

Socket &Socket::operator=(Socket &&socket) noexcept
{
    if (&socket == this)
        return *this;

    close();

    type = socket.type;
    handle = socket.handle;
    blocking = socket.blocking;

    socket.handle = impl::SocketImpl::invalidSocketHandle();

    return *this;
}

void Socket::setBlocking(const bool blocking)
{
    if (impl::SocketImpl::isValidHandle(handle))
        impl::SocketImpl::setBlocking(handle, blocking);

    this->blocking = blocking;
}

bool Socket::isBlocking() const
{
    return blocking;
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
            if (setsockopt(handle, IPPROTO_TCP, TCP_NODELAY, &set_opt, sizeof(set_opt)) < 0)
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