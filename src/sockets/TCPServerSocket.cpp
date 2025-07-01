#include "sockets/TCPServerSocket.hpp"

namespace sck
{

TCPServerSocket::TCPServerSocket() : Socket(Type::TCP)
{
}

TCPServerSocket::~TCPServerSocket()
{
    close();
}

Socket::Status TCPServerSocket::listen(const unsigned short port, const IPAddress &address)
{
    close();
    create();

    if (address == IPAddress::Broadcast)
    {
        std::cerr << "Cannot listen on broadcast address" << std::endl;
        return Status::Error;
    }

    // Enable address reuse (avoid "address in use" after restart)
    int reuse = 1;
    if (setsockopt(getSystemHandle(), SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char *>(&reuse), sizeof(reuse)) <
        0)
    {
        std::cerr << "Failed to set SO_REUSEADDR: " << impl::SocketImpl::getLastError() << std::endl;
        // Continue anyway (not critical)
    }

    sockaddr_in addr = impl::SocketImpl::createAddress(address.toInteger(), port);

    if (bind(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << "Failed to bind to port " << port << ": " << impl::SocketImpl::getLastError() << std::endl;
        return Status::Error;
    }

    if (::listen(getSystemHandle(), SOMAXCONN) < 0)
    {
        std::cerr << "Failed to listen on port " << port << ": " << impl::SocketImpl::getLastError() << std::endl;
        return Status::Error;
    }

    return Status::Good;
}

void TCPServerSocket::close()
{
    Socket::close();
}

Socket::Status TCPServerSocket::accept(TCPClientSocket &socket, unsigned int timeout_ms, IPAddress *peer_address,
                                       unsigned short *peer_port)
{
    if (!impl::SocketImpl::isValidHandle(getSystemHandle()))
    {
        std::cerr << "Socket not listening" << std::endl;
        return Status::Error;
    }

    // Set non-blocking mode if timeout specified
    const bool was_blocking = isBlocking();
    if (timeout_ms > 0)
        setBlocking(false);

    sockaddr_in addr = {};
    impl::SocketImpl::AddrLen len = sizeof(addr);
    SocketHandle handle;

    // Wait for connection (with timeout if specified)
    if (timeout_ms > 0)
    {
        const int ready = impl::SocketImpl::waitRead(getSystemHandle(), timeout_ms);

        if (ready <= 0)
        {
            setBlocking(was_blocking);
            return Status::Timeout;
        }
    }

    handle = ::accept(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), &len);
    if (!impl::SocketImpl::isValidHandle(handle))
    {
        std::cerr << "Accept failed: " << impl::SocketImpl::getLastError() << std::endl;
        setBlocking(was_blocking);
        return Status::Error;
    }

    // Restore blocking mode if changed
    if (timeout_ms > 0)
        setBlocking(was_blocking);

    // Provide peer info if requested
    if (peer_address)
        *peer_address = IPAddress(addr.sin_addr.s_addr);

    if (peer_port)
        *peer_port = ntohs(addr.sin_port);

    socket.close();
    socket.create(handle);

    return Status::Good;
}

} // namespace sck