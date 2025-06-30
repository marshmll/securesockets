#include "sockets/TCPClientSocket.hpp"

namespace sck
{

TCPClientSocket::TCPClientSocket() : Socket(Type::TCP)
{
}

TCPClientSocket::~TCPClientSocket()
{
    disconnect();
}

std::optional<IPAddress> TCPClientSocket::getRemoteAddress() const
{
    if (getSystemHandle() != impl::SocketImpl::InvalidHandle)
    {
        sockaddr_in addr = {};
        impl::SocketImpl::AddrLen len = sizeof(addr);

        memset(&addr, 0, sizeof(addr));

        if (getpeername(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), &len) < 0)
        {
            return IPAddress(addr.sin_addr.s_addr);
        }
    }

    return std::nullopt;
}

unsigned short TCPClientSocket::getRemotePort() const
{
    if (getSystemHandle() != impl::SocketImpl::InvalidHandle)
    {
        sockaddr_in addr = {};
        impl::SocketImpl::AddrLen len = sizeof(addr);

        memset(&addr, 0, sizeof(addr));

        if (getpeername(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), &len) != -1)
        {
            return ntohs(addr.sin_port);
        }
    }

    return 0;
}

Socket::Status TCPClientSocket::connect(IPAddress remote_address, unsigned short remote_port, unsigned int timeout_ms)
{
    disconnect();
    create();

    sockaddr_in addr = impl::SocketImpl::createAddress(remote_address.toInteger(), remote_port);
    if (timeout_ms == 0)
    {
        if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            return impl::SocketImpl::getErrorStatus();
        }

        return Status::Ready;
    }

    const bool was_blocking = isBlocking();

    if (was_blocking)
        setBlocking(false);

    // Instantaneous connection
    if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) >= 0)
    {
        setBlocking(was_blocking);
        return Status::Ready;
    }

    Status status = impl::SocketImpl::getErrorStatus();

    if (!was_blocking)
        return status;

    if (status == Status::WouldBlock)
    {
        if (impl::SocketImpl::waitWrite(getSystemHandle(), timeout_ms) <= 0)
        {
            status = impl::SocketImpl::getErrorStatus();
        }
        else
        {
            if (getRemoteAddress().has_value())
            {
                status = Status::Ready;
            }
            else
            {
                status = impl::SocketImpl::getErrorStatus();
            }
        }
    }

    setBlocking(true);

    return status;
}

void TCPClientSocket::disconnect()
{
    close();
}

Socket::Status TCPClientSocket::send(const void *data, size_t size, const unsigned int timeout_ms)
{
    if (!isBlocking())
    {
        std::cerr << "Caution: Non-blocking mode may require handling partial sends manually" << std::endl;
    }

    size_t sent = 0;
    return send(data, size, sent, timeout_ms);
}

Socket::Status TCPClientSocket::send(const void *data, size_t size, size_t &sent, const unsigned int timeout_ms)
{
    if (!data || size == 0)
    {
        std::cerr << "Failed to send data: No data or invalid buffer." << std::endl;
        return Status::Error;
    }

    sent = 0;
    ssize_t bytes_sent = 0;

    while (sent < size)
    {
        bytes_sent = ::send(getSystemHandle(), reinterpret_cast<const char *>(data) + sent, size - sent, flags);

        if (bytes_sent > 0)
        {
            sent += bytes_sent;
        }
        else if (bytes_sent == 0)
        {
            // Peer closed the connection during send.
            return Status::Disconnected;
        }
        else // bytes_sent < 0 (error)
        {
            const Status status = impl::SocketImpl::getErrorStatus();

            if (status == Status::WouldBlock)
            {
                if (isBlocking())
                {
                    if (impl::SocketImpl::waitWrite(getSystemHandle(), timeout_ms) <= 0)
                    {
                        return impl::SocketImpl::getErrorStatus();
                    }

                    continue;
                }
                else
                {
                    // Non-blocking mode: Return Partial if some data was sent.
                    return (sent > 0) ? Status::Partial : impl::SocketImpl::getErrorStatus();
                }
            }

            // Other errors (e.g., ConnectionReset, InvalidSocket).
            return status;
        }
    }

    return Status::Ready;
}

Socket::Status TCPClientSocket::recv(void *data, size_t size, size_t &received, const unsigned int timeout_ms)
{
    received = 0;

    if (!data || size == 0)
    {
        std::cerr << "Failed to receive data: Invalid buffer or size" << std::endl;
        return Status::Error;
    }

    while (received < size)
    {
        const ssize_t bytes_received =
            ::recv(getSystemHandle(), static_cast<char *>(data) + received, size - received, flags);

        if (bytes_received > 0)
        {
            received += bytes_received;
        }
        else if (bytes_received == 0)
        {
            return Status::Disconnected; // Peer shutdown
        }
        else
        {
            const Status status = impl::SocketImpl::getErrorStatus();

            if (status == Status::WouldBlock)
            {
                if (isBlocking())
                {
                    continue; // Retry in blocking mode
                }
                else
                {
                    return (received > 0) ? Status::Partial : impl::SocketImpl::getErrorStatus();
                }
            }

            return status; // Other errors
        }
    }

    return Status::Ready;
}

} // namespace sck