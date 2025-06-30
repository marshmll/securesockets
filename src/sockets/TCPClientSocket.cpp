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

    if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) >= 0)
    {
        setBlocking(was_blocking);
        return Status::Ready;
    }

    Status status = impl::SocketImpl::getErrorStatus();

    if (!was_blocking)
        return status;

    if (status == Status::Blocked)
    {
        fd_set selector;
        FD_ZERO(&selector);
        FD_SET(getSystemHandle(), &selector);

        timeval time = {};
        time.tv_sec = timeout_ms / 1000;
        time.tv_usec = 0;

        if (select(static_cast<int>(getSystemHandle() + 1), nullptr, &selector, nullptr, &time) > 0)
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
        else
        {
            status = impl::SocketImpl::getErrorStatus();
        }
    }

    setBlocking(true);

    return status;
}

void TCPClientSocket::disconnect()
{
    close();
}

Socket::Status TCPClientSocket::send(const void *data, size_t size)
{
    if (!isBlocking())
    {
        std::cerr << "WARNING: Partial sends might not be handled properly" << std::endl;
    }

    size_t sent = 0;
    return send(data, size, sent);
}

Socket::Status TCPClientSocket::send(const void *data, size_t size, size_t &sent)
{
    if (!data || size == 0)
    {
        std::cerr << "Failed to send data because there is no data to send" << std::endl;
        return Status::Error;
    }

    size_t bytes_sent = 0;

    for (sent = 0; sent < size; sent += bytes_sent)
    {
        bytes_sent = ::send(getSystemHandle(), reinterpret_cast<const char *>(data) + sent, size - sent, flags);

        if (bytes_sent < 0)
        {
            const Status status = impl::SocketImpl::getErrorStatus();

            if ((status == Status::Blocked) && (sent > 0))
            {
                return Status::Partial;
            }

            return status;
        }
    }

    return Status::Ready;
}

Socket::Status TCPClientSocket::recv(void *data, size_t size, size_t &received)
{
    received = 0;

    if (!data)
    {
        std::cerr << "Failed to receive data: Destination buffer is invalid" << std::endl;
        return Status::Error;
    }

    const size_t bytes_received = ::recv(getSystemHandle(), static_cast<char *>(data), size, flags);

    if (bytes_received > 0)
    {
        received = bytes_received;
        return Status::Ready;
    }

    if (bytes_received == 0)
    {
        return Socket::Status::Disconnected;
    }

    return impl::SocketImpl::getErrorStatus();
}

} // namespace sck