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

        if (getpeername(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), &len) != -1)
        {
            if (addr.sin_addr.s_addr == 0)
                return std::nullopt;
            else
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

    sockaddr_in address = impl::SocketImpl::createAddress(remote_address.toInteger(), remote_port);

    if (timeout_ms == 0)
    {
        if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) == -1)
            return impl::SocketImpl::getLastStatus();

        return Status::Good;
    }

    const bool was_blocking = isBlocking();

    if (was_blocking)
        setBlocking(false);

    if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&address), sizeof(address)) >= 0)
    {
        setBlocking(was_blocking);
        return Status::Good;
    }

    Status status = impl::SocketImpl::getLastStatus();

    // If socket was in non-blocking mode, return immediately
    if (!was_blocking)
        return status;

    if (status == Socket::Status::Again || status == Socket::Status::WouldBlock || status == Socket::Status::InProgress)
    {
        // Wait for something to write to the socket
        if (impl::SocketImpl::waitWrite(getSystemHandle()) > 0)
        {
            if (getRemoteAddress().has_value())
            {
                // Connection accepted
                std::cout << "Connected to " << getRemoteAddress()->toString() << std::endl;
                status = Status::Good;
            }
            else
            {
                // Connection refused
                status = Status::ConnectionRefused;
            }
        }
        else
        {
            // Failed to connect before timeout is over
            status = Status::Error;
        }
    }

    // Switch back to original blocking mode
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
    const auto start_time = std::chrono::steady_clock::now();

    while (sent < size)
    {
        const ssize_t bytes_sent =
            ::send(getSystemHandle(), static_cast<const char *>(data) + sent, size - sent, flags);

        if (bytes_sent > 0)
        {
            sent += bytes_sent;
            continue;
        }

        // Handle errors
        if (bytes_sent == 0)
        {
            return Status::ConnectionReset; // Peer shutdown
        }

        const Status err = impl::SocketImpl::getLastStatus();

        if (err == Status::Again || err == Socket::Status::WouldBlock)
        {
            if (!isBlocking())
            {
                return (sent > 0) ? Status::Partial : Status::WouldBlock;
            }

            // Check total elapsed time
            const auto now = std::chrono::steady_clock::now();
            const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count();

            if (elapsed >= timeout_ms)
            {
                return Status::Timeout;
            }

            // Wait for socket to become writable
            const auto remaining = timeout_ms - elapsed;

            if (impl::SocketImpl::waitWrite(getSystemHandle(), remaining) <= 0)
            {
                return impl::SocketImpl::getLastStatus();
            }
        }
        else
        {
            return err;
        }
    }

    return Status::Good;
}

Socket::Status TCPClientSocket::recv(void *data, size_t size, size_t &received, const unsigned int timeout_ms)
{
    received = 0;

    if (!data || size == 0)
    {
        std::cerr << "Cannot send data because there is no data to send" << std::endl;
    }

    const bool was_blocking = isBlocking();

    if (was_blocking)
    {
        while (true)
        {
            if (timeout_ms > 0)
                setBlocking(false);

            const ssize_t bytes_received = ::recv(getSystemHandle(), reinterpret_cast<char *>(data), size, flags);

            if (bytes_received > 0)
            {
                setBlocking(true);
                received += bytes_received;
                return Status::Good;
            }
            else if (bytes_received == 0)
            {
                setBlocking(true);
                return Status::ConnectionReset;
            }
            else
            {
                const Status err = impl::SocketImpl::getLastStatus();

                if (err == Status::Again || err == Status::WouldBlock || err == Status::InProgress)
                {
                    if (impl::SocketImpl::waitRead(getSystemHandle(), timeout_ms) <= 0)
                    {
                        return Status::Timeout;
                    }
                    else
                        continue;
                }
            }
        }
    }
    else
    {
        const ssize_t bytes_received = ::recv(getSystemHandle(), reinterpret_cast<char *>(data), size, flags);

        if (bytes_received > 0)
        {
            received += bytes_received;
            return Status::Good;
        }
        else if (bytes_received == 0)
        {
            return Status::ConnectionReset;
        }
        else
        {
            const Status err = impl::SocketImpl::getLastStatus();

            if (err == Status::Again || err == Status::WouldBlock || err == Status::InProgress)
            {
                return Status::Partial;
            }
        }
    }

    return impl::SocketImpl::getLastStatus();
}

} // namespace sck