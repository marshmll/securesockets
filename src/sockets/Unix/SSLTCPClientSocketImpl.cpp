#include "sockets/SSLTCPClientSocket.hpp"

namespace sck
{

SSLTCPClientSocket::SSLTCPClientSocket() : SSLSocket(Type::TCP)
{
}

SSLTCPClientSocket::~SSLTCPClientSocket()
{
    disconnect();
}

std::optional<IPAddress> SSLTCPClientSocket::getRemoteAddress() const
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

unsigned short SSLTCPClientSocket::getRemotePort() const
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

Socket::Status SSLTCPClientSocket::connect(IPAddress remote_address, unsigned short remote_port,
                                           unsigned int timeout_ms)
{
    disconnect();
    create();

    const bool was_blocking = isBlocking();
    Status status = Status::Ready;

    sockaddr_in addr = impl::SocketImpl::createAddress(remote_address.toInteger(), remote_port);

    if (timeout_ms == 0)
    {
        if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
        {
            return impl::SocketImpl::getErrorStatus();
        }

        if (!was_blocking)
            setBlocking(true);

        // SSL handshake is done in blocking mode.
        if (!OpenSSL::connect(ssl))
        {
            status = Status::SSLError;
        }

        if (!was_blocking)
            setBlocking(false);

        return status;
    }

    if (was_blocking)
        setBlocking(false);

    // Instantaneous connection
    if (::connect(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) >= 0)
    {
        setBlocking(was_blocking);

        if (!OpenSSL::connect(ssl))
        {
            status = Status::SSLError;
        }

        return status;
    }

    status = impl::SocketImpl::getErrorStatus();

    // Return instantly if socket wasn't blocking
    if (!was_blocking)
        return status;

    // If socket is not busy, then some error ocurred
    if (status != Status::WouldBlock)
    {
        return status;
    }

    // Wait for timeout
    fd_set selector;
    FD_ZERO(&selector);
    FD_SET(getSystemHandle(), &selector);

    timeval time = {};
    time.tv_sec = static_cast<time_t>(timeout_ms / 1000);
    time.tv_usec = 0;

    // If nothing happens to socket
    if (select(static_cast<int>(getSystemHandle() + 1), nullptr, &selector, nullptr, &time) < 0)
    {
        status = impl::SocketImpl::getErrorStatus();
    }

    if (!getRemoteAddress().has_value())
    {
        status = impl::SocketImpl::getErrorStatus();
        return status;
    }

    setBlocking(was_blocking);

    if (!OpenSSL::connect(ssl))
    {
        status = Status::SSLError;
    }

    return status;
}

void SSLTCPClientSocket::disconnect()
{
    close();
}

Socket::Status SSLTCPClientSocket::send(const void *data, size_t size, const unsigned short timeout_ms)
{
    if (!isBlocking())
    {
        std::cerr << "WARNING: Partial sends might not be handled properly" << std::endl;
    }

    size_t sent = 0;
    return send(data, size, sent, timeout_ms);
}

Socket::Status SSLTCPClientSocket::send(const void *data, size_t size, size_t &sent, const unsigned short timeout_ms)
{
    if (!data || size == 0)
    {
        std::cerr << "Failed to send data: There is no data to send" << std::endl;
        return Status::Error;
    }

    sent = 0;
    size_t bytes_sent = 0;

    while (sent < size)
    {
        int ret = OpenSSL::write(ssl, reinterpret_cast<const char *>(data) + sent, size - sent, bytes_sent);

        if (ret <= 0)
        {
            OpenSSL::SSLStatus status = OpenSSL::getErrorStatus();

            if (status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE)
            {
                if (isBlocking())
                {
                    if (OpenSSL::waitWrite(ssl, timeout_ms) <= 0)
                    {
                        return impl::SocketImpl::getErrorStatus();
                    }

                    bytes_sent = 0; // Reset since we're retrying
                    continue;
                }
                else
                {
                    // Non-blocking mode: Return Partial if some data was sent
                    return (sent > 0) ? Status::Partial : impl::SocketImpl::getErrorStatus();
                }
            }
            else if (status == SSL_ERROR_ZERO_RETURN)
            {
                // Peer disconnected during send
                return Status::Disconnected;
            }
            else
            {
                // Other SSL errors (SSL_ERROR_SSL, SSL_ERROR_SYSCALL)
                return Status::SSLError;
            }
        }

        sent += bytes_sent;
        bytes_sent = 0; // Reset for next iteration
    }

    return Status::Ready;
}

Socket::Status SSLTCPClientSocket::recv(void *data, size_t size, size_t &received, const unsigned short timeout_ms)
{
    received = 0;

    if (!data || size == 0)
    {
        std::cerr << "Failed to receive data: Destination buffer is invalid" << std::endl;
        return Status::Error;
    }

    size_t bytes_received = 0;
    int ret;

    do
    {
        ret = OpenSSL::read(ssl, data, size, bytes_received);
        if (ret <= 0)
        {
            OpenSSL::SSLStatus status = OpenSSL::getErrorStatus();

            if ((status == SSL_ERROR_WANT_READ || status == SSL_ERROR_WANT_WRITE))
            {
                if (isBlocking())
                {
                    if (OpenSSL::waitRead(ssl, timeout_ms) <= 0)
                    {
                        return impl::SocketImpl::getErrorStatus();
                    }

                    continue;
                }
                else
                {
                    return Status::Partial;
                }
            }
            else if (status == SSL_ERROR_ZERO_RETURN)
            {
                return Status::Disconnected;
            }
            else if ((status == SSL_ERROR_SSL) || (status == SSL_ERROR_SYSCALL))
            {
                return Status::SSLError;
            }

            return impl::SocketImpl::getErrorStatus();
        }

        received = bytes_received;
        return Status::Ready;

    } while (isBlocking());

    return impl::SocketImpl::getErrorStatus();
}

} // namespace sck