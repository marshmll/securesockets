#include <sockets/UDPSocket.hpp>

namespace sck
{

UDPSocket::UDPSocket() : Socket(Type::UDP)
{
}

UDPSocket::~UDPSocket()
{
    close();
}

Socket::Status UDPSocket::bind(const unsigned short port, const IPAddress &address)
{
    close();
    create();

    if (address == IPAddress::Broadcast)
    {
        return Status::Error;
    }

    sockaddr_in addr = impl::SocketImpl::createAddress(address.toInteger(), port);

    if (::bind(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << "Failed to bind UDP socket to port: " << port << std::endl;
    }

    return Status::Good;
}

void UDPSocket::unbind()
{
    close();
}

Socket::Status UDPSocket::send(const void *data, const size_t size, const IPAddress &address, const unsigned short port)
{
    create();

    if (size > MaxDatagramUsableSize)
    {
        std::cerr << "Failed to send data because it's size (" << size << " bytes) is too big for datagram size ("
                  << MaxDatagramUsableSize << " bytes). Check sck::UDPSocket::MaxDatagramUsableSize" << std::endl;

        return Status::Error;
    }

    sockaddr_in addr = impl::SocketImpl::createAddress(address.toInteger(), port);

    ssize_t sent = sendto(getSystemHandle(), reinterpret_cast<const char *>(data), size, 0,
                          reinterpret_cast<sockaddr *>(&addr), sizeof(addr));

    if (sent == -1)
        return impl::SocketImpl::getLastStatus();

    return Status::Good;
}

Socket::Status UDPSocket::recv(void *const buf, const size_t size, size_t &received, IPAddress &remote_address,
                               unsigned short &remote_port)
{
    received = 0;
    remote_port = 0;

    if (!buf)
    {
        std::cerr << "Failed to receive data because the destination buffer is invalid" << std::endl;
        return Status::Error;
    }

    sockaddr_in addr = impl::SocketImpl::createAddress(INADDR_ANY, 0);

    impl::SocketImpl::AddrLen addr_len = sizeof(addr);

    received = static_cast<size_t>(recvfrom(getSystemHandle(), reinterpret_cast<char *const>(buf), size, 0,
                                            reinterpret_cast<sockaddr *>(&addr), &addr_len));

    remote_address = IPAddress(ntohl(addr.sin_addr.s_addr));
    remote_port = addr.sin_port;

    return Status::Good;
}

} // namespace sck