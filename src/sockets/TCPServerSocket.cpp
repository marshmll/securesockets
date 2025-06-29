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
        return Status::Error;

    sockaddr_in addr = impl::SocketImpl::createAddress(address.toInteger(), port);

    if (bind(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0)
    {
        std::cerr << "Failed to bind socket server to port " << port << std::endl;
        return Status::Error;
    }

    if (::listen(getSystemHandle(), SOMAXCONN) < 0)
    {
        std::cerr << "Socket server failed to listen to port " << port << std::endl;
        return Status::Error;
    }

    return Status::Ready;
}

void TCPServerSocket::close()
{
    Socket::close();
}

Socket::Status TCPServerSocket::accept(TCPClientSocket &socket)
{
    if (!impl::SocketImpl::isValidHandle(getSystemHandle()))
    {
        std::cerr << "Failed to accept connections: Socket is not listening" << std::endl;
        return Status::Error;
    }

    sockaddr_in addr = {};
    impl::SocketImpl::AddrLen len = sizeof(addr);

    memset(&addr, 0, sizeof(addr));

    const SocketHandle handle = ::accept(getSystemHandle(), reinterpret_cast<sockaddr *>(&addr), &len);

    if (!impl::SocketImpl::isValidHandle(handle))
    {
        std::cerr << "Error during connection accept" << std::endl;
        return Status::Error;
    }

    socket.close();
    socket.create(handle);

    return Status::Ready;
}

} // namespace sck