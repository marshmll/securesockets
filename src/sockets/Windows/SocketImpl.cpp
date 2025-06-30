#include <sockets/SocketImpl.hpp>

#include <cstring>

namespace sck
{

sockaddr_in impl::SocketImpl::createAddress(const uint32_t addr, const unsigned short port)
{
    WinSock2::instance();

    sockaddr_in sa = {};
    memset(&sa, 0, sizeof(sa));

    sa.sin_addr.s_addr = htonl(addr);
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    return sa;
}

bool impl::SocketImpl::isValidHandle(SocketHandle handle)
{
    WinSock2::instance();

    return handle != InvalidHandle;
}

void impl::SocketImpl::close(SocketHandle handle)
{
    WinSock2::instance();

    closesocket(handle);
}

void impl::SocketImpl::setBlocking(SocketHandle handle, const bool blocking)
{
    WinSock2::instance();

    u_long block = blocking ? 0 : 1;
    ioctlsocket(handle, static_cast<long>(FIONBIO), &block);
}

Socket::Status impl::SocketImpl::getErrorStatus()
{
    WinSock2::instance();

    switch (WSAGetLastError())
    {
    case WSAEWOULDBLOCK:
        return Socket::Status::Blocked;
    case WSAEALREADY:
        return Socket::Status::Blocked;
    case WSAECONNABORTED:
        return Socket::Status::Disconnected;
    case WSAECONNRESET:
        return Socket::Status::Disconnected;
    case WSAETIMEDOUT:
        return Socket::Status::Disconnected;
    case WSAENETRESET:
        return Socket::Status::Disconnected;
    case WSAENOTCONN:
        return Socket::Status::Disconnected;
    case WSAEISCONN:
        return Socket::Status::Ready;
    default:
        return Socket::Status::Error;
    }
}

} // namespace sck