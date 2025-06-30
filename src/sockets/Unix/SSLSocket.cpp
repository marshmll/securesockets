#include "sockets/SSLSocket.hpp"

namespace sck
{

SSLSocket::SSLSocket(Type type) : Socket(type)
{
}

SSLSocket::~SSLSocket()
{
    close();
}

void SSLSocket::create(SocketHandle handle)
{
    if (!impl::SocketImpl::isValidHandle(this->handle))
    {
        this->handle = handle;
        setBlocking(blocking);

        ctx = OpenSSL::createContext(TLS_method());
        ssl = OpenSSL::create(ctx);
    }
}

void SSLSocket::close()
{
    if (impl::SocketImpl::isValidHandle(handle))
    {
        OpenSSL::destroy(ssl, ctx);
        impl::SocketImpl::close(handle);
        handle = impl::SocketImpl::invalidHandle();
    }
}

} // namespace sck