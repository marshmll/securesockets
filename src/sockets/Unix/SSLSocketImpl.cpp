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

        OpenSSL::SSLMethod meth = TLS_method();
        ctx = OpenSSL::createContext(meth);
        ssl = OpenSSL::createConnection(ctx);
        OpenSSL::setSSLConnectionSocket(ssl, getSystemHandle());
    }
}

void SSLSocket::close()
{
    if (impl::SocketImpl::isValidHandle(handle))
    {
        OpenSSL::destroySSLConnection(ssl);
        OpenSSL::destroySSLContext(ctx);

        impl::SocketImpl::close(handle);
        handle = impl::SocketImpl::InvalidHandle;
    }
}

} // namespace sck