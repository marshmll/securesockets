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

SSLSocket::SSLSocket(SSLSocket &&socket) noexcept : Socket(socket.type, socket.handle, socket.blocking)
{
#ifdef __unix__
    ctx = socket.ctx;
    ssl = socket.ssl;

    socket.ctx = nullptr;
    socket.ssl = nullptr;
    socket.handle = impl::SocketImpl::InvalidHandle;
#endif
}

SSLSocket &SSLSocket::operator=(SSLSocket &&socket) noexcept
{
    if (&socket == this)
        return *this;

    close();

    type = socket.type;
    handle = socket.handle;
    blocking = socket.blocking;

#ifdef __unix__
    ctx = socket.ctx;
    ssl = socket.ssl;

    socket.ctx = nullptr;
    socket.ssl = nullptr;
#endif

    socket.handle = impl::SocketImpl::InvalidHandle;

    return *this;
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