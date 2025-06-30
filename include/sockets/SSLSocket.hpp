#pragma once

#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#ifdef __unix__
#include "sockets/Unix/OpenSSL.hpp"
#endif

namespace sck
{

class SSLSocket : public Socket
{
  public:
    /**
     * @brief Virtual destructor to allow proper cleanup in derived classes
     */
    virtual ~SSLSocket();

    // Delete copy operations to prevent socket duplication
    SSLSocket(const SSLSocket &) = delete;
    SSLSocket &operator=(const SSLSocket &) = delete;

    /**
     * @brief Move constructor
     * @param socket The socket to move from
     */
    SSLSocket(SSLSocket &&socket) noexcept;

    /**
     * @brief Move assignment operator
     * @param socket The socket to move from
     * @return Reference to this socket
     */
    SSLSocket &operator=(SSLSocket &&socket) noexcept;

  protected:
#ifdef __unix__
    OpenSSL::SSLContext ctx = nullptr;
    OpenSSL::SSLConnection ssl = nullptr;
#endif

    /**
     * @brief Constructs a SSL socket of the specified type
     * @param type The type of socket to create (TCP or UDP)
     */
    explicit SSLSocket(Type type);

    using Socket::create;

    virtual void create(SocketHandle handle) override;

    virtual void close() override;
};

} // namespace sck