#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/SSLSocket.hpp"
#include "sockets/SocketImpl.hpp"

namespace sck
{

class SSLTCPClientSocket : public SSLSocket
{
  public:
    SSLTCPClientSocket();

    ~SSLTCPClientSocket();

    [[nodiscard]] std::optional<IPAddress> getRemoteAddress() const;

    [[nodiscard]] unsigned short getRemotePort() const;

    [[nodiscard]] Status connect(IPAddress remote_address, unsigned short remote_port, unsigned int timeout_ms = 0);

    void disconnect();

    [[nodiscard]] Status send(const void *data, size_t size, const unsigned short timeout_ms = 0);

    [[nodiscard]] Status send(const void *data, size_t size, size_t &sent, const unsigned short timeout_ms = 0);

    [[nodiscard]] Status recv(void *data, size_t size, size_t &received, const unsigned short timeout_ms = 0);
};

} // namespace sck