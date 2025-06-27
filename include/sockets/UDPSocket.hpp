#pragma once

#include "sockets/IPAddress.hpp"
#include "sockets/Socket.hpp"
#include "sockets/SocketImpl.hpp"

#include <cstddef>
#include <cstring>
#include <iostream>
#include <vector>

namespace sck
{
class UDPSocket : public Socket
{
  public:
    static constexpr size_t MaxDatagramUsableSize = 65507;

    UDPSocket();
    ~UDPSocket();

    [[nodiscard]] unsigned short getBoundPort() const;
    [[nodiscard]] Status bind(const unsigned short port, const IPAddress &ip = IPAddress::OSDefined);
    void unbind();
    [[nodiscard]] Status send(const void *data, const size_t size, const IPAddress &ip, const unsigned short port);
    [[nodiscard]] Status recv(void *const buf, const size_t size, size_t &received, IPAddress &remote_ip,
                              unsigned short &port);

  private:
    std::vector<std::byte> buffer;
};
} // namespace sck