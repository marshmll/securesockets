#pragma once

#include <arpa/inet.h>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <optional>
#include <string>

namespace sck
{

class IPAddress
{
  public:
    static const IPAddress OSDefined;
    static const IPAddress LocalHost;
    static const IPAddress Broadcast;

    struct Resolution
    {
        std::string ipString;
        in_addr inAddress;
    };

    IPAddress(const std::string &address);
    IPAddress(const uint32_t address);

    const std::string &toString() const;
    const in_addr &toInternetAddress() const;
    const uint32_t &toInteger() const;

    bool operator==(IPAddress other) const;

    static std::optional<Resolution> resolve(const std::string hostname);
    static std::optional<std::string> convertInternetAddressToIpString(const uint32_t address);

  private:
    in_addr internetAddress;
    std::string ipString;

    void initVariables();
};
} // namespace sck