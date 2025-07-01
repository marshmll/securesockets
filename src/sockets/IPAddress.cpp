#include "sockets/IPAddress.hpp"

namespace sck
{

const char *IPAddress::InvalidIPString = "INVALID";

const IPAddress IPAddress::Any(INADDR_ANY);
const IPAddress IPAddress::LocalHost("127.0.0.1");
const IPAddress IPAddress::Broadcast("255.255.255.255");
const IPAddress IPAddress::Invalid;

IPAddress::IPAddress()
{
    clear();
}

IPAddress::IPAddress(const std::string &address)
{
    clear();

    auto resolution = IPAddress::resolve(address);
    if (!resolution)
    {
        throw std::invalid_argument("Failed to resolve address: " + address);
    }

    internetAddress = resolution->inAddress;
    ipString = resolution->ipString;
}

IPAddress::IPAddress(uint32_t address)
{
    clear();
    internetAddress.s_addr = address;

    char buffer[INET_ADDRSTRLEN];

    if (inet_ntop(AF_INET, &internetAddress, buffer, sizeof(buffer)))
    {
        ipString = buffer;
    }
    else
    {
        throw std::runtime_error("Failed to convert address to string: " + std::string(strerror(errno)));
    }
}

const std::string &IPAddress::toString() const
{
    return ipString;
}

const uint32_t IPAddress::toInteger() const
{
    return internetAddress.s_addr;
}

bool IPAddress::operator==(const IPAddress &other) const
{
    return internetAddress.s_addr == other.internetAddress.s_addr;
}

bool IPAddress::operator!=(const IPAddress &other) const
{
    return !(*this == other);
}

std::optional<IPAddress::Resolution> IPAddress::resolve(const std::string &hostname)
{
    Resolution res{};

    // First try to parse as dotted-decimal notation
    if (inet_pton(AF_INET, hostname.c_str(), &res.inAddress) == 1)
    {
        res.ipString = hostname;
        return res;
    }

    // If not an IP address, try DNS resolution
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = 0;
    hints.ai_flags = AI_ADDRCONFIG;

    addrinfo *result = nullptr;
    if (getaddrinfo(hostname.c_str(), nullptr, &hints, &result) != 0)
    {
        return std::nullopt;
    }

    // Take the first IPv4 address found
    for (auto rp = result; rp != nullptr; rp = rp->ai_next)
    {
        if (rp->ai_family == AF_INET)
        {
            auto ipv4 = reinterpret_cast<sockaddr_in *>(rp->ai_addr);
            res.inAddress = ipv4->sin_addr;

            char buffer[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &res.inAddress, buffer, sizeof(buffer)))
            {
                res.ipString = buffer;
                freeaddrinfo(result);
                return res;
            }
        }
    }

    freeaddrinfo(result);
    return std::nullopt;
}

void IPAddress::clear()
{
    internetAddress.s_addr = INADDR_NONE;
    ipString = InvalidIPString;
}

} // namespace sck