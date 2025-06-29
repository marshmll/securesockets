#include "sockets/IPAddress.hpp"

namespace sck
{

const char *IPAddress::InvalidIPString = "INVALID";

const IPAddress IPAddress::Any(0);
const IPAddress IPAddress::LocalHost("127.0.0.1");
const IPAddress IPAddress::Broadcast("255.255.255.255");
const IPAddress IPAddress::Invalid;

IPAddress::IPAddress()
{
    initVariables();
}

IPAddress::IPAddress(const std::string &address)
{
    initVariables();

    auto resolution = IPAddress::resolve(address);

    if (resolution.has_value())
    {
        internetAddress = resolution->inAddress;
        ipString = resolution->ipString;
    }
    else
    {
        std::cerr << "Failed to resolve address" << std::endl;
    }
}

IPAddress::IPAddress(const uint32_t address)
{
    initVariables();

    internetAddress.s_addr = address;

    if (address > 0)
    {
        if (inet_ntop(AF_INET, &internetAddress.s_addr, ipString.data(), ipString.size()) == NULL)
        {
            std::cerr << "Failed to convert Internet Address (" << address << ") to string: " << strerror(errno)
                      << std::endl;
        }
    }
    else
    {
        ipString = "0.0.0.0";
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

bool IPAddress::operator==(IPAddress other) const
{
    return this->ipString == other.ipString && this->internetAddress.s_addr == other.internetAddress.s_addr;
}

bool IPAddress::operator!=(IPAddress other) const
{
    return this->ipString != other.ipString || this->internetAddress.s_addr != other.internetAddress.s_addr;
}

std::optional<IPAddress::Resolution> IPAddress::resolve(const std::string hostname)
{
    Resolution res = {};
    memset(reinterpret_cast<void *>(&res), 0, sizeof(res));

    if (inet_pton(AF_INET, hostname.c_str(), &res.inAddress.s_addr) == 1)
    {
        res.ipString = hostname;
        return res;
    }
    else
    {
        addrinfo hints = {};
        memset(&hints, 0, sizeof(hints));

        hints.ai_family = AF_INET;
        hints.ai_socktype = 0; // TCP or UDP

        addrinfo *result = nullptr;
        if (getaddrinfo(hostname.c_str(), NULL, &hints, &result) != 0)
        {
            std::cerr << "Invalid IP address or hostname: " << hostname << std::endl;
            return std::nullopt;
        }
        else
        {
            addrinfo *rp;

            for (rp = result; rp != NULL; rp = rp->ai_next)
            {
                if (rp->ai_family == AF_INET)
                {
                    struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;

                    auto str = IPAddress::convertInternetAddressToIpString(ipv4->sin_addr.s_addr);

                    if (str)
                    {
                        res.inAddress = ipv4->sin_addr;
                        res.ipString = *str;
                        return res;
                    }
                    else
                    {
                        std::cerr << "Failed to convert Internet Address (" << ipv4->sin_addr.s_addr
                                  << ") to string: " << strerror(errno) << std::endl;
                    }
                }
            }
        }
    }

    return std::nullopt;
}

std::optional<std::string> IPAddress::convertInternetAddressToIpString(const uint32_t address)
{
    std::string str;
    str.resize(INET_ADDRSTRLEN);

    if (inet_ntop(AF_INET, &address, str.data(), str.size()) == NULL)
        return std::nullopt;

    str.resize(strlen(str.c_str())); // Remove unused space at end of string
    return str;
}

void IPAddress::initVariables()
{
    memset(&internetAddress, 0, sizeof(internetAddress));
    ipString.resize(INET_ADDRSTRLEN);
    ipString = InvalidIPString;
}

} // namespace sck