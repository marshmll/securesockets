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
/**
 * @class IPAddress
 * @brief Represents and manipulates IPv4 addresses
 *
 * This class provides a convenient wrapper for IPv4 address operations including:
 * - Address resolution from strings and integers
 * - Conversion between different address formats
 * - Common address constants
 * - Network byte order handling
 */
class IPAddress
{
  public:
    /// @name Error Constants
    /// @{
    /**
     * @brief Convenience string for invalid ip string checks
     */
    static const char *InvalidIPString;
    /// @}

    /// @name Common Address Constants
    /// @{
    /**
     * @brief Special address indicating the OS should define the address
     */
    static const IPAddress Any;

    /**
     * @brief Localhost address (127.0.0.1)
     */
    static const IPAddress LocalHost;

    /**
     * @brief Broadcast address (255.255.255.255)
     */
    static const IPAddress Broadcast;

    /**
     * @brief Invalid address
     */
    static const IPAddress Invalid;
    /// @}

    /**
     * @struct Resolution
     * @brief Contains resolved address information
     */
    struct Resolution
    {
        std::string ipString; ///< Human-readable IP address (e.g., "192.168.1.1")
        in_addr inAddress;    ///< Binary address in network byte order
    };

    /// @name Constructors
    /// @{

    /**
     * @brief Construct a default IpAddress object.
     * @note Sets internet address and ip string to 0.
     */
    IPAddress();

    /**
     * @brief Construct from string representation
     * @param address IP address in string format (e.g., "192.168.1.1") or hostname
     * @note Performs DNS resolution if hostname is provided
     */
    IPAddress(const std::string &address);

    /**
     * @brief Construct from 32-bit integer
     * @param address IP address in network byte order
     * @warning The address needs to be in NETWORK BYTE ORDER. Use `ntohl` and `htonl` for conversions.
     */
    IPAddress(const uint32_t address);
    /// @}

    /// @name Conversion Methods
    /// @{
    /**
     * @brief Get string representation of the address
     * @return Const reference to the internal IP string
     */
    const std::string &toString() const;

    /**
     * @brief Get 32-bit integer representation
     * @return Const reference to the address as 32-bit integer (network byte order)
     * @warning The returned integer is in NETWORK BYTE ORDER. Use `ntohl and htonl` for conversions.
     */
    const uint32_t &toInteger() const;
    /// @}

    /**
     * @brief Equality comparison operator
     * @param other IPAddress to compare with
     * @return true if addresses are identical
     */
    bool operator==(IPAddress other) const;

    /**
     * @brief Inequality comparison operator
     * @param other IPAddress to compare with
     * @return true if addresses are not identical
     */
    bool operator!=(IPAddress other) const;

    /// @name Static Methods
    /// @{
    /**
     * @brief Resolve a hostname or IP string to address information
     * @param hostname Hostname or IP address string to resolve
     * @return Optional containing Resolution if successful, nullopt otherwise
     *
     * @note Handles both:
     * - Direct IP address strings (e.g., "192.168.1.1")
     * - Hostnames (performs DNS lookup)
     */
    static std::optional<Resolution> resolve(const std::string hostname);

    /**
     * @brief Convert 32-bit address to string representation
     * @param address Network byte order IP address
     * @return Optional containing IP string if conversion succeeded
     */
    static std::optional<std::string> convertInternetAddressToIpString(const uint32_t address);
    /// @}

  private:
    in_addr internetAddress; ///< Binary address in network byte order
    std::string ipString;    ///< String representation of the address

    /**
     * @brief Initialize internal variables
     *
     * Sets:
     * - internetAddress to zero
     * - ipString buffer to appropriate size
     */
    void initVariables();
};
} // namespace sck