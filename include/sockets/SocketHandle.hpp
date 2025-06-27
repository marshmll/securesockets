#pragma once

#ifdef __WIN32__
#include <basetsd.h> // For UINT_PTR definition on Windows
#endif

namespace sck
{
/**
 * @typedef SocketHandle
 * @brief Platform-independent socket handle type
 *
 * This type provides a unified way to represent socket handles across different platforms:
 * - On Windows: Uses UINT_PTR (unsigned integer type for pointers) to match Windows SOCKET type
 * - On Unix-like systems (Linux, macOS, etc.): Uses int as socket descriptors are file descriptors
 *
 * @note The actual underlying type differs between platforms:
 *       - Windows: UINT_PTR (typically 64-bit on 64-bit systems)
 *       - Unix: int (typically 32-bit signed integer)
 *
 * @see SocketImpl for platform-specific socket operations using this handle type
 */
#ifdef __WIN32__

using SocketHandle = UINT_PTR;

#else

using SocketHandle = int;

#endif
} // namespace sck