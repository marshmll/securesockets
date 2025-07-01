#pragma once

#ifdef __unix__

#include "sockets/SocketHandle.hpp"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <cassert>

namespace sck
{

struct OpenSSL
{
    using SSLMethod = const SSL_METHOD *;
    using SSLContext = SSL_CTX *;
    using SSLConnection = SSL *;
    using SSLStatus = unsigned long;

    OpenSSL()
    {
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
    }

    ~OpenSSL()
    {
        ERR_free_strings();
        EVP_cleanup();
    }

    static OpenSSL singleton()
    {
        static const OpenSSL ssl = OpenSSL();
        return ssl;
    }

    static SSLContext createContext(SSLMethod &meth)
    {
        assert(meth && "Cannot create SSL context because method is invalid");

        singleton();
        SSLContext ctx = SSL_CTX_new(meth);

        if (!ctx)
        {
            ERR_print_errors_fp(stderr);
            ctx = nullptr;
        }

        SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE); // Enable partial sends

        return ctx;
    }

    static SSLConnection createConnection(SSLContext &ctx)
    {
        assert(ctx && "Cannot initialize a SSL connection because context is invalid");

        singleton();

        SSLConnection ssl = SSL_new(ctx);

        if (!ssl)
        {
            ERR_print_errors_fp(stderr);
            ssl = nullptr;
        }

        return ssl;
    }

    static void destroySSLConnection(SSLConnection &ssl) noexcept
    {
        singleton();

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    static void destroySSLContext(SSLContext &ctx) noexcept
    {
        singleton();

        if (ctx)
        {
            SSL_CTX_free(ctx);
        }
    }

    static void setSSLConnectionSocket(SSLConnection &ssl, SocketHandle socket)
    {
        assert(ssl && "Cannot associate SSL connection to socket because SSL handle is invalid");
        assert((socket != -1) && "Cannot associate SSL connection to socket because socket is invalid");

        singleton();
        SSL_set_fd(ssl, socket);
    }

    [[nodiscard]] static bool connect(SSLConnection &ssl)
    {
        assert(ssl && "Cannot connect because SSL connection is invalid");
        singleton();

        int ret;
        while ((ret = SSL_connect(ssl)) <= 0)
        {
            const int ssl_err = SSL_get_error(ssl, ret);

            switch (ssl_err)
            {
            case SSL_ERROR_WANT_READ:
                if (waitRead(ssl) <= 0)
                    return false; // Timeout or error
                continue;

            case SSL_ERROR_WANT_WRITE:
                if (waitWrite(ssl) <= 0)
                    return false; // Timeout or error
                continue;

            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                ERR_print_errors_fp(stderr);
                return false;
            }
        }

        return true; // Only if SSL_connect returns 1
    }

    [[nodiscard]] static bool accept(SSLConnection &ssl)
    {
        assert(ssl && "Cannot accept because SSL connection is invalid");
        singleton();

        int ret;
        while ((ret = SSL_accept(ssl)) <= 0)
        {
            const int ssl_err = SSL_get_error(ssl, ret);

            switch (ssl_err)
            {
            case SSL_ERROR_NONE:
                // Should never happen with ret <= 0
                break;

            case SSL_ERROR_WANT_READ:
                if (waitRead(ssl) <= 0)
                    return false;
                continue;

            case SSL_ERROR_WANT_WRITE:
                if (waitWrite(ssl) <= 0)
                    return false;
                continue;

            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
            default:
                ERR_print_errors_fp(stderr);
                return false;
            }
        }

        return true; // Only if SSL_accept returns 1
    }

    static int write(SSLConnection &ssl, const void *data, const size_t size, size_t &written)
    {
        assert(ssl && "Cannot get cipher name because SSL connection is invalid");
        assert(data && "Cannot write data because the data pointer is invalid");
        assert(size && "Cannot write data because the size is zero");

        return SSL_write_ex(ssl, data, size, &written);
    }

    static int read(SSLConnection &ssl, void *const buf, const size_t size, size_t &read)
    {
        assert(ssl && "Cannot get cipher name because SSL connection is invalid");
        assert(buf && "Cannot read data because the buffer pointer is invalid");
        assert(size && "Cannot read data because the size is zero");

        return SSL_read_ex(ssl, buf, size, &read);
    }

    [[nodiscard]] static int waitWrite(SSL *ssl, unsigned int timeout_ms = 0)
    {
        if (!ssl)
        {
            errno = EBADF;
            return -1;
        }

        const int sock = SSL_get_fd(ssl);
        if (sock < 0)
        {
            errno = EBADF;
            return -1;
        }

        fd_set write_fds;
        FD_ZERO(&write_fds);
        FD_SET(sock, &write_fds);

        timeval timeout = {};
        timeval *timeout_ptr = nullptr;

        if (timeout_ms > 0)
        {
            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;
            timeout_ptr = &timeout;
        }

        // Wait for write availability
        const int result = select(sock + 1, nullptr, &write_fds, nullptr, timeout_ptr);

        if (result < 0)
        {
            // Handle EINTR (interrupted system call)
            if (errno == EINTR)
            {
                return 0; // Treat as timeout
            }

            return -1;
        }

        return result; // 1 if ready, 0 if timeout
    }

    [[nodiscard]] static int waitRead(SSL *ssl, unsigned int timeout_ms = 0)
    {
        if (!ssl)
        {
            errno = EBADF;
            return -1;
        }

        const int sock = SSL_get_fd(ssl);
        if (sock < 0)
        {
            errno = EBADF;
            return -1;
        }

        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);

        timeval timeout = {};
        timeval *timeout_ptr = nullptr;

        if (timeout_ms > 0)
        {
            timeout.tv_sec = timeout_ms / 1000;
            timeout.tv_usec = (timeout_ms % 1000) * 1000;
            timeout_ptr = &timeout;
        }

        // Wait for read availability
        const int result = select(sock + 1, &read_fds, nullptr, nullptr, timeout_ptr);

        if (result < 0)
        {
            // Handle EINTR (interrupted system call)
            if (errno == EINTR)
            {
                return 0; // Treat as timeout
            }

            return -1;
        }

        return result; // 1 if ready, 0 if timeout
    }

    static const char *getCipher(SSLConnection &ssl)
    {
        assert(ssl && "Cannot get cipher name because SSL connection is invalid");

        singleton();
        return SSL_get_cipher(ssl);
    }

    static SSLStatus getErrorStatus()
    {
        return ERR_get_error();
    }
};

} // namespace sck

#endif