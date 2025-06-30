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

    static SSLContext createContext(SSLMethod meth)
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

    static SSLConnection createConnection(SSLContext ctx)
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

    static void destroySSLConnection(SSLConnection ssl)
    {
        singleton();

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }

    static void destroySSLContext(SSLContext ctx)
    {
        singleton();

        if (ctx)
        {
            SSL_CTX_free(ctx);
        }
    }

    static void setSSLConnectionSocket(SSLConnection ssl, SocketHandle socket)
    {
        assert(ssl && "Cannot associate SSL connection to socket because SSL handle is invalid");
        assert((socket != -1) && "Cannot associate SSL connection to socket because socket is invalid");

        singleton();
        SSL_set_fd(ssl, socket);
    }

    [[nodiscard]] static bool connect(SSLConnection ssl)
    {
        assert(ssl && "Cannot connect because SSL connection is invalid");

        singleton();

        SSLStatus status;

        // While no fatal error
        while ((status = SSL_connect(ssl)) != -1)
        {
            switch (status)
            {
            case SSL_ERROR_WANT_READ:
                waitRead(ssl);
                continue;
            case SSL_ERROR_WANT_WRITE:
                waitWrite(ssl);
                continue;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                ERR_print_errors_fp(stderr);
                return false;
            }
        }

        return true;
    }

    static bool accept(SSLConnection ssl)
    {
        assert(ssl && "Cannot accept because SSL connection is invalid");

        singleton();

        int ret;

        // While no fatal error
        while ((ret = SSL_accept(ssl)) != -1)
        {
            switch (ret)
            {
            case SSL_ERROR_WANT_READ:
                waitRead(ssl);
                continue;
            case SSL_ERROR_WANT_WRITE:
                waitWrite(ssl);
                continue;
            case SSL_ERROR_ZERO_RETURN:
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                ERR_print_errors_fp(stderr);
                return false;
            }
        }

        return true;
    }

    static int write(SSLConnection ssl, const void *data, const size_t size, size_t &written)
    {
        assert(ssl && "Cannot get cipher name because SSL connection is invalid");
        assert(data && "Cannot write data because the data pointer is invalid");
        assert(size && "Cannot write data because the size is zero");

        return SSL_write_ex(ssl, data, size, &written);
    }

    static int read(SSLConnection ssl, void *const buf, const size_t size, size_t &read)
    {
        assert(ssl && "Cannot get cipher name because SSL connection is invalid");
        assert(buf && "Cannot read data because the buffer pointer is invalid");
        assert(size && "Cannot read data because the size is zero");

        return SSL_read_ex(ssl, buf, size, &read);
    }

    static int waitWrite(SSLConnection ssl, unsigned int timeout_ms = 0)
    {
        fd_set fds;
        int width, sock;

        // Get hold of the underlying file descriptor for the socket
        sock = SSL_get_fd(ssl);

        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        width = sock + 1;

        timeval time = {};
        time.tv_sec = static_cast<time_t>(timeout_ms / 1000);
        time.tv_usec = 0;

        return select(width, nullptr, &fds, nullptr, &time);
    }

    static int waitRead(SSLConnection ssl, unsigned int timeout_ms = 0)
    {
        fd_set fds;
        int width, sock;

        // Get hold of the underlying file descriptor for the socket
        sock = SSL_get_fd(ssl);

        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        width = sock + 1;

        timeval time = {};
        time.tv_sec = static_cast<time_t>(timeout_ms / 1000);
        time.tv_usec = 0;

        return select(width, &fds, nullptr, nullptr, &time);
    }

    static const char *getCipher(SSLConnection ssl)
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