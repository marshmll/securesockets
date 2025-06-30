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
    using SSLContext = SSL_CTX *;
    using SSLMethod = const SSL_METHOD *;
    using SSL = SSL *;

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
            ERR_print_errors_fp(stderr);

        return ctx;
    }

    static SSL create(SSLContext ctx)
    {
        assert(ctx && "Cannot initialize SSL because context is invalid");

        singleton();

        SSL ssl = SSL_new(ctx);

        if (!ssl)
            ERR_print_errors_fp(stderr);

        return ssl;
    }

    static void destroy(SSL ssl, SSLContext ctx)
    {
        singleton();

        if (ssl)
        {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        if (ctx)
        {
            SSL_CTX_free(ctx);
        }
    }

    static void setSSLSocket(SSL ssl, SocketHandle socket)
    {
        assert(ssl && "Cannot associate SSL to socket because SSL handle is invalid");
        assert((socket != -1) && "Cannot associate SSL to socket because socket is invalid");

        singleton();
        SSL_set_fd(ssl, socket);
    }

    static void connect(SSL ssl)
    {
        assert(ssl && "Cannot connect because SSL handle is invalid");

        singleton();

        if (SSL_connect(ssl) <= 0)
            ERR_print_errors_fp(stderr);
    }

    static void accept(SSL ssl)
    {
        assert(ssl && "Cannot accept because SSL handle is invalid");

        singleton();

        if (SSL_accept(ssl) <= 0)
            ERR_print_errors_fp(stderr);
    }

    static const char *getCipher(SSL ssl)
    {
        assert(ssl && "Cannot get cipher name because SSL handle is invalid");

        singleton();
        return SSL_get_cipher(ssl);
    }
};

} // namespace sck

#endif