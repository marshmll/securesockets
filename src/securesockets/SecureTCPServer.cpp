#include "securesockets/SecureTCPServer.hpp"

using namespace sck;

SecureTCPServer::SecureTCPServer(const std::filesystem::path &cert_path, const std::filesystem::path &priv_key_path)
    : certPath(cert_path), privKeyPath(priv_key_path)
{
    nullifyHandles();
}

SecureTCPServer::~SecureTCPServer()
{
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

const bool SecureTCPServer::listen(const unsigned short int port, const unsigned int queue_size)
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    meth = TLS_server_method();
    ctx = SSL_CTX_new(meth);

    CHK_NULL(ctx, "[ SecureTCPServer ] Failed to create SSL context")

    if (SSL_CTX_use_certificate_file(ctx, certPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        std::cerr << "[ SecureTCPServer ] Failed to load certificate from file: " << certPath << std::endl;
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, privKeyPath.c_str(), SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        std::cerr << "[ SecureTCPServer ] Failed to load private key from file: " << privKeyPath << std::endl;
        return false;
    }

    if (!SSL_CTX_check_private_key(ctx))
    {
        std::cerr << "[ SecureTCPServer ] Private key does not match the certificate public key" << std::endl;
        return false;
    }

    /* ----------------------------------------------- */
    /* Prepare TCP socket for receiving connections */

    listenSd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(listenSd, "[ SecureTCPServer ] Failed to create socket");

    memset(&saServer, 0, sizeof(saServer));
    saServer.sin_family = AF_INET;
    saServer.sin_addr.s_addr = INADDR_ANY;
    saServer.sin_port = htons(port); /* Server Port number */

    err = bind(listenSd, (struct sockaddr *)&saServer, sizeof(saServer));
    CHK_ERR(err, "[ SecureTCPServer ] Failed to bind socket to port: " + std::to_string(port));

    /* Receive a TCP connection. */

    err = ::listen(listenSd, 5);
    CHK_ERR(err, "[ SecureTCPServer ] Failed to listen for incoming connection requests");

    return true;
}

const bool SecureTCPServer::accept()
{
    clientLen = sizeof(saClient);
    sd = ::accept(listenSd, (struct sockaddr *)&saClient, &clientLen);
    CHK_ERR(sd, "[ SecureTCPServer ] Failed to accept incoming connection request");
    close(listenSd);

    std::cout << "[ SecureTCPServer ] Connection from " << saClient.sin_addr.s_addr << " port " << saClient.sin_port
              << "\n";

    /* ----------------------------------------------- */
    /* TCP connection is ready. Do server side SSL. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl, "[ SecureTCPServer ] Failed to start SSL negotiation");

    SSL_set_fd(ssl, sd);
    err = SSL_accept(ssl);
    CHK_SSL(err, "[ SecureTCPServer ] Failed to accept SSL negotiation");

    /* Get the cipher - opt */

    std::cout << "[ SecureTCPServer ] SSL connection using " << SSL_get_cipher(ssl) << "\n";

    /* Get client's certificate (note: beware of dynamic allocation) - opt */

    clientCert = SSL_get_peer_certificate(ssl);

    if (clientCert != NULL)
    {
        std::cout << "[ SecureTCPServer ] Client certificate:" << "\n";

        str = X509_NAME_oneline(X509_get_subject_name(clientCert), 0, 0);
        CHK_NULL(str, "[ SecureTCPServer ] Failed to read subject from client's certificate");
        std::cout << "\t subject: " << str << "\n";
        OPENSSL_free(str);

        str = X509_NAME_oneline(X509_get_issuer_name(clientCert), 0, 0);
        CHK_NULL(str, "[ SecureTCPServer ] Failed to read issuer from client's certificate");
        std::cout << "\t issuer: " << str << "\n";
        OPENSSL_free(str);

        /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */

        X509_free(clientCert);
    }
    else
        printf("Client does not have certificate.\n");

    return true;
}

const int SecureTCPServer::recv(char *const buf, const size_t size)
{
    err = SSL_read(ssl, buf, size - 1);
    buf[err] = '\0';

    return err;
}

const int SecureTCPServer::send(const char *data, const size_t size)
{
    err = SSL_write(ssl, data, size);
    return err;
}

void SecureTCPServer::nullifyHandles()
{
    ctx = nullptr;
    ssl = nullptr;
    clientCert = nullptr;
    str = nullptr;
    meth = nullptr;
}
