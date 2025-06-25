#include "securesockets/SecureTCPClient.hpp"

using namespace sck;

SecureTCPClient::SecureTCPClient() : serverAddr("0.0.0.0"), serverPort(0)
{
    nullifyHandles();
}

SecureTCPClient::~SecureTCPClient()
{
    SSL_shutdown(ssl); /* send SSL/TLS close_notify */
    close(sd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
}

const bool SecureTCPClient::connect(const std::string &server_addr, const unsigned short int server_port)
{
    serverAddr = server_addr;
    serverPort = server_port;

    OpenSSL_add_ssl_algorithms();
    meth = TLS_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(meth);

    CHK_NULL(ctx, "[ SecureTCPClient ] Failed to create new SSL context")

    /* ----------------------------------------------- */
    /* Create a socket and connect to server using normal socket calls. */

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHK_ERR(sd, "[ SecureTCPClient ] Failed to create socket");

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(serverAddr.c_str());
    sa.sin_port = htons(serverPort);

    err = ::connect(sd, (struct sockaddr *)&sa, sizeof(sa));
    CHK_ERR(err, "[ SecureTCPClient ] Failed to connect socket to address " + serverAddr + " port " +
                     std::to_string(serverPort));

    /* ----------------------------------------------- */
    /* Now we have TCP conncetion. Start SSL negotiation. */

    ssl = SSL_new(ctx);
    CHK_NULL(ssl, "[ SecureTCPClient ] Failed to initialize SSL negotiation");
    SSL_set_fd(ssl, sd);

    err = SSL_connect(ssl);
    CHK_SSL(err, "[ SecureTCPClient ] Failed to complete SSL negotiation.");

    /* Following two steps are optional and not required for data exchange to be successful. */

    /* Get the cipher - opt */

    std::cout << "[ SecureTCPClient ] SSL connection using" << SSL_get_cipher(ssl) << "\n";

    /* Get server's certificate (note: beware of dynamic allocation) - opt */

    serverCert = SSL_get_peer_certificate(ssl);
    CHK_NULL(serverCert, "[ SecureTCPClient ] Certificate is null");
    std::cout << "[ SecureTCPClient ] Server certificate:" << "\n";

    str = X509_NAME_oneline(X509_get_subject_name(serverCert), 0, 0);
    CHK_NULL(str, "[ SecureTCPClient ] Failed to get subject from X509 certificate");
    std::cout << "\t subject: " << str << "\n";
    OPENSSL_free(str);

    str = X509_NAME_oneline(X509_get_issuer_name(serverCert), 0, 0);
    CHK_NULL(str, "[ SecureTCPClient ] Failed to get issuer from X509 certificate");
    std::cout << "\t issuer: " << str << "\n";
    OPENSSL_free(str);

    /* We could do all sorts of certificate verification stuff here before deallocating the certificate. */

    X509_free(serverCert);

    return true;
}

const bool SecureTCPClient::send(const void *data, const size_t size)
{
    err = SSL_write(ssl, data, size);
    CHK_SSL(err, "[ SecureTCPClient ] Failed to connect socket to address " + serverAddr + " port " +
                     std::to_string(serverPort));

    return true;
}

const int SecureTCPClient::receive(char *buffer, const size_t size)
{
    err = SSL_read(ssl, buffer, size - 1);
    CHK_SSL(err, "[ SecureTCPClient ] Failed to receive data.");

    buffer[err] = '\0';
    std::cout << "[ SecureTCPClient ] Got " << err << " chars: " << buffer << "\n";

    return err;
}

void SecureTCPClient::nullifyHandles()
{
    ctx = nullptr;
    ssl = nullptr;
    serverCert = nullptr;
    str = nullptr;
    meth = nullptr;
}
