#ifndef SOCKETUTILS_H
#define SOCKETUTILS_H

namespace sck
{
#define CHK_NULL(p, msg)                                                                                               \
    if (p == NULL)                                                                                                     \
    {                                                                                                                  \
        std::cerr << msg << std::endl;                                                                                 \
        return false;                                                                                                  \
    }

#define CHK_ERR(err, msg)                                                                                              \
    if (err == -1)                                                                                                     \
    {                                                                                                                  \
        std::cerr << msg << std::endl;                                                                                 \
        return false;                                                                                                  \
    }

#define CHK_SSL(ssl, msg)                                                                                              \
    if (ssl == -1)                                                                                                     \
    {                                                                                                                  \
        ERR_print_errors_fp(stderr);                                                                                   \
        std::cerr << msg << std::endl;                                                                                 \
        return false;                                                                                                  \
    }
} // namespace sck

#endif // SOCKETUTILS_H