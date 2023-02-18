#ifndef _TLS_CTX_H
#define _TLS_CTX_H

#include <openssl/ssl.h>

class TLS_cosket;

class TLS_CTX {
public:
    /**
     * @brief 
     * @param crt_file 
     * @param key_file 
     *      server's private key
     * @param ca_file 
     *      optional
     * @return 
    */
    bool InitServer(const char* server_crt
        , const char* server_key
        , const char* client_crt = 0);


private:
    SSL_CTX* _mp_ssl_ctx = 0;
};
#endif // !_TLS_CTX_H
