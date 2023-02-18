#ifndef _TLS_CTX_H
#define _TLS_CTX_H

#include <openssl/ssl.h>

class MySSL {
public:
    MySSL();
    ~MySSL();

    bool SetSSL(SSL* ssl);
    // server
    bool Accept();
    // client
    bool Connect();

    void Close();
private:
    SSL* _mp_ssl = nullptr;
};

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
        , const char* client_crt = nullptr);

    bool InitSSL(int socket, MySSL& myssl);

private:
    SSL_CTX* _mp_ssl_ctx = nullptr;
};




#endif // !_TLS_CTX_H
