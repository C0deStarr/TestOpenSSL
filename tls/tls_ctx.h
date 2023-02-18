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

    int  Read(char* buf, int nBuf);
    int  Write(const char* data, int nData);


    void Close();
private:
    SSL* _mp_ssl = nullptr;
};

class TLS_CTX {
public:
    
    ~TLS_CTX();
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

    bool InitClient(const char* server_crt
        , const char* cacert);

    bool InitSSL(int socket, MySSL& myssl);

    bool VerifyCRT(const char* crt);

private:
    SSL_CTX* _mp_ssl_ctx = nullptr;
};




#endif // !_TLS_CTX_H
