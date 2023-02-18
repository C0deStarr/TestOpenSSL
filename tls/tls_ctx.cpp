#include "tls_ctx.h"
#include <iostream>
#include <openssl/err.h>
using namespace std;



static int verify_cb(int preverify_ok, X509_STORE_CTX* x509_ctx)
{
	if (preverify_ok == 0)
	{
		cout << "SSL cert validate failed!" << endl;
	}
	else
	{
		cout << "SSL cert validate success!" << endl;
	}
	// more over , check domain name etc.
	return preverify_ok;
}



bool TLS_CTX::InitServer(const char* server_crt
	, const char* server_key
	, const char* client_crt)
{
	bool bRet = true;
	int nRet = 0;

	// 1. init ctx
	_mp_ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (!_mp_ssl_ctx)
	{
		cerr << "SSL_CTX_new TLS_server_method failed!" << endl;
		return false;
	}

	// 2. load crt
	nRet = SSL_CTX_use_certificate_file(_mp_ssl_ctx, server_crt, SSL_FILETYPE_PEM);
	if (nRet <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "Load certificate success!" << endl;

	// 3. load server private key and check it
	nRet = SSL_CTX_use_PrivateKey_file(_mp_ssl_ctx, server_key, SSL_FILETYPE_PEM);
	if (nRet <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "Load PrivateKey success!" << endl;

	nRet = SSL_CTX_check_private_key(_mp_ssl_ctx);
	if (nRet <= 0)
	{
		//cout << "private key does not match the certificate!" << endl;
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "check_private_key success!" << endl;

	// 4. optionally, check client's crt
	if (client_crt)
	{
		SSL_CTX_set_verify(_mp_ssl_ctx, SSL_VERIFY_PEER, verify_cb);
		SSL_CTX_load_verify_locations(_mp_ssl_ctx, client_crt, 0);
	}
	return bRet;
}


bool TLS_CTX::InitSSL(int socket, MySSL &myssl)
{
	bool bRet = true;
	SSL * pSsl = nullptr;

	if (socket <= 0 || !_mp_ssl_ctx)
	{
		cout << "socket <=0 or ssl_ctx == 0" << endl;
		return false;
	}

	pSsl = SSL_new(_mp_ssl_ctx);
	if (!pSsl)
	{
		cerr << "SSL_new failed!" << endl;
		return false;
	}
	SSL_set_fd(pSsl, socket);
	myssl.SetSSL(pSsl);
	return bRet;
}

MySSL::MySSL() 
{
	_mp_ssl = nullptr; 
}
MySSL::~MySSL()
{
	Close();
}

bool MySSL::SetSSL(SSL* ssl)
{
	if (!_mp_ssl && ssl)
	{
		_mp_ssl = ssl;
		return true;
	}
	return false;
}



bool MySSL::Accept()
{
	bool bRet = true;
	if (!_mp_ssl)
		return false;

	// wait for a TLS/SSL client to initiate a TLS/SSL handshake
	int re = SSL_accept(_mp_ssl);
	if (re <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "SSL_accept success!" << endl;
	return bRet;
}

bool MySSL::Connect()
{
	bool bRet = true;
	if (!_mp_ssl)
		return false;

	// initiate the TLS/SSL handshake with an TLS/SSL server
	int re = SSL_connect(_mp_ssl);
	if (re <= 0)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}
	cout << "SSL_connect success!" << endl;
	return bRet;
}

void MySSL::Close()
{
	if (_mp_ssl)
	{
		// shut down a TLS/SSL connection
		SSL_shutdown(_mp_ssl);
		// free an allocated SSL structure
		SSL_free(_mp_ssl);
		_mp_ssl = nullptr;
	}
}
