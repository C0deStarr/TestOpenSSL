#include "tls_ctx.h"
#include <iostream>
#include <openssl/err.h>
using namespace std;


/*
https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_verify.html
*/
typedef struct {
	int verbose_mode;
	int verify_depth;
	int always_continue;
} mydata_t;
int mydata_index;
static int verify_cb(int preverify_ok, X509_STORE_CTX* ctx)
{
	char    buf[256];
	X509* err_cert;
	int     err, depth;
	SSL* ssl = nullptr;
	//mydata_t* mydata;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = (SSL*)X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	//mydata = (mydata_t*)SSL_get_ex_data(ssl, mydata_index);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

	/*
	 * Catch a too long certificate chain. The depth limit set using
	 * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
	 * that whenever the "depth>verify_depth" condition is met, we
	 * have violated the limit and want to log this error condition.
	 * We must do it here, because the CHAIN_TOO_LONG error would not
	 * be found explicitly; only errors introduced by cutting off the
	 * additional certificates would be logged.
	 */
	// if (depth > mydata->verify_depth) {
	// 	preverify_ok = 0;
	// 	err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
	// 	X509_STORE_CTX_set_error(ctx, err);
	// }
	if (!preverify_ok) {
		printf("verify error:num=%d:%s:depth=%d:%s\n", err,
			X509_verify_cert_error_string(err), depth, buf);
	}
	// else if (mydata->verbose_mode) {
	// 	printf("depth=%d:%s\n", depth, buf);
	// }

	/*
	 * At this point, err contains the last verification error. We can use
	 * it for something special
	 */
	 
	if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
		X509_NAME_oneline(X509_get_issuer_name(err_cert), buf, 256);
		printf("issuer= %s\n", buf);
	}

	//if (mydata->always_continue)
	//	return 1;
	//else
		return preverify_ok;
}



TLS_CTX::~TLS_CTX()
{
	if (_mp_ssl_ctx)
	{
		SSL_CTX_free(_mp_ssl_ctx);
		_mp_ssl_ctx = 0;
	}
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
		VerifyCRT(client_crt);
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

bool TLS_CTX::InitClient(const char* server_crt
	, const char* cacert)
{
	bool bRet = true;
	if (!server_crt || !cacert)
	{
		return false;
	}
	_mp_ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!_mp_ssl_ctx)
	{
		ERR_print_errors_fp(stderr);
		return false;
	}

	// trust ca first
	bRet = SSL_CTX_load_verify_locations(_mp_ssl_ctx, cacert, 0);
	//bRet = SSL_CTX_use_certificate_chain_file(_mp_ssl_ctx, cacert);
	bRet = VerifyCRT(server_crt);
	return bRet;
}

bool TLS_CTX::VerifyCRT(const char* crt)
{
	bool bRet = false;
	if(crt)
	{
		bRet = SSL_CTX_load_verify_locations(_mp_ssl_ctx, crt, 0);
		SSL_CTX_set_verify(_mp_ssl_ctx, SSL_VERIFY_PEER, verify_cb);
	}
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
		// re = SSL_get_error(_mp_ssl, re);
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

int MySSL::Read(char* buf, int nBuf)
{
	if (!_mp_ssl)return 0;
	return SSL_read(_mp_ssl, buf, nBuf);
}

int MySSL::Write(const char* data, int nData)
{
	if (!_mp_ssl)return 0;
	return SSL_write(_mp_ssl, data, nData);
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
