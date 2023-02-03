#ifndef _RSA_H
#define _RSA_H
#include <openssl/evp.h>

void GenerateRSAKeys(int nBits, EVP_PKEY** ppKey);


void ExportKeys(const EVP_PKEY* pKey
	, const char* pStrFilePubPath
	, const char* pStrFilePriPath
	, const unsigned char* pPassword
	, int nPass);

void test_rsa();
#endif // !_RSA_H
