#include "rsa.h"
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/encoder.h>

#ifdef _WIN32
#include <openssl/applink.c>
#endif

void GenerateRSAKeys(int nBits, EVP_PKEY** ppKey)
{
	unsigned int primes = 3;
	unsigned int bits = 4096;
	//OSSL_PARAM params[3];


	//EVP_PKEY_CTX* pCtx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
	EVP_PKEY_CTX* pCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	
	if (!ppKey)
	{
		return;
	}

	do {
		if(EVP_PKEY_keygen_init(pCtx) <= 0) break;

		if(EVP_PKEY_CTX_set_rsa_keygen_bits(pCtx, nBits) <= 0) break;
		// params[0] = OSSL_PARAM_construct_uint("bits", &bits);
		// params[1] = OSSL_PARAM_construct_uint("primes", &primes);
		// params[2] = OSSL_PARAM_construct_end();
		// EVP_PKEY_CTX_set_params(pctx, params);

		if(EVP_PKEY_generate(pCtx, ppKey) <= 0) break;

		
	}while(0);
	EVP_PKEY_CTX_free(pCtx);
}

void ExportKeys(const EVP_PKEY* pKey
	, const char* pStrFilePubPath
	, const char* pStrFilePriPath
	, const unsigned char* pPassword
	, int nPass)
{
	FILE* pFilePub = NULL;
	FILE* pFilePri = NULL;
	const RSA *pRSA = NULL;
	OSSL_ENCODER_CTX* ectx = NULL;
	const char* format = "PEM";
	const char* structure = "PrivateKeyInfo"; /* PKCS#8 structure */
	if(!pStrFilePriPath || !pStrFilePubPath) return;



	do {
		ectx = OSSL_ENCODER_CTX_new_for_pkey(pKey,
			OSSL_KEYMGMT_SELECT_KEYPAIR
			| OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS,
			format, structure,
			NULL);
		if(!ectx) break;

		if (pPassword)
			OSSL_ENCODER_CTX_set_passphrase(ectx, pPassword, nPass);

		OSSL_ENCODER_CTX_set_cipher(ectx, "AES-256-CBC", NULL);
		//pRSA = EVP_PKEY_get0_RSA(pKey);
		//if(!pRSA) break;

		pFilePri = fopen(pStrFilePriPath, "w");
		//PEM_write_RSAPrivateKey(pFilePri
		//	, pRSA
		//	, EVP_des_ede3_cbc()
		//	, pPassword
		//	, nPass
		//	, NULL
		//	, NULL
		//);

		if (OSSL_ENCODER_to_fp(ectx, pFilePri)) {
			/* pkey was successfully encoded into the bio */
		}
		else {
			/* encoding failure */
		}

		pFilePub = fopen(pStrFilePubPath, "w");
		//PEM_write_RSA_PUBKEY(pFilePub, pRSA);
		PEM_write_PUBKEY_ex(pFilePub, pKey, NULL, NULL);

	}while(0);
	
	{
		if (ectx)
		{
			OSSL_ENCODER_CTX_free(ectx);
			ectx = NULL;
		}
		if (pFilePub)
		{
			fclose(pFilePub);
			pFilePub = NULL;
		}
		if (pFilePri)
		{
			fclose(pFilePri);
			pFilePri = NULL;
		}
	}

}

void test_rsa()
{
	EVP_PKEY* pKey = NULL;
	const OSSL_PARAM* pParams = NULL;
	BIO* bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	unsigned char arrPassword[] = "123";
	int nPass = sizeof(arrPassword) - 1;
	const char* pStrFilePubPath = "pub.pem";
	const char* pStrFilePriPath = "pri.pem";

	GenerateRSAKeys(1024, &pKey);

	std::cout << "params:" << std::endl;
	EVP_PKEY_print_params(bio_out, pKey, 4, NULL);
	std::cout << "public:" << std::endl;
	EVP_PKEY_print_public(bio_out, pKey, 4, NULL);
	std::cout << "private:" << std::endl;
	EVP_PKEY_print_private(bio_out, pKey, 4, NULL);
	pParams = EVP_PKEY_gettable_params(pKey);
	//while (pParams && pParams->key)
	{
		//std::cout << pParams->key << std::endl;
		//std::cout << std::hex << pParams->data << std::endl;
	}

	ExportKeys(pKey
		, pStrFilePubPath
		, pStrFilePriPath
		, arrPassword
		, nPass);
	BIO_free_all(bio_out);
}
