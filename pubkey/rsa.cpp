#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>

void GenerateRSAKeys()
{
	unsigned int primes = 3;
	unsigned int bits = 4096;
	OSSL_PARAM params[3];
	EVP_PKEY* pkey = NULL;
	BIO * bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);

	EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);

	EVP_PKEY_keygen_init(pctx);

	params[0] = OSSL_PARAM_construct_uint("bits", &bits);
	params[1] = OSSL_PARAM_construct_uint("primes", &primes);
	params[2] = OSSL_PARAM_construct_end();
	EVP_PKEY_CTX_set_params(pctx, params);

	EVP_PKEY_generate(pctx, &pkey);
	EVP_PKEY_print_private(bio_out, pkey, 0, NULL);
	EVP_PKEY_CTX_free(pctx);
	BIO_free_all(bio_out);
}