// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// OpenSSL-based implementation of csr_gen.h.

#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "azure_c_shared_utility/csr_gen.h"
#include "azure_c_shared_utility/azure_base64.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/strings.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/xlogging.h"
#include "macro_utils/macro_utils.h"

int csr_gen_ec_p256(const char* common_name, char** csr_base64, char** private_key_pem)
{
    int result = MU_FAILURE;
    EVP_PKEY* pkey = NULL;
    X509_REQ* req = NULL;
    unsigned char* der_buf = NULL;
    BUFFER_HANDLE der_buffer = NULL;
    STRING_HANDLE b64 = NULL;
    BIO* bio = NULL;
    char* csr_out = NULL;
    char* key_out = NULL;

    if (common_name == NULL || csr_base64 == NULL || private_key_pem == NULL)
    {
        LogError("Invalid argument to csr_gen_ec_p256");
        return MU_FAILURE;
    }

    *csr_base64 = NULL;
    *private_key_pem = NULL;

    do
    {
        if ((pkey = EVP_EC_gen("P-256")) == NULL)
        {
            LogError("EVP_EC_gen(P-256) failed");
            break;
        }

        if ((req = X509_REQ_new()) == NULL)
        {
            LogError("X509_REQ_new failed");
            break;
        }

        X509_REQ_set_version(req, 0);

        X509_NAME* name = X509_REQ_get_subject_name(req);
        if (name == NULL ||
            X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                (const unsigned char*)common_name, -1, -1, 0) != 1)
        {
            LogError("Failed to set CSR subject CN");
            break;
        }

        if (X509_REQ_set_pubkey(req, pkey) != 1 ||
            X509_REQ_sign(req, pkey, EVP_sha256()) <= 0)
        {
            LogError("Failed to sign CSR");
            break;
        }

        // CSR -> DER -> base64
        int der_len = i2d_X509_REQ(req, &der_buf);
        if (der_len <= 0)
        {
            LogError("i2d_X509_REQ failed");
            break;
        }

        if ((der_buffer = BUFFER_create(der_buf, (size_t)der_len)) == NULL)
        {
            LogError("BUFFER_create failed");
            break;
        }

        if ((b64 = Azure_Base64_Encode(der_buffer)) == NULL)
        {
            LogError("Azure_Base64_Encode failed");
            break;
        }

        if (mallocAndStrcpy_s(&csr_out, STRING_c_str(b64)) != 0)
        {
            LogError("mallocAndStrcpy_s for CSR failed");
            break;
        }

        // Private key -> PKCS#8 PEM
        if ((bio = BIO_new(BIO_s_mem())) == NULL)
        {
            LogError("BIO_new failed");
            break;
        }

        if (PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) != 1)
        {
            LogError("PEM_write_bio_PrivateKey failed");
            break;
        }

        char* pem_data = NULL;
        long pem_len = BIO_get_mem_data(bio, &pem_data);
        if (pem_len <= 0 || pem_data == NULL)
        {
            LogError("BIO_get_mem_data returned empty PEM");
            break;
        }

        if ((key_out = (char*)malloc((size_t)pem_len + 1)) == NULL)
        {
            LogError("malloc for PEM private key failed");
            break;
        }
        memcpy(key_out, pem_data, (size_t)pem_len);
        key_out[pem_len] = '\0';

        *csr_base64 = csr_out;
        csr_out = NULL;
        *private_key_pem = key_out;
        key_out = NULL;
        result = 0;
    } while (0);

    free(csr_out);
    free(key_out);
    if (bio != NULL) BIO_free(bio);
    if (b64 != NULL) STRING_delete(b64);
    if (der_buffer != NULL) BUFFER_delete(der_buffer);
    if (der_buf != NULL) OPENSSL_free(der_buf);
    if (req != NULL) X509_REQ_free(req);
    if (pkey != NULL) EVP_PKEY_free(pkey);

    return result;
}
