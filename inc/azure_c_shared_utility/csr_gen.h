// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Platform-abstracted Certificate Signing Request (CSR) generation.
//
// Two implementations are provided in c-utility/adapters:
//   - csr_gen_openssl.c  (built when use_openssl  is ON)
//   - csr_gen_schannel.c (built when use_schannel is ON)
//
// Both implementations produce byte-identical output *formats*:
//   csr_base64      = Base64(DER(PKCS#10 CertificationRequest)), no PEM armor
//   private_key_pem = PEM "-----BEGIN PRIVATE KEY-----" PKCS#8 PrivateKeyInfo
// so downstream consumers do not need to know which platform API produced them.

#ifndef CSR_GEN_H
#define CSR_GEN_H

#ifdef __cplusplus
extern "C" {
#endif

#include "umock_c/umock_c_prod.h"

// Generate a P-256 ECDSA key pair, build a CSR with the given common name signed
// with the new key, and return the base64(DER) CSR plus PKCS#8 PEM private key.
// On success returns 0 and sets *csr_base64 / *private_key_pem to malloc'd
// NUL-terminated strings owned by the caller. On failure returns non-zero.
MOCKABLE_FUNCTION(, int, csr_gen_ec_p256, const char*, common_name, char**, csr_base64, char**, private_key_pem);

#ifdef __cplusplus
}
#endif

#endif /* CSR_GEN_H */
