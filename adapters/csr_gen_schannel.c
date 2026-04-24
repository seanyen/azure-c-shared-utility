// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

// Windows (Schannel / CNG + WinCrypt) implementation of csr_gen.h.
//
// Generates an ephemeral ECDSA P-256 key with BCrypt, builds a PKCS#10
// CertificationRequest using CryptEncodeObjectEx, signs the TBS with
// BCryptSignHash, and exports the private key as PKCS#8 PEM.

#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>

#include <stdlib.h>
#include <string.h>

#include "azure_c_shared_utility/csr_gen.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/optimize_size.h"
#include "azure_c_shared_utility/xlogging.h"
#include "azure_macro_utils/macro_utils.h"

#ifndef BCRYPT_SUCCESS
#define BCRYPT_SUCCESS(s) ((s) >= 0)
#endif

#define P256_COORD_LEN  32u

static void secure_local_free(void* p) { if (p != NULL) LocalFree(p); }

// Wrap a base64 payload into PEM with given label; returns malloc'd string.
static char* pem_wrap(const char* label, const BYTE* data, DWORD len)
{
    // First compute base64 with CRLF line breaks.
    DWORD b64_len = 0;
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64, NULL, &b64_len))
    {
        LogError("CryptBinaryToStringA size query failed");
        return NULL;
    }
    char* b64 = (char*)malloc(b64_len);
    if (b64 == NULL) return NULL;
    if (!CryptBinaryToStringA(data, len, CRYPT_STRING_BASE64, b64, &b64_len))
    {
        free(b64);
        return NULL;
    }

    size_t header_len = strlen("-----BEGIN ") + strlen(label) + strlen("-----\n");
    size_t footer_len = strlen("-----END ") + strlen(label) + strlen("-----\n");
    size_t total = header_len + b64_len + footer_len + 1;
    char* pem = (char*)malloc(total);
    if (pem == NULL) { free(b64); return NULL; }
    int written = sprintf_s(pem, total, "-----BEGIN %s-----\n%s-----END %s-----\n", label, b64, label);
    free(b64);
    if (written < 0) { free(pem); return NULL; }
    return pem;
}

// Build DER-encoded parameters = OID(szOID_ECC_CURVE_P256).
// Caller must LocalFree *out.
static BOOL encode_p256_curve_oid_params(BYTE** out, DWORD* out_len)
{
    return CryptEncodeObjectEx(X509_ASN_ENCODING, X509_OBJECT_IDENTIFIER,
        szOID_ECC_CURVE_P256, CRYPT_ENCODE_ALLOC_FLAG, NULL, out, out_len);
}

// Build DER-encoded Subject Name with a single CN RDN.
// Caller must LocalFree *out.
static BOOL encode_subject_cn(const char* common_name, BYTE** out, DWORD* out_len)
{
    CERT_RDN_ATTR rdn_attr;
    memset(&rdn_attr, 0, sizeof(rdn_attr));
    rdn_attr.pszObjId = szOID_COMMON_NAME;
    rdn_attr.dwValueType = CERT_RDN_UTF8_STRING;
    rdn_attr.Value.pbData = (BYTE*)common_name;
    rdn_attr.Value.cbData = (DWORD)strlen(common_name);

    CERT_RDN rdn;
    rdn.cRDNAttr = 1;
    rdn.rgRDNAttr = &rdn_attr;

    CERT_NAME_INFO name_info;
    name_info.cRDN = 1;
    name_info.rgRDN = &rdn;

    return CryptEncodeObjectEx(X509_ASN_ENCODING, X509_NAME,
        &name_info, CRYPT_ENCODE_ALLOC_FLAG, NULL, out, out_len);
}

// Encode the ECDSA signature (raw R||S, each P256_COORD_LEN bytes) as DER
// SEQUENCE { INTEGER r, INTEGER s }. Caller must LocalFree *out.
static BOOL encode_ecdsa_signature(const BYTE* raw_sig, BYTE** out, DWORD* out_len)
{
    CERT_ECC_SIGNATURE ecc_sig;
    ecc_sig.r.cbData = P256_COORD_LEN;
    ecc_sig.r.pbData = (BYTE*)raw_sig;
    ecc_sig.s.cbData = P256_COORD_LEN;
    ecc_sig.s.pbData = (BYTE*)(raw_sig + P256_COORD_LEN);
    return CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ECC_SIGNATURE,
        &ecc_sig, CRYPT_ENCODE_ALLOC_FLAG, NULL, out, out_len);
}

// Build and DER-encode PKCS#8 PrivateKeyInfo for an EC P-256 private key
// (d, with optional publicKey embedded). Caller must LocalFree *out.
static BOOL encode_pkcs8_ec_private_key(const BYTE* d, const BYTE* pub_x, const BYTE* pub_y,
    BYTE** out, DWORD* out_len)
{
    // Build uncompressed public point (0x04 || X || Y) for the optional publicKey.
    BYTE public_point[1 + P256_COORD_LEN * 2];
    public_point[0] = 0x04;
    memcpy(public_point + 1, pub_x, P256_COORD_LEN);
    memcpy(public_point + 1 + P256_COORD_LEN, pub_y, P256_COORD_LEN);

    // 1. Encode RFC 5915 ECPrivateKey.
    CRYPT_ECC_PRIVATE_KEY_INFO ec_pki;
    memset(&ec_pki, 0, sizeof(ec_pki));
    ec_pki.dwVersion = CRYPT_ECC_PRIVATE_KEY_INFO_v1;
    ec_pki.PrivateKey.cbData = P256_COORD_LEN;
    ec_pki.PrivateKey.pbData = (BYTE*)d;
    ec_pki.szCurveOid = szOID_ECC_CURVE_P256;
    ec_pki.PublicKey.cbData = sizeof(public_point);
    ec_pki.PublicKey.pbData = public_point;

    BYTE* ec_der = NULL;
    DWORD ec_der_len = 0;
    if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ECC_PRIVATE_KEY,
        &ec_pki, CRYPT_ENCODE_ALLOC_FLAG, NULL, &ec_der, &ec_der_len))
    {
        LogError("Encode X509_ECC_PRIVATE_KEY failed (err=0x%08x)", (unsigned)GetLastError());
        return FALSE;
    }

    // 2. Encode P-256 curve OID as algorithm parameters.
    BYTE* curve_params = NULL;
    DWORD curve_params_len = 0;
    if (!encode_p256_curve_oid_params(&curve_params, &curve_params_len))
    {
        LogError("Encode P-256 curve OID failed (err=0x%08x)", (unsigned)GetLastError());
        LocalFree(ec_der);
        return FALSE;
    }

    // 3. Wrap in PKCS#8 PrivateKeyInfo.
    CRYPT_PRIVATE_KEY_INFO pki;
    memset(&pki, 0, sizeof(pki));
    pki.Version = 0;
    pki.Algorithm.pszObjId = (LPSTR)szOID_ECC_PUBLIC_KEY;
    pki.Algorithm.Parameters.pbData = curve_params;
    pki.Algorithm.Parameters.cbData = curve_params_len;
    pki.PrivateKey.pbData = ec_der;
    pki.PrivateKey.cbData = ec_der_len;

    BOOL ok = CryptEncodeObjectEx(X509_ASN_ENCODING, PKCS_PRIVATE_KEY_INFO,
        &pki, CRYPT_ENCODE_ALLOC_FLAG, NULL, out, out_len);

    LocalFree(ec_der);
    LocalFree(curve_params);

    if (!ok)
    {
        LogError("Encode PKCS_PRIVATE_KEY_INFO failed (err=0x%08x)", (unsigned)GetLastError());
    }
    return ok;
}

int csr_gen_ec_p256(const char* common_name, char** csr_base64, char** private_key_pem)
{
    int result = MU_FAILURE;
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_ALG_HANDLE hHashAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    BYTE* keypair_blob = NULL;
    DWORD blob_len = 0;
    BYTE* subject_der = NULL;     DWORD subject_der_len = 0;
    BYTE* curve_params = NULL;    DWORD curve_params_len = 0;
    BYTE* tbs_der = NULL;         DWORD tbs_der_len = 0;
    BYTE* sig_der = NULL;         DWORD sig_der_len = 0;
    BYTE* csr_der = NULL;         DWORD csr_der_len = 0;
    BYTE* pkcs8_der = NULL;       DWORD pkcs8_der_len = 0;
    char* csr_b64_out = NULL;
    char* key_pem_out = NULL;

    if (common_name == NULL || csr_base64 == NULL || private_key_pem == NULL)
    {
        LogError("Invalid argument to csr_gen_ec_p256");
        return MU_FAILURE;
    }
    *csr_base64 = NULL;
    *private_key_pem = NULL;

    do
    {
        // --- 1. Generate ECDSA P-256 key pair ---
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg,
                BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0)))
        {
            LogError("BCryptOpenAlgorithmProvider(ECDSA_P256) failed");
            break;
        }
        if (!BCRYPT_SUCCESS(BCryptGenerateKeyPair(hAlg, &hKey, 256, 0)))
        {
            LogError("BCryptGenerateKeyPair failed");
            break;
        }
        if (!BCRYPT_SUCCESS(BCryptFinalizeKeyPair(hKey, 0)))
        {
            LogError("BCryptFinalizeKeyPair failed");
            break;
        }

        // --- 2. Export key material: BCRYPT_ECCKEY_BLOB header + X + Y + d ---
        if (!BCRYPT_SUCCESS(BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                NULL, 0, &blob_len, 0)))
        {
            LogError("BCryptExportKey size query failed");
            break;
        }
        keypair_blob = (BYTE*)malloc(blob_len);
        if (keypair_blob == NULL) { LogError("OOM keypair blob"); break; }
        if (!BCRYPT_SUCCESS(BCryptExportKey(hKey, NULL, BCRYPT_ECCPRIVATE_BLOB,
                keypair_blob, blob_len, &blob_len, 0)))
        {
            LogError("BCryptExportKey failed");
            break;
        }

        BCRYPT_ECCKEY_BLOB* hdr = (BCRYPT_ECCKEY_BLOB*)keypair_blob;
        if (hdr->cbKey != P256_COORD_LEN ||
            blob_len < sizeof(BCRYPT_ECCKEY_BLOB) + 3 * P256_COORD_LEN)
        {
            LogError("Unexpected ECC key blob layout");
            break;
        }
        const BYTE* pub_x = keypair_blob + sizeof(BCRYPT_ECCKEY_BLOB);
        const BYTE* pub_y = pub_x + P256_COORD_LEN;
        const BYTE* priv_d = pub_y + P256_COORD_LEN;

        // --- 3. Build CSR TBS (CERT_REQUEST_INFO) ---
        if (!encode_subject_cn(common_name, &subject_der, &subject_der_len))
        {
            LogError("Encode subject CN failed");
            break;
        }
        if (!encode_p256_curve_oid_params(&curve_params, &curve_params_len))
        {
            LogError("Encode curve params failed");
            break;
        }

        BYTE public_point[1 + P256_COORD_LEN * 2];
        public_point[0] = 0x04;
        memcpy(public_point + 1, pub_x, P256_COORD_LEN);
        memcpy(public_point + 1 + P256_COORD_LEN, pub_y, P256_COORD_LEN);

        CERT_REQUEST_INFO req_info;
        memset(&req_info, 0, sizeof(req_info));
        req_info.dwVersion = CERT_REQUEST_V1;
        req_info.Subject.cbData = subject_der_len;
        req_info.Subject.pbData = subject_der;
        req_info.SubjectPublicKeyInfo.Algorithm.pszObjId = (LPSTR)szOID_ECC_PUBLIC_KEY;
        req_info.SubjectPublicKeyInfo.Algorithm.Parameters.cbData = curve_params_len;
        req_info.SubjectPublicKeyInfo.Algorithm.Parameters.pbData = curve_params;
        req_info.SubjectPublicKeyInfo.PublicKey.cbData = sizeof(public_point);
        req_info.SubjectPublicKeyInfo.PublicKey.pbData = public_point;
        req_info.SubjectPublicKeyInfo.PublicKey.cUnusedBits = 0;
        req_info.cAttribute = 0;
        req_info.rgAttribute = NULL;

        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT_REQUEST_TO_BE_SIGNED,
                &req_info, CRYPT_ENCODE_ALLOC_FLAG, NULL, &tbs_der, &tbs_der_len))
        {
            LogError("Encode CSR TBS failed (err=0x%08x)", (unsigned)GetLastError());
            break;
        }

        // --- 4. SHA-256 the TBS ---
        BYTE tbs_hash[32];
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&hHashAlg,
                BCRYPT_SHA256_ALGORITHM, NULL, 0)))
        {
            LogError("BCryptOpenAlgorithmProvider(SHA256) failed");
            break;
        }
        if (!BCRYPT_SUCCESS(BCryptHash(hHashAlg, NULL, 0,
                tbs_der, tbs_der_len, tbs_hash, sizeof(tbs_hash))))
        {
            LogError("BCryptHash failed");
            break;
        }

        // --- 5. Sign hash (raw ECDSA -> R||S, 64 bytes for P-256) ---
        BYTE raw_sig[P256_COORD_LEN * 2];
        DWORD raw_sig_len = 0;
        if (!BCRYPT_SUCCESS(BCryptSignHash(hKey, NULL, tbs_hash, sizeof(tbs_hash),
                raw_sig, sizeof(raw_sig), &raw_sig_len, 0))
            || raw_sig_len != sizeof(raw_sig))
        {
            LogError("BCryptSignHash failed");
            break;
        }

        if (!encode_ecdsa_signature(raw_sig, &sig_der, &sig_der_len))
        {
            LogError("Encode ECDSA signature failed");
            break;
        }

        // --- 6. Build CERT_SIGNED_CONTENT_INFO and encode full CSR ---
        CERT_SIGNED_CONTENT_INFO signed_info;
        memset(&signed_info, 0, sizeof(signed_info));
        signed_info.ToBeSigned.cbData = tbs_der_len;
        signed_info.ToBeSigned.pbData = tbs_der;
        signed_info.SignatureAlgorithm.pszObjId = (LPSTR)szOID_ECDSA_SHA256;
        signed_info.SignatureAlgorithm.Parameters.cbData = 0;
        signed_info.SignatureAlgorithm.Parameters.pbData = NULL;
        signed_info.Signature.cbData = sig_der_len;
        signed_info.Signature.pbData = sig_der;
        signed_info.Signature.cUnusedBits = 0;

        if (!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_CERT,
                &signed_info, CRYPT_ENCODE_ALLOC_FLAG, NULL, &csr_der, &csr_der_len))
        {
            LogError("Encode signed CSR failed (err=0x%08x)", (unsigned)GetLastError());
            break;
        }

        // --- 7. Base64-encode the CSR DER (no line breaks, no PEM armor) ---
        DWORD b64_len = 0;
        if (!CryptBinaryToStringA(csr_der, csr_der_len,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &b64_len))
        {
            LogError("CryptBinaryToStringA size query failed");
            break;
        }
        csr_b64_out = (char*)malloc(b64_len);
        if (csr_b64_out == NULL) { LogError("OOM csr base64"); break; }
        if (!CryptBinaryToStringA(csr_der, csr_der_len,
                CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, csr_b64_out, &b64_len))
        {
            LogError("CryptBinaryToStringA failed");
            break;
        }

        // --- 8. Export private key as PKCS#8 PEM ---
        if (!encode_pkcs8_ec_private_key(priv_d, pub_x, pub_y, &pkcs8_der, &pkcs8_der_len))
        {
            break;
        }

        key_pem_out = pem_wrap("PRIVATE KEY", pkcs8_der, pkcs8_der_len);
        if (key_pem_out == NULL)
        {
            LogError("pem_wrap failed");
            break;
        }

        *csr_base64 = csr_b64_out; csr_b64_out = NULL;
        *private_key_pem = key_pem_out; key_pem_out = NULL;
        result = 0;
    } while (0);

    free(csr_b64_out);
    free(key_pem_out);
    if (keypair_blob != NULL)
    {
        SecureZeroMemory(keypair_blob, blob_len);
        free(keypair_blob);
    }
    secure_local_free(subject_der);
    secure_local_free(curve_params);
    secure_local_free(tbs_der);
    secure_local_free(sig_der);
    secure_local_free(csr_der);
    if (pkcs8_der != NULL)
    {
        SecureZeroMemory(pkcs8_der, pkcs8_der_len);
        LocalFree(pkcs8_der);
    }
    if (hKey != NULL) BCryptDestroyKey(hKey);
    if (hHashAlg != NULL) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hAlg != NULL) BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}
