/*
 * Copyright (C) 2024 wolfSSL Inc.
 *
 * This file is part of wolfHSM.
 *
 * wolfHSM is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfHSM is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with wolfHSM.  If not, see <http://www.gnu.org/licenses/>.
 */
/*
 * wolfhsm/wh_crypto.h
 *
 * Common crypto functions for both the client and server
 *
 */

#ifndef WOLFHSM_WH_CRYPTO_H_
#define WOLFHSM_WH_CRYPTO_H_

/* Pick up compile-time configuration */
#include "wolfhsm/wh_settings.h"

#ifndef WOLFHSM_CFG_NO_CRYPTO

/* System libraries */
#include <stdint.h>

#include "wolfssl/wolfcrypt/settings.h"
#include "wolfssl/wolfcrypt/types.h"
#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/cmac.h"
#include "wolfssl/wolfcrypt/rsa.h"
#include "wolfssl/wolfcrypt/curve25519.h"
#include "wolfssl/wolfcrypt/ecc.h"
#include "wolfssl/wolfcrypt/ed25519.h"
#include "wolfssl/wolfcrypt/dilithium.h"
#include "wolfssl/wolfcrypt/wc_mlkem.h"

#include "wolfhsm/wh_message_crypto.h"

#ifdef WOLFSSL_CMAC
/* Save portable CMAC state from a Cmac context into a message state struct */
void wh_Crypto_CmacAesSaveStateToMsg(whMessageCrypto_CmacAesState* state,
                                     const Cmac*                   cmac);
/* Restore portable CMAC state from a message state struct into a Cmac context
 */
int wh_Crypto_CmacAesRestoreStateFromMsg(
    Cmac* cmac, const whMessageCrypto_CmacAesState* state);
#endif /* WOLFSSL_CMAC */

#ifndef NO_AES
int wh_Crypto_SerializeAesKey(Aes* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
int wh_Crypto_DeserializeAesKey(uint16_t size, const uint8_t* buffer,
        Aes* key);
#endif /* !NO_AES */

#ifndef NO_RSA
/* Store a RsaKey to a byte sequence (currently DER format) */
int wh_Crypto_RsaSerializeKeyDer(const RsaKey* key, uint16_t max_size,
        uint8_t* buffer, uint16_t *out_size);
/* Restore a RsaKey from a byte sequence (currently DER format) */
int wh_Crypto_RsaDeserializeKeyDer(uint16_t size, const uint8_t* buffer,
        RsaKey* key);
#endif /* !NO_RSA */

#ifdef HAVE_ECC
/* Store an ecc_key to a byte sequence */
int wh_Crypto_EccSerializeKeyDer(ecc_key* key,
        uint16_t max_size, uint8_t* buffer, uint16_t *out_size);

/* Restore an ecc_key from a byte sequence */
int wh_Crypto_EccDeserializeKeyDer(const uint8_t* buffer, uint16_t pub_size,
        ecc_key* key);

/* Helper to update an ECC private-only key with the corresponding public key,
 * similar to wc_ecc_make_pub().  The incoming byte array of the public key is
 * expected to have been exported using wc_EccPublicKeyToDer().
 */
int wh_Crypto_EccUpdatePrivateOnlyKeyDer(ecc_key* key, uint16_t pub_size,
        const uint8_t* pub_buffer);

#endif /* HAVE_ECC */

#ifdef HAVE_CURVE25519
/* Store a curve25519_key to a byte sequence */
int wh_Crypto_Curve25519SerializeKey(curve25519_key* key, uint8_t* buffer,
                                     uint16_t* outDerSize);
/* Restore a curve25519_key from a byte sequence */
int wh_Crypto_Curve25519DeserializeKey(const uint8_t* derBuffer,
                                       uint16_t derSize, curve25519_key* key);
#endif /* HAVE_CURVE25519 */

#ifdef HAVE_ED25519
#define WH_CRYPTO_ED25519_MAX_CTX_LEN (255U)
int wh_Crypto_Ed25519SerializeKeyDer(const ed25519_key* key, uint16_t max_size,
                                     uint8_t* buffer, uint16_t* out_size);

int wh_Crypto_Ed25519DeserializeKeyDer(const uint8_t* buffer, uint16_t size,
                                       ed25519_key* key);
#endif /* HAVE_ED25519 */

#ifdef HAVE_DILITHIUM
#define WH_CRYPTO_MLDSA_MAX_CTX_LEN (255U)
/* Store a MlDsaKey to a byte sequence */
int wh_Crypto_MlDsaSerializeKeyDer(MlDsaKey* key, uint16_t max_size,
                                   uint8_t* buffer, uint16_t* out_size);
/* Restore a MlDsaKey from a byte sequence */
int wh_Crypto_MlDsaDeserializeKeyDer(const uint8_t* buffer, uint16_t size,
                                     MlDsaKey* key);
#endif /* HAVE_DILITHIUM */

#ifdef WOLFSSL_HAVE_MLKEM
/* Store a MlKemKey to a byte sequence */
int wh_Crypto_MlKemSerializeKey(MlKemKey* key, uint16_t max_size,
                                uint8_t* buffer, uint16_t* out_size);
/* Restore a MlKemKey from a byte sequence. Tries the level already set in the
 * key first, then probes other supported ML-KEM levels if needed. */
int wh_Crypto_MlKemDeserializeKey(const uint8_t* buffer, uint16_t size,
                                  MlKemKey* key);
#endif /* WOLFSSL_HAVE_MLKEM */

/* Stateful hash-based signature key serialization (LMS / XMSS).
 *
 * The slot blob layout is:
 *   uint32_t magic;
 *   uint16_t pubLen;
 *   uint16_t privLen;
 *   uint16_t paramLen;
 *   uint16_t reserved;        (must be 0)
 *   uint8_t  paramDescriptor[paramLen];
 *   uint8_t  pub[pubLen];
 *   uint8_t  priv[privLen];
 *
 * paramDescriptor encodes the parameter set:
 *   LMS  : 3 bytes (levels, height, winternitz) - paramLen == 3
 *   XMSS : NUL-terminated parameter string, paramLen == strlen+1
 *
 * The blob is server-internal (NVM-stored) and uses native byte order. */
#define WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_LMS  0x4C4D5301u  /* 'LMS\1' */
#define WH_CRYPTO_STATEFUL_SIG_BLOB_MAGIC_XMSS 0x584D5301u  /* 'XMS\1' */

#ifdef WOLFSSL_HAVE_LMS
/* Store an LmsKey (parameter set + public key + priv_raw) into a byte
 * sequence. The key must have a parameter set bound (params != NULL) and pub
 * populated. priv_raw is read directly from the key.
 *
 * @param [in]      key       LmsKey to serialize.
 * @param [in]      max_size  Capacity of buffer in bytes.
 * @param [out]     buffer    Destination buffer.
 * @param [in,out]  out_size  On success, total blob size.
 * @return WH_ERROR_OK on success, WH_ERROR_BUFFER_SIZE if max_size is too
 *         small, WH_ERROR_BADARGS otherwise. */
int wh_Crypto_LmsSerializeKey(LmsKey* key, uint16_t max_size, uint8_t* buffer,
                              uint16_t* out_size);

/* Restore an LmsKey from a byte sequence. The caller must pass a key that
 * has been wc_LmsKey_Init'd. After this call returns, the key has its params
 * set, key->pub populated, and key->priv_raw populated. The caller must still
 * install read/write callbacks and call wc_LmsKey_Reload before signing.
 *
 * @param [in]      buffer  Source blob.
 * @param [in]      size    Blob size in bytes.
 * @param [in,out]  key     Initialized LmsKey to populate.
 * @return WH_ERROR_OK on success, WH_ERROR_BADARGS on malformed blob. */
int wh_Crypto_LmsDeserializeKey(const uint8_t* buffer, uint16_t size,
                                LmsKey* key);
#endif /* WOLFSSL_HAVE_LMS */

#ifdef WOLFSSL_HAVE_XMSS
/* Store an XmssKey (param string + public key + secret state) into a byte
 * sequence. */
int wh_Crypto_XmssSerializeKey(XmssKey* key, const char* paramStr,
                               uint16_t max_size, uint8_t* buffer,
                               uint16_t* out_size);

/* Restore an XmssKey from a byte sequence. The caller must pass a key that
 * has been wc_XmssKey_Init'd. The function calls wc_XmssKey_SetParamStr
 * (which allocates key->sk) and copies pub and sk from the blob. */
int wh_Crypto_XmssDeserializeKey(const uint8_t* buffer, uint16_t size,
                                 XmssKey* key);
#endif /* WOLFSSL_HAVE_XMSS */

#endif  /* !WOLFHSM_CFG_NO_CRYPTO */

#endif /* WOLFHSM_WH_CRYPTO_H_ */
