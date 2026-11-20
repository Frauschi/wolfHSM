/*
 * Copyright (C) 2026 wolfSSL Inc.
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
#include "wh_bench_mod.h"
#include "wolfhsm/wh_error.h"
#include "wolfhsm/wh_client.h"
#include "wolfhsm/wh_client_crypto.h"
#include "wolfhsm/wh_message_crypto.h"

#if !defined(WOLFHSM_CFG_NO_CRYPTO) && defined(WOLFHSM_CFG_BENCH_ENABLE)
#include "wolfssl/wolfcrypt/wc_slhdsa.h"
#include "wolfssl/wolfcrypt/random.h"

#if defined(WOLFSSL_HAVE_SLHDSA)

#if !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
static const byte g_slhDsaBenchMsg[] = "wolfHSM SLH-DSA benchmark message";

/* Returns 1 if a non-DMA sign response and verify request carry sigSz. */
static int _slhDsaFitsComm(word32 sigSz)
{
    word32 signRes = (word32)sizeof(whMessageCrypto_GenericResponseHeader) +
                     (word32)sizeof(whMessageCrypto_SlhDsaSignResponse) + sigSz;
    word32 verifyReq = (word32)sizeof(whMessageCrypto_GenericRequestHeader) +
                       (word32)sizeof(whMessageCrypto_SlhDsaVerifyRequest) +
                       (word32)sizeof(g_slhDsaBenchMsg) + sigSz;

    return (signRes <= WOLFHSM_CFG_COMM_DATA_LEN) &&
           (verifyReq <= WOLFHSM_CFG_COMM_DATA_LEN);
}

/* Caches a fresh key on the server and leaves *key as its public handle. */
static int _slhDsaCacheKey(whClientContext* client, enum SlhDsaParam param,
                           SlhDsaKey* key, whKeyId* keyId)
{
    uint8_t label[] = "bench-slhdsa-key";
    int     ret;

    ret = wh_Client_SlhDsaMakeCacheKeyAndExportPublic(
        client, (int)param, keyId,
        WH_NVM_FLAGS_USAGE_SIGN | WH_NVM_FLAGS_USAGE_VERIFY, sizeof(label),
        label, key);
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to cache SLH-DSA key %d\n", ret);
    }
    return ret;
}

/* Signs or verifies with a server-cached key; sign != 0 times signing. */
static int _benchSlhDsaSignVerify(whClientContext* client,
                                  whBenchOpContext* ctx, int id,
                                  enum SlhDsaParam param, int useDma, int sign)
{
    int        ret      = 0;
    SlhDsaKey* key      = NULL;
    byte*      sig      = NULL;
    word32     sigSz    = 0;
    word32     localSz;
    whKeyId    keyId    = WH_KEYID_ERASED;
    int        keyInit  = 0;
    int        iters;
    int        i;
    byte       addRnd[WC_SLHDSA_MAX_SEED];

    XMEMSET(addRnd, 0x5A, sizeof(addRnd));
    (void)wh_Client_SetDmaMode(client, useDma);

    ret = wc_SlhDsaKey_SigSizeFromParam(param);
    if (ret <= 0) {
        WH_BENCH_PRINTF("Failed to wc_SlhDsaKey_SigSizeFromParam %d\n", ret);
        return (ret == 0) ? WH_ERROR_BADARGS : ret;
    }
    sigSz = (word32)ret;
    ret   = 0;
    if (!useDma && !_slhDsaFitsComm(sigSz)) {
        return WH_ERROR_NOTIMPL;
    }

    key = (SlhDsaKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_SLHDSA);
    sig = (byte*)XMALLOC(sigSz, NULL, DYNAMIC_TYPE_SIGNATURE);
    if ((key == NULL) || (sig == NULL)) {
        WH_BENCH_PRINTF("Failed to allocate SLH-DSA key or signature\n");
        ret = WH_ERROR_NOSPACE;
    }

    if (ret == 0) {
        ret = wc_SlhDsaKey_Init(key, param, NULL, WH_CLIENT_DEVID(client));
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_SlhDsaKey_Init %d\n", ret);
        }
        else {
            keyInit = 1;
        }
    }
    if (ret == 0) {
        ret = _slhDsaCacheKey(client, param, key, &keyId);
    }
    if ((ret == 0) && !sign) {
        localSz = sigSz;
        ret = wc_SlhDsaKey_SignWithRandom(key, NULL, 0, g_slhDsaBenchMsg,
                                          sizeof(g_slhDsaBenchMsg), sig,
                                          &localSz, addRnd);
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_SlhDsaKey_SignWithRandom %d\n", ret);
        }
        sigSz = localSz;
    }

    iters = sign ? WOLFHSM_CFG_BENCH_SLHDSA_SIGN_ITERS
                 : WOLFHSM_CFG_BENCH_PK_ITERS;
    for (i = 0; (i < iters) && (ret == 0); i++) {
        int benchStartRet;
        int benchStopRet;

        localSz       = sigSz;
        benchStartRet = wh_Bench_StartOp(ctx, id);
        if (sign) {
            ret = wc_SlhDsaKey_SignWithRandom(key, NULL, 0, g_slhDsaBenchMsg,
                                              sizeof(g_slhDsaBenchMsg), sig,
                                              &localSz, addRnd);
        }
        else {
            ret = wc_SlhDsaKey_Verify(key, NULL, 0, g_slhDsaBenchMsg,
                                      sizeof(g_slhDsaBenchMsg), sig, sigSz);
        }
        benchStopRet = wh_Bench_StopOp(ctx, id);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
        }
        else if (ret != 0) {
            WH_BENCH_PRINTF("Failed to SLH-DSA %s %d\n",
                            sign ? "sign" : "verify", ret);
        }
        else if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
        }
    }

    if (keyInit) {
        wc_SlhDsaKey_Free(key);
    }
    if (keyId != WH_KEYID_ERASED) {
        int evictRet = wh_Client_KeyEvict(client, keyId);
        if (evictRet != 0) {
            WH_BENCH_PRINTF("Failed to evict key %d\n", evictRet);
            if (ret == 0) {
                ret = evictRet;
            }
        }
    }
    XFREE(sig, NULL, DYNAMIC_TYPE_SIGNATURE);
    XFREE(key, NULL, DYNAMIC_TYPE_SLHDSA);
    return ret;
}

static int _benchSlhDsaSign(whClientContext* client, whBenchOpContext* ctx,
                            int id, enum SlhDsaParam param, int useDma)
{
    return _benchSlhDsaSignVerify(client, ctx, id, param, useDma, 1);
}

/* Generates and exports a key pair on the server each iteration. */
static int _benchSlhDsaKeyGen(whClientContext* client, whBenchOpContext* ctx,
                              int id, enum SlhDsaParam param, int useDma)
{
    int        ret     = 0;
    SlhDsaKey* key     = NULL;
    WC_RNG     rng[1];
    int        rngInit = 0;
    int        i;

    (void)wh_Client_SetDmaMode(client, useDma);

    key = (SlhDsaKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_SLHDSA);
    if (key == NULL) {
        WH_BENCH_PRINTF("Failed to allocate SLH-DSA key\n");
        return WH_ERROR_NOSPACE;
    }
    ret = wc_InitRng_ex(rng, NULL, WH_CLIENT_DEVID(client));
    if (ret != 0) {
        WH_BENCH_PRINTF("Failed to wc_InitRng_ex %d\n", ret);
    }
    else {
        rngInit = 1;
    }

    for (i = 0; (i < WOLFHSM_CFG_BENCH_SLHDSA_KG_ITERS) && (ret == 0); i++) {
        int benchStartRet;
        int benchStopRet;

        ret = wc_SlhDsaKey_Init(key, param, NULL, WH_CLIENT_DEVID(client));
        if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_SlhDsaKey_Init %d\n", ret);
            break;
        }
        benchStartRet = wh_Bench_StartOp(ctx, id);
        ret           = wc_SlhDsaKey_MakeKey(key, rng);
        benchStopRet  = wh_Bench_StopOp(ctx, id);
        wc_SlhDsaKey_Free(key);

        if (benchStartRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StartOp %d\n", benchStartRet);
            ret = benchStartRet;
        }
        else if (ret != 0) {
            WH_BENCH_PRINTF("Failed to wc_SlhDsaKey_MakeKey %d\n", ret);
        }
        else if (benchStopRet != 0) {
            WH_BENCH_PRINTF("Failed to wh_Bench_StopOp %d\n", benchStopRet);
            ret = benchStopRet;
        }
    }

    if (rngInit) {
        wc_FreeRng(rng);
    }
    XFREE(key, NULL, DYNAMIC_TYPE_SLHDSA);
    return ret;
}

static int _benchSlhDsaVerify(whClientContext* client, whBenchOpContext* ctx,
                              int id, enum SlhDsaParam param, int useDma)
{
    return _benchSlhDsaSignVerify(client, ctx, id, param, useDma, 0);
}
#endif /* !WOLFSSL_SLHDSA_VERIFY_ONLY */

#if defined(WOLFSSL_SLHDSA_PARAM_128S)
int wh_Bench_Mod_SlhDsaShake128sSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE128S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128sSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE128S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128sVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE128S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128sVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE128S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128sKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE128S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128sKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE128S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_128S */

#if defined(WOLFSSL_SLHDSA_PARAM_128F)
int wh_Bench_Mod_SlhDsaShake128fSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE128F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128fSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE128F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128fVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE128F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128fVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE128F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128fKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE128F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake128fKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE128F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_128F */

#if defined(WOLFSSL_SLHDSA_PARAM_192S)
int wh_Bench_Mod_SlhDsaShake192sSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE192S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192sSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE192S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192sVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE192S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192sVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE192S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192sKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE192S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192sKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE192S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_192S */

#if defined(WOLFSSL_SLHDSA_PARAM_192F)
int wh_Bench_Mod_SlhDsaShake192fSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE192F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192fSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE192F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192fVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE192F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192fVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE192F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192fKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE192F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake192fKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE192F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_192F */

#if defined(WOLFSSL_SLHDSA_PARAM_256S)
int wh_Bench_Mod_SlhDsaShake256sSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE256S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256sSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE256S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256sVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE256S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256sVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE256S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256sKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE256S, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256sKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE256S, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_256S */

#if defined(WOLFSSL_SLHDSA_PARAM_256F)
int wh_Bench_Mod_SlhDsaShake256fSign(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE256F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256fSignDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaSign(client, ctx, id, SLHDSA_SHAKE256F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256fVerify(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE256F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256fVerifyDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaVerify(client, ctx, id, SLHDSA_SHAKE256F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256fKeyGen(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if !defined(WOLFHSM_CFG_TEST_CLIENT_LARGE_DATA_DMA_ONLY) && \
    !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE256F, 0);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

int wh_Bench_Mod_SlhDsaShake256fKeyGenDma(
    whClientContext* client, whBenchOpContext* ctx, int id, void* params)
{
#if defined(WH_BENCH_CRYPTOCB_DMA) && !defined(WOLFSSL_SLHDSA_VERIFY_ONLY)
    (void)params;
    return _benchSlhDsaKeyGen(client, ctx, id, SLHDSA_SHAKE256F, 1);
#else
    (void)client;
    (void)ctx;
    (void)id;
    (void)params;
    return WH_ERROR_NOTIMPL;
#endif
}

#endif /* WOLFSSL_SLHDSA_PARAM_256F */

#endif /* WOLFSSL_HAVE_SLHDSA */

#endif /* !WOLFHSM_CFG_NO_CRYPTO && WOLFHSM_CFG_BENCH_ENABLE */
