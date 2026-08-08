/*
 * ngtcp2
 *
 * Copyright (c) 2026 ngtcp2 contributors
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_mbedtls.h>

#include <mbedtls/ssl.h>
#include <mbedtls/ssl_ciphersuites.h>
#include <psa/crypto.h>

#include "ngtcp2_macro.h"
#include "shared.h"

typedef enum ngtcp2_mbedtls_aead_id {
  NGTCP2_MBEDTLS_AEAD_AES_128_GCM = 1,
  NGTCP2_MBEDTLS_AEAD_AES_256_GCM,
  NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305,
  NGTCP2_MBEDTLS_AEAD_AES_128_CCM
} ngtcp2_mbedtls_aead_id;

typedef enum ngtcp2_mbedtls_md_id {
  NGTCP2_MBEDTLS_MD_SHA256 = 1,
  NGTCP2_MBEDTLS_MD_SHA384
} ngtcp2_mbedtls_md_id;

typedef enum ngtcp2_mbedtls_cipher_id {
  NGTCP2_MBEDTLS_CIPHER_AES_128_ECB = 1,
  NGTCP2_MBEDTLS_CIPHER_AES_256_ECB,
  NGTCP2_MBEDTLS_CIPHER_CHACHA20
} ngtcp2_mbedtls_cipher_id;

typedef struct ngtcp2_mbedtls_aead_ctx {
  mbedtls_svc_key_id_t key;
  psa_algorithm_t alg;
} ngtcp2_mbedtls_aead_ctx;

typedef struct ngtcp2_mbedtls_cipher_ctx {
  mbedtls_svc_key_id_t key;
  psa_algorithm_t alg;
  ngtcp2_mbedtls_cipher_id id;
  uint8_t raw_key[32];
} ngtcp2_mbedtls_cipher_ctx;

static int ensure_psa_initialized(void) {
  return psa_crypto_init() == PSA_SUCCESS ? 0 : -1;
}

static void *id2ptr(intptr_t id) { return (void *)id; }

static intptr_t ptr2id(const void *p) { return (intptr_t)p; }

static psa_algorithm_t aead_alg(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
    return PSA_ALG_GCM;
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return PSA_ALG_CHACHA20_POLY1305;
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return PSA_ALG_CCM;
  default:
    assert(0);
    abort();
  }
}

static psa_key_type_t aead_key_type(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return PSA_KEY_TYPE_AES;
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return PSA_KEY_TYPE_CHACHA20;
  default:
    assert(0);
    abort();
  }
}

static size_t aead_keylen(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return 16;
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return 32;
  default:
    assert(0);
    abort();
  }
}

static size_t aead_taglen(ngtcp2_mbedtls_aead_id id) {
  (void)id;
  return 16;
}

static size_t md_hashlen(ngtcp2_mbedtls_md_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_MD_SHA256:
    return 32;
  case NGTCP2_MBEDTLS_MD_SHA384:
    return 48;
  default:
    assert(0);
    abort();
  }
}

static psa_algorithm_t md_hash_alg(ngtcp2_mbedtls_md_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_MD_SHA256:
    return PSA_ALG_SHA_256;
  case NGTCP2_MBEDTLS_MD_SHA384:
    return PSA_ALG_SHA_384;
  default:
    assert(0);
    abort();
  }
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_aes_128_gcm(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead,
                                 id2ptr(NGTCP2_MBEDTLS_AEAD_AES_128_GCM));
}

ngtcp2_crypto_md *ngtcp2_crypto_md_sha256(ngtcp2_crypto_md *md) {
  md->native_handle = id2ptr(NGTCP2_MBEDTLS_MD_SHA256);
  return md;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_initial(ngtcp2_crypto_ctx *ctx) {
  ngtcp2_crypto_aead_init(&ctx->aead,
                          id2ptr(NGTCP2_MBEDTLS_AEAD_AES_128_GCM));
  ctx->md.native_handle = id2ptr(NGTCP2_MBEDTLS_MD_SHA256);
  ctx->hp.native_handle = id2ptr(NGTCP2_MBEDTLS_CIPHER_AES_128_ECB);
  ctx->max_encryption = 0;
  ctx->max_decryption_failure = 0;
  return ctx;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_init(ngtcp2_crypto_aead *aead,
                                            void *aead_native_handle) {
  aead->native_handle = aead_native_handle;
  aead->max_overhead =
    aead_taglen((ngtcp2_mbedtls_aead_id)ptr2id(aead_native_handle));
  return aead;
}

ngtcp2_crypto_aead *ngtcp2_crypto_aead_retry(ngtcp2_crypto_aead *aead) {
  return ngtcp2_crypto_aead_init(aead,
                                 id2ptr(NGTCP2_MBEDTLS_AEAD_AES_128_GCM));
}

static ngtcp2_mbedtls_cipher_id crypto_get_hp(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return NGTCP2_MBEDTLS_CIPHER_AES_128_ECB;
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
    return NGTCP2_MBEDTLS_CIPHER_AES_256_ECB;
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return NGTCP2_MBEDTLS_CIPHER_CHACHA20;
  default:
    assert(0);
    abort();
  }
}

static uint64_t
crypto_aead_get_max_encryption(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_GCM;
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_CHACHA20_POLY1305;
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return NGTCP2_CRYPTO_MAX_ENCRYPTION_AES_CCM;
  default:
    assert(0);
    abort();
  }
}

static uint64_t
crypto_aead_get_max_decryption_failure(ngtcp2_mbedtls_aead_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_AEAD_AES_128_GCM:
  case NGTCP2_MBEDTLS_AEAD_AES_256_GCM:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_GCM;
  case NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_CHACHA20_POLY1305;
  case NGTCP2_MBEDTLS_AEAD_AES_128_CCM:
    return NGTCP2_CRYPTO_MAX_DECRYPTION_FAILURE_AES_CCM;
  default:
    assert(0);
    abort();
  }
}

static int crypto_get_ctx(ngtcp2_mbedtls_aead_id *paead,
                          ngtcp2_mbedtls_md_id *pmd,
                          const mbedtls_ssl_context *ssl) {
  switch (mbedtls_ssl_get_ciphersuite_id_from_ssl(ssl)) {
  case MBEDTLS_TLS1_3_AES_128_GCM_SHA256:
    *paead = NGTCP2_MBEDTLS_AEAD_AES_128_GCM;
    *pmd = NGTCP2_MBEDTLS_MD_SHA256;
    return 0;
  case MBEDTLS_TLS1_3_AES_256_GCM_SHA384:
    *paead = NGTCP2_MBEDTLS_AEAD_AES_256_GCM;
    *pmd = NGTCP2_MBEDTLS_MD_SHA384;
    return 0;
  case MBEDTLS_TLS1_3_CHACHA20_POLY1305_SHA256:
    *paead = NGTCP2_MBEDTLS_AEAD_CHACHA20_POLY1305;
    *pmd = NGTCP2_MBEDTLS_MD_SHA256;
    return 0;
  case MBEDTLS_TLS1_3_AES_128_CCM_SHA256:
    *paead = NGTCP2_MBEDTLS_AEAD_AES_128_CCM;
    *pmd = NGTCP2_MBEDTLS_MD_SHA256;
    return 0;
  default:
    return -1;
  }
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls(ngtcp2_crypto_ctx *ctx,
                                         void *tls_native_handle) {
  mbedtls_ssl_context *ssl = tls_native_handle;
  ngtcp2_mbedtls_aead_id aead;
  ngtcp2_mbedtls_md_id md;

  if (crypto_get_ctx(&aead, &md, ssl) != 0) {
    return NULL;
  }

  ngtcp2_crypto_aead_init(&ctx->aead, id2ptr(aead));
  ctx->md.native_handle = id2ptr(md);
  ctx->hp.native_handle = id2ptr(crypto_get_hp(aead));
  ctx->max_encryption = crypto_aead_get_max_encryption(aead);
  ctx->max_decryption_failure =
    crypto_aead_get_max_decryption_failure(aead);
  return ctx;
}

ngtcp2_crypto_ctx *ngtcp2_crypto_ctx_tls_early(ngtcp2_crypto_ctx *ctx,
                                               void *tls_native_handle) {
  return ngtcp2_crypto_ctx_tls(ctx, tls_native_handle);
}

size_t ngtcp2_crypto_md_hashlen(const ngtcp2_crypto_md *md) {
  return md_hashlen((ngtcp2_mbedtls_md_id)ptr2id(md->native_handle));
}

size_t ngtcp2_crypto_aead_keylen(const ngtcp2_crypto_aead *aead) {
  return aead_keylen((ngtcp2_mbedtls_aead_id)ptr2id(aead->native_handle));
}

size_t ngtcp2_crypto_aead_noncelen(const ngtcp2_crypto_aead *aead) {
  (void)aead;
  return 12;
}

static int import_key(mbedtls_svc_key_id_t *pkey, psa_key_usage_t usage,
                      psa_algorithm_t alg, psa_key_type_t type,
                      const uint8_t *key, size_t keylen) {
  psa_key_attributes_t attrs = PSA_KEY_ATTRIBUTES_INIT;
  psa_status_t status;

  if (ensure_psa_initialized() != 0) {
    return -1;
  }

  psa_set_key_usage_flags(&attrs, usage);
  psa_set_key_algorithm(&attrs, alg);
  psa_set_key_type(&attrs, type);
  psa_set_key_bits(&attrs, keylen * 8);

  status = psa_import_key(&attrs, key, keylen, pkey);
  psa_reset_key_attributes(&attrs);

  return status == PSA_SUCCESS ? 0 : -1;
}

static int aead_ctx_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                         const ngtcp2_crypto_aead *aead,
                         const uint8_t *key, psa_key_usage_t usage) {
  ngtcp2_mbedtls_aead_id id =
    (ngtcp2_mbedtls_aead_id)ptr2id(aead->native_handle);
  ngtcp2_mbedtls_aead_ctx *ctx = calloc(1, sizeof(*ctx));

  if (ctx == NULL) {
    return -1;
  }

  ctx->alg = aead_alg(id);
  if (import_key(&ctx->key, usage, ctx->alg, aead_key_type(id), key,
                 aead_keylen(id)) != 0) {
    free(ctx);
    return -1;
  }

  aead_ctx->native_handle = ctx;
  return 0;
}

int ngtcp2_crypto_aead_ctx_encrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  (void)noncelen;
  return aead_ctx_init(aead_ctx, aead, key, PSA_KEY_USAGE_ENCRYPT);
}

int ngtcp2_crypto_aead_ctx_decrypt_init(ngtcp2_crypto_aead_ctx *aead_ctx,
                                        const ngtcp2_crypto_aead *aead,
                                        const uint8_t *key, size_t noncelen) {
  (void)noncelen;
  return aead_ctx_init(aead_ctx, aead, key, PSA_KEY_USAGE_DECRYPT);
}

void ngtcp2_crypto_aead_ctx_free(ngtcp2_crypto_aead_ctx *aead_ctx) {
  ngtcp2_mbedtls_aead_ctx *ctx = aead_ctx->native_handle;

  if (ctx != NULL) {
    psa_destroy_key(ctx->key);
    free(ctx);
    aead_ctx->native_handle = NULL;
  }
}

static size_t cipher_keylen(ngtcp2_mbedtls_cipher_id id) {
  switch (id) {
  case NGTCP2_MBEDTLS_CIPHER_AES_128_ECB:
    return 16;
  case NGTCP2_MBEDTLS_CIPHER_AES_256_ECB:
  case NGTCP2_MBEDTLS_CIPHER_CHACHA20:
    return 32;
  default:
    assert(0);
    abort();
  }
}

int ngtcp2_crypto_cipher_ctx_encrypt_init(ngtcp2_crypto_cipher_ctx *cipher_ctx,
                                          const ngtcp2_crypto_cipher *cipher,
                                          const uint8_t *key) {
  ngtcp2_mbedtls_cipher_id id =
    (ngtcp2_mbedtls_cipher_id)ptr2id(cipher->native_handle);
  ngtcp2_mbedtls_cipher_ctx *ctx = calloc(1, sizeof(*ctx));

  if (ctx == NULL) {
    return -1;
  }

  ctx->id = id;
  if (id == NGTCP2_MBEDTLS_CIPHER_CHACHA20) {
    memcpy(ctx->raw_key, key, cipher_keylen(id));
    cipher_ctx->native_handle = ctx;
    return 0;
  }

  ctx->alg = PSA_ALG_ECB_NO_PADDING;
  if (import_key(&ctx->key, PSA_KEY_USAGE_ENCRYPT, ctx->alg, PSA_KEY_TYPE_AES,
                 key, cipher_keylen(id)) != 0) {
    free(ctx);
    return -1;
  }

  cipher_ctx->native_handle = ctx;
  return 0;
}

void ngtcp2_crypto_cipher_ctx_free(ngtcp2_crypto_cipher_ctx *cipher_ctx) {
  ngtcp2_mbedtls_cipher_ctx *ctx = cipher_ctx->native_handle;

  if (ctx != NULL) {
    if (ctx->id != NGTCP2_MBEDTLS_CIPHER_CHACHA20) {
      psa_destroy_key(ctx->key);
    }
    ngtcp2_secure_clear(ctx, sizeof(*ctx));
    free(ctx);
    cipher_ctx->native_handle = NULL;
  }
}

int ngtcp2_crypto_hkdf_extract(uint8_t *dest, const ngtcp2_crypto_md *md,
                               const uint8_t *secret, size_t secretlen,
                               const uint8_t *salt, size_t saltlen) {
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  ngtcp2_mbedtls_md_id id =
    (ngtcp2_mbedtls_md_id)ptr2id(md->native_handle);
  const uint8_t empty = 0;
  psa_status_t status;

  if (ensure_psa_initialized() != 0) {
    return -1;
  }

  status = psa_key_derivation_setup(&op,
                                    PSA_ALG_HKDF_EXTRACT(md_hash_alg(id)));
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_input_bytes(
    &op, PSA_KEY_DERIVATION_INPUT_SALT, saltlen == 0 ? &empty : salt, saltlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_input_bytes(&op,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          secretlen == 0 ? &empty : secret,
                                          secretlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_output_bytes(&op, dest, md_hashlen(id));
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_abort(&op);
  return status == PSA_SUCCESS ? 0 : -1;

fail:
  psa_key_derivation_abort(&op);
  return -1;
}

int ngtcp2_crypto_hkdf_expand(uint8_t *dest, size_t destlen,
                              const ngtcp2_crypto_md *md,
                              const uint8_t *secret, size_t secretlen,
                              const uint8_t *info, size_t infolen) {
  psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
  ngtcp2_mbedtls_md_id id =
    (ngtcp2_mbedtls_md_id)ptr2id(md->native_handle);
  const uint8_t empty = 0;
  psa_status_t status;

  if (ensure_psa_initialized() != 0) {
    return -1;
  }

  status =
    psa_key_derivation_setup(&op, PSA_ALG_HKDF_EXPAND(md_hash_alg(id)));
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_input_bytes(&op,
                                          PSA_KEY_DERIVATION_INPUT_SECRET,
                                          secretlen == 0 ? &empty : secret,
                                          secretlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_input_bytes(&op, PSA_KEY_DERIVATION_INPUT_INFO,
                                          infolen == 0 ? &empty : info,
                                          infolen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_output_bytes(&op, dest, destlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_key_derivation_abort(&op);
  return status == PSA_SUCCESS ? 0 : -1;

fail:
  psa_key_derivation_abort(&op);
  return -1;
}

int ngtcp2_crypto_hkdf(uint8_t *dest, size_t destlen,
                       const ngtcp2_crypto_md *md, const uint8_t *secret,
                       size_t secretlen, const uint8_t *salt, size_t saltlen,
                       const uint8_t *info, size_t infolen) {
  uint8_t prk[64];

  if (ngtcp2_crypto_hkdf_extract(prk, md, secret, secretlen, salt, saltlen) !=
        0 ||
      ngtcp2_crypto_hkdf_expand(dest, destlen, md, prk,
                                ngtcp2_crypto_md_hashlen(md), info,
                                infolen) != 0) {
    ngtcp2_secure_clear(prk, sizeof(prk));
    return -1;
  }

  ngtcp2_secure_clear(prk, sizeof(prk));
  return 0;
}

int ngtcp2_crypto_encrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *plaintext, size_t plaintextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_mbedtls_aead_ctx *ctx = aead_ctx->native_handle;
  size_t outlen;

  return psa_aead_encrypt(ctx->key, ctx->alg, nonce, noncelen, aad, aadlen,
                          plaintext, plaintextlen, dest,
                          plaintextlen + aead->max_overhead, &outlen) ==
             PSA_SUCCESS &&
           outlen == plaintextlen + aead->max_overhead ?
         0 : -1;
}

int ngtcp2_crypto_decrypt(uint8_t *dest, const ngtcp2_crypto_aead *aead,
                          const ngtcp2_crypto_aead_ctx *aead_ctx,
                          const uint8_t *ciphertext, size_t ciphertextlen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *aad, size_t aadlen) {
  ngtcp2_mbedtls_aead_ctx *ctx = aead_ctx->native_handle;
  size_t outlen;

  return psa_aead_decrypt(ctx->key, ctx->alg, nonce, noncelen, aad, aadlen,
                          ciphertext, ciphertextlen, dest, ciphertextlen,
                          &outlen) == PSA_SUCCESS &&
           outlen + aead->max_overhead == ciphertextlen ?
         0 : -1;
}

int ngtcp2_crypto_hp_mask(uint8_t *dest, const ngtcp2_crypto_cipher *hp,
                          const ngtcp2_crypto_cipher_ctx *hp_ctx,
                          const uint8_t *sample) {
  ngtcp2_mbedtls_cipher_id id =
    (ngtcp2_mbedtls_cipher_id)ptr2id(hp->native_handle);
  ngtcp2_mbedtls_cipher_ctx *ctx = hp_ctx->native_handle;
  psa_cipher_operation_t op = PSA_CIPHER_OPERATION_INIT;
  uint8_t buf[16];
  size_t outlen = 0, finlen = 0;
  psa_status_t status;

  if (id == NGTCP2_MBEDTLS_CIPHER_CHACHA20) {
    return mbedtls_ssl_quic_generate_chacha20_hp_mask(ctx->raw_key, sample,
                                                       dest) == 0 ? 0 : -1;
  }

  status = psa_cipher_encrypt_setup(&op, ctx->key, ctx->alg);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_cipher_update(&op, sample, 16, buf, sizeof(buf), &outlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  status = psa_cipher_finish(&op, buf + outlen, sizeof(buf) - outlen, &finlen);
  if (status != PSA_SUCCESS) {
    goto fail;
  }

  memcpy(dest, buf, 5);
  return 0;

fail:
  psa_cipher_abort(&op);
  return -1;
}

static mbedtls_ssl_quic_encryption_level
mbedtls_from_ngtcp2_level(ngtcp2_encryption_level level) {
  switch (level) {
  case NGTCP2_ENCRYPTION_LEVEL_INITIAL:
    return MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_INITIAL;
  case NGTCP2_ENCRYPTION_LEVEL_0RTT:
    return MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_EARLY_DATA;
  case NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE:
    return MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_HANDSHAKE;
  case NGTCP2_ENCRYPTION_LEVEL_1RTT:
    return MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_APPLICATION;
  default:
    assert(0);
    abort();
  }
}

static ngtcp2_encryption_level
ngtcp2_from_mbedtls_level(mbedtls_ssl_quic_encryption_level level) {
  switch (level) {
  case MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_INITIAL:
    return NGTCP2_ENCRYPTION_LEVEL_INITIAL;
  case MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_EARLY_DATA:
    return NGTCP2_ENCRYPTION_LEVEL_0RTT;
  case MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_HANDSHAKE:
    return NGTCP2_ENCRYPTION_LEVEL_HANDSHAKE;
  case MBEDTLS_SSL_QUIC_ENCRYPTION_LEVEL_APPLICATION:
    return NGTCP2_ENCRYPTION_LEVEL_1RTT;
  default:
    assert(0);
    abort();
  }
}

int ngtcp2_crypto_read_write_crypto_data(
  ngtcp2_conn *conn, ngtcp2_encryption_level encryption_level,
  const uint8_t *data, size_t datalen) {
  mbedtls_ssl_context *ssl = ngtcp2_conn_get_tls_native_handle2(conn);
  int rv;

  if (datalen > 0 &&
      mbedtls_ssl_provide_quic_data(
        ssl, mbedtls_from_ngtcp2_level(encryption_level), data, datalen) != 0) {
    return -1;
  }

  if (!ngtcp2_conn_get_handshake_completed2(conn)) {
    rv = mbedtls_ssl_handshake(ssl);
    if (rv != 0) {
      if (rv == MBEDTLS_ERR_SSL_WANT_READ ||
          rv == MBEDTLS_ERR_SSL_WANT_WRITE) {
        return 0;
      }
      return -1;
    }

    ngtcp2_conn_tls_handshake_completed(conn);
  }

  return 0;
}

int ngtcp2_crypto_set_remote_transport_params(ngtcp2_conn *conn, void *tls) {
  const uint8_t *tp;
  size_t tplen;
  int rv;

  if (mbedtls_ssl_get_peer_quic_transport_params(tls, &tp, &tplen) != 0) {
    return -1;
  }

  rv = ngtcp2_conn_decode_and_set_remote_transport_params(conn, tp, tplen);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  return 0;
}

int ngtcp2_crypto_set_local_transport_params(void *tls, const uint8_t *buf,
                                             size_t len) {
  return mbedtls_ssl_set_quic_transport_params(tls, buf, len) == 0 ? 0 : -1;
}

int ngtcp2_crypto_get_path_challenge_data_cb(ngtcp2_conn *conn, uint8_t *data,
                                             void *user_data) {
  (void)conn;
  (void)user_data;

  return ensure_psa_initialized() == 0 &&
           psa_generate_random(data, NGTCP2_PATH_CHALLENGE_DATALEN) ==
             PSA_SUCCESS ?
         0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

int ngtcp2_crypto_get_path_challenge_data2_cb(ngtcp2_conn *conn,
                                              ngtcp2_path_challenge_data *data,
                                              void *user_data) {
  (void)conn;
  (void)user_data;

  return ensure_psa_initialized() == 0 &&
           psa_generate_random(data->data, NGTCP2_PATH_CHALLENGE_DATALEN) ==
             PSA_SUCCESS ?
         0 : NGTCP2_ERR_CALLBACK_FAILURE;
}

int ngtcp2_crypto_random(uint8_t *data, size_t datalen) {
  return ensure_psa_initialized() == 0 &&
           psa_generate_random(data, datalen) == PSA_SUCCESS ?
         0 : -1;
}

static ngtcp2_conn *get_conn(mbedtls_ssl_context *ssl) {
  ngtcp2_crypto_conn_ref *conn_ref = mbedtls_ssl_get_user_data_p(ssl);

  return conn_ref->get_conn(conn_ref);
}

static int set_read_secret(void *ctx, mbedtls_ssl_quic_encryption_level level,
                           const unsigned char *secret, size_t secretlen) {
  ngtcp2_conn *conn = get_conn(ctx);

  return ngtcp2_crypto_derive_and_install_rx_key(
    conn, NULL, NULL, NULL, ngtcp2_from_mbedtls_level(level), secret,
    secretlen);
}

static int set_write_secret(void *ctx, mbedtls_ssl_quic_encryption_level level,
                            const unsigned char *secret, size_t secretlen) {
  ngtcp2_conn *conn = get_conn(ctx);

  return ngtcp2_crypto_derive_and_install_tx_key(
    conn, NULL, NULL, NULL, ngtcp2_from_mbedtls_level(level), secret,
    secretlen);
}

static int add_handshake_data(void *ctx,
                              mbedtls_ssl_quic_encryption_level level,
                              const unsigned char *data, size_t datalen) {
  ngtcp2_conn *conn = get_conn(ctx);
  int rv;

  rv = ngtcp2_conn_submit_crypto_data(conn, ngtcp2_from_mbedtls_level(level),
                                      data, datalen);
  if (rv != 0) {
    ngtcp2_conn_set_tls_error(conn, rv);
    return -1;
  }

  return 0;
}

static int flush_flight(void *ctx) {
  (void)ctx;
  return 0;
}

static int send_alert(void *ctx, mbedtls_ssl_quic_encryption_level level,
                      unsigned char alert) {
  ngtcp2_conn *conn = get_conn(ctx);

  (void)level;

  ngtcp2_conn_set_tls_alert(conn, alert);
  return 0;
}

static const mbedtls_ssl_quic_method quic_method = {
  set_read_secret,
  set_write_secret,
  add_handshake_data,
  flush_flight,
  send_alert,
};

static int crypto_mbedtls_configure_session(mbedtls_ssl_context *ssl) {
  if (ensure_psa_initialized() != 0) {
    return -1;
  }

  return mbedtls_ssl_set_quic_method(ssl, &quic_method, ssl) == 0 ? 0 : -1;
}

int ngtcp2_crypto_mbedtls_configure_server_session(mbedtls_ssl_context *ssl) {
  return crypto_mbedtls_configure_session(ssl);
}

int ngtcp2_crypto_mbedtls_configure_client_session(mbedtls_ssl_context *ssl) {
  return crypto_mbedtls_configure_session(ssl);
}
