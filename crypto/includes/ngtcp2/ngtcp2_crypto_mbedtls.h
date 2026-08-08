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
#ifndef NGTCP2_CRYPTO_MBEDTLS_H
#define NGTCP2_CRYPTO_MBEDTLS_H

#include <ngtcp2/ngtcp2.h>

#include <mbedtls/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif /* defined(__cplusplus) */

/**
 * @function
 *
 * `ngtcp2_crypto_mbedtls_configure_server_session` configures |ssl|
 * for server side QUIC connection.
 *
 * Application must set a pointer to :type:`ngtcp2_crypto_conn_ref` to
 * |ssl| by calling `mbedtls_ssl_set_user_data_p`, and
 * :type:`ngtcp2_crypto_conn_ref` object must have
 * :member:`ngtcp2_crypto_conn_ref.get_conn` field assigned to get
 * :type:`ngtcp2_conn`.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_mbedtls_configure_server_session(
  mbedtls_ssl_context *ssl);

/**
 * @function
 *
 * `ngtcp2_crypto_mbedtls_configure_client_session` configures |ssl|
 * for client side QUIC connection.
 *
 * Application must set a pointer to :type:`ngtcp2_crypto_conn_ref` to
 * |ssl| by calling `mbedtls_ssl_set_user_data_p`, and
 * :type:`ngtcp2_crypto_conn_ref` object must have
 * :member:`ngtcp2_crypto_conn_ref.get_conn` field assigned to get
 * :type:`ngtcp2_conn`.
 *
 * It returns 0 if it succeeds, or -1.
 */
NGTCP2_EXTERN int ngtcp2_crypto_mbedtls_configure_client_session(
  mbedtls_ssl_context *ssl);

#ifdef __cplusplus
}
#endif /* defined(__cplusplus) */

#endif /* !defined(NGTCP2_CRYPTO_MBEDTLS_H) */
