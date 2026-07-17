/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief API to obtain correct Crypto Binding (CMAC Field)
 *
 * @file sstp-cmac.h
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_CMAC_H__
#define __SSTP_CMAC_H__


/*< Set SHA1 operation for the crypto binding */
#define SSTP_CMAC_SHA1      SSTP_PROTO_HASH_SHA1

/*< Set SHA256 operation for the crypto binding */
#define SSTP_CMAC_SHA256    SSTP_PROTO_HASH_SHA256

/*< Specify server mode, HLAK: MPPE(RECV) | MPPE(SEND) */
#define SSTP_CMAC_SERVER    0x04

/*< THe length of HLAK key */
#define SSTP_HLAK_KEYLEN    32

/*< The maximum size of the MPPE key supported */
#define SSTP_MPPE_MAX_KEYLEN 32


struct camc_ctx;
typedef struct cmac_ctx cmac_ctx_st;

/*!
 * @brief Initialize a request to generate the CMAC Attribute
 */
int sstp_cmac_init(cmac_ctx_st **ctx, int flag);


/*! 
 * @brief Set the MPPE key for send operation
 */
void sstp_cmac_send_key(cmac_ctx_st *ctx, uint8_t *key, size_t len);


/*!
 * @brief Set the MPPE key for recv operation
 */
void sstp_cmac_recv_key(cmac_ctx_st *ctx, uint8_t *key, size_t len);


/*! 
 * @brief Generate the CMAC Field
 * @param msg    [IN]   The entire 112 bytes of the CONNECTED w/CMAC zeroed out
 * @param mlen   [IN]   The length of the message
 * @param result [IN]   The resulting Crypto Binding attribute for CMAC
 * @param length [IN]   The length of the result buffer
 */
int sstp_cmac_result(cmac_ctx_st *ctx, uint8_t *msg, int mlen, uint8_t *result, size_t length);


/**
 * @brief Free the cmac_ctx_st structure
 */
void sstp_cmac_free(cmac_ctx_st *ctx);

#endif
