/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Routines for handling CHAP authentication.
 *
 * @file sstp-chap.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_CHAP_H__
#define __SSTP_CHAP_H__


#define SSTP_CHAP_SENDING   0x01
#define SSTP_CHAP_SERVER    0x02


/*!
 * @brief The data snooped from pppd
 */
typedef struct sstp_chap
{
    /* The challenge field */
    unsigned char challenge[16];

    /*! The response field */
    unsigned char response[8];

    /*! The NT Response field */
    unsigned char nt_response[24];

    /*! Any flags */
    unsigned char flags[1];

} __attribute__((packed)) sstp_chap_st;
 
#define MSCHAP_VALUE_LEN 49     // sizeof(sstp_chap)

/*! 
 * @brief Takes the CHAP context and generate the MPPE key
 *
 * @param ctx   The ms-chap hanshake context
 * @param password  The user's password
 * @param skey      The resulting MPEE send key
 * @param rkey      The resulting MPPE receive key
 * @param server    Are we acting as a server?
 *
 * @retval 0: success, -1: failure
 */
int sstp_chap_mppe_get(sstp_chap_st *ctx, const char *password, 
        uint8_t skey[16], uint8_t rkey[16], char server);
 
#endif
