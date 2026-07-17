/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Abstraction for when mppe.h isn't available
 *
 * @file sstp-mppe.c
 *
 * @author Copyright (C) 2021 Eivind Naess, 
 *      All Rights Reserved
 */

#include <config.h>

#include <string.h>
#include <stdarg.h>
#include <pppd/pppd.h>
#include <sstp-pppd-compat.h>

#ifndef HAVE_MPPE_KEYS_FUNCTIONS

#define MPPE_MAX_KEY_SIZE 16
extern u_char mppe_send_key[MPPE_MAX_KEY_SIZE];
extern u_char mppe_recv_key[MPPE_MAX_KEY_SIZE];
extern int mppe_keys_set;

/*
 * Get the MPPE send key
 */
int mppe_get_send_key(u_char *send_key, int length)
{
    if (mppe_keys_isset()) {
        if (length > MPPE_MAX_KEY_SIZE)
            length = MPPE_MAX_KEY_SIZE;
        memcpy(mppe_send_key, send_key, length);
        return length;
    }
    return 0;
}

/*
 * Get the MPPE recv key
 */
int mppe_get_recv_key(u_char *recv_key, int length)
{
    if (mppe_keys_isset()) {
        if (length > mppe_keys_set)
            length = MPPE_MAX_KEY_SIZE;
        memcpy(mppe_recv_key, recv_key, length);
        return length;
    }
    return 0;
}

/*
 * Check if the MPPE keys are set
 */
bool mppe_keys_isset(void)
{
    return !!mppe_keys_set;
}

#endif  // HAVE_MPPE_KEYS_FUNCTIONS
