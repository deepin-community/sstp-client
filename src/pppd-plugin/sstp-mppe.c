/*!
 * @brief Abstraction for when mppe.h isn't available
 *
 * @file sstp-mppe.c
 *
 * @author Copyright (C) 2021 Eivind Naess, 
 *      All Rights Reserved
 *
 * @par License:
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <pppd/pppd.h>
#include <sstp-mppe.h>

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
        BCOPY(mppe_send_key, send_key, length);
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
        BCOPY(mppe_recv_key, recv_key, length);
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

#endif  // #ifdef HAVE_MPPE_KEYS_FUNCTIONS
