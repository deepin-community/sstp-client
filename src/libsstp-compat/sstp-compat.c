/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Provide compability layer for sstp-client and other libraries
 *
 * @file sstp-comapt.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#include <config.h>
#include <sstp-compat.h>

#ifndef HAVE_LIBEVENT2

event_st *event_new(event_base_st *base, int sock, short fl, 
    event_fn cb, void *arg)
{
    event_st *event = calloc(1, sizeof(event_st));
    if (event)
    {
        event_set(event, sock, fl, cb, arg);
        event_base_set(base, event);
    }

    return event;
}


void event_free(event_st *event)
{
    free(event);
}

#endif
