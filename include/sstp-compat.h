/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Provide compability layer for sstp-client and other libraries
 *
 * @file sstp-comapt.h
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_COMPAT_H__
#define __SSTP_COMPAT_H__

#include <event.h>
#include <openssl/ssl.h>

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/provider.h>
#include <openssl/core_names.h>
#endif

#if HAVE_LIBEVENT2
#include <event2/dns.h>
#include <event2/util.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#else
#include <event.h>
#endif


typedef struct event_base event_base_st;
typedef struct event event_st;
typedef void (*event_fn)(int, short, void *);

#ifndef HAVE_LIBEVENT2

/*! 
 * @brief provide a dummy function for missing event_new of libevent 1.4
 */
event_st *event_new(event_base_st *base, int sock, short fl, 
    event_fn cb, void *arg);


/*! 
 * @brief provide a dummy function for missing event_free of libevent 1.4
 */
void event_free(event_st *event);

#endif  /* #ifndef HAVE_LIBEVENT2 */



#endif	/* #ifndef __SSTP_COMMON_H__ */
