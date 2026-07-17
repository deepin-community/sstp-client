/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief This is the sstp-client code
 *
 * @file sstp-client.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_CLIENT_H__
#define __SSTP_CLIENT_H__

/*!
 * @brief Simple peer structure for our oposite end
 */
typedef struct sstp_peer
{
    /*! The peer name */
    char name[255];

    /*! The address information of our peer */
    struct sockaddr_storage addr;

    /*! The address length */
    socklen_t alen;
    
    /*! The peer's ssl session (for re-connect) */
    void *ssl_session;

} sstp_peer_st;


/*!
 * @brief Client context structure
 */
typedef struct
{
    /*! The active server url */
    sstp_url_st *url;

    /*! The server peer */
    sstp_peer_st host;

    /*! The extended options */
    sstp_option_st option;

    /*! The SSL I/O streams */
    sstp_stream_st *stream;

    /*! The pppd context */
    sstp_pppd_st *pppd;

    /*! The HTTP handshake context */
    sstp_http_st *http;

    /*! The SSTP layer state machine */
    sstp_state_st *state;

    /*! The ip-up notification helper */
    sstp_event_st *event;

    /*! The particular server route */
    sstp_route_st route;

    /*! The route context */
    sstp_route_ctx_st *route_ctx;

    /*! The SSL context */
    SSL_CTX *ssl_ctx;

    /*! The event base */
    event_base_st *ev_base;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    /*! The legacy provider */
    OSSL_PROVIDER *legacy;

    /*! The default provider */
    OSSL_PROVIDER *provider;
#endif

} sstp_client_st;


#endif  /* #ifndef __SSTP_CLIENT_H__ */
