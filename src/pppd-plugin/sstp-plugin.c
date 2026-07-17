/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Plugin for pppd to relay the MPPE keys to sstp-client
 *
 * @file sstp-plugin.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#include <config.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <sstp-api.h>

#include "sstp-pppd-compat.h"

#define SSTP_MAX_BUFLEN             255

#define PPP_PROTO_PAP               0xc023
#define PPP_PROTO_CHAP              0xc223
#define PPP_PROTO_EAP               0xc227

#define SSTP_MPPE_MAX_KEYSIZE 32

/*!
 * @brief PPP daemon requires this symbol to be exported
 */
const char pppd_version [] = PPPD_VERSION;

/*! The socket we send sstp-client our MPPE keys */
static char sstp_sock[SSTP_MAX_BUFLEN+1];

/*! Set of options required for this module */
static option_t sstp_option [] = 
{
    { "sstp-sock", o_string, &sstp_sock, 
      "Set the address of the socket to connect back to sstp-client",
      OPT_PRIO | OPT_PRIV | OPT_STATIC, NULL, SSTP_MAX_BUFLEN
    }
};

/*!
 * @brief Exchange the MPPE keys with sstp-client
 */
static void sstp_send_notify()
{
    struct sockaddr_un addr;
    int ret  = (-1);
    int sock = (-1);
    int alen = (sizeof(addr));
    uint8_t buf[SSTP_MAX_BUFLEN+1];
    sstp_api_msg_st  *msg  = NULL;

    /* Open the socket */
    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock < 0) {
        fatal("Could not open socket to communicate with sstp-client");
    }

    /* Setup the address */
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sstp_sock, sizeof(addr.sun_path)-1);

    /* Connect the socket */
    ret = connect(sock, (struct sockaddr*) &addr, alen);
    if (ret < 0) {
        fatal("Could not connect to sstp-client (%s), %s (%d)", sstp_sock,
            strerror(errno), errno);
    }

    /* Create a new message */
    msg = sstp_api_msg_new(buf, SSTP_API_MSG_AUTH);
    
    /* If the MPPE keys are set, add them to the message */
    if (mppe_keys_isset()) {
        unsigned char key[SSTP_MPPE_MAX_KEYSIZE];
        int key_len;
    
        key_len = mppe_get_send_key(key, sizeof(key));
        if (key_len > 0) {
            sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_SEND, key_len, key);
            if (debug_on()) {
                dbglog("The mppe send key (%d): %0.*B", key_len, key_len, key);
            }
        }

        key_len = mppe_get_recv_key(key, sizeof(key));
        if (key_len > 0) {
            sstp_api_attr_add(msg, SSTP_API_ATTR_MPPE_RECV, key_len, key);
            if (debug_on()) {
                dbglog("The mppe recv key (%d): %0.*B", key_len, key_len, key);
            }
        }
        memset(key, 0, sizeof(key));
    }
   
    /* Send the structure */
    ret = send(sock, msg, sstp_api_msg_len(msg), 0);
    if (ret < 0) {
        fatal("Could not send data to sstp-client");
    }
    
    /* Wait for the ACK to be received */
    ret = recv(sock, msg, (sizeof(*msg)), 0);
    if (ret < 0 || ret != (sizeof(*msg))) {
        fatal("Could not wait for ack from sstp-client");
    }

    /* Clear the buffer, it may contain the MPPE keys */
    memset(buf, 0, sizeof(buf));

    /* Close socket */
    close(sock);
}

#if HAVE_AUTH_NOTIFIER_SUPPORT
/**
 * The introduction of pppd-2.4.9 now supports the callback via auth_up_notifier
 *    which previously was only done when peer had authenticated itself (server side).
 *
 * The benefit of this approach, is that we hook in after auth is completed; but before
 * CCP layer is brought up and will clear the MPPE keys.
 */
static void sstp_auth_done(void *arg, int dummy)
{
    sstp_send_notify();
}
#else

static bool sstp_sent_notify = 0;

/*!
 * @brief Make sure we send notification, if we didn't snoop MSCHAPv2
 * 
 * @par Note:
 *  IF MPPE was enabled, the keys have been zeroed out for security
 *  reasons. 
 *
 *  You can configure PAP, CHAP-MD5 and MSCHAP with the NAP service,
 *  these are disabled by Microsoft 2008 server by default.
 *
 *  BUG: If the MPPE keys are sent at ip-up; the WIN2K16 server expects 
 *  the MPPE keys to be all zero.
 */
static void sstp_ip_up(void *arg, int dummy)
{
    /* If notify haven't been sent yet, then send all zero for MPPE keys */
    if (!sstp_sent_notify) {

        /* Send *blank* MPPE keys to the sstpc client */
        sstp_send_notify();
        sstp_sent_notify = 1;
    }

    snoop_recv_hook = NULL;
}

/*!
 * @brief Snoop the Authentication Success packet, steal MPPE keys
 */
static void sstp_snoop_recv(unsigned char *buf, int len)
{
    unsigned int psize;
    unsigned int proto;
    bool pcomp;
    
    /* Skip the HDLC header */
    if (buf[0] == 0xFF && buf[1] == 0x03) {
        buf += 2;
        len -= 2;
    }
    
    /* Take into account protocol compression */
    pcomp = (buf[0] & 0x10);
    psize = pcomp ? 1 : 2;

    /* Too short of a packet */
    if (len <= psize) {
        return;
    }

    /* Stop snooping if it is not a LCP Auth CHAP/EAP packet */
    proto = (pcomp) ? buf[0] : (buf[0] << 8 | buf[1]);
    if (proto != PPP_PROTO_CHAP && proto != PPP_PROTO_EAP) {
        return;
    }
    
    buf += psize;
    len -= psize;

    /* Look for a SUCCESS packet indicating authentication complete */
    switch (proto) 
    {
    case PPP_PROTO_CHAP:
        if (buf[0] != CHAP_SUCCESS) {
            return;
        }
        break;
    case PPP_PROTO_EAP:
        if (buf[0] != EAP_SUCCESS) {
            return;
        }
        break;
    }
    
    /* Did the MPPE keys get set? */
    if (!mppe_keys_isset()) {
        return;
    }

    /* Notify SSTPC of the MPPE keys */
    sstp_send_notify();
    sstp_sent_notify = 1;

    /* Disable the send-hook */
    snoop_recv_hook = NULL;
}
#endif // #ifndef HAVE_AUTH_NOTIFIER_SUPPORT

/*!
 * @brief PPP daemon requires this symbol to be exported for initialization
 */
void plugin_init(void)
{
    /* Clear memory */
    memset(&sstp_sock, 0, sizeof(sstp_sock));

    /* Allow us to intercept options */
    ppp_add_options(sstp_option);

#if HAVE_AUTH_NOTIFIER_SUPPORT
    ppp_add_notify(NF_AUTH_UP, sstp_auth_done, NULL);
#else
    /* Let's snoop for CHAP authentication */
    snoop_recv_hook = sstp_snoop_recv;

    /* Add ip-up notifier */
    ppp_add_notify(NF_IP_UP, sstp_ip_up, NULL);
#endif
}

