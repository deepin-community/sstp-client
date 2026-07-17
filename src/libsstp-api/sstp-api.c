/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Functions for libsstp-api
 *
 * @file sstp-api.c
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#include <config.h>
#include <stdint.h>
#include <string.h>

#include <sstp-api.h>


SSTP_API 
sstp_api_msg_st *sstp_api_msg_new(unsigned char *buf, sstp_api_msg_t type)
{
    sstp_api_msg_st *msg = (sstp_api_msg_st*) buf;
    msg->msg_magic = SSTP_API_MSG_MAGIC;
    msg->msg_type  = type;
    msg->msg_len   = 0;
    return msg;
}


SSTP_API 
int sstp_api_msg_len(sstp_api_msg_st *msg)
{
    return (sizeof(*msg) + msg->msg_len);
}


SSTP_API
int sstp_api_msg_type(sstp_api_msg_st *msg, sstp_api_msg_t *type)
{
    int retval = (-1);

    /* Check the signature */
    if (msg->msg_magic != SSTP_API_MSG_MAGIC)
    {
        goto done;
    }

    /* Return the message type */
    *type = msg->msg_type;

    /* Success! */
    retval = 0;

done:

    return (retval);
}


SSTP_API 
void sstp_api_attr_add(sstp_api_msg_st *msg, sstp_api_attr_t type, 
    unsigned int len, void *data)
{
    sstp_api_attr_st *attr = (sstp_api_attr_st*) 
            &msg->msg_data[msg->msg_len];

    attr->attr_type = type;
    attr->attr_len  = len;
    memcpy(&attr->attr_data[0], data, attr->attr_len);
    msg->msg_len += (sizeof(*attr) + ALIGN32(attr->attr_len));
}


SSTP_API 
int sstp_api_attr_parse(char *buf, int length, sstp_api_attr_st *list[],
        int count)
{
    int index = 0;

    /* Reset the list of attribute pointers */
    memset(list, 0, sizeof(sstp_api_attr_st*) * count);
    
    /* Iterate over the memory */
    while (index < length)
    {
        /* Get the attribute */
        sstp_api_attr_st* attr = (sstp_api_attr_st*) &buf[index];
        if (attr->attr_type >  SSTP_API_ATTR_MAX ||
            attr->attr_type <= SSTP_API_ATTR_UNKNOWN)
        {
            return -1;
        }

        /* Assign the attribute type and increment length */
        list[attr->attr_type] = attr;
        index += (sizeof(*attr) + ALIGN32(attr->attr_len));
    }

    return 0;
}


