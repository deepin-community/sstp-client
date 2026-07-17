/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Provide common declarations for the sstp project
 *
 * @file sstp-common.h
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_COMMON_H__
#define __SSTP_COMMON_H__

/*!
 * @brief Common return values
 */
typedef enum
{
    /*!< Generic failure */
    SSTP_FAIL   = -1,

    /*!< General okay */
    SSTP_OKAY   =  0,
    
    /*!< Operation in progress */
    SSTP_INPROG = 1,

    /*!< Socket connected */
    SSTP_CONNECTED = 2,

    /*!< Buffer overflow */
    SSTP_OVERFLOW = 3,

    /*!< Not implemented (yet) */
    SSTP_NOTIMPL = 4,

    /*!< Operation timed out */
    SSTP_TIMEOUT = 5,

    /*!< Authentication required */
    SSTP_AUTHENTICATE = 6,

} status_t;

#endif	/* #ifndef __SSTP_COMMON_H__ */
