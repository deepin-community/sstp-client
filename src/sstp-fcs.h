/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief Declaration for HDLC frame encoding
 *
 * @file sstp-fcs.h
 *
 * @author Copyright (C) 2011 Eivind Naess,
 *      All Rights Reserved
 */
#ifndef __SSTP_FCS_H__
#define __SSTP_FCS_H__


/*< Initial FCS value */
#define PPPINITFCS16        0xffff

/*< Good final FCS value */
#define PPPGOODFCS16        0xf0b8

#define HDLC_FLAG           0x7E
#define HDLC_ESCAPE         0x7D
#define HDLC_TRANSPARENCY   0x20


/*! 
 * @brief Calculate checksum of a frame per RFC1662
 */
uint16_t sstp_frame_check(uint16_t fcs, const unsigned char *cp, int len);

/*!
 * @brief Decode a frame from the buffer and decapsulate it
 */
status_t sstp_frame_decode(const unsigned char *buf, int *length, 
    unsigned char *frame, int *size);

/*!
 * @brief Encode input buffer with HDLC framing
 */
status_t sstp_frame_encode(const unsigned char *source, int ilen, 
        unsigned char *frame, int *flen);

#endif /* #ifndef __SSTP_FCS_H__ */
