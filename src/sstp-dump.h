/* SPDX-License-Identifier: GPL-2.0-or-later */
/*!
 * @brief The packet dump related declarations
 *
 * @file sstp-dump.h
 *
 * @author Copyright (C) 2011 Eivind Naess, 
 *      All Rights Reserved
 */

#ifndef __SSTP_DUMP_H__
#define __SSTP_DUMP_H__

void sstp_pkt_dump(sstp_buff_st *buf, sstp_direction_t dir, const char *file, int line);

#endif /* #ifdef __SSTP_DUMP_H__ */
