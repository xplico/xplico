/* gtp.h
 *
 * $Id:$
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */


#ifndef __GTP_H__
#define __GTP_H__


/* definitions of GTP messages */
#define GTP_MSG_UNKNOWN             0x00
#define GTP_MSG_ECHO_REQ            0x01
#define GTP_MSG_ECHO_RESP           0x02
#define GTP_MSG_VER_NOT_SUPP        0x03
#define GTP_MSG_NODE_ALIVE_REQ      0x04
#define GTP_MSG_NODE_ALIVE_RESP     0x05
#define GTP_MSG_REDIR_REQ           0x06
#define GTP_MSG_REDIR_RESP          0x07
#define GTP_MSG_CREATE_PDP_REQ      0x10
#define GTP_MSG_CREATE_PDP_RESP     0x11
#define GTP_MSG_UPDATE_PDP_REQ      0x12
#define GTP_MSG_UPDATE_PDP_RESP     0x13
#define GTP_MSG_DELETE_PDP_REQ      0x14
#define GTP_MSG_DELETE_PDP_RESP     0x15
#define GTP_MSG_CREATE_AA_PDP_REQ   0x16    /* 2G */
#define GTP_MSG_CREATE_AA_PDP_RESP  0x17    /* 2G */
#define GTP_MSG_DELETE_AA_PDP_REQ   0x18    /* 2G */
#define GTP_MSG_DELETE_AA_PDP_RESP  0x19    /* 2G */
#define GTP_MSG_ERR_IND             0x1A
#define GTP_MSG_PDU_NOTIFY_REQ      0x1B
#define GTP_MSG_PDU_NOTIFY_RESP     0x1C
#define GTP_MSG_PDU_NOTIFY_REJ_REQ  0x1D
#define GTP_MSG_PDU_NOTIFY_REJ_RESP 0x1E
#define GTP_MSG_SUPP_EXT_HDR        0x1F
#define GTP_MSG_SEND_ROUT_INFO_REQ  0x20
#define GTP_MSG_SEND_ROUT_INFO_RESP 0x21
#define GTP_MSG_FAIL_REP_REQ        0x22
#define GTP_MSG_FAIL_REP_RESP       0x23
#define GTP_MSG_MS_PRESENT_REQ      0x24
#define GTP_MSG_MS_PRESENT_RESP     0x25
#define GTP_MSG_IDENT_REQ           0x30
#define GTP_MSG_IDENT_RESP          0x31
#define GTP_MSG_SGSN_CNTXT_REQ      0x32
#define GTP_MSG_SGSN_CNTXT_RESP     0x33
#define GTP_MSG_SGSN_CNTXT_ACK      0x34
#define GTP_MSG_FORW_RELOC_REQ      0x35
#define GTP_MSG_FORW_RELOC_RESP     0x36
#define GTP_MSG_FORW_RELOC_COMP     0x37
#define GTP_MSG_RELOC_CANCEL_REQ    0x38
#define GTP_MSG_RELOC_CANCEL_RESP   0x39
#define GTP_MSG_FORW_SRNS_CNTXT     0x3A
#define GTP_MSG_FORW_RELOC_ACK      0x3B
#define GTP_MSG_FORW_SRNS_CNTXT_ACK 0x3C


#define GTP_MSG_RAN_INFO_RELAY      70
#define GTP_MBMS_NOTIFY_REQ         96
#define GTP_MBMS_NOTIFY_RES         97
#define GTP_MBMS_NOTIFY_REJ_REQ     98
#define GTP_MBMS_NOTIFY_REJ_RES     99
#define GTP_CREATE_MBMS_CNTXT_REQ   100
#define GTP_CREATE_MBMS_CNTXT_RES   101
#define GTP_UPD_MBMS_CNTXT_REQ      102
#define GTP_UPD_MBMS_CNTXT_RES      103
#define GTP_DEL_MBMS_CNTXT_REQ      104
#define GTP_DEL_MBMS_CNTXT_RES      105
#define GTP_MBMS_REG_REQ            112
#define GTP_MBMS_REG_RES            113
#define GTP_MBMS_DE_REG_REQ         114
#define GTP_MBMS_DE_REG_RES         115
#define GTP_MBMS_SES_START_REQ      116
#define GTP_MBMS_SES_START_RES      117
#define GTP_MBMS_SES_STOP_REQ       118
#define GTP_MBMS_SES_STOP_RES       119
#define GTP_MBMS_SES_UPD_REQ        120
#define GTP_MBMS_SES_UPD_RES        121
/* 122-127  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MS_INFO_CNG_NOT_REQ     128
#define GTP_MS_INFO_CNG_NOT_RES     129
/* 130-239  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MSG_DATA_TRANSF_REQ     0xF0
#define GTP_MSG_DATA_TRANSF_RESP    0xF1
/* 242-254  For future use. Shall not be sent.
 * If received, shall be treated as an Unknown message.
 */
#define GTP_MSG_END_MARKER          0xFE /* 254 */
#define GTP_MSG_TPDU                0xFF


#define GTP_MIN_HEADER_SIZE         8

typedef struct _gtphdr_t gtphdr;
struct _gtphdr_t {
    unsigned char npdu:1;     /* N-PDU number flag */
    unsigned char seq:1;      /* sequence number flag */
    unsigned char ext:1;      /* extension header flag */
    unsigned char res:1;      /* reserved */
    unsigned char prot:1;     /* protocol type */
    unsigned char ver:3;      /* version */
    unsigned char mtype;      /* message Type */
    unsigned short len;       /* length */
    unsigned int teid;        /* tunnel endpoint identifier */
    unsigned short seq_num;   /* sequence number */
    unsigned char npdu_num;   /* N-PDU number */
    unsigned char neht;       /* next extension header type */
} __attribute__((packed));


#endif /* __GTP_H__ */
