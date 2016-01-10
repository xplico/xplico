/* mms_decode.c
 * Routines for decode mms message
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
 *
 * based on packet-mmse.c of Wireshark, Copyright 1998 Gerald Combs
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
 *
 */

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdlib.h>

#include "mms_decode.h"
#include "dmemory.h"

/* to run without xplico comment next line */
#define XPL_ON          1
#ifdef XPL_ON
# include "log.h"
# define printf(...)
#else
# define LogPrintf(...)
#endif

/*
 * Header field values
 */
/* MMS 1.0 */
#define MM_BCC_HDR		0x81	/* Bcc			*/
#define MM_CC_HDR		0x82	/* Cc			*/
#define MM_CLOCATION_HDR	0x83	/* X-Mms-Content-Location	*/
#define MM_CTYPE_HDR		0x84	/* Content-Type		*/
#define MM_DATE_HDR		0x85	/* Date				*/
#define MM_DREPORT_HDR		0x86	/* X-Mms-Delivery-Report	*/
#define MM_DTIME_HDR		0x87	/* X-Mms-Delivery-Time		*/
#define MM_EXPIRY_HDR		0x88	/* X-Mms-Expiry			*/
#define MM_FROM_HDR		0x89	/* From				*/
#define MM_MCLASS_HDR		0x8A	/* X-Mms-Message-Class		*/
#define MM_MID_HDR		0x8B	/* Message-ID			*/
#define MM_MTYPE_HDR		0x8C	/* X-Mms-Message-Type		*/
#define MM_VERSION_HDR		0x8D	/* X-Mms-MMS-Version		*/
#define MM_MSIZE_HDR		0x8E	/* X-Mms-Message-Size		*/
#define MM_PRIORITY_HDR		0x8F	/* X-Mms-Priority		*/
#define MM_RREPLY_HDR		0x90	/* X-Mms-Read-Reply		*/
#define MM_RALLOWED_HDR		0x91	/* X-Mms-Report-Allowed		*/
#define MM_RSTATUS_HDR		0x92	/* X-Mms-Response-Status	*/
#define MM_RTEXT_HDR		0x93	/* X-Mms-Response-Text		*/
#define MM_SVISIBILITY_HDR	0x94	/* X-Mms-Sender-Visibility	*/
#define MM_STATUS_HDR		0x95	/* X-Mms-Status			*/
#define MM_SUBJECT_HDR		0x96	/* Subject			*/
#define MM_TO_HDR		0x97	/* To				*/
#define MM_TID_HDR		0x98	/* X-Mms-Transaction-Id		*/
/* MMS 1.1 */
#define MM_RETRIEVE_STATUS_HDR	0x99	/* X-Mms-Retrieve-Status	*/
#define MM_RETRIEVE_TEXT_HDR	0x9A	/* X-Mms-Retrieve-Text		*/
#define MM_READ_STATUS_HDR	0x9B	/* X-Mms-Read-Status		*/
#define MM_REPLY_CHARGING_HDR	0x9C	/* X-Mms-Reply-Charging		*/
#define MM_REPLY_CHARGING_DEADLINE_HDR	\
				0x9D	/* X-Mms-Reply-Charging-Deadline*/
#define MM_REPLY_CHARGING_ID_HDR	\
				0x9E	/* X-Mms-Reply-Charging-ID	*/
#define MM_REPLY_CHARGING_SIZE_HDR	\
				0x9F	/* X-Mms-Reply-Charging-Size	*/
#define MM_PREV_SENT_BY_HDR	0xA0	/* X-Mms-Previously-Sent-By	*/
#define MM_PREV_SENT_DATE_HDR	0xA1	/* X-Mms-Previously-Sent-Date	*/
/* MMS 1.2 */
#define MM_STORE_HDR		0xA2	/* X-Mms-Store			*/
#define MM_MM_STATE_HDR		0xA3	/* X-Mms-MM-State		*/
#define MM_MM_FLAGS_HDR		0xA4	/* X-Mms-MM-Flags		*/
#define MM_STORE_STATUS_HDR	0xA5	/* X-Mms-Store-Status		*/
#define MM_STORE_STATUS_TEXT_HDR	\
				0xA6	/* X-Mms-Store-Status-Text	*/
#define MM_STORED_HDR		0xA7	/* X-Mms-Stored			*/
#define MM_ATTRIBUTES_HDR	0xA8	/* X-Mms-Attributes		*/
#define MM_TOTALS_HDR		0xA9	/* X-Mms-Totals			*/
#define MM_MBOX_TOTALS_HDR	0xAA	/* X-Mms-Mbox-Totals		*/
#define MM_QUOTAS_HDR		0xAB	/* X-Mms-Quotas			*/
#define MM_MBOX_QUOTAS_HDR	0xAC	/* X-Mms-Mbox-Quotas		*/
#define MM_MBOX_MSG_COUNT_HDR	0xAD	/* X-Mms-Message-Count		*/
#define MM_CONTENT_HDR		0xAE	/* Content			*/
#define MM_START_HDR		0xAF	/* X-Mms-Start			*/
#define MM_ADDITIONAL_HDR	0xB0	/* Additional-headers		*/
#define MM_DISTRIBUION_IND_HDR	0xB1	/* X-Mms-Distribution-Indcator	*/
#define MM_ELEMENT_DESCR_HDR	0xB2	/* X-Mms-Element-Descriptor	*/
#define MM_LIMIT_HDR		0xB3	/* X-Mms-Limit			*/

/*
 * Valuestrings for PDU types
 */
/* MMS 1.0 */
#define PDU_M_SEND_REQ		0x80
#define PDU_M_SEND_CONF		0x81
#define PDU_M_NOTIFICATION_IND	0x82
#define PDU_M_NOTIFYRESP_IND	0x83
#define PDU_M_RETRIEVE_CONF	0x84
#define PDU_M_ACKNOWLEDGE_IND	0x85
#define PDU_M_DELIVERY_IND	0x86
/* MMS 1.1 */
#define PDU_M_READ_REC_IND	0x87
#define PDU_M_READ_ORIG_IND	0x88
#define PDU_M_FORWARD_REQ	0x89
#define PDU_M_FORWARD_CONF	0x8A
/* MMS 1.2 */
#define PDU_M_MBOX_STORE_REQ	0x8B
#define PDU_M_MBOX_STORE_CONF	0x8C
#define PDU_M_MBOX_VIEW_REQ	0x8D
#define PDU_M_MBOX_VIEW_CONF	0x8E
#define PDU_M_MBOX_UPLOAD_REQ	0x8F
#define PDU_M_MBOX_UPLOAD_CONF	0x90
#define PDU_M_MBOX_DELETE_REQ	0x91
#define PDU_M_MBOX_DELETE_CONF	0x92
#define PDU_M_MBOX_DESCR	0x93

#define MM_QUOTE                0x22
#define MM_ABSOL_TOKEN          0x80
#define MM_RELAT_TOKEN          0x81


/* Typed parameter */
#define MMT_Q                   0x00
#define MMT_CHARSET             0x01
#define MMT_LEVEL               0x02
#define MMT_TYPE                0x03
#define MMT_NAME                0x05
#define MMT_FILENAME            0x06
#define MMT_DIFFERENCES         0x07
#define MMT_PADDING             0x08
#define MMT_TYPE_SPEC           0x09
#define MMT_START               0x0A
#define MMT_START_INFO          0x0B
#define MMT_COMMENT             0x0C
#define MMT_DOMAIN              0x0D
#define MMT_MAX_AGE             0x0E
#define MMT_PATH                0x0F
#define MMT_SECURE              0x10
#define MMT_SEC                 0x11
#define MMT_MAC                 0x12
#define MMT_CREATION_DATE       0x13
#define MMT_MODIFI_DATE         0x14
#define MMT_READ_DATE           0x15
#define MMT_SIZE                0x16
#define MMT_NAME_VAL            0x17
#define MMT_FILENAME_VAL        0x18
#define MMT_START_MULTI         0x19
#define MMT_START_INFO_MULTI    0x1A
#define MMT_COMMENT_VAL         0x1B
#define MMT_DOMAIN_VAL          0x1C
#define MMT_PATH_VAL            0x1D


typedef struct {
    unsigned short id;
    char *str;
} value_string;

static const value_string vals_message_type[] = {
    /* MMS 1.0 */
    { PDU_M_SEND_REQ,		"m-send-req" },
    { PDU_M_SEND_CONF,		"m-send-conf" },
    { PDU_M_NOTIFICATION_IND,	"m-notification-ind" },
    { PDU_M_NOTIFYRESP_IND,	"m-notifyresp-ind" },
    { PDU_M_RETRIEVE_CONF,	"m-retrieve-conf" },
    { PDU_M_ACKNOWLEDGE_IND,	"m-acknowledge-ind" },
    { PDU_M_DELIVERY_IND,	"m-delivery-ind" },
    /* MMS 1.1 */
    { PDU_M_READ_REC_IND,	"m-read-rec-ind" },
    { PDU_M_READ_ORIG_IND,	"m-read-orig-ind" },
    { PDU_M_FORWARD_REQ,	"m-forward-req" },
    { PDU_M_FORWARD_CONF,	"m-forward-conf" },
    /* MMS 1.2 */
    { PDU_M_MBOX_STORE_REQ,	"m-mbox-store-req" },
    { PDU_M_MBOX_STORE_CONF,	"m-mbox-store-conf" },
    { PDU_M_MBOX_VIEW_REQ,	"m-mbox-view-req" },
    { PDU_M_MBOX_VIEW_CONF,	"m-mbox-view-conf" },
    { PDU_M_MBOX_UPLOAD_REQ,	"m-mbox-upload-req" },
    { PDU_M_MBOX_UPLOAD_CONF,	"m-mbox-upload-conf" },
    { PDU_M_MBOX_DELETE_REQ,	"m-mbox-delete-req" },
    { PDU_M_MBOX_DELETE_CONF,	"m-mbox-delete-conf" },
    { PDU_M_MBOX_DESCR,		"m-mbox-descr" },
    { 0x00, NULL },
};


static const value_string vals_yes_no[] = {
    { 0x80, "Yes" },
    { 0x81, "No" },
    { 0x00, NULL },
};

static const value_string vals_message_class[] = {
    { 0x80, "Personal" },
    { 0x81, "Advertisement" },
    { 0x82, "Informational" },
    { 0x83, "Auto" },
    { 0x00, NULL },
};


static const value_string vals_priority[] = {
    { 0x80, "Low" },
    { 0x81, "Normal" },
    { 0x82, "High" },
    { 0x00, NULL },
};


static const value_string vals_response_status[] = {
    /* MMS 1.0 - obsolete as from MMS 1.1 */
    { 0x80, "Ok" },
    { 0x81, "Unspecified" },
    { 0x82, "Service denied" },
    { 0x83, "Message format corrupt" },
    { 0x84, "Sending address unresolved" },
    { 0x85, "Message not found" },
    { 0x86, "Network problem" },
    { 0x87, "Content not accepted" },
    { 0x88, "Unsupported message" },

    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Sending address unresolved" },
    { 0xC2, "Transient: Message not found" },
    { 0xC3, "Transient: Network problem" },
    /* MMS 1.2 */
    { 0xC4, "Transient: Partial success" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message format corrupt" },
    { 0xE3, "Permanent: Sending address unresolved" },
    { 0xE4, "Permanent: Message not found" },
    { 0xE5, "Permanent: Content not accepted" },
    { 0xE6, "Permanent: Reply charging limitations not met" },
    { 0xE7, "Permanent: Reply charging request not accepted" },
    { 0xE8, "Permanent: Reply charging forwarding denied" },
    { 0xE9, "Permanent: Reply charging not supported" },
    /* MMS 1.2 */
    { 0xEA, "Permanent: Address hiding not supported" },
    
    { 0x00, NULL },
};


static const value_string vals_sender_visibility[] = {
    { 0x80, "Hide" },
    { 0x81, "Show" },
    { 0x00, NULL },
};


static const value_string vals_message_status[] = {
    /* MMS 1.0 */
    { 0x80, "Expired" },
    { 0x81, "Retrieved" },
    { 0x82, "Rejected" },
    { 0x83, "Deferred" },
    { 0x84, "Unrecognized" },
    /* MMS 1.1 */
    { 0x85, "Indeterminate" },
    { 0x86, "Forwarded" },
    /* MMS 1.2 */
    { 0x87, "Unreachable" },
    
    { 0x00, NULL },
};

static const value_string vals_retrieve_status[] = {
    /*
     * Transient errors
     */
    /* MMS 1.1 */
    { 0xC0, "Transient failure" },
    { 0xC1, "Transient: Message not found" },
    { 0xC2, "Transient: Network problem" },

    /*
     * Permanent errors
     */
    /* MMS 1.1 */
    { 0xE0, "Permanent failure" },
    { 0xE1, "Permanent: Service denied" },
    { 0xE2, "Permanent: Message not found" },
    { 0xE3, "Permanent: Content unsupported" },

    { 0x00, NULL },
};


static const value_string vals_read_status[] = {
    { 0x80, "Read" },
    { 0x81, "Deleted without being read" },

    { 0x00, NULL },
};


static const value_string vals_reply_charging[] = {
    { 0x80, "Requested" },
    { 0x81, "Requested text only" },
    { 0x82, "Accepted" },
    { 0x83, "Accepted text only" },

    { 0x00, NULL },
};


static const value_string vals_content_types[] = {
    /* Well-known media types */
    { 0x00, "*/*" },
    { 0x01, "text/*" },
    { 0x02, "text/html" },
    { 0x03, "text/plain" },
    { 0x04, "text/x-hdml" },
    { 0x05, "text/x-ttml" },
    { 0x06, "text/x-vCalendar" },
    { 0x07, "text/x-vCard" },
    { 0x08, "text/vnd.wap.wml" },
    { 0x09, "text/vnd.wap.wmlscript" },
    { 0x0A, "text/vnd.wap.channel" },
    { 0x0B, "multipart/*" },
    { 0x0C, "multipart/mixed" },
    { 0x0D, "multipart/form-data" },
    { 0x0E, "multipart/byteranges" },
    { 0x0F, "multipart/alternative" },
    { 0x10, "application/*" },
    { 0x11, "application/java-vm" },
    { 0x12, "application/x-www-form-urlencoded" },
    { 0x13, "application/x-hdmlc" },
    { 0x14, "application/vnd.wap.wmlc" },
    { 0x15, "application/vnd.wap.wmlscriptc" },
    { 0x16, "application/vnd.wap.channelc" },
    { 0x17, "application/vnd.wap.uaprof" },
    { 0x18, "application/vnd.wap.wtls-ca-certificate" },
    { 0x19, "application/vnd.wap.wtls-user-certificate" },
    { 0x1A, "application/x-x509-ca-cert" },
    { 0x1B, "application/x-x509-user-cert" },
    { 0x1C, "image/*" },
    { 0x1D, "image/gif" },
    { 0x1E, "image/jpeg" },
    { 0x1F, "image/tiff" },
    { 0x20, "image/png" },
    { 0x21, "image/vnd.wap.wbmp" },
    { 0x22, "application/vnd.wap.multipart.*" },
    { 0x23, "application/vnd.wap.multipart.mixed" },
    { 0x24, "application/vnd.wap.multipart.form-data" },
    { 0x25, "application/vnd.wap.multipart.byteranges" },
    { 0x26, "application/vnd.wap.multipart.alternative" },
    { 0x27, "application/xml" },
    { 0x28, "text/xml" },
    { 0x29, "application/vnd.wap.wbxml" },
    { 0x2A, "application/x-x968-cross-cert" },
    { 0x2B, "application/x-x968-ca-cert" },
    { 0x2C, "application/x-x968-user-cert" },
    { 0x2D, "text/vnd.wap.si" },
    { 0x2E, "application/vnd.wap.sic" },
    { 0x2F, "text/vnd.wap.sl" },
    { 0x30, "application/vnd.wap.slc" },
    { 0x31, "text/vnd.wap.co" },
    { 0x32, "application/vnd.wap.coc" },
    { 0x33, "application/vnd.wap.multipart.related" },
    { 0x34, "application/vnd.wap.sia" },
    { 0x35, "text/vnd.wap.connectivity-xml" },
    { 0x36, "application/vnd.wap.connectivity-wbxml" },
    { 0x37, "application/pkcs7-mime" },
    { 0x38, "application/vnd.wap.hashed-certificate" },
    { 0x39, "application/vnd.wap.signed-certificate" },
    { 0x3A, "application/vnd.wap.cert-response" },
    { 0x3B, "application/xhtml+xml" },
    { 0x3C, "application/wml+xml" },
    { 0x3D, "text/css" },
    { 0x3E, "application/vnd.wap.mms-message" },
    { 0x3F, "application/vnd.wap.rollover-certificate" },
    { 0x40, "application/vnd.wap.locc+wbxml"},
    { 0x41, "application/vnd.wap.loc+xml"},
    { 0x42, "application/vnd.syncml.dm+wbxml"},
    { 0x43, "application/vnd.syncml.dm+xml"},
    { 0x44, "application/vnd.syncml.notification"},
    { 0x45, "application/vnd.wap.xhtml+xml"},
    { 0x46, "application/vnd.wv.csp.cir"},
    { 0x47, "application/vnd.oma.dd+xml"},
    { 0x48, "application/vnd.oma.drm.message"},
    { 0x49, "application/vnd.oma.drm.content"},
    { 0x4A, "application/vnd.oma.drm.rights+xml"},
    { 0x4B, "application/vnd.oma.drm.rights+wbxml"},
    { 0x4C, "application/vnd.wv.csp+xml"},
    { 0x4D, "application/vnd.wv.csp+wbxml"},
    /* The following media types are registered by 3rd parties */
    { 0x0201, "application/vnd.uplanet.cachop-wbxml" },
    { 0x0202, "application/vnd.uplanet.signal" },
    { 0x0203, "application/vnd.uplanet.alert-wbxml" },
    { 0x0204, "application/vnd.uplanet.list-wbxml" },
    { 0x0205, "application/vnd.uplanet.listcmd-wbxml" },
    { 0x0206, "application/vnd.uplanet.channel-wbxml" },
    { 0x0207, "application/vnd.uplanet.provisioning-status-uri" },
    { 0x0208, "x-wap.multipart/vnd.uplanet.header-set" },
    { 0x0209, "application/vnd.uplanet.bearer-choice-wbxml" },
    { 0x020A, "application/vnd.phonecom.mmc-wbxml" },
    { 0x020B, "application/vnd.nokia.syncset+wbxml" },
    { 0x020C, "image/x-up-wpng"},
    { 0x0300, "application/iota.mmc-wbxml"},
    { 0x0301, "application/iota.mmc-xml"},
    { 0x00, NULL }
};


static char *Value2String(unsigned char val, const value_string *array, char *def)
{
    int i = 0;

    while (array[i].str != NULL && array[i].id != val) {
        i++;
    }
    if (array[i].str == NULL)
        return def;
    
    return array[i].str;
}


static int MMSString(const unsigned char *data, const int dim, int offset, char **str)
{
    int i, j;

    i = offset;
    j = 0;
    if (data[i] == MM_QUOTE) {
        i++;
    }

    *str = xmalloc(strlen((const char *)data + i) + 1);
    
    while (data[i] > 0) {
        (*str)[j++] = (char)data[i++];
    }
    (*str)[j] = '\0';

    i++;
    
    return i-offset;
}


static unsigned int MMSUIntVar(const unsigned char *data, const int dim, int offset, int *count)
{
    unsigned int value = 0;
    unsigned int octet;
    unsigned int counter = 0;
    char cont = 1;

    while (cont != 0) {
        value<<=7;	/* Value only exists in 7 of the 8 bits */
        octet = data[offset+counter];
        counter++;
        value += (octet & 0x7F);
        cont = (octet & 0x80);
    }
    
    if (count != NULL) {
        *count += counter;
    }

    return value;
}


static int MMSValueLength(const unsigned char *data, const int dim, int offset, int *count)
{
    int ret = 0;
    unsigned int field;

    field = data[offset];
    (*count)++;
    
    if (field < 0x1F)
        ret = field;
    else if (field == 0x1F) {
        ret = MMSUIntVar(data, dim, offset+*count, count);
    }

    return ret;
}


static int MMSEncString(const unsigned char *data, const int dim, int offset, char **strval)
{
    int field;
    int length;
    int	count, i;

    field = data[offset];
    count = 0;
    if (field < 0x20) {
        length = MMSValueLength(data, dim, offset, &count);
        *strval = xmalloc(length);
	if (length < 2) {
	    **strval = '\0';
	} else {
            for (i=0; i!=length-1; i++) {
                (*strval)[i] = data[offset+count+1+i];
            }
            (*strval)[length] = '\0';
	}
	return count + length;
    }
    else
	return MMSString(data, dim, offset, strval);
}


static long MMSGetLongInt(const unsigned char *data, const int dim, int offset, int *count)
{
    long val;

    *count = data[offset++];
    switch (*count) {
	case 1:
	    val = data[offset];
	    break;
	case 2:
	    val = ntohs(*((unsigned short *)&data[offset]));
	    break;
	case 3:
	    /* ntoh24 */
	    break;
	case 4:
	    val = ntohl(*((unsigned int *)&data[offset]));
	    break;
	default:
	    val = 0;
	    break;
    }

    (*count)++;

    return val;
}


static int MMSReadContentType(const unsigned char *data, const int dim, int offset, unsigned int *well_known_content, char **str, char **name)
{
    unsigned char field;
    char *ct_str;
    int len, count, end;
    char *buff;
    int ret;

    field = data[offset];
    ct_str = NULL;
    *well_known_content = 0;
    len = ret = 0;
    if (field & 0x80) {
        ct_str = Value2String(field & 0x7F, vals_content_types, "Unknown type");
        *str = strdup(ct_str);
        ret = 1;
        *well_known_content = field & 0x7F;
    }
    else if ((field == 0) || (field >= 0x20)) {
        ret = MMSString(data, dim, offset, str);
        ret++;
        *well_known_content = 0;
    }
    else {
        count = 0;
        len = MMSValueLength(data, dim, offset, &count);
        offset += count;
        ret = len + count;
        end = offset + len;
        field = data[offset];
        if (((field == 0) || ( (field >= 32) && (field <= 127)) )) {
            count = MMSEncString(data, dim, offset, str);
            offset += count;
        }
        else if ((field  & 0x80 ) || field <= 30) {
            ct_str = Value2String(field & 0x7F, vals_content_types, "Unknown type");
            *str = strdup(ct_str);
            offset++;
            *well_known_content = field & 0x7F;
        } else {
            *str = xmalloc(1);
            (*str)[0] = '\0';
        }
        if (offset < end) {
            /* Add parameters if any */
            while (offset < end) {
                field = data[offset++] & 0x7F;
                switch (field) {
                case MMT_CHARSET:
                    if (data[offset] == 0x6A || data[offset] == 0xEA) {
                        printf("Parameter MMT_CHARSET: utf-8\n");
                    }
                    else {
                        printf("Parameter MMT_CHARSET: 0x%x\n", data[offset]);
                    }
                    offset++;
                    break;

                case MMT_TYPE_SPEC:
                    count = MMSEncString(data, dim, offset, &buff);
                    offset += count;
                    printf("Parameter MMT_TYPE_SPEC: %s\n", buff);
                    xfree(buff);
                    break;

                case MMT_START:
                    count = MMSEncString(data, dim, offset, &buff);
                    offset += count;
                    printf("Parameter MMT_START: %s\n", buff);
                    xfree(buff);
                    break;
                    
                case MMT_FILENAME:
                    count = MMSEncString(data, dim, offset, &buff);
                    offset += count;
                    printf("Parameter MMT_FILENAME: %s\n", buff);
                    xfree(buff);
                    break;

                case MMT_NAME:
                    count = MMSEncString(data, dim, offset, &buff);
                    offset += count;
                    printf("Parameter MMT_NAME: %s\n", buff);
                    if (name != NULL) {
                        *name = xmalloc(count+1);
                        strcpy(*name, buff);
                    }
                    xfree(buff);
                    break;

                default:
                    printf("Parameter unknow: 0x%x\n", field);
                    break;
                }
            }
        }
    }

    return ret;
}


static int MMSHeader(mms_message *msg, const unsigned char *data, const int dim, unsigned int *ctype)
{
    unsigned char field, pdu, version;
    char *str;
    const char *str_val;
    int offset, len, count, cnt, i;
    char cont = 1;
    unsigned char maj, min;
    long sec;

    offset = 0;
    version = 0x80; /* Default to MMSE 1.0 */
    strcpy(msg->version, "1.0");
    while (cont && offset < dim) {
        field = data[offset++];
        //printf("0x%x\n", field);
        if (!(field & 0x80)) {
            len = MMSString(data, dim, offset, &str);
            printf("Unknow: %s\n", str);
            xfree(str);
            offset += len;
            continue;
        }
        switch (field) {
        case MM_MTYPE_HDR:
            pdu = data[offset++];
            str_val = Value2String(pdu, vals_message_type, "Unknown type");
            msg->msg_type = xmalloc(strlen(str_val)+1);
            strcpy(msg->msg_type, str_val);
            printf("MM_MTYPE_HDR: %s\n", msg->msg_type);
            break;

        case MM_CTYPE_HDR:
            len = MMSReadContentType(data, dim, offset, ctype, &str, NULL);
            msg->cont_type = xmalloc(strlen(str)+1);
            strcpy(msg->cont_type, str);
            xfree(str);
            printf("MM_CTYPE_HDR: %s\n", msg->cont_type);
            offset += len;
            cont = 0;
            break;

        case MM_TID_HDR:		/* Text-string	*/
            len = MMSString(data, dim, offset, &str);
            printf("MM_TID_HDR: %s\n", str);
            xfree(str);
            offset += len;
            break;
            
        case MM_VERSION_HDR:		/* nibble-Major/nibble-minor*/
            version = data[offset++];
            maj = (version & 0x70) >> 4;
            min = version & 0x0F;
            if (min == 0x0F)
                sprintf(msg->version, "%i", maj);
            else
                sprintf(msg->version, "%i.%i", maj, min);
            break;

        case MM_BCC_HDR:		/* Encoded-string-value	*/
            len = MMSEncString(data, dim, offset, &str);
            printf("MM_BCC_HDR: %s\n", str);
            msg->bcc = str;
            offset += len;
            break;
            
        case MM_CC_HDR:			/* Encoded-string-value	*/
            len = MMSEncString(data, dim, offset, &str);
            printf("MM_BCC_HDR: %s\n", str);
            msg->cc = str;
            offset += len;
            break;

        case MM_CLOCATION_HDR:		/* Uri-value		*/
            if (pdu == PDU_M_MBOX_DELETE_CONF) {
                len = data[offset];
                count = 0;
                if (len == 0x1F) {
                    len = MMSUIntVar(data, dim, offset, &count);
                    len += 1 + count;
                }
                else {
                    len++;
                }
            }
            else {
                len = MMSString(data, dim, offset, &str);
                printf("MM_CLOCATION_HDR: %s\n", str);
                xfree(str);
            }
            offset += len;
            break;
            
        case MM_DATE_HDR:		/* Long-integer		*/
            count = 0;
            sec = MMSGetLongInt(data, dim, offset, &count);
            printf("MM_DATE_HDR: %s\n", ctime(&sec));
            offset += count;
            break;

        case MM_DREPORT_HDR:		/* Yes|No		*/
            field = data[offset];
            str_val = Value2String(field, vals_yes_no, "Unknown type");
            printf("MM_DREPORT_HDR: %s\n", str_val);
            offset++;
            break;
            
        case MM_DTIME_HDR:
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            field = data[offset + count];
            cnt = 0;
            sec = MMSGetLongInt(data, dim, offset + count + 1, &cnt);
            if (field == MM_ABSOL_TOKEN) {
                printf("MM_DTIME_HDR: %s\n", ctime(&sec));
            }
            else {
                printf("MM_DTIME_HDR: %li\n", sec);
            }
            offset += count + len;
            break;
            
        case MM_EXPIRY_HDR:
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            field = data[offset + count];
            cnt = 0;
            sec = MMSGetLongInt(data, dim, offset + count + 1, &cnt);
            if (field == MM_ABSOL_TOKEN) {
                printf("MM_EXPIRY_HDR: %s\n", ctime(&sec));
            }
            else {
                printf("MM_EXPIRY_HDR: %li\n", sec);
            }
            offset += count + len;
            break;
            
        case MM_FROM_HDR:
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            field = data[offset + count];
            if (field == MM_RELAT_TOKEN) {
                if (len > 1) {
                    str = xmalloc(len + 1);
                    for (i=0; i != len; i++)
                        str[i] = data[offset + i];
                    str[len] = '\0';
                }
                else {
                    str = xmalloc(1);
                    str[0] = '\0';
                }
                printf("MM_FROM_HDR 1: %s %i\n", str);
            }
            else {
                MMSEncString(data, dim, offset, &str);
                printf("MM_FROM_HDR 2: %s\n", str);
            }
            msg->from = str;
            offset += count + len;
            break;

        case MM_MCLASS_HDR:
            field = data[offset];
            if (field & 0x80) {
                offset++;
                str_val = Value2String(field, vals_message_class, "Unknown type");
                printf("MM_MCLASS_HDR: %s\n", str_val);
            }
            else {
                len = MMSString(data, dim, offset, &str);
                printf("MM_MCLASS_HDR: %s\n", str);
                xfree(str);
                offset += len;
            }
            break;

        case MM_MID_HDR:		/* Text-string		*/
            len = MMSString(data, dim, offset, &str);
            printf("MM_MID_HDR: %s\n", str);
            xfree(str);
            offset += len;
            break;

        case MM_MSIZE_HDR:		/* Long-integer		*/
            count = 0;
            len = MMSGetLongInt(data, dim, offset, &count);
            printf("MM_MSIZE_HDR: %i\n", len);
            offset += count;
            break;
            
        case MM_PRIORITY_HDR:		/* Low|Normal|High	*/
            field = data[offset];
            str_val = Value2String(field, vals_priority, "Unknown type");
            printf("MM_PRIORITY_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_RREPLY_HDR:		/* Yes|No		*/
            field = data[offset];
            str_val = Value2String(field, vals_yes_no, "Unknown type");
            printf("MM_RREPLY_HDR: %s\n", str_val);
            offset++;
            break;
            
        case MM_RALLOWED_HDR:		/* Yes|No		*/
            field = data[offset];
            str_val = Value2String(field, vals_yes_no, "Unknown type");
            printf("MM_RALLOWED_HDR: %s\n", str_val);
            offset++;
            break;
            
        case MM_RSTATUS_HDR:
            field = data[offset];
            str_val = Value2String(field, vals_response_status, "Unknown type");
            printf("MM_RSTATUS_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_RTEXT_HDR:		/* Encoded-string-value	*/
            if (pdu == PDU_M_MBOX_DELETE_CONF) {
                len = data[offset];
                count = 0;
                if (len == 0x1F) {
                    len = MMSUIntVar(data, dim, offset, &count);
                    len += 1 + count;
                }
                else {
                    len++;
                }
            }
            else {
                len = MMSEncString(data, dim, offset, &str);
                printf("MM_RTEXT_HDR: %s\n", str);
                xfree(str);
            }
            offset += len;
            break;

        case MM_SVISIBILITY_HDR:	/* Hide|Show		*/
            field = data[offset];
            str_val = Value2String(field, vals_sender_visibility, "Unknown type");
            printf("MM_SVISIBILITY_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_STATUS_HDR:
            field = data[offset];
            str_val = Value2String(field, vals_message_status, "Unknown type");
            printf("MM_STATUS_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_SUBJECT_HDR:		/* Encoded-string-value	*/
            len = MMSEncString(data, dim, offset, &str);
            printf("MM_SUBJECT_HDR: %s\n", str);
            xfree(str);
            offset += len;
            break;

        case MM_TO_HDR:			/* Encoded-string-value	*/
            len = MMSEncString(data, dim, offset, &str);
            printf("MM_TO_HDR: %s\n", str);
            msg->to = str;
            offset += len;
            break;

            /*
             * MMS Encapsulation 1.1
             */
        case MM_RETRIEVE_STATUS_HDR:	/* Well-known-value */
            field = data[offset];
            str_val = Value2String(field, vals_retrieve_status, "Unknown type");
            printf("MM_RETRIEVE_STATUS_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_RETRIEVE_TEXT_HDR:
            if (pdu == PDU_M_MBOX_DELETE_CONF) {
                len = data[offset];
                count = 0;
                if (len == 0x1F) {
                    len = MMSUIntVar(data, dim, offset, &count);
                    len += 1 + count;
                }
                else {
                    len++;
                }
            }
            else {
                len = MMSEncString(data, dim, offset, &str);
                printf("MM_RETRIEVE_TEXT_HDR: %s\n", str);
                xfree(str);
            }
            offset += len;
            break;

        case MM_READ_STATUS_HDR:	/* Well-known-value */
            field = data[offset];
            str_val = Value2String(field, vals_read_status, "Unknown type");
            printf("MM_READ_STATUS_HDR: %s\n", str_val);
            offset++;
            break;

        case MM_REPLY_CHARGING_HDR:	/* Well-known-value */
            field = data[offset];
            str_val = Value2String(field, vals_reply_charging, "Unknown type");
            printf("MM_REPLY_CHARGING_HDR: %s\n", str_val);
            break;

        case MM_REPLY_CHARGING_DEADLINE_HDR:	/* Well-known-value */
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            field = data[offset + count];
            cnt = 0;
            sec = MMSGetLongInt(data, dim, offset + count + 1, &cnt);
            if (field == MM_ABSOL_TOKEN) {
                printf("MM_REPLY_CHARGING_DEADLINE_HDR: %s\n", ctime(&sec));
            }
            else {
                printf("MM_REPLY_CHARGING_DEADLINE_HDR: %li\n", sec);
            }
            offset += count + len;
            break;

        case MM_REPLY_CHARGING_ID_HDR:	/* Text-string */
            len = MMSString(data, dim, offset, &str);
            printf("MM_REPLY_CHARGING_ID_HDR: %s\n", str);
            xfree(str);
            offset += len;
            break;
            
        case MM_REPLY_CHARGING_SIZE_HDR:	/* Long-integer */
            count = 0;
            len = MMSGetLongInt(data, dim, offset, &count);
            printf("MM_REPLY_CHARGING_SIZE_HDR: %i\n", len);
            offset += count;
            break;

        case MM_PREV_SENT_BY_HDR:
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            printf("MM_PREV_SENT_BY_HDR: %i\n", len);
            offset += len + count;
            break;

        case MM_PREV_SENT_DATE_HDR:
            count = 0;
            len = MMSValueLength(data, dim, offset, &count);
            printf("MM_PREV_SENT_DATE_HDR: %i\n", len);
            offset += len + count;
            break;

            /* MMS Encapsulation 1.2 */

        default:
            cont = 0; /*  end */
            break;
        }
    }

    return offset;
}


static int MMsBody(mms_message *msg, const unsigned char *data, const int dim, int offset, unsigned int ctype, const char *tmp_path)
{
    int nparts, i;
    int count;
    int header_len, data_len;
    unsigned int tmp;
    FILE *fp;

    count = 0;
    nparts = MMSUIntVar(data, dim, offset, &count);
    offset += count;
    printf("Parts: %i\n", nparts);
    msg->nparts = nparts;
    msg->part = xmalloc(sizeof(mms_part) * nparts);
    if (msg->part == NULL || nparts <= 0)
        return -1;
    memset(msg->part, 0, sizeof(mms_part) * nparts);
    if (ctype == 0x33) {
        /* multipart related */
        printf("Body: multipart related\n");
    }
    else {
        /* multipart */
        printf("Body: multipart\n");
    }
    for (i=0; i!=nparts; i++) {
        count = 0;
        header_len = MMSUIntVar(data, dim, offset, &count);
        offset += count;
        count = 0;
        data_len = MMSUIntVar(data, dim, offset, &count);
        offset += count;
        msg->part[i].size = data_len;
        MMSReadContentType(data, dim, offset, &tmp, &msg->part[i].ctype, &msg->part[i].name);
        printf("Ctype: %s\n", msg->part[i].ctype);
        msg->part[i].path = xmalloc(MMS_STR_DIM);
        sprintf(msg->part[i].path, "%s/%lld_%p_%i.bin", tmp_path, (long long)time(NULL), msg->part[i].path, i);
        fp = fopen(msg->part[i].path, "w");
        fwrite(data+offset+header_len, 1, data_len, fp);
        fclose(fp);
        offset += data_len + header_len;
    }

    return 0;
}


int MMSDecode(mms_message *msg, const unsigned char *data, const int len, const char *tmp_path)
{
    int offset;
    unsigned int ctype;

    /* decode header */
    ctype = 0;
    offset = MMSHeader(msg, data, len, &ctype);
    /* if content type */
    if ((ctype == 0x22) || (ctype == 0x23) || (ctype == 0x24) ||
        (ctype == 0x25) || (ctype == 0x26) || (ctype == 0x33)    ) {
        MMsBody(msg, data, len, offset, ctype, tmp_path);
    }
    
    return 0;
}


int MMSInit(mms_message *msg)
{
    memset(msg, 0, sizeof(mms_message));

    return 0;
}


int MMSFree(mms_message *msg)
{
    int i;

    if (msg->msg_type != NULL) {
        xfree(msg->msg_type);
        msg->msg_type = NULL;
    }
    if (msg->cont_type != NULL) {
        xfree(msg->cont_type);
        msg->cont_type = NULL;
    }
    if (msg->bcc != NULL) {
        xfree(msg->bcc);
        msg->bcc = NULL;
    }
    if (msg->part != NULL) {
        for (i=0; i!=msg->nparts; i++) {
            if (msg->part[i].ctype != NULL) {
                xfree(msg->part[i].ctype);
            }
            if (msg->part[i].name != NULL) {
                xfree(msg->part[i].name);
            }
            if (msg->part[i].path != NULL) {
                xfree(msg->part[i].path);
            }
        }
        xfree(msg->part);
        msg->part = NULL;
    }

    return 0;
}

#ifdef printf
# undef printf
#endif

int MMSPrint(mms_message *msg)
{
    int i;

    printf("Versrion %s\n", msg->version);
    if (msg->msg_type != NULL)
        printf("Message type: %s\n", msg->msg_type);
    if (msg->cont_type != NULL)
        printf("Content type: %s\n", msg->cont_type);
    if (msg->from != NULL)
        printf("From: %s\n", msg->from);
    if (msg->to != NULL)
        printf("To: %s\n", msg->to);
    if (msg->cc != NULL)
        printf("CC: %s\n", msg->cc);
    if (msg->bcc != NULL)
        printf("Bcc: %s\n", msg->bcc);

    if (msg->part != NULL) {
        for (i=0; i!=msg->nparts; i++) {
            printf("Part %i\n", i+1);
            if (msg->part[i].ctype != NULL)
                printf("  ctype: %s\n", msg->part[i].ctype);
            if (msg->part[i].name != NULL)
                printf("  name: %s\n", msg->part[i].name);
            if (msg->part[i].path != NULL) {
                printf("  path: %s\n", msg->part[i].path);
                printf("  size: %i\n", msg->part[i].size);
            }
        }
    }

    return 0;
}
