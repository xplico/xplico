/* sdp.h
 *
 * $Id:  $
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


#ifndef __SDP_H__
#define __SDP_H__

#define SDP_MAX_RTP_CHANNELS 4
#define SDP_MAX_RTP_PAYLOAD_TYPES 20

/** Media type */
typedef enum {
    SDP_MEDIA_UNKNOW,
    SDP_MEDIA_AUDIO,
    SDP_MEDIA_VIDEO
} sdp_media_type;


typedef struct {
  int pt[SDP_MAX_RTP_PAYLOAD_TYPES];
  char *rtp_dyn_payload[SDP_MAX_RTP_PAYLOAD_TYPES];
  short pt_count;
} sdp_transport_media_pt;


/** Network type */
typedef enum {
    SDP_NETTP_NONE=0,         /**< Unknown network type */
    SDP_NETTP_IN,             /**< Internet */
} sdp_nettype;


/** Address type */
typedef enum {
    SDP_ADDRTP_NONE=0,        /**< Unknown address type */
    SDP_ADDRTP_IP4,           /**< IPv4 address */
    SDP_ADDRTP_IP6,	      /**< IPv6 address */
} sdp_addrtype;


/** SDP connection - host or group address */
typedef struct {
  sdp_nettype nettype;        /**< Network type */
  sdp_addrtype addrtype;      /**< Address type */
  char *address;              /**< Host or group address */
} sdp_connection;


typedef struct {
  sdp_media_type type[SDP_MAX_RTP_CHANNELS];
  unsigned short port[SDP_MAX_RTP_CHANNELS];
  char *proto[SDP_MAX_RTP_CHANNELS];
  sdp_transport_media_pt media[SDP_MAX_RTP_CHANNELS];
  short count;
} sdp_transport_info;


/** Session description identification */ 
typedef struct {
  char *username;             /**< Username of originator */
  unsigned long sid;          /**< Session identification  */
  unsigned long sversion;     /**< Version of session description */
  sdp_connection *address;    /**< Address of originator */
} sdp_owner;


/** Session description */
typedef struct _sdp_msg sdp_msg;
struct _sdp_msg {
    short version;            /**< SDP version */
    sdp_owner owner;          /**< Owner/creator and session ID */
    char *ses_name;           /**< Session name */
    char *ses_info;           /**< Session information  */
    char *uri;                /**< URI of description */
    char *email;              /**< E-mail address(s) */
    char *phone;              /**< Phone number(s)  */
    sdp_connection cntn_info; /**< Group (or member) address */
    sdp_transport_info transp;/**< Session attributes */
};


void SdpMsgFree(sdp_msg *msg);
void SdpMsgPrint(sdp_msg *msg);


#endif /* __SDP_H__ */
