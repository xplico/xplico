/* lite.h
 *
 * Xplico System dispatcher module for SQLite DB
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2014 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __LITE_H__
#define __LITE_H__

#include "ftypes.h"
#include "configs.h"

/* XI dir */
#define XS_DB_INSTALL_DIR     "/opt/xplico"
#define XS_DB_FILE            XS_DB_INSTALL_DIR"/xplico.db" /* DB file path */
#define XS_DIR_PATH           XS_DB_INSTALL_DIR"/pol_%d/sol_%d"
#define XS_MAIL_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/mail"
#define XS_HTTP_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/http"
#define XS_FTP_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/ftp"
#define XS_IPP_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/ipp"
#define XS_PJL_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/pjl"
#define XS_MMS_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/mms"
#define XS_GEA_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/gea"
#define XS_TFTP_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/tftp"
#define XS_DNS_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/dns"
#define XS_NNTP_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/nntp"
#define XS_FBWC_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/fbwchat"
#define XS_TELNET_DIR_PATH    XS_DB_INSTALL_DIR"/pol_%d/sol_%d/telnet"
#define XS_WEBMAIL_DIR_PATH   XS_DB_INSTALL_DIR"/pol_%d/sol_%d/webmail"
#define XS_HTTPFILE_DIR_PATH  XS_DB_INSTALL_DIR"/pol_%d/sol_%d/httpfile"
#define XS_GRBTCP_DIR_PATH    XS_DB_INSTALL_DIR"/pol_%d/sol_%d/grbtcp"
#define XS_GRBUDP_DIR_PATH    XS_DB_INSTALL_DIR"/pol_%d/sol_%d/grbudp"
#define XS_RTP_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/rtp"
#define XS_SIP_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/sip"
#define XS_ARP_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/arp"
#define XS_IRC_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/irc"
#define XS_PLT_EXP_DIR_PATH   XS_DB_INSTALL_DIR"/pol_%d/sol_%d/paltalk_exp"
#define XS_PALTALK_DIR_PATH   XS_DB_INSTALL_DIR"/pol_%d/sol_%d/paltalk"
#define XS_MSN_DIR_PATH       XS_DB_INSTALL_DIR"/pol_%d/sol_%d/msn"
#define XS_ICMPv6_DIR_PATH    XS_DB_INSTALL_DIR"/pol_%d/sol_%d/icmpv6"
#define XS_SYSLOG_DIR_PATH    XS_DB_INSTALL_DIR"/pol_%d/sol_%d/syslog"
#define XS_WEBYMSG_DIR_PATH   XS_DB_INSTALL_DIR"/pol_%d/sol_%d/webymsg"
#define XS_UNKFILE_DIR_PATH   XS_DB_INSTALL_DIR"/pol_%d/sol_%d/unkfile"
#define XS_MGCP_DIR_PATH      XS_DB_INSTALL_DIR"/pol_%d/sol_%d/mgcp"
#define XS_WA_DIR_PATH        XS_DB_INSTALL_DIR"/pol_%d/sol_%d/whatsapp"


/* db */
/* time UTC/GMT or local time */
#ifndef XP_CAPTURE_UTC
# error "Define in configs.h the type of capture time!"
#endif
#if XP_CAPTURE_UTC
# define XPCAP_DATE          "DATETIME(%lld, 'unixepoch')"
#else
# define XPCAP_DATE          "DATETIME(%lld, 'unixepoch', 'localtime')"
#endif

/* geomap */
#define XS_GEA_TMPDIR_PATH XS_DB_INSTALL_DIR"/pol_%d/tmp"
#define XS_GEA_SEM         "/gea_pol_%i"    /* dema.h ximysql.h */

/* file paths type
   if XS_ONE_FILE_PATHS is 0 the file paths are stored in /opt/xplico/pol_x/lastdata.txt files,
   if XS_ONE_FILE_PATHS is 1 the file paths are stored in /opt/xplico/lastdata.txt for every pol
*/
#define XS_ONE_FILE_PATHS  1
#if XS_ONE_FILE_PATHS == 0
# define XS_FILE_PATHS      XS_DB_INSTALL_DIR"/pol_%d/lastdata.txt"
#else
# define XS_FILE_PATHS      XS_DB_INSTALL_DIR"/lastdata.txt"
#endif

/* parser, buffer and status */
#define XS_MIME_PARSER     XS_DB_INSTALL_DIR"/script/mimedump.pyc"
#define XS_MIME_TO         "TO:"
#define XS_MIME_FROM       "FROM:"
#define XS_MIME_SUBJECT    "SUBJECT:"
#define XS_HTTP_URL        "http://"
#define XS_HTTP_URL_LEN    7

#define XS_URL_REL_1       "POSSIBLY_CONTAINER"
#define XS_URL_REL_2       "POSSIBLY_CONTAINED"
#define XS_URL_REL_3       "CONTAINER"
#define XS_URL_REL_4       "CONTAINED"
#define XS_URL_REL_5       "SERVICES"
#define XS_URL_REL_6       "NONE"


/* services type definition */
#define ST_WEB                 1  /* web page type: http */
#define ST_MAIL                2
#define ST_WEBMAIL             3
#define ST_FTP                 4
#define ST_PRINT               5
#define ST_MMS                 6
#define ST_TFTP                7
#define ST_NNTP                8
#define ST_FBWC                9
#define ST_TELNET              10
#define ST_HTTPFILE            11
#define ST_RTP                 12
#define ST_SIP                 13
#define ST_IRC                 14
#define ST_PLT_EXP             15
#define ST_PLT                 16
#define ST_MSN                 17
#define ST_MGCP                18
#define ST_YAHOO_WEB           19
#define ST_DIG_FILE            20


#define XS_QUERY_DIM           10240
#define XS_STR_DIM             4096
#define XS_STR_PATH            2048
#define XS_STR_NONE            10
#define XS_CP_BUFFER           (1024*1024)

#define XS_HOST_ID_ADD         30
typedef struct {
    int id;                  /* DB id */
    ftval ip;                /* IP address */
    enum ftype type;         /* ip type */
} host_id;

/* sqlite 3 */
#define XS_QUERY_SOURCE_TEMPLATE     "INSERT INTO sources (sol_id, pol_id, ip, name) VALUES (%i, %i, '%s', '%s')"
#define XS_QUERY_SOURCE_SEARCH       "SELECT id FROM sources WHERE sol_id=%d and ip='%s'"
#define XS_QUERY_POP_TEMPLATE        "INSERT INTO emails (sol_id, pol_id, source_id, capture_date, data_size, flow_info, receive, username, password, sender, receivers, subject, mime_path, relevance, attach_dir) VALUES (%i, %i, %i, "XPCAP_DATE", %lu, '%s', 1, '%s', '%s', '%s', '%s', '%s', '%s', 100, '%s')"
#define XS_QUERY_SMTP_TEMPLATE       "INSERT INTO emails (sol_id, pol_id, source_id, capture_date, data_size, flow_info, receive, sender, receivers, subject, mime_path, relevance, attach_dir) VALUES (%i, %i, %i, "XPCAP_DATE", %lu, '%s', 0, '%s', '%s',  '%s', '%s', 100, '%s')"
#define XS_QUERY_IMAP_TEMPLATE       "INSERT INTO emails (sol_id, pol_id, source_id, capture_date, data_size, flow_info, receive, username, password, sender, receivers, subject, mime_path, relevance, attach_dir) VALUES (%i, %i, %i, "XPCAP_DATE", %lu, '%s', 1, '%s', '%s', '%s', '%s', '%s', '%s', 100, '%s')"
#define XS_QUERY_WEB_TEMPLATE        "INSERT INTO webs (sol_id, pol_id, source_id, capture_date, flow_info, url, relation, method, response, agent, host, content_type, rq_header, rq_body, rq_bd_size, rs_header, rs_body, rs_bd_size) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', %lu, '%s', '%s', %lu)"
#define XS_QUERY_FTP_TEMPLATE        "INSERT INTO ftps (sol_id, pol_id, source_id, capture_date, flow_info, url, username, password, cmd_path) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s')"
#define XS_QUERY_FTP_UPDATE          "UPDATE ftps SET upload_num=%s, download_num=%s WHERE id=%lu"
#define XS_QUERY_FTP_DATA_TEMPLATE   "INSERT INTO ftp_files (sol_id, pol_id, source_id, capture_date, flow_info, ftp_id, filename, file_path, file_size, dowloaded) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%lu', '%s', '%s', '%lu', '%i')"
#define XS_QUERY_PJL_TEMPLATE        "INSERT INTO pjls (sol_id, pol_id, source_id, capture_date, flow_info, url, pdf_path, pdf_size, pcl_path, pcl_size) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%lu', '%s', '%lu')"
#define XS_QUERY_MMS_TEMPLATE        "INSERT INTO mms (sol_id, pol_id, source_id, capture_date, flow_info, url, from_num, to_num, cc_num, bcc_num, contents) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', '%s', %i)"
#define XS_QUERY_MMS_CONT_TEMPLATE   "INSERT INTO mmscontents (sol_id, pol_id, source_id, mm_id, content_type, filename, file_path, file_size) VALUES (%i, %i, %i, %lu, '%s', '%s', '%s', %lu)"
#define XS_QUERY_FEEDS_TEMPLATE      "INSERT INTO feeds (sol_id, pol_id, source_id, name, site) VALUES (%i, %i, %i, '%s', '%s')"
#define XS_QUERY_FEEDS_SEARCH        "SELECT id FROM feeds WHERE sol_id=%d and name='%s'"
#define XS_QUERY_FEEDS_XML_TEMPLATE  "INSERT INTO feed_xmls (sol_id, pol_id, source_id, feed_id, capture_date, flow_info, url, rs_header, rs_body, rs_bd_size) VALUES (%i, %i, %i, %lu, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%lu')"
#define XS_QUERY_TFTP_TEMPLATE       "INSERT INTO tftps (sol_id, pol_id, source_id, capture_date, flow_info, url, cmd_path) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s')"
#define XS_QUERY_TFTP_UPDATE         "UPDATE tftps SET upload_num=%s, download_num=%s WHERE id=%lu"
#define XS_QUERY_TFTP_DATA_TEMPLATE  "INSERT INTO tftp_files (sol_id, pol_id, source_id, capture_date, flow_info, tftp_id, filename, file_path, file_size, dowloaded) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%lu', '%s', '%s', '%lu', '%i')"
#define XS_QUERY_DNS_TEMPLATE        "INSERT INTO dns_messages (sol_id, pol_id, source_id, capture_date, flow_info, hostname, cname, ip) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s')"
#define XS_QUERY_NNTP_TEMPLATE       "INSERT INTO nntp_groups (sol_id, pol_id, source_id, name) VALUES (%i, %i, %i, '%s')"
#define XS_QUERY_NNTP_SEARCH         "SELECT id FROM nntp_groups WHERE sol_id=%d and name='%s'"
#define XS_QUERY_NNTP_ARTCL_TEMPLATE "INSERT INTO nntp_articles (sol_id, pol_id, source_id, nntp_group_id, capture_date, data_size, flow_info, receive, only_body, sender, receivers, subject, mime_path) VALUES (%i, %i, %i, %lu, "XPCAP_DATE", %lu, '%s', %i, %i, '%s', '%s', '%s', '%s')"
#define XS_QUERY_FBWCHAT_TEMPLATE    "INSERT INTO fbuchats (sol_id, pol_id, source_id, username, uid) VALUES (%i, %i, %i, '%s', '%s')"
#define XS_QUERY_FBWCHAT_SEARCH      "SELECT id FROM fbuchats WHERE sol_id=%d and uid='%s'"
#define XS_QUERY_FBWCHAT_CHAT        "INSERT INTO fbchats (sol_id, pol_id, source_id, fbuchat_id, capture_date, data_size, flow_info, username, friend, chat) VALUES (%i, %i, %i, %lu, "XPCAP_DATE", %lu, '%s', '%s', '%s', '%s')"
#define XS_QUERY_FBWCHAT_UPDATE      "UPDATE fbchats SET flow_info='%s', chat='%s', data_size=%lu, duration=%lu WHERE id=%lu"
#define XS_QUERY_TELNET_TEMPLATE     "INSERT INTO telnets (sol_id, pol_id, source_id, capture_date, flow_info, hostname, username, password, cmd, cmd_size) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', %lu)"
#define XS_QUERY_WBAMIL_TEMPLATE     "INSERT INTO webmails (sol_id, pol_id, source_id, capture_date, data_size, flow_info, receive, service, messageid, sender, receivers, cc_receivers, subject, mime_path, txt_path, html_path, relevance) VALUES (%i, %i, %i, "XPCAP_DATE", %lu, '%s', %i, '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', 100)"
#define XS_QUERY_HTTPFILE_TEMPLATE   "INSERT INTO httpfiles (sol_id, pol_id, source_id, capture_date, flow_info, url, content_type, file_path, file_name, file_size, file_parts, file_stat) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', %lu, '%s', '%s')"
#define XS_QUERY_GRBTCP_TEMPLATE     "INSERT INTO unknows (sol_id, pol_id, source_id, capture_date, flow_info, dst, dst_port, l7prot, file_path, size, duration) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', %i, '%s', '%s', %lu, %lu)"
#define XS_QUERY_GRBUDP_TEMPLATE     "INSERT INTO unknows (sol_id, pol_id, source_id, capture_date, flow_info, dst, dst_port, l7prot, file_path, size, duration) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', %i, '%s', '%s', %lu, %lu)"
#define XS_QUERY_RTP_TEMPLATE        "INSERT INTO rtps (sol_id, pol_id, source_id, capture_date, flow_info, from_addr, to_addr, ucaller, ucalled, umix, duration) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', '%s', '%s')"
#define XS_QUERY_SIP_TEMPLATE        "INSERT INTO sips (sol_id, pol_id, source_id, capture_date, flow_info, from_addr, to_addr, ucaller, ucalled, umix, duration, commands) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"
#define XS_QUERY_ARP_TEMPLATE        "INSERT INTO arps (sol_id, pol_id, capture_date, flow_info, mac, ip) VALUES (%i, %i, "XPCAP_DATE", '%s', '%s', '%s')"
#define XS_QUERY_IRC_TEMPLATE        "INSERT INTO ircs (sol_id, pol_id, source_id, capture_date, flow_info, url, cmd_path, channel_num) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s')"
#define XS_QUERY_IRC_UPDATE          "UPDATE ircs SET channel_num=%s WHERE id=%lu"
#define XS_QUERY_IRC_CHN_TEMPLATE    "INSERT INTO irc_channels (sol_id, pol_id, source_id, capture_date, flow_info, irc_id, channel, end_date, channel_path, cusers, cnick) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%lu', '%s', "XPCAP_DATE", '%s', '%s', '%s')"
#define XS_QUERY_PLT_EXP_TEMPLATE    "INSERT INTO paltalk_exps (sol_id, pol_id, source_id, capture_date, flow_info, user_nick, end_date, channel_path) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', "XPCAP_DATE", '%s')"
#define XS_QUERY_PLT_EXP_UPDATE      "UPDATE paltalk_exps SET flow_info='%s', end_date="XPCAP_DATE", channel_path='%s' WHERE id=%lu"
#define XS_QUERY_PALTALK_TEMPLATE    "INSERT INTO paltalk_rooms (sol_id, pol_id, source_id, capture_date, flow_info, room, end_date, room_path, duration, rusers, rnick) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', "XPCAP_DATE", '%s', '%s', '%s', '%s')"
#define XS_QUERY_MSN_TEMPLATE        "INSERT INTO msn_chats (sol_id, pol_id, source_id, capture_date, flow_info, chat, end_date, chat_path, duration) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', "XPCAP_DATE", '%s', '%s')"
#define XS_QUERY_ICMPv6_TEMPLATE     "INSERT INTO icmpv6s (sol_id, pol_id, capture_date, flow_info, mac, ip) VALUES (%i, %i, "XPCAP_DATE", '%s', '%s', '%s')"
#define XS_QUERY_SYSLOG_TEMPLATE     "INSERT INTO syslogs (sol_id, pol_id, source_id, capture_date, flow_info, hosts, log, log_size) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', %lu)"
#define XS_QUERY_WEBYMSG_CHAT        "INSERT INTO webymsgs (sol_id, pol_id, source_id, capture_date, data_size, flow_info, username, friend, chat) VALUES (%i, %i, %i, "XPCAP_DATE", %lu, '%s', '%s', '%s', '%s')"
#define XS_QUERY_WEBYMSG_UPDATE      "UPDATE webymsgs SET flow_info='%s', chat='%s', data_size=%lu, duration=%lu WHERE id=%lu"
#define XS_QUERY_UNKFILE_TEMPLATE    "INSERT INTO unkfiles (sol_id, pol_id, source_id, capture_date, flow_info, url, file_path, file_name, fsize, file_type) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', %lu, '%s')"
#define XS_QUERY_MGCP_TEMPLATE       "INSERT INTO mgcps (sol_id, pol_id, source_id, capture_date, flow_info, from_addr, to_addr, ucaller, ucalled, umix, duration, commands) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')"
#define XS_QUERY_WA_TEMPLATE         "INSERT INTO was (sol_id, pol_id, source_id, capture_date, flow_info, device, phone) VALUES (%i, %i, %i, "XPCAP_DATE", '%s', '%s', '%s')"

#endif /* __LITE_H__ */
