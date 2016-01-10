/* wa.c
 * Dissector WahtsApp
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2014 Gianluca Costa. Web: www.xplico.org
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

/*
    Protocol description:
    https://github.com/koenk/whatspoke/wiki/FunXMPP
*/


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <linux/tcp.h>
#include <dirent.h>
#include <ctype.h>

#include "ntoh.h"
#include "proto.h"
#include "dmemory.h"
#include "config_file.h"
#include "etypes.h"
#include "flow.h"
#include "log.h"
#include "wa.h"
#include "pei.h"


#define WA_TMP_DIR       "wa"

static int ip_id;
static int ipv6_id;
static int tcp_id;
static int ip_src_id;
static int ip_dst_id;
static int ip_offset_id;
static int ipv6_src_id;
static int ipv6_dst_id;
static int ipv6_offset_id;
static int port_src_id;
static int port_dst_id;
static int lost_id;
static int wa_id;
static volatile int serial = 0;

/* pei id */
static int pei_wa_device_id;
static int pei_wa_phone_id;
 
static const unsigned short std_ports[] = TCP_PORTS_WA;
static unsigned short std_ports_dim;
static volatile unsigned int incr;
static const char *wa_labels[] = {"None-0", "stream:stream", "None-2", "None-3", "None-4", "account", "ack",
        "action", "active", "add", "after", "ib", "all", "allow", "apple", "audio",
        "auth", "author", "available", "bad-protocol", "bad-request", "before",
        "Bell.caf", "body", "Boing.caf", "cancel", "category", "challenge", "chat",
        "clean", "code", "composing", "config", "conflict", "contacts", "count",
        "create", "creation", "default", "delay", "delete", "delivered", "deny",
        "digest", "DIGEST-MD5-1", "DIGEST-MD5-2", "dirty", "elapsed", "broadcast",
        "enable", "encoding", "duplicate", "error", "event", "expiration", "expired",
        "fail", "failure", "false", "favorites", "feature", "features", "field",
        "first", "free", "from", "g.us", "get", "Glass.caf", "google", "group",
        "groups", "g_notify", "g_sound", "Harp.caf", "http://etherx.jabber.org/streams",
        "http://jabber.org/protocol/chatstates", "id", "image", "img", "inactive",
        "index", "internal-server-error", "invalid-mechanism", "ip", "iq", "item",
        "item-not-found", "user-not-found", "jabber:iq:last", "jabber:iq:privacy",
        "jabber:x:delay", "jabber:x:event", "jid", "jid-malformed", "kind", "last",
        "latitude", "lc", "leave", "leave-all", "lg", "list", "location", "longitude",
        "max", "max_groups", "max_participants", "max_subject", "mechanism", "media",
        "message", "message_acks", "method", "microsoft", "missing", "modify", "mute",
        "name", "nokia", "none", "not-acceptable", "not-allowed", "not-authorized",
        "notification", "notify", "off", "offline", "order", "owner", "owning", "paid",
        "participant", "participants", "participating", "password", "paused", "picture",
        "pin", "ping", "platform", "pop_mean_time", "pop_plus_minus", "port",
        "presence", "preview", "probe", "proceed", "prop", "props", "p_o", "p_t",
        "query", "raw", "reason", "receipt", "receipt_acks", "received", "registration",
        "relay", "remote-server-timeout", "remove", "Replaced by new connection",
        "request", "required", "resource", "resource-constraint", "response", "result",
        "retry", "rim", "s.whatsapp.net", "s.us", "seconds", "server", "server-error",
        "service-unavailable", "set", "show", "sid", "silent", "sound", "stamp",
        "unsubscribe", "stat", "status", "stream:error", "stream:features", "subject",
        "subscribe", "success", "sync", "system-shutdown", "s_o", "s_t", "t", "text",
        "timeout", "TimePassing.caf", "timestamp", "to", "Tri-tone.caf", "true", "type",
        "unavailable", "uri", "url", "urn:ietf:params:xml:ns:xmpp-sasl",
        "urn:ietf:params:xml:ns:xmpp-stanzas", "urn:ietf:params:xml:ns:xmpp-streams",
        "urn:xmpp:delay", "urn:xmpp:ping", "urn:xmpp:receipts", "urn:xmpp:whatsapp",
        "urn:xmpp:whatsapp:account", "urn:xmpp:whatsapp:dirty", "urn:xmpp:whatsapp:mms",
        "urn:xmpp:whatsapp:push", "user", "username", "value", "vcard", "version",
        "video", "w", "w:g", "w:p", "w:p:r", "w:profile:picture", "wait", "x",
        "xml-not-well-formed", "xmlns", "xmlns:stream", "Xylophone.caf", "1", "WAUTH-1"};

static unsigned char *WAPacketRecontruct(wa_rcnst *msgs, packet *pkt, unsigned short offset)
{
    unsigned char *ret, *data;
    unsigned short res;
    wa_rcnst *nxt, *elab;
    unsigned long len, rawlen;
    ret = NULL;

    if (pkt != NULL && pkt->len != 0) {
        elab = msgs;
        len = 0;
        data = (unsigned char *)pkt->data + offset;
        rawlen = pkt->len - offset;
        do {
            if (elab->dim == 0) {
                if (elab->len == 0) {
                    if (rawlen > 2) {
                        elab->dim = ntohs(getu16(data, 1)) + 3; /* 3 byte of header */
                        elab->msg = xmalloc(elab->dim+1);
                        elab->msg[elab->dim] = '\0';
                        //printf("ok %i 0x%x 0x%x 0x%x\n", pkt->len, data[0], data[1], data[2]);
                    }
                    else {
                        elab->msg = xmalloc(rawlen - len);
                        memcpy(elab->msg, data, rawlen - len);
                        elab->len = rawlen - len;
                        len = rawlen;
                    }
                }
                else {
                    if (rawlen - len + elab->len > 2) {
                        elab->msg = xrealloc(elab->msg, 100);
                        memcpy(elab->msg+elab->len, data, rawlen - 3 - elab->len);
                        
                        elab->dim = ntohs(getu16(elab->msg, 1)) + 3; /* 3 byte of header */
                        elab->msg = xrealloc(elab->msg, elab->dim+1);
                        elab->msg[elab->dim] = '\0';
                    }
                    else {
                        elab->msg = xrealloc(elab->msg, 100);
                        memcpy(elab->msg+elab->len, data, rawlen - len);
                        elab->len += rawlen - len;
                        len = rawlen;
                    }
                }
            }
            //printf("Dim: %i\n", elab->dim-3);
            if (elab->dim != 0) {
                res = elab->dim - elab->len;
                if (res > rawlen - len) {
                    memcpy(elab->msg+elab->len, data, rawlen - len);
                    elab->len += rawlen - len;
                    len = rawlen;
                }
                else {
                    memcpy(elab->msg+elab->len, data, res);
                    len += res;
                    elab->len += res;
                    data = data + elab->dim;
                    elab->nxt = xmalloc(sizeof(wa_rcnst));
                    memset(elab->nxt, 0, sizeof(wa_rcnst));
                    elab = elab->nxt;
                    //printf("A %i %i\n", len, rawlen);
                }
            }
        } while (len != rawlen);
    }

    if (msgs->dim != 0 && msgs->len == msgs->dim) {
        ret = msgs->msg;
        if (msgs->nxt != NULL) {
            nxt = msgs->nxt;
            memcpy(msgs, nxt, sizeof(wa_rcnst));
            xfree(nxt);
        }
        else {
            memset(msgs, 0, sizeof(wa_rcnst));
        }
    }
    
    return ret;
}


static void WAPacketRecFree(wa_rcnst *msgs)
{
    wa_rcnst *nxt, *tmp;
    
    if (msgs == NULL)
        return;
    if (msgs->msg != NULL) {
        xfree(msgs->msg);
        msgs->msg = NULL;
        msgs->dim = 0;
        msgs->len = 0;
    }
    tmp = msgs->nxt;

    while (tmp != NULL) {
        nxt = tmp->nxt;
        if (tmp->msg != NULL)
            xfree(tmp->msg);
        xfree(tmp);
        tmp = nxt;
    }
}


static bool WAVerifyCheck(int flow_id, bool check)
{
    packet *pkt; 
    ftval lost;
    wa_rcnst msg;
    unsigned char *wa_raw, data[5];
    unsigned short offset, len;
    
    pkt = FlowGetPktCp(flow_id);
    while (pkt != NULL && pkt->len == 0) {
        PktFree(pkt);
        pkt = FlowGetPktCp(flow_id);
    }
    if (pkt != NULL) {
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE) {
            offset = 4;
            if (pkt->len > 3) {
                if (pkt->data[0] == 'W' && pkt->data[1] == 'A' &&
                    pkt->data[4] == 0 &&
                    pkt->data[2] >= 0 && pkt->data[2] <= 9 &&
                    pkt->data[3] >= 0 && pkt->data[3] <= 9) {
                    if (check == FALSE) {
                        PktFree(pkt);
                        return TRUE;
                    }
                }
                else
                    return FALSE;
            }
            if (pkt->len > 0) {
                if (pkt->data[0] != 'W') {
                    PktFree(pkt);
                    return FALSE;
                }
                len = 0;
                data[4] = '\0';
                do {
                    if (pkt->len < 4-len) {
                        memcpy(data+len, pkt->data, pkt->len);
                        len += pkt->len;
                    }
                    else {
                        memcpy(data+len, pkt->data, 4-len);
                        offset = 4 - len;
                        len = 4;
                        break;
                    }
                    PktFree(pkt);
                    pkt = FlowGetPktCp(flow_id);
                    if (pkt != NULL) {
                        ProtGetAttr(pkt->stk, lost_id, &lost);
                        if (lost.uint8 == TRUE) {
                            PktFree(pkt);
                            return FALSE;
                        }
                    }
                } while (pkt != NULL);
                if (len > 3 && data[0] == 'W' && data[1] == 'A' &&
                    data[2] >= 0 && data[2] <= 9 &&
                    data[3] >= 0 && data[3] <= 9) {
                    if (check == FALSE) {
                        PktFree(pkt);
                        return TRUE;
                    }
                }
                else
                    return FALSE;
            }
            memset(&msg, 0, sizeof(wa_rcnst));
            do {
                wa_raw = WAPacketRecontruct(&msg, pkt, offset);
                if (wa_raw != NULL)
                    break;
                PktFree(pkt);
                pkt = FlowGetPktCp(flow_id);
                if (pkt != NULL) {
                    ProtGetAttr(pkt->stk, lost_id, &lost);
                    if (lost.uint8 == TRUE) {
                        PktFree(pkt);
                        pkt = NULL;
                    }
                }
            } while (pkt != NULL);
            WAPacketRecFree(&msg);
            if (wa_raw != NULL) { /* we try to decode the message */
                xfree(wa_raw);
            }
        }
        if (pkt != NULL)
            PktFree(pkt);
    }

    return FALSE;
}


static bool WAVerify(int flow_id)
{
    return WAVerifyCheck(flow_id, FALSE);
}


static bool WACheck(int flow_id)
{
    return WAVerifyCheck(flow_id, TRUE);
}


static void WAPei(pei *ppei, wa_data *wadata, wa_priv *priv, time_t *cap_sec, time_t *end_cap)
{
    pei_component *cmpn;
    
    /*   device */
    PeiNewComponent(&cmpn, pei_wa_device_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, wadata->device);
    PeiAddComponent(ppei, cmpn);
    /* phone */
    PeiNewComponent(&cmpn, pei_wa_phone_id);
    PeiCompCapTime(cmpn, *cap_sec);
    PeiCompCapEndTime(cmpn, *end_cap);
    PeiCompAddStingBuff(cmpn, wadata->phone);
    PeiAddComponent(ppei, cmpn);
}


static bool WAClientPkt(wa_priv *priv, packet *pkt)
{
    bool ret;
    ftval port, ip;
    enum ftype type;
    
    ret = FALSE;
    if (priv->port_diff == TRUE) {
        ProtGetAttr(pkt->stk, port_src_id, &port);
        if (port.uint16 == priv->port_s)
            ret = TRUE;
    }
    else {
        if (priv->ipv6 == TRUE) {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ipv6_src_id, &ip);
            type = FT_IPv6;
        }
        else {
            ProtGetAttr(ProtGetNxtFrame(pkt->stk), ip_src_id, &ip);
            type = FT_IPv4;
        }
        if (FTCmp(&priv->ip_s, &ip, type, FT_OP_EQ, NULL) == 0)
            ret = TRUE;
    }
    
    return ret;
}


static int MsgParseStr(unsigned char *wa_str, char *buff)
{
    int len, i;

    len = wa_str[0];
    for (i=0; i != len; i++) {
        buff[i] = wa_str[i+1];
    }
    buff[len] = '\0';
    
    return len+1;
}


static bool MsgParse(unsigned char *msg, wa_data *wadata)
{
    int offset, len, elem;
    unsigned char key;
    unsigned char value;
    char strvalue[256];
    
    if (msg[0] & WA_FLAG_CRYP)
        return FALSE;

    len = (msg[1]<<8) +  msg[2];
    if (len == 0)
        return TRUE;
    
    offset = 3;
    if (msg[offset] == WA_MSG_LISTS) {
        offset++;
        elem = msg[offset++];
        if (msg[offset] == WA_LBL_STREAM) {
            offset++;
            elem--;
            while (elem > 1) {
                /* key */
                key = msg[offset++];
                /* value */
                value = msg[offset++];
                if (value == WA_MSG_STR) {
                    offset += MsgParseStr(msg+offset, strvalue);
                }
                elem -= 2;
                if ((key == WA_LBL_PAUSED || key == WA_LBL_PICTURE) && wadata->device == NULL) {
                    wadata->device = strdup(strvalue);
                }
            }
        }
        else if (msg[offset] == WA_LBL_ALL) {
            offset++;
            elem--;
            while (elem > 1) {
                /* key */
                key = msg[offset++];
                
                /* value */
                value = msg[offset++];
                if (value == WA_MSG_STR) {
                    offset += MsgParseStr(msg+offset, strvalue);
                }
                elem -= 2;
                if (key == WA_LBL_SOUND && wadata->phone == NULL) {
                    wadata->phone = strdup(strvalue);
                }
                else {
                    printf("k2: 0x%x 0x%x\n", key, value);
                }
            }
        }
    }

    if (wadata->phone != NULL && wadata->device != NULL)
        return FALSE;

    return TRUE;
}


static packet *WADissector(int flow_id)
{
    packet *pkt;
    wa_priv priv;
    const pstack_f *tcp, *ip;
    ftval port_src, port_dst, lost;
    bool ipv4, clnt;
    pei *ppei;
    time_t cap_sec, end_cap;
    bool clost, slost, end;
    unsigned char *wa_raw;
    wa_rcnst msg_c, msg_s;
    unsigned short offset, hs;
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ips_str[INET6_ADDRSTRLEN], ipd_str[INET6_ADDRSTRLEN];
    wa_data wadata;
    
    LogPrintf(LV_DEBUG, "WhatsApp flowid: %i", flow_id);
    
    /* init */
    memset(&priv, 0, sizeof(wa_priv));
    memset(&msg_c, 0, sizeof(wa_rcnst));
    memset(&msg_s, 0, sizeof(wa_rcnst));
    memset(&wadata, 0, sizeof(wa_data));
    tcp = FlowStack(flow_id);
    ip = ProtGetNxtFrame(tcp);
    ProtGetAttr(tcp, port_src_id, &port_src);
    ProtGetAttr(tcp, port_dst_id, &port_dst);
    priv.port_s = port_src.uint16;
    priv.stack = tcp;
    if (priv.port_s != port_dst.uint16)
        priv.port_diff = TRUE;
    priv.ipv6 = TRUE;
    ipv4 = FALSE;
    clost = slost = end = FALSE;
    if (ProtFrameProtocol(ip) == ip_id) {
        ipv4 = TRUE;
        priv.ipv6 = FALSE;
    }
    if (ipv4) {
        ProtGetAttr(ip, ip_src_id, &priv.ip_s);
        ProtGetAttr(ip, ip_dst_id, &priv.ip_d);
        ip_addr.s_addr = priv.ip_s.uint32;
        inet_ntop(AF_INET, &ip_addr, ips_str, INET6_ADDRSTRLEN);
        ip_addr.s_addr = priv.ip_d.uint32;
        inet_ntop(AF_INET, &ip_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    else {
        ProtGetAttr(ip, ipv6_src_id, &priv.ip_s);
        ProtGetAttr(ip, ipv6_dst_id, &priv.ip_d);
        memcpy(ipv6_addr.s6_addr, priv.ip_s.ipv6, sizeof(priv.ip_s.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ips_str, INET6_ADDRSTRLEN);
        memcpy(ipv6_addr.s6_addr, priv.ip_d.ipv6, sizeof(priv.ip_d.ipv6));
        inet_ntop(AF_INET6, &ipv6_addr, ipd_str, INET6_ADDRSTRLEN);
    }
    LogPrintf(LV_DEBUG, "\tSRC: [%s]:%d", ips_str, port_src.uint16);
    LogPrintf(LV_DEBUG, "\tDST: [%s]:%d", ipd_str, port_dst.uint16);
    
    pkt = NULL;
    ppei = NULL;
    hs = 4;
    do {
        pkt = FlowGetPkt(flow_id);
        if (pkt != NULL) {
            ProtGetAttr(pkt->stk, lost_id, &lost);
            if (lost.uint8 == FALSE) {
                /* create pei */
                PeiNew(&ppei, wa_id);
                PeiCapTime(ppei, pkt->cap_sec);
                PeiMarker(ppei, pkt->serial);
                PeiStackFlow(ppei, tcp);
                cap_sec = pkt->cap_sec;
                end_cap = pkt->cap_sec;
            }
            else {
                clnt = WAClientPkt(&priv, pkt);
                if (clnt)
                    clost = TRUE;
                else
                    slost = TRUE;
                hs = 0;
                break;
            }
        }
        if (hs < pkt->len) {
            offset = hs;
            hs = 0;
        }
        else {
            hs -= pkt->len;
            PktFree(pkt);
            pkt = NULL;
        }
    } while (pkt == NULL && hs != 0);

    
    while (pkt != NULL && end == FALSE) {
        clnt = WAClientPkt(&priv, pkt);
        //ProtStackFrmDisp(pkt->stk, TRUE);
        ProtGetAttr(pkt->stk, lost_id, &lost);
        wa_raw = NULL;
        if (lost.uint8 == FALSE) {
            if (clnt) {
                if (clost) {
                    /* resync */
                    if (pkt->len > 3) {
                    }
                }
                if (!clost) {
                    wa_raw = WAPacketRecontruct(&msg_c, pkt, offset);
                    offset = 0;
                }
            
                /* analyse wa packet */
                while (wa_raw != NULL) {
                    if (MsgParse(wa_raw, &wadata) == FALSE) {
                        end = TRUE;
                    }
                    xfree(wa_raw);
                    wa_raw = WAPacketRecontruct(&msg_c, NULL, 0);
                }
                priv.bsent += pkt->len;
                priv.pkt_sent++;
            }
            else {
                if (slost) {
                    /* resync */
                    if (pkt->len > 5) {
                    }
                }
                if (!slost)
                    wa_raw = WAPacketRecontruct(&msg_s, pkt, 0);
            
                /* analyse wa packet */
                while (wa_raw != NULL) {
                    xfree(wa_raw);
                    wa_raw = WAPacketRecontruct(&msg_s, NULL, 0);
                }
                priv.breceiv += pkt->len;
                priv.pkt_receiv++;
            }
        }
        else {
            if (clnt)
                clost = TRUE;
            else
                slost = TRUE;
#if CA_CHECK_LOST
            LogPrintf(LV_WARNING, "Packet Lost (size:%lu)", pkt->len);
            ProtStackFrmDisp(pkt->stk, TRUE);
#endif
            if (clnt) {
                priv.blost_sent += pkt->len;
                if (priv.blost_sent == 0)
                    priv.blost_sent = 1;
            }
            else {
                priv.blost_receiv += pkt->len;
                if (priv.blost_receiv == 0)
                    priv.blost_receiv = 1;
            }
        }
        
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }
    while (pkt != NULL) {
        ProtGetAttr(pkt->stk, lost_id, &lost);
        if (lost.uint8 == FALSE && pkt->len != 0) {
            clnt = WAClientPkt(&priv, pkt);
            if (clnt) {
                priv.bsent += pkt->len;
                priv.pkt_sent++;
            }
            else {
                priv.breceiv += pkt->len;
                priv.pkt_receiv++;
            }
        }
        PktFree(pkt);
        pkt = FlowGetPkt(flow_id);
    }

    WAPacketRecFree(&msg_c);
    WAPacketRecFree(&msg_s);
    
    /* insert data */
    WAPei(ppei, &wadata, &priv, &cap_sec, &end_cap);
    if (wadata.device != NULL) {
        LogPrintf(LV_DEBUG, "WA: %s %s.", wadata.device, wadata.phone);
        xfree(wadata.device);
    }
    if (wadata.phone != NULL) {
        xfree(wadata.phone);
    }
    
    /* insert pei */
    PeiIns(ppei);
    
    /* end */
    LogPrintf(LV_DEBUG, "WA bye bye.");

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    proto_heury_dep hdep;
    pei_cmpt peic;
    unsigned short i;
    
    /* init */
    std_ports_dim = sizeof(std_ports)/sizeof(unsigned short);
    
    memset(&dep, 0, sizeof(proto_dep));
    memset(&hdep, 0, sizeof(proto_heury_dep));
    memset(&peic, 0, sizeof(pei_cmpt));
 
    /* protocol name */
    ProtName("WhatsApp Analysis", "wa");

    /* dep: tcp */
    dep.name = "tcp";
    dep.attr = "tcp.dstport";
    dep.type = FT_UINT16;
    dep.ProtCheck = WAVerify;
    dep.pktlim = TCP_WA_PKT_LIMIT;
    for (i=0; i!=std_ports_dim; i++) {
        dep.val.uint16 = std_ports[i];
        ProtDep(&dep);
    }
    
    /* hdep: tcp */
    hdep.name = "tcp";
    hdep.ProtCheck = WACheck;
    hdep.pktlim = TCP_WA_PKT_LIMIT;
    //ProtHeuDep(&hdep);

    /* PEI components */
    peic.abbrev = "dev";
    peic.desc = "Device";
    ProtPeiComponent(&peic);
    
    peic.abbrev = "phone";
    peic.desc = "Phone Number";
    ProtPeiComponent(&peic);
    
    /* dissectors subdissectors registration */
    ProtDissectors(NULL, WADissector, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    char tmp_dir[256];

    /* part of file name */
    incr = 0;

    /* info id */
    ip_id = ProtId("ip");
    ipv6_id = ProtId("ipv6");
    tcp_id = ProtId("tcp");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
        ip_offset_id = ProtAttrId(ip_id, "ip.offset");
    }
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
        ipv6_offset_id = ProtAttrId(ipv6_id, "ipv6.offset");
    }
    if (tcp_id != -1) {
        port_dst_id = ProtAttrId(tcp_id, "tcp.dstport");
        port_src_id = ProtAttrId(tcp_id, "tcp.srcport");
        lost_id = ProtAttrId(tcp_id, "tcp.lost");
    }
    wa_id = ProtId("wa");
    
    /* pei id */
    pei_wa_device_id = ProtPeiComptId(wa_id, "dev");
    pei_wa_phone_id = ProtPeiComptId(wa_id, "phone");

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), WA_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);

    return 0;
}
