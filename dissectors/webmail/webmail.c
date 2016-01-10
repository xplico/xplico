/* webmail.c
 * Web Mial services of AOL, Hotmail, Yahoo!
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2009-2011 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#include "proto.h"
#include "dmemory.h"
#include "etypes.h"
#include "log.h"
#include "pei.h"
#include "http.h"
#include "webmail.h"

static int prot_id;
static int pei_service_id;
static int pei_dir_id;
static int pei_url_id;
static int pei_client_id;
static int pei_host_id;
static int pei_req_header_id;
static int pei_req_body_id;
static int pei_res_header_id;
static int pei_res_body_id;

static PktDissector HttpPktDis;  /* this functions create the http pei for all http packets */
static short aol_pattern_read;


static int WebmailPei(const char *stype, packet* pkt, bool out)
{
    http_msg *msg;
    pei *ppei;
    pei_component *cmpn;
    
    ppei = NULL;

    /* display info */
    msg = (http_msg *)pkt->data;

    /* pei */
    PeiNew(&ppei, prot_id);
    PeiCapTime(ppei, pkt->cap_sec);
    PeiMarker(ppei, pkt->serial);
    PeiStackFlow(ppei, pkt->stk);
    /*   service type */
    PeiNewComponent(&cmpn, pei_service_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, stype);
    PeiAddComponent(ppei, cmpn);
    /*   dir type */
    PeiNewComponent(&cmpn, pei_dir_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    if (out)
        PeiCompAddStingBuff(cmpn, "s");
    else
        PeiCompAddStingBuff(cmpn, "r");
    PeiAddComponent(ppei, cmpn);
    /*   url */
    PeiNewComponent(&cmpn, pei_url_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, msg->uri);
    PeiAddComponent(ppei, cmpn);
    /*   clent */
    PeiNewComponent(&cmpn, pei_client_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, msg->client);
    PeiAddComponent(ppei, cmpn);
    /*   host */
    PeiNewComponent(&cmpn, pei_host_id);
    PeiCompCapTime(cmpn, msg->start_cap);
    PeiCompCapEndTime(cmpn, msg->end_cap);
    PeiCompAddStingBuff(cmpn, msg->host);
    PeiAddComponent(ppei, cmpn);
    /*   req hdr */
    if (msg->req_hdr_file) {
        PeiNewComponent(&cmpn, pei_req_header_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiAddComponent(ppei, cmpn);
        PeiCompAddFile(cmpn, NULL, msg->req_hdr_file, msg->req_hdr_size);
        if (msg->error && msg->req_body_size == 0 && msg->res_hdr_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
    }
    /*   req body */
    if (msg->req_body_size) {
        PeiNewComponent(&cmpn, pei_req_body_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiAddComponent(ppei, cmpn);
        PeiCompAddFile(cmpn, NULL, msg->req_body_file, msg->req_body_size);
        if (msg->error && msg->res_hdr_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
    }
    /*   res hdr */
    if (msg->res_hdr_size) {
        PeiNewComponent(&cmpn, pei_res_header_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiAddComponent(ppei, cmpn);
        PeiCompAddFile(cmpn, NULL, msg->res_hdr_file, msg->res_hdr_size);
        if (msg->error && msg->res_body_size == 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
    }
    /*   res body */
    if (msg->res_body_size) {
        PeiNewComponent(&cmpn, pei_res_body_id);
        PeiCompCapTime(cmpn, msg->start_cap);
        PeiCompCapEndTime(cmpn, msg->end_cap);
        PeiAddComponent(ppei, cmpn);
        PeiCompAddFile(cmpn, NULL, msg->res_body_file, msg->res_body_size);
        if (msg->error == 2) {
            PeiCompError(cmpn, ELMT_ER_HOLE);
        }
        else if (msg->error != 0) {
            PeiCompError(cmpn, ELMT_ER_PARTIAL);
        }
    }
    
    /* insert pei */
    PeiIns(ppei);

    return 0;
}


static packet* WebmailDissector(packet *pkt)
{
    http_msg *msg;
    bool ins;
    char *check;
    const char *bnd;

    /* display info */
    msg = (http_msg *)pkt->data;
    ins = FALSE;

#ifdef XPL_CHECK_CODE
    if (msg->serial == 0) {
        LogPrintf(LV_FATAL, "WebmailDissector serial error");
        exit(-1);
    }
#endif
    /* client is not a web browser */
    if (strstr(msg->client, WMAIL_YAHOO_ANDROID)) {
        ins = TRUE; /* all data go to manipulator or are deleted */
        if (strstr(msg->host, "mg.mail.yahoo.com") != NULL) {
           if (strstr(msg->uri, "/hg/controller/controller.php") != NULL) {
               /* send to manipulator */
               WebmailPei(WMAIL_SERVICE_YAHOO_ANDRO, pkt, FALSE);
           }
        }
    }
    /* from web browsers */
    else if (msg->uri != NULL) {
        /* yahoo! web mail */
        if (strstr(msg->host, ".mail.yahoo.com") != NULL) {
            if (strstr(msg->uri, "m=GetDisplayMessage") != NULL) {
                if (msg->mtd == HTTP_MT_POST && strstr(msg->uri, "appid=YahooMailNeo") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_YAHOO_V2, pkt, FALSE);
                    ins = TRUE;
                }
                else {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_YAHOO, pkt, FALSE);
                    ins = TRUE;
                }
            }
            else if (msg->mtd == HTTP_MT_POST && strstr(msg->uri, "m=SendMessage") != NULL) {
                if (strstr(msg->uri, "appid=YahooMailNeo") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_YAHOO_V2, pkt, TRUE);
                    ins = TRUE;
                }
                else {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_YAHOO, pkt, TRUE);
                    ins = TRUE;
                }
            }
        }
        
        /* live! web mail */
        else if (strstr(msg->host, ".mail.live.com") != NULL) {
            if (strstr(msg->uri, "MailBox.GetInboxData") != NULL) {
                /* send to manipulator */
                WebmailPei(WMAIL_SERVICE_HOTMAIL, pkt, FALSE);
                ins = TRUE;
            }
            else if (msg->mtd == HTTP_MT_POST && strstr(msg->uri, "SendMessageLight") != NULL) {
                /* send to manipulator */
                WebmailPei(WMAIL_SERVICE_HOTMAIL, pkt, TRUE);
                ins = TRUE;
            }
            else if (msg->mtd == HTTP_MT_POST && strstr(msg->uri, "AttachmentUploader") != NULL) {
                /* send to manipulator */
#if 0
                WebmailPei(WMAIL_SERVICE_HOTMAIL, pkt, TRUE);
                ins = TRUE;
#else
# warning "to complete"
#endif
            }
        }

        /* GMAIL webamil */
        else if (strstr(msg->host, "mail.google.com") != NULL) {
            if (msg->mtd == HTTP_MT_POST) {
                if (strstr(msg->uri, "&search=inbox") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_GMAIL, pkt, FALSE);
                    ins = TRUE;
                }
                else if (strstr(msg->uri, "&act=sm&") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_GMAIL, pkt, TRUE);
                    ins = TRUE;
                }
            }
        }
        
        /* AOL web mail */
        else if (strstr(msg->host, "webmail.aol.com") != NULL) {
            if ((check = strstr(msg->uri, WMAIL_AOL_PATTERN_READ)) != NULL) {
                if (check[aol_pattern_read] == '\0') {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_AOL, pkt, FALSE);
                    ins = TRUE;
                }
            }
            else if (msg->mtd == HTTP_MT_POST && strstr(msg->uri, "a=SendMessage") != NULL) {
                /* send to manipulator */
                WebmailPei(WMAIL_SERVICE_AOL, pkt, TRUE);
                ins = TRUE;
            }
        }
        else if (strstr(msg->host, "mail.aol.com") != NULL) {
            if (msg->mtd == HTTP_MT_POST) {
                if (strstr(msg->uri, "&a=GetMessage") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_AOL_V2, pkt, FALSE);
                    ins = TRUE;
                }
                else if (strstr(msg->uri, "&a=SendMessage") != NULL) {
                    bnd = HttpMsgBodyBoundary(msg, TRUE);
                    if (bnd == NULL) {
                        /* send to manipulator */
                        WebmailPei(WMAIL_SERVICE_AOL_V2, pkt, TRUE);
                        ins = TRUE;
                    }
                }
            }
        }

        /* Alice Telecom Italia */
        else if (strstr(msg->host, ".alice.it") != NULL) {
            if (msg->mtd == HTTP_MT_POST) {
                if (strstr(msg->uri, "cp/ps/mail/SLcommands/SLEmailBody") != NULL ||
                    strstr(msg->uri, "cp/ps/mail/SLcommands/SLEmailHeaders") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_ROSSOALICE, pkt, FALSE);
                    ins = TRUE;
                }
                else if (strstr(msg->uri, "cp/ps/mail/SLcommands/SLSendMessage") != NULL) {
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_ROSSOALICE, pkt, TRUE);
                    ins = TRUE;
                }
            }
            else { /* GET */
                if (strstr(msg->uri, "cp/ps/Mail/Downloader") != NULL) {
                    /* attached file */
                }
            }
        }
        
        /* Libero.it webmail */
        else if (strstr(msg->host, ".libero.it") != NULL) {
            if (strstr(msg->uri, "&pid=") != NULL) {
                if (msg->mtd == HTTP_MT_GET && strstr(msg->uri, "commands/LoadMessage") != NULL) { /* email header */
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_LIBERO, pkt, FALSE);
                    ins = TRUE;
                }
                else if (msg->mtd == HTTP_MT_GET && strstr(msg->uri, "MailMessageBody.jsp") != NULL) { /* email body */
                    /* send to manipulator */
                    WebmailPei(WMAIL_SERVICE_LIBERO, pkt, FALSE);
                    ins = TRUE;
                }
            }
            else if (msg->mtd == HTTP_MT_GET && strstr(msg->uri, "/m/wmm/read/") != NULL) { /* email */
                /* send to manipulator */
                WebmailPei(WMAIL_SERVICE_LIBERO_MOBI, pkt, FALSE);
                ins = TRUE;
            }
            else if (0 && msg->mtd == HTTP_MT_POST && strstr(msg->uri, "cgi-bin/webmail.cgi") != NULL) { /* old libero webmail */
                /* send to manipulator */
                WebmailPei(WMAIL_SERVICE_LIBERO_OLD, pkt, FALSE);
                ins = TRUE;
            }
        }
    }
    
    if (ins == FALSE && HttpPktDis != NULL) {
        /* http pei generation and insertion */
        HttpPktDis(pkt);
    }
    else {
        /* free memory */
        HttpMsgFree(msg);
        PktFree(pkt);
    }

    return NULL;
}


int DissecRegist(const char *file_cfg)
{
    proto_dep dep;
    pei_cmpt peic;

    memset(&dep, 0, sizeof(proto_dep));
    memset(&peic, 0, sizeof(pei_cmpt));

    /* protocol name */
    ProtName("Webmail: AOL, Yahoo!, HOTMAIL, Yahoo! Android, Gmail, RossoAlice, Libero.it", "webmail");

    /* http dependence */
    /* dep: http Rosso Alice Telecom Italia! */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_ROSSOALICE_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_ROSSOALICE_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);
    
    /* dep: http Yahoo! */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_YAHOO_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_YAHOO_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* dep: http Yahoo! Android Mail */
    dep.name = "http";
    dep.attr = "http.user_agent";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_YAHOO_ANDROID)+1);
    strcpy(dep.val.str, WMAIL_YAHOO_ANDROID);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* dep: http aol */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_AOL_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_AOL_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);
    /*** aol 2011 */
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_AOL_V2_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_AOL_V2_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* dep: http gmail */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_GMAIL_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_GMAIL_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* dep: http hotmail */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_HOTMAIL_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_HOTMAIL_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* dep: http libero.it */
    dep.name = "http";
    dep.attr = "http.host";
    dep.type = FT_STRING;
    dep.op = FT_OP_REX;
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_LIBERO_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_LIBERO_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);
    /* libero old */
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_LIBERO_OLD_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_LIBERO_OLD_REX);
    //ProtDep(&dep);
    DMemFree(dep.val.str);
    /* libero mobile */
    dep.val.str = DMemMalloc(strlen(WMAIL_HOST_NAME_LIBERO_MOBI_REX)+1);
    strcpy(dep.val.str, WMAIL_HOST_NAME_LIBERO_MOBI_REX);
    ProtDep(&dep);
    DMemFree(dep.val.str);

    /* PEI components */
    peic.abbrev = "service";
    peic.desc = "Service Type";
    ProtPeiComponent(&peic);

    /*
      if 'r' then received, if 's' then sent
     */
    peic.abbrev = "dir";
    peic.desc = "Mail received('r') or sent ('s')";
    ProtPeiComponent(&peic);

    peic.abbrev = "url";
    peic.desc = "Uniform Resource Locator";
    ProtPeiComponent(&peic);

    peic.abbrev = "client";
    peic.desc = "Client";
    ProtPeiComponent(&peic);

    peic.abbrev = "host";
    peic.desc = "Host";
    ProtPeiComponent(&peic);

    peic.abbrev = "req.header";
    peic.desc = "Request header";
    ProtPeiComponent(&peic);

    peic.abbrev = "req.body";
    peic.desc = "Request body";
    ProtPeiComponent(&peic);

    peic.abbrev = "res.header";
    peic.desc = "Response header";
    ProtPeiComponent(&peic);

    peic.abbrev = "res.body";
    peic.desc = "Response body";
    ProtPeiComponent(&peic);
    
    /* dissectors registration */
    ProtDissectors(WebmailDissector, NULL, NULL, NULL);

    return 0;
}


int DissectInit(void)
{
    int http_id;

    prot_id = ProtId("webmail");

    /* Http pei generator */
    HttpPktDis = NULL;
    http_id = ProtId("http");
    if (http_id != -1) {
        HttpPktDis = ProtPktDefaultDis(http_id);
    }

    /* static values */
    aol_pattern_read = strlen(WMAIL_AOL_PATTERN_READ);

    /* pei id */
    pei_service_id = ProtPeiComptId(prot_id, "service");
    pei_dir_id = ProtPeiComptId(prot_id, "dir");
    pei_url_id = ProtPeiComptId(prot_id, "url");
    pei_client_id = ProtPeiComptId(prot_id, "client");
    pei_host_id = ProtPeiComptId(prot_id, "host");
    pei_req_header_id = ProtPeiComptId(prot_id, "req.header");
    pei_req_body_id = ProtPeiComptId(prot_id, "req.body");
    pei_res_header_id = ProtPeiComptId(prot_id, "res.header");
    pei_res_body_id = ProtPeiComptId(prot_id, "res.body");
    
    return 0;
}
