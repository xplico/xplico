/* lite.c
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

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <signal.h>
#include <sqlite3.h>
#include <sys/wait.h>

#include "proto.h"
#include "log.h"
#include "pei.h"
#include "dmemory.h"
#include "lite.h"
#include "gearth.h"
#include "dnsdb.h"

#ifndef DISP_CLI_FILE_LIST
#  define DISP_CLI_FILE_LIST    0
#  define DispFilePaths(x, y)      
#endif

#define PEI_TIME(x)    ((long long)(x))

/* pol */
static int pol_id;
static int pol_polid_id;
static int pol_sesid_id;
static int pol_filename_id;
/* ip v4 id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
/* ip v6 id */
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;
/* tcp */
static int tcp_id;
static int tcp_dstport_id;
/* udp */
static int udp_id;
static int udp_dstport_id;
/* pop id */
static int pop_id;
static int pei_pop_user_id;
static int pei_pop_pswd_id;
static int pei_pop_eml_id;
/* smtp id */
static int smtp_id;
static int pei_smtp_to_id;
static int pei_smtp_from_id;
static int pei_smtp_eml_id;
/* imap id */
static int imap_id;
static int pei_imap_user_id;
static int pei_imap_pswd_id;
static int pei_imap_eml_id;
/* http id */
static int http_id;
static int pei_http_url_id;
static int pei_http_client_id;
static int pei_http_host_id;
static int pei_http_content_type_id;
static int pei_http_method_id;
static int pei_http_status_id;
static int pei_http_req_header_id;
static int pei_http_req_body_id;
static int pei_http_res_header_id;
static int pei_http_res_body_id;
static int pei_http_file_id;
/* ftp */
static int ftp_id;
static int pei_ftp_url_id;
static int pei_ftp_user_id;
static int pei_ftp_pswd_id;
static int pei_ftp_cmd_id;
static int pei_ftp_file_in_id;
static int pei_ftp_file_out_id;
static int pei_ftp_file_offset_id;
static int pei_ftp_down_n_id;
static int pei_ftp_up_n_id;
/* ipp */
static int ipp_id;
static int pei_ipp_url_id;
static int pei_ipp_pdf_id;
static int pei_ipp_pcl_id;
/* pjl */
static int pjl_id;
static int pei_pjl_url_id;
static int pei_pjl_pdf_id;
static int pei_pjl_pcl_id;
/* mms */
static int mms_id;
static int pei_mms_url_id;
static int pei_mms_from_id;
static int pei_mms_to_id;
static int pei_mms_cc_id;
static int pei_mms_bcc_id;
static int pei_mms_part_id;
static int pei_mms_raw_id;
/* tftp */
static int tftp_id;
static int pei_tftp_url_id;
static int pei_tftp_cmd_id;
static int pei_tftp_file_in_id;
static int pei_tftp_file_out_id;
static int pei_tftp_down_n_id;
static int pei_tftp_up_n_id;
/* dns */
static int dns_id;
static int pei_dns_host_id;
static int pei_dns_ip_id;
static int pei_dns_cname_id;
static int pei_dns_pkt_id;
/* nntp */
static int nntp_id;
static int pei_nntp_url_id;
static int pei_nntp_grp_id;
static int pei_nntp_article_id;
static int pei_nntp_header_id;
static int pei_nntp_body_id;
static int pei_nntp_post_id;
/* facebook web chat */
static int fbwc_id;
static int pei_fbwc_user_id;
static int pei_fbwc_uid_id;
static int pei_fbwc_friend_id;
static int pei_fbwc_chat_id;
static int pei_fbwc_duration_id;
/* telnet */
static int telnet_id;
static int pei_telnet_host_id;
static int pei_telnet_user_id;
static int pei_telnet_password_id;
static int pei_telnet_cmd_id;
/* webmail */
static int webmail_id;
static int pei_webmail_serv_id;
static int pei_webmail_dir_id;
static int pei_webmail_to_id;
static int pei_webmail_from_id;
static int pei_webmail_cc_id;
static int pei_webmail_sent_id;
static int pei_webmail_rec_id;
static int pei_webmail_messageid_id;
static int pei_webmail_subj_id;
static int pei_webmail_eml_id;
static int pei_webmail_html_id;
static int pei_webmail_txt_id;
/* http file */
static int httpfile_id;
static int pei_httpfile_url_id;
static int pei_httpfile_file_id;
static int pei_httpfile_content_type;
static int pei_httpfile_parts_id;
static int pei_httpfile_complete_id;
/* garbage tcp */
static int grb_tcp_id;
static int pei_grb_tcp_l7protocol_id;
static int pei_grb_tcp_txt_id;
static int pei_grb_tcp_size_id;
static int pei_grb_tcp_file_id;
static int pei_grb_tcp_file_type_id;
/* garbage udp */
static int grb_udp_id;
static int pei_grb_udp_l7protocol_id;
static int pei_grb_udp_txt_id;
static int pei_grb_udp_size_id;
/* rtp voip */
static int rtp_id;
static int pei_rtp_from;
static int pei_rtp_to;
static int pei_rtp_audio_from;
static int pei_rtp_audio_to;
static int pei_rtp_audio_mix;
static int pei_rtp_duration;
/* sip voip */
static int sip_id;
static int pei_sip_from;
static int pei_sip_to;
static int pei_sip_cmd;
static int pei_sip_audio_from;
static int pei_sip_audio_to;
static int pei_sip_audio_mix;
static int pei_sip_duration;
/* arp/rarp */
static int arp_id;
static int pei_arp_mac_id;
static int pei_arp_ip_id;
/* irc */
static int irc_id;
static int pei_irc_url_id;
static int pei_irc_server_id;
static int pei_irc_channel_id;
static int pei_irc_channels_num_id;
static int pei_irc_channel_users_id;
static int pei_irc_channel_nick_id;
/* paltalk express */
static int paltalk_exp_id;
static int pei_pltk_e_user_id;
static int pei_pltk_e_chat_id;
static int pei_pltk_e_duration_id;
/* paltalk */
static int paltalk_id;
static int pei_pltk_room_id;
static int pei_pltk_room_duration_id;
static int pei_pltk_room_users_id;
static int pei_pltk_room_nick_id;
/* msn */
static int msn_id;
static int pei_msn_from_id;
static int pei_msn_to_id;
static int pei_msn_chat_id;
static int pei_msn_duration_id;
/* icmpv6 */
static int icmpv6_id;
static int pei_icmpv6_mac_id;
static int pei_icmpv6_ip_id;
/* mgcp voip */
static int mgcp_id;
static int pei_mgcp_from;
static int pei_mgcp_to;;
static int pei_mgcp_cmd;
static int pei_mgcp_audio_from;
static int pei_mgcp_audio_to;
static int pei_mgcp_audio_mix;
static int pei_mgcp_duration;
/* yahoo web chat */
static int webymsg_id;
static int pei_webymsg_user_id;
static int pei_webymsg_friend_id;
static int pei_webymsg_chat_id;
static int pei_webymsg_duration_id;
/* syslog */
static int syslog_id;
static int pei_syslog_host_id;
static int pei_syslog_log_id;
/* whatsapp */
static int wa_id;
static int pei_wa_device_id;
static int pei_wa_phone_id;

/* DB */
/* sqlite */
static sqlite3 *db;                   /* sqlite DB */
static pthread_mutex_t db_mux;        /* mutex to access db */
static pthread_mutex_t feed_mux;      /* mutex to access feed table */
static pthread_mutex_t nntp_mux;      /* mutex to access nntp_group table */
static pthread_mutex_t fbchat_mux;    /* DB access of fb chat data */
static char query_l[2*XS_QUERY_DIM];  /* to be used inside db_mux mutex lock */

/* geomap */
static volatile unsigned long geo_id;  /* geo session number, in this case we have only one session */
static pthread_mutex_t geo_mux; /* mut to create the geo session */

/* host */
static volatile host_id * volatile host;
static volatile unsigned long host_num;
static volatile unsigned long host_dim;
static pthread_mutex_t host_mux;

/* lock to access of file */
#if DISP_CLI_FILE_LIST
static pthread_mutex_t file_mux;  /* mutex to access the file */
static int pol_file;
static char file_paths[XS_STR_PATH];
#endif

static int DispQuery(char *query, unsigned long *id);

#if DISP_CLI_FILE_LIST
static inline void DispFilePaths(int pol, char *path)
{
    FILE *fp;
    
    pthread_mutex_lock(&file_mux);
    if (pol_file != pol) {
#if XS_ONE_FILE_PATHS == 0
        sprintf(file_paths, XS_FILE_PATHS, pol);
#else
        sprintf(file_paths, XS_FILE_PATHS);
#endif
        pol_file = pol;
    }
    fp = fopen(file_paths, "a");
    if (fp != NULL) {
        fwrite(path, 1, strlen(path), fp);
        fwrite("\n", 1, 1, fp);
        fclose(fp);
    }

    pthread_mutex_unlock(&file_mux);
}
#endif


static void DispInteraction(bool update, bool add_sz,int pol, int sol, int src_id, time_t cdate, char *desc, size_t size, int stype, unsigned long sid, char *query)
{
}


static int DispHostExt(void)
{
    host_id *new;

    /* the mutex is in already locked */
    new = xrealloc((void *)host, sizeof(host_id)*(host_dim + XS_HOST_ID_ADD));
    if (new == NULL)
        return -1;
    memset(new+sizeof(host_id)*(host_dim), 0, sizeof(host_id)*XS_HOST_ID_ADD);
    host = new;
    host_dim += XS_HOST_ID_ADD;
    
    return 0;
}


static int DispHostSrch(ftval *ip, enum ftype type)
{
    int i, ret;

    pthread_mutex_lock(&host_mux);
    for (i=0; i != host_num; i++) {
        if (host[i].type == type) {
            if (FTCmp(ip, (void *)&(host[i].ip), type, FT_OP_EQ, NULL) == 0) {
                ret = host[i].id;
                pthread_mutex_unlock(&host_mux);
                return ret;
            }
        }
    }
    /* mutex unlock at DispHostIns */

    return -1;
}


static int DispHostIns(ftval *ip, enum ftype type, int db_id)
{
    if (host_num == host_dim) {
        if (DispHostExt() != 0) {
            pthread_mutex_unlock(&host_mux);
            return -1;
        }
    }
    host[host_num].id = db_id;
    FTCopy((void *)&(host[host_num].ip), ip, type);
    host[host_num].type = type;
    host_num++;
    
    pthread_mutex_unlock(&host_mux);

    return 0;
}


static int DispHostDb(const char *ip, int pol, int sol)
{
    int ret, res;
    sqlite3_stmt *stmt;
    
    ret = -1;
    pthread_mutex_lock(&db_mux);
    sprintf(query_l, XS_QUERY_SOURCE_SEARCH, sol, ip);

    sqlite3_prepare_v2(db, query_l, -1, &stmt, 0);
    while ((res = sqlite3_step(stmt)) == SQLITE_LOCKED || res == SQLITE_BUSY)
        sched_yield();
    if (res == SQLITE_ROW) {
        ret = sqlite3_column_int(stmt, 0);
    }
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&db_mux);

    return ret;
}


static int DispHostDbIns(const char *ip, char *name, int pol, int sol)
{
    unsigned long id;
    char query[XS_QUERY_DIM];

    sprintf(query, XS_QUERY_SOURCE_TEMPLATE, sol, pol, ip, name);
    if (DispQuery(query, &id) != 0) {
        printf("query: %s\n", query);
    }

    return id;
}


static void DispFlowInfo(char *fname, const pstack_f *stack)
{
    char *xmlog;
    int fd;

    if (stack != NULL) {
        /* xml flow */
        xmlog = ProtStackFrmXML(stack);
        
        /* save_xml_file */
        fd = open(fname, O_CREAT|O_RDWR, 0x01B6);
        if (fd != -1) {
            write(fd, xmlog, strlen(xmlog));
            close(fd);
        }
        xfree(xmlog);
    }
}


static char* DispUrlNorm(char *url)
{
    char *app, a, b;
    int i;

    app = strchr(url, '\'');
    while (app != NULL) {
        i = 0;
        a = '\\';
        while (a != '\0') {
            b = app[i+1];
            app[i] = a;
            a = b;
            i++;
        }
        app[i] = a;

        app += 2; /* possible ' */
        app = strchr(url, '\'');
    }
    
    return url;
}


static int DispCopy(char *old, char *new, bool rm)
{
    bool cp;
    char *buff;
    FILE *in, *out;
    size_t len;

    cp = !rm;
    if (rm) {
        /* rename */
        remove(new);
        if (rename(old, new) != 0)
            cp = TRUE;
        else
            rm = FALSE;
    }
    if (cp) {
        /* copy */        
        in = fopen(old, "r");
        if (in != NULL) {
            out = fopen(new, "w");
            if (out != NULL) {
                buff = xmalloc(XS_CP_BUFFER);
                if (buff != NULL) {
                    while ((len = fread(buff, 1, XS_CP_BUFFER, in)) != 0)
                        fwrite(buff, 1, len, out);
                    xfree(buff);
                }
                fclose(out);
            }
            else {
                LogPrintf(LV_WARNING, "Unable to open file (%s)", new);
            }
            fclose(in);
        }
        else {
            if (rm)
                LogPrintf(LV_WARNING, "Unable to open file (%s)", old);
            else {
                /* create file */
                out = fopen(new, "w");
                if (out != NULL) {
                    fclose(out);
                }
            }
        }
    }
    if (rm) {
        /* remove */
        remove(old);
    }

    return 0;
}


static int DispQuery(char *query, unsigned long *id)
{
    int ret;
    char *err;

    pthread_mutex_lock(&db_mux);

    err = NULL;
    while (sqlite3_exec(db, query, NULL, NULL, &err) == SQLITE_BUSY) {
        sched_yield();
        if (err != NULL)
            break;
    }
    if (err != NULL) {
        LogPrintf(LV_ERROR, "Query: %s", query);
        LogPrintf(LV_DEBUG, "Error: %s", err);
        sqlite3_free(err);
    }
    if (id != NULL) {
        /* return record id */
        *id = sqlite3_last_insert_rowid(db);
    }

    pthread_mutex_unlock(&db_mux);

    ret = 0;

    return ret;
}


static int DispStrCnv(char *dst, char *src, int len)
{
    int i, n, dim;

    i = 0;
    n = 0;
    dim = strlen(dst);
    if (dim != 0) {
        n = dim ;
        dst[n++] = ',';
        dst[n++] = ' ';
    }
    len = len - dim;

    while (i<len && src[i] != '\0') {
        if (src[i] == '\'') {
            dst[n] = '\'';
            n++;
        }
        if (src[i] != '\r' && src[i] != '\n') {
            dst[n] = src[i];
            n++;
        }
        i++;
    }

    return 0;
}


static char *DispLabelCnv(char *src, char *dst)
{
    int i, n, len;

    i = 0;
    n = 0;
    len = strlen(src);
    while (i<len && src[i] != '\0') {
        if (src[i] == '\'') {
            dst[n] = '\'';
            n++;
        }
        dst[n] = src[i];
        n++;
        i++;
    }
    dst[n] = '\0';

    return dst;
}


static int DispMimeParse(char *file, char *subject, char *from, char *to, char *att_dir)
{
    static unsigned int cnt = 0;
    char cmd[XS_QUERY_DIM];
    char dump[XS_STR_DIM];
    char none[XS_STR_NONE];
    FILE *fp;
    int data, ret;
    
    /* mime dump */
    sprintf(dump, "%s/dump_%i_%p_%i.txt", ProtTmpDir(), getpid(), file, cnt++);
    sprintf(cmd, "%s -d %s %s 2>/dev/null 1> %s", XS_MIME_PARSER, att_dir, file, dump);
    ret = system(cmd);
    if (WIFSIGNALED(ret) && 
        (WTERMSIG(ret) == SIGINT ||
         WTERMSIG(ret) == SIGQUIT)) {
         
        ret = -1;
    }
    else {
        /* read file */
        fp = fopen(dump, "r");
        if (fp) {
            ret = 0;
            data = 0;
            while (fgets(cmd, XS_QUERY_DIM, fp) != NULL) {
                cmd[XS_QUERY_DIM-1] = '\0';
                if (strncmp(cmd, XS_MIME_TO, 3) == 0) {
                    data = 1;
                }
                else if (strncmp(cmd, XS_MIME_FROM, 5) == 0) {
                    data = 2;
                }
                else if (strncmp(cmd, XS_MIME_SUBJECT, 8) == 0) {
                    data = 3;
                }
                else {
                    none[0] = '\0';
                    switch (data) {
                    case 1:
                        if (to != NULL) {
                            DispStrCnv(to, cmd, XS_STR_DIM);
                            if (strcmp(to, "None") == 0)
                                ret++;
                        }
                        else {
                            DispStrCnv(none, cmd, XS_STR_NONE);
                            if (strcmp(none, "None") == 0)
                                ret++;
                        }
                        break;
                        
                    case 2:
                        if (from != NULL) {
                            DispStrCnv(from, cmd, XS_STR_DIM);
                            if (strcmp(from, "None") == 0)
                                ret++;
                        }
                        else {
                            DispStrCnv(none, cmd, XS_STR_NONE);
                            if (strcmp(none, "None") == 0)
                                ret++;
                        }
                        break;
                        
                    case 3:
                        DispStrCnv(subject, cmd, XS_STR_DIM);
                        if (strcmp(subject, "None") == 0)
                            ret++;
                        else {
                            if (strchr(subject, '\'') != NULL) {
                                DispUrlNorm(subject);
                            }
                        }
                        break;
                        
                    default:
                        break;
                    }
                    data = 0;
                }
                memset(cmd, 0, XS_QUERY_DIM);
            }
            fclose(fp);
            if (ret == 3)
                ret = -1;
        }
        else {
            ret = -1;
        }
    }
    remove(dump);

    return ret;
}


static int DispPop(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char subject[XS_STR_DIM];
    char from[XS_STR_DIM];
    char to[XS_STR_DIM];
    char flow_info[XS_STR_PATH];
    char att_dir[XS_STR_PATH];
    int pol, sess, src_id;
    char *user, *pwd, *path;
    struct stat info;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    unsigned long id;
    size_t msize;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = pwd = user = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pop_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pop_pswd_id) {
            pwd = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    
    cmpn = ppei->components;
    while (cmpn != NULL) {
        path = NULL;
        if (cmpn->eid == pei_pop_eml_id) {
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        /* compose query and insert record */
        if (path && stat(path, &info) == 0) {
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_MAIL_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_MAIL_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* parse mime */
            sprintf(att_dir, XS_MAIL_DIR_PATH"/%s_attach", pol, sess, name);
            memset(subject, 0, XS_STR_DIM);
            memset(from, 0, XS_STR_DIM);
            memset(to, 0, XS_STR_DIM);
            if (DispMimeParse(rep, subject, from, to, att_dir) != -1) {
                /* query */
                sprintf(query, XS_QUERY_POP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                        (unsigned long)info.st_size, flow_info, user, pwd, from, to, subject, rep, att_dir);
                if (DispQuery(query, &id) != 0) {
                    printf("query: %s\n", query);
                }
                else {
                    DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, subject, msize, ST_MAIL, id, query);
                }
            }
        }
        cmpn = cmpn->next;
    }

    return 0;
}


static int DispSmtp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char subject[XS_STR_DIM];
    char *from;
    char to[XS_STR_DIM];
    char flow_info[XS_STR_PATH];
    char att_dir[XS_STR_PATH];
    int pol;
    int sess, src_id;
    char *path;
    struct stat info;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    unsigned long id;
    size_t msize;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = NULL;
    to[0] = '\0';
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_smtp_to_id && cmpn->strbuf != NULL) {
            if (to[0] != '\0') {
                strcat(to, ", ");
            }
            strcat(to, cmpn->strbuf);
        }
        if (cmpn->eid == pei_smtp_from_id) {
            from = cmpn->strbuf;
        }
        if (cmpn->eid == pei_smtp_eml_id) {
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (path &&stat(path, &info) == 0) {
        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_MAIL_DIR_PATH"/%s", pol, sess, name);
        rename(path, rep);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_MAIL_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* parse mime */
        sprintf(att_dir, XS_MAIL_DIR_PATH"/%s_attach", pol, sess, name);
        memset(subject, '\0', XS_STR_DIM);
        if (DispMimeParse(rep, subject, NULL, NULL, att_dir) != -1) {
            /* query */
            sprintf(query, XS_QUERY_SMTP_TEMPLATE, sess, pol, src_id, (PEI_TIME(ppei->time_cap)),
                    (unsigned long)info.st_size, flow_info, from, to, subject, rep, att_dir);
            if (DispQuery(query, &id) != 0) {
                printf("query: %s\n", query);
            }
            else {
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, subject, msize, ST_MAIL, id, query);
            }
        }
    }

    return 0;
}


static int DispImap(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char subject[XS_STR_DIM];
    char from[XS_STR_DIM];
    char to[XS_STR_DIM];
    char flow_info[XS_STR_PATH];
    char att_dir[XS_STR_PATH];
    int pol, sess, src_id;
    char *user;
    char *pwd;
    char *path;
    struct stat info;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    unsigned long id;
    size_t msize;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = pwd = user = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_imap_user_id) {
            user = cmpn->strbuf;
        }
        if (cmpn->eid == pei_imap_pswd_id) {
            pwd = cmpn->strbuf;

        }
        if (cmpn->eid == pei_imap_eml_id) {
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        cmpn = cmpn->next;

        /* compose query and insert record */
        if (path && stat(path, &info) == 0) {
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_MAIL_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_MAIL_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* parse mime */
            sprintf(att_dir, XS_MAIL_DIR_PATH"/%s_attach", pol, sess, name);
            memset(subject, '\0', XS_STR_DIM);
            memset(from, '\0', XS_STR_DIM);
            memset(to, '\0', XS_STR_DIM);
            if (DispMimeParse(rep, subject, from, to, att_dir) != -1) {
                /* query */
                sprintf(query, XS_QUERY_IMAP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                        (unsigned long)info.st_size, flow_info, user, pwd, from, to, subject, rep, att_dir);
                if (DispQuery(query, &id) != 0) {
                    printf("query: %s\n", query);
                }
                else {
                    DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, subject, msize, ST_MAIL, id, query);
                }
            }
        }
    }

    return 0;
}


static int DispHttp(pei *ppei)
{
    pei_component *cmpn;
    char query[2*XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char url[2*XS_QUERY_DIM];
    char rq_header[XS_STR_PATH], rq_body[XS_STR_PATH],
        rs_header[XS_STR_PATH], rs_body[XS_STR_PATH], tmp[XS_STR_PATH];
    char buffer[XS_QUERY_DIM];
    int pol, sess, dim, ret, res, src_id;
    unsigned long id;
    char *host, *host_t, *urlp, *path;
    char *file, *filename;
    char *cont_type, *title, *link, *end, *err;
    char *cont_type_big, *cont_type_resp, *agent;
    sqlite3_stmt *stmt;
    char *rep, *method, *response;
    size_t size, rq_bd_size, rs_bd_size;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    bool http;
    FILE *fp;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, buffer);
            src_id = DispHostDb(buffer, pol, sess);
            if (src_id == -1) {
                url[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, url, XS_QUERY_DIM);
                src_id = DispHostDbIns(buffer, url, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, buffer);
                src_id = DispHostDb(buffer, pol, sess);
                if (src_id == -1) {
                    url[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, url, XS_QUERY_DIM);
                    src_id = DispHostDbIns(buffer, url, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    agent = file = filename = host = host_t = method = response = rep = cont_type = urlp = cont_type_big = cont_type_resp = NULL;
    flow_info[0] = '\0';
    url[0] = '\0';
    rq_bd_size = rs_bd_size = 0;
    memcpy(rq_header, "NULL", 5);
    memcpy(rq_body, "NULL", 5);
    memcpy(rs_header, "NULL", 5);
    memcpy(rs_body, "NULL", 5);
    cmpn = ppei->components;
    http = FALSE;
    err = NULL;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_http_url_id) {
            if (strlen(cmpn->strbuf) >= XS_HTTP_URL_LEN && strncmp(cmpn->strbuf, XS_HTTP_URL, XS_HTTP_URL_LEN) == 0) {
                http = TRUE;
            }
            if (host_t != NULL && http == FALSE) {
                sprintf(url, "%s%s", host_t, cmpn->strbuf);
            }
            else {
                if (http == TRUE) {
                    sprintf(url, "%s", cmpn->strbuf+XS_HTTP_URL_LEN);
                }
                else {
                    urlp = cmpn->strbuf;
                }
            }
        }
        else if (cmpn->eid == pei_http_host_id) {
            host = cmpn->strbuf;
            if (urlp != NULL) {
                if (cmpn->strbuf != NULL)
                    sprintf(url, "%s%s", cmpn->strbuf, urlp);
                else
                    sprintf(url, "no-host%s", urlp);
            }
            else {
                if (cmpn->strbuf != NULL)
                    host_t = cmpn->strbuf;
                else
                    host_t = "no-host";
            }
        }
        else if (cmpn->eid == pei_http_content_type_id) {
            if (cont_type == NULL) {
                cont_type = cmpn->strbuf;
                cont_type_resp = cont_type;
            }
            else {
                cont_type_resp = cmpn->strbuf;
                cont_type_big = xmalloc(strlen(cont_type)+strlen(cmpn->strbuf)+3);
                sprintf(cont_type_big, "%s;%s", cont_type, cmpn->strbuf);
                cont_type = cont_type_big;
            }
        }
        else if (cmpn->eid == pei_http_method_id) {
            method = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_http_status_id) {
            response = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_http_client_id) {
            agent = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_http_req_header_id) {
            /* new path */
            rep = rq_header;
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_HTTP_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
        }
        else if (cmpn->eid == pei_http_req_body_id) {
            /* new path */
            rep = rq_body;
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_HTTP_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
            rq_bd_size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_http_res_header_id) {
            /* new path */
            rep = rs_header;
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_HTTP_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
        }
        else if (cmpn->eid == pei_http_res_body_id) {
            /* new path */
            rep = rs_body;
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_HTTP_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
            rs_bd_size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_http_file_id) {
            file = cmpn->file_path;
            filename = cmpn->name;
            size = cmpn->file_size;
        }

        cmpn = cmpn->next;
    }
    /* compose httpfile query and insert record */
    if (file != NULL) {
        /* new paths */
        name = strrchr(file, '/');
        name++;
        rep = rq_body;
        sprintf(rep, XS_HTTPFILE_DIR_PATH"/%s", pol, sess, name);
        rename(file, rep);
        DispFilePaths(pol, rep);
        
        /* flow info */
        sprintf(flow_info, XS_HTTPFILE_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_HTTPFILE_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                url, "", rep, filename, (unsigned long)size, "", "100%");
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    /* compose http query and insert record */
    else if (rs_header != NULL) {
        /* normalise url */
        if (strchr(url, '\'') != NULL) {
            DispUrlNorm(url);
        }

        /* flow info */
        sprintf(flow_info, XS_HTTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_WEB_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                url, XS_URL_REL_6, method, response, agent, host, cont_type, rq_header, rq_body, rq_bd_size, rs_header, rs_body, rs_bd_size);
        if (DispQuery(query, &id) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, rq_bd_size+rs_bd_size, ST_WEB, id, query);
        }
    }

    /* if feed */
    if (cont_type_resp != NULL && rs_bd_size != 0 && strstr(cont_type_resp, "xml") != NULL) {
        /* read body file */
        sprintf(tmp, "gunzip %s -c > %s/%p.dec 2> /dev/null", rs_body, ProtTmpDir(), rs_body);
        ret = system(tmp);
        sprintf(tmp, "%s/%p.dec", ProtTmpDir(), rs_body);
        if (ret == 0) {
            fp = fopen(tmp, "r");
        }
        else {
            fp = fopen(rs_body, "r");
        }
        if (fp != NULL) {
            dim = fread(buffer, 1, XS_QUERY_DIM, fp);
            buffer[dim-1] = '\0';
            /* RSS */
            if (strstr(buffer, "<rss") != NULL) {
                /* find title */
                title = strstr(buffer, "<title>");
                if (title != NULL) {
                    title += 7; 
                    end = strstr(title, "</");
                    if (end != NULL) {
                        end[0] = '\0';
                        char dst[strlen(title)*2];
                        /* find if already insert */
                        pthread_mutex_lock(&feed_mux); /* this garantee the use of only one entry */
                        pthread_mutex_lock(&db_mux);
                        sprintf(query, XS_QUERY_FEEDS_SEARCH, sess, DispLabelCnv(title, dst));

                        sqlite3_prepare_v2(db, query, -1, &stmt, 0);
                        while ((res = sqlite3_step(stmt)) == SQLITE_LOCKED || res == SQLITE_BUSY)
                            sched_yield();
                        if (res != SQLITE_ROW) {
                            sqlite3_finalize(stmt);
                        }
                        if (res != SQLITE_ROW) {
                            pthread_mutex_unlock(&db_mux);
                            
                            /* find link */
                            link = strstr(end+1, "<link>");
                            if (link != NULL) {
                                link += 6;
                                end = strstr(link, "</");
                                if (end != NULL) {
                                    end[0] = '\0';
                                    /*printf("Title: %s link: %s\n", title, link);*/
                                }
                            }
                            else {
                                link = "";
                            }
                            /* insert feed */
                            /* query */
                            sprintf(query, XS_QUERY_FEEDS_TEMPLATE, sess, pol, src_id, DispLabelCnv(title, dst), link);
                            if (DispQuery(query, &id) != 0) {
                                printf("query: %s\n", query);
                            }
                            sprintf(query, XS_QUERY_FEEDS_XML_TEMPLATE, sess, pol, src_id, id, PEI_TIME(ppei->time_cap), flow_info, url, rs_header, rs_body, rs_bd_size);
                            if (DispQuery(query, NULL) != 0) {
                                printf("query: %s\n", query);
                            }
                        }
                        else {
                            id = sqlite3_column_int(stmt, 0);
                            sqlite3_finalize(stmt);
                            pthread_mutex_unlock(&db_mux);
                            /* insert feed */
                            /* query */
                            sprintf(query, XS_QUERY_FEEDS_XML_TEMPLATE, sess, pol, src_id, id, PEI_TIME(ppei->time_cap), flow_info, url, rs_header, rs_body, rs_bd_size);
                            if (DispQuery(query, NULL) != 0) {
                                printf("query: %s\n", query);
                            }
                        }
                        pthread_mutex_unlock(&feed_mux);
                        if (err != NULL) {
                            sqlite3_free(err);
                            err = NULL;
                        }
                    }
                }
            }
            else {
                /* Atom */
                if (strstr(buffer, "<feed") != NULL && strstr(buffer, "http://www.w3.org/2005/Atom") != NULL) {
                    /* find title */
                    title = strstr(buffer, "<title");
                    if (title != NULL) {
                        title = strstr(title, ">");
                    }
                    if (title != NULL) {
                        title += 1;
                        end = strstr(title, "</");
                        if (end != NULL) {
                            end[0] = '\0';
                            char dst[strlen(title)*2];
                            
                            /* find if already insert */
                            pthread_mutex_lock(&feed_mux); /* this garantee the use of only one entry */
                            pthread_mutex_lock(&db_mux);
                            sprintf(query, XS_QUERY_FEEDS_SEARCH, sess, DispLabelCnv(title, dst));

                            sqlite3_prepare_v2(db, query, -1, &stmt, 0);
                            while ((res = sqlite3_step(stmt)) == SQLITE_LOCKED || res == SQLITE_BUSY)
                                sched_yield();
                            if (res != SQLITE_ROW) {
                                sqlite3_finalize(stmt);
                            }
                            if (res != SQLITE_ROW) {
                                pthread_mutex_unlock(&db_mux);
                                
                                /* find link */
                                link = host;
                                /* insert feed */
                                /* query */
                                sprintf(query, XS_QUERY_FEEDS_TEMPLATE, sess, pol, src_id, DispLabelCnv(title, dst), link);
                                if (DispQuery(query, &id) != 0) {
                                    printf("query: %s\n", query);
                                }
                                sprintf(query, XS_QUERY_FEEDS_XML_TEMPLATE, sess, pol, src_id, id, PEI_TIME(ppei->time_cap), flow_info, url, rs_header, rs_body, rs_bd_size);
                                if (DispQuery(query, NULL) != 0) {
                                    printf("query: %s\n", query);
                                }
                            }
                            else {
                                id = sqlite3_column_int(stmt, 0);
                                sqlite3_finalize(stmt);
                                pthread_mutex_unlock(&db_mux);
                                /* insert feed */
                                /* query */
                                sprintf(query, XS_QUERY_FEEDS_XML_TEMPLATE, sess, pol, src_id, id, PEI_TIME(ppei->time_cap), flow_info, url, rs_header, rs_body, rs_bd_size);
                                if (DispQuery(query, NULL) != 0) {
                                    printf("query: %s\n", query);
                                }
                            }
                            pthread_mutex_unlock(&feed_mux);
                        }
                    }
                }
            }
            fclose(fp);
        }
        remove(tmp);
    }
    
    if (cont_type_big != NULL)
        xfree(cont_type_big);

    return 0;
}


static int DispFtp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    char *user, *passwd, *url, *filename, *path, *name, *up_n, *down_n;
    const pstack_f *frame;
    int pol, sess, src_id, downloaded;
    unsigned long rid;
    size_t msize;
    ftval val, ip;
    bool datafile;
    struct stat info;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    url = NULL;
    path = NULL;
    filename = passwd = user = "";
    cmpn = ppei->components;
    downloaded = 1;
    datafile = FALSE;
    msize = 0;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ftp_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_pswd_id) {
            passwd = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_cmd_id) {
            filename = cmpn->name;
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        else if (cmpn->eid == pei_ftp_file_in_id) {
            downloaded = 1;
            datafile = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        else if (cmpn->eid == pei_ftp_file_out_id) {
            downloaded = 0;
            datafile = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
            msize = cmpn->file_size;
        }
        else if (cmpn->eid == pei_ftp_file_offset_id) {
        }
        else if (cmpn->eid == pei_ftp_up_n_id) {
            up_n = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_ftp_down_n_id) {
            down_n = cmpn->strbuf;
        }

        cmpn = cmpn->next;
    }
    
    /* compose query and insert record */
    if (url && path) {
        if (ppei->id == 0 && ppei->ret == TRUE) {
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_FTP_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_FTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_FTP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info, url,
                    user, passwd, rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, msize, ST_FTP, rid, query);
            }
        }
        if (ppei->ret == FALSE) {
            /* update number of file */
            sprintf(query, XS_QUERY_FTP_UPDATE, up_n, down_n, ppei->id);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, msize, ST_FTP, rid, query);
            }
        }
    }
    else if (datafile == TRUE && path && stat(path, &info) == 0) {
        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_FTP_DIR_PATH"/%s", pol, sess, name);
        rename(path, rep);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_FTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_FTP_DATA_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                ppei->pid, filename, rep, (unsigned long)info.st_size, downloaded);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(TRUE, TRUE, pol, sess, src_id, ppei->time_cap, url, msize, ST_FTP, ppei->pid, query);
        }
    }

    return 0;
}


static int DispIpp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char pdf[XS_QUERY_DIM];
    char pcl[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *url, *path, *name;
    off_t pdf_size, pcl_size;
    const pstack_f *frame;
    ftval val, ip;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = NULL;
    pdf[0] = '\0';
    pcl[0] = '\0';
    pdf_size = pcl_size = 0;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ipp_url_id) {
            url = cmpn->strbuf;
        }
        if (cmpn->eid == pei_ipp_pdf_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(pdf, XS_IPP_DIR_PATH"/%s", pol, sess, name);
            rename(path, pdf);
            DispFilePaths(pol, pdf);
            pdf_size = cmpn->file_size;
        }
        if (cmpn->eid == pei_ipp_pcl_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(pcl, XS_IPP_DIR_PATH"/%s", pol, sess, name);
            rename(path, pcl);
            DispFilePaths(pol, pcl);
            pcl_size = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (pcl[0] != '\0') {
        /* flow info */
        sprintf(flow_info, XS_IPP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);

        /* query */
        sprintf(query, XS_QUERY_PJL_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                url, pdf, (unsigned long)pdf_size, pcl, (unsigned long)pcl_size);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, (unsigned long)pdf_size, ST_PRINT, rid, query);
        }
    }
    
    return 0;
}


static int DispPjl(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char pdf[XS_QUERY_DIM];
    char pcl[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *url, *path, *name;
    off_t pdf_size, pcl_size;
    const pstack_f *frame;
    ftval val, ip;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = NULL;
    pdf[0] = '\0';
    pcl[0] = '\0';
    pdf_size = pcl_size = 0;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pjl_url_id) {
            url = cmpn->strbuf;
        }
        if (cmpn->eid == pei_pjl_pdf_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(pdf, XS_PJL_DIR_PATH"/%s", pol, sess, name);
            rename(path, pdf);
            DispFilePaths(pol, pdf);
            pdf_size = cmpn->file_size;
        }
        if (cmpn->eid == pei_pjl_pcl_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(pcl, XS_PJL_DIR_PATH"/%s", pol, sess, name);
            rename(path, pcl);
            DispFilePaths(pol, pcl);
            pcl_size = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (pcl[0] != '\0') {
        /* flow info */
        sprintf(flow_info, XS_PJL_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);

        /* query */
        sprintf(query, XS_QUERY_PJL_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                url, pdf, (unsigned long)pdf_size, pcl, (unsigned long)pcl_size);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, (unsigned long)pdf_size, ST_PRINT, rid, query);
        }
    }
    
    return 0;
}


static int DispMms(pei *ppei)
{
    static int inc = 0;
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char new_path[XS_QUERY_DIM];
    char *path, *name;
    const pstack_f *frame;
    char *from, *to, *cc, *bcc;
    int pol, sess, src_id, contents;
    unsigned long rid;
    ftval val, ip;
    size_t msize;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    contents = 0;
    from = to = cc = bcc = " ";
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_mms_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_to_id) {
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_cc_id) {
            cc = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_bcc_id) {
            bcc = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mms_part_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, XS_MMS_DIR_PATH"/%s", pol, sess, name);
            rename(path, new_path);
            DispFilePaths(pol, new_path);
            DMemFree(cmpn->file_path);
            cmpn->file_path = DMemMalloc(strlen(new_path)+1);
            strcpy(cmpn->file_path, new_path);
            contents++;
        }
        else if (cmpn->eid == pei_mms_raw_id) {
            path = cmpn->file_path;
            name = strrchr(path, '/');
            name++;
            sprintf(new_path, XS_MMS_DIR_PATH"/%s", pol, sess, name);
            rename(path, new_path);
            DispFilePaths(pol, new_path);
            DMemFree(cmpn->file_path);
            cmpn->file_path = DMemMalloc(strlen(new_path)+1);
            strcpy(cmpn->file_path, new_path);            
            contents++;
        }
        cmpn = cmpn->next;
    }
    /* flow info */
    sprintf(flow_info, XS_MMS_DIR_PATH"/flow_%lld_%i.xml", pol, sess, (long long)time(NULL), inc++);
    DispFlowInfo(flow_info, ppei->stack);
    /* compose query and insert record */
    sprintf(query, XS_QUERY_MMS_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
            " ", from, to, cc, bcc, contents);
    if (DispQuery(query, &rid) != 0) {
        printf("query: %s\n", query);
    }
    else {
        msize = 0;
        /* compose query and insert record for pevery art */
        cmpn = ppei->components;
        while (cmpn != NULL) {
            if (cmpn->eid == pei_mms_part_id) {
                if (cmpn->strbuf != NULL) {
                    if (cmpn->name != NULL) {
                        sprintf(query, XS_QUERY_MMS_CONT_TEMPLATE, sess, pol, src_id, rid, cmpn->strbuf, cmpn->name, cmpn->file_path, (unsigned long)cmpn->file_size);
                    }
                    else {
                        sprintf(query, XS_QUERY_MMS_CONT_TEMPLATE, sess, pol, src_id, rid, cmpn->strbuf, "No name", cmpn->file_path, (unsigned long)cmpn->file_size);
                    }
                }
                else if (cmpn->name != NULL) {
                    sprintf(query, XS_QUERY_MMS_CONT_TEMPLATE, sess, pol, src_id, rid, "unknow", cmpn->name, cmpn->file_path, (unsigned long)cmpn->file_size);
                }
                else {
                    sprintf(query, XS_QUERY_MMS_CONT_TEMPLATE, sess, pol, src_id, rid, "unknow", "No name", cmpn->file_path, (unsigned long)cmpn->file_size);
                }
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
            else if (cmpn->eid == pei_mms_raw_id) {
                msize = cmpn->file_size;
                sprintf(query, XS_QUERY_MMS_CONT_TEMPLATE, sess, pol, src_id, rid, "binary", "raw.mms", cmpn->file_path, (unsigned long)cmpn->file_size);
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
            cmpn = cmpn->next;
        }
        sprintf(flow_info, "%s -> %s", from, to);
        DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, flow_info, (unsigned long)msize, ST_MMS, rid, query);
    }
    
    return 0;
}


static int DispTftp(pei *ppei)
{
    static int inc = 0;
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    char *url, *filename, *path, *name, *up_n, *down_n;
    const pstack_f *frame;
    int pol, sess, src_id, downloaded;
    unsigned long rid;
    ftval val, ip;
    bool datafile;
    size_t data_size;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    
    url = NULL;
    path = filename = "";
    cmpn = ppei->components;
    downloaded = TRUE;
    datafile = FALSE;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_tftp_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_tftp_cmd_id) {
            filename = cmpn->name;
            path = cmpn->file_path;
            data_size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_tftp_file_in_id) {
            downloaded = 1;
            datafile = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
            data_size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_tftp_file_out_id) {
            downloaded = 0;
            datafile = TRUE;
            filename = cmpn->name;
            path = cmpn->file_path;
            data_size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_tftp_up_n_id) {
            up_n = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_tftp_down_n_id) {
            down_n = cmpn->strbuf;
        }

        cmpn = cmpn->next;
    }
    
    /* compose query and insert record */
    if (url && path) {
        if (ppei->id == 0 && ppei->ret == TRUE) {
            /* new path */
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_TFTP_DIR_PATH"/%s", pol, sess, name);
            DispCopy(path, rep, FALSE);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_TFTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_TFTP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info, url,
                    rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, data_size, ST_TFTP, rid, query);
            }
        }
        if (ppei->ret == FALSE) {
            /* update file */
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_TFTP_DIR_PATH"/%s", pol, sess, name);
            DispCopy(path, rep, TRUE);
            DispFilePaths(pol, rep);
            /* update number of file */
            sprintf(query, XS_QUERY_TFTP_UPDATE, up_n, down_n, ppei->id);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, url, data_size, ST_TFTP, rid, query);
            }
        }
    }
    else if (datafile == TRUE && path) {
         /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_TFTP_DIR_PATH"/%s", pol, sess, name);
        DispCopy(path, rep, TRUE);
        /* flow info */
        sprintf(flow_info, XS_TFTP_DIR_PATH"/flow_%s_%i.xml", pol, sess, name, inc++);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_TFTP_DATA_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                ppei->pid, filename, rep, (unsigned long)data_size, downloaded);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(TRUE, TRUE, pol, sess, src_id, ppei->time_cap, url, data_size, ST_TFTP, ppei->pid, query);
        }
    }

    return 0;
}


static int DispDns(pei *ppei)
{
    static int inc = 0;
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char *ip_one, *host, *cname;
    const pstack_f *frame;
    int pol, sess, src_id;
    ftval val, ip;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    
    ip_one = NULL;
    host = NULL;
    cname = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_dns_host_id) {
            host = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_ip_id && ip_one == NULL) {
            ip_one = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_cname_id && cname == NULL) {
            cname = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip_one != NULL || cname != NULL) {
        if (cname == NULL)
            cname = "";
        if (ip_one == NULL)
            ip_one = "";
        
        /* flow info */
        sprintf(flow_info, XS_DNS_DIR_PATH"/flow_%lld_%i.xml", pol, sess, (long long)time(NULL), inc++);
        DispFlowInfo(flow_info, ppei->stack);
        
        /* compose query and insert record */
        sprintf(query, XS_QUERY_DNS_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                host, cname, ip_one);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    
    return 0;
}


static int DispNntp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char subject[XS_STR_DIM];
    char from[XS_STR_DIM];
    char to[XS_STR_DIM];
    char flow_info[XS_STR_PATH];
    char att_dir[XS_STR_PATH];
    int pol, sess, src_id, res, obody, receiv;
    unsigned long id;
    char *grp, *url, *body, *post, *artcl;
    char *path;
    struct stat info;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    bool data;
    sqlite3_stmt *stmt;
    size_t msize;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    path = url = grp = artcl = body = post = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_nntp_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_nntp_grp_id) {
            grp = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_nntp_article_id) {
            artcl = cmpn->file_path;
        }
        else if (cmpn->eid == pei_nntp_body_id) {
            body = cmpn->file_path;
        }
        else if (cmpn->eid == pei_nntp_post_id) {
            post = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }
    /* check data */
    data = FALSE;
    obody = 0;
    receiv = 1;
    if (artcl != NULL) {
        if (stat(artcl, &info) == 0 && info.st_size != 0) {
            data = TRUE;
            path = artcl;
        }
    }
    else if (body != NULL) {
        if (stat(body, &info) == 0 && info.st_size != 0) {
            data = TRUE;
            path = body;
            obody = 1;
            msize = cmpn->file_size;
        }
    }
    else if (post != NULL) {
        if (stat(post, &info) == 0 && info.st_size != 0) {
            data = TRUE;
            path = post;
            receiv = 0;
            msize = cmpn->file_size;
        }
    }
    /* compose query and insert record */
    if (data == TRUE && grp != NULL) {
        char dst[strlen(grp)*2];

        /* grp find if already insert */
        pthread_mutex_lock(&nntp_mux); /* this garantee the use of only one entry */
        pthread_mutex_lock(&db_mux);
        sprintf(query, XS_QUERY_NNTP_SEARCH, sess, DispLabelCnv(grp, dst));
        sqlite3_prepare_v2(db, query, -1, &stmt, 0);
        while ((res = sqlite3_step(stmt)) == SQLITE_LOCKED || res == SQLITE_BUSY)
            sched_yield();
        if (res != SQLITE_ROW) {
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_mux);
            /* insert nntp grp */
            /* query */
            sprintf(query, XS_QUERY_NNTP_TEMPLATE, sess, pol, src_id, DispLabelCnv(grp, dst));
            if (DispQuery(query, &id) != 0) {
                printf("query: %s\n", query);
            }
        }
        else {
            id = sqlite3_column_int(stmt, 0);
            sqlite3_finalize(stmt);
            pthread_mutex_unlock(&db_mux);
        }
        pthread_mutex_unlock(&nntp_mux);
        
        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_NNTP_DIR_PATH"/%s", pol, sess, name);
        rename(path, rep);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_NNTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* parse mime */
        sprintf(att_dir, XS_NNTP_DIR_PATH"/%s_attach", pol, sess, name);
        memset(subject, 0, XS_STR_DIM);
        memset(from, 0, XS_STR_DIM);
        memset(to, 0, XS_STR_DIM);
        if (DispMimeParse(rep, subject, from, to, att_dir) != -1) {
            /* query */
            sprintf(query, XS_QUERY_NNTP_ARTCL_TEMPLATE, sess, pol, src_id, id, PEI_TIME(ppei->time_cap),
                    (unsigned long)info.st_size, flow_info, receiv, obody, from, to, subject, rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, subject, msize, ST_NNTP, rid, query);
            }
        }
    }

    return 0;
}


static int DispFbwc(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id, res;
    unsigned long id, rid;
    char *chat, *user, *uid, *friend;
    long duration;
    char *dst_a, *dst_b;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    sqlite3_stmt *stmt;
    size_t chtsize;
    
    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    chat = user = uid = friend = NULL;
    duration = 0; /* duration 0 sec */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_fbwc_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_uid_id) {
            uid = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_friend_id) {
            friend = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_fbwc_chat_id) {
            chat = cmpn->file_path;
            chtsize = cmpn->file_size;
        }
        else if (cmpn->eid == pei_fbwc_duration_id) {
            duration = atol(cmpn->strbuf);
        }
        cmpn = cmpn->next;
    }
    /* check data */
    if (chat == NULL)
        return 0;

    /* compose query and insert record */
    dst_a = xmalloc(strlen(user)*2);
    dst_b = xmalloc(strlen(friend)*2);

    /* uid find if already insert */
    pthread_mutex_lock(&fbchat_mux); /* this garantee the use of only one entry */
    pthread_mutex_lock(&db_mux);
    sprintf(query, XS_QUERY_FBWCHAT_SEARCH, sess, uid);
    sqlite3_prepare_v2(db, query, -1, &stmt, 0);
    while ((res = sqlite3_step(stmt)) == SQLITE_LOCKED || res == SQLITE_BUSY)
        sched_yield();
    if (res != SQLITE_ROW) {
        sqlite3_finalize(stmt);
    }
    if (res != SQLITE_ROW) {
        pthread_mutex_unlock(&db_mux);
        /* insert new user */
        /* query */
        sprintf(query, XS_QUERY_FBWCHAT_TEMPLATE, sess, pol, src_id, DispLabelCnv(user, dst_a), uid);
        if (DispQuery(query, &id) != 0) {
            printf("query: %s\n", query);
        }
    }
    else {
        id = sqlite3_column_int(stmt, 0);
        sqlite3_finalize(stmt);
        pthread_mutex_unlock(&db_mux);
    }
    pthread_mutex_unlock(&fbchat_mux);
    
    /* new path */
    name = strrchr(chat, '/');
    name++;
    sprintf(rep, XS_FBWC_DIR_PATH"/%s", pol, sess, name);
    if (ppei->ret == TRUE) {
        if (ppei->id == 0) {
            DispCopy(chat, rep, FALSE);
            DispFilePaths(pol, rep);
            
            /* flow info */
            sprintf(flow_info, XS_FBWC_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_FBWCHAT_CHAT, sess, pol, src_id, id, PEI_TIME(ppei->time_cap), (unsigned long)chtsize, flow_info, DispLabelCnv(user, dst_a), DispLabelCnv(friend, dst_b), rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
                sprintf(flow_info, "%s - %s", dst_a, dst_b);
                DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, flow_info, chtsize, ST_FBWC, rid, query);
            }
        }
        else {
            /* update */
            DispCopy(chat, rep, FALSE);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_FBWC_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_FBWCHAT_UPDATE, flow_info, rep, (unsigned long)chtsize, duration, ppei->id);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
            else {
                DispInteraction(TRUE, FALSE, pol, sess, src_id, ppei->time_cap, NULL, chtsize, ST_FBWC, ppei->id, query);
            }
        }
    }
    else {
        /* update and end */
        DispCopy(chat, rep, TRUE);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_FBWC_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_FBWCHAT_UPDATE, flow_info, rep, (unsigned long)chtsize, duration, ppei->id);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(TRUE, FALSE, pol, sess, src_id, ppei->time_cap, NULL, chtsize, ST_FBWC, ppei->id, query);
        }
    }
    free(dst_a);
    free(dst_b);

    return 0;
}


static int DispTelnet(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *host, *user, *pwd, *path;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t size;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    host = path = NULL;
    pwd = user = " ";
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_telnet_host_id) {
            host = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_telnet_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_telnet_password_id) {
            pwd = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_telnet_cmd_id) {
            path = cmpn->file_path;
            size = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (path) {
        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_TELNET_DIR_PATH"/%s", pol, sess, name);
        rename(path, rep);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_TELNET_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_TELNET_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                host, user, pwd, rep, (unsigned long)size);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, host, size, ST_TELNET, rid, query);
        }
    }

    return 0;
}


static int DispWebmail(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep_0[XS_QUERY_DIM];
    char rep_1[XS_QUERY_DIM];
    char rep_2[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id, i, dirv;
    char *rep, *dir, *path, *service, *to, *from, *cc, *mid, *subj, *eml, *html, *txt;
    const pstack_f *frame;
    ftval val, ip;
    char *name, *subject;
    size_t size;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    service = to = from = cc = mid = subj = "";
    subject = NULL;
    eml = html = txt = NULL;
    rep_0[0] = '\0';
    rep_1[0] = '\0';
    rep_2[0] = '\0';
    dirv = 1;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_webmail_serv_id) {
            service = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_to_id) {
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_cc_id) {
            cc = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_messageid_id) {
            mid = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webmail_subj_id) {
            subj = cmpn->strbuf;
            if (strchr(subj, '\'') != NULL) {
                subject = xmalloc(strlen(subj)*2);
                strcpy(subject, subj);
                DispUrlNorm(subject);
                subj = subject;
            }
        }
        else if (cmpn->eid == pei_webmail_eml_id) {
            eml = cmpn->file_path;
            size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_webmail_dir_id) {
            dir = cmpn->strbuf;
            if (dir[0] == 's')
                dirv = 0;
        }
        else if (cmpn->eid == pei_webmail_html_id) {
            html = cmpn->file_path;
        }
        else if (cmpn->eid == pei_webmail_txt_id) {
            txt = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (eml) {
        /* new path */
        i = 3;
        while (i) {
            switch (i) {
            case 3:
                path = eml;
                rep = rep_0;
                i--;
                break;

            case 2:
                i--;
                if (txt == NULL) {
                    continue;
                }
                path = txt;
                rep = rep_1;
                break;

            case 1:
                i--;
                if (html == NULL) {
                    continue;
                }
                path = html;
                rep = rep_2;
                break;
            }
            name = strrchr(path, '/');
            name++;
            sprintf(rep, XS_WEBMAIL_DIR_PATH"/%s", pol, sess, name);
            rename(path, rep);
            DispFilePaths(pol, rep);
        }
        /* flow info */
        sprintf(flow_info, XS_WEBMAIL_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_WBAMIL_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), (unsigned long)size, flow_info, dirv, service, mid, from, to , cc, subj, rep_0, rep_1, rep_2);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, subj, size, ST_WEBMAIL, rid, query);
        }
    }
    if (subject != NULL)
        xfree(subject);
    
    return 0;
}


static int DispHttpFile(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char repb[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *url, *file, *filename, *content, *parts, *perc, *path;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t size;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    url = file = filename = parts = NULL;
    perc = content = "";
    cmpn = ppei->components;
    
    while (cmpn != NULL) {
        if (cmpn->eid == pei_httpfile_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid ==pei_httpfile_content_type ) {
            content = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_httpfile_file_id) {
            file = cmpn->file_path;
            filename = cmpn->name;
            size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_httpfile_parts_id) {
            parts = cmpn->file_path;
        }
        else if (cmpn->eid == pei_httpfile_complete_id) {
            perc = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (file) {
        rep[0] = repb[0] = '\0';
        /* new paths */
        name = strrchr(file, '/');
        name++;
        sprintf(rep, XS_HTTPFILE_DIR_PATH"/%s", pol, sess, name);
        rename(file, rep);
        DispFilePaths(pol, rep);
        
        if (parts != NULL) {
            path = strrchr(parts, '/');
            path++;
            sprintf(repb, XS_HTTPFILE_DIR_PATH"/%s", pol, sess, path);
            rename(parts, repb);
        }
        
        /* flow info */
        sprintf(flow_info, XS_HTTPFILE_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_HTTPFILE_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                url, content, rep, filename, (unsigned long)size, repb, perc);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, filename, size, ST_HTTPFILE, rid, query);
        }
    }

    return 0;
}


static int DispGrbTcp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char dst[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *prot, *file;
    const pstack_f *frame;
    ftval val, ip;
    char *name, *raw, *raw_name, *raw_type;
    size_t size;
    unsigned short dst_port;
    unsigned long dur;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
        ProtGetAttr(frame, ip_dst_id, &ip);
        if (DnsDbSearch(&ip, FT_IPv4, dst, XS_QUERY_DIM) != 0) {
            FTString(&ip, FT_IPv4, dst);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
            ProtGetAttr(frame, ipv6_dst_id, &ip);
            if (DnsDbSearch(&ip, FT_IPv6, dst, XS_QUERY_DIM) != 0) {
                FTString(&ip, FT_IPv6, dst);
            }
        }
    }
    ProtGetAttr(ppei->stack, tcp_dstport_id, &val);
    dst_port = val.int16;

    prot = file = raw = raw_name = raw_type = NULL;
    cmpn = ppei->components;
    dur = 0;
    size = 0;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_grb_tcp_l7protocol_id) {
            prot = cmpn->strbuf;
            dur = cmpn->time_cap_end - cmpn->time_cap;
        }
        else if (cmpn->eid == pei_grb_tcp_size_id) {
            size = atoll(cmpn->strbuf);
        }
        else if (cmpn->eid == pei_grb_tcp_txt_id) {
            file = cmpn->file_path;
            size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_grb_tcp_file_id) {
            raw = cmpn->file_path;
            raw_name = cmpn->name;
            size = cmpn->file_size;
        }
        else if (cmpn->eid == pei_grb_tcp_file_type_id) {
            raw_type = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (size != 0) {
        if (raw == NULL) {
            if (file != NULL) {
                /* new paths */
                name = strrchr(file, '/');
                name++;
                sprintf(rep, XS_GRBTCP_DIR_PATH"/%s", pol, sess, name);
                rename(file, rep);
                DispFilePaths(pol, rep);
                /* flow info */
                sprintf(flow_info, XS_GRBTCP_DIR_PATH"/flow_%s.xml", pol, sess, name);
            }
            else {
                /* flow info */
                sprintf(flow_info, XS_GRBTCP_DIR_PATH"/flow_%p_%x_%lld_%p.xml", pol, sess, dst, dst[0], (long long)time(NULL), dst);
                strcpy(rep, "None");
            }
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_GRBTCP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                    dst,  dst_port, prot, rep, (unsigned long)size, dur);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
        }
        else {
            /* new paths */
            name = strrchr(raw, '/');
            name++;
            sprintf(rep, XS_UNKFILE_DIR_PATH"/%s", pol, sess, name);
            rename(raw, rep);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_UNKFILE_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_UNKFILE_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                    "", rep, raw_name, (unsigned long)size, raw_type);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
        }
    }

    return 0;
}


static int DispGrbUdp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char dst[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *prot, *file;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t size;
    unsigned short dst_port;
    unsigned long dur;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
        ProtGetAttr(frame, ip_dst_id, &ip);
        if (DnsDbSearch(&ip, FT_IPv4, dst, XS_QUERY_DIM) != 0) {
            FTString(&ip, FT_IPv4, dst);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
            ProtGetAttr(frame, ipv6_dst_id, &ip);
            if (DnsDbSearch(&ip, FT_IPv6, dst, XS_QUERY_DIM) != 0) {
                FTString(&ip, FT_IPv6, dst);
            }
        }
    }
    ProtGetAttr(ppei->stack, tcp_dstport_id, &val);
    dst_port = val.int16;

    prot = file = NULL;
    cmpn = ppei->components;
    dur = 0;
    size = 0;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_grb_udp_l7protocol_id) {
            prot = cmpn->strbuf;
            dur = cmpn->time_cap_end - cmpn->time_cap;
        }
        else if (cmpn->eid == pei_grb_udp_size_id) {
            size = atoll(cmpn->strbuf);
        }
        else if (cmpn->eid == pei_grb_udp_txt_id) {
            file = cmpn->file_path;
            size = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (size != 0) {
        if (file) {
            /* new paths */
            name = strrchr(file, '/');
            name++;
            sprintf(rep, XS_GRBUDP_DIR_PATH"/%s", pol, sess, name);
            rename(file, rep);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_GRBUDP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        }
        else {
            /* flow info */
            sprintf(flow_info, XS_GRBUDP_DIR_PATH"/flow_%p_%x_%lld_%p.xml", pol, sess, dst, dst[0], (long long)time(NULL), dst);
            strcpy(rep, "None");
        }
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_GRBUDP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                dst,  dst_port, prot, rep, (unsigned long)size, dur);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    
    return 0;
}


static int DispRtp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep1[XS_QUERY_DIM];
    char rep2[XS_QUERY_DIM];
    char rep3[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *from, *to, *audio_from, *audio_to, *mix, *duration;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t msize;
    unsigned long rid;
    bool calr, caled;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    from = to = mix = audio_from = audio_to = duration = NULL;
    msize = 0;
    calr = caled = FALSE;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_rtp_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_rtp_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_rtp_duration){
            duration = cmpn->strbuf;
            msize = atol(duration);
        }
        else if (cmpn->eid == pei_rtp_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_rtp_audio_from) {
            if (calr)
                audio_from = cmpn->file_path;
            else
                remove(cmpn->file_path);
            calr = TRUE;
        }
        else if (cmpn->eid == pei_rtp_audio_to) {
            if (caled)
                audio_to = cmpn->file_path;
            else
                remove(cmpn->file_path);
            caled = TRUE;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (from) {
        /* new paths */
        if (audio_from) {
            name = strrchr(audio_from, '/');
            name++;
            sprintf(rep1, XS_RTP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_from, rep1);
            DispFilePaths(pol, rep1);
        }
        else {
            rep1[0] = '\0';
        }
        if (audio_to) {
            name = strrchr(audio_to, '/');
            name++;
            sprintf(rep2, XS_RTP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_to, rep2);
            DispFilePaths(pol, rep2);
        }
        else {
            rep2[0] = '\0';
        }
        if (mix) {
            name = strrchr(mix, '/');
            name++;
            sprintf(rep3, XS_RTP_DIR_PATH"/%s", pol, sess, name);
            rename(mix, rep3);
            DispFilePaths(pol, rep3);
        }
        else {
            rep3[0] = '\0';
        }
        
        /* flow info */
        sprintf(flow_info, XS_RTP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_RTP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                from, to, rep1, rep2, rep3, duration);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            sprintf(flow_info, "%s - %s", from, to);
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, flow_info, msize, ST_RTP, rid, query);
        }
    }

    return 0;
}


static int DispSip(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep1[XS_QUERY_DIM];
    char rep2[XS_QUERY_DIM];
    char rep3[XS_QUERY_DIM];
    char rep4[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *from, *to, *audio_from, *audio_to, *mix, *duration, *cmds;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t msize;
    unsigned long rid;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    from = to = mix = audio_from = audio_to = duration = cmds = NULL;
    msize = 0;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_sip_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_sip_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_sip_cmd) {
            cmds = cmpn->file_path;
        }
        else if (cmpn->eid == pei_sip_duration){
            duration = cmpn->strbuf;
            msize = atol(duration);
        }
        else if (cmpn->eid == pei_sip_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_sip_audio_from) {
            audio_from = cmpn->file_path;
        }
        else if (cmpn->eid == pei_sip_audio_to) {
            audio_to = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (from) {
        /* new paths */
        if (audio_from) {
            name = strrchr(audio_from, '/');
            name++;
            sprintf(rep1, XS_SIP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_from, rep1);
            DispFilePaths(pol, rep1);
        }
        else {
            rep1[0] = '\0';
        }
        if (audio_to) {
            name = strrchr(audio_to, '/');
            name++;
            sprintf(rep2, XS_SIP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_to, rep2);
            DispFilePaths(pol, rep2);
        }
        else {
            rep2[0] = '\0';
        }
        if (mix) {
            name = strrchr(mix, '/');
            name++;
            sprintf(rep3, XS_SIP_DIR_PATH"/%s", pol, sess, name);
            rename(mix, rep3);
            DispFilePaths(pol, rep3);
        }
        else {
            rep3[0] = '\0';
        }
        if (cmds) {
            name = strrchr(cmds, '/');
            name++;
            sprintf(rep4, XS_SIP_DIR_PATH"/%s", pol, sess, name);
            rename(cmds, rep4);
            DispFilePaths(pol, rep4);
        }
        else {
            rep4[0] = '\0';
        }
        
        /* flow info */
        sprintf(flow_info, XS_SIP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_SIP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                from, to, rep1, rep2, rep3, duration, rep4);
        if (DispQuery(query, &rid) != 0) {
            printf("query: %s\n", query);
        }
        else {
            sprintf(flow_info, "%s - %s", from, to);
            DispInteraction(FALSE, FALSE, pol, sess, src_id, ppei->time_cap, flow_info, msize, ST_SIP, rid, query);
        }
    }

    return 0;
}


static int DispArp(pei *ppei)
{
    static int inc = 0;
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char *ip, *mac;
    const pstack_f *frame;
    int pol, sess;
    ftval val;
    
    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }

    mac = NULL;
    ip = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_arp_mac_id) {
            mac = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_arp_ip_id) {
            ip = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip != NULL && mac != NULL) {
        /* flow info */
        sprintf(flow_info, XS_ARP_DIR_PATH"/flow_%lld_%i.xml", pol, sess, (long long)time(NULL), inc++);
        DispFlowInfo(flow_info, ppei->stack);
        
        /* compose query and insert record */
        sprintf(query, XS_QUERY_ARP_TEMPLATE, sess, pol, PEI_TIME(ppei->time_cap), flow_info,
                mac, ip);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    
    return 0;
}


static int DispIcmpv6(pei *ppei)
{
    static int inc = 0;
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char *ip, *mac;
    const pstack_f *frame;
    int pol, sess;
    ftval val;
    
    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }

    mac = NULL;
    ip = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_icmpv6_mac_id) {
            mac = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_icmpv6_ip_id) {
            ip = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }
    if (ip != NULL && mac != NULL) {
        /* flow info */
        sprintf(flow_info, XS_ICMPv6_DIR_PATH"/flow_%lld_%i.xml", pol, sess, (long long)time(NULL), inc++);
        DispFlowInfo(flow_info, ppei->stack);
        
        /* compose query and insert record */
        sprintf(query, XS_QUERY_ICMPv6_TEMPLATE, sess, pol, PEI_TIME(ppei->time_cap), flow_info,
                mac, ip);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    
    return 0;
}


static int DispIrc(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    char rep1[XS_QUERY_DIM];
    char rep2[XS_QUERY_DIM];
    const pstack_f *frame;
    int pol, sess, src_id;
    unsigned long rid;
    ftval val, ip;
    char *name;
    char *channel, *cfile, *ufile, *cmd, *nick, *url, *num;
    time_t end;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }

    channel = cfile = ufile = cmd = nick = url = num = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_irc_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_irc_channels_num_id) {
            num = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_irc_server_id) {
            cmd = cmpn->file_path;
        }
        else if (cmpn->eid == pei_irc_channel_id) {
            channel = cmpn->name;
            cfile = cmpn->file_path;
            end = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_irc_channel_users_id) {
            ufile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_irc_channel_nick_id) {
            nick = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == TRUE) {
        if (cmd != NULL && ppei->id == 0) {
            /* new path */
            name = strrchr(cmd, '/');
            name++;
            sprintf(rep, XS_IRC_DIR_PATH"/%s", pol, sess, name);
            DispCopy(cmd, rep, FALSE);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_IRC_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_IRC_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                    flow_info, url, rep, num);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
            }
        }
    }
    else {
        if (cmd != NULL) {
            if (ppei->id != 0) {
                /* update */
                /* new path */
                name = strrchr(cmd, '/');
                name++;
                sprintf(rep, XS_IRC_DIR_PATH"/%s", pol, sess, name);
                DispCopy(cmd, rep, TRUE);
                DispFilePaths(pol, rep);
                /* query */
                sprintf(query, XS_QUERY_IRC_UPDATE, num, ppei->id);
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
            else {
                /* new path */
                name = strrchr(cmd, '/');
                name++;
                sprintf(rep, XS_IRC_DIR_PATH"/%s", pol, sess, name);
                DispCopy(cmd, rep, TRUE);
                DispFilePaths(pol, rep);
                /* flow info */
                sprintf(flow_info, XS_IRC_DIR_PATH"/flow_%s.xml", pol, sess, name);
                DispFlowInfo(flow_info, ppei->stack);
                /* query */
                sprintf(query, XS_QUERY_IRC_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                        flow_info, url, rep, num);
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
        }
        if (channel != NULL) {
            /* new path */
            name = strrchr(cfile, '/');
            name++;
            sprintf(rep, XS_IRC_DIR_PATH"/%s", pol, sess, name);
            DispCopy(cfile, rep, TRUE);
            DispFilePaths(pol, rep);
            name = strrchr(ufile, '/');
            name++;
            sprintf(rep1, XS_IRC_DIR_PATH"/%s", pol, sess, name);
            DispCopy(ufile, rep1, TRUE);
            DispFilePaths(pol, rep1);
            name = strrchr(nick, '/');
            name++;
            sprintf(rep2, XS_IRC_DIR_PATH"/%s", pol, sess, name);
            DispCopy(nick, rep2, TRUE);
            DispFilePaths(pol, rep2);

            /* flow info */
            sprintf(flow_info, XS_IRC_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_IRC_CHN_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                    flow_info, ppei->pid, channel, PEI_TIME(end), rep, rep1, rep2);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
            
        }
    }

    return 0;
}


static int DispPaltalkExp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    const pstack_f *frame;
    int pol, sess, src_id;
    unsigned long rid;
    ftval val, ip;
    char *name;
    char *duration, *chat, *nick;
    time_t end;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }

    duration = chat = nick = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pltk_e_user_id) {
            nick = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pltk_e_chat_id) {
            chat = cmpn->file_path;
            end = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_pltk_e_duration_id) {
            duration = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == TRUE) {
        if (chat != NULL && ppei->id == 0) {
            /* new path */
            name = strrchr(chat, '/');
            name++;
            sprintf(rep, XS_PLT_EXP_DIR_PATH"/%s", pol, sess, name);
            DispCopy(chat, rep, FALSE);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_PLT_EXP_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_PLT_EXP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                    flow_info, nick, PEI_TIME(ppei->time_cap), rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
            }
        }
    }
    else {
        if (chat != NULL) {
            if (ppei->id != 0) {
                /* update */
                /* new path */
                name = strrchr(chat, '/');
                name++;
                sprintf(rep, XS_PLT_EXP_DIR_PATH"/%s", pol, sess, name);
                DispCopy(chat, rep, TRUE);
                DispFilePaths(pol, rep);
                /* flow info */
                sprintf(flow_info, XS_PLT_EXP_DIR_PATH"/flow_%s.xml", pol, sess, name);
                DispFlowInfo(flow_info, ppei->stack);
                /* query */
                sprintf(query, XS_QUERY_PLT_EXP_UPDATE, flow_info, end, rep, ppei->id);
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
            else {
                /* new path */
                name = strrchr(chat, '/');
                name++;
                sprintf(rep, XS_PLT_EXP_DIR_PATH"/%s", pol, sess, name);
                DispCopy(chat, rep, FALSE);
                DispFilePaths(pol, rep);
                /* flow info */
                sprintf(flow_info, XS_PLT_EXP_DIR_PATH"/flow_%s.xml", pol, sess, name);
                DispFlowInfo(flow_info, ppei->stack);
                /* query */
                sprintf(query, XS_QUERY_PLT_EXP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                        flow_info, nick, PEI_TIME(ppei->time_cap), rep);
                if (DispQuery(query, NULL) != 0) {
                    printf("query: %s\n", query);
                }
            }
        }
    }

    return 0;
}


static int DispPaltalk(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    char rep1[XS_QUERY_DIM];
    char rep2[XS_QUERY_DIM];
    const pstack_f *frame;
    int pol, sess, src_id;
    ftval val, ip;
    char *name;
    char *room, *rfile, *ufile, *nick, *duration;
    time_t end;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }

    room = rfile = ufile = nick = duration = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_pltk_room_duration_id) {
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pltk_room_id) {
            room = cmpn->name;
            rfile = cmpn->file_path;
            end = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_pltk_room_users_id) {
            ufile = cmpn->file_path;
        }
        else if (cmpn->eid == pei_pltk_room_nick_id) {
            nick = cmpn->file_path;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == TRUE) {
        /* real time data */
    }
    else {
        /* end */
        if (room != NULL) {
            /* new path */
            name = strrchr(rfile, '/');
            name++;
            sprintf(rep, XS_PALTALK_DIR_PATH"/%s", pol, sess, name);
            DispCopy(rfile, rep, TRUE);
            DispFilePaths(pol, rep);
            name = strrchr(ufile, '/');
            name++;
            sprintf(rep1, XS_PALTALK_DIR_PATH"/%s", pol, sess, name);
            DispCopy(ufile, rep1, TRUE);
            DispFilePaths(pol, rep1);
            if (nick != NULL) {
                name = strrchr(nick, '/');
                name++;
                sprintf(rep2, XS_PALTALK_DIR_PATH"/%s", pol, sess, name);
                DispCopy(nick, rep2, TRUE);
                DispFilePaths(pol, rep2);
            }
            else {
                rep2[0] = '\0'; /* null path */
            }

            /* flow info */
            sprintf(flow_info, XS_PALTALK_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_PALTALK_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                    flow_info, room, PEI_TIME(end), rep, duration, rep1, rep2);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
            
        }
    }

    return 0;
}


static int DispMsn(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    char rep[XS_QUERY_DIM];
    const pstack_f *frame;
    int pol, sess, src_id;
    ftval val, ip;
    char *name;
    char *chat, *cfile, *from, *to, *duration;
    time_t end;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }

    chat = from = cfile = to = NULL;
    duration = "0";
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_msn_duration_id) {
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_msn_chat_id) {
            chat = cmpn->name;
            cfile = cmpn->file_path;
            end = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_msn_from_id) {
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_msn_to_id) {
            to = cmpn->strbuf;
        }
        
        cmpn = cmpn->next;
    }
    if (ppei->ret == TRUE) {
    }
    else {
        /* end */
        if (chat != NULL) {
            /* new path */
            name = strrchr(cfile, '/');
            name++;
            sprintf(rep, XS_MSN_DIR_PATH"/%s", pol, sess, name);
            DispCopy(cfile, rep, TRUE);
            DispFilePaths(pol, rep);

            /* flow info */
            sprintf(flow_info, XS_MSN_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_MSN_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap),
                    flow_info, chat, PEI_TIME(end), rep, duration);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
        }
    }

    return 0;
}


static int DispMgcp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep1[XS_QUERY_DIM];
    char rep2[XS_QUERY_DIM];
    char rep3[XS_QUERY_DIM];
    char rep4[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *from, *to, *audio_from, *audio_to, *mix, *duration, *cmds;
    const pstack_f *frame;
    ftval val, ip;
    char *name;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    from = to = mix = audio_from = audio_to = duration = cmds = NULL;

    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_mgcp_from){
            from = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mgcp_to){
            to = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mgcp_cmd) {
            cmds = cmpn->file_path;
        }
        else if (cmpn->eid == pei_mgcp_duration){
            duration = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_mgcp_audio_mix) {
            mix = cmpn->file_path;
        }
        else if (cmpn->eid == pei_mgcp_audio_from) {
            audio_from = cmpn->file_path;
        }
        else if (cmpn->eid == pei_mgcp_audio_to) {
            audio_to = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (from) {
        /* new paths */
        if (audio_from) {
            name = strrchr(audio_from, '/');
            name++;
            sprintf(rep1, XS_MGCP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_from, rep1);
            DispFilePaths(pol, rep1);
        }
        else {
            rep1[0] = '\0';
        }
        if (audio_to) {
            name = strrchr(audio_to, '/');
            name++;
            sprintf(rep2, XS_MGCP_DIR_PATH"/%s", pol, sess, name);
            rename(audio_to, rep2);
            DispFilePaths(pol, rep2);
        }
        else {
            rep2[0] = '\0';
        }
        if (mix) {
            name = strrchr(mix, '/');
            name++;
            sprintf(rep3, XS_MGCP_DIR_PATH"/%s", pol, sess, name);
            rename(mix, rep3);
            DispFilePaths(pol, rep3);
        }
        else {
            rep3[0] = '\0';
        }
        if (cmds) {
            name = strrchr(cmds, '/');
            name++;
            sprintf(rep4, XS_MGCP_DIR_PATH"/%s", pol, sess, name);
            rename(cmds, rep4);
            DispFilePaths(pol, rep4);
        }
        else {
            rep4[0] = '\0';
        }
        
        /* flow info */
        sprintf(flow_info, XS_MGCP_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_MGCP_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                from, to, rep1, rep2, rep3, duration, rep4);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }

    return 0;
}


static int DispWebYmsg(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    unsigned long rid;
    char *chat, *user, *friend;
    long duration;
    char *dst_a, *dst_b;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    size_t chtsize;
    
    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    chat = user = friend = NULL;
    duration = 0; /* duration 0 sec */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_webymsg_user_id) {
            user = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webymsg_friend_id) {
            friend = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_webymsg_chat_id) {
            chat = cmpn->file_path;
            chtsize = cmpn->file_size;
        }
        else if (cmpn->eid == pei_webymsg_duration_id) {
            duration = atol(cmpn->strbuf);
        }
        cmpn = cmpn->next;
    }
    /* check data */
    if (chat == NULL)
        return 0;

    /* compose query and insert record */
    dst_a = xmalloc(strlen(user)*2);
    dst_b = xmalloc(strlen(friend)*2);
    
    /* new path */
    name = strrchr(chat, '/');
    name++;
    sprintf(rep, XS_WEBYMSG_DIR_PATH"/%s", pol, sess, name);
    if (ppei->ret == TRUE) {
        if (ppei->id == 0) {
            DispCopy(chat, rep, FALSE);
            DispFilePaths(pol, rep);
            
            /* flow info */
            sprintf(flow_info, XS_WEBYMSG_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_WEBYMSG_CHAT, sess, pol, src_id, PEI_TIME(ppei->time_cap), (unsigned long)chtsize, flow_info, DispLabelCnv(user, dst_a), DispLabelCnv(friend, dst_b), rep);
            if (DispQuery(query, &rid) != 0) {
                printf("query: %s\n", query);
            }
            else {
                ppei->id = rid;
            }
        }
        else {
            /* update */
            DispCopy(chat, rep, FALSE);
            DispFilePaths(pol, rep);
            /* flow info */
            sprintf(flow_info, XS_WEBYMSG_DIR_PATH"/flow_%s.xml", pol, sess, name);
            DispFlowInfo(flow_info, ppei->stack);
            /* query */
            sprintf(query, XS_QUERY_WEBYMSG_UPDATE, flow_info, rep, (unsigned long)chtsize, duration, ppei->id);
            if (DispQuery(query, NULL) != 0) {
                printf("query: %s\n", query);
            }
        }
    }
    else {
        /* update and end */
        DispCopy(chat, rep, TRUE);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_WEBYMSG_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_WEBYMSG_UPDATE, flow_info, rep, (unsigned long)chtsize, duration, ppei->id);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }
    free(dst_a);
    free(dst_b);

    return 0;
}


static int DispSyslog(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *hosts, *path;
    const pstack_f *frame;
    ftval val, ip;
    char *name;
    unsigned long size;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    hosts = path = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_syslog_host_id) {
            hosts = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_syslog_log_id) {
            path = cmpn->file_path;
            size = cmpn->file_size;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (path) {
        /* new path */
        name = strrchr(path, '/');
        name++;
        sprintf(rep, XS_TELNET_DIR_PATH"/%s", pol, sess, name);
        rename(path, rep);
        DispFilePaths(pol, rep);
        /* flow info */
        sprintf(flow_info, XS_SYSLOG_DIR_PATH"/flow_%s.xml", pol, sess, name);
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_SYSLOG_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                hosts, rep, (unsigned long)size);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }

    return 0;
}


static int DispWhatsApp(pei *ppei)
{
    pei_component *cmpn;
    char query[XS_QUERY_DIM];
    char rep[XS_QUERY_DIM];
    char flow_info[XS_STR_PATH];
    int pol, sess, src_id;
    char *device, *phone;
    const pstack_f *frame;
    ftval val, ip;

    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        ProtGetAttr(frame, pol_polid_id, &val);
        pol = val.int32;
        ProtGetAttr(frame, pol_sesid_id, &val);
        sess = val.int32;
    }
    else {
        sess = pol = 1;
    }
    /* search source ip */
    src_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        src_id = DispHostSrch(&ip, FT_IPv4);
        if (src_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            src_id = DispHostDb(flow_info, pol, sess);
            if (src_id == -1) {
                query[0] = '\0';
                /* insert record */
                DnsDbSearch(&ip, FT_IPv4, query, XS_QUERY_DIM);
                src_id = DispHostDbIns(flow_info, query, pol, sess);
            }
            DispHostIns(&ip, FT_IPv4, src_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            src_id = DispHostSrch(&ip, FT_IPv6);
            if (src_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                src_id = DispHostDb(flow_info, pol, sess);
                if (src_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    DnsDbSearch(&ip, FT_IPv6, query, XS_QUERY_DIM);
                    src_id = DispHostDbIns(flow_info, query, pol, sess);
                }
                DispHostIns(&ip, FT_IPv6, src_id);
            }
        }
    }
    device = phone = NULL;
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_wa_device_id) {
            device = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_wa_phone_id) {
            phone = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }

    /* compose query and insert record */
    if (phone) {
        /* flow info */
        sprintf(flow_info, XS_SYSLOG_DIR_PATH"/flow_%p_%lu.xml", pol, sess, phone, time(NULL));
        DispFlowInfo(flow_info, ppei->stack);
        /* query */
        sprintf(query, XS_QUERY_WA_TEMPLATE, sess, pol, src_id, PEI_TIME(ppei->time_cap), flow_info,
                device, phone);
        if (DispQuery(query, NULL) != 0) {
            printf("query: %s\n", query);
        }
    }

    return 0;
}


/* DB static function */
static int DBInit(void)
{
    char *err;
    int res;

    err = NULL;
    res = sqlite3_open(XS_DB_FILE, &db);
    if (res != SQLITE_OK)
        return -1;
    
    sqlite3_exec(db, "PRAGMA synchronous = OFF", NULL, NULL, &err);
    sqlite3_exec(db, "PRAGMA journal_mode = MEMORY", NULL, NULL, &err);
    
    return 0;
}


static int DBClose(void)
{
    sqlite3_close(db);

    return 0;
}


int DispInit(const char *cfg_file)
{
    LogPrintf(LV_DEBUG, "Lite Dispatcher");

    pol_id = ProtId("pol");
    if (pol_id == -1) {
        printf("This dispacter run olny with pol dissector and capture\n");

        return -1;
    }
    pol_sesid_id = ProtAttrId(pol_id, "pol.sesid");
    pol_polid_id = ProtAttrId(pol_id, "pol.polid");
    pol_filename_id = ProtAttrId(pol_id, "pol.file");
    geo_id = 0;

    /* ip id */
    ip_id = ProtId("ip");
    if (ip_id != -1) {
        ip_dst_id = ProtAttrId(ip_id, "ip.dst");
        ip_src_id = ProtAttrId(ip_id, "ip.src");
    }
    ipv6_id = ProtId("ipv6");
    if (ipv6_id != -1) {
        ipv6_dst_id = ProtAttrId(ipv6_id, "ipv6.dst");
        ipv6_src_id = ProtAttrId(ipv6_id, "ipv6.src");
    }
    
    /* tcp id */
    tcp_id = ProtId("tcp");
    tcp_dstport_id = ProtAttrId(tcp_id, "tcp.dstport");

    /* udp id */
    udp_id = ProtId("udp");
    udp_dstport_id = ProtAttrId(udp_id, "udp.dstport");
    
    /* pei id */
    pop_id = ProtId("pop");
    if (pop_id != -1) {
        pei_pop_user_id = ProtPeiComptId(pop_id, "user");
        pei_pop_pswd_id = ProtPeiComptId(pop_id, "password");
        pei_pop_eml_id = ProtPeiComptId(pop_id, "eml");
    }

    smtp_id = ProtId("smtp");
    if (smtp_id != -1) {
        pei_smtp_to_id = ProtPeiComptId(smtp_id, "to");
        pei_smtp_from_id = ProtPeiComptId(smtp_id, "from");
        pei_smtp_eml_id = ProtPeiComptId(smtp_id, "eml");
    }

    imap_id = ProtId("imap");
    if (imap_id != -1) {
        pei_imap_user_id = ProtPeiComptId(imap_id, "user");
        pei_imap_pswd_id = ProtPeiComptId(imap_id, "password");
        pei_imap_eml_id = ProtPeiComptId(imap_id, "eml");
    }
    
    http_id = ProtId("http");
    if (http_id != -1) {
        pei_http_url_id = ProtPeiComptId(http_id, "url");
        pei_http_client_id = ProtPeiComptId(http_id, "client");
        pei_http_host_id = ProtPeiComptId(http_id, "host");
        pei_http_content_type_id = ProtPeiComptId(http_id, "content_type");
        pei_http_method_id = ProtPeiComptId(http_id, "method");
        pei_http_status_id = ProtPeiComptId(http_id, "status");
        pei_http_req_header_id = ProtPeiComptId(http_id, "req.header");
        pei_http_req_body_id = ProtPeiComptId(http_id, "req.body");
        pei_http_res_header_id = ProtPeiComptId(http_id, "res.header");
        pei_http_res_body_id = ProtPeiComptId(http_id, "res.body");
        pei_http_file_id = ProtPeiComptId(http_id, "boundary");
    }

    ftp_id = ProtId("ftp");
    if (ftp_id != -1) {
        pei_ftp_url_id = ProtPeiComptId(ftp_id, "url");
        pei_ftp_user_id = ProtPeiComptId(ftp_id, "user");
        pei_ftp_pswd_id = ProtPeiComptId(ftp_id, "password");
        pei_ftp_cmd_id = ProtPeiComptId(ftp_id, "cmd");
        pei_ftp_file_in_id = ProtPeiComptId(ftp_id, "file_in");
        pei_ftp_file_out_id = ProtPeiComptId(ftp_id, "file_out");
        pei_ftp_file_offset_id = ProtPeiComptId(ftp_id, "offset");
        pei_ftp_down_n_id = ProtPeiComptId(ftp_id, "down_n");
        pei_ftp_up_n_id = ProtPeiComptId(ftp_id, "up_n");
    }

    ipp_id = ProtId("ipp");
    if (ipp_id != -1) {
        pei_ipp_url_id = ProtPeiComptId(ipp_id, "url");
        pei_ipp_pdf_id = ProtPeiComptId(ipp_id, "pdf");
        pei_ipp_pcl_id = ProtPeiComptId(ipp_id, "pcl");
    }

    pjl_id = ProtId("pjl");
    if (pjl_id != -1) {
        pei_pjl_url_id = ProtPeiComptId(pjl_id, "url");
        pei_pjl_pdf_id = ProtPeiComptId(pjl_id, "pdf");
        pei_pjl_pcl_id = ProtPeiComptId(pjl_id, "pcl");
    }

    mms_id = ProtId("mms");
    if (mms_id != -1) {
        pei_mms_url_id = ProtPeiComptId(mms_id, "url");
        pei_mms_from_id = ProtPeiComptId(mms_id, "from");
        pei_mms_to_id = ProtPeiComptId(mms_id, "to");
        pei_mms_cc_id = ProtPeiComptId(mms_id, "cc");
        pei_mms_bcc_id = ProtPeiComptId(mms_id, "bcc");
        pei_mms_part_id = ProtPeiComptId(mms_id, "part");
        pei_mms_raw_id = ProtPeiComptId(mms_id, "raw");
    }

    tftp_id = ProtId("tftp");
    if (tftp_id != -1) {
        pei_tftp_url_id = ProtPeiComptId(tftp_id, "url");
        pei_tftp_cmd_id = ProtPeiComptId(tftp_id, "cmd");
        pei_tftp_file_in_id = ProtPeiComptId(tftp_id, "file_in");
        pei_tftp_file_out_id = ProtPeiComptId(tftp_id, "file_out");
        pei_tftp_down_n_id = ProtPeiComptId(tftp_id, "down_n");
        pei_tftp_up_n_id = ProtPeiComptId(tftp_id, "up_n");
    }
    
    dns_id = ProtId("dns");
    if (dns_id != -1) {
        pei_dns_host_id =  ProtPeiComptId(dns_id, "host");
        pei_dns_ip_id =  ProtPeiComptId(dns_id, "ip");
        pei_dns_cname_id =  ProtPeiComptId(dns_id, "cname");
        pei_dns_pkt_id = ProtPeiComptId(dns_id, "id");
    }

    nntp_id = ProtId("nntp");
    if (nntp_id != -1) {
        pei_nntp_url_id = ProtPeiComptId(nntp_id, "url");
        pei_nntp_grp_id = ProtPeiComptId(nntp_id, "grp");
        pei_nntp_article_id = ProtPeiComptId(nntp_id, "article");
        pei_nntp_header_id = ProtPeiComptId(nntp_id, "header");
        pei_nntp_body_id = ProtPeiComptId(nntp_id, "body");
        pei_nntp_post_id = ProtPeiComptId(nntp_id, "post");
    }
    
    fbwc_id = ProtId("fbwchat");
    if (fbwc_id != -1) {
        pei_fbwc_user_id = ProtPeiComptId(fbwc_id, "user");
        pei_fbwc_uid_id = ProtPeiComptId(fbwc_id, "uid");
        pei_fbwc_friend_id = ProtPeiComptId(fbwc_id, "friend");
        pei_fbwc_chat_id = ProtPeiComptId(fbwc_id, "chat");
        pei_fbwc_duration_id = ProtPeiComptId(fbwc_id, "duration");
    }

    telnet_id = ProtId("telnet");
    if (telnet_id != -1) {
        pei_telnet_host_id = ProtPeiComptId(telnet_id, "host");
        pei_telnet_user_id = ProtPeiComptId(telnet_id, "user");
        pei_telnet_password_id= ProtPeiComptId(telnet_id, "password");
        pei_telnet_cmd_id = ProtPeiComptId(telnet_id, "cmd");
    }

    webmail_id = ProtId("webmail");
    if (webmail_id != -1) {
        pei_webmail_serv_id = ProtPeiComptId(webmail_id, "serv");
        pei_webmail_dir_id = ProtPeiComptId(webmail_id, "dir");
        pei_webmail_to_id = ProtPeiComptId(webmail_id, "to");
        pei_webmail_from_id = ProtPeiComptId(webmail_id, "from");
        pei_webmail_cc_id = ProtPeiComptId(webmail_id, "cc");
        pei_webmail_sent_id = ProtPeiComptId(webmail_id, "sent");
        pei_webmail_rec_id = ProtPeiComptId(webmail_id, "rec");
        pei_webmail_messageid_id = ProtPeiComptId(webmail_id, "id");
        pei_webmail_subj_id = ProtPeiComptId(webmail_id, "subject");
        pei_webmail_eml_id = ProtPeiComptId(webmail_id, "eml");
        pei_webmail_html_id = ProtPeiComptId(webmail_id, "html");
        pei_webmail_txt_id = ProtPeiComptId(webmail_id, "txt");
    }

    httpfile_id = ProtId("httpfd");
    if (httpfile_id != -1) {
        pei_httpfile_url_id = ProtPeiComptId(httpfile_id, "url");
        pei_httpfile_file_id = ProtPeiComptId(httpfile_id, "file");
        pei_httpfile_content_type = ProtPeiComptId(httpfile_id, "content_type");
        pei_httpfile_parts_id = ProtPeiComptId(httpfile_id, "parts");
        pei_httpfile_complete_id = ProtPeiComptId(httpfile_id, "complete");
    }

    grb_tcp_id = ProtId("tcp-grb");
    if (grb_tcp_id != -1) {
        pei_grb_tcp_l7protocol_id = ProtPeiComptId(grb_tcp_id, "l7prot");
        pei_grb_tcp_txt_id = ProtPeiComptId(grb_tcp_id, "txt");
        pei_grb_tcp_size_id = ProtPeiComptId(grb_tcp_id, "size");
        pei_grb_tcp_file_id = ProtPeiComptId(grb_tcp_id, "file");
        pei_grb_tcp_file_type_id = ProtPeiComptId(grb_tcp_id, "ftype");
    }

    grb_udp_id = ProtId("udp-grb");
    if (grb_udp_id != -1) {
        pei_grb_udp_l7protocol_id = ProtPeiComptId(grb_udp_id, "l7prot");
        pei_grb_udp_txt_id = ProtPeiComptId(grb_udp_id, "txt");
        pei_grb_udp_size_id = ProtPeiComptId(grb_udp_id, "size");
    }

    rtp_id = ProtId("rtp");
    if (rtp_id != -1) {
        pei_rtp_from = ProtPeiComptId(rtp_id, "from");
        pei_rtp_to = ProtPeiComptId(rtp_id, "to");
        pei_rtp_audio_from = ProtPeiComptId(rtp_id, "audio_from");
        pei_rtp_audio_to = ProtPeiComptId(rtp_id, "audio_to");
        pei_rtp_audio_mix = ProtPeiComptId(rtp_id, "audio_mix");
        pei_rtp_duration = ProtPeiComptId(rtp_id, "duration");
    }

    sip_id = ProtId("sip");
    if (sip_id != -1) {
        pei_sip_from = ProtPeiComptId(sip_id, "from");
        pei_sip_to = ProtPeiComptId(sip_id, "to");
        pei_sip_cmd = ProtPeiComptId(sip_id, "cmd");
        pei_sip_audio_from = ProtPeiComptId(sip_id, "audio_from");
        pei_sip_audio_to = ProtPeiComptId(sip_id, "audio_to");
        pei_sip_audio_mix = ProtPeiComptId(sip_id, "audio_mix");
        pei_sip_duration = ProtPeiComptId(sip_id, "duration");
    }
    
    arp_id = ProtId("arp");
    if (arp_id != -1) {
        pei_arp_mac_id = ProtPeiComptId(arp_id, "mac");
        pei_arp_ip_id = ProtPeiComptId(arp_id, "ip");
    }
    
    irc_id = ProtId("irc");
    if (irc_id != -1) {
        pei_irc_url_id = ProtPeiComptId(irc_id, "url");
        pei_irc_server_id = ProtPeiComptId(irc_id, "cmd");
        pei_irc_channel_id = ProtPeiComptId(irc_id, "channel");
        pei_irc_channels_num_id = ProtPeiComptId(irc_id, "chnl_num");
        pei_irc_channel_users_id = ProtPeiComptId(irc_id, "cusers");
        pei_irc_channel_nick_id= ProtPeiComptId(irc_id, "cnick");
    }

    paltalk_exp_id = ProtId("paltalk_exp");
    if (paltalk_exp_id != -1) {
        pei_pltk_e_user_id = ProtPeiComptId(paltalk_exp_id, "user");
        pei_pltk_e_chat_id = ProtPeiComptId(paltalk_exp_id, "chat");
        pei_pltk_e_duration_id = ProtPeiComptId(paltalk_exp_id, "duration");
    
    }
    
    paltalk_id = ProtId("paltalk");
    if (paltalk_id != -1) {
        pei_pltk_room_id = ProtPeiComptId(paltalk_id, "room");
        pei_pltk_room_users_id = ProtPeiComptId(paltalk_id, "users");
        pei_pltk_room_nick_id= ProtPeiComptId(paltalk_id, "nick");
        pei_pltk_room_duration_id = ProtPeiComptId(paltalk_id, "duration");
    }
    
    msn_id = ProtId("msn");
    if (msn_id != -1) {
        pei_msn_from_id = ProtPeiComptId(msn_id, "from");
        pei_msn_to_id = ProtPeiComptId(msn_id, "to");
        pei_msn_chat_id = ProtPeiComptId(msn_id, "chat");
        pei_msn_duration_id = ProtPeiComptId(msn_id, "duration");

    }
    
    icmpv6_id = ProtId("icmpv6");
    if (arp_id != -1) {
        pei_icmpv6_mac_id = ProtPeiComptId(icmpv6_id, "mac");
        pei_icmpv6_ip_id = ProtPeiComptId(icmpv6_id, "ip");
    }

    mgcp_id = ProtId("mgcp");
    if (mgcp_id != -1) {
        pei_mgcp_from = ProtPeiComptId(mgcp_id, "from");
        pei_mgcp_to = ProtPeiComptId(mgcp_id, "to");
        pei_mgcp_cmd = ProtPeiComptId(mgcp_id, "cmd");
        pei_mgcp_audio_from = ProtPeiComptId(mgcp_id, "audio_from");
        pei_mgcp_audio_to = ProtPeiComptId(mgcp_id, "audio_to");
        pei_mgcp_audio_mix = ProtPeiComptId(mgcp_id, "audio_mix");
        pei_mgcp_duration = ProtPeiComptId(mgcp_id, "duration");
    }
    
    webymsg_id = ProtId("webymsg");
    if (webymsg_id != -1) {
        pei_webymsg_user_id = ProtPeiComptId(webymsg_id, "user");
        pei_webymsg_friend_id = ProtPeiComptId(webymsg_id, "friend");
        pei_webymsg_chat_id = ProtPeiComptId(webymsg_id, "chat");
        pei_webymsg_duration_id = ProtPeiComptId(webymsg_id, "duration");
    }
    
    syslog_id = ProtId("syslog");
    if (syslog_id != -1) {
        pei_syslog_host_id = ProtPeiComptId(syslog_id, "hosts");
        pei_syslog_log_id = ProtPeiComptId(syslog_id, "log");
    }
    
    wa_id = ProtId("wa");
    if (wa_id != -1) {
        pei_wa_device_id = ProtPeiComptId(wa_id, "dev");
        pei_wa_phone_id = ProtPeiComptId(wa_id, "phone");
    }

    /* db connection */
    if (DBInit()) {
        printf("DB connections error\n");

        return -1;
    }
    pthread_mutex_init(&geo_mux, NULL);
    pthread_mutex_init(&db_mux, NULL);
    pthread_mutex_init(&feed_mux, NULL);
    pthread_mutex_init(&nntp_mux, NULL);
    pthread_mutex_init(&host_mux, NULL);
    pthread_mutex_init(&fbchat_mux, NULL);
    
#if DISP_CLI_FILE_LIST
    pthread_mutex_init(&file_mux, NULL);
    pol_file = -1;
#endif
    host_num = 0;
    host_dim = 0;
    host = NULL;
    
    return 0;
}


int DispEnd()
{
    if (geo_id != 0) {
        GearthClose(geo_id);
    }
    LogPrintf(LV_DEBUG, "DispEnd");
    
    return DBClose();
}


int DispInsPei(pei *ppei)
{
    int ret;
    const pstack_f *frame;
    char kml_file[XS_STR_PATH];
    char kml_tmp[XS_STR_PATH];
    char kml_sem[XS_STR_PATH];
    char *name;
    int pol, sess;
    ftval val;

    if (ppei != NULL) {
		if (ppei->prot_id == http_id) {
            ret = DispHttp(ppei);
        }
        else if (ppei->prot_id == pop_id) {
            ret = DispPop(ppei);
        }
        else if (ppei->prot_id == smtp_id) {
            ret = DispSmtp(ppei);
        }
        else if (ppei->prot_id == imap_id) {
            ret = DispImap(ppei);
        }
        else if (ppei->prot_id == ftp_id) {
            ret = DispFtp(ppei);
        }
        else if (ppei->prot_id == ipp_id) {
            ret = DispIpp(ppei);
        }
        else if (ppei->prot_id == pjl_id) {
            ret = DispPjl(ppei);
        }
        else if (ppei->prot_id == mms_id) {
            ret = DispMms(ppei);
        }
        else if (ppei->prot_id == tftp_id) {
            ret = DispTftp(ppei);
        }
        else if (ppei->prot_id == dns_id) {
            ret = DispDns(ppei);
        }
        else if (ppei->prot_id == nntp_id) {
            ret = DispNntp(ppei);
        }
        else if (ppei->prot_id == fbwc_id) {
            ret = DispFbwc(ppei);
        }
        else if (ppei->prot_id == telnet_id) {
            ret = DispTelnet(ppei);
        }
        else if (ppei->prot_id == webmail_id) {
            ret = DispWebmail(ppei);
        }
        else if (ppei->prot_id == httpfile_id) {
            ret = DispHttpFile(ppei);
        }
        else if (ppei->prot_id == grb_tcp_id) {
            ret = DispGrbTcp(ppei);
        }
        else if (ppei->prot_id == grb_udp_id) {
            ret = DispGrbUdp(ppei);
        }
        else if (ppei->prot_id == rtp_id) {
            ret = DispRtp(ppei);
        }
        else if (ppei->prot_id == sip_id) {
            ret = DispSip(ppei);
        }
        else if (ppei->prot_id == arp_id) {
            ret = DispArp(ppei);
        }
        else if (ppei->prot_id == irc_id) {
            ret = DispIrc(ppei);
        }
        else if (ppei->prot_id == paltalk_exp_id) {
            ret = DispPaltalkExp(ppei);
        }
        else if (ppei->prot_id == paltalk_id) {
            ret = DispPaltalk(ppei);
        }
        else if (ppei->prot_id == msn_id) {
            ret = DispMsn(ppei);
        }
        else if (ppei->prot_id == icmpv6_id) {
            ret = DispIcmpv6(ppei);
        }
        else if (ppei->prot_id == mgcp_id) {
            ret = DispMgcp(ppei);
        }
        else if (ppei->prot_id == webymsg_id) {
            ret = DispWebYmsg(ppei);
        }
        else if (ppei->prot_id == syslog_id) {
            ret = DispSyslog(ppei);
        }
        else if (ppei->prot_id == wa_id){
            ret = DispWhatsApp(ppei);
        }
        else {
            PeiPrint(ppei);
        }
        if (geo_id == 0) {
            pthread_mutex_lock(&geo_mux);
            frame = ProtStackSearchProt(ppei->stack, pol_id);
            if (frame != NULL && geo_id == 0) {
                ProtGetAttr(frame, pol_polid_id, &val);
                pol = val.int32;
                ProtGetAttr(frame, pol_sesid_id, &val);
                sess = val.int32;
                ProtGetAttr(frame, pol_filename_id, &val);
                name = strrchr(val.str, '/');
                if (name != NULL) {
                    name++;
                }
                else {
                    name = val.str;
                }
                sprintf(kml_file, XS_GEA_DIR_PATH"/%s.kml", pol, sess, name);
                sprintf(kml_tmp, XS_GEA_TMPDIR_PATH"/%s.kml", pol, name);
                sprintf(kml_sem, XS_GEA_SEM, pol);
                FTFree(&val, FT_STRING);
                GearthNew(1, kml_file, kml_tmp, kml_sem);
                geo_id = 1;
            }
            GearthPei(geo_id, ppei);
            pthread_mutex_unlock(&geo_mux);
        }
        else {
            GearthPei(geo_id, ppei);
        }
    }
    
    return 0;
}

