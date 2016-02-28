/* capostgres.c
 * Xplico System dispatcher for CapAnalysis
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2012-2013 Gianluca Costa. Web: www.xplico.org
 *
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <postgresql/libpq-fe.h>


#include "proto.h"
#include "log.h"
#include "pei.h"
#include "dmemory.h"
#include "capostgres.h"
#include "fileformat.h"
#include "config_param.h"
#include "dispatch.h"

#define FLOW_XML_FILE          0
#define DATA_DIR_REPO          0
#define DST_PORT_RANGE         2048
#define DST_PORT_RANGE_FIRST   1024

/* pol */
static int pol_id;
static int pol_polid_id;
static int pol_sesid_id;
static int pol_count_id;
static int pol_offset_id;

/* eth */
static int eth_id;
static int eth_mac_src_id;
/* ip v4 id */
static int ip_id;
static int ip_src_id;
static int ip_dst_id;
/* ip v6 id */
static int ipv6_id;
static int ipv6_src_id;
static int ipv6_dst_id;

static int dns_ca_id;
static int tcp_ca_id;
static int udp_ca_id;
static int ipsec_ca_id;

/* pei id */
static int pei_ip_src_id;
static int pei_ip_dst_id;
static int pei_dns_id;
static int pei_port_src_id;
static int pei_port_dst_id;
static int pei_l7protocol_id;
static int pei_lat_id;
static int pei_long_id;
static int pei_country_code_id;
static int pei_bsent_id;
static int pei_brecv_id;
static int pei_blost_sent_id;
static int pei_blost_recv_id;
static int pei_pkt_sent_id;
static int pei_pkt_recv_id;
static int pei_trace_sent;
static int pei_trace_recv;
static int pei_metadata;
static int pei_trace_img;

/* decode dir and db */
static char xdecode[CFG_LINE_MAX_SIZE];
static char sqlite_file[CFG_LINE_MAX_SIZE];

static dbconf db_c;                /* a copy of native configuration */
static PGconn *psql_i;             /* Postgres DB (inser) */
static PGconn *psql_s;             /* Postgres DB (select) */
static pthread_mutex_t db_mux;     /* mutex to access db */
static pthread_mutex_t db_ind;     /* id counter */
static unsigned int ds_id;
static unsigned int ip_index;
static volatile bool ds;
static unsigned int file_id;
static unsigned int group_q;
static bool libpqtf;
static bool group;
static bool ip_no_search;

/* host */
static char query_l[2*CAL_QUERY_DIM];  /* to be used inside db_mux mutex lock */
static volatile host_id * volatile host;
static volatile unsigned long host_num;
static volatile unsigned long host_dim;
static pthread_mutex_t host_mux;

/* statistcs */
static volatile unsigned long qins;
static volatile unsigned long qdbins;
static volatile unsigned long commit;
static volatile unsigned long commit_0pei;
static volatile unsigned long commit_id;
static volatile unsigned long qdbsearch;

#define CA_DEBUG                       1
static int DBInit(void);
static int DBClose(void);

static int DispQuery(char *query, unsigned long *id)
{
    int ret;
    short try = 1;
    PGresult *res;

    ret = -1;
    pthread_mutex_lock(&db_mux);
    if (!group) {
        if (id == NULL) {
            group = TRUE;
            group_q = CAL_GROUP_INSERT;
            res = PQexec(psql_i, "BEGIN;");
            PQclear(res);
        }
    }
    else if (id != NULL) {
        group = FALSE;
        res = PQexec(psql_i, "COMMIT;");
        if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
            LogPrintf(LV_ERROR, "Query: %s", PQresultErrorMessage(res));
        }
        PQclear(res);
        commit_id++;
    }

    do {
        res = PQexec(psql_i, query);
        if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
            group = FALSE;
            LogPrintf(LV_ERROR, "Query: %s", PQresultErrorMessage(res));
            LogPrintf(LV_ERROR, "Query: %s", query);
            PQclear(res);
            DBClose();
            DBInit();
        }
        else {
            ret = 0;
            break;
        }
    } while(try--);
    if (ret == 0 && id != NULL) {
        *id = atol(PQgetvalue(res, 0, 0));
    }
    if (ret == 0) {
        PQclear(res); 
    }
    if (group) {
        group_q--;
        if (group_q == 0) {
            group = FALSE;
            res = PQexec(psql_i, "COMMIT;");
            if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
                LogPrintf(LV_ERROR, "Query: %s", PQresultErrorMessage(res));
            }
            PQclear(res);
            commit++;
        }
    }

    pthread_mutex_unlock(&db_mux);
    
    return ret;
}


static int DispHostExt(void)
{
    char *new;

    /* the mutex is in already locked */
    new = xrealloc((void *)host, sizeof(host_id)*(host_dim + CAL_HOST_ID_ADD));
    if (new == NULL)
        return -1;
    memset(new+sizeof(host_id)*(host_dim), 0, sizeof(host_id)*CAL_HOST_ID_ADD);
    
    host = (host_id *)new;
    host_dim += CAL_HOST_ID_ADD;
    
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
    if (db_id != -1) {
        host[host_num].id = db_id;
        FTCopy((void *)&(host[host_num].ip), ip, type);
        host[host_num].type = type;
        host_num++;
    }
    
    pthread_mutex_unlock(&host_mux);

    return 0;
}


static int DispHostDbLastId(int ds)
{
    int id;
    short try = 1;
    PGresult *res;
    
    id = -1;
    pthread_mutex_lock(&db_mux);
    sprintf(query_l, CAL_QUERY_IP_LAST_ID, ds);
    qdbsearch++;
    do {
        res = PQexec(psql_s, query_l);
        if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
            group = FALSE;
            LogPrintf(LV_ERROR, "Query: %s", PQresultErrorMessage(res));
            LogPrintf(LV_ERROR, "Query: %s", query_l);
            PQclear(res);
            DBClose();
            DBInit();
        }
        else {
            id = 0;
            break;
        }
    } while(try--);
    if (id == 0) {
        if (PQntuples(res)) {
            id = atol(PQgetvalue(res, 0, 0));
        }
        else {
            id = -1;
        }
        PQclear(res); 
    }
    pthread_mutex_unlock(&db_mux);

    return id;
}


static int DispHostDb(const char *ip, int ds)
{
    int id;
    short try = 1;
    PGresult *res;
    
    if (ip_no_search)
        return -1;
    
    id = -1;
    pthread_mutex_lock(&db_mux);
    sprintf(query_l, CAL_QUERY_IP_SEARCH, ds, ip);
    qdbsearch++;
    do {
        res = PQexec(psql_s, query_l);
        if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
            group = FALSE;
            LogPrintf(LV_ERROR, "Query: %s", PQresultErrorMessage(res));
            LogPrintf(LV_ERROR, "Query: %s", query_l);
            PQclear(res);
            DBClose();
            DBInit();
        }
        else {
            id = 0;
            break;
        }
    } while(try--);
    if (id == 0) {
        if (PQntuples(res)) {
            id = atol(PQgetvalue(res, 0, 0));
        }
        else {
            id = -1;
        }
        PQclear(res); 
    }
    pthread_mutex_unlock(&db_mux);

    return id;
}


static int DispHostDbIns(const char *ip, char *name, int ds)
{
    int ret;
    char query[CAL_QUERY_DIM];

    ret = -1;
    pthread_mutex_lock(&db_ind);
    sprintf(query, CAL_QUERY_IP_TEMPLATE, ds, ip_index, ds, ip);
    if (DispQuery(query, NULL) != 0) {
        printf("query: %s\n", query);
    }
    else {
        ret = ip_index;
        ip_index++;
    }
    qdbins++;
    pthread_mutex_unlock(&db_ind);

    return ret;
}


/* DB static function */
static int DBInit(void)
{
    char con_param[CAL_QUERY_DIM];
    
    /* postgresql */
    sprintf(con_param, "host = '%s' dbname = '%s' user = '%s' password = '%s' connect_timeout = '900'", db_c.host, db_c.name, db_c.user, db_c.password);

    /* insert connection */
    psql_i = PQconnectdb(con_param);
    if (!psql_i) {
        return -1;
    }
    if (PQstatus(psql_i) != CONNECTION_OK) {
        printf("%s\n", PQerrorMessage(psql_i));
        return -1;
    }

    /* select connection */
    psql_s = PQconnectdb(con_param);
    if (!psql_s) {
        DBClose();
        return -1;
    }
    if (PQstatus(psql_s) != CONNECTION_OK) {
        printf("%s\n", PQerrorMessage(psql_s));
        DBClose();
        return -1;
    }
    
    return 0;
}


static int DBClose(void)
{
    if (psql_i != NULL)
        PQfinish(psql_i);
        
    if (psql_s != NULL)
        PQfinish(psql_s);
    
    return 0;
}

#if FLOW_XML_FILE
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
#endif

static int DispCa(pei *ppei, char *l4)
{
#if FLOW_XML_FILE
    static unsigned long inc = 0;
#endif
    pei_component *cmpn;
    char query[CAL_QUERY_DIM];
    char flow_info[CAL_STR_DIM];
    char new_path[CAL_STR_DIM];
    char encaps[CAL_STR_DIM];
    char mac_src[CAL_STR_DIM];
    char mac_dst[CAL_STR_DIM];
    unsigned long pkt_count;
    struct tm thm;
    int min5, week, days, seconds;
    char *name, *metadata;
    ftval val, ip;
    const pstack_f *frame;
    time_t time_cap_end, dur;
    unsigned int lfile_id;
    char *ip_src, *ip_dst, *dns, *port_src,
        *port_dst, *l7protocol, *lat, *longi, *country_code,
        *bsent, *brecv, *blost_sent, *blost_recv, *pkt_sent,
        *pkt_recv, *trace_sent, *trace_recv, *trace_img1, *trace_img2, *trace_img_name;
    long dst_port_n;
    size_t pkt_offset;
    unsigned long ips_id, ipd_id;
    int daynumber, day, x;

    bsent = brecv = blost_sent = blost_recv = pkt_sent = pkt_recv = "0";
    dns = trace_sent = trace_recv = trace_img_name = "";
    trace_img1 = trace_img2 = NULL;
    country_code = "---";
    encaps[0] = mac_src[0] = mac_dst[0] = flow_info[0] = '\0';
    pkt_count = pkt_offset = 0;
    dst_port_n = 0;
    ips_id = ipd_id = 0;
    metadata = "";
    
    /* search pol and session */
    frame = ProtStackSearchProt(ppei->stack, pol_id);
    if (frame) {
        if (ds) {
            pthread_mutex_lock(&db_ind);
            if (ds) {
                ProtGetAttr(frame, pol_polid_id, &val);
                ds_id = val.uint32;
                ip_index = DispHostDbLastId(ds_id);
                if (ip_index == -1) {
                    ip_index = 1;
                    ip_no_search = TRUE;
                }
                else {
                    ip_index++;
                }
                ds = FALSE;
            }
            pthread_mutex_unlock(&db_ind);
        }
        
        ProtGetAttr(frame, pol_sesid_id, &val);
        lfile_id = val.uint32;
        if (file_id != lfile_id) {
            file_id = lfile_id;
#if DATA_DIR_REPO
            /* directory for files repository */
            sprintf(new_path, DIR_DATA"/%i", xdecode, lfile_id);
            mkdir(new_path, 0x01FF);
#endif
        }
    }
    /* encaps and mac address */
    frame = ppei->stack;
    while (frame != NULL && ProtFrameProtocol(frame) != pol_id) {
        if (ProtFrameProtocol(frame) == eth_id) {
            ProtGetAttr(frame, eth_mac_src_id, &val);
            FTString(&val, FT_ETHER, mac_src);
        }
        strcat(encaps, ProtGetName(ProtFrameProtocol(frame)));
        strcat(encaps, " ");
        frame = ProtGetNxtFrame(frame);
    }
    if (frame != NULL) {
        ProtGetAttr(frame, pol_count_id, &val);
        pkt_count = val.uint32;
        ProtGetAttr(frame, pol_offset_id, &val);
        pkt_offset = val.size;
    }
    /* search source and destination ip */
    ips_id = ipd_id = -1;
    frame = ProtStackSearchProt(ppei->stack, ip_id);
    if (frame) {
        ProtGetAttr(frame, ip_src_id, &ip);
        ips_id = DispHostSrch(&ip, FT_IPv4);
        if (ips_id == -1) {
            /* search in the db */
            FTString(&ip, FT_IPv4, flow_info);
            ips_id = DispHostDb(flow_info, ds_id);
            if (ips_id == -1) {
                query[0] = '\0';
                /* insert record */
                //DnsDbSearch(&ip, FT_IPv4, query, CAL_QUERY_DIM);
                ips_id = DispHostDbIns(flow_info, "", ds_id);
            }
            DispHostIns(&ip, FT_IPv4, ips_id);
        }
        ProtGetAttr(frame, ip_dst_id, &ip);
        ipd_id = DispHostSrch(&ip, FT_IPv4);
        if (ipd_id == -1) {
            /* search in db */
            FTString(&ip, FT_IPv4, flow_info);
            ipd_id = DispHostDb(flow_info, ds_id);
            if (ipd_id == -1) {
                query[0] = '\0';
                /* insert record */
                //DnsDbSearch(&ip, FT_IPv4, query, CAL_QUERY_DIM);
                ipd_id = DispHostDbIns(flow_info, "", ds_id);
            }
            DispHostIns(&ip, FT_IPv4, ipd_id);
        }
    }
    else if (ipv6_id != -1) {
        frame = ProtStackSearchProt(ppei->stack, ipv6_id);
        if (frame) {
            ProtGetAttr(frame, ipv6_src_id, &ip);
            ips_id = DispHostSrch(&ip, FT_IPv6);
            if (ips_id == -1) {
                /* search in the db */
                FTString(&ip, FT_IPv6, flow_info);
                ips_id = DispHostDb(flow_info, ds_id);
                if (ips_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    //DnsDbSearch(&ip, FT_IPv6, query, CAL_QUERY_DIM);
                    ips_id = DispHostDbIns(flow_info, "", ds_id);
                }
                DispHostIns(&ip, FT_IPv6, ips_id);
            }
            ProtGetAttr(frame, ipv6_dst_id, &ip);
            ipd_id = DispHostSrch(&ip, FT_IPv6);
            if (ipd_id == -1) {
                /* search in db */
                FTString(&ip, FT_IPv6, flow_info);
                ipd_id = DispHostDb(flow_info, ds_id);
                if (ipd_id == -1) {
                    query[0] = '\0';
                    /* insert record */
                    //DnsDbSearch(&ip, FT_IPv6, query, CAL_QUERY_DIM);
                    ipd_id = DispHostDbIns(flow_info, "", ds_id);
                }
                DispHostIns(&ip, FT_IPv6, ipd_id);
            }
        }
    }
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_ip_src_id) {
            ip_src = cmpn->strbuf;
            time_cap_end = cmpn->time_cap_end;
        }
        else if (cmpn->eid == pei_ip_dst_id) {
            ip_dst = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_dns_id) {
            dns = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_port_src_id) {
            port_src = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_port_dst_id) {
            port_dst = cmpn->strbuf;
            dst_port_n = atol(port_dst);
            if (dst_port_n < DST_PORT_RANGE_FIRST) {
                dst_port_n = DST_PORT_RANGE_FIRST;
            }
            else {
                dst_port_n -= DST_PORT_RANGE_FIRST;
                dst_port_n = dst_port_n/DST_PORT_RANGE;
                dst_port_n = (dst_port_n+1)*DST_PORT_RANGE + DST_PORT_RANGE_FIRST;
            }
        }
        else if (cmpn->eid == pei_l7protocol_id) {
            l7protocol = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_lat_id) {
            lat = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_long_id) {
            longi = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_country_code_id) {
            country_code = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_bsent_id) {
            bsent = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_brecv_id) {
            brecv = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_blost_sent_id) {
            blost_sent = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_blost_recv_id) {
            blost_recv = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pkt_sent_id) {
            pkt_sent = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_pkt_recv_id) {
            pkt_recv = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_trace_sent) {
            trace_sent = cmpn->file_path;
        }
        else if (cmpn->eid == pei_trace_recv) {
            trace_recv = cmpn->file_path;
        }
        else if (cmpn->eid == pei_metadata) {
            metadata = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_trace_img) {
            if (trace_img1 == NULL) {
                trace_img_name = cmpn->name;
                trace_img1 = cmpn->file_path;
            }
            else
                trace_img2 = cmpn->file_path;
        }
        cmpn = cmpn->next;
    }


#if DATA_DIR_REPO
# if FLOW_XML_FILE
    /* flow info */
    sprintf(flow_info, DIR_DATA"/%i/flow_%p_%lu.xml", xdecode, lfile_id, ppei, inc++);
    DispFlowInfo(flow_info, ppei->stack);
# endif

    /* images */
    if (trace_img1) {
        /* new path */
        name = strrchr(trace_img1, '/');
        name++;
        sprintf(new_path, DIR_DATA"/%i/%s", xdecode, lfile_id, name);
        rename(trace_img1, new_path);
    }
    if (trace_img2) {
        /* new path */
        name = strrchr(trace_img2, '/');
        name++;
        sprintf(new_path, DIR_DATA"/%i/%s", xdecode, lfile_id, name);
        rename(trace_img2, new_path);
    }
#endif

    dur = (time_cap_end-ppei->time_cap);
#if CA_DEBUG
    if ((time_cap_end-ppei->time_cap) > (3600*3) || ppei->time_cap > time_cap_end) {
        LogPrintf(LV_WARNING, "Possible time anomaly");
        ProtStackFrmDisp(ppei->stack, TRUE);
    }
#endif
    if (ppei->time_cap > time_cap_end)
        dur = 0;
    localtime_r(&(ppei->time_cap), &thm);
    min5 = thm.tm_min % 5;
    min5 = thm.tm_min - min5;
    daynumber = thm.tm_yday + 1;
    day = thm.tm_wday;
    if (day == 0)
        day = 7;
    x = daynumber - day;
    week = x/7+1;
    if (x < 0)
        week = 1;
    if (x%7 < 0)
        x += 7;
    if (x%7 > 3)
        week++;
    days = ppei->time_cap/86400; /* (3600*24) */
    seconds = ppei->time_cap%86400;

    /* inter item */
    sprintf(query, CAL_QUERY_ITEM_TEMPLATE, ds_id, ds_id, lfile_id, ppei->time_cap, ppei->time_cap,
            thm.tm_year+1900, thm.tm_mon+1, week, thm.tm_hour, min5, days, seconds, flow_info, metadata, ip_src, ip_dst, ips_id, ipd_id, dns,
            port_src, port_dst, dst_port_n, l4, l7protocol, lat, longi, country_code, bsent, brecv, blost_sent, blost_recv, 
            pkt_sent, pkt_recv, trace_sent, trace_recv, trace_img_name, dur, pkt_count, pkt_offset, mac_src, mac_dst, encaps);
    if (DispQuery(query, NULL) != 0) {
        printf("query: %s\n", query);
    }
    qins++; /* it is not atomic! */
    
    return 0;
}


int DispInit(const char *cfg_file)
{
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    FILE *fp;
    int res, i;
    bool ok;
    
    LogPrintf(LV_DEBUG, "CapAnalysis Dispatcher");
    
    memset(&db_c, 0, sizeof(dbconf));
    ok = FALSE;
    xdecode[0] = '\0';
    sqlite_file[0] = '\0';
    ds = TRUE;
    file_id = 0;
    if (PQisthreadsafe())
        libpqtf = TRUE;
    else
        libpqtf = FALSE;
    group = FALSE;
    group_q = CAL_GROUP_INSERT;
    ip_no_search = FALSE;

    /* read configuration file */
    fp = fopen(cfg_file, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    res = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_XDECODE);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_XDECODE"=%s %s", xdecode, bufcpy);
            }
            param = strstr(buffer, CFG_PAR_DB_HOST);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DB_HOST"=%s %s", db_c.host, bufcpy);
            }
            param = strstr(buffer, CFG_PAR_DB_NAME);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DB_NAME"=%s %s", db_c.name, bufcpy);
            }
            param = strstr(buffer, CFG_PAR_DB_USER);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DB_USER"=%s %s", db_c.user, bufcpy);
            }
            param = strstr(buffer, CFG_PAR_DB_PASSWORD);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DB_PASSWORD"=%s %s", db_c.password, bufcpy);
            }
        }
    }
    fclose(fp);
#if 1
    if (xdecode[0] == '\0' ||
        db_c.name[0] == '\0' ||
        db_c.user[0] == '\0' ||
        db_c.password[0] == '\0' ||
        db_c.host[0] == '\0') {
        LogPrintf(LV_ERROR, "Config file has not the output dir or the DB params.");
        return -1;
    }
    else {
        i = 0;
        while (xdecode[i] != '\0' && xdecode[i] != ' ')
            i++;
        xdecode[i] = '\0';
    }
    pol_id = ProtId("pol");
    if (pol_id == -1) {
        printf("This dispacter run olny with pol dissector and capture\n");

        return -1;
    }
#endif
    pol_sesid_id = ProtAttrId(pol_id, "pol.sesid");
    pol_polid_id = ProtAttrId(pol_id, "pol.polid");
    pol_count_id = ProtAttrId(pol_id, "pol.count");
    pol_offset_id = ProtAttrId(pol_id, "pol.offset");
    
    eth_id = ProtId("eth");
    if (eth_id != -1) {
        eth_mac_src_id = ProtAttrId(eth_id, "eth.src");
    }

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

    /* pei id */
    dns_ca_id = ProtId("dns");
    tcp_ca_id = ProtId("tcp-ca");
    udp_ca_id = ProtId("udp-ca");
    if (tcp_ca_id != -1) {
        pei_ip_src_id = ProtPeiComptId(tcp_ca_id, "ip.src");
        pei_ip_dst_id = ProtPeiComptId(tcp_ca_id, "ip.dst");
        pei_dns_id = ProtPeiComptId(tcp_ca_id, "dns");
        pei_port_src_id = ProtPeiComptId(tcp_ca_id, "port.src");
        pei_port_dst_id = ProtPeiComptId(tcp_ca_id, "port.dst");
        pei_l7protocol_id = ProtPeiComptId(tcp_ca_id, "l7prot");
        pei_lat_id = ProtPeiComptId(tcp_ca_id, "lat");
        pei_long_id = ProtPeiComptId(tcp_ca_id, "long");
        pei_country_code_id = ProtPeiComptId(tcp_ca_id, "country_code");
        pei_bsent_id = ProtPeiComptId(tcp_ca_id, "byte.sent");
        pei_brecv_id = ProtPeiComptId(tcp_ca_id, "byte.receiv");
        pei_blost_sent_id = ProtPeiComptId(tcp_ca_id, "byte.lost.sent");
        pei_blost_recv_id = ProtPeiComptId(tcp_ca_id, "byte.lost.receiv");
        pei_pkt_sent_id = ProtPeiComptId(tcp_ca_id, "pkt.sent");
        pei_pkt_recv_id = ProtPeiComptId(tcp_ca_id, "pkt.receiv");
        pei_trace_sent = ProtPeiComptId(tcp_ca_id, "trace.sent");
        pei_trace_recv = ProtPeiComptId(tcp_ca_id, "trace.receiv");
        pei_metadata = ProtPeiComptId(tcp_ca_id, "metadata");
        pei_trace_img = ProtPeiComptId(tcp_ca_id, "trace.img");

        ok = TRUE;
    }
    if (dns_ca_id != -1) {
        if (pei_ip_src_id != ProtPeiComptId(dns_ca_id, "ip.src")) { ok = FALSE;}
        if (pei_ip_dst_id != ProtPeiComptId(dns_ca_id, "ip.dst")) { ok = FALSE;}
        if (pei_dns_id != ProtPeiComptId(dns_ca_id, "dns")) { ok = FALSE;}
        if (pei_port_src_id != ProtPeiComptId(dns_ca_id, "port.src")) { ok = FALSE;}
        if (pei_port_dst_id != ProtPeiComptId(dns_ca_id, "port.dst")) { ok = FALSE;}
        if (pei_l7protocol_id != ProtPeiComptId(dns_ca_id, "l7prot")) { ok = FALSE;}
        if (pei_lat_id != ProtPeiComptId(dns_ca_id, "lat")) { ok = FALSE;}
        if (pei_long_id != ProtPeiComptId(dns_ca_id, "long")) { ok = FALSE;}
        if (pei_country_code_id != ProtPeiComptId(dns_ca_id, "country_code")) { ok = FALSE;}
        if (pei_bsent_id != ProtPeiComptId(dns_ca_id, "byte.sent")) { ok = FALSE;}
        if (pei_brecv_id != ProtPeiComptId(dns_ca_id, "byte.receiv")) { ok = FALSE;}
        if (pei_blost_sent_id != ProtPeiComptId(dns_ca_id, "byte.lost.sent")) { ok = FALSE;}
        if (pei_blost_recv_id != ProtPeiComptId(dns_ca_id, "byte.lost.receiv")) { ok = FALSE;}
        if (pei_pkt_sent_id != ProtPeiComptId(dns_ca_id, "pkt.sent")) { ok = FALSE;}
        if (pei_pkt_recv_id != ProtPeiComptId(dns_ca_id, "pkt.receiv")) { ok = FALSE;}
        if (pei_trace_sent != ProtPeiComptId(dns_ca_id, "trace.sent")) { ok = FALSE;}
        if (pei_trace_recv != ProtPeiComptId(dns_ca_id, "trace.receiv")) { ok = FALSE;}
    }
    
    if (udp_ca_id != -1) {
        if (pei_ip_src_id != ProtPeiComptId(udp_ca_id, "ip.src")) { ok = FALSE;}
        if (pei_ip_dst_id != ProtPeiComptId(udp_ca_id, "ip.dst")) { ok = FALSE;}
        if (pei_dns_id != ProtPeiComptId(udp_ca_id, "dns")) { ok = FALSE;}
        if (pei_port_src_id != ProtPeiComptId(udp_ca_id, "port.src")) { ok = FALSE;}
        if (pei_port_dst_id != ProtPeiComptId(udp_ca_id, "port.dst")) { ok = FALSE;}
        if (pei_l7protocol_id != ProtPeiComptId(udp_ca_id, "l7prot")) { ok = FALSE;}
        if (pei_lat_id != ProtPeiComptId(udp_ca_id, "lat")) { ok = FALSE;}
        if (pei_long_id != ProtPeiComptId(udp_ca_id, "long")) { ok = FALSE;}
        if (pei_country_code_id != ProtPeiComptId(udp_ca_id, "country_code")) { ok = FALSE;}
        if (pei_bsent_id != ProtPeiComptId(udp_ca_id, "byte.sent")) { ok = FALSE;}
        if (pei_brecv_id != ProtPeiComptId(udp_ca_id, "byte.receiv")) { ok = FALSE;}
        if (pei_blost_sent_id != ProtPeiComptId(udp_ca_id, "byte.lost.sent")) { ok = FALSE;}
        if (pei_blost_recv_id != ProtPeiComptId(udp_ca_id, "byte.lost.receiv")) { ok = FALSE;}
        if (pei_pkt_sent_id != ProtPeiComptId(udp_ca_id, "pkt.sent")) { ok = FALSE;}
        if (pei_pkt_recv_id != ProtPeiComptId(udp_ca_id, "pkt.receiv")) { ok = FALSE;}
        if (pei_trace_sent != ProtPeiComptId(udp_ca_id, "trace.sent")) { ok = FALSE;}
        if (pei_trace_recv != ProtPeiComptId(udp_ca_id, "trace.receiv")) { ok = FALSE;}
        if (pei_metadata != ProtPeiComptId(udp_ca_id, "metadata")) { ok = FALSE;}
        if (pei_trace_img != ProtPeiComptId(udp_ca_id, "trace.img")) { ok = FALSE;}
    }
    ipsec_ca_id = ProtId("esp-ca");
    if (ipsec_ca_id != -1) {
        if (pei_ip_src_id != ProtPeiComptId(ipsec_ca_id, "ip.src")) { ok = FALSE;}
        if (pei_ip_dst_id != ProtPeiComptId(ipsec_ca_id, "ip.dst")) { ok = FALSE;}
        if (pei_dns_id != ProtPeiComptId(ipsec_ca_id, "dns")) { ok = FALSE;}
        if (pei_port_src_id != ProtPeiComptId(ipsec_ca_id, "port.src")) { ok = FALSE;}
        if (pei_port_dst_id != ProtPeiComptId(ipsec_ca_id, "port.dst")) { ok = FALSE;}
        if (pei_l7protocol_id != ProtPeiComptId(ipsec_ca_id, "l7prot")) { ok = FALSE;}
        if (pei_lat_id != ProtPeiComptId(ipsec_ca_id, "lat")) { ok = FALSE;}
        if (pei_long_id != ProtPeiComptId(ipsec_ca_id, "long")) { ok = FALSE;}
        if (pei_country_code_id != ProtPeiComptId(ipsec_ca_id, "country_code")) { ok = FALSE;}
        if (pei_bsent_id != ProtPeiComptId(ipsec_ca_id, "byte.sent")) { ok = FALSE;}
        if (pei_brecv_id != ProtPeiComptId(ipsec_ca_id, "byte.receiv")) { ok = FALSE;}
        if (pei_blost_sent_id != ProtPeiComptId(ipsec_ca_id, "byte.lost.sent")) { ok = FALSE;}
        if (pei_blost_recv_id != ProtPeiComptId(ipsec_ca_id, "byte.lost.receiv")) { ok = FALSE;}
        if (pei_pkt_sent_id != ProtPeiComptId(ipsec_ca_id, "pkt.sent")) { ok = FALSE;}
        if (pei_pkt_recv_id != ProtPeiComptId(ipsec_ca_id, "pkt.receiv")) { ok = FALSE;}
        if (pei_trace_sent != ProtPeiComptId(ipsec_ca_id, "trace.sent")) { ok = FALSE;}
        if (pei_trace_recv != ProtPeiComptId(ipsec_ca_id, "trace.receiv")) { ok = FALSE;}
        if (pei_metadata != ProtPeiComptId(ipsec_ca_id, "metadata")) { ok = FALSE;}
        if (pei_trace_img != ProtPeiComptId(ipsec_ca_id, "trace.img")) { ok = FALSE;}
    }
    if (ok == FALSE) {
        LogPrintf(LV_ERROR, "PEI definition error!");
        return -1;
    }

    /* db connection */
    if (DBInit()) {
        printf("DB connections error\n");

        return -1;
    }
    pthread_mutex_init(&db_mux, NULL);
    pthread_mutex_init(&db_ind, NULL);
    
    /* directory used as repository */
    mkdir(xdecode, 0x01FF);
    sprintf(buffer, DIR_DATA, xdecode);
    mkdir(buffer, 0x01FF);
    sprintf(buffer, DIR_HISTORY, xdecode);
    mkdir(buffer, 0x01FF);

    pthread_mutex_init(&host_mux, NULL);
    host_num = 0;
    host_dim = 0;
    host = NULL;
    
    /* statistics */
    qins = qdbins = qdbsearch = 0;
    commit = 0;
    commit_0pei = 0;
    commit_id = 0;

    return 0;
}


int DispEnd()
{
    PGresult *res;
    unsigned long tot, avg;
    
    if (group) {
        group = FALSE;
        res = PQexec(psql_i, "COMMIT;");
        PQclear(res);
        commit++;
    }
    DBClose();
    tot = commit + commit_0pei + commit_id;
    avg = 0;
    if (tot > 0) {
        avg = qins/tot;
    }
    printf("Query: %lu, Commit: %lu[%lu - %lu - %lu], Average: %lu, IP query: %lu, IP search: %lu\n", qins, tot, commit, commit_0pei, commit_id, avg, qdbins, qdbsearch);
    
    return 0;
}


int DispInsPei(pei *ppei)
{
    int ret;
    PGresult *res;
    
    if (ppei != NULL) {
        /* pei */
        //PeiPrint(ppei);
        if (ppei->prot_id == udp_ca_id || ppei->prot_id == dns_ca_id)
            ret = DispCa(ppei, "UDP");
        else if (ppei->prot_id == tcp_ca_id)
            ret = DispCa(ppei, "TCP");
        else
            ret = DispCa(ppei, "ESP");
    }
    if (DispatchPeiPending() == 1) {
        pthread_mutex_lock(&db_mux);
        if (group) {
            group = FALSE;
            res = PQexec(psql_i, "COMMIT;");
            PQclear(res);
            commit_0pei++;
        }
        pthread_mutex_unlock(&db_mux);
    }
    return 0;
}

