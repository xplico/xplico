/* dema.h
 * monitoring tables
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __DEMA_H__
#define __DEMA_H__

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#define DM_FILENAME_PATH         2048
#define DM_FILTER_LINE           2048
#define DM_TBL_ADD               500
#define DM_HASH_STR              1024
#define DM_POL_NAME              "pol_"
#define DM_SESSION_NAME          "sol_"
#define DM_POL_DIR               "%s/pol_%i"
#define DM_TMP_DIR               "%s/pol_%i/tmp"
#define DM_CFG_DIR               "%s/pol_%i/cfg"
#define DM_LOG_DIR               "%s/pol_%i/log"
#define DM_NEW_DIR               "%s/pol_%i/sol_%i/new"
#define DM_RAW_DIR               "%s/pol_%i/sol_%i/raw"
#define DM_DECOD_DIR             "%s/pol_%i/sol_%i/decode"
#define DM_FAULT_DIR             "%s/pol_%i/sol_%i/fault"
#define DM_HISTORY_DIR           "%s/pol_%i/sol_%i/history"
#define DM_DEMA_RUN              "/var/run/dema.pid"
#define DM_RT_START_FILE         "realtime_start"
#define DM_RT_STOP_FILE          "realtime_stop"
#define DM_DELETE_CASE           "delete"
#define DM_DELETE_SESSION        "sol_rm"
#define DM_PCAPIP_FILE_PORT      "pcap_ip.port"
#define DM_LUCENE_CMD            "%s/script/session_mng.pyc -l %i %i"
#define POL_INIT_SESSION_FILE    "pol_sinit.cfg"
#define POL_END_SESSION_FILE     "pol_send.cfg"
#define DB_T_MYSQL               "mysql"
#define DB_T_SQLITE              "sqlite"
#define DB_T_POSTGRES            "postgresql"
/* cfg master files */
#define DM_XPLICO_LITE_CFG       "xplico_install_lite.cfg"
#define DM_XPLICO_MYSQL_CFG      "xplico_install_mysql.cfg"
#define DM_XPLICO_POSTGRES_CFG   "xplico_install_postgres.cfg"

/* default cert ssl */
#define DM_DEFAULT_XPLICO_CERT   "%s/cfg/xplico.pem"

/* dema config file */
#define DM_DEFAULT_CFG           "%s/cfg/dema.cfg"

/* BPF filter file location */
#define DM_BPF_FILE_FILTER       "%s/pol_%i/cfg/filter.bpf"

/* manipulartor cfg line for xplico */
#define DM_XPLICO_MANIP          "MANIP=%s   MPHOST=127.0.0.1  MPPORT=%s"


/* named semaphore */
#define XS_GEA_SEM               "/gea_pol_%i" /* lite.h ximysql.h */


/** boolean type */
typedef unsigned char bool;
#define TRUE     (0==0)
#define FALSE    (!TRUE)

/** default port */
#define DM_MANIP_DEF_PROT      23456
#define DM_MANIP_MAX             100
#define DM_PCAP_IP_DEF_PROT    30000
#define DM_PCAP_MAX               50

/** erase session timeout */
#define DM_ERASE_SESSION           2
#define DM_END_TO                600 /* 10 min */
#define DM_GROWTH_TO               2 /* sec */
#define DM_TIME_BETWEEN_PCAPS     30 /* sec, default value */


/** task pid list  */
typedef struct _task task;
struct _task {
    int tot;         /* total task in execution */
    pid_t xplico;    /* decoder */
    pid_t manip[DM_MANIP_MAX];  /* manipulators/aggregators */
};


/** pol->session & decoder  */
typedef struct _podec podec;
struct _podec {
    int pol_id;                  /* pol ID */
    int sol_id;                  /* sol ID */
    bool run;                    /* task running */
    task pid;                    /* task pid */
    bool end;                    /* closing task */
    int end_to;                  /* end timeout [s] */
    char name[DM_FILENAME_PATH]; /* file name */
    off_t size;                  /* size of last file */
    int filenum;                 /* file number */
    time_t growth;               /* file growth */
    bool rt;                     /* real time or not */
    int sd[2];                   /* sockets IPv4 and IPv6 */
};


int DemaSol(int pol);

#endif /* __DEMA_H__ */
