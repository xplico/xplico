/* dbinterface.h
 *
 * $Id: dbinterface.h,v 1.1 2007/09/08 07:11:52 costa Exp $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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


#ifndef __DBINTERFACE_H__
#define __DBINTERFACE_H__

#include "captime.h"
#include "config.h"


#define DBCFG_BUFF_SIZE      512

#ifndef XP_CAPTURE_UTC
# error "Define in config.h the type of capture time!"
#endif
#if XP_CAPTURE_UTC
# define XPCAP_DATE          "DATETIME(%lu, 'unixepoch')"
#else
# define XPCAP_DATE          "DATETIME(%lu, 'unixepoch', 'localtime')"
#endif

/* common */
#define DBINT_QUERY_DIM           10240
#define DBINT_QUERY_WAITING_DEC   "UPDATE sols SET status='START DECODING' WHERE id='%d';"
#define DBINT_QUERY_START_DEC     "UPDATE sols SET status='DECODING' WHERE id='%d';"
#define DBINT_QUERY_END_DEC       "UPDATE sols SET status='DECODING COMPLETED' WHERE id='%d';"
#define DBINT_QUERY_DELETE_POL    "DELETE FROM pols WHERE id='%d';"
#define DBINT_QUERY_DELETE_SOL    "DELETE FROM sols WHERE id='%d';"
#define DBINT_QUERY_DELETE_RM_SOL "DELETE FROM sols WHERE rm='1' AND pol_id='%d';"

/* mysql */
#define DBINT_1_QUERY_START_T_TEMPLATE  "UPDATE sols SET start_time=FROM_UNIXTIME(%lu) WHERE id='%d' AND start_time='1990-01-01 00:00:00';"
#define DBINT_1_QUERY_END_T_TEMPLATE    "UPDATE sols SET end_time=FROM_UNIXTIME(%lu) WHERE id='%d';"
#define DBINT_1_QUERY_INPUT_FILE        "INSERT INTO inputs (pol_id, sol_id, start_time, end_time, data_size, filename, md5, sha1) VALUES (%i, %i, FROM_UNIXTIME(%lu), FROM_UNIXTIME(%lu), %lu, '%s', '%s', '%s');"
#define DBINT_1_QUERY_FIX_STATUS        "UPDATE sols SET status='DECODING COMPLETED'"

/* sqlite 3 */
#define DBINT_DB_FILE_DEFAULT           "xplico.db" /* DB file */
#define DBINT_2_QUERY_START_T_TEMPLATE  "UPDATE sols SET start_time="XPCAP_DATE" WHERE id='%d' AND start_time='1990-01-01 00:00:00';"
#define DBINT_2_QUERY_END_T_TEMPLATE    "UPDATE sols SET end_time="XPCAP_DATE" WHERE id='%d';"
#define DBINT_2_QUERY_INPUT_FILE        "INSERT INTO inputs (pol_id, sol_id, start_time, end_time, data_size, filename, md5, sha1) VALUES (%i, %i, "XPCAP_DATE", "XPCAP_DATE", %lu, '%s', '%s', '%s');"
#define DBINT_2_QUERY_FIX_STATUS        "UPDATE sols SET status='DECODING COMPLETED'"

/* postgres */
#define DBINT_3_QUERY_START_T_TEMPLATE  "UPDATE sols SET start_time=to_timestamp(%ld) WHERE id='%d' AND start_time='1990-01-01 00:00:00';"
#define DBINT_3_QUERY_END_T_TEMPLATE    "UPDATE sols SET end_time=to_timestamp(%ld) WHERE id='%d';"
#define DBINT_3_QUERY_INPUT_FILE        "INSERT INTO inputs (pol_id, sol_id, start_time, end_time, data_size, filename, md5, sha1) VALUES (%i, %i, to_timestamp(%ld), to_timestamp(%ld), %lu, '%s', '%s', '%s');"
#define DBINT_3_QUERY_FIX_STATUS        "UPDATE sols SET status='DECODING COMPLETED'"


typedef enum {
    DB_MYSQL,
    DB_SQLITE,
    DB_POSTGRESQL
} dbtype;


typedef struct __dbconf_t dbconf;
struct __dbconf_t {
    dbtype type;                      /* DB type */
    char name[DBCFG_BUFF_SIZE];       /* DB name */
    char user[DBCFG_BUFF_SIZE];       /* DB uaser name */
    char password[DBCFG_BUFF_SIZE];   /* DB password */
    char host[DBCFG_BUFF_SIZE];       /* DB host name */
    char file[DBCFG_BUFF_SIZE];       /* DB file path */
};


int DBIntInit(dbconf *conf);
int DBIntClose(void);
int DBIntCapTime(int pol_id, int sol_id, cap_time *ctime);
int DBIntDecWaiting(int pol_id, int sol_id);
int DBIntDecStart(int pol_id, int sol_id);
int DBIntDecEnd(int pol_id, int sol_id);
int DBIntInputPcap(int pol_id, int sol_id, cap_time *ctime, unsigned long size,
                   const char *name, const char *md5, const char *sha1);
int DBIntDeletePol(int pol_id);
int DBIntDeleteSol(int pol_id, int sol_id);

#endif /* __DBINTERFACE_H__ */
