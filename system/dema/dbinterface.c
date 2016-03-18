/* dbinterface.c
 *
 * $Id:  $
 *
 * Xplico System
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

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#ifdef MYSQLXON
#include <mysql/mysql.h>
#endif
#include <sqlite3.h>
#include <postgresql/internal/libpq-int.h>

#include "dbinterface.h"
#include "log.h"


/* mysql, postgres, sqlite */
static PGconn *psql;               /* Postgres DB */
#ifdef MYSQLXON
static MYSQL *conn;                /* pointer to connection handler */
#endif
static sqlite3 *db_sqlite;         /* sqlite DB */
static dbtype dbt;                 /* db type */
static dbconf bconf;               /* a copy of native configuration */

static int DBIntQuery(char *query)
{
    int ret;
    char *err = NULL;
    short try = 1;
    PGresult *res;

    ret = -1;
    if (dbt == DB_MYSQL) {
#ifdef MYSQLXON
        do {
            ret = mysql_query(conn, query);
            if (ret != 0) {
                DBIntClose();
                DBIntInit(&bconf);
            }
            else {
                break;
            }
        } while(try--);
#else
        return -1;
#endif
    }
    else if (dbt == DB_POSTGRESQL) {
        do {
            res = PQexec(psql, query);
            if (PQresultStatus(res) != PGRES_COMMAND_OK && PQresultStatus(res) != PGRES_TUPLES_OK) {
                LogPrintf(LV_ERROR, "PQexec: %s\n", PQerrorMessage(psql));
                PQclear(res);
                DBIntClose();
                DBIntInit(&bconf);
            }
            else {
                ret = 0;
                break;
            }
        } while(try--);
        if (ret == 0) {
            PQclear(res);
        }
    }
    else {
        while (sqlite3_exec(db_sqlite, query, NULL, NULL, &err) == SQLITE_BUSY) {
            if (err != NULL) {
                sqlite3_free(err);
            }
            err = NULL;
        }
        if (err != NULL) {
            LogPrintf(LV_DEBUG, "Query: %s\n", query);
            LogPrintf(LV_ERROR, "sqlite3_exec Error: %s\n", err);
            sqlite3_free(err);
            err = NULL;
        }
        ret = 0;
    }
    #warning "to complete"

    return ret;
}


int DBIntInit(dbconf *conf)
{
#ifdef MYSQLXON
    MYSQL *ret;
#endif
    int res;
    char con_param[DBINT_QUERY_DIM];

    dbt = conf->type;

    if (dbt == DB_MYSQL) {
#ifdef MYSQLXON
        /* mysql */
        conn = mysql_init(NULL);
        ret = mysql_real_connect(
            conn,           /* pointer to connection handler */
            conf->host,     /* host to connect to */
            conf->user,     /* user name */
            conf->password, /* password */
            conf->name,     /* database to use */
            0,              /* port (use default) */
            NULL,           /* socket (use default) */
            0);             /* flags (none) */
        
        if (!ret)
            return -1;
        memcpy(&bconf, conf, sizeof(dbconf));
#else
        return -1;
#endif
    }
    else if (dbt == DB_POSTGRESQL) {
        /* postgresql */
        memcpy(&bconf, conf, sizeof(dbconf));
        sprintf(con_param, "host = '%s' dbname = '%s' user = '%s' password = '%s' connect_timeout = '900'", bconf.host, bconf.name, bconf.user, bconf.password);
        psql = PQconnectdb(con_param);
        if (!psql) {
            return -1; /* db not running */
        }
        if (PQstatus(psql) != CONNECTION_OK) {
            sprintf(con_param, "\"%s\"", bconf.user);
            if (strstr(PQerrorMessage(psql), con_param)) {
                res = -2; /* user error */
                LogPrintf(LV_ERROR, "User fail:\n%s\n", PQerrorMessage(psql));
            }
            else {
                sprintf(con_param, "\"%s\"", bconf.name);
                if (strstr(PQerrorMessage(psql), con_param)) {
                    res = -3; /* user error */
                    LogPrintf(LV_ERROR, "DB name fail:\n%s\n", PQerrorMessage(psql));
                }
                else {
                    res = -1; /* db not running */
                    LogPrintf(LV_ERROR, "DB fail\n");
                }
            }
            PQfinish(psql);
            
            return res;
        }
    }
    else if (dbt == DB_SQLITE) {
        /* sqlite */
        res = sqlite3_open(conf->file, &db_sqlite);
        if (res != SQLITE_OK)
            return -1;
    }
    else {
        return -1;
    }

    /* fix status on DB */
    switch (dbt) {
    case DB_MYSQL:
        DBIntQuery(DBINT_1_QUERY_FIX_STATUS);
        break;
        
    case DB_SQLITE:
        DBIntQuery(DBINT_2_QUERY_FIX_STATUS);
        break;
        
    case DB_POSTGRESQL:
        DBIntQuery(DBINT_3_QUERY_FIX_STATUS);
        break;
	
    default:
        return -1;
        break;
    }

    return 0;
}


int DBIntClose(void)
{
    switch (dbt) {
    case DB_MYSQL:
#ifdef MYSQLXON
        mysql_close(conn);
#endif
        break;
    
    case DB_SQLITE:
        sqlite3_close(db_sqlite);
        break;

    case DB_POSTGRESQL:
        PQfinish(psql);
        break;
    
    default:
        return -1;
        break;
    }

    return 0;
}


int DBIntCapTime(int pol_id, int sol_id, cap_time *ctime)
{
    char query[DBINT_QUERY_DIM];

    switch (dbt) {
    case DB_MYSQL:
        /* query start time */
        sprintf(query, DBINT_1_QUERY_START_T_TEMPLATE, ctime->start_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        /* query end time */
        sprintf(query, DBINT_1_QUERY_END_T_TEMPLATE, ctime->end_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    case DB_SQLITE:
         /* query start time */
        sprintf(query, DBINT_2_QUERY_START_T_TEMPLATE, ctime->start_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        /* query end time */
        sprintf(query, DBINT_2_QUERY_END_T_TEMPLATE, ctime->end_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    case DB_POSTGRESQL:
        /* query start time */
        sprintf(query, DBINT_3_QUERY_START_T_TEMPLATE, ctime->start_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        /* query end time */
        sprintf(query, DBINT_3_QUERY_END_T_TEMPLATE, ctime->end_sec, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    default:
        return -1;
        break;
    }

    return 0;
}


int DBIntDecWaiting(int pol_id, int sol_id)
{
    char query[DBINT_QUERY_DIM];

    /* query start decoding */
    sprintf(query, DBINT_QUERY_WAITING_DEC, sol_id);
    if (DBIntQuery(query) != 0) {
        return -1;
    }
    
    return 0;
}


int DBIntDecStart(int pol_id, int sol_id)
{
    char query[DBINT_QUERY_DIM];

    /* query start decoding */
    sprintf(query, DBINT_QUERY_START_DEC, sol_id);
    if (DBIntQuery(query) != 0) {
        return -1;
    }

    return 0;
}


int DBIntDecEnd(int pol_id, int sol_id)
{
    char query[DBINT_QUERY_DIM];
    
    /* query end decoding */
    sprintf(query, DBINT_QUERY_END_DEC, sol_id);
    if (DBIntQuery(query) != 0) {
        return -1;
    }

    return 0;
}

int DBIntInputPcap(int pol_id, int sol_id, cap_time *ctime, unsigned long size,
                   const char *name, const char *md5, const char *sha1)
{
    char query[DBINT_QUERY_DIM];

    switch (dbt) {
    case DB_MYSQL:
        sprintf(query, DBINT_1_QUERY_INPUT_FILE, pol_id, sol_id, ctime->start_sec, ctime->end_sec,
                size, name, md5, sha1);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    case DB_SQLITE:
        sprintf(query, DBINT_2_QUERY_INPUT_FILE, pol_id, sol_id, ctime->start_sec,
                ctime->end_sec, size, name, md5, sha1);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    case DB_POSTGRESQL:
        sprintf(query, DBINT_3_QUERY_INPUT_FILE, pol_id, sol_id, ctime->start_sec, ctime->end_sec,
                size, name, md5, sha1);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;

    default:
        return -1;
        break;
    }

    return 0;
}


int DBIntDeletePol(int pol_id)
{
    char query[DBINT_QUERY_DIM];
    
    switch (dbt) {
    case DB_SQLITE:
        /* this enable cascade actions */
        sprintf(query, "PRAGMA foreign_keys = ON;");
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;
        
    default:
        /* not return -1 */
        break;
    }
    
    /* query delete pol */
    sprintf(query, DBINT_QUERY_DELETE_POL, pol_id);
    if (DBIntQuery(query) != 0) {
        return -1;
    }
    
    return 0;
}


int DBIntDeleteSol(int pol_id, int sol_id)
{
    char query[DBINT_QUERY_DIM];
    
    switch (dbt) {
    case DB_SQLITE:
        /* this enable cascade actions */
        sprintf(query, "PRAGMA foreign_keys = ON;");
        if (DBIntQuery(query) != 0) {
            return -1;
        }
        break;
        
    default:
        /* not return -1 */
        break;
    }

    /* query delete sol */
    if (sol_id != -1) {
        sprintf(query, DBINT_QUERY_DELETE_SOL, sol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
    }
    else {
        sprintf(query, DBINT_QUERY_DELETE_RM_SOL, pol_id);
        if (DBIntQuery(query) != 0) {
            return -1;
        }
    }

    return 0;
}
