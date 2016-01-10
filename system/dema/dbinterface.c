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
#include <sqlite3.h>

#include "dbinterface.h"
#include "log.h"


static sqlite3 *db_sqlite;         /* sqlite DB */
static dbtype dbt;                 /* db type */

static int DBIntQuery(char *query)
{
    int ret;
    char *err = NULL;
    
    while (sqlite3_exec(db_sqlite, query, NULL, NULL, &err) == SQLITE_BUSY) {
        if (err != NULL) {
            LogPrintf(LV_DEBUG, "Query: %s\n", query);
            LogPrintf(LV_ERROR, "sqlite3_exec Error: %s\n", err);
            sqlite3_free(err);
            err = NULL;
        }
    }
    if (err != NULL) {
        sqlite3_free(err);
        err = NULL;
    }
    ret = 0;
    
    #warning "to complete"

    return ret;
}


int DBIntInit(dbconf *conf)
{
    int res;

    dbt = conf->type;
    
    if (dbt == DB_SQLITE) {
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
    case DB_SQLITE:
        DBIntQuery(DBINT_2_QUERY_FIX_STATUS);
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
    case DB_SQLITE:
        sqlite3_close(db_sqlite);
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
    case DB_SQLITE:
        sprintf(query, DBINT_2_QUERY_INPUT_FILE, pol_id, sol_id, ctime->start_sec,
                ctime->end_sec, size, name, md5, sha1);
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
        return -1;
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
        return -1;
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
