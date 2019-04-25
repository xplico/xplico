/* geoiploc.c
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2013 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <pthread.h>
#include <string.h>

#include "geoiploc.h"
#include "configs.h"
#include "log.h"
#include "dmemory.h"
#include "config_file.h"

#if (XPL_GEO_IP && GEOIP_LIBRARY)
#include <maxminddb.h>

static pthread_mutex_t atom; /* atomic action */
static bool city = FALSE;


#define  GEOIP_FILE_PATH_SIZE           500
#define  GEOIP_CFG_PARAM_GEOIP2_FILE    "GEOIP2_DB_FILE"

static MMDB_s mmdb;
static bool geodb;

int GeoIPLocInit(const char *file_cfg)
{
    int status;
    char ipf[GEOIP_FILE_PATH_SIZE];
    
    geodb = FALSE;
    pthread_mutex_init(&atom, NULL);

    status = MMDB_FILE_OPEN_ERROR;
    
    ipf[0] = '\0';
    CfgParamStr(file_cfg, GEOIP_CFG_PARAM_GEOIP2_FILE, ipf, GEOIP_FILE_PATH_SIZE);
    if (ipf[0] != '\0') {
        LogPrintf(LV_INFO, "GeoIP2: %s", ipf);
        status = MMDB_open(ipf, MMDB_MODE_MMAP, &mmdb);
    }
    
    if (MMDB_SUCCESS != status) {
        status = MMDB_open("/opt/xplico/GeoLite2-City.mmdb", MMDB_MODE_MMAP, &mmdb);
        if (MMDB_SUCCESS != status) {
            status = MMDB_open("GeoLite2-City.mmdb", MMDB_MODE_MMAP, &mmdb);
            if (MMDB_SUCCESS != status) {
                status = MMDB_open("GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb);
            
                LogPrintf(LV_ERROR, "GeoIP2 without GeoLiteCity/GeoIP database");
        
                return -1;
            }
        }
    }
    else {
        LogPrintf(LV_INFO, "GeoIP2: %s", ipf);
    }

    LogPrintf(LV_INFO, "GeoIP2 %s: OK", mmdb.metadata.database_type);
    if (strstr(mmdb.metadata.database_type, "City") != NULL) {
        city = TRUE;
    }
    else {
        city = FALSE;
    }
    
    geodb = TRUE;
    
    return 0;
}


int GeoIPLocIP(ftval *ip, enum ftype itype, float *latitude, float *longitude, char **country_code)
{
    int mmdb_error;
    int status;
    MMDB_lookup_result_s result;
    MMDB_entry_data_s entry_data;
    struct sockaddr *psa;
    struct sockaddr_in sa;
    struct sockaddr_in6 sa6;
    
    if (itype != FT_IPv4 && itype != FT_IPv6) {
        LogPrintf(LV_ERROR, "GeoIP IP type error");

        return -1;
    }

    if (geodb == FALSE)
        return -1;

    if (itype == FT_IPv4) {
        sa.sin_family = AF_INET;
        sa.sin_port = 0;
        sa.sin_addr.s_addr = ip->uint32;
        psa = (struct sockaddr *)&sa;
    }
    else {
        sa6.sin6_family = AF_INET6;
        sa6.sin6_port = 0;
        sa6.sin6_flowinfo = 0;
        sa6.sin6_scope_id = 0;
        memcpy(sa6.sin6_addr.s6_addr, ip->ipv6, 16);
        psa = (struct sockaddr *)&sa6;
    }
        
    pthread_mutex_lock(&atom);
    
    result = MMDB_lookup_sockaddr(&mmdb, psa, &mmdb_error);
    
    pthread_mutex_unlock(&atom);
    
    if (!result.found_entry)
        return -1;

    if (country_code != NULL) {
        status = MMDB_get_value(&result.entry, &entry_data, "country", "iso_code", NULL);
        if (status == MMDB_SUCCESS) {
            if(entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_UTF8_STRING) {
                *country_code = DMemMalloc(entry_data.data_size+1);
                if (*country_code == NULL) {
                    return -1;
                }
                strncpy(*country_code, (char *)entry_data.utf8_string, entry_data.data_size);
                (*country_code)[entry_data.data_size] = '\0';
            }
            else {
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    
    if (city) {
        status = MMDB_get_value(&result.entry, &entry_data, "location", "latitude", NULL);
        if (status == MMDB_SUCCESS) {
            if(entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                *longitude = entry_data.double_value;
            }
            else {
                return -1;
            }
        }
        else {
            return -1;
        }
        status = MMDB_get_value(&result.entry, &entry_data, "location", "longitude", NULL);
        if (status == MMDB_SUCCESS) {
            if(entry_data.has_data && entry_data.type == MMDB_DATA_TYPE_DOUBLE) {
                *latitude = entry_data.double_value;
            }
            else {
                return -1;
            }
        }
        else {
            return -1;
        }
    }
    
    return 0;
}

#else /* GeoIPLoc disabled */
int GeoIPLocInit(const char *file_cfg)
{
    LogPrintf(LV_INFO, "GeoIP Disabled");

    return 0;
}


int GeoIPLocIP(ftval *ip, enum ftype itype, float *latitude, float *longitude, char **country_code)
{
    return -1;
}


#endif
