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

#include "geoiploc.h"
#include "configs.h"
#include "log.h"
#include "config_file.h"

#if (XPL_GEO_IP && GEOIP_LIBRARY)
#include "GeoIP.h"
#include "GeoIPCity.h"

#define  GEOIP_FILE_PATH_SIZE   500
#define  GEOIP_CFG_PARAM_IPV4_FILE      "GEOIP_IPV4_DB_FILE"
#define  GEOIP_CFG_PARAM_IPV6_FILE      "GEOIP_IPV6_DB_FILE"


static GeoIP *gi;
static GeoIP *giv6;
static pthread_mutex_t atom; /* atomic action */
static pthread_mutex_t atom6; /* atomic action */
static bool city = FALSE;
static bool cityv6 = FALSE;


int GeoIPLocInit(const char *file_cfg)
{
    char ipv4f[GEOIP_FILE_PATH_SIZE];
    char ipv6f[GEOIP_FILE_PATH_SIZE];
    
    pthread_mutex_init(&atom, NULL);
    pthread_mutex_init(&atom6, NULL);
    
    ipv4f[0] = '\0';
    ipv6f[0] = '\0';
    CfgParamStr(file_cfg, GEOIP_CFG_PARAM_IPV4_FILE, ipv4f, GEOIP_FILE_PATH_SIZE);
    CfgParamStr(file_cfg, GEOIP_CFG_PARAM_IPV6_FILE, ipv6f, GEOIP_FILE_PATH_SIZE);
    
    LogPrintf(LV_INFO, "GeoIP IPv4 file: %s", ipv4f);
    /* try to open an db */
    giv6 = NULL;
    gi = GeoIP_open(ipv4f, GEOIP_MEMORY_CACHE);
    if (gi == NULL) {
        gi = GeoIP_open("GeoLiteCity.dat", GEOIP_MEMORY_CACHE);
    }
    if (gi == NULL) {
        /* country db */
        gi = GeoIP_open("GeoIP.dat", GEOIP_MEMORY_CACHE);
        if (gi == NULL) {
            LogPrintf(LV_ERROR, "GeoIP without GeoLiteCity/GeoIP database");
            return -1;
        }
    }

    if (gi != NULL) {
        if (gi->databaseType == GEOIP_CITY_EDITION_REV1) {
            city = TRUE;
            LogPrintf(LV_INFO, "GeoIP IPv4 DB City");
        }
        else {
            LogPrintf(LV_INFO, "GeoIP IPv4 DB Country");
        }
    }
    
    LogPrintf(LV_INFO, "GeoIP IPv6 file: %s", ipv6f);
    giv6 = GeoIP_open(ipv6f, GEOIP_MEMORY_CACHE);
    if (giv6 == NULL) {
        giv6 = GeoIP_open("GeoLiteCityv6.dat", GEOIP_MEMORY_CACHE);
    }
    if (giv6 == NULL) {
        /* country db */
        giv6 = GeoIP_open("GeoIPv6.dat", GEOIP_MEMORY_CACHE);
        if (giv6 == NULL) {
            LogPrintf(LV_ERROR, "GeoIP without GeoLiteCity/GeoIP V6 database");
        }
        return -1;
    }
    if (giv6 != NULL) {
        if (giv6->databaseType == GEOIP_CITY_EDITION_REV1_V6) {
            cityv6 = TRUE;
            LogPrintf(LV_INFO, "GeoIP IPv6 DB City");
        }
        else {
            LogPrintf(LV_INFO, "GeoIP IPv6 DB Country");
        }
    }
    
    return 0;
}


int GeoIPLocIP(ftval *ip, enum ftype itype, float *latitude, float *longitude, char **country_code)
{
    GeoIPRecord *gir;
    geoipv6_t gv6;
    const char *ccode;

    gir = NULL;
    ccode = NULL;
    switch (itype) {
    case FT_IPv4:
        if (gi == NULL)
            return -1;
        pthread_mutex_lock(&atom);
        if (city) {
            gir = GeoIP_record_by_ipnum(gi, ntohl(ip->uint32));
            if (gir != NULL) {
                ccode = gir->country_code;
            }
        }
        else {
            ccode = GeoIP_country_code_by_ipnum(gi, ntohl(ip->uint32));
        }
        pthread_mutex_unlock(&atom);
        break;
        
    case FT_IPv6:
        if (giv6 == NULL)
            return -1;
        memcpy(gv6.s6_addr, ip->ipv6, 16);
        pthread_mutex_lock(&atom6);
        if (cityv6) {
            gir = GeoIP_record_by_ipnum_v6(giv6, gv6);
            if (gir != NULL)
                ccode = gir->country_code;
        }
        else {
            ccode = GeoIP_country_code_by_ipnum_v6(giv6, gv6);
        }
        pthread_mutex_unlock(&atom6);
        break;

    default:
        LogPrintf(LV_ERROR, "GeoIP IP type error");
    }

    if (gir != NULL) {
        *latitude = gir->latitude;
        *longitude = gir->longitude;
        if (country_code != NULL)
            *country_code = (char *)ccode;
        GeoIPRecord_delete(gir);
        return 0;
    }
    if (country_code != NULL && ccode != NULL) {
        *country_code = (char *)ccode;
        return 0;
    }

    return -1;
}


int GeoIPLocAddr(char *addr, float *latitude, float *longitude)
{
    GeoIPRecord *gir;

    if (gi == NULL)
       return -1;

    if (city) {
        gir = GeoIP_record_by_addr(gi, (const char *)addr);
        if (gir != NULL) {
            *latitude = gir->latitude;
            *longitude = gir->longitude;
            GeoIPRecord_delete(gir);
            return 0;
        }
    }
    
    return -1;
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


int GeoIPLocAddr(char *addr, float *latitude, float *longitude)
{
    return -1;
}

#endif
