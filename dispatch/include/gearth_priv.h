/* gearth_priv.h
 * private data strutures
 *
 *
 * $Id: disp_aggreg.h,v 1.2 2007/11/07 14:30:41 costa Exp $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#ifndef __GEARTH_PRIV_H__
#define __GEARTH_PRIV_H__

#include <stdio.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <semaphore.h>

#define GEA_PATH_SIZE        4096
#define GEA_TMP_DIR         "gea"
#define GEA_BUFFER_SIZE   (10240)
#define GEA_STRTIME_SIZE       24
#define GEA_MIN_DTIME         600
#define GEA_URL_SIZE        10240
#define GEA_UPDATE_KML         30 /* sec */

/** information describing a google earth kml file that belongs  at every ID */
typedef struct _gea_info gea_info;
struct _gea_info {
    unsigned long id; /* id reference */
    char kml_file[GEA_PATH_SIZE];  /* kml file, end path */
    char tmp_file[GEA_PATH_SIZE];  /* tmp kml file */
    char sem_name[GEA_PATH_SIZE];  /* sem name */
    sem_t *sem;                    /* semaphore */
    FILE *volatile fp;             /* file pointer of tmp_file file */
    pthread_mutex_t file_mux; /* control access to file */
    gea_info *nxt; /* next gea_info */
};

typedef struct _gea_coord gea_coord;
struct _gea_coord {
    float latitude;
    float longitude;
};

int GearthInit(const char *file_cfg);
int GearthEnd(void);

#define GEA_KML_HEADER {                                     \
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",        \
            "<kml xmlns=\"http://www.opengis.net/kml/2.2\" xmlns:atom=\"http://www.w3.org/2005/Atom\">",   \
            "<Document>",                                    \
            "    <atom:author>",                             \
            "        <atom:name>Xplico Internet traffic decoder</atom:name>", \
            "    </atom:author>",                            \
            "    <atom:link href=\"http://www.xplico.org\" />", \
            "    <name>xplico_geomap.kml</name>",               \
            "    <open>1</open>",                               \
            "    <LookAt>",                                     \
            "        <longitude>%f</longitude>",           \
            "        <latitude>%f</latitude>",                \
            "        <altitude></altitude>",            \
            "        <range>2500000</range>",                      \
            "        <tilt>0</tilt>",                           \
            "        <heading>0</heading>",                     \
            "    </LookAt>",                                    \
            NULL \
            }

#define GEA_KML_FOOTER { \
        "</Document>",   \
            "</kml>",    \
            NULL         \
            }

#define GEA_KML_LSTYLE_FTP     "linestyleFtp"
#define GEA_KML_LSTYLE_HTTP    "linestyleHttp"
#define GEA_KML_LSTYLE_EMAIL   "linestyleEmail"
#define GEA_KML_LSTYLE_IPP     "linestyleIpp"
#define GEA_KML_LSTYLE_IRC     "linestyleIrc"
#define GEA_KML_LSTYLE_MMS     "linestyleMms"
#define GEA_KML_LSTYLE_NNTP    "linestyleNntp"
#define GEA_KML_LSTYLE_PJL     "linestylePjl"
#define GEA_KML_LSTYLE_RTP     "linestyleRtp"
#define GEA_KML_LSTYLE_SIP     "linestyleSip"
#define GEA_KML_LSTYLE_DNS     "linestyleDns"
#define GEA_KML_LSTYLE_TCP     "linestyleTcp"
#define GEA_KML_LSTYLE_UDP     "linestyleUdp"
#define GEA_KML_LSTYLE_TFTP    "linestyleTftp"
#define GEA_KML_LSTYLE_FBCHAT  "linestyleFBchat"
#define GEA_KML_LSTYLE_TELNET  "linestyleTelnet"
#define GEA_KML_LINE_STYLE {                   \
        "    <Style id=\"linestyleFtp\">",     \
            "        <LineStyle>",             \
            "        <color>7F00FFFF</color>", \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleHttp\">", \
            "        <LineStyle>",              \
            "        <color>7F00F000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleEmail\">",\
            "        <LineStyle>",              \
            "        <color>7FF00000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleIpp\">",  \
            "        <LineStyle>",              \
            "        <color>7FF00000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleIrc\">",  \
            "        <LineStyle>",              \
            "        <color>7FF00000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleMms\">",  \
            "        <LineStyle>",              \
            "        <color>7F0000F0</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleNntp\">", \
            "        <LineStyle>",              \
            "        <color>7FF00000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestylePjl\">",  \
            "        <LineStyle>",              \
            "        <color>7F00FFFF</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleRtp\">",  \
            "        <LineStyle>",              \
            "        <color>7F0000F0</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleSip\">",  \
            "        <LineStyle>",              \
            "        <color>7F0000F0</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleDns\">",  \
            "        <LineStyle>",              \
            "        <color>7F40AFF0</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleTcp\">",  \
            "        <LineStyle>",              \
            "        <color>7F000000</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleUdp\">",  \
            "        <LineStyle>",              \
            "        <color>7FFFFFFF</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleUdp\">",  \
            "        <LineStyle>",              \
            "        <color>7FFFFFFF</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleTftp\">", \
            "        <LineStyle>",              \
            "        <color>b0e77b</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleFBchat\">", \
            "        <LineStyle>",              \
            "        <color>f0e77b</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            "    <Style id=\"linestyleTelnet\">", \
            "        <LineStyle>",              \
            "        <color>f4ef7b</color>",  \
            "        <width>4</width>", \
            "        </LineStyle>",     \
            "    </Style>",             \
            NULL \
            }
        

#endif /* __GEARTH_PRIV_H__ */
