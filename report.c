/* report.c
 * report in a socket connection the Xplico status/statistics
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

#include <stdio.h>
#include <time.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>

#include "proto.h"
#include "report.h"
#include "fthread.h"
#include "capture.h"
#include "dispatch.h"
#include "dnsdb.h"
#include "grp_flows.h"

#define FD_FILE_PATH_DIM         300

extern bool cli_status_log;
extern bool report_splash;

extern int GrpStatus(void);

int ReportInit(void)
{
    report_splash = FALSE;
    
    return 0;
}


void ReportFilesDescr(void)
{
    DIR *dir;
    struct dirent *entry;
    char link[FD_FILE_PATH_DIM], name[FD_FILE_PATH_DIM];
    int num = 0;

    /* check the number of FD open */
    dir = opendir("/proc/self/fd/");
    if (dir != NULL) {
        while((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.' || strcmp(entry->d_name, "socket:") != 0)
                continue;
            num++;
        }
        closedir(dir);        
    }

    if (num > 6) {
        dir = opendir("/proc/self/fd/");
        if (dir != NULL) {
            printf("Files open:\n");
            while((entry = readdir(dir)) != NULL) {
                if (entry->d_name[0] == '.')
                    continue;
                memset(name, '\0', FD_FILE_PATH_DIM);
                sprintf(link, "/proc/self/fd/%s", entry->d_name);
                if (readlink(link, name, FD_FILE_PATH_DIM) > 0) {
                    printf("\t%s\n", name);
                }
            }
            closedir(dir);        
        }
        printf("File manager: Bug!!!!!\n\n");
        exit(-1);
    }
}


int ReportSplash(void)
{
    unsigned int dns_ip, dns_name;
    unsigned long dns_size;
    time_t t;

    if (cli_status_log == FALSE && report_splash == FALSE)
        return 0;
    report_splash = FALSE;
    
    ProtStatus(NULL);
    DispatchStatus(NULL);
    printf("Fthread: %lu/%lu\n", FthreadRunning(), FthreadTblDim());
    printf("Flows: %lu\n", FlowNumber());
    GrpStatus();
    DnsDbStatus(&dns_ip, &dns_name, &dns_size);
    printf("Dns DB: ip number: %i, name number: %i, total size: %lu\n", dns_ip, dns_name, dns_size);
    t = FlowGetGblTime();
    printf("Data source: %s\n", CapSource());
    printf("Cap. time: %s\n", ctime(&t));

    return 0;
}



