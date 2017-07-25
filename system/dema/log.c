/* log.c
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2014 Gianluca Costa. Web: www.xplico.org
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
#include <stdarg.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
 
#include "log.h"
#include "config_file.h"

#define LOG_FILE_TMPL     "%s/%s_%i_%.2i_%.2i.log"

static char log_dir[CFG_LINE_MAX_SIZE];
static char log_name[CFG_LINE_MAX_SIZE];
static char log_file[2*CFG_LINE_MAX_SIZE] = {'\0'};
static time_t next_day;
static unsigned short log_mask;


static int LogFile(char *line)
{
    FILE *fp;
    struct tm time_st, *time_st_p;
    time_t time_log;

    time_log = time(NULL);
    if (time_log >= next_day) {
        /* change file */
        time_st_p = localtime_r(&time_log, &time_st);
        sprintf(log_file, LOG_FILE_TMPL, log_dir, log_name, 1900+time_st_p->tm_year, time_st_p->tm_mon+1, time_st_p->tm_mday);
        time_st_p->tm_hour = 0;
        time_st_p->tm_min = 0;
        time_st_p->tm_sec = 0;
        next_day = mktime(time_st_p) + 86400;
    }
    fp = fopen(log_file, "a");
    if (fp != NULL) {
        fputs(line, fp);
        fclose(fp);
    }

    return 0;
}


int LogCfg(char *file_cfg, char *root_dir)
{
    struct tm time_st, *time_st_p;
    time_t time_log;
    char dirbase[CFG_LINE_MAX_SIZE];
    char name[CFG_LINE_MAX_SIZE];
    char mask[CFG_LINE_MAX_SIZE];
    
    log_mask = LV_DEFAULT;
    sprintf(log_name, "dema");

    /* time */
    time_log = time(NULL);
    time_st_p = localtime_r(&time_log, &time_st);
    time_st_p->tm_hour = 0;
    time_st_p->tm_min = 0;
    time_st_p->tm_sec = 0;
    next_day = mktime(time_st_p) + 86400;
    
    if (root_dir != NULL && root_dir[0] != '\0') {
        sprintf(log_dir, "%s/log", root_dir);
    }
    else {
        sprintf(log_dir, "/tmp");
    }
    /* dir creation */
    if (mkdir(log_dir, 0x01FF) == -1 && errno != EEXIST) {
        printf("error: unable to create dir %s\n", log_dir);
        return -1;
    }

    sprintf(log_file, LOG_FILE_TMPL, log_dir, log_name, 1900+time_st_p->tm_year, time_st_p->tm_mon+1, time_st_p->tm_mday);

    if (file_cfg != NULL && file_cfg[0] != '\0') {
        if (CfgParamStr(file_cfg, CFG_PAR_ROOT_DIR, dirbase, CFG_LINE_MAX_SIZE) == 0) {
            sprintf(log_dir, "%s/log", dirbase);
        }
        if (CfgParamStr(file_cfg, CFG_PAR_LOG_NAME, name, CFG_LINE_MAX_SIZE) == 0) {
            strcpy(log_name, name);
        }
        if (CfgParamStr(file_cfg, CFG_PAR_LOG_LEVELS, mask, CFG_LINE_MAX_SIZE) == 0) {
            log_mask = LV_OOPS;
            if (strchr(mask, 'F') != NULL) {
                log_mask |= LV_FATAL;
            }
            if (strchr(mask, 'E') != NULL) {
                log_mask |= LV_ERROR;
            }
            if (strchr(mask, 'W') != NULL) {
                log_mask |= LV_WARNING;
            }
            if (strchr(mask, 'I') != NULL) {
                log_mask |= LV_INFO;
            }
            if (strchr(mask, 'T') != NULL) {
                log_mask |= LV_TRACE;
            }
            if (strchr(mask, 'D') != NULL) {
                log_mask |= LV_DEBUG;
            }
            if (strchr(mask, 'S') != NULL) {
                log_mask |= LV_START;
            }
        }
    }
    
    return 0;
}


int LogPrintf(unsigned short level, const char *format, ...)
{
    va_list argptr;
    char log[LV_LINE_MAX_DIM];
    char *buff;
    int len;
    struct tm time_st, *time_st_p;
    time_t time_log;

    /* check level */
    if ((level & log_mask) == 0)
        return 0;
    
    buff = log;
    len = 0;

    /* time */
    time_log = time(NULL);
    time_st_p = localtime_r(&time_log, &time_st);
    if (time_st_p != NULL) {
        len = sprintf(buff, "%.2i:%.2i:%.2i ", time_st_p->tm_hour,
                      time_st_p->tm_min, time_st_p->tm_sec);
    }
    buff += len;

    switch (level) {
    case LV_OOPS:
        len = sprintf(buff, "OOPS: ");
        break;

    case LV_FATAL:
        len = sprintf(buff, "FATAL: ");
        break;
        
    case LV_ERROR:
        len = sprintf(buff, "ERROR: ");
        break;
        
    case LV_WARNING:
        len = sprintf(buff, "WARNING: ");
        break;
        
    case LV_INFO:
        len = sprintf(buff, "INFO: ");
        break;
        
    case LV_TRACE:
        len = sprintf(buff, "TRACE: ");
        break;
        
    case LV_DEBUG:
        len = sprintf(buff, "DEBUG: ");
        break;
        
    case LV_START:
        len = sprintf(buff, "STA: ");
        break;
        
    default:
        len = sprintf(buff, "---: ");
        break;
    }
    buff += len;

    va_start(argptr, format);
    len = vsprintf(buff, format, argptr);
    va_end(argptr);
    buff += len;
    
    /* end line */
    *(buff++) = '\r';
    *(buff++) = '\n';
    *buff = '\0';

    /* write to file */
    LogFile(log);
    
    return 0;
}
