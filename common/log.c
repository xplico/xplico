/* log.c
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
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
#include "proto.h"
#include "flow.h"
#include "dmemory.h"
#include "fthread.h"
#include "config_param.h"
#include "grp_flows.h"


#define LOG_CORE_ID       -1   /* see make files */
#define LOG_CAPTURE_ID    -2
#define LOG_DISPATCH_ID   -3
#define LOG_FILE_TMPL     "%s/%s_%i_%.2i_%.2i.log"

/* external crash info */
extern unsigned long crash_pkt_cnt; 
extern char *crash_ref_name;

static unsigned short core_mask = LV_DEFAULT;
static unsigned short dispatch_mask = LV_DEFAULT;
static unsigned short capture_mask = LV_DEFAULT;
static char log_dir[CFG_LINE_MAX_SIZE];
static char log_name[CFG_LINE_MAX_SIZE];
static char log_file[2*CFG_LINE_MAX_SIZE] = {'\0'};
static time_t next_day;
static pthread_mutex_t mux;          /* mutex to manipulate counter */
static bool log_screen = FALSE;

static int LogXml(char *fname, int fid, const pstack_f *ref_stack)
{
    const pstack_f *stack;
    char *xmlog;
    int fd, gid;
    static volatile int xml_id = 1;
    int copy;
    char xml_file[256];

    stack = NULL;
    gid = -1;
    if (fid != -1) {
        gid = FlowGrpId(fid);
        if (gid != -1) {
            stack = FlowGrpStack(gid);
        }
        else {
            stack = FlowStack(fid);
        }
    }
    else {
        stack = ref_stack;
    }

    if (stack != NULL) {
        /* save_xml_file */
        pthread_mutex_lock(&mux);
        copy = xml_id;
        sprintf(xml_file, "%s_%i_%lld.xml", fname, copy, (long long)time(NULL));
        fd = open(xml_file, O_CREAT|O_RDWR, 0x01B6);
        if (fd != -1) {
            xml_id++;
            pthread_mutex_unlock(&mux);
            /* xml flow */
            xmlog = ProtStackFrmXML(stack);
            write(fd, xmlog, strlen(xmlog));
            close(fd);
            xfree(xmlog);
        }
        else {
            pthread_mutex_unlock(&mux);
            if (gid != -1)
                ProtDelFrame((pstack_f *)stack);
            return -1;
        }
    }
    else
        return -1;

    if (gid != -1)
        ProtDelFrame((pstack_f *)stack);

    return copy;
}


static int LogFile(char *line)
{
    FILE *fp;
    struct tm time_st, *time_st_p;
    time_t time_log;

    time_log = time(NULL);
    if (time_log >= next_day) {
        /* change file */
        time_st_p = localtime_r(&time_log, &time_st);
#warning "to implemente a lock"
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


int LogPrintfPrt(int prot_id, unsigned short level, const pstack_f *stack, const char *format, ...)
{
    va_list argptr;
#warning "to be complete with malloc, in this way reduce stack size"
    char log[LV_LINE_MAX_DIM];
    char *buff;
    char xml_file[256];
    int len;
    int fid, xml_id;
    struct tm time_st, *time_st_p;
    time_t time_log;

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

    /* prot_id >= 0 is for dissector
       prot_id = -1 for core
       prot_id = -2 for capture modules
       prot_id = -3 for dispatcer modules
    */

    /* log mask */
    if (prot_id > -1) {
        /* protocol dissector mask */
        level &= ProtLogMask(prot_id);

        /* name */
        len = sprintf(buff, "[%s]", ProtLogName(prot_id));
    }
    else if (prot_id == LOG_CORE_ID) {
        /* core mask */
        level &= core_mask;

        /* name */
        len = sprintf(buff, "[CORE]");
        
    }
    else if (prot_id == LOG_CAPTURE_ID) {
        /* capture mask */
        level &= capture_mask;

        /* name */
        len = sprintf(buff, "[CAPT]");
    }
    else if (prot_id == LOG_DISPATCH_ID) {
        /* dispatch mask */
        level &= dispatch_mask;

        /* name */
        len = sprintf(buff, "[DISP]");
    }
    buff += len;
    
    /* flow id */
    fid = FthreadSelfFlowId();
    if (fid != -1)
        len = sprintf(buff, "{%i}-",fid);
    else
        len = sprintf(buff, "{c}-");
    buff += len;
    
    if (stack != NULL) {
        /* special case of log */
        fid = -1;
    }
    
    /* file id and name */
    /* level */
    switch (level) {
    case 0:
        return  0;
        break;

    case LV_OOPS:
        sprintf(xml_file, "%s/oops_%s", log_dir, log_name);
        xml_id = LogXml(xml_file, fid, stack);
        if (xml_id != -1) {
            len = sprintf(buff, "OOPS: (%i) ", xml_id);
        }
        else
            len = sprintf(buff, "OOPS: ");
        break;

    case LV_FATAL:
        sprintf(xml_file, "%s/fatal_%s", log_dir, log_name);
        xml_id = LogXml(xml_file, fid, stack);
        if (xml_id != -1) {
            len = sprintf(buff, "FATAL: (%i) ", xml_id);
        }
        else
            len = sprintf(buff, "FATAL: ");
        break;
        
    case LV_ERROR:
        sprintf(xml_file, "%s/error_%s", log_dir, log_name);
        xml_id = LogXml(xml_file, fid, stack);
        if (xml_id != -1) {
            len = sprintf(buff, "ERROR: (%i) ", xml_id);
        }
        else
            len = sprintf(buff, "ERROR: ");
        break;
        
    case LV_WARNING:
        sprintf(xml_file, "%s/warn_%s", log_dir, log_name);
        xml_id = LogXml(xml_file, fid, stack);
        if (xml_id != -1) {
            len = sprintf(buff, "WARNING: (%i) ", xml_id);
        }
        else
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

#ifdef XPL_CHECK_CODE
    if (log_screen)
        puts(log);
#endif

    /* end line */
    *(buff++) = '\r';
    *(buff++) = '\n';
    *buff = '\0';

    /* write to file */
    LogFile(log);

    return 0;
}


int LogSetMask(int component, unsigned short mask)
{
    switch (component) {
    case LOG_CORE_ID:
        core_mask = mask;
        break;

    case LOG_CAPTURE_ID:
        capture_mask = mask;
        break;

    case LOG_DISPATCH_ID:
        dispatch_mask = mask;
        break;
        
    default:
        printf("Log mask error\n");
        exit(-1);
        break;
    }

    return 0;
}


int LogDirName(char *file_cfg)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    int res, nl;
    struct tm time_st, *time_st_p;
    time_t time_log;

    /* time */
    time_log = time(NULL);
    time_st_p = localtime_r(&time_log, &time_st);

    time_st_p->tm_hour = 0;
    time_st_p->tm_min = 0;
    time_st_p->tm_sec = 0;
    next_day = mktime(time_st_p) + 86400;

    /* mutex init */
    pthread_mutex_init(&mux, NULL);
    
    if (file_cfg == NULL) {
        sprintf(log_dir, "/tmp"); /* default dir */
        sprintf(log_file, LOG_FILE_TMPL, log_dir, log_name, 1900+time_st_p->tm_year, time_st_p->tm_mon+1, time_st_p->tm_mday);
        return 0;
    }
    
    /* search dir path */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        return -1;
    }
    nl = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check all line */
        if (strlen(buffer)+1 == CFG_LINE_MAX_SIZE) {
            fclose(fp);
            printf("error: Config file line more length to %d characters\n", CFG_LINE_MAX_SIZE);
            return -1;
        }
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            /* dir path */
            param = strstr(buffer, CFG_PAR_LOG_DIR_PATH);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_LOG_DIR_PATH"=%s %s", log_dir, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        fclose(fp);
                        printf("error: Config param error in line %d. Unknow param: %s\n", nl, bufcpy);
                        return -1;
                    }
                }
            }
            /* name template */
            param = strstr(buffer, CFG_PAR_LOG_NAME_TMP);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_LOG_NAME_TMP"=%s %s", log_name, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        fclose(fp);
                        printf("error: Config param error in line %d. Unknow param: %s\n", nl, bufcpy);
                        return -1;
                    }
                }
            }
        }
    }
    fclose(fp);
    /* dir creation */
    if (mkdir(log_dir, 0x01FF) == -1 && errno != EEXIST) {
        printf("error: unable to create dir %s\n", log_dir);
        return -1;
    }
    sprintf(log_file, LOG_FILE_TMPL, log_dir, log_name, 1900+time_st_p->tm_year, time_st_p->tm_mon+1, time_st_p->tm_mday);

    return 0;
}


int LogFault(const char *format, ...)
{
    va_list argptr;
    char log[LV_LINE_MAX_DIM];
    char *filter_line;
    char fault_file[256];
    int len;
    FILE *fp;
    const pstack_f *stack;
    int pre_id;

    /* file */
    sprintf(fault_file, "%s/fault_%lld.txt", log_dir, (long long)time(NULL));
    fp = fopen(fault_file, "w");
    if (fp == NULL) {
        return -1;
    }
    
    va_start(argptr, format);
    len = vsprintf(log, format, argptr);
    va_end(argptr);
    fprintf(fp, "Event: %s\n", log);
    fprintf(fp, "Reduce pcap size with this tshark filter (tshark -r <original_pcap> -R \"<all line below>\" -w fault.pcap):\n\n");

    pre_id = -1;
    stack = FlowNxtStack(pre_id, &pre_id);
    while (stack != NULL) {
        filter_line = ProtStackFrmFilter(stack);
        if (filter_line != NULL) {
            fprintf(fp, "%s", filter_line);
            xfree(filter_line);
        }
        stack = FlowNxtStack(pre_id, &pre_id);
        if (stack != NULL) {
            fprintf(fp, " or ");
        }
    }
    fflush(NULL);

    /* last packet */
    if (crash_ref_name != NULL) {
        fprintf(fp, "\nEnd filter\n\n\n\n");
        fprintf(fp, "File name: %s; last packet num: %lu\n", crash_ref_name, crash_pkt_cnt);
    }
    else {
        fprintf(fp, "\nEnd filter\n\n\n");
        fprintf(fp, "\nLast packet num: %lu\n", crash_pkt_cnt);
    }
    fclose(fp);

    return 0;
}


int LogToScreen(bool enb)
{
    /* enable/disable log in the screen */
    log_screen = enb;

    return 0;
}
