/* dema.c
 *
 * Decoding Manager daemon 
 *
 * $Id: $
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

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <signal.h>
#include <pthread.h>

#include "dema.h"
#include "session_decoding.h"
#include "dbinterface.h"
#include "captime.h"
#include "version.h"
#include "config_file.h"
#include "log.h"

static volatile bool terminate;
static pthread_mutex_t pd_mux;           /* mutex to access atomicly the tbl */
static podec * volatile pd_tbl;
static volatile int dim;


static void Usage(char *name)
{
    printf("\n");
    printf("usage: %s [-v] {-c <config_file> | {-d <pol_root_dir> -b <db_type>}} [-h]\n", name);
    printf("\t-v version\n");
    printf("\t-c config file\n");
    printf("\t-d pols root dir\n");
    printf("\t-b DB type (postgresql or mysql or sqlite)\n");
    printf("\t-h this help\n");
    printf("\n");
}


static void DemaDecInit(podec *dec)
{
    memset(dec, 0, sizeof(podec));
    dec->pol_id = -1;
    dec->sol_id = -1;
    dec->run = FALSE;
    dec->end = FALSE;
    dec->name[0] = '\0';
    dec->size = 0;
    dec->filenum = 0;
    dec->rt = FALSE;
    dec->sd[0] = -1;
    dec->sd[1] = -1;
}


int DemaHash(const char *path_src, char *md5, char *sha1)
{
    char cmd[2*DM_FILENAME_PATH];
    char buffer[2*DM_HASH_STR];
    char dummy[DM_HASH_STR];
    FILE *fp;
    int res, ret = 0;
    
    /* run md5sum and sha1sum */
    sprintf(cmd, "md5sum \"%s\" > /tmp/dema_hash.txt; sha1sum \"%s\" >> /tmp/dema_hash.txt", path_src, path_src);
    system(cmd);
    fp = fopen("/tmp/dema_hash.txt", "r");
    if (fp != NULL) {
        if (fgets(buffer, 2*DM_HASH_STR, fp) != NULL) {
            /* md5 */
            res = sscanf(buffer, "%s %s", md5, dummy);
            if (res != 2) {
                ret = -1;
            }

            /* sha1 */
            if (fgets(buffer, 2*DM_HASH_STR, fp) != NULL) {
                res = sscanf(buffer, "%s %s", sha1, dummy);
                if (res != 2) {
                    ret = -1;
                }
            }
            else {
                ret = -1;
            }
        }
        else {
            ret = -1;
        }
        
        fclose(fp);
    }
    else {
        ret = -1;
    }

    remove("/tmp/dema_hash.txt");

    return ret;
}


static void DemaSigTerm(int sig)
{
    terminate = TRUE;
}


static int DemaLoop(dbconf *db_c, char *root, time_t twpcap)
{
    podec *npd_tbl;
    int num, i, j;
    struct stat info;
    char *filename, *tmp;
    char dir[DM_FILENAME_PATH];
    char path_src[DM_FILENAME_PATH];
    char path_dst[DM_FILENAME_PATH];
    char cmd[DM_FILENAME_PATH];
    char interf[DM_FILENAME_PATH];
    char filter[DM_FILTER_LINE];
    int nxt_ses;
    pid_t chld;
    cap_time *ctime;
    char sha1[DM_HASH_STR];
    char md5[DM_HASH_STR];
    FILE *fp;
    short session_rm;
    pid_t lpid;
    time_t time_now;
    bool one_file;
    
    pd_tbl = malloc(sizeof(podec)*DM_TBL_ADD);
    for (i=0; i!=DM_TBL_ADD; i++) {
        DemaDecInit(&(pd_tbl[i]));
    }
    dim = DM_TBL_ADD;
    num = 0;
    session_rm = 0;
    
    /* main loop */
    while (1) {
        /* find new pol */
        pthread_mutex_lock(&pd_mux);
        i = SeDeFind(root, pd_tbl, dim);
        pthread_mutex_unlock(&pd_mux);
        if (i > 0) {
            num += i;
            if (dim-num < DM_TBL_ADD) {
                pthread_mutex_lock(&pd_mux);
                npd_tbl = realloc(pd_tbl, sizeof(podec)*(dim+DM_TBL_ADD));
                if (npd_tbl != NULL) {
                    pd_tbl = npd_tbl;
                    memset(pd_tbl+dim, -1, sizeof(podec)*DM_TBL_ADD);
                    for (i=dim; i!= dim+DM_TBL_ADD; i++) {
                        DemaDecInit(&(pd_tbl[i]));
                    }
                    dim += DM_TBL_ADD;
                }
                pthread_mutex_unlock(&pd_mux);
            }
        }
        
        /* check file to decode */
        for (i=0, j=0; j<num; i++) {
            if (pd_tbl[i].pol_id == -1)
                continue;
            j++;
            /* if not rt decoding */
            if (pd_tbl[i].rt == TRUE)
                continue;

            /* check old files (from a crash) */
            if (pd_tbl[i].run == FALSE) {
                filename = SeDeFileDecode(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                if (filename != NULL) {
                    sprintf(dir, DM_DECOD_DIR, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                    sprintf(path_src, "%s/%s", dir, filename);
                    /* start decoding */
                    if (SeDeStart(db_c, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &pd_tbl[i].pid, FALSE, NULL, NULL) == 0) {
                        /* change status in to db */
                        DBIntDecStart(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                        pd_tbl[i].run = TRUE;
                        pd_tbl[i].end_to = -1;
                    }
                    else {
                        LogPrintf(LV_FATAL, "Applications executions error\n");
                        exit(-1);
                    }
                }
            }

            /* check new files */
            filename = SeDeFileNew(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &one_file);
            if (filename != NULL && pd_tbl[i].end == FALSE) {
                /* check file name */
                time_now = time(NULL);
                if (strcmp(filename, pd_tbl[i].name) != 0) {
                    pd_tbl[i].size = 0;
                    strcpy(pd_tbl[i].name, filename);
                    pd_tbl[i].growth = time_now + DM_GROWTH_TO;
                    if (pd_tbl[i].run == FALSE) {
                        /* change status in to db */
                        DBIntDecWaiting(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                    }
                }
                if (one_file == FALSE) {
                    pd_tbl[i].growth = 0;
                }
                
                sprintf(dir, DM_NEW_DIR, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                sprintf(path_src, "%s/%s", dir, filename);
                
                /* check file growth */
                if (time_now < pd_tbl[i].growth)
                    time_now = 0;
                
                if (time_now && stat(path_src, &info) == 0) {
                    if (pd_tbl[i].size == info.st_size && SeDeFileActive(path_src) == FALSE) {
                        /* capture time update */
                        ctime = CapTime(path_src);
                        if (ctime != NULL) {
                            /* checksum/hash */
                            if (DemaHash(path_src, md5, sha1) != 0) {
                                /* empty hash */
                                md5[0] = '\0';
                                sha1[0] = '\0';
                            }

                            /* insert/update data in DB */
                            DBIntCapTime(pd_tbl[i].pol_id, pd_tbl[i].sol_id, ctime);
                            DBIntInputPcap(pd_tbl[i].pol_id, pd_tbl[i].sol_id, ctime, pd_tbl[i].size, pd_tbl[i].name, md5, sha1);
                        }
                        else {
                            LogPrintf(LV_WARNING, "Error: incorrect capture file %s\n", filename);
                            /* free */
                            pd_tbl[i].name[0] = '\0';
                            pd_tbl[i].size = 0;
                            pd_tbl[i].growth = 0;
                            if (pd_tbl[i].run == FALSE) {
                                /* change status in to db */
                                DBIntDecEnd(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                            }
                            /* remove file */
                            remove(path_src);
                            continue;
                        }
                        /* free */
                        pd_tbl[i].name[0] = '\0';
                        pd_tbl[i].size = 0;
                        pd_tbl[i].growth = 0;
                        
                        /* move file in raw */
                        sprintf(dir, DM_RAW_DIR, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                        sprintf(path_dst, "%s/%s", dir, filename);
                        if (rename(path_src, path_dst) != 0) {
                            sprintf(path_dst, "%s/%lu_%s", dir, (unsigned long)time(NULL), filename);
                            rename(path_src, path_dst);
                        }

                        /* link file in decode */
                        sprintf(path_src, "%s/%s", dir, filename);
                        sprintf(dir, DM_DECOD_DIR, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                        sprintf(path_dst, "%s/%s", dir, filename);
                        link(path_src, path_dst);
                        pd_tbl[i].filenum++;

                        /* start decoding */
                        if (pd_tbl[i].run == FALSE) {
                            if (SeDeStart(db_c, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &pd_tbl[i].pid, FALSE, NULL, NULL) == 0) {
                                /* change status in to db */
                                DBIntDecStart(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                                pd_tbl[i].run = TRUE;
                                pd_tbl[i].end_to = -1;
                            }
                            else {
                                if (pd_tbl[i].run == FALSE) {
                                    /* change status in to db */
                                    DBIntDecEnd(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                                }
                                LogPrintf(LV_FATAL, "Applications executions error\n");
                                exit(-1);
                            }
                        }
                        
                        /* exist new file? */
                        filename = SeDeFileNew(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &one_file);
                        if (filename != NULL) {
                            strcpy(pd_tbl[i].name, filename);
                            sprintf(dir, DM_NEW_DIR, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                            sprintf(path_src, "%s/%s", dir, filename);
                            if (stat(path_src, &info) == 0) {
                                pd_tbl[i].size = info.st_size;
                            }
                        }
                    }
                    else {
                        pd_tbl[i].size = info.st_size;
                        pd_tbl[i].growth = time_now + DM_GROWTH_TO;
                    }
                }
                else {
                    if (time_now)
                        perror("");
                }
            }
            else if (pd_tbl[i].end == FALSE && pd_tbl[i].run == TRUE) {
                /* there isn't a new file */
                time_now = time(NULL);
                if (pd_tbl[i].name[0] != '\0') { /* last file found */
                    pd_tbl[i].name[0] = '\0';
                    pd_tbl[i].growth = time_now + twpcap;
                }
                if (time_now > pd_tbl[i].growth) {
                    SeDeEnd(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &pd_tbl[i].pid);
                    pd_tbl[i].end = TRUE;
                    pd_tbl[i].end_to = -1;
                }
            }
        }

        /* examine sessions in the pol */
        for (i=0, j=0; j<num; i++) {
            if (pd_tbl[i].pol_id == -1)
                continue;
            j++;
            if (pd_tbl[i].run == FALSE && pd_tbl[i].size == 0) {
                nxt_ses = SeDeNextSession(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                if (nxt_ses != -1) {
                    LogPrintf(LV_INFO, "Created new session with id:%i\n", nxt_ses);
                    pd_tbl[i].sol_id = nxt_ses;
                }
            }
        }
        
        /* check case and session deletion */
        for (i=0, j=0; j<num; i++) {
            if (pd_tbl[i].pol_id == -1)
                continue;
            j++;
            sprintf(path_src, DM_POL_DIR"/%s", root, pd_tbl[i].pol_id, DM_DELETE_CASE);
            if (stat(path_src, &info) == 0) {
                /* delete pol (case) */
                SeDeKill(pd_tbl, i);
                /* delete records in DB */
                DBIntDeletePol(pd_tbl[i].pol_id);
                remove(path_src); /* this frees the XI */
                /* delete files */
                sprintf(cmd, "rm -rf "DM_POL_DIR, root, pd_tbl[i].pol_id);
                system(cmd);
                DemaDecInit(&(pd_tbl[i]));
                num--;
            }
            
            /* every DM_ERASE_SESSSION tick we erase all session not used */
            if (session_rm == DM_ERASE_SESSION) {
                sprintf(path_src, DM_POL_DIR"/"DM_DELETE_SESSION, root, pd_tbl[i].pol_id);
                if (stat(path_src, &info) == 0) {
                    /* delete sol records in DB */
                    DBIntDeleteSol(pd_tbl[i].pol_id, -1);
                    /* delete files of SOL */
                    sprintf(cmd, "rm -rf "DM_POL_DIR"/"DM_DELETE_SESSION, root, pd_tbl[i].pol_id);
                    system(cmd);
                }
            }
        }
        if (session_rm > DM_ERASE_SESSION)
            session_rm = 0;

        /* check realtime case -start/stop- */
        for (i=0, j=0; j<num; i++) {
            if (pd_tbl[i].pol_id == -1)
                continue;
            j++;
            
            /* stop */
            sprintf(path_dst, DM_POL_DIR"/%s", root, pd_tbl[i].pol_id, DM_RT_STOP_FILE);
            if (stat(path_dst, &info) == 0) {
                /* stop rt acquisition */
                SeDeEnd(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &pd_tbl[i].pid);
                pd_tbl[i].end = TRUE;
                pd_tbl[i].rt = FALSE;
                sprintf(path_src, DM_POL_DIR"/%s", root, pd_tbl[i].pol_id, DM_RT_START_FILE);
                remove(path_src);
                remove(path_dst);
            }
            if (pd_tbl[i].run == TRUE)
                continue;
            
            /* start */
            sprintf(path_src, DM_POL_DIR"/%s", root, pd_tbl[i].pol_id, DM_RT_START_FILE);
            if (stat(path_src, &info) == 0) {
                /* netework interface */
                fp = fopen(path_src, "r");
                if (fp != NULL) {
                    /* network intrface */
                    if (fgets(interf, DM_FILENAME_PATH, fp) != NULL) {
                        if ((tmp = strchr(interf, '\r')) != NULL) {
                            tmp[0] = '\0';
                        }
                        if ((tmp = strchr(interf, ' ')) != NULL) {
                            tmp[0] = '\0';
                        }
                        if ((tmp = strchr(interf, '\n')) != NULL) {
                            tmp[0] = '\0';
                        }
                        /* filter */
                        if (fgets(filter, DM_FILENAME_PATH, fp) != NULL) {
                            if ((tmp = strchr(filter, '\r')) != NULL) {
                                tmp[0] = '\0';
                            }
                            if ((tmp = strchr(filter, '\n')) != NULL) {
                                tmp[0] = '\0';
                            }
                        }
                        else {
                            filter[0] = '\0';
                        }
                        fclose(fp);

                        /* start rt acquisition */
                        if (SeDeStart(db_c, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id, &pd_tbl[i].pid, TRUE, interf, filter) == 0) {
                            /* change status in to db */
                            DBIntDecStart(pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                            pd_tbl[i].run = TRUE;
                            pd_tbl[i].rt = TRUE;
                            pd_tbl[i].end_to = -1;
                        }
                        else {
                            remove(path_src);
                            LogPrintf(LV_FATAL, "Applications executions error\n");
                            exit(-1);
                        }
                    }
                    else {
                        remove(path_src);
                        LogPrintf(LV_ERROR, "Network Interface error\n");
                    }
                }
                else {
                    remove(path_src);
                }
            }
        }

        /* check end timeout */
        for (i=0, j=0; j<num; i++) {
            if (pd_tbl[i].pol_id == -1)
                continue;
            j++;
            if (pd_tbl[i].end == TRUE && pd_tbl[i].run == TRUE) {
                if (pd_tbl[i].end_to == 0) {
                    /* force kill all task */
                    SeDeKill(pd_tbl, i);
                    pd_tbl[i].end_to = -1;
                }
                else if (pd_tbl[i].end_to != -1)
                    pd_tbl[i].end_to--;
            }
        }

        /* check termination */
        if (terminate == TRUE) {
            for (i=0; i!=dim; i++) {
                SeDeKill(pd_tbl, i);
            }
            system("killall xplico 2>/dev/null 1>/dev/null");
            break; /* exit from main cicle */
        }

        /* check process termination */
        do {
            chld = waitpid(0, NULL, WNOHANG);
            if (chld > 0) {
                for (i=0, j=0; j<num; i++) {
                    if (pd_tbl[i].pol_id == -1)
                        continue;
                    j++;
                    if (pd_tbl[i].run == TRUE) {
                        if (SeDeRun(&pd_tbl[i].pid, chld, TRUE) == 0) {
                            filename = SeDeFileDecode(root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                            if (pd_tbl[i].end && filename == NULL) {
                                pd_tbl[i].end_to = DM_END_TO;
                                pd_tbl[i].pid.tot--;
                            }
                            else {
                                /* force the end, with kill */
                                pd_tbl[i].pid.tot--;
                                pd_tbl[i].end = TRUE;
                                pd_tbl[i].end_to = 1; /* without timeout */
                                SeDeKill(pd_tbl, i);
                                LogPrintf(LV_ERROR, "Xplico or a Manipulator is dead!\n");
                            }
                            if (pd_tbl[i].pid.tot == 0) {
                                pd_tbl[i].run = FALSE;
                                pd_tbl[i].end = FALSE;
                                pd_tbl[i].rt = FALSE;
                                pd_tbl[i].end_to = -1;
                                /* change status in to db */
                                DBIntDecEnd(pd_tbl[i].pol_id, pd_tbl[i].sol_id);

                                /* update Lucene Index */
                                lpid = fork();
                                if (lpid != -1) {
                                    if (lpid == 0) {
                                        sprintf(cmd, DM_LUCENE_CMD, root, pd_tbl[i].pol_id, pd_tbl[i].sol_id);
                                        system(cmd);
                                        exit(0);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            else {
                chld = 0;
            }
        } while (chld);
        
        /* wait */
        sleep(1); /* tick, if you chane it then change also all the timeout: DM_END_TO, ... */
        session_rm++;
    }
    
    /* free memory */
    free(pd_tbl);
    
    return 0;
}


int CfgParIsComment(char *line)
{
    char *cmnt;

    cmnt = strchr(line, CFG_LINE_COMMENT);
    if (cmnt == NULL)
        return 0;
    while (*line != CFG_LINE_COMMENT) {
        if (*line != ' ')
            return 0;
        line++;
    }
    
    return 1;
}


int CfgParamStr(const char *cfg_file, const char *rparam, char *ret_val, int rsize)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char scans[CFG_LINE_MAX_SIZE];
    char prm[CFG_LINE_MAX_SIZE];
    char *param;
    int res, ret;

    if (cfg_file == NULL)
        return -1;
        
    ret = -1;
    /* configuration file is without errors! */
    fp = fopen(cfg_file, "r");
    sprintf(scans, "%s=%s", rparam, "%s %s");
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = buffer;
            while (param[0] == ' ')
                param++;
            if (param[0] != '\0') {
                res = sscanf(param, scans, prm, bufcpy);
                if (res > 0) {
                    if (strlen(prm) > rsize) {
                        LogPrintf(LV_ERROR, "Config file parameter (%s) to big", rparam);
                    }
                    else {
                        strcpy(ret_val, prm);
                        ret = 0;
                    }
                    break;
                }
            }
        }
    }

    fclose(fp);
    
    return ret;
}

static int ReadConfigFile(char *path, dbconf *db_c, char *root_dir, time_t *twpcap, char *cert)
{
    FILE *fp;
    int res, nl;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char dbts[CFG_LINE_MAX_SIZE];
    char *param;
    bool root = FALSE;

    if (root_dir[0] != '\0')
        root = TRUE;
    
    fp = fopen(path, "r");
    if (fp == NULL) {
        LogPrintf(LV_WARNING, "Config file \"%s\" can't be opened", path);
        return -1;
    }
    nl = 0;
    dbts[0] = '\0';
    memset(db_c, '\0', sizeof(dbconf));
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check all line */
        if (strlen(buffer)+1 == CFG_LINE_MAX_SIZE) {
            LogPrintf(LV_WARNING,"Config file line more length to %d characters", CFG_LINE_MAX_SIZE);
            return -1;
        }
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_PCAP_FILES_TIME);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_PCAP_FILES_TIME"=%lu %s", twpcap, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            param = strstr(buffer, CFG_PAR_DB_TYPE);
            if (param != NULL) {
                if (dbts[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_DB_TYPE);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_DB_TYPE"=%s %s", dbts, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            param = strstr(buffer, CFG_PAR_DB_FILE_NAME);
            if (param != NULL) {
                if (db_c->file[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_DB_FILE_NAME);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_DB_FILE_NAME"=%s %s", db_c->file, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            param = strstr(buffer, CFG_PAR_ROOT_DIR);
            if (param != NULL) {
                if (root_dir[0] != '\0' && root == FALSE) {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_ROOT_DIR);
                    return -1;
                }
                root = FALSE;
                res = sscanf(param, CFG_PAR_ROOT_DIR"=%s %s", root_dir, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            param = strstr(buffer, CFG_SSL_CERT);
            if (param != NULL) {
                if (cert[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_SSL_CERT);
                    return -1;
                }
                res = sscanf(param, CFG_SSL_CERT"=%s %s", cert, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
        }
    }
    fclose(fp);
    
    /* check data */
    if (dbts[0] == '\0') {
        LogPrintf(LV_ERROR, "Config file without DB type [%s]\n", CFG_PAR_DB_TYPE);
        return -1;
    }
    if (strcmp(dbts, DB_T_MYSQL) == 0) {
        db_c->type = DB_MYSQL;
    }
    else if (strcmp(dbts, DB_T_SQLITE) == 0) {
        db_c->type = DB_SQLITE;
    }
    else if (strcmp(dbts, DB_T_POSTGRES) == 0) {
        db_c->type = DB_POSTGRESQL;
    }
    else {
        LogPrintf(LV_ERROR, "Unknown DB type:%s\n", dbts);
        return -1;
    }

    switch (db_c->type) {
    case DB_MYSQL:
        printf("For DEMA with MySQL DB contact: xplico@evolka.it");
        return -1;
        break;

    case DB_SQLITE:
        if (db_c->file[0] == '\0') {
            LogPrintf(LV_ERROR, "Config file error. DB SQLite requires: %s\n", CFG_PAR_DB_FILE_NAME);
            return -1;
        }        
        break;

    case DB_POSTGRESQL:
        printf("For DEMA with POSTGRES DB contact: xplico@evolka.it");
        return -1;
        break;
    }

    return 0;
}


int DemaSol(int pol)
{
    int i, sol_id;

    pthread_mutex_lock(&pd_mux);
    for (i=0; i!=dim; i++) {
        if (pd_tbl[i].pol_id == pol)
            break;
    }
    sol_id = pd_tbl[i].sol_id;
    pthread_mutex_unlock(&pd_mux);

    return sol_id;
}


int main(int argc, char *argv[])
{
    char c;
    char config_file[DM_FILENAME_PATH];
    char root_dir[DM_FILENAME_PATH];
    char db_type[DM_FILENAME_PATH];
    char cert[DM_FILENAME_PATH];
    dbconf db_c;
    FILE *run;
    extern char *optarg;
    extern int optind, optopt;
    time_t twpcap;
    int ret;

    pthread_mutex_init(&pd_mux, NULL);
    pd_tbl = NULL;
    dim = 0;
    twpcap = DM_TIME_BETWEEN_PCAPS;
    config_file[0] = '\0';
    root_dir[0] = '\0';
    db_type[0] = '\0';
    cert[0] = '\0';
    memset(&db_c, '\0', sizeof(dbconf));
    while ((c = getopt(argc, argv, "ivc:d:b:h")) != -1) {
        switch(c) {
        case 'v':
            printf("dema %d.%d.%d\n", DEMA_VER_MAG, DEMA_VER_MIN, DEMA_VER_REV);
            return 0;
            break;
        case 'c':
            sprintf(config_file, "%s", optarg);
            break;

        case 'd':
            sprintf(root_dir, "%s", optarg);
            break;

        case 'b':
            sprintf(db_type, "%s", optarg);
            break;

        case 'h':
            printf("dema v%d.%d.%d\n", DEMA_VER_MAG, DEMA_VER_MIN, DEMA_VER_REV);
            printf("%s\n", DEMA_CR);
            Usage(argv[0]);
            return 0;
            break;

        case 'i':
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            Usage(argv[0]);
            exit(-1);
            break;
        }
    }
    
    LogCfg(config_file, root_dir);
    
    printf("dema v%d.%d.%d\n", DEMA_VER_MAG, DEMA_VER_MIN, DEMA_VER_REV);
    printf("%s\n", DEMA_CR);

    /* db type */
    if (strcmp(db_type, DB_T_SQLITE) == 0) {
        db_c.type = DB_SQLITE;
        sprintf(db_c.file, "%s/%s", root_dir, DBINT_DB_FILE_DEFAULT);
    }
    else if (config_file[0] == '\0') {
        if (strcmp(db_type, DB_T_MYSQL) == 0) {
            db_c.type = DB_MYSQL;
        }
        else if (strcmp(db_type, DB_T_POSTGRES) == 0) {
            db_c.type = DB_POSTGRESQL;
        }
        else {
            Usage(argv[0]);
        
            return 0;
        }
    }
    if (config_file[0] != '\0') {
        /* read config file */
        if (ReadConfigFile(config_file, &db_c, root_dir, &twpcap, cert) != 0) {
            Usage(argv[0]);
            
            return 0;
        }
    }

    if (root_dir[0] != '\0') {
        /* daemon */
        ret = daemon(1, 0);

        /* init db connection */
        if (DBIntInit(&db_c) != 0) {
            LogPrintf(LV_FATAL, "Error: DB interface\n");
            return -1;
        }

        /* kill all xplico running */
        system("killall xplico 2>/dev/null 1>/dev/null");

        /* sigterm function */
        terminate = FALSE;
        signal(SIGTERM, DemaSigTerm);

        /* init session params */
        SeDeInit(cert, root_dir);

        run = fopen(DM_DEMA_RUN, "w+");
        if (run != NULL) {
            fprintf(run, "%i\n", getpid());
            fclose(run);
            DemaLoop(&db_c, root_dir, twpcap);
        }
        /* close db connection */
        DBIntClose();
    }
    else {
        Usage(argv[0]);
    }

    return 0;
}
