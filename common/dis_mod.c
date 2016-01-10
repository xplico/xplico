/* dis_mod.c
 * Dissector modules load and inizialization
 *
 * $Id:  $
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
#include <string.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <regex.h>

#include "flow.h"
#include "proto.h"
#include "dmemory.h"
#include "dis_mod.h"
#include "log.h"
#include "config_param.h"
#include "istypes.h"
#include "fthread.h"
#include "pei.h"

/* structures */
struct dm_module {
    char name[CFG_LINE_MAX_SIZE];    /* moduel name */
    char path[CFG_LINE_MAX_SIZE];    /* module path */
    unsigned short logm;             /* log mask    */
};


/* global variables */
prot_desc *prot_tbl;
int prot_tbl_dim;
bool report_splash;

/* crash info */
unsigned long crash_pkt_cnt; 
char *crash_ref_name;
extern volatile pei *volatile mnp_pei;

/* local variables */
static int prot_ins;
static char tmp_dir[CFG_LINE_MAX_SIZE];

/* local functions */
static void DisModGraph(int id, int *graph, int space)
{
    int i, j, k, h;
    int mod_num, add;
    bool skip;

    mod_num = prot_tbl_dim;
    if (graph == NULL) {
        graph = xmalloc(sizeof(int)*mod_num);
        memset(graph, 0, sizeof(int)*mod_num);
        printf("------------------------------------------\n");
        printf("------------- Protocol Graph -------------\n");
        printf("------------------------------------------\n");

        for (i=0; i<mod_num; i++) {
            add = 0;
            if (graph[i] == 0) {
                graph[i] = 3;
                printf("\033[%iC%s\n", space, prot_tbl[i].name);
                if (prot_tbl[i].stbl_dim != 0) {
                    printf("\033[%iC  |\n", space);
                }
                else {
                    graph[i] = -1;
                }
                for (j=0; j<prot_tbl[i].stbl_dim; j++) {
                    if (j != prot_tbl[i].stbl_dim-1) {
                        if (prot_tbl[i].stbl[j].id != prot_tbl[i].stbl[j+1].id) {
                            printf("\033[%iC  |--->%s\n", space, prot_tbl[prot_tbl[i].stbl[j].id].name);
                        }
                    }
                    else {
                        printf("\033[%iC  `--->%s\n", space, prot_tbl[prot_tbl[i].stbl[j].id].name);
                        graph[i] = -1;
                        add = 7;
                    }
                    for (h=0; h<mod_num; h++) {
                        for (k=100; k>1; k--) {
                            if (k == graph[h] && h != i) {
                                printf("\r\033[1A\033[%iC  |\n", k+4);
                            }
                        }
                    }
                    if (graph[prot_tbl[i].stbl[j].id] == 0) {
                        if (prot_tbl[prot_tbl[i].stbl[j].id].stbl_dim != 0) {
                            printf("\033[%iC  |\n", space+add);
                            for (h=0; h<mod_num; h++) {
                                for (k=100; k>1; k--) {
                                    if (k == graph[h]) {
                                        printf("\r\033[1A\033[%iC  |\n", k+4);
                                    }
                                }
                            }
                        }
                        DisModGraph(prot_tbl[i].stbl[j].id, graph, space+7);
                    }
                }
                printf("------------------------------------------\n");
            }
        }
        xfree(graph);
    }
    else {
        graph[id] = space+2;
        
        for (j=0; j<prot_tbl[id].stbl_dim; j++) {
            skip = FALSE;
            if (j != prot_tbl[id].stbl_dim-1) {
                if (prot_tbl[id].stbl[j].id != prot_tbl[id].stbl[j+1].id) {
                    printf("\033[%iC  |--->%s\n", space, prot_tbl[prot_tbl[id].stbl[j].id].name);
                }
                else
                    skip = TRUE;
            }
            else {
                printf("\033[%iC  `--->%s\n", space, prot_tbl[prot_tbl[id].stbl[j].id].name);
                graph[id] = -1;
            }
            if (!skip) {
                for (i=0; i<mod_num; i++) {
                    for (k=100; k>1; k--) {
                        if (k == graph[i] && i != id) {
                            printf("\r\033[1A\033[%iC  |\n", k+4-6);
                        }
                    }
                }
                if (graph[prot_tbl[id].stbl[j].id] == 0) {
                    if (prot_tbl[prot_tbl[id].stbl[j].id].stbl_dim != 0) {
                        printf("\033[%iC        |\n", space);
                        for (i=0; i<mod_num; i++) {
                            for (k=100; k>1; k--) {
                                if (k == graph[i]) {
                                    printf("\r\033[1A\033[%iC  |\n", k+4-6);
                                }
                            }
                        }
                    }
                    DisModGraph(prot_tbl[id].stbl[j].id, graph, space+6);
                }
            }
        }
        graph[id] = -1;
    }
}


void DisModProtInfo(const char *iana_name)
{
    int i, j;

    /* search protocol */
    for (i=0; i<prot_tbl_dim; i++) {
        if (strcmp(prot_tbl[i].name, iana_name) == 0) {
            /* list of info that protocol supply */
            printf("-----------------------------------------------------------\n");
            printf("%s: %s\n", prot_tbl[i].name, prot_tbl[i].desc);
            printf("-----------------------------------------------------------\n");
            if (prot_tbl[i].info_num > 0) {
                printf("Pkt info:\n");
                for (j=0; j<prot_tbl[i].info_num; j++) {
                    printf("\t%s: %s\n", prot_tbl[i].info[j].abbrev, prot_tbl[i].info[j].name);
                }
                printf("-----------------------------------------------------------\n");
            }
            if (prot_tbl[i].pei == TRUE) {
                printf("Pei components type:\n");
                for (j=0; j<prot_tbl[i].peic_num; j++) {
                    printf("\t%s: %s\n", prot_tbl[i].peic[j].abbrev, prot_tbl[i].peic[j].desc);
                }
                printf("-----------------------------------------------------------\n");
            }
            printf("-----------------------------------------------------------\n");

            return;
        }
    }
    
    /* list of all iana name */
    printf("Protocol '%s' not found\n", iana_name);
    printf("Protocol module loaded are:\n");
    for (i=0; i<prot_tbl_dim; i++) {
        printf("\t%s ... %s\n", prot_tbl[i].name, prot_tbl[i].desc);
    }
}


static void ProtCheck(int sig)
{
    int i;
    
    for (i=0; i!=prot_tbl_dim; i++) {
        if (prot_tbl[i].flow == TRUE) {
            if (prot_tbl[i].tver)
                ProtFlowTimeOutForce(i);
            else
                prot_tbl[i].tver = TRUE; /* it is not necessary to use the semaphore */
        }
    }
    
    alarm(PROT_FLOW_CHECK_FLOW);
}


static void SegFault(int sig)
{
    int fid;
    const pstack_f *stk;
    
    /* default handler */
    signal(SIGSEGV, SIG_DFL);

    LogPrintf(LV_OOPS, "SegFault");
    /* print flow stack of thread */
    fid = FthreadSelfFlowId();
    if (fid != -1) {
        stk = FlowStack(fid);
        ProtStackFrmDisp(stk, TRUE);
    }
    else {
        fflush(NULL);
        if (mnp_pei != NULL)
            LogPrintfPei(LV_OOPS, mnp_pei, "Fault data saved in xml file");
        LogPrintf(LV_ERROR, "Thread without xplico's protol-stack (possible main flow)"); 
    }
    /* save to file in wireshark filter format all flows active in the time of fault */
    LogFault("Segmentation Fault");
    printf("Segmentation Fault: see log file and report it to the developers: bug@xplico.org\n");
    fflush(NULL);
#if 0
    while (1)
        sleep(1);
#endif
    raise(SIGSEGV); /* call default handler*/
}


static void SigPipe(int sig)
{
    LogPrintf(LV_OOPS, "SigPipe: %s", strerror(errno));
}


static void SigUsr1(int sig)
{
    report_splash = TRUE;
}


/* global functions */
int DisModLoad(char *file_cfg)
{
    FILE *fp;
    struct dm_module *mod_list;
    char module_dir[CFG_LINE_MAX_SIZE];
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char mname[CFG_LINE_MAX_SIZE];
    char mask[CFG_LINE_MAX_SIZE];
    unsigned short logm;
    char *param;
    int mod_num;
    int res, nl;
    int i, j, k, h;
    bool son, rule;
    int stbl_dim;

    /* crash info */
    crash_pkt_cnt = 0;
    crash_ref_name = NULL;

    if (file_cfg == NULL) {
        LogPrintf(LV_ERROR, "Config file not found");
        return -1;
    }

    /* search module dir path and tmp dir path */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    module_dir[0] = '\0';
    tmp_dir[0] = '\0';
    nl = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check all line */
        if (strlen(buffer)+1 == CFG_LINE_MAX_SIZE) {
            LogPrintf(LV_ERROR, "Config file line more length to %d characters", CFG_LINE_MAX_SIZE);
            return -1;
        }
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_MODULES_DIR);
            if (param != NULL) {
                if (module_dir[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_MODULES_DIR);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_MODULES_DIR"=%s %s", module_dir, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                }
            }
            param = strstr(buffer, CFG_PAR_TMP_DIR_PATH);
            if (param != NULL) {
                if (tmp_dir[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_TMP_DIR_PATH);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_TMP_DIR_PATH"=%s %s", tmp_dir, bufcpy);
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
    LogPrintf(LV_START, "Modules dir: %s", module_dir);
    if (tmp_dir[0] == '\0') {
        /* local dir */
        tmp_dir[0] = '.';
        tmp_dir[1] = '\0';
    }
    else {
        if (mkdir(tmp_dir, 0x01FF) == -1 && errno != EEXIST) {
            LogPrintf(LV_ERROR, "No writable permision");
            return -1;
        }
    }
    LogPrintf(LV_START, "Tmp dir: %s", tmp_dir);

    /* modules list */
    fp = fopen(file_cfg, "r");
    mod_list = NULL;
    mod_num = 0;
    nl = 0;
    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        nl++;
        /* check i line comment */
        if (!CfgParIsComment(buffer)) {
            param = buffer;
            while (param[0] == ' ')
                param++;
            if (param[0] != '\0') {
                /*name */
                res = sscanf(param, CFG_PAR_MODULE_NAME"=%s %s", mname, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        /* log mask */
                        res = strncmp(bufcpy, CFG_PAR_MODULE_LOG, strlen(CFG_PAR_MODULE_LOG));
                        if (res != 0) {
                            LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                            return -1;
                        }
                        param = strstr(buffer, CFG_PAR_MODULE_LOG);
                        res = sscanf(param, CFG_PAR_MODULE_LOG"=%s %s", mask, bufcpy);
                        logm = LV_BASE;
                        if (res > 0) {
                            if (res == 2 && !CfgParIsComment(bufcpy)) {
                                LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                                return -1;
                            }
                            logm |= CfgParLogMask(mask, nl);
                        }
                        else {
                            LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                            return -1;
                        }
                        /* new module */
                        LogPrintf(LV_START, "Module ---> %s log --> %s", mname, mask);
                        mod_list = xrealloc(mod_list, sizeof(struct dm_module)*(mod_num+1));
                        memset(&mod_list[mod_num], 0, sizeof(struct dm_module));
                        strcpy(mod_list[mod_num].name, mname);
                        sprintf(mod_list[mod_num].path, "%s/%s", module_dir, mname);
                        mod_list[mod_num].logm = logm;
                        mod_num++;
                    }
                }
            }
        }
    }
    fclose(fp);

    /* protocol table */
    prot_tbl = xmalloc(sizeof(prot_desc)*mod_num);
    memset(prot_tbl, 0, sizeof(prot_desc)*mod_num);
    prot_tbl_dim = mod_num;
    /* module register */
    for (i=0; i<mod_num; i++) {
        prot_tbl[i].log_mask = mod_list[i].logm;
        pthread_mutex_init(&prot_tbl[i].rl_mux, NULL);
        pthread_mutex_init(&prot_tbl[i].mux, NULL);
#ifdef XPL_PEDANTIC_STATISTICS
        pthread_mutex_init(&prot_tbl[i].cnt_mux, NULL);
#endif
        prot_tbl[i].rl_nesting = 0;
        prot_tbl[i].nesting = 0;
        prot_tbl[i].handle = dlopen(mod_list[i].path, RTLD_NOW);
        /* open module */
        if (prot_tbl[i].handle == NULL) {
            LogPrintf(LV_ERROR, "Can't load module %s",  dlerror());
            return -1;
        }
        /* attach functions */
        prot_tbl[i].DissecRegist = dlsym(prot_tbl[i].handle, DISMOD_REGIST_FUN);
        if (prot_tbl[i].DissecRegist == NULL) {
            LogPrintf(LV_ERROR, "In module %s don't exist function %s", mod_list[i].path, DISMOD_REGIST_FUN);
            return -1;
        }
        prot_tbl[i].DissectInit = dlsym(prot_tbl[i].handle, DISMOD_INIT_FUN);
        if (prot_tbl[i].DissectInit == NULL) {
            LogPrintf(LV_ERROR, "In module %s doesn't exist function %s", mod_list[i].path, DISMOD_INIT_FUN);
            return -1;
        }
        prot_tbl[i].DissectLog = dlsym(prot_tbl[i].handle, DISMOD_LOG_FUN);
        if (prot_tbl[i].DissectLog == NULL) {
            LogPrintf(LV_ERROR, "In module %s doesn't exist function %s", mod_list[i].path, DISMOD_LOG_FUN);
            return -1;
        }
        prot_tbl[i].FlowHash = dlsym(prot_tbl[i].handle, DISMOD_FLOW_HASH);
        prot_tbl[i].FlowCmp = dlsym(prot_tbl[i].handle, DISMOD_FLOW_CMP);
        prot_tbl[i].FlowCmpFree = dlsym(prot_tbl[i].handle, DISMOD_FLOW_CMPFREE);
    }

    /* protocol log initializazione and self registration */
    prot_ins = -1;
    for (i=0; i!=mod_num; i++) {
        prot_ins = i;
        prot_tbl[i].DissectLog(i);
        if (prot_tbl[i].FlowCmp != NULL || prot_tbl[i].FlowHash != NULL || prot_tbl[i].FlowCmpFree != NULL)
            prot_tbl[i].flow = TRUE;
        prot_tbl[i].DissecRegist(file_cfg);
    }
    prot_ins = -1;

    /* cross dependence to crerate protocol son */
    for (i=0; i<mod_num; i++) {
        /* dependece */
        for (k=0; k<prot_tbl[i].dep_num; k++) {
            j = h = 0;
            son = FALSE;
            while (j<mod_num && son == FALSE) {
                /* search protocol */
                if (strcmp(prot_tbl[i].dep[k].name, prot_tbl[j].name) != 0) {
                    j++;
                    continue;
                }
                /* search info to match */
                h = 0;
                while (h<prot_tbl[j].info_num && son == FALSE){
                    if (strcmp(prot_tbl[i].dep[k].attr, prot_tbl[j].info[h].abbrev) == 0)
                        son = TRUE;
                    else
                        h++;
                }
                if (son == FALSE)
                    j++;
            }
            
            /* dep find or not */
            if (son == FALSE) {
                LogPrintf(LV_WARNING, "dissector '%s' dependence '%s->%s' not found", prot_tbl[i].name,
                          prot_tbl[i].dep[k].name, prot_tbl[i].dep[k].attr);
            }
            else {
                /* check ftype */
                if (prot_tbl[i].dep[k].type != prot_tbl[j].info[h].type) {
                    LogPrintf(LV_ERROR, "Type mismatch in dependence '%s' of protocol '%s'", prot_tbl[i].name, prot_tbl[i].dep[k].name);
                    return -1;
                }

                /* insert son */
                stbl_dim = prot_tbl[j].stbl_dim;
                prot_tbl[j].stbl = xrealloc(prot_tbl[j].stbl, sizeof(proto_son)*(stbl_dim+1));
                memset(&prot_tbl[j].stbl[stbl_dim], 0, sizeof(proto_son));
                prot_tbl[j].stbl[stbl_dim].id = i;
                prot_tbl[j].stbl[stbl_dim].dep = &prot_tbl[i].dep[k];
                prot_tbl[j].stbl[stbl_dim].info = &prot_tbl[j].info[h];
                prot_tbl[j].stbl[stbl_dim].sfpaid = h;
                prot_tbl[j].stbl[stbl_dim].heu_dep = NULL;
                prot_tbl[j].stbl_dim++;
            }
        }
        /* heuristic dependece */
        for (k=0; k<prot_tbl[i].heu_num; k++) {
            j = 0;
            son = FALSE;
            while (j<mod_num && son == FALSE) {
                /* search protocol */
                if (strcmp(prot_tbl[i].heu_dep[k].name, prot_tbl[j].name) != 0) {
                    j++;
                }
                else {
                    son = TRUE;
                }
            }
            
            /* dep find or not */
            if (son == FALSE) {
                LogPrintf(LV_WARNING, "dissector '%s' heurystic dependence '%s' not found", prot_tbl[i].name,
                          prot_tbl[i].heu_dep[k].name);
            }
            else {
                /* insert son */
                stbl_dim = prot_tbl[j].stbl_dim;
                prot_tbl[j].stbl = xrealloc(prot_tbl[j].stbl, sizeof(proto_son)*(stbl_dim+1));
                memset(&prot_tbl[j].stbl[stbl_dim], 0, sizeof(proto_son));
                prot_tbl[j].stbl[stbl_dim].id = i;
                prot_tbl[j].stbl[stbl_dim].dep = NULL;
                prot_tbl[j].stbl[stbl_dim].info = NULL;
                prot_tbl[j].stbl[stbl_dim].sfpaid = -1;
                prot_tbl[j].stbl[stbl_dim].heu_dep = &prot_tbl[i].heu_dep[k];
                prot_tbl[j].stbl_dim++;
            }
        }
    }

    /* check consistency of dissector packet and flow */
    for (i=0; i<mod_num; i++) {
        if (prot_tbl[i].FlowDis == NULL && prot_tbl[i].grp == TRUE) {
            LogPrintf(LV_WARNING, "In dissector '%s' isn't defined FlowDissector but it's a flow of group",
                      prot_tbl[i].name);
        }
        for (j=0; j<prot_tbl[i].stbl_dim; j++) {
            if (prot_tbl[i].PktDis == NULL && prot_tbl[i].dep_num == 0) {
                LogPrintf(LV_ERROR, "In dissector '%s' isn't defined PktDissector",
                          prot_tbl[i].name);
                return -1;
            }
            if (prot_tbl[i].flow == FALSE) {
                if (prot_tbl[prot_tbl[i].stbl[j].id].PktDis == NULL) {
                    LogPrintf(LV_ERROR, "In dissector '%s' isn't defined PktDissector (%s)",
                              prot_tbl[prot_tbl[i].stbl[j].id].name, prot_tbl[i].name);
                    return -1;
                }
            }
            else {
                if (prot_tbl[prot_tbl[i].stbl[j].id].FlowDis == NULL &&
                    prot_tbl[prot_tbl[i].stbl[j].id].PktDis == NULL) {
                    LogPrintf(LV_ERROR, "In dissector '%s' aren't defined PktDissector and FlowDissector", prot_tbl[prot_tbl[i].stbl[j].id].name);
                    return -1;
                }
                if (prot_tbl[prot_tbl[i].stbl[j].id].FlowDis == NULL)
                    LogPrintf(LV_WARNING, "Assume '%s' protocol flow dissector as exstension of packet dissector in case of '%s' protocol", prot_tbl[prot_tbl[i].stbl[j].id].name, prot_tbl[i].name);
            }
        }
    }

    /* rule estrapolation */
    for (i=0; i!=mod_num; i++) {
        if (prot_tbl[i].flow == TRUE) {
            rule = TRUE;
            if (prot_tbl[i].FlowCmp == NULL || prot_tbl[i].FlowHash == NULL || prot_tbl[i].FlowCmpFree == NULL)
                rule = FALSE;
            if (rule == FALSE) {
                LogPrintf(LV_WARNING, "In dissector '%s' doesn't exist valid rules", prot_tbl[i].name);
                return -1;
            }
        }
    }

    /* stack frame real size */
    for (i=0; i!=mod_num; i++) {
        prot_tbl[i].pstack_sz = sizeof(pstack_f) + sizeof(ftval)*prot_tbl[i].info_num;
        LogPrintf(LV_INFO, "'%s' stack frame size: %db with %d info", prot_tbl[i].name, prot_tbl[i].pstack_sz, prot_tbl[i].info_num);
    }
    
    /* free memory */
    if (mod_list != NULL)
        xfree(mod_list);

    return 0;
}


int DisModInit(void)
{
    int i;

    for (i=0; i<prot_tbl_dim; i++) {
        if (prot_tbl[i].DissectInit() != 0) {
            LogPrintf(LV_ERROR, "Protocol '%s' initialization error.", prot_tbl[i].name);
            return -1;
        }
    }

    signal(SIGALRM, ProtCheck);
    alarm(PROT_FLOW_CHECK_FLOW);

    signal(SIGPIPE, SigPipe);
    signal(SIGSEGV, SegFault);
    signal(SIGUSR1, SigUsr1);

    return 0;
}


int DisModClose(void)
{
    int i;

    for (i=0; i<prot_tbl_dim; i++) {
        if (prot_tbl[i].handle != NULL) {
            dlclose(prot_tbl[i].handle);
            prot_tbl[i].handle = NULL;
        }
    }

    return 0;
}


void DisModProtGraph(void)
{
    /* protocol graph */
    DisModGraph(0, NULL, 0);
}


int ProtInfo(proto_info *ppinfo)
{
    int inf_n;

    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }

    /* insert */
    inf_n = prot_tbl[prot_ins].info_num;
    prot_tbl[prot_ins].info = xrealloc(prot_tbl[prot_ins].info, sizeof(proto_info)*(inf_n+1));
    memset(&(prot_tbl[prot_ins].info[inf_n]), 0,  sizeof(proto_info));
    prot_tbl[prot_ins].info[inf_n].name = xmalloc(strlen(ppinfo->name)+1);
    strcpy(prot_tbl[prot_ins].info[inf_n].name, ppinfo->name);
    prot_tbl[prot_ins].info[inf_n].abbrev = xmalloc(strlen(ppinfo->abbrev)+1);
    strcpy(prot_tbl[prot_ins].info[inf_n].abbrev, ppinfo->abbrev);
    prot_tbl[prot_ins].info[inf_n].type = ppinfo->type;

    prot_tbl[prot_ins].info_num++;

    return inf_n;
}


int ProtDep(proto_dep *ppdep)
{
    int dep_n;

    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }
    
    /* insert */
    dep_n = prot_tbl[prot_ins].dep_num;
    prot_tbl[prot_ins].dep = xrealloc(prot_tbl[prot_ins].dep, sizeof(proto_dep)*(dep_n+1));
    memset(&prot_tbl[prot_ins].dep[dep_n], 0, sizeof(proto_dep));
    prot_tbl[prot_ins].dep[dep_n].name = xmalloc(strlen(ppdep->name)+1);
    strcpy(prot_tbl[prot_ins].dep[dep_n].name, ppdep->name);
    prot_tbl[prot_ins].dep[dep_n].attr = xmalloc(strlen(ppdep->attr)+1);
    strcpy(prot_tbl[prot_ins].dep[dep_n].attr, ppdep->attr);
    prot_tbl[prot_ins].dep[dep_n].type = ppdep->type;
    FTCopy(&(prot_tbl[prot_ins].dep[dep_n].val), &(ppdep->val), ppdep->type);
    if (ppdep->op == FT_OP_REX) {
        /* compile regular expression */
        if (regcomp(&(prot_tbl[prot_ins].dep[dep_n].opd), ppdep->val.str, REG_ICASE) != 0) {
            LogPrintf(LV_ERROR, "Regular expression errror (%s) in %s dissector", ppdep->val.str, prot_tbl[prot_ins].name);
            return -1;
        }
    }
    prot_tbl[prot_ins].dep[dep_n].op = ppdep->op;
    prot_tbl[prot_ins].dep[dep_n].ProtCheck = ppdep->ProtCheck;
    if (ppdep->pktlim != 0)
        prot_tbl[prot_ins].dep[dep_n].pktlim = ppdep->pktlim;
    else
        prot_tbl[prot_ins].dep[dep_n].pktlim = USHRT_MAX;

    prot_tbl[prot_ins].dep_num++;

    return dep_n;
}


int ProtHeuDep(proto_heury_dep *ppedep)
{
    int heu_num;

    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }

    /* insert */
    if (ppedep->ProtCheck == NULL) {
        LogPrintf(LV_ERROR, "ProtCheck of heurystics dependence is NULL");
        return -1;
    }

    heu_num = prot_tbl[prot_ins].heu_num;
    prot_tbl[prot_ins].heu_dep = xrealloc(prot_tbl[prot_ins].heu_dep, sizeof(proto_heury_dep)*(heu_num+1));
    memset(&prot_tbl[prot_ins].heu_dep[heu_num], 0, sizeof(proto_heury_dep));
    prot_tbl[prot_ins].heu_dep[heu_num].name = xmalloc(strlen(ppedep->name)+1);
    strcpy(prot_tbl[prot_ins].heu_dep[heu_num].name, ppedep->name);
    prot_tbl[prot_ins].heu_dep[heu_num].ProtCheck = ppedep->ProtCheck;
    if (ppedep->pktlim != 0)
        prot_tbl[prot_ins].heu_dep[heu_num].pktlim = ppedep->pktlim;
    else
        prot_tbl[prot_ins].heu_dep[heu_num].pktlim = USHRT_MAX;

    prot_tbl[prot_ins].heu_num++;

    return heu_num;
}


int ProtName(char *name, char *abbr)
{
    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }

    /* description */
    if (prot_tbl[prot_ins].desc != NULL) {
        LogPrintf(LV_ERROR, "%s: name already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].desc = xmalloc(strlen(name)+1);
        strcpy(prot_tbl[prot_ins].desc, name);
    }

    /* name */
    if (prot_tbl[prot_ins].name != NULL) {
        LogPrintf(LV_ERROR, "%s: abbr already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].name = xmalloc(strlen(abbr)+1);
        strcpy(prot_tbl[prot_ins].name, abbr);
    }
    
    return 0;
}


int ProtAddRule(char *rule)
{
    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }

    if (prot_tbl[prot_ins].FlowHash == NULL || prot_tbl[prot_ins].FlowCmp == NULL || prot_tbl[prot_ins].FlowCmpFree == NULL) {
        LogPrintf(LV_FATAL, "The dissector '%s' is too old.", prot_tbl[prot_ins].name);
        printf("The dissector '%s' is too old.\n", prot_tbl[prot_ins].name);
        exit(-1);

        return -1;
    }
    
    return 0;
}


int ProtPeiComponent(pei_cmpt *ppeic)
{
    int piec_num;

    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in DissecRegist function", __FUNCTION__);
        return -1;
    }

    /* set a protocol as pei generator */
    prot_tbl[prot_ins].pei = TRUE;

    /* insert new component */
    piec_num = prot_tbl[prot_ins].peic_num;
    prot_tbl[prot_ins].peic = xrealloc(prot_tbl[prot_ins].peic, sizeof(pei_cmpt)*(piec_num+1));
    memset(&prot_tbl[prot_ins].peic[piec_num], 0, sizeof(pei_cmpt));
    prot_tbl[prot_ins].peic[piec_num].desc = xmalloc(strlen(ppeic->desc)+1);
    strcpy(prot_tbl[prot_ins].peic[piec_num].desc, ppeic->desc);
    prot_tbl[prot_ins].peic[piec_num].abbrev = xmalloc(strlen(ppeic->abbrev)+1);
    strcpy(prot_tbl[prot_ins].peic[piec_num].abbrev, ppeic->abbrev);
    prot_tbl[prot_ins].peic_num++;

    return piec_num; /* component id */
}


int ProtGrpEnable(void)
{
    if (prot_ins == -1) {
        LogPrintf(LV_FATAL, "%s can be used only in DissecRegist function", __FUNCTION__);
        exit(-1);
        return -1;
    }
    
    /* set a protocol as group of flow */
    prot_tbl[prot_ins].grp = TRUE;

    return 0;
}


int ProtDissectors(PktDissector p_dis, FlowDissector f_dis, GroupFlow g_flow, PktDissector dflt_subdis)
{
    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in function DissecRegist", __FUNCTION__);
        return -1;
    }
    
    /* insert */
    if (prot_tbl[prot_ins].PktDis != NULL) {
        LogPrintf(LV_ERROR, "PktDissector already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].PktDis = p_dis;
    }
    if (prot_tbl[prot_ins].FlowDis != NULL) {
        LogPrintf(LV_ERROR, "FlowDissector already inizializated", __FUNCTION__);
    }
    else {
        prot_tbl[prot_ins].FlowDis = f_dis;
    }
    if (prot_tbl[prot_ins].GrpFlow != NULL) {
        LogPrintf(LV_ERROR, "GroupFlow already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].GrpFlow = g_flow;
    }
    if (prot_tbl[prot_ins].DflSubDis != NULL) {
        LogPrintf(LV_ERROR, "PktDissector already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].DflSubDis = dflt_subdis;
    }

    return 0;
}


int ProtSubDissectors(FlowSubDissector p_sdis)
{
    if (prot_ins == -1) {
        LogPrintf(LV_ERROR, "%s can be used only in function DissecRegist", __FUNCTION__);
        return -1;
    }
    
    /* insert */
    if (prot_tbl[prot_ins].SubDis != NULL) {
        LogPrintf(LV_ERROR, "PktSubDissector already inizializated", __FUNCTION__);
        return -1;
    }
    else {
        prot_tbl[prot_ins].SubDis = p_sdis;
    }

    return 0;
}


const char* ProtTmpDir(void)
{
    return tmp_dir;
}


/* protocol of manipulator */
int ManipPeiProtocol(int prot_id)
{
    prot_ins = prot_id;

    return 0;
}


int ManipPeiRegister(void)
{
    prot_ins = -1;

    return 0;
}


int ManipTmpDir(char *file_cfg)
{
    FILE *fp;
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char *param;
    int res;

    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }

    while (fgets(buffer, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(buffer)) {
            param = strstr(buffer, CFG_PAR_TMP_DIR_PATH);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_TMP_DIR_PATH"=%s %s", tmp_dir, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error. Unknow param: %s", bufcpy);
                        return -1;
                    }
                }
            }
        }
    }
    fclose(fp);

    if (tmp_dir[0] != '\0') {
        if (mkdir(tmp_dir, 0x01FF) == -1 && errno != EEXIST) {
            LogPrintf(LV_ERROR, "No writable permision");
            return -1;
        }
    }

    return 0;
}
