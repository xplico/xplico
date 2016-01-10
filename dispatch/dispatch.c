/* dispatch.c
 * Dispatch interface
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2009 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <dlfcn.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

#include "dispatch.h"
#include "dispatch_dev.h"
#include "disp_manipula.h"
#include "config_param.h"
#include "dmemory.h"
#include "log.h"
#include "pei.h"
#include "proto.h"
#include "gearth_priv.h"


static void *handle;
static bool parallel;
static int (*DispInit)(const char *cfg_file);
static int (*DispEnd)(void);
static int (*DispInsPei)(pei *ppei);
static volatile pei_list *plist;        /* list of pei to be inseted in serial mode */
static volatile pei_list *plist_end;    /* last pei of list */
static pthread_mutex_t plist_mux;       /* mutex to access at list */
static pthread_cond_t plist_cond;       /* condiction to access at list */
static volatile unsigned long pei_ins;  /* pei inserted */
static volatile unsigned long pei_pend; /* pei pending */
static manip_con *manip;                /* manipulator connections array */
static unsigned short manip_num;        /* manipulators dim */
static char *config_path;               /* config file path */


static inline char *PeiStrCpy(const char *cpy)
{
    char *ret;
    int len;

    if (cpy == NULL)
        return NULL;
    
    len = strlen(cpy);
    ret = DMemMalloc(len+1);
    if (ret != NULL) {
        memcpy(ret, cpy, len);
        ret[len] = '\0';
    }

    return ret;
}


static void* DispatchAgent(void *arg)
{
    pei_list *pl;
    bool pret;

    LogPrintf(LV_START, "Serial mode");

    pthread_mutex_lock(&plist_mux);
    while (1) {
        if (plist == NULL) {
            /* wait new pei */
            pthread_cond_wait(&plist_cond, &plist_mux);
        }
        pl = (pei_list *)plist;
        plist = plist->nxt;
        if (plist == NULL) {
            plist_end = NULL;
        }
        pthread_mutex_unlock(&plist_mux);
        
        pret = pl->ppei->ret;

        /* insert pei */
        if (DispManipPutPei(pl->ppei) == -1) {
            DispInsPei(pl->ppei);

            /* free memory */
            if (pret == FALSE) {
                PeiFree(pl->ppei);
            }
        }

        /* wake up thread */
        if (pret) {
            pthread_cond_signal(&pl->cond);
        }
        else {
            /* pei inserted */
            pei_ins++; /* this is the only operation with this variable and with only one thread */
            DMemFree(pl);
        }
        pthread_mutex_lock(&plist_mux);
        pei_pend--; /* now the pei is inseted */
    }

    return NULL;
}


int DispatchInit(const char *file_cfg)
{
    FILE *fp;
    char module_dir[CFG_LINE_MAX_SIZE];
    char buffer[CFG_LINE_MAX_SIZE];
    char bufcpy[CFG_LINE_MAX_SIZE];
    char module_path[CFG_LINE_MAX_SIZE];
    char module_name[CFG_LINE_MAX_SIZE];
    char mask[CFG_LINE_MAX_SIZE];
    char manip_name[CFG_LINE_MAX_SIZE];
    char manip_host[CFG_LINE_MAX_SIZE];
    char manip_bin[CFG_LINE_MAX_SIZE];
    unsigned int manip_port;
    char *param;
    unsigned short logm;
    int res, nl, val, i;
    pthread_t pid;
    
    /* default */
    parallel = FALSE;
    pei_ins = 0;
    pei_pend = 0;
    manip = NULL;
    manip_num = 0;

    /* find directory location of module from config file */
    fp = fopen(file_cfg, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Config file can't be opened");
        return -1;
    }
    
    /* copy path */
    config_path = xmalloc(strlen(file_cfg) + 1);
    strcpy(config_path, file_cfg);

    /* modules */
    module_dir[0] = '\0';
    module_name[0] = '\0';
    manip_bin[0] = '\0';
    manip_host[0] = '\0';
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
            /* modules directory */
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
            /* dispatcher module name */
            param = strstr(buffer, CFG_PAR_DISPATCH"=");
            if (param != NULL) {
                if (module_name[0] != '\0') {
                    LogPrintf(LV_ERROR, "Config param error: param '%s' defined two times", CFG_PAR_DISPATCH);
                    return -1;
                }
                res = sscanf(param, CFG_PAR_DISPATCH"=%s %s", module_name, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        /* log mask */
                        res = strncmp(bufcpy, CFG_PAR_MODULE_LOG, strlen(CFG_PAR_MODULE_LOG));
                        if (res != 0) {
                            LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                            return -1;
                        }
                        param = strstr(param, CFG_PAR_MODULE_LOG);
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
                        /* set mask */
                        LogSetMask(LOG_COMPONENT, logm);
                    }
                }
            }

            /* parallel o serial insert */
            param = strstr(buffer, CFG_PAR_DISPATCH_PARAL);
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DISPATCH_PARAL"=%i %s", &val, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                        return -1;
                    }
                    else {
                        if (val == 1)
                            parallel = TRUE;
                        else
                            parallel = FALSE;
                    }
                }
            }

            /* manipulator connection info */
            param = strstr(buffer, CFG_PAR_DISPATCH_MANIP_NAME"=");
            if (param != NULL) {
                res = sscanf(param, CFG_PAR_DISPATCH_MANIP_NAME"=%s %s", manip_name, bufcpy);
                if (res > 0) {
                    if (res == 2 && !CfgParIsComment(bufcpy)) {
                        /* manipulator host */
                        res = strncmp(bufcpy, CFG_PAR_DISPATCH_MANIP_HOST, strlen(CFG_PAR_DISPATCH_MANIP_HOST));
                        if (res != 0) {
                            param = strstr(param, CFG_PAR_DISPATCH_MANIP_BIN);
                            if (param != NULL) {
                                res = sscanf(param, CFG_PAR_DISPATCH_MANIP_BIN"=%s %s", manip_bin, bufcpy);
                                if (res > 0) {
                                    /* inset manip in table */
                                    manip = xrealloc(manip, sizeof(manip_con)*(manip_num + 1));
                                    memset(&(manip[manip_num]), 0, sizeof(manip_con));
                                    strcpy(manip[manip_num].name, manip_name);
                                    strcpy(manip[manip_num].host, manip_host);
                                    strcpy(manip[manip_num].bin, manip_bin);
                                    manip[manip_num].port = 0;
                                    manip[manip_num].sock = -1;
                                    manip[manip_num].wait = FALSE;
                                    manip[manip_num].peil = NULL;
                                    manip[manip_num].peilast = NULL;
                                    /* check pei of protocol */
                                    manip[manip_num].pid = ProtId(manip[manip_num].name);
                                    manip[manip_num].mux = xmalloc(sizeof(pthread_mutex_t));
                                    pthread_mutex_init(manip[manip_num].mux, NULL);
                                    if (manip[manip_num].pid == -1) {
                                        LogPrintf(LV_WARNING, "Protocol Manipulator %s haven't PEI", manip[manip_num].name);
                                    }
                                    manip_num++;
                                }
                            }
                            else {
                                LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                                return -1;
                            }
                        }
                        else {
                            param = strstr(param, CFG_PAR_DISPATCH_MANIP_HOST);
                            res = sscanf(param, CFG_PAR_DISPATCH_MANIP_HOST"=%s %s", manip_host, bufcpy);
                            if (res > 0) {
                                if (res == 2 && !CfgParIsComment(bufcpy)) {
                                    res = strncmp(bufcpy, CFG_PAR_DISPATCH_MANIP_PORT, strlen(CFG_PAR_DISPATCH_MANIP_PORT));
                                    if (res != 0) {
                                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, bufcpy);
                                        return -1;
                                    }
                                    param = strstr(param, CFG_PAR_DISPATCH_MANIP_PORT);
                                    res = sscanf(param, CFG_PAR_DISPATCH_MANIP_PORT"=%d %s", &manip_port, bufcpy);
                                    if (res > 0) {
                                        if (res == 2 && !CfgParIsComment(bufcpy)) {
                                            LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                                            return -1;
                                        }
                                        /* inset manip in table */
                                        manip = xrealloc(manip, sizeof(manip_con)*(manip_num + 1));
                                        memset(&(manip[manip_num]), 0, sizeof(manip_con));
                                        strcpy(manip[manip_num].name, manip_name);
                                        strcpy(manip[manip_num].host, manip_host);
                                        manip[manip_num].bin[0] = '\0';
                                        manip[manip_num].port = manip_port;
                                        manip[manip_num].sock = -1;
                                        manip[manip_num].wait = FALSE;
                                        manip[manip_num].peil = NULL;
                                        manip[manip_num].peilast = NULL;
                                        /* check pei of protocol */
                                        manip[manip_num].pid = ProtId(manip[manip_num].name);
                                        manip[manip_num].mux = xmalloc(sizeof(pthread_mutex_t));
                                        pthread_mutex_init(manip[manip_num].mux, NULL);
                                        if (manip[manip_num].pid == -1) {
                                            LogPrintf(LV_WARNING, "Protocol Manipulator %s haven't PEI", manip[manip_num].name);
                                        }
                                        manip_num++;
                                    }
                                    else {
                                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                                        return -1;
                                    }
                                }
                                else {
                                    LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                                    return -1;
                                }
                            }
                            else {
                                LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                                return -1;
                            }
                        }
                    }
                    else {
                        LogPrintf(LV_ERROR, "Config param error in line %d. Unknow param: %s", nl, buffer);
                        return -1;
                    }
                }
            }
        }
    }
    fclose(fp);

    /* check name */
    if (module_name[0] == '\0') {
        LogPrintf(LV_WARNING, "The dispatch module isn't defined, will be used 'none' dispatch module");
        printf("The dispatch module isn't defined, will be used 'none' dispatch module\n");

        /* default dispatcher */
        strcpy(module_name, "disp_none.so");
    }

    /* module path */
    sprintf(module_path, "%s/%s", module_dir, module_name);

    /* open module */
    handle = dlopen(module_path, RTLD_NOW);
    if (handle == NULL) {
        printf("Can't load dispatch module %s\n", dlerror());
        return -1;
    }
    
    /* inizilizations of all software that can be used in dispatcer modules */
    /* gearth initialization */
    if (GearthInit(file_cfg) == -1) {
        return -1;
    }
    /* end inizilizations of all software that can be used in dispatcer modules */

    /* attach functions */
    DispInit = dlsym(handle, DISP_INIT_FUN);
    if (DispInit == NULL) {
        printf("Dispatch module don't contain function %s\n", DISP_INIT_FUN);
        return -1;
    }

    DispEnd = dlsym(handle, DISP_END_FUN);
    if (DispEnd == NULL) {
        printf("Dispatch module don't contain function %s\n", DISP_END_FUN);
        return -1;
    }

    DispInsPei = dlsym(handle, DISP_INDPEI_FUN);
    if (DispInsPei == NULL) {
        printf("Dispatch module don't contain function %s\n", DISP_INDPEI_FUN);
        return -1;
    }

    /* initialize dispatcher module */
    if (DispInit(file_cfg) == -1) {
        printf("Dispatch module initialization error\n");
        return -1;
    }
    
    if (DispManipInit() == -1) {
        printf("Dispatch to manipulator initialization error\n");
        return -1;
    }

    /* parallel or serial */
    pthread_mutex_init(&plist_mux, NULL);
    if (parallel == FALSE) {
        /* in this case single dissector that generate and insert one PEI call 'directly' the
           insert function of dispatcher module, otherwise a thread is the middelware from dissectors
           and dispatch function module */
        pthread_cond_init(&plist_cond, NULL);
        plist = NULL;
        plist_end = NULL;
        res = pthread_create(&pid, NULL, DispatchAgent, NULL);
        if (res != 0) {
            printf("Dispatch Agent setup failed");
            LogPrintf(LV_ERROR, "Dispatch Agent setup failed");
            return -1;
        }
        pthread_detach(pid);
    }

    /* manipeagtor info */
    for (i=0; i!=manip_num; i++) {
        LogPrintf(LV_START, "Manipulator ---> %s host:%s port:%d", manip[i].name, manip[i].host, manip[i].port);
    }

    return 0;
}


manip_con *DispatManip(int prot_id)
{
    manip_con *ret;
    int i;
    
#ifdef XPL_CHECK_CODE
    if (prot_id == -1) {
        LogPrintf(LV_FATAL, "Pei ID Protocol wrong ", __FUNCTION__);
        exit(-1);
    }
#endif
    ret = NULL;
    for (i=0; i!=manip_num; i++) {
        if (prot_id == manip[i].pid) {
            ret = manip + i;
            break;
        }
    }

    return ret;
}

void DispatManipOff(int prot_id)
{
    int i;
    
    for (i=0; i!=manip_num; i++) {
        if (prot_id == manip[i].pid) {
            close(manip[i].sock);
            manip[i].sock = -1;
            manip[i].wait = TRUE;
            break;
        }
    }
}


manip_con *DispatManipOffLine(void)
{
    manip_con *ret;
    int i;

    ret = NULL;
    for (i=0; i!=manip_num; i++) {
        if (manip[i].sock == -1) {
            ret = manip + i;
            break;
        }
    }
    
    return ret;
}


manip_con *DispatManipWait(void)
{
    manip_con *ret;
    int i;

    ret = NULL;
    for (i=0; i!=manip_num; i++) {
        if (manip[i].wait == TRUE) {
            ret = manip + i;
            break;
        }
    }
    
    return ret;
}


const char *DispatManipModulesCfg(void)
{
    return config_path;
}


int DispatchStatus(FILE *fp)
{
    if (fp == NULL)
        printf("Pei inserted: %lu\nPei to be insert: %lu\n", pei_ins, pei_pend);
    else
        fprintf(fp, "Pei inserted: %lu\nPei to be insert: %lu\n", pei_ins, pei_pend);
    
    return 0;
}


unsigned long DispatchPeiPending(void)
{
    return pei_pend;
}


int DispatchEnd(void)
{
    int ret;
    struct timespec to;
    
    /* wait pei insert */
    while (plist != NULL) {
        to.tv_nsec = 0;
        to.tv_sec = 1;
        nanosleep(&to, NULL);
    }
    while (pei_pend != 0) {
        /* waiting pei insertion */
        if (pei_pend < 0) {
            LogPrintf(LV_ERROR, "Bug in Dispatch, PEI negative!!!");
        }
        to.tv_nsec = 0;
        to.tv_sec = 1;
        nanosleep(&to, NULL);
    }

    ret = DispEnd();
    DispManipEnd();
    dlclose(handle);

    /* gerath end */
    GearthEnd();

    return ret;
}


int PeiInit(pei *ppei)
{
    memset(ppei, 0, sizeof(pei));

    return 0;
}


int PeiNew(pei **ppei, int prot_id)
{
    if (ppei == NULL) {
        return -1;
    }

    *ppei = DMemMalloc(sizeof(pei));
    if (*ppei == NULL) {
        return -1;
    }
    PeiInit(*ppei);
    (*ppei)->prot_id = prot_id;
    (*ppei)->time = time(NULL);

    return 0;
}


int PeiSetReturn(pei *ppei, bool ret)
{
    ppei->ret = ret;
    
    return 0;
}


bool PeiGetReturn(pei *ppei)
{    
    return ppei->ret;
}


int PeiParent(pei *ppei, pei *ppei_parent)
{
    ppei->pid = ppei_parent->id;
    
    return 0;
}


int PeiCapTime(pei *ppei, time_t time_cap)
{
    ppei->time_cap = time_cap;

    return 0;
}


int PeiDecodeTime(pei *ppei, time_t time_dec)
{
    ppei->time = time_dec;

    return 0;
}


int PeiStackFlow(pei *ppei, const pstack_f *stack)
{
    if (ppei->stack != NULL) {
        ProtDelFrame(ppei->stack);
    }
    ppei->stack = ProtCopyFrame(stack, TRUE);

    return 0;
}

int PeiMarker(pei *ppei, unsigned long serial)
{
    ppei->serial = serial;

    return 0;
}


int PeiNewComponent(pei_component **comp, int comp_id)
{
    if (comp == NULL) {
        return -1;
    }

    *comp = DMemMalloc(sizeof(pei_component));
    if (*comp == NULL) {
        return -1;
    }
    memset(*comp, 0, sizeof(pei_component));
    (*comp)->eid = comp_id;

    return 0;
}


int PeiCompAddFile(pei_component *comp, const char *file_name, const char *file_path, unsigned long file_size)
{
    struct stat st;

    if (file_name != NULL) {
        if (comp->name != NULL)
            DMemFree(comp->name);
        comp->name = PeiStrCpy(file_name);
    }
    if (comp->file_path != NULL)
        DMemFree(comp->file_path);
    comp->file_path = PeiStrCpy(file_path);
    if (file_size)
        comp->file_size = file_size;
    else {
        if (stat(comp->file_path, &st) == 0) {
            comp->file_size = st.st_size;
        }
    }

    return 0;
}


int PeiCompAddStingBuff(pei_component *comp, const char *strbuf)
{
    if (comp->strbuf != NULL)
        DMemFree(comp->strbuf);
    comp->strbuf = PeiStrCpy(strbuf);

    return 0;
}


int PeiCompCapTime(pei_component *comp, time_t time_cap)
{
    comp->time_cap = time_cap;
    comp->time_cap_end = time_cap;
    
    return 0;
}


int PeiCompCapEndTime(pei_component *comp, time_t time_cap_end)
{
    comp->time_cap_end = time_cap_end;

    return 0;
}


int PeiCompError(pei_component *comp, eerror err)
{
    comp->err = err;

    return 0;
}


int PeiCompUpdated(pei_component *comp)
{
    struct stat st;
    
    comp->changed = TRUE;
    
    if (comp->file_path != NULL) {
        if (stat(comp->file_path, &st) == 0) {
            comp->file_size = st.st_size;
        }
    }

    return 0;
}


pei_component *PeiCompSearch(pei *ppei, int comp)
{
    pei_component *cmp;
    
    cmp = ppei->components;
    while (cmp != NULL && cmp->eid != comp)
        cmp = cmp->next;

    return cmp;
}


int PeiAddComponent(pei *ppei, pei_component *comp)
{
    int i;
    pei_component **lcomp;

    if (ppei == NULL || comp == NULL) {
        return -1;
    }
    
    /* find last component */
    i = 0;
    lcomp = &ppei->components;
    while (*lcomp != NULL) {
        i++;
        lcomp = &((*lcomp)->next);
    }
    *lcomp = comp;
    comp->id = i;

    return 0;
}


int PeiAddStkGrp(pei *ppei, const pstack_f *add)
{
    pstack_f *new, *nxt;
    const pstack_f *flame_stk, *stk;
    int flow_par;
    
    /* check if the flow/stack is already insert */
    if (ppei->stack != NULL) {
        flame_stk = add;
        flow_par = -1;
        while (flame_stk != NULL && flame_stk->flow == FALSE) {
            flame_stk = flame_stk->pfp;
        }
        if (flame_stk != NULL) {
            flow_par = flame_stk->flow_id;
            stk = flame_stk;
            
            nxt = ppei->stack;
            while (nxt->gstack != NULL) {
                flame_stk = nxt->gstack;
                while (flame_stk != NULL && flame_stk->flow == FALSE) {
                    flame_stk = flame_stk->pfp;
                }
                if (flame_stk != NULL) {
                    if (flow_par == flame_stk->flow_id) {
                        if (ProtDiffFrame(stk, flame_stk, TRUE) == TRUE) {
                            /* it is a copy */
                            return 0;
                        }
                    }
                }
                nxt = nxt->gstack;
            }
        }
    }

    /* add */
    new = ProtCopyFrame(add, TRUE);
    if (ppei->stack != NULL) {
        nxt = ppei->stack;
        while (nxt->gstack != NULL)
            nxt = nxt->gstack;
        nxt->gstack = new;
    }
    else {
        ppei->stack = new;
    }

    return 0;
}


int PeiIns(pei *ppei)
{
    pei_list *pl;
    bool pret;
    int ret;

    /* end time */
    if (ppei != NULL) {
        ppei->time = time(NULL);
    }

    pret = ppei->ret;

    /* parallel/concurrent insert */
    if (parallel) {
        pthread_mutex_lock(&plist_mux);
        pei_pend++;
        pthread_mutex_unlock(&plist_mux);

        /* insert pei */
        if (DispManipPutPei(ppei) == -1) {
            ret = DispInsPei(ppei);
            
            /* free memory */
            if (pret == FALSE) {
                PeiFree(ppei);
            }
        }

        pthread_mutex_lock(&plist_mux);
        pei_pend--;
        if (pret == FALSE)
            pei_ins++;
        pthread_mutex_unlock(&plist_mux);

        return ret;
    }

    /* push in the list */
    pl = DMemMalloc(sizeof(pei_list));
    pl->ppei = ppei;
    if (pret) {
        pthread_cond_init(&pl->cond, NULL);
    }
    pl->nxt = NULL;
    pthread_mutex_lock(&plist_mux);
    pei_pend++;
    if (plist_end != NULL) {
        plist_end->nxt = pl;
        plist_end = pl;
    }
    else {
#ifdef XPL_CHECK_CODE
        if (plist != NULL) {
            LogPrintf(LV_FATAL, "Pei List error", __FUNCTION__);
            exit(-1);
        }
#endif
        plist = pl;
        plist_end = pl;
        /* standup DispatchAgent */
        pthread_cond_signal(&plist_cond);
    }
    if (pret) {
        pthread_cond_wait(&pl->cond, &plist_mux);
        pthread_cond_destroy(&pl->cond);
        DMemFree(pl);
    }
    pthread_mutex_unlock(&plist_mux);
   

    return 0;
}


int PeiFree(pei *ppei)
{
    pei_component *cmpn, *nxt;

    /* free components */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        nxt = cmpn->next;
        if (cmpn->strbuf != NULL)
            DMemFree(cmpn->strbuf);
        if (cmpn->name != NULL)
            DMemFree(cmpn->name);
        if (cmpn->file_path != NULL)
            DMemFree(cmpn->file_path);
        DMemFree(cmpn);
        cmpn = nxt;
    }

    /* free protocol stack */
    if (ppei->stack != NULL)
        ProtDelFrame(ppei->stack);

    DMemFree(ppei);

    return 0;
}


int PeiDestroy(pei *ppei)
{
    pei_component *cmpn, *nxt;

    /* free components */
    cmpn = ppei->components;
    while (cmpn != NULL) {
        nxt = cmpn->next;
        if (cmpn->strbuf != NULL)
            DMemFree(cmpn->strbuf);
        if (cmpn->name != NULL)
            DMemFree(cmpn->name);
        if (cmpn->file_path != NULL) {
            remove(cmpn->file_path);
            DMemFree(cmpn->file_path);
        }
        DMemFree(cmpn);
        cmpn = nxt;
    }
    ppei->components = NULL;
    
    /* free protocol stack */
    if (ppei->stack != NULL) {
        ProtDelFrame(ppei->stack);
        ppei->stack = NULL;
    }
    
    return 0;
}


void PeiPrint(const pei *ppei)
{
    pei_component *cmpn;
    char *tv;

    cmpn = ppei->components;
    LogPrintf(LV_INFO, "Protocol: %s", ProtLogName(ppei->prot_id));
    tv = xmalloc(10240);
    while (cmpn != NULL) {
        LogPrintf(LV_INFO, "Pei component: %i", cmpn->id);
        LogPrintf(LV_INFO, "\teid: %i", cmpn->eid);
        if (cmpn->strbuf != NULL)
            LogPrintf(LV_INFO, "\tstr: %s", cmpn->strbuf);
        if (cmpn->name != NULL)
            LogPrintf(LV_INFO, "\tname: %s", cmpn->name);
        if (cmpn->file_path != NULL) {
            LogPrintf(LV_INFO, "\tfile: %s", cmpn->file_path);
            LogPrintf(LV_INFO, "\tsize: %i", cmpn->file_size);
        }
        if (cmpn->time_cap != 0) {
            strcpy(tv, ctime((time_t *)&cmpn->time_cap));
            tv[strlen(tv)-1] = '\0';
            LogPrintf(LV_INFO, "\ttime: %s", tv);
        }
        if (cmpn->time_cap_end != 0) {
            strcpy(tv, ctime((time_t *)&cmpn->time_cap_end));
            tv[strlen(tv)-1] = '\0';
            LogPrintf(LV_INFO, "\tend time: %s", tv);
        }
        if (cmpn->err != ELMT_ER_NONE)
            LogPrintf(LV_INFO, "\terr: %i", cmpn->err);
        cmpn = cmpn->next;
    }
    xfree(tv);
}
