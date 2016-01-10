/* analyse.c
 * analyse stack and time to realise pei
 *
 * $Id:  $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdlib.h>
#include <sys/wait.h>

#include "log.h"
#include "analyse.h"
#include "proto.h"
#include "dmemory.h"
#include "pei.h"

#define HTTPFILE_TMP_DIR      "httpfile"
#define HTTPFILE_ADD_LIST     10
#define HTTPFILE_FILE_DIM     (1024*1024)


/* http id */
static int http_id;
static int http_encoding_id;
/* httpfd */
static int prot_id;
static int pei_url_id;
static int pei_file_id;
static int pei_range_id;
static int pei_content_type;
static int pei_parts_id;
static int pei_complete_id;

/* list file */
static file_http *list; /* file list */
static long list_dim; /* file list dim */
static long incr; /* counter */
static unsigned long tt_num; /* total file recomposed (100% and not) */

static int HFileExt(void)
{
    static file_http *tmp;
    long i;

    tmp = xrealloc(list, sizeof(file_http)*(list_dim + HTTPFILE_ADD_LIST));
    if (tmp != NULL) {
        list = tmp;
        for (i=0; i!=HTTPFILE_ADD_LIST; i++) {
            memset(&(list[list_dim+i]), 0, sizeof(file_http));
        }
        list_dim += HTTPFILE_ADD_LIST;
        
        return 0;
    }
        
    return -1;
}


static int HFilePartSort(const void *a, const void *b)
{
    file_part *ap, *bp;

    ap = (file_part *)a;
    bp = (file_part *)b;
    
    if (ap->start < bp->start)
        return -1;
    else if (ap->start > bp->start)
        return 1;
    return 0;
}


static pei *HFileElab(const char *url, const char *file, size_t len, const char *range, const char *ct, const pei *lpei)
{
    long i, j, k, add;
    pei *ppei, *new;
    unsigned long bstart, bend, bdim;
    char *file_name, *tmp;
    FILE *fp, *fpr;
    size_t rd;
    bool complete;
    pei_component *cmpn;
    file_part *parts;
    long parts_dim;
    struct stat file_st;

    ppei = NULL;
    add = -1;
    
    /* reseacrh file */
    for (i=0; i!=list_dim; i++) {
        if (strcmp(url, list[i].url) == 0) {
            break;
        }
        else if (add == -1 && list[i].url[0] == '\0') {
            add = i;
        }
    }
    if (range != NULL) {
        sscanf(range, "%lu-%lu/%lu", &bstart, &bend, &bdim);
        bend = bstart+len-1;
    }
    else {
        LogPrintfPei(LV_DEBUG, lpei, "No range");
        bstart = 0;
        bend = bstart+len-1;
        bdim = len + 1; /* in this way the file is not completed (see comp_note) */
    }
    if (i == list_dim) {
        /* new file */
        if (add == -1) {
            add = list_dim;
            if (HFileExt() == -1) {
                LogPrintf(LV_ERROR, "Unable to extend file manager table!");
                return NULL;
            }
        }
        /* insert basic data */
        strcpy(list[add].url, url);
        sprintf(list[add].file, "%s/%s/httpfile_%lld_%p_%li", ProtTmpDir(), HTTPFILE_TMP_DIR, (long long)time(NULL), list, incr);
        sprintf(list[add].part_list, "%s/%s/httpfile_part_%lld_%p_%li", ProtTmpDir(), HTTPFILE_TMP_DIR, (long long)time(NULL), file, incr++);
        LogPrintf(LV_DEBUG, "File(%i): %s", bdim, list[add].part_list);
        if (ct != NULL) {
            sprintf(list[add].content_type, "%s", ct);
        }
        
        list[add].range = FALSE;
        fp = fopen(list[add].file, "w");
        if (fp != NULL) {
            tmp = xcalloc(1, HTTPFILE_FILE_DIM);
            for (j=0; j!=(long)(bdim/HTTPFILE_FILE_DIM); j++) {
                fwrite(tmp, 1, HTTPFILE_FILE_DIM, fp);
            }
            fwrite(tmp, 1, (bdim%HTTPFILE_FILE_DIM), fp);
            fclose(fp);
            xfree(tmp);
        }
        file_name = strrchr(url, '/');
        if (file_name == NULL) {
            file_name = strrchr(url, '\\');
        }
        if (file_name == NULL) {
            strcpy(list[add].file_name, url);
        }
        else {
            strcpy(list[add].file_name, file_name+1);
        }
        list[add].dim = bdim;
        list[add].len = 0;
        list[add].cnt = 0;
        /* create a PEI */
        PeiNew(&new, prot_id);
        list[add].ppei = new;
        PeiSetReturn(new, TRUE);
        PeiCapTime(new, lpei->time_cap);
        PeiMarker(new, lpei->serial);
        PeiStackFlow(new, lpei->stack);
        /* url */
        PeiNewComponent(&cmpn, pei_url_id);
        PeiCompCapTime(cmpn, lpei->time_cap);
        PeiCompAddStingBuff(cmpn, url);
        PeiAddComponent(new, cmpn);
        /* content type */
        if (ct != NULL) {
            PeiNewComponent(&cmpn, pei_content_type);
            PeiCompCapTime(cmpn, lpei->time_cap);
            PeiCompAddStingBuff(cmpn, ct);
            PeiAddComponent(new, cmpn);
        }
        
        i = add;
    }
    /* range file or not */
    if (list[i].range == FALSE) {
        if (range != NULL) {
            /* real size of file */
            if (stat(list[i].file, &file_st) == 0) {
                fp = fopen(list[i].file, "a");
                if (fp != NULL) {
                    tmp = xcalloc(1, HTTPFILE_FILE_DIM);
                    for (j=0; j!= (bdim-file_st.st_size)/HTTPFILE_FILE_DIM; j++) {
                        fwrite(tmp, 1, HTTPFILE_FILE_DIM, fp);
                    }
                    fwrite(tmp, 1, ((bdim-file_st.st_size)%HTTPFILE_FILE_DIM), fp);
                    fclose(fp);
                    xfree(tmp);
                }
                list[i].range = TRUE;
                list[i].dim = bdim;
                LogPrintf(LV_DEBUG, "Size: %lu", bdim);
            }
        }
    }
    /* compose file */
    fp = fopen(list[i].file, "r+");
    if (fp != NULL) {
        fseek(fp, bstart, SEEK_SET);
        fpr = fopen(file, "r");
        if (fpr != NULL) {
            tmp = xmalloc(HTTPFILE_FILE_DIM);
            rd = fread(tmp, 1, HTTPFILE_FILE_DIM, fpr);
            while (rd) {
                fwrite(tmp, 1, rd, fp);
                rd = fread(tmp, 1, HTTPFILE_FILE_DIM, fpr);
            }
            fclose(fpr);
            xfree(tmp);
        }
        else {
            LogPrintfPei(LV_ERROR, lpei, "Unable to open file: %s", file);
        }
        fclose(fp);
    }
    else {
        LogPrintfPei(LV_ERROR, lpei, "Unable to open file: %s", list[i].file);
    }
    remove(file);
    list[i].len += len;
    list[i].cnt++;
    /* add stack */
    PeiAddStkGrp(list[i].ppei, lpei->stack);

    /* update file of parts */
    fp = fopen(list[i].part_list, "a");
    if (fp != NULL) {
        fprintf(fp, "%lu %lu\n", bstart, bend);
        LogPrintf(LV_DEBUG, "start:%lu  end:%lu", bstart, bend);
        fclose(fp);
    }

    /* file completed ? */
    complete = FALSE;
    if (list[i].len >= list[i].dim) {
        complete = TRUE;
        fp = fopen(list[i].part_list, "r");
        if (fp != NULL) {
            /* load part info */
            parts_dim = list[i].cnt;
            j = 0;
            parts = xcalloc(1, sizeof(file_part)*parts_dim);
            while (fscanf(fp, "%lu %lu", &bstart, &bend) == 2) {
                parts[j].start = bstart;
                parts[j].end = bend;
                j++;
            }
            fclose(fp);
            if (parts_dim != j) {
                LogPrintfPei(LV_ERROR, lpei, "Number of parts (%i != %i)", parts_dim, j);
            }
            /* sort info */
            qsort(parts, j, sizeof(file_part), HFilePartSort);
            /* check file completiton */
            if (parts[0].start != 0) {
                complete = FALSE;
            }
            bdim = parts[0].end - parts[0].start + 1;
            for (k=1; k!=j; k++) {
                if (parts[k].start > (parts[k-1].end + 1)) {
                    complete = FALSE;
                    bdim += parts[k].end - parts[k].start + 1;
                }
                else {
                    bdim += parts[k].end - parts[k-1].end;
                }
            }
            xfree(parts);
    
            if (complete && bdim == list[i].dim) {
                /* complete pei */
                ppei = list[i].ppei;
                /* file */
                PeiNewComponent(&cmpn, pei_file_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompCapEndTime(cmpn, lpei->time_cap);
                PeiCompAddFile(cmpn, list[i].file_name, list[i].file, 0);
                PeiAddComponent(ppei, cmpn);
                /* part */
                PeiNewComponent(&cmpn, pei_parts_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompCapEndTime(cmpn, lpei->time_cap);
                PeiCompAddFile(cmpn, "file_part.txt", list[i].part_list, 0);
                PeiAddComponent(ppei, cmpn);
                /* complete */
                PeiNewComponent(&cmpn, pei_complete_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompCapEndTime(cmpn, lpei->time_cap);
                PeiCompAddStingBuff(cmpn, "100%");
                PeiAddComponent(ppei, cmpn);
                memset(&(list[i]), 0, sizeof(file_http));
                list[i].url[0] = '\0';
            }
            else {
                list[i].len = bdim;
            }
        }
    }

    return ppei;
}


static pei *HFileEnd(void)
{
    long i, j, k, parts_dim;
    pei *ppei;
    FILE *fp; 
    file_part *parts;
    char perc[40];
    float bdim;
    unsigned long bstart, bend;
    pei_component *cmpn;
    
    ppei = NULL;
    for (i=0; i!=list_dim; i++) {
        if (list[i].url[0] != '\0') {
            if (list[i].range == FALSE) {
#if 1
                list[i].dim -= 1; /* see comp_note */
#else
                remove(list[i].part_list);
                remove(list[i].file);
                list[i].url[0] = '\0';
                continue;
#endif
            }
            fp = fopen(list[i].part_list, "r");
            if (fp != NULL) {
                /* load part info */
                parts_dim = list[i].cnt;
                j = 0;
                parts = xcalloc(1, sizeof(file_part)*parts_dim);
                while (fscanf(fp, "%lu %lu", &bstart, &bend) == 2) {
                    parts[j].start = bstart;
                    parts[j].end = bend;
                    j++;
                }
                fclose(fp);
                if (parts_dim != j) {
                    LogPrintfPei(LV_ERROR, list[i].ppei, "Number of parts (%i != %i)", parts_dim, j);
                }
                /* sort info */
                qsort(parts, j, sizeof(file_part), HFilePartSort);
                /* check file completiton size */
                bdim = parts[0].end - parts[0].start + 1;
                for (k=1; k!=j; k++) {
                    if (parts[k].start > (parts[k-1].end + 1)) {
                        bdim += parts[k].end - parts[k].start + 1;
                    }
                    else {
                        if (parts[k].end > parts[k-1].end)
                            bdim += parts[k].end - parts[k-1].end;
                    }
                }
                xfree(parts);
                sprintf(perc, "%f%%", (bdim*100)/list[i].dim);

                /* complete pei */
                ppei = list[i].ppei;
                /* file */
                PeiNewComponent(&cmpn, pei_file_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompAddFile(cmpn, list[i].file_name, list[i].file, 0);
                PeiAddComponent(ppei, cmpn);
                /* part */
                PeiNewComponent(&cmpn, pei_parts_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompAddFile(cmpn, "file_part.txt", list[i].part_list, 0);
                PeiAddComponent(ppei, cmpn);
                /* complete */
                PeiNewComponent(&cmpn, pei_complete_id);
                PeiCompCapTime(cmpn, ppei->time_cap);
                PeiCompAddStingBuff(cmpn, perc);
                PeiAddComponent(ppei, cmpn);
                memset(&(list[i]), 0, sizeof(file_http));

                list[i].url[0] = '\0';
                break;
            }
            
            list[i].url[0] = '\0';
        }
    }
    
    return ppei;
}


int AnalyseInit(void)
{
    char tmp_dir[256];
    
    list = NULL;
    list_dim = 0;
    incr = 0;
    tt_num = 0;
    
    http_id = ProtId("http");
    if (http_id != -1) {
        http_encoding_id = ProtAttrId(http_id, "http.content_encoding");
    }
      
    prot_id = ProtId("httpfd");
    if (prot_id != -1) {
        pei_url_id = ProtPeiComptId(prot_id, "url");
        pei_file_id = ProtPeiComptId(prot_id, "file");
        pei_range_id = ProtPeiComptId(prot_id, "range");
        pei_content_type = ProtPeiComptId(prot_id, "content_type");
        pei_parts_id = ProtPeiComptId(prot_id, "parts");
        pei_complete_id = ProtPeiComptId(prot_id, "complete");
    }

    /* tmp directory */
    sprintf(tmp_dir, "%s/%s", ProtTmpDir(), HTTPFILE_TMP_DIR);
    mkdir(tmp_dir, 0x01FF);
    
    return 0;
}


int AnalysePei(pei *ppei)
{
    pei_component *cmpn;
    char *url, *file, *range, *ct;
    pei *npei;
    size_t len;

    if (ppei == NULL)
        return 0;
    
    if (ppei->ret == TRUE) {
        ProtStackFrmDisp(ppei->stack, TRUE);
        LogPrintfPei(LV_WARNING, ppei, "Pei with return!");
    }
    npei = NULL;
    url = file = range = ct = NULL;
    
    //PeiPrint(ppei);
    cmpn = ppei->components;
    while (cmpn != NULL) {
        if (cmpn->eid == pei_url_id) {
            url = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_file_id) {
            file = cmpn->file_path;
            len = cmpn->file_size;
        }
        else if (cmpn->eid == pei_range_id) {
            range = cmpn->strbuf;
        }
        else if (cmpn->eid == pei_content_type) {
            ct = cmpn->strbuf;
        }
        cmpn = cmpn->next;
    }

    /* file part elaboration */
    if (len > 0) {
        npei = HFileElab(url, file, len, range, ct, ppei);
    }
    
    PeiFree(ppei);
    if (npei != NULL) {
        PeiIns(npei);
        tt_num++;
    }
    
    return 0;
}


int AnalyseEnd(void)
{
    pei *npei;

    npei = HFileEnd();
    while (npei != NULL) {
        tt_num++;
        PeiIns(npei);
        npei = HFileEnd();
    }
    
    LogPrintf(LV_STATUS, "-------------------------");
    LogPrintf(LV_STATUS, "Total PEI inserted: %lu", tt_num);
    LogPrintf(LV_STATUS, "-------------------------");

    return 0;
}

