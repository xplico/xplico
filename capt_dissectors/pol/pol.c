/* pol.c
 * main function for dissect a pol acqusition
 *
 * $Id:  $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007-2012 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <dirent.h>
#include <errno.h>
#include <arpa/inet.h>

#include "log.h"
#include "packet.h"
#include "dmemory.h"
#include "proto.h"
#include "flow.h"
#include "pol.h"
#include "report.h"
#include "config_param.h"
#include "dispatch.h"
#include "snoop.h"

#define DISP_PEI_MAX_QUEUE    1500

/* external crash info */
extern unsigned long crash_pkt_cnt; 
extern char *crash_ref_name;

static int pol_prot_id;
static unsigned long pkt_serial = 0; 
static char file_source[PCAP_PATH_DIM];
static char file_status[PCAP_PATH_DIM];
static FILE *pcap_of;


static int ListSort(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}


static int PolParam(int argc, char *argv[], char *dir, char **filtr_cmp)
{
    int c;
    short n;
    char fitr_file[PCAP_PATH_DIM];
    size_t len;
    char *cr;
    FILE *fp;
    struct stat sbuf;
    extern char *optarg;
    extern int optind, optopt;
    
    fitr_file[0] = '\0';
    n = 0;
    while ((c = getopt(argc, argv, "d:F:")) != -1) {
        switch(c) {
        case 'd':
            strcpy(dir, optarg);
            n++;
            break;

        case 'F':
            strcpy(fitr_file, optarg);
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            return -1;
        }
    }
    if (n != 1)
        return -1;
    
    /* load filter */
    if (fitr_file[0] != '\0') {
        if (stat(fitr_file, &sbuf) == 0) {
            *filtr_cmp = xmalloc(sbuf.st_size + 256);
            if (*filtr_cmp == NULL) {
                printf("Error: out of memory");
                LogPrintf(LV_FATAL, "out of memory");
                return -1;
            }
            fp = fopen(fitr_file, "r");
            if (fp != NULL) {
                len = fread(*filtr_cmp, 1, sbuf.st_size, fp);
                if (len > 0) {
                    (*filtr_cmp)[len] = '\0';
                    /* remove \r and \n */
                    do {
                        cr = strchr(*filtr_cmp, '\r');
                        if (cr != NULL)
                            *cr = ' ';
                    } while (cr != NULL);
                    do {
                        cr = strchr(*filtr_cmp, '\n');
                        if (cr != NULL)
                            *cr = ' ';
                    } while (cr != NULL);
                }
                fclose(fp);
            }
        }
        else {
            printf("Error in file filter: %s\n", fitr_file);
            LogPrintf(LV_ERROR, "File filter (%s) not present!", fitr_file);
            return -1;
        }
    }

    return 0;
}


static char *PolFile(char *dirpath, bool *one)
{
    char **list;
    char *file;
    DIR *dir;
    int i, num;
    struct dirent *entry;

    *one = TRUE;
    dir = opendir(dirpath);
    if (dir == NULL) {
        perror("");
        return NULL;
    }

    /* file list */
    num = 0;
    list = NULL;
    file = NULL;
    while((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.')
            continue;
        list = xrealloc(list, sizeof(char *)*(num+1));
        list[num] = xmalloc(strlen(dirpath)+strlen(entry->d_name)+5);
        sprintf(list[num], "%s/%s", dirpath, entry->d_name);
        num++;
    }
    closedir(dir);

    /* sort */
    qsort(list, num, sizeof(char *), ListSort);
    if (num == 0) {
        return NULL;
    }
    if (num > 1)
        *one = FALSE;
    if (list != NULL) {
        file = list[0];    
        for (i=1; i<num; i++) {
            xfree(list[i]);
        }
        xfree(list);
    }

    return file;
}


static void PcapDissector(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct cap_ref *ref = (struct cap_ref *)user;
    int offset;
    packet *pkt;
    static time_t tm = 0;
    static time_t tstart = 0;
    static size_t tsize = 0;
    struct timespec to;
    FILE *fp;

    pkt = PktNew();
    
    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+sizeof(unsigned long)*2+sizeof(size_t));
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    tsize += h->caplen;
    offset = 0;
    *((unsigned long *)&(pkt->raw[pkt->raw_len])) = ref->dlt;
    offset += sizeof(unsigned long);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->cnt;
    offset += sizeof(unsigned long);
    *((char **)&(pkt->raw[pkt->raw_len+offset])) = ref->file_name;
    offset += sizeof(char *);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->ses_id;
    offset += sizeof(unsigned long);
    *((unsigned long *)&(pkt->raw[pkt->raw_len+offset])) = ref->pol_id;
    offset += sizeof(unsigned long);
    *((size_t *)&(pkt->raw[pkt->raw_len+offset])) = ref->offset;
    if (h->ts.tv_sec < 0)
        pkt->cap_sec = 0;
    else
        pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;
    ref->offset = ftell(pcap_of); /* update offset */
        
    /* crash info */
    crash_pkt_cnt = ref->cnt;
    crash_ref_name = ref->file_name;
    
    /* decode */
    ProtDissec(pol_prot_id, pkt);

    FlowSetGblTime(h->ts.tv_sec);

    /* next serial number */
    pkt_serial++;

    if (time(NULL) > tm) {
        tm = time(NULL);
        ReportSplash();
        while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
            to.tv_sec = 2;
            to.tv_nsec = 1;
            /* wait some time */
            while (nanosleep(&to, &to) != 0)
                ;
            ReportSplash();
        }
        
        if (tstart == 0) {
            tstart = tm;
        }
        else {
            fp = fopen(file_status, "w+");
            if (fp != NULL) {
                fprintf(fp, "s:%lu r:%lld\n", (unsigned long)tsize, (long long)(tm - tstart));
                fclose(fp);
            }
        }
        tm += 5;
    }
}

static int SnoopDissector(FILE *fp, struct cap_ref *ref)
{
    struct snoop_packet_header hdr;
    unsigned long hlen, len;
    packet *pkt;
    time_t tm = 0;
    static time_t tstart = 0;
    static size_t tsize = 0;
    int offset;
    struct timespec to;
    FILE *fpl;

    while (1) {
        /* read header */
        hlen = fread(&hdr, 1, sizeof(struct snoop_packet_header), fp);
        if (hlen != sizeof(struct snoop_packet_header)) {
            if (hlen == 0)
                return 0;
            printf("Snoop file error\n");
            return -1;
        }
        pkt = PktNew();
        /* conver values */
        hdr.tlen = ntohl(hdr.tlen);
        hdr.len = ntohl(hdr.len);
        hdr.blen = ntohl(hdr.blen);
        hdr.secs = ntohl(hdr.secs);
        hdr.usecs = ntohl(hdr.usecs);
        len = hdr.blen - hlen;
        ref->cnt++;
        pkt->raw = DMemMalloc(len+sizeof(unsigned long)*2+sizeof(char *)+sizeof(unsigned long)*2+sizeof(size_t));
        len = fread(pkt->raw, 1, len, fp);
        pkt->raw_len = len;
        tsize += len;
        offset = 0;
        *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
        offset += sizeof(unsigned long);
        *((unsigned long *)&(pkt->raw[len+offset])) = ref->cnt;
        offset += sizeof(unsigned long);
        *((char **)(&(pkt->raw[len+offset]))) = ref->file_name;
        offset += sizeof(char *);
        *((unsigned long *)&(pkt->raw[len+offset])) = ref->ses_id;
        offset += sizeof(unsigned long);
        *((unsigned long *)&(pkt->raw[len+offset])) = ref->pol_id;
        offset += sizeof(unsigned long);
        *((size_t *)&(pkt->raw[pkt->raw_len+offset])) = 0;
        pkt->cap_sec = hdr.secs;
        pkt->cap_usec = hdr.usecs;
        pkt->serial = pkt_serial;
        
        /* crash info */
        crash_pkt_cnt = ref->cnt;
        crash_ref_name = ref->file_name;
        
        /* decode */
        ProtDissec(pol_prot_id, pkt);
        
        FlowSetGblTime(hdr.secs);

        /* next serial number */
        pkt_serial++;

        if (time(NULL) > tm) {
            tm = time(NULL);
            ReportSplash();
            while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
                to.tv_sec = 2;
                to.tv_nsec = 1;
                /* wait some time */
                while (nanosleep(&to, &to) != 0)
                    ;
                ReportSplash();
            }
            if (tstart == 0)
                tstart = tm;
            else {
                fpl = fopen(file_status, "w+");
                if (fpl != NULL) {
                    fprintf(fpl, "s:%lu r:%lld\n", (unsigned long)tsize, (long long)(tm - tstart));
                    fclose(fpl);
                }
            }
            tm += 5;
        }
    }

    return 0;
}


char* CaptDisOptions(void)
{
    return "-d <pol_dir_path> [-F <filter_file>]";
}


void CaptDisOptionsHelp(void)
{
    printf("\t-d directory of the session\n");
    printf("\t-F BPF filtering file\n");
    printf("\tNOTE: this capture module run ONLY with DeMa\n");
}


int CaptDisMain(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char dirpath[PCAP_PATH_DIM];
    char tmp[PCAP_PATH_DIM];
    char ifile[PCAP_PATH_DIM];
    char *pcapfile, *param;
    bool end, ses_id, pol_id;
    pcap_t *cap = NULL;
    int res;
    struct cap_ref ref;
    struct timespec to;
    FILE *fp;
    struct stat info_a, info_b;
    struct snoop_file_header snooph;
    char *filter_app;
    struct bpf_program filter;     /* The compiled filter */
    bool one;

    end = FALSE;
    ses_id = FALSE;
    pol_id = FALSE;
    pcapfile = NULL;
    filter_app = NULL;
    
    /* pol  protocol id */
    pol_prot_id = ProtId("pol");
    if (pol_prot_id == -1) {
        return -1;
    }
    
    /* serial number of packet */
    pkt_serial = 1;

    /* pol dir name */
    dirpath[0] = '\0';
    res = PolParam(argc, argv, dirpath, &filter_app);
    if (res != 0) {
        return -1;
    }

    /* check name dir */
    if (dirpath[0] == '\0') {
        return -1;
    }

    /* read pol info */
    sprintf(ifile, "%s/%s", dirpath, POL_INIT_SESSION_FILE);
    fp = fopen(ifile, "r");
    if (fp == NULL) {
        LogPrintf(LV_ERROR, "Pol info file (%s) not present!", ifile);

        return -1;
    }
    while (fgets(tmp, CFG_LINE_MAX_SIZE, fp) != NULL) {
        /* check if line is a comment */
        if (!CfgParIsComment(tmp)) {
            param = strstr(tmp, POL_SESSION_ID);
            if (param != NULL) {
                res = sscanf(param, POL_SESSION_ID"=%lu", &ref.ses_id);
                if (res == 1) {
                    ses_id = TRUE;
                }
            }
            param = strstr(tmp, POL_POL_ID);
            if (param != NULL) {
                res = sscanf(param, POL_POL_ID"=%lu", &ref.pol_id);
                if (res == 1) {
                    pol_id = TRUE;
                }
            }
        }
    }
    fclose(fp);
    remove(ifile);

    sprintf(file_status, "%s/../../tmp/%s", dirpath, POL_POL_STATUS);

    if (ses_id == FALSE || pol_id == FALSE) {
        LogPrintf(LV_ERROR, "Pol info file (%s) incomplete!", tmp);

        return -1;
    }
    
    /* pcap file decoding */
    do {
        /* pcap file name */
        do {
            pcapfile = PolFile(dirpath, &one);
            if (pcapfile == NULL) {
                /* timeout */
                to.tv_sec = 2;
                to.tv_nsec = 1;
                if (!end) {
                    /* wait new file */
                    while (nanosleep(&to, &to) != 0)
                        ;
                }
            }
            else {
                /* check if the file is the end file flag */
                if (strstr(pcapfile, POL_END_SESSION_FILE) != NULL) {
                    end = TRUE;
                    remove(pcapfile);
                    xfree(pcapfile);
                    pcapfile = PolFile(dirpath, &one);
                }
            }
        } while (pcapfile == NULL && end == FALSE);

        if (pcapfile != NULL) {
            /* wait file download completition */
            if (one) {
                do {
                    /* timeout */
                    to.tv_sec = 5;
                    to.tv_nsec = 1;
                    stat(pcapfile, &info_a);
                    nanosleep(&to, NULL);
                    stat(pcapfile, &info_b);
                } while (info_a.st_size != info_b.st_size);
            }

            errbuf[sizeof(errbuf) - 1] = '\0';
            errbuf[0] = '\0';
            
            /* open the input pcap file (or stdin) */
            cap = pcap_open_offline(pcapfile, errbuf);
            if (cap != NULL) {
                pcap_of = pcap_file(cap);
                /* compile and apply the filter */
                if (filter_app != NULL) {
                    if (pcap_compile(cap, &filter, filter_app, 1, 0) < 0) {
                        printf("Bad filter %s\n", filter_app);
                        pcap_perror(cap, "Filter");
                        return -1;
                    }
                    
                    pcap_setfilter(cap, &filter);
                    pcap_freecode(&filter);
                }
                
                /* file name */
                ref.file_name = pcapfile;
                strncpy(file_source, pcapfile, PCAP_PATH_DIM);
                
                /* data link type */
                ref.dlt = pcap_datalink(cap);
                
                /* packet counter */
                ref.cnt = 0;
                ref.offset = ftell(pcap_of);

                /* let pcap loop over the input, passing data to the decryptor */
                pcap_loop(cap, -1, (pcap_handler)&PcapDissector, (u_char*)&ref);
                
                pcap_close(cap);
            }
            else {
                /* try with snoop */
                fp = fopen(pcapfile, "r");
                if (fp != NULL) {
                    if (fread(&snooph, 1, sizeof(snooph), fp) == sizeof(snooph)) {
                        if (strcmp(snooph.format_name, "snoop") != 0) {
                            fclose(fp);
                            fp = NULL;
                            LogPrintf(LV_ERROR, "File %s: %s", pcapfile, errbuf);
                        }
                        else {
                            snooph.version = ntohl(snooph.version);
                            snooph.mac = ntohl(snooph.mac);
                            /* file name */
                            ref.file_name = pcapfile;
                            strncpy(file_source, pcapfile, PCAP_PATH_DIM);
                            /* data link type */
                            switch (snooph.mac) {
                            case 0x04: 
                                ref.dlt = DLT_EN10MB;
                                break;
                                
                            case 0x08:
                                ref.dlt = DLT_FDDI;
                                break;
                                
                            case 0x12:
                                ref.dlt = DLT_SUNATM;
                                break;
                            }
                            
                            /* packet counter */
                            ref.cnt = 0;
                            
                            SnoopDissector(fp , &ref);
                            fclose(fp);
                            fp = NULL;
                        }
                    }
                    else {
                        fclose(fp);
                        fp = NULL;
                        LogPrintf(LV_ERROR, "File %s: %s", pcapfile, errbuf);
                    }
                }
                else {
                    LogPrintf(LV_ERROR, "File %s: %s", pcapfile, errbuf);
                }
            }
            /* remove file */
            remove(pcapfile);
            xfree(pcapfile);
        }
    } while (pcapfile);

    if (filter_app != NULL)
        xfree(filter_app);
    
    return 0;
}


const char *CaptDisSource(void)
{
    return file_source;
}

