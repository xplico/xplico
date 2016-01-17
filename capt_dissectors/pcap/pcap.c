/* pcap.c
 * main function for dissect a pcap file
 *
 * $Id: $
 *
 * Xplico - Internet Traffic Decoder
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
#include <signal.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "log.h"
#include "packet.h"
#include "dmemory.h"
#include "proto.h"
#include "flow.h"
#include "pcapd.h"
#include "report.h"
#include "dispatch.h"
#include "snoop.h"

#define DISP_PEI_MAX_QUEUE    1500


/* external crash info */
extern unsigned long crash_pkt_cnt;
extern char *crash_ref_name;

static int pcap_prot_id;
static unsigned long pkt_serial = 0; 
static volatile bool ciao;
static char file_source[PCAP_PATH_DIM];

static int ListSort(const void *a, const void *b)
{
    return strcmp(*(char **)a, *(char **)b);
}


void PcapCiao(int sig)
{
    ciao = TRUE;
}


static int PcapParam(int argc, char *argv[], char *file, char *dir, bool *tresp)
{
    int c;
    short n;
    extern char *optarg;
    extern int optind, optopt;

    n = 0;
    while ((c = getopt(argc, argv, "f:d:t")) != -1) {
        switch(c) {
        case 'f':
            strcpy(file, optarg);
            n++;
            break;

        case 'd':
            strcpy(dir, optarg);
            n++;
            break;

        case 't':
            *tresp = TRUE;
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            return -1;
        }
    }
    if (n != 1)
        return -1;
    return 0;
}


static void PcapDissector(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct cap_ref *ref = (struct cap_ref *)user;
    packet *pkt;
    static time_t tm = 0;
    struct timespec to;
    unsigned long len;
    char tgl;

    pkt = PktNew();

    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+4);
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    /* align 4b */
    len = pkt->raw_len;
    len = len + 4 - (len%4);
    *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
    *((unsigned long *)&(pkt->raw[len+sizeof(unsigned long)])) = ref->cnt;
    *((char **)(&(pkt->raw[len+sizeof(unsigned long)*2]))) = ref->file_name;
    if (h->ts.tv_sec < 0)
        pkt->cap_sec = 0;
    else
        pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;
        
    /* crash info */
    crash_pkt_cnt = ref->cnt;
    crash_ref_name = ref->file_name;
    
    /* decode */
    if (!ciao)
        ProtDissec(pcap_prot_id, pkt);

    FlowSetGblTime(h->ts.tv_sec);
    /* next serial number */
    pkt_serial++;
    if (time(NULL) > tm) {
        tgl = 0;
        ReportSplash();
        while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
            tgl = (tgl + 1) % 4;
            to.tv_sec = 0;
            to.tv_nsec = 300000000;
            /* wait some time */
            while (nanosleep(&to, &to) != 0)
                ;
            if (tgl == 0)
                ReportSplash();
        }
        tm = time(NULL) + 2;
    }
}


static void PcapDissectorTsec(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes)
{
    struct cap_ref *ref = (struct cap_ref *)user;
    packet *pkt;
    static time_t tm = 0;
    struct timespec to;
    unsigned long len;
    struct timespec dt;
    static struct timespec last_t = {0,0};
    
    pkt = PktNew();

    ref->cnt++;
    pkt->raw = DMemMalloc(h->caplen+sizeof(unsigned long)*2+sizeof(char *)+4);
    memcpy(pkt->raw, bytes, h->caplen);
    pkt->raw_len = h->caplen;
    /* align 4b */
    len = pkt->raw_len;
    len = len + 4 - (len%4);
    *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
    *((unsigned long *)&(pkt->raw[len+sizeof(unsigned long)])) = ref->cnt;
    *((char **)(&(pkt->raw[len+sizeof(unsigned long)*2]))) = ref->file_name;
    if (h->ts.tv_sec < 0)
        pkt->cap_sec = 0;
    else
        pkt->cap_sec = h->ts.tv_sec;
    pkt->cap_usec = h->ts.tv_usec;
    pkt->serial = pkt_serial;
        
    /* crash info */
    crash_pkt_cnt = ref->cnt;
    crash_ref_name = ref->file_name;
    
    if (tm != 0) {
        dt.tv_sec = pkt->cap_sec - last_t.tv_sec;
        dt.tv_nsec = (1000000 - last_t.tv_nsec + pkt->cap_usec)*1000; /* nsec */
    }
    last_t.tv_sec = pkt->cap_sec;
    last_t.tv_nsec = pkt->cap_usec; /* usec */
    nanosleep(&dt, NULL);

    /* decode */
    if (!ciao)
        ProtDissec(pcap_prot_id, pkt);

    FlowSetGblTime(h->ts.tv_sec);
    /* next serial number */
    pkt_serial++;
    if (time(NULL) > tm) {
        ReportSplash();
        while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
            to.tv_sec = 0;
            to.tv_nsec = 300000000;
            /* wait some time */
            while (nanosleep(&to, &to) != 0)
                ;
            ReportSplash();
        }
        tm = time(NULL) + 2;
    }
}


static int SnoopDissector(FILE *fp, struct cap_ref *ref)
{
    struct snoop_packet_header hdr;
    unsigned long hlen, len;
    packet *pkt;
    time_t tm = 0;
    struct timespec to;

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
        pkt->raw = DMemMalloc(len+sizeof(unsigned long)*2+sizeof(char *)+4);
        len = fread(pkt->raw, 1, len, fp);
        pkt->raw_len = len;
        /* align 4b */
        len = len + 4 - (len%4);
        *((unsigned long *)&(pkt->raw[len])) = ref->dlt;
        *((unsigned long *)&(pkt->raw[len+sizeof(unsigned long)])) = ref->cnt;
        *((char **)(&(pkt->raw[len+sizeof(unsigned long)*2]))) = ref->file_name;
        pkt->cap_sec = hdr.secs;
        pkt->cap_usec = hdr.usecs;
        pkt->serial = pkt_serial;
        
        /* crash info */
        crash_pkt_cnt = ref->cnt;
        crash_ref_name = ref->file_name;
        
        /* decode */
        if (!ciao)
            ProtDissec(pcap_prot_id, pkt);
        
        FlowSetGblTime(hdr.secs);
        /* next serial number */
        pkt_serial++;
        if (time(NULL) > tm) {
            ReportSplash();
            while (DispatchPeiPending() > DISP_PEI_MAX_QUEUE) {
                to.tv_sec = 0;
                to.tv_nsec = 300000000;
                /* wait some time */
                while (nanosleep(&to, &to) != 0)
                    ;
                ReportSplash();
            }
            tm = time(NULL) + 2;
        }
    }

    return 0;
}


char* CaptDisOptions(void)
{
    return "[-t] -f <file> | -d <file_dir_path>";
}


void CaptDisOptionsHelp(void)
{
    printf("\t-f pcap or snoop file name\n");
    printf("\t-d pcap or snoop files dir path\n");
    printf("\t-t the pcap will be elaborated with respect of the time (sec resolution)\n");
}


int CaptDisMain(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    char infile[PCAP_PATH_DIM], dirpath[PCAP_PATH_DIM];
    char **list;
    char *pcap_file;
    int i, num;
    pcap_t *cap = NULL;
    int ret;
    DIR *dir;
    struct dirent *entry;
    struct cap_ref ref;
    FILE *fp;
    struct snoop_file_header snooph;
    static bool tresp;

    /* pcapfile  protocol id */
    pcap_prot_id = ProtId("pcapf");
    if (pcap_prot_id == -1) {
        printf("It is necessary to load (from config file) the dissector pcapf\n");
        return -1;
    }
    
    /* serial number of packet */
    pkt_serial = 1;

    /* pcap file/dir name */
    infile[0] = '\0';
    dirpath[0] = '\0';
    tresp = FALSE;
    ret = PcapParam(argc, argv, infile, dirpath, &tresp);
    if (ret != 0) {
        return -1;
    }
    /* ^C */
    ciao = FALSE;
    signal(SIGTERM, PcapCiao);
    signal(SIGINT, PcapCiao);
    
    list = NULL;
    num = 0;
    if (dirpath[0] != '\0') {
        dir = opendir(dirpath);
        if (dir == NULL) {
            perror("");
            return -1;
        }
        /* file list */
        while((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.')
                continue;
            list = xrealloc(list, sizeof(char *)*(num+1));
            list[num] = xmalloc(strlen(dirpath)+strlen(entry->d_name)+5);
            sprintf(list[num], "%s/%s", dirpath, entry->d_name);
            num++;
        }
        qsort(list, num, sizeof(char *), ListSort);
        closedir(dir);
        if (num == 0) {
            printf("Directory without pcap/snoop file\n");
            return -1;
        }
#if 0
        /* list debug */
        printf("Files list:\n");
        for (i=0; i!=num; i++) {
            printf(" %s\n", list[i]);
        }
#endif
        pcap_file = list[0];
    }
    else
        pcap_file = infile;

    i = 0;
    do {
        errbuf[sizeof(errbuf) - 1] = '\0';
        errbuf[0] = '\0';
        
        /* open the input pcap file */
        cap = pcap_open_offline(pcap_file, errbuf);
        if (cap != NULL) {
            /* file name */
            ref.file_name = pcap_file;
            strncpy(file_source, pcap_file, PCAP_PATH_DIM);
            /* data link type */
            ref.dlt = pcap_datalink(cap);
            /* packet counter */
            ref.cnt = 0;
            
            /* let pcap loop over the input, passing data to the decryptor */
            if (tresp)
                pcap_loop(cap, -1, (pcap_handler)&PcapDissectorTsec, (u_char*)&ref);
            else
                pcap_loop(cap, -1, (pcap_handler)&PcapDissector, (u_char*)&ref);

            pcap_close(cap);
        }
        else {
            /* try with snoop */
            fp = fopen(pcap_file, "r");
            if (fp != NULL) {
                if (fread(&snooph, 1, sizeof(snooph), fp) == sizeof(snooph)) {
                    if (strcmp(snooph.format_name, "snoop") != 0) {
                        fclose(fp);
                        fp = NULL;
                        LogPrintf(LV_ERROR, "File %s: %s", pcap_file, errbuf);
                    }
                    else {
                        snooph.version = ntohl(snooph.version);
                        snooph.mac = ntohl(snooph.mac);
                        /* file name */
                        ref.file_name = pcap_file;
                        strncpy(file_source, pcap_file, PCAP_PATH_DIM);
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

                        SnoopDissector(fp, &ref);
                        fclose(fp);
                        fp = NULL;
                    }
                }
                else {
                    fclose(fp);
                    fp = NULL;
                    LogPrintf(LV_ERROR, "File %s: %s", pcap_file, errbuf);
                }
            }
            else {
                 LogPrintf(LV_ERROR, "File %s: %s", pcap_file, errbuf);
            }
        }
        
        i++;
        if (i < num)
            pcap_file = list[i];
    } while (i<num && !ciao);

    return 0;
}


const char *CaptDisSource(void)
{
    return file_source;
}
