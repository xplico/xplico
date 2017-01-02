/* trigcap.c
 *
 * $Id: $
 *
 * Xplico System
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2010 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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
#include <pcap.h>


#define TC_VER_MAG      1
#define TC_VER_MIN      1
#define TC_VER_REV      0
#define TC_CR           "Part of Xplico Internet Traffic Decoder (NFAT).\nSee http://www.xplico.org for more information.\n\nCopyright 2007-2011 Gianluca Costa & Andrea de Franceschi and contributors.\nThis is free software; see the source for copying conditions. There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n"

#define TC_BUFFER_SIZE  1024

struct pcappkt_hdr {
    unsigned int tv_sec;      /* timestamp seconds */
    unsigned int tv_usec;     /* timestamp microseconds */
    unsigned int caplen;      /* number of octets of packet saved in file */
    unsigned int len;	      /* actual length of packet */
};

static void Usage(char *name)
{
    printf("\n");
    printf("usage: %s [-v] -f <input_file> -t <pkt num> -b <pkt numbers before> -a <pkt numbers after> -o <output_file> [-h]\n", name);
    printf("\t-v version\n");
    printf("\t-f input pcap file\n");
    printf("\t-t trigger packet number\n");
    printf("\t-b packet numbers before trigger packet\n");
    printf("\t-a packet numbers after trigger packet\n");
    printf("\t-o output pcap file\n");
    printf("\t-h this help\n");
    printf("\n");
}


int main(int argc, char *argv[])
{
    char c;
    char in_file[TC_BUFFER_SIZE];
    char out_file[TC_BUFFER_SIZE];
    char check;
    unsigned long tp;
    unsigned long bnp;
    unsigned long anp;
    unsigned long pk_start, pk_stop, pk_cnt;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *cap;
    struct pcap_pkthdr *h;
    struct pcappkt_hdr nh;
    const u_char *bytes;
    struct pcap_file_header fh;
    FILE *fp_pcap;
    size_t nwrt, wcnt;
    extern char *optarg;
    extern int optind, optopt;

    tp = 0;
    bnp = 0;
    anp = 0;
    check = 0;
    while ((c = getopt(argc, argv, "vf:t:b:a:o:h")) != -1) {
        switch(c) {
        case 'v':
            printf("trigcap %d.%d.%d\n", TC_VER_MAG, TC_VER_MIN, TC_VER_REV);
            return 0;
            break;

        case 'f':
            snprintf(in_file, TC_BUFFER_SIZE, "%s", optarg);
            in_file[TC_BUFFER_SIZE-1] = '\0';
            check |= 0x01;
            break;

        case 't':
            tp = atol(optarg);
            check |= 0x02;
            break;

        case 'b':
            bnp = atol(optarg);
            check |= 0x04;
            break;

        case 'a':
            anp = atol(optarg);
            break;

        case 'o':
            sprintf(out_file, "%s", optarg);
            check |= 0x08;
            break;

        case 'h':
            Usage(argv[0]);
            return 0;
            break;

        case '?':
            printf("Error: unrecognized option: -%c\n", optopt);
            Usage(argv[0]);
            exit(-1);
            break;
        }
    }
    
    printf("trigcap v%d.%d.%d\n", TC_VER_MAG, TC_VER_MIN, TC_VER_REV);
    printf("%s\n", TC_CR);
    
    if (check != 0x0F) {
        Usage(argv[0]);
            exit(-1);
    }
    
    if (bnp > tp)
        pk_start = 0;
    else
        pk_start = tp - bnp;
    pk_stop = tp + anp;
    
    printf("Trigger packet: %lu\n", tp);
    printf("Total packet: %lu\n", bnp+anp);
    printf("Start packet: %lu\n", pk_start);
    printf("Stop packet: %lu\n", pk_stop);
    
    pk_cnt = 0;
    cap = pcap_open_offline(in_file, errbuf);
    if (cap == NULL) {
        printf("Error:%s\n", errbuf);
        return -1;
    }
    
    /* pcap out file */
    fp_pcap = fopen(out_file, "w");
    memset(&fh, 0, sizeof(struct pcap_file_header));
    fh.magic = 0xA1B2C3D4;
    fh.version_major = PCAP_VERSION_MAJOR;
    fh.version_minor = PCAP_VERSION_MINOR;
    fh.snaplen = 65535;
    fh.linktype = pcap_datalink(cap);
    if (fp_pcap != NULL) {
        fwrite((char *)&fh, 1, sizeof(struct pcap_file_header), fp_pcap);
    }
    else {
        printf("Error to open file:%s\n", out_file);
        pcap_close(cap);
        return -1;
    }
        
    while (pcap_next_ex(cap, &h, &bytes) == 1) {
        pk_cnt++;
        if (pk_cnt > pk_stop)
            break;
        if (pk_cnt >= pk_start) {
            wcnt = 0;
            nh.tv_sec = h->ts.tv_sec;
            nh.tv_usec = h->ts.tv_usec;
            nh.caplen = h->caplen;
            nh.len = h->len;
            do {
                nwrt = fwrite(((char *)&nh)+wcnt, 1, sizeof(struct pcappkt_hdr)-wcnt, fp_pcap);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != sizeof(struct pcappkt_hdr));
            
            wcnt = 0;
            do {
                nwrt = fwrite(((char *)bytes)+wcnt, 1, h->caplen-wcnt, fp_pcap);
                if (nwrt != -1)
                    wcnt += nwrt;
                else
                    break;
            } while (wcnt != h->caplen);
        }
    }
    fclose(fp_pcap);
    pcap_close(cap);

    return 0;
}
