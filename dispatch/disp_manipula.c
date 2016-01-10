/* disp_manipula.c
 * Dispatcher-Manipulator functions protocols
 *
 * $Id: $
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

#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <errno.h>

extern int errno;

#include "dmemory.h"
#include "log.h"
#include "pei.h"
#include "disp_manipula.h"
#include "dispatch_dev.h"
#include "proto.h"

/* global */
volatile pei *volatile mnp_pei;


static unsigned short free_port;

static ssize_t DispSockWrite(int fd, void *buf, size_t count)
{
    size_t wr, tot;

    wr = write(fd, buf, count);
    if (wr == count)
        return wr;
    
    if (wr == 0)
        return 0;
    
    if (wr == -1) {
        if (errno == EINTR)
            wr = 0;
        else
            return -1;
    }
    tot = wr;
    do {
        wr = write(fd, ((char *)buf)+tot, count-tot);
        if (wr == 0)
            return 0;
        if (wr == -1) {
            if (errno == EINTR)
                wr = 0;
            else
                return -1;
        }
        tot += wr;
    } while (tot != count);
    
    return count;
}


/* IMPORTANT!: if valgrind notifies a warning as "write(buf) points to uninitialised byte" it is not a bug, all attributes are union and the function ProtInsAttr copy all data even if uninitialised */
static int DispManipSend(int sock, pei *ppei)
{
    int wr, dim, i;
    pei_component *cmpt;
    pstack_f *stack;
    enum ftype tp;
    ftval attr;

    /* send all data */
    wr = DispSockWrite(sock, ppei, sizeof(pei));
    if (wr == -1) {
        printf("************* Error:%s\n", strerror(errno));
        return -1;
    }
    cmpt = ppei->components;
    while (cmpt != NULL) {
        wr = DispSockWrite(sock, cmpt, sizeof(pei_component));
        if (cmpt->strbuf != NULL) {
            dim = strlen(cmpt->strbuf) + 1;
            wr = DispSockWrite(sock, &dim, sizeof(int));
            wr = DispSockWrite(sock, cmpt->strbuf, dim);
        }
        if (cmpt->name != NULL) {
            dim = strlen(cmpt->name) + 1;
            wr = write(sock, &dim, sizeof(int));
            wr = write(sock, cmpt->name, dim);
        }
        if (cmpt->file_path != NULL) {
            dim = strlen(cmpt->file_path) + 1;
            wr = DispSockWrite(sock, &dim, sizeof(int));
            wr = DispSockWrite(sock, cmpt->file_path, dim);
        }
        cmpt = cmpt->next;
    }

    stack = ppei->stack;
    while (stack != NULL) {
        dim = ProtFrameSize(stack->pid);
        wr = DispSockWrite(sock, &stack->pid, sizeof(int));
        wr = DispSockWrite(sock, stack, dim);
        i = 0;
        tp = ProtAttrType(stack->pid, i);
        while (tp != FT_NONE) {
            if (tp == FT_STRING) {
                ProtGetAttr(stack, i, &attr);
                if (attr.str != NULL) {
                    dim = strlen(attr.str) + 1;
                    wr = DispSockWrite(sock, &dim, sizeof(dim));
                    wr = DispSockWrite(sock, attr.str, dim);
                }
                else {
                    dim = 0;
                    wr = DispSockWrite(sock, &dim, sizeof(dim));
                }
                FTFree(&attr, FT_STRING);
            }
            i++;
            tp = ProtAttrType(stack->pid, i);
        }

        if (stack->gstack != NULL) {
            LogPrintf(LV_FATAL, "This PEI requres Xplico Professional edition. Contact: xplico@iserm.com");
            exit(-1);
        }

        stack = stack->pfp;
    }

    return 0;
}


static unsigned short DispAggPort(void)
{
    struct sockaddr_in servAddr;
    struct sockaddr_in6 servAddr6;
    int yes;
    int sd, sd6;
    int ip_port, ip6_port, ret;
    
    ip_port = ip6_port = 0;
    /* create socket */
    sd = socket(AF_INET, SOCK_STREAM, 0);
    sd6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (sd < 0 && sd6 < 0) {
        printf("cannot open socket\n");
        return 0;
    }
    if (sd > 0) {
        yes = 1;
        if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
                       (char *) &yes, sizeof (yes)) < 0) {
            printf("setsockopt\n");
            close(sd);
            return 0;
        }
#ifdef SO_REUSEPORT
        if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, sizeof(yes)) < 0) {
            perror("SO_REUSEPORT");
            close(sd);
            return 0;
        }
#endif
    }
    if (sd6 > 0) {
        yes = 1;
        if (setsockopt(sd6, SOL_SOCKET, SO_REUSEADDR,
                       (char *) &yes, sizeof (yes)) < 0) {
            printf("setsockopt\n");
            close(sd);
            return 0;
        }
#ifdef SO_REUSEPORT
        if (setsockopt(sd6, SOL_SOCKET, SO_REUSEPORT, (char *) &yes, sizeof(yes)) < 0) {
            perror("SO_REUSEPORT");
            close(sd);
            return 0;
        }
#endif
    }
    do {
        if (sd > 0) {
            do {
                /* bind server port */
                memset (&servAddr, 0, sizeof (servAddr));
                servAddr.sin_family = AF_INET;
                servAddr.sin_addr.s_addr = htonl(INADDR_ANY);
                servAddr.sin_port = htons(free_port);
                
                if (bind(sd, (struct sockaddr *)&servAddr, sizeof(servAddr)) == 0) {
                    break;
                }
                free_port++;
            } while (free_port != 0);
            ip_port = free_port;
            if (ip6_port == ip_port)
                break;
        }

        if (sd6 > 0 && free_port != 0) {
            do {
                /* bind server port */
                memset (&servAddr6, 0, sizeof (servAddr6));
                servAddr6.sin6_family = AF_INET6;
                servAddr6.sin6_addr = in6addr_any;
                servAddr6.sin6_port = htons(free_port);
                //servAddr6.sin6_scope_id = 5;
                
                if (bind(sd6, (struct sockaddr *)&servAddr6, sizeof(servAddr6)) == 0) {
                    break;
                }
                free_port++;
            } while (free_port != 0);
            ip6_port = free_port;
        }
        if (sd6 > 0 && sd > 0) {
            if (ip6_port == ip_port)
                break;
            close(sd);
            close(sd6);
            sd = socket(AF_INET, SOCK_STREAM, 0);
            sd6 = socket(AF_INET6, SOCK_STREAM, 0);
            free_port = ip6_port;
        }
        else
            break;
    } while (free_port != 0);

    if (sd > 0)
        close(sd);
    if (sd6 > 0)
        close(sd6);

    ret = free_port;
    free_port++;

    return ret;
}


static int DispAggConn(manip_con *con)
{
    struct addrinfo *ai;
    struct addrinfo hints;
    const char *cfg_mdls;
    struct timespec to;
    int dim, rc, try;
    int mt;
    char sport[25];

    try = 0;
    /* if bin we start application */
    if (con->bin[0] != '\0') {
        strcpy(con->host, "localhost");
        /* start manipulator */
        con->port = DispAggPort();
        if (con->port == 0) {
            printf("Manipulator port error\n");
            return -1;
        }
        sprintf(sport, "%i", con->port);
        mt = fork();
        if (mt == 0) {
            char path[256];

            /* manipulator */
            sprintf(path, "%s", con->bin);
            execlp(path, con->bin, "-s", "-p", sport, NULL);
            exit(-1);
        }
        else if (mt == -1) {
            printf("Manipulator start error\n");
        }
        else {
            try = 6;
        }
    }
    else {
        sprintf(sport, "%i", con->port);
    }
    /* up connections */
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(con->host, sport, &hints, &ai);
    /* create socket */
    con->sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

    if (con->sock < 0) {
        LogPrintf(LV_FATAL, "Cannot open socket\n");
        return -1;
    }

    to.tv_sec = 0;
    do {
        rc = connect(con->sock, ai->ai_addr, ai->ai_addrlen);
        if (rc < 0) {
            if (try == 0) {
                fflush(NULL);
                LogPrintf(LV_WARNING, "Cannot connect to %s's manipulator [%s:%u]", con->name, con->host, con->port);
                close(con->sock);
                con->sock = -1;
                freeaddrinfo(ai);
                return -1;
            }
            try--;
            to.tv_nsec = 500000000;
            /* wait some time */
            while (nanosleep(&to, &to) != 0)
                ;
            to.tv_sec++;
        }
        else {
            break;
        }
    } while (try != -1);
    con->wait = FALSE;
    freeaddrinfo(ai);

    /* send config file of modules */
    cfg_mdls = DispatManipModulesCfg();
    dim = strlen(cfg_mdls);
    write(con->sock, &dim, sizeof(int));
    write(con->sock, cfg_mdls, dim);
    
    return 0;
}


static ssize_t DispSockRead(int fd, void *buf, size_t count)
{
    size_t rd, tot;

    rd = read(fd, buf, count);
    if (rd == count)
        return rd;
    
    if (rd == 0)
        return 0;
    if (rd == -1) {
        if (errno == EINTR)
            rd = 0;
        else
            return -1;
    }
    tot = rd;
    do {
        rd = read(fd, ((char *)buf)+tot, count-tot);
        if (rd == 0)
            return 0;
        if (rd == -1) {
            if (errno == EINTR)
                rd = 0;
            else
                return -1;
        }
        tot += rd;
    } while (tot != count);
    
    return count;
}


pei *DispManipGetPei(int sock)
{
    size_t rd; 
    int dim, pid, i;
    pei *ppei;
    pei_component **cmpt;
    pstack_f **stack;
    enum ftype tp;
    ftval attr;

    ppei = DMemMalloc(sizeof(pei));
    PeiInit(ppei);

    rd = DispSockRead(sock, ppei, sizeof(pei));
    if (rd == sizeof(pei)) {
        cmpt = &(ppei->components);
        while (*cmpt != NULL) {
            *cmpt = DMemMalloc(sizeof(pei_component));
            rd = DispSockRead(sock, *cmpt, sizeof(pei_component));
            if (rd == sizeof(pei_component)) {
                if ((*cmpt)->strbuf != NULL) {
                    rd = DispSockRead(sock, &dim, sizeof(int));
                    (*cmpt)->strbuf = DMemMalloc(dim);
                    rd = DispSockRead(sock, (*cmpt)->strbuf, dim);
                }
                if ((*cmpt)->name != NULL) {
                    rd = DispSockRead(sock, &dim, sizeof(int));
                    (*cmpt)->name = DMemMalloc(dim);
                    rd = DispSockRead(sock, (*cmpt)->name, dim);
                }
                if ((*cmpt)->file_path != NULL) {
                    rd = DispSockRead(sock, &dim, sizeof(int));
                    (*cmpt)->file_path = DMemMalloc(dim);
                    rd = DispSockRead(sock, (*cmpt)->file_path, dim);
                }
                cmpt = &((*cmpt)->next);
            }
            else {
                *cmpt = NULL;
                LogPrintf(LV_FATAL, "PEI component error transmission!!");
                return NULL;
            }
        }

        stack = &(ppei->stack);
        while (*stack != NULL) {
            rd = DispSockRead(sock, &pid, sizeof(int));
            dim = ProtFrameSize(pid);
            *stack = ProtCreateFrame(pid);
            rd = DispSockRead(sock, (*stack), dim);
            i = 0;
            tp = ProtAttrType((*stack)->pid, i);
            while (tp != FT_NONE) {
                if (tp == FT_STRING) {
                    rd = DispSockRead(sock, &dim, sizeof(dim));
                    if (dim) {
                        attr.str = DMemMalloc(dim);
                        rd = DispSockRead(sock, attr.str, dim);
                    }
                    else
                        attr.str = NULL;
                    ProtInsAttr(*stack, i, &attr);
                    DMemFree(attr.str);
                }
                i++;
                tp = ProtAttrType((*stack)->pid, i);
            }
            stack = &((*stack)->pfp);
        }
    }
    else {
        DMemFree(ppei);
        ppei = NULL;
        if (rd != 0)
            LogPrintf(LV_FATAL, "PEI error transmission!!");
    }
    
    return ppei;
}


int DispManipPutPei(pei *ppei)
{
    manip_con *con;
    pei_list *peil;

    if (ppei != NULL) {
        con = DispatManip(ppei->prot_id);

        if (con != NULL) {
            if (ppei->ret == TRUE) {
                LogPrintf(LV_WARNING, "Pei with return!");
#ifdef XPL_CHECK_CODE
                PeiPrint(ppei);
                ProtStackFrmDisp(ppei->stack, TRUE);
                exit(-1);
#endif
            }

            /* lock */
            pthread_mutex_lock(con->mux);
            /* check if manipulator off */
            if (con->wait == TRUE) {
                /* put pei in queue */
                peil = DMemMalloc(sizeof(pei_list));
                peil->ppei = ppei;
                peil->nxt = NULL;
                ppei = NULL;
                if (con->peilast != NULL) {
                    con->peilast->nxt = peil;
                    con->peilast = peil;
                }
                else {
#ifdef XPL_CHECK_CODE
                    if (con->peil != NULL) {
                        LogPrintf(LV_FATAL, "Manipulator queue error");
                        exit(-1);
                    }
#endif                    
                    con->peil = peil;
                    con->peilast = peil;
                }
                /* reconnect */
                if (DispAggConn(con) == 0) {
                    /* send all pei */
                    peil = con->peil;
                    while (peil != NULL) {
                        if (DispManipSend(con->sock, peil->ppei) != 0) {
                            DispatManipOff(peil->ppei->prot_id);
                            peil = NULL;
                        }
                        else {
                            con->peil = peil->nxt;
                            PeiFree(peil->ppei);
                            DMemFree(peil);
                            peil = con->peil;
                            if (peil == NULL) {
                                con->peilast = NULL;
                            }
                        }
                    }
                }
            }
            else {
                /* send to manipulator */
                /* IMPORTANT!: if valgrind notifies a warning as "write(buf) points to uninitialised byte" it is not a bug, all attribute are union and the function ProtInsAttr copy all data even if uninitialised */
                if (DispManipSend(con->sock, ppei) != 0) {
                    DispatManipOff(ppei->prot_id);
                    /* put pei in queue */
                    peil = DMemMalloc(sizeof(pei_list));
                    peil->ppei = ppei;
                    peil->nxt = NULL;
                    ppei = NULL;
#ifdef XPL_CHECK_CODE
                    if (con->peil != NULL) {
                        LogPrintf(LV_FATAL, "Manipulator queue error");
                        exit(-1);
                    }
#endif                    
                    con->peil = peil;
                    con->peilast = peil;
                }
            }
            /* unlock */
            pthread_mutex_unlock(con->mux);
            
            if (ppei != NULL) {
                /* free memory */
                PeiFree(ppei);
            }
            return 0;
        }
    }

    return -1;
}


int DispManipInit(void)
{
    manip_con *con;

    mnp_pei = NULL;
    
    free_port = DISP_MANIP_START_PORT;
    /* contact manipulators */
    con = DispatManipOffLine();
    while (con != NULL) {
        if (DispAggConn(con) != 0) {
            printf("Manipulator %s error\n", con->name);
            return -1;
        }

        /* next server */
        con = DispatManipOffLine();
    }

    return 0;
}


int DispManipEnd(void)
{
    manip_con *con;
    pei_list *peil;
    struct timespec to;

    /* contact manipulators */
    con = DispatManipWait();
    while (con != NULL) {
        while (DispAggConn(con) != 0) {
            to.tv_nsec = 0;
            to.tv_sec = 1;
            /* wait some time */
            nanosleep(&to, NULL);
        }
        /* send all pei */
        peil = con->peil;
        while (peil != NULL) {
            if (DispManipSend(con->sock, peil->ppei) != 0) {
                DispatManipOff(peil->ppei->prot_id);
                peil = NULL;
            }
            else {
                con->peil = peil->nxt;
                PeiFree(peil->ppei);
                DMemFree(peil);
                peil = con->peil;
                if (peil == NULL) {
                    con->peilast = NULL;
                }
            }
        }

        /* next server */
        con = DispatManipWait();
    }
    return 0;
}
