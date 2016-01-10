/* field_types.c
 * field types functions set
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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <regex.h>

#include "ftypes.h"
#include "istypes.h"
#include "dmemory.h"
#include "log.h"

int FTCopy(ftval *d, const ftval *s, enum ftype type)
{
    switch (type) {
    case FT_STRING:
        if (s->str != NULL) {
            d->str = DMemMalloc(strlen(s->str)+1);
            strcpy(d->str, s->str);
        }
        else
            d->str = NULL;
        break;
        
    default:
        memcpy(d, s, sizeof(ftval));
    }

    return 0;
}


int FTFree(ftval *a, enum ftype type)
{
    switch (type) {
    case FT_STRING:
        if (a->str != NULL) {
            DMemFree(a->str);
        }
        break;
        
    default:
        break;
    }

    return 0;
}


int FTCmp(const ftval *a, const ftval *b, enum ftype type, enum ft_op op, void *opd)
{
    int ret = 0;

    if (op == FT_OP_EQ) {
        switch (type) {
        case FT_NONE:
            break;
            
        case FT_UINT8:
            ret = (a->uint8 == b->uint8);
            break;
            
        case FT_UINT16:
            ret = (a->uint16 == b->uint16);
            break;
            
        case FT_UINT24:
            ret = (a->uint32 == b->uint32);
            break;
            
        case FT_UINT32:
        case FT_IPv4:
            ret = (a->uint32 == b->uint32);
            break;
            
        case FT_UINT64:
            LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
            exit(-1);
            break;
            
        case FT_INT8:
            ret = (a->int8 == b->int8);
            break;
            
        case FT_INT16:
            ret = (a->int16 == b->int16);
            break;
            
        case FT_INT24:
            ret = (a->int32 == b->int32);
            break;
            
        case FT_INT32:
            ret = (a->int32 == b->int32);
            break;
            
        case FT_INT64:
            LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
            exit(-1);
            break;
            
        case FT_SIZE:
            ret = (a->size == b->size);
            break;

        case FT_FLOAT:
            ret = (a->flt == b->flt);
            break;
            
        case FT_DOUBLE:
            ret = (a->dbl == b->dbl);
            break;
            
        case FT_STRING:
            if (a->str != NULL && b->str != NULL && strcmp(a->str, b->str) == 0) {
                return 0;
            }
            break;
            
        case FT_IPv6:
            if (memcmp(a->ipv6, b->ipv6, 16) == 0)
                return 0;
            break;

        case FT_ETHER:
            if (memcmp(a->mac, b->mac, 6) == 0)
                return 0;
            break;
        }
    }
    else if (op == FT_OP_CNTD) {
        switch (type) {
        case FT_STRING:
            if (a->str != NULL && b->str != NULL && strstr(a->str, b->str) != NULL) {
                return 0;
            }
            break;

        default:
            break;
        }
    }
    else if (op == FT_OP_REX) {
        switch (type) {
        case FT_STRING:
            if (a->str != NULL) {
                if (regexec(opd, a->str, 0, NULL, 0) == 0)
                    return 0;
            }
            break;

        default:
            break;
        }
    }
    
    return !ret;
}


int FTCmpVal(const ftval *a, const ftval *b, enum ftype type)
{
    switch (type) {
    case FT_NONE:
        break;
        
    case FT_UINT8:
        if (a->uint8 == b->uint8)
            return 0;
        if (a->uint8 > b->uint8)
            return 1;
        return -1;
        break;
        
    case FT_UINT16:
        if (a->uint16 == b->uint16)
            return 0;
        if (a->uint16 > b->uint16)
            return 1;
        return -1;
        break;
        
    case FT_UINT24:
        if (a->uint32 == b->uint32)
            return 0;
        if (a->uint32 > b->uint32)
            return 1;
        return -1;
        break;
        
    case FT_UINT32:
    case FT_IPv4:
        if (a->uint32 == b->uint32)
            return 0;
        if (a->uint32 > b->uint32)
            return 1;
        return -1;
        break;
        
    case FT_UINT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;
        
    case FT_INT8:
        if (a->int8 == b->int8)
            return 0;
        if (a->int8 > b->int8)
            return 1;
        return -1;
        break;
        
    case FT_INT16:
        if (a->int16 == b->int16)
            return 0;
        if (a->int16 > b->int16)
            return 1;
        return -1;
        break;
        
    case FT_INT24:
        if (a->int32 == b->int32)
            return 0;
        if (a->int32 > b->int32)
            return 1;
        return -1;
        break;
        
    case FT_INT32:
        if (a->int32 == b->int32)
            return 0;
        if (a->int32 > b->int32)
            return 1;
        return -1;
        break;
        
    case FT_INT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;
        
    case FT_SIZE:
        if (a->size == b->size)
            return 0;
        if (a->size > b->size)
            return 1;
        return -1;
        break;

    case FT_FLOAT:
        if (a->flt == b->flt)
            return 0;
        if (a->flt > b->flt)
            return 1;
        return -1;
        break;
        
    case FT_DOUBLE:
        if (a->dbl == b->dbl)
            return 0;
        if (a->dbl > b->dbl)
            return 1;
        return -1;
        break;
        
    case FT_STRING:
        return strcmp(a->str, b->str);
        break;
        
    case FT_IPv6:
        return memcmp(a->ipv6, b->ipv6, 16);
        break;
        
    case FT_ETHER:
        return memcmp(a->mac, b->mac, 6);
        break;

    default:
        LogPrintf(LV_OOPS, "Compare without type value %s line: %d", __FILE__, __LINE__);
        break;
    }

    
    return 0;
}


char *FTString(const ftval *val, enum ftype type, char *buff)
{
    struct in_addr ip_addr;
    struct in6_addr ipv6_addr;
    char ip_str[INET6_ADDRSTRLEN];

    switch (type) {
    case FT_NONE:
        buff[0] = '\0';
        break;

    case FT_UINT8:
        sprintf(buff, "%d", val->uint8);
        break;

    case FT_UINT16:
        sprintf(buff, "%d", val->uint16);
        break;

    case FT_UINT24:
        sprintf(buff, "%i", val->uint32);
        break;

    case FT_UINT32:
        sprintf(buff, "%i", val->uint32);
        break;

    case FT_UINT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;

    case FT_INT8:
        sprintf(buff, "%d", val->int8);
        break;

    case FT_INT16:
        sprintf(buff, "%d", val->int16);
        break;

    case FT_INT24:
        sprintf(buff, "%i", val->int32);
        break;

    case FT_INT32:
        sprintf(buff, "%i", val->int32);
        break;

    case FT_INT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;

    case FT_SIZE:
        sprintf(buff, "%zu", val->size);
        break;

    case FT_FLOAT:
        sprintf(buff, "%f", val->flt);
        break;

    case FT_DOUBLE:
        sprintf(buff, "%f", val->dbl);
        break;

    case FT_STRING:
        if (val->str != NULL)
            sprintf(buff, "%s", val->str);
        else
            sprintf(buff, "(nill)");
        break;
        
    case FT_IPv4:
        ip_addr.s_addr = val->uint32;
        sprintf(buff, "%s", inet_ntop(AF_INET, &ip_addr, ip_str, INET6_ADDRSTRLEN));
        break;

    case FT_IPv6:
        memcpy(ipv6_addr.s6_addr, val->ipv6, 16);
        sprintf(buff, "%s", inet_ntop(AF_INET6, &ipv6_addr, ip_str, INET6_ADDRSTRLEN));
        break;

    case FT_ETHER:
        sprintf(buff, "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x", val->mac[0], val->mac[1], val->mac[2], val->mac[3], val->mac[4], val->mac[5]);
        break;

    default:
        buff[0] = '\0';
    }

    return buff;
}


unsigned long FTHash(ftval *val, enum ftype type)
{
    unsigned long hash;


    switch (type) {
    case FT_NONE:
        break;

    case FT_UINT8:
        hash = (unsigned long)val->uint8;
        break;

    case FT_UINT16:
        hash = (unsigned long)val->uint16;
        break;

    case FT_UINT24:
        hash = (unsigned long)val->uint32;
        break;

    case FT_UINT32:
        hash = (unsigned long)val->uint32;
        break;

    case FT_UINT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;

    case FT_INT8:
        hash = (unsigned long)val->int8;
        break;

    case FT_INT16:
        hash = (unsigned long)val->int16;
        break;

    case FT_INT24:
        hash = (unsigned long)val->int32;
        break;

    case FT_INT32:
        hash = (unsigned long)val->int32;
        break;

    case FT_INT64:
        LogPrintf(LV_OOPS, "FT_UINT64 not defined!");
        exit(-1);
        break;

    case FT_SIZE:
        if (sizeof(unsigned long) < sizeof(size_t)) {
            LogPrintf(LV_OOPS, "FT_SIZE has not hash!");
            exit(-1);
        }
        else
            hash = (unsigned long)val->size;
        break;

    case FT_FLOAT:
    case FT_DOUBLE:
    case FT_STRING:
        LogPrintf(LV_OOPS, "To be implemente: function %s line: %d", __FILE__, __LINE__);
        break;
        
    case FT_IPv4:
        hash = (unsigned long)val->uint32;
        break;

    case FT_IPv6:
        hash = *(unsigned int *)(val->ipv6);
        hash += *(unsigned int *)(val->ipv6+4);
        hash += *(unsigned int *)(val->ipv6+8);
        hash += *(unsigned int *)(val->ipv6+12);
        break;

    case FT_ETHER:
        hash = *(unsigned int *)(val->mac);
        hash += *(unsigned short *)(val->mac+4);
        break;
    }

    return hash;
}
