/* dmemory.c
 *
 * $Id: dmemory.c,v 1.6 2007/06/18 06:14:16 costa Exp $
 *
 * Xplico - Internet Traffic Decoder
 * By Gianluca Costa <g.costa@xplico.org>
 * Copyright 2007 Gianluca Costa & Andrea de Franceschi. Web: www.xplico.org
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

#include <stdlib.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>

#include "dmemory.h"
#include "log.h"

#define MEM_BLOCK_LIMIT     (60*1024*1024) /* 60Mb */

#if XP_MEM_SPEED
# define DYN_MEM_ADD_BLOCK    10
# define DYN_MEM_BLOCK_SIZE   2097152

/** protocol descriptor */
typedef struct _dyn_mem dyn_mem;
struct _dyn_mem {
    void *realp;           /**< real malloc pointer */
    size_t size;           /**< block memory size */
    void *lastbyte;        /**< last byte of block */
    void * volatile farea; /**< pointer to free memory area */
    volatile size_t fsize; /**< dimension of free area of block */
    int cnt;               /**< number of dmaloc */
# ifdef XPL_PEDANTIC_STATISTICS
    time_t time_live;      /**< creation time */
# endif
};

static dyn_mem * volatile tbl_block;
static volatile int tbl_dim;
static volatile int tbl_dmem_id;
static pthread_mutex_t dm_mux;


static int DMExtend(void)
{
    dyn_mem *tmp;
    int i;

    /* extend tbl */
    tmp = realloc(tbl_block, sizeof(dyn_mem)*(tbl_dim+DYN_MEM_ADD_BLOCK));
    if (tmp == NULL)
        return -1;
    tbl_block = tmp;

    /* inizialize new element of table */
    for (i=tbl_dim; i<tbl_dim+DYN_MEM_ADD_BLOCK; i++) {
        tbl_block[i].realp = NULL;
        tbl_block[i].size = 0;
        tbl_block[i].lastbyte = NULL;
        tbl_block[i].farea = NULL;
        tbl_block[i].fsize = 0;
        tbl_block[i].cnt = 0;
# ifdef XPL_PEDANTIC_STATISTICS
        tbl_block[i].time_live = 0;
# endif
    }
    tbl_dim += DYN_MEM_ADD_BLOCK;

    return 0;
}


static void DMBlockFree(int id)
{
    /* free memory */
    if (tbl_block[id].realp != NULL)
        free(tbl_block[id].realp);
    
    /* setup tbl element */
    tbl_block[id].realp = NULL;
    tbl_block[id].size = 0;
    tbl_block[id].lastbyte = NULL;
    tbl_block[id].farea = NULL;
    tbl_block[id].fsize = 0;
    tbl_block[id].cnt = 0;
# ifdef XPL_PEDANTIC_STATISTICS
    tbl_block[id].time_live = 0;
# endif
}


static int DMBlockAlloc(int id)
{
    tbl_block[id].realp = malloc(DYN_MEM_BLOCK_SIZE);
    if (tbl_block[id].realp == NULL)
        return -1;

    tbl_block[id].size = DYN_MEM_BLOCK_SIZE;
    tbl_block[id].lastbyte = (char *)(tbl_block[id].realp) + DYN_MEM_BLOCK_SIZE;
    tbl_block[id].farea = tbl_block[id].realp;
    tbl_block[id].fsize = DYN_MEM_BLOCK_SIZE;
    tbl_block[id].cnt = 0;
# ifdef XPL_PEDANTIC_STATISTICS
    tbl_block[id].time_live = time(NULL);
# endif
    
    return 0;
}


int DMemInit(void)
{
    /* inizialize mutex */
    pthread_mutex_init(&dm_mux, NULL);

    /* initialization of table of blocks */
    tbl_block = NULL;
    tbl_dim = 0;
    tbl_dmem_id = 0;
    DMExtend();

    /* create first block */
    DMBlockAlloc(tbl_dmem_id);

    return 0;
}


void *DMemMalloc(size_t size)
{
    int i;
    void *ret;

    pthread_mutex_lock(&dm_mux);
    /* verify memory space */
    if (tbl_block[tbl_dmem_id].fsize < size) {
        /* new block */
        for (i=0; i<tbl_dim; i++) {
            if (tbl_block[i].realp == NULL) {
                if (DMBlockAlloc(i) == -1) {
                    pthread_mutex_unlock(&dm_mux);

                    return NULL;
                }
                tbl_dmem_id = i;
                if (tbl_block[i].size < size) {
                    pthread_mutex_unlock(&dm_mux);
                    
                    return NULL;
                }

                break;
            }
        }
    }
    ret = tbl_block[tbl_dmem_id].farea;
    tbl_block[tbl_dmem_id].farea = (char *)(tbl_block[tbl_dmem_id].farea)+size;
    tbl_block[tbl_dmem_id].fsize -= size;
    tbl_block[tbl_dmem_id].cnt++;

    pthread_mutex_unlock(&dm_mux);

    return ret;
}


void DMemFree(void *ptr)
{
    int i;

    pthread_mutex_lock(&dm_mux);
    /* seach block */
    for (i=0; i<tbl_dim; i++) {
        if (tbl_block[i].realp <= ptr && tbl_block[i].lastbyte > ptr) {
            tbl_block[i].cnt--;
            /* check if last free */
            if (tbl_block[i].cnt == 0 && i != tbl_dmem_id) {
                DMBlockFree(i);
            }
                
            break;
        }
    }
    if (i == tbl_dim) {
        LogPrintf(LV_FATAL, "DMemFree error");
        while (1)
            sleep(1);
        exit(-1);
    }
    pthread_mutex_unlock(&dm_mux);
}


void DMemEmpty(void)
{
    int i;

    pthread_mutex_lock(&dm_mux);
    /* force free of all block */
    for (i=0; i<tbl_dim; i++) {
        if (tbl_block[i].realp != NULL) {
            DMBlockFree(i);
        }
    }
    
    /* create first block */
    if (DMBlockAlloc(0) == -1) {
        LogPrintf(LV_FATAL, "DMemEmpty error");
        exit(-1);
    }
    tbl_dmem_id = 0;

    pthread_mutex_unlock(&dm_mux);
    
}


void DMemState(void)
{
    pthread_mutex_lock(&dm_mux);
    
    pthread_mutex_unlock(&dm_mux);
}

#endif

#if XP_MEM_DEBUG
void *XMalloc(size_t size, const char *function, int line)
{
    if (size > MEM_BLOCK_LIMIT) {
        LogPrintf(LV_WARNING, "Try to allocate big (%lubyte) memory block: %s:%i", size, function, line);
    }

    return malloc(size);
}


void XFree(void *ptr, const char *function, int line)
{
    free(ptr);
}


void *XRealloc(void *ptr, size_t size, const char *function, int line)
{
    if (size > MEM_BLOCK_LIMIT) {
        LogPrintf(LV_WARNING, "Try to re-allocate big (%lubyte) memory block: %s:%i", size, function, line);
    }

    return realloc(ptr, size);
}


void *XMemcpy(void *dest, const void *src, size_t n, const char *function, int line)
{
    unsigned int i, z;
    
    if (n > MEM_BLOCK_LIMIT) {
        LogPrintf(LV_WARNING, "Try to memcpy big (%lubyte) memory block: %s:%i", n, function, line);
    }
    
    z = n/sizeof(unsigned long);
    for (i=0; i!=z; i++) {
        ((unsigned long *)dest)[i] = ((unsigned long *)src)[i];
    }
    z = z*sizeof(unsigned long);
    for (i=z; i!=n; i++) {
        ((unsigned char *)dest)[i] = ((unsigned char *)src)[i];
    }
    
    return dest;
}

char *XStrcpy(char *dest, const char *src, const char *function, int line)
{
    unsigned int i;

    if (dest == NULL || src == NULL)
        return NULL;
    
    i = 0;

    while (src[i] != '\0') {
        dest[i] = src[i];
        i++;
    }
    dest[i] = src[i];
    
    return dest;
}

#endif
