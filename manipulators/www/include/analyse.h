/* analise.h
 *
 * $Id:  $
 *
 * Xplico System
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


#ifndef __ANALISE_H__
#define __ANALISE_H__

#include <time.h>

#include "pei.h"
#include "packet.h"

#define SITE_PQ_LIMIT     100
#define SITE_BUFFER_DIM   1024
#define SITE_BIG_TIME     10000

/* pei queue */
typedef struct _peiq peiq;
struct _peiq {
    pei *pei;
    bool container;  /* if true it is likely a html page */
    bool contained;  /* if true it is a contained! */
    bool href;       /* it has a refer */
    time_t thref; /* sec */
    unsigned short nref; /* it is a refer for many contents */
    time_t tnref; /* sec */
    peiq *pre;
    peiq *nxt;
};


/** pei of same client */
typedef struct _anls_cln anls_cln;
struct _anls_cln {
    pstack_f *stack;             /**< stack base            */
    ftval ipx;                   /**< client IP             */
    enum ftype ip_tp;            /**< ip type: IPv4 or IPv6 */
};


int AnalyseInit(void);
int AnalysePei(pei *ppei);
int AnalyseEnd(void);


#endif /* __ANALISE_H__ */
