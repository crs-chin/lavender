/*
 * nfqm.h management of packets in nfq
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

/**
 * INTRO: track packets in kernel nfq, drop them when it takes too
 * much time for user to respond, or the packet just get outdated,
 * most of all, send them immediately when verdicted allow, so that
 * socket connection doesn't have to depend on retransmission
 * mechanism of uppper layer protocol(or application)
 */

#ifndef __NFQM_H
#define __NFQM_H

#include <time.h>
#include <malloc.h>
#include <pthread.h>
#include <sys/types.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include "util.h"
#include "timer.h"
#include "nfq.h"

__BEGIN_DECLS

typedef struct _nfqm nfqm;

struct _nfqm{
    pthread_mutex_t lock;
    nfq_queue *nfq;
    int flags;
    size_t cnt;
    size_t wmark;
    size_t limit;
    /* timered state full pkts */
    list pkts;
    /* stateless pkts */
    list ipkts;
    /* ?? worth it for just personal fw */
    size_t hash_sz;
    /* currently we hash only tcp packet here */
    hlist_head *phash;
    hlist_head *ihash;
    void *cur;
    __u32 initval;
    timer timer;
    /* tcp syn retries */
    int retries;
};

#define NFQM_F_TCP_CHECK 1            /* handle tcp specially */

int nfqm_init(nfqm *q, int flags, nfq_queue *nfq, size_t max_len);

static inline nfqm *nfqm_create(int flags, nfq_queue *nfq, size_t max_len)
{
    nfqm *q;

    if((q = (nfqm *)malloc(sizeof(*q))))  {
        if(! nfqm_init(q, flags, nfq, max_len))
            return q;
        free(q);
    }
    return NULL;
}

/**
 * currently we manage AF_INET pkts only
 */
int nfqm_push(nfqm *q, const struct iphdr *ip, __be32 pkt_id, __u64 id);
void nfqm_pop(nfqm *q, __u64 id, int verd, __u32 mark);

void nfqm_dump(nfqm *q);

/**
 * @verd: verdict for packets queued, do nothing if set -1
 */
void nfqm_destroy(nfqm *q, int verd, __u32 mark);

__END_DECLS

#endif  /* ! __NFQM_H */

