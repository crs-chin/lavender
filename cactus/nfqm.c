/*
 * nfqm.c
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

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <malloc.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <linux/types.h>
#include <linux/netfilter.h>

#include "util.h"
#include "timer.h"
#include "nfq.h"
#include "nfqm.h"
#include "jhash.h"
#include "cactus_log.h"

#define TCP_INIT_RTO 3000
/* pending pkt no more 60 sec */
#define TCP_MAX_RTO 60000
/* try not keep pkt pending too long, AP may already timed out */
#define TCP_MIN_RETRY 3
#define TCP_DFT_RETRY 4
#define TCP_MAX_RETRY 5
/* not keep normal pkt pending too log, 30 sec at most */
#define PKT_DFT_TIMEOUT 30000
#define HASH_MAX 1024
/* drop packets when queue usage reached 80% */
#define WMARK_FACTOR 80

typedef struct _kpkt kpkt;

/* currently we only identyfy tcp packets, which got timeout and
   retransmit issues, for the other, just let it pending for timeout
   or verdict */
typedef struct _stamp_tcp stamp_tcp;

struct _kpkt{
    list list;
    hlist pnode;
    hlist inode;
    struct timespec ts;
    /* uint in ms */
    unsigned int delta;
    __u64 id;
    __be32 pkt_id;
    int prot;
    char stamp[0];
};

/* FIXME: identify IPv4 only here */
struct _stamp_tcp{
    __be32 src;
    __be32 dst;
    struct{
        __be16 sport;
        __be16 dport;
        __be32 seq;
        __be32 ack;
        __be16 flags_and_etc;
    }tcp __attribute__((packed));
};

static void nfqm_lock(nfqm *q)
{
    pthread_mutex_lock(&q->lock);
}

static void nfqm_unlock(nfqm *q)
{
    pthread_mutex_unlock(&q->lock);
}

static inline int tcphdr_cmp(const struct tcphdr *a, const struct tcphdr *b)
{
    return memcmp(a, b, sizeof(stamp_tcp));
}

static inline int syn_retries(void)
{
    int ret;

    if(file_read_int("/proc/sys/net/ipv4/tcp_syn_retries", &ret))
        return TCP_DFT_RETRY;
    return ret;
}

static inline void *ip_next_hdr(const struct iphdr *ip)
{
    return (char *)ip + ip->ihl * 4;
}

static int ___pkt_drop(nfqm *q, kpkt *p, int verd, __u32 mark)
{
    int err;

    if((err = nfq_verdict(q->nfq, p->pkt_id, verd, mark)))
        LOG_WARN("fail to verdict %d to pkt %u, prot %u",
                 verd, p->pkt_id, p->prot);
    list_delete(&p->list);
    if(hlist_hashed(&p->pnode))
        hlist_delete(&p->pnode);
    if(hlist_hashed(&p->inode))
        hlist_delete(&p->inode);
    if(p == q->cur)
        q->cur = NULL;
    free(p);
    q->cnt--;
    return err;
}

static kpkt *__pkt_latest(nfqm *q)
{
    kpkt *pkt = NULL, *ipkt = NULL;

    if(! list_empty(&q->pkts))
        pkt = list_entry(q->pkts.l_nxt, kpkt, list);
    if(! list_empty(&q->ipkts))
        ipkt = list_entry(q->ipkts.l_nxt, kpkt, list);
    if(! pkt)
        return ipkt;
    if(! ipkt)
        return pkt;
    return ((ts_cmp(&pkt->ts, &ipkt->ts) > 0) ? pkt : ipkt);
}

static inline void __pkt_drop(nfqm *q)
{
    kpkt *p;

    if((p = __pkt_latest(q)))
        ___pkt_drop(q, p, NF_DROP, 0);
}

static inline void __timer_check(nfqm *q)
{
    kpkt *p = __pkt_latest(q);

    if(! p)
        __timer_cancel(&q->timer);
    else if(p != q->cur)  {
        q->cur = p;
        __timer_sched_abs(&q->timer, &p->ts);
    }
}

/* lock already grapped by timer source */
static int __nfqm_timeout(void *ud)
{
    nfqm *q = (nfqm *)ud;
    kpkt *p = (kpkt *)q->cur;
    __be32 pkt_id;
    __u64 id;

    if(p)  {
        pkt_id = p->pkt_id;
        id = p->id;
        if(! ___pkt_drop(q, p, NF_DROP, 0))
            LOG_DEBUG("dropped timed out pkt %u, verd id %" PRIu64, pkt_id, id);
        q->cur = NULL;
        __timer_check(q);
    }else  {
        LOG_ERROR("report bug, timed out pkt stolen, continue");
    }
    return 1;
}

int nfqm_init(nfqm *q, int flags, nfq_queue *nfq, size_t max_len)
{
    if(! q || ! nfq || ! max_len)
        return -1;

    memset(q, 0, sizeof(*q));
    pthread_mutex_init(&q->lock, NULL);
    q->nfq = nfq;
    if(flags & NFQM_F_TCP_CHECK)
        q->flags = NFQM_F_TCP_CHECK;
    list_init(&q->pkts);
    list_init(&q->ipkts);
    q->retries = syn_retries();
    if(q->retries < TCP_MIN_RETRY)
        q->retries = TCP_MIN_RETRY;
    if(q->retries > TCP_MAX_RETRY)
        q->retries = TCP_MAX_RETRY;
    q->limit = max_len;
    q->wmark = q->limit * WMARK_FACTOR / 100;
    q->hash_sz = HASH_MAX;
    if(q->hash_sz > q->wmark)
        q->hash_sz = q->wmark;

    if(flags & NFQM_F_TCP_CHECK)  {
        q->initval = (__u32)random();
        if(! (q->phash = malloc(sizeof(hlist_head) * q->hash_sz)))  {
            LOG_EMERG("unable to alloc phash table, sz %u", q->hash_sz);
            pthread_mutex_destroy(&q->lock);
            return -1;
        }
        memset(q->phash, 0, sizeof(hlist_head) * q->hash_sz);
        LOG_INFO("nfqm allocated phash size %u", q->hash_sz);
    }

    if(! (q->ihash = malloc(sizeof(hlist_head) * q->hash_sz)))  {
        LOG_EMERG("unable to alloc ihash table, sz %u", q->hash_sz);
        if(flags & NFQM_F_TCP_CHECK)
            free(q->phash);
        pthread_mutex_destroy(&q->lock);
        return -1;
    }

    memset(q->ihash, 0, sizeof(hlist_head) * q->hash_sz);
    LOG_INFO("nfqm allocated ihash size %u", q->hash_sz);

    timer_init(&q->timer, &q->lock, __nfqm_timeout, q);
    if(timer_register_src(&q->timer))  {
        LOG_EMERG("unable to register nfqm timer src");
        if(flags & NFQM_F_TCP_CHECK)
            free(q->phash);
        free(q->ihash);
        pthread_mutex_destroy(&q->lock);
        return -1;
    }

    return 0;
}

/* take advantage of kernel's impl. */
static inline __u32 hash_stamp_tcp(const stamp_tcp *st, size_t sz, __u32 initval)
{
    __u32 n = (sizeof(*st) + sizeof(st->tcp.flags_and_etc)) / sizeof(__u32);
    __u32 h = jhash2((__u32 *)st, n, initval ^ ((__u32)st->tcp.flags_and_etc));

    return ((__u64)h * sz) >> 32;
}

/*
static kpkt *___lookup_phash(nfqm *q, const stamp_tcp *st)
{
    __u32 hash = hash_stamp_tcp(st, q->hash_sz, q->initval);
    hlist_head h = &q->phash[hash];
    kpkt *p;
    hlist *pos;

    hlist_for_each_entry(p, pos, h, pnode)  {
        if(! memcmp(st, &p->stamp, sizeof(*st)))
            return p;
    }
    return NULL;
}
*/

static inline __u32 hash_u64(__u64 n, size_t sz)
{
    return (__u32)(n % sz);
}

static inline void __pkt_enqueue(nfqm *q, kpkt *p)
{
    kpkt *iter;

    if((q->flags & NFQM_F_TCP_CHECK) && p->prot == IPPROTO_TCP)  {
        list_for_each_entry(iter, &q->pkts, list)  {
            if(ts_cmp(&p->ts, &iter->ts) < 0)  {
                list_append(iter->list.l_prv, &p->list);
                return;
            }
        }
        list_append(&q->pkts, &p->list);
    }else  {
        list_append(&q->ipkts, &p->list);
    }
}

/* val unit in ms */
static inline void kpkt_init_timer(kpkt *p, unsigned int delta)
{
    clock_gettime(CLOCK_MONOTONIC, &p->ts);
    ts_add(&p->ts, delta);
    p->delta = delta;
}

static void __pkt_phash(nfqm *q, kpkt *p)
{
    __u32 hash = hash_stamp_tcp((const stamp_tcp *)&p->stamp, q->hash_sz, q->initval);
    hlist_head *h = &q->phash[hash];
    unsigned int delta;
    kpkt *iter;
    hlist *pos;

    hlist_for_each_entry(iter, pos, h, pnode)  {
        if(! memcmp(iter->stamp, p->stamp, sizeof(stamp_tcp)))  {
            delta = iter->delta * 2;
            if(delta > TCP_MAX_RTO)
                delta = TCP_MAX_RTO;
            kpkt_init_timer(p, delta);
            ___pkt_drop(q, iter, NF_DROP, 0);
            LOG_DEBUG("retransmition kpkt %" PRIu64 " received, set delta %u, "
                      "dropped the existing %" PRIu64 "", p->id, delta, iter->id);
            break;
        }
    }
    hlist_prepend(h, &p->pnode);
}

static inline void __pkt_ihash(nfqm *q, kpkt *p)
{
    __u32 hash = hash_u64(p->id, q->hash_sz);
    hlist_head *h = &q->ihash[hash];
    /* kpkt *iter; */
    /* hlist *pos; */

    /** unneccessary duplicating check
    hlist_for_each_entry(iter, pos, h, inode)  {
        if(iter->pkt_id == p->pkt_id && iter->id == p->id)  {
            ___pkt_drop(q, iter, NF_DROP, 0);
            LOG_ERROR("unexpected duplicating kpkt %u %" PRIu64 ", dropped the existing",
                      iter->pkt_id, iter->id);
            break;
        }
    }
    */
    hlist_prepend(h, &p->inode);
}

static inline void __pkt_hash(nfqm *q, kpkt *p)
{
    if((q->flags & NFQM_F_TCP_CHECK) && p->prot == IPPROTO_TCP)
        __pkt_phash(q, p);
    __pkt_ihash(q, p);
}

static void __pkt_insert(nfqm *q, kpkt *p)
{
    if(q->cnt >= q->wmark)  {
        LOG_INFO("pkts reaching nfq wmark, start dropping");
        __pkt_drop(q);
    }
    __pkt_hash(q, p);
    __pkt_enqueue(q, p);
    q->cnt++;
    __timer_check(q);
}

static kpkt *kpkt_alloc(const struct iphdr *ip, __be32 pkt_id, __u64 id, size_t stamp_sz)
{
    kpkt *p = (kpkt *)malloc(sizeof(kpkt) + stamp_sz);

    if(p)  {
        list_init(&p->list);
        hlist_init(&p->pnode);
        hlist_init(&p->inode);
        p->id = id;
        p->pkt_id = pkt_id;
        p->prot = ip->protocol;
    }
    return p;
}

static int __tcp_push(nfqm *q, const struct iphdr *ip, __be32 pkt_id, __u64 id)
{
    kpkt *p = kpkt_alloc(ip, pkt_id, id, sizeof(stamp_tcp));
    stamp_tcp *s;

    /* ?? check tcp syn flg ?? */
    if(p)  {
        kpkt_init_timer(p, TCP_INIT_RTO);
        s = (stamp_tcp *)&p->stamp;
        s->src = ip->saddr;
        s->dst = ip->daddr;
        memcpy(&s->tcp, ip_next_hdr(ip), sizeof(s->tcp));
        __pkt_insert(q, p);
        return 0;
    }
    return -1;
}

int nfqm_push(nfqm *q, const struct iphdr *ip, __be32 pkt_id, __u64 id)
{
    kpkt *p;
    int err = 0;

    nfqm_lock(q);
    if(q->flags & NFQM_F_TCP_CHECK && ip->protocol == IPPROTO_TCP)  {
        err = __tcp_push(q, ip, pkt_id, id);
    }else if((p = kpkt_alloc(ip, pkt_id, id, 0)))  {
        kpkt_init_timer(p, PKT_DFT_TIMEOUT);
        __pkt_insert(q, p);
    }else  {
        err = -1;
    }
    nfqm_unlock(q);
    return err;
}

static int __nfqm_pop(nfqm *q, __u64 id, int verd, __u32 mark)
{
    __u32 hash = hash_u64(id, q->hash_sz);
    hlist_head *h = &q->ihash[hash];
    kpkt *p;
    hlist *pos, *n;
    int cnt = 0;

    hlist_for_each_entry_safe(p, pos, n, h, inode)  {
        if(p->id == id)  {
            if(! ___pkt_drop(q, p, verd, mark))
                LOG_DEBUG("pkt %u with verdict %" PRIu64 " popped, verdict %d",
                          p->pkt_id, id, verd);
            else
                LOG_INFO("fail to verdict nfqm pkt %u %" PRIu64 "", p->pkt_id, p->id);
            cnt++;
        }
    }
    return cnt;
}

void nfqm_pop(nfqm *q, __u64 id, int verd, __u32 mark)
{
    nfqm_lock(q);
    if(__nfqm_pop(q, id, verd, mark) <= 0)
        LOG_INFO("no pkt with verdict %" PRIu64 " managed, ignore", id);
    else
        __timer_check(q);
    nfqm_unlock(q);
}

void nfqm_dump(nfqm *q)
{
    kpkt *p;
    stamp_tcp *s;

    nfqm_lock(q);
    if(q->cnt)  {
        LOG_INFO("dump pkts in queue(%u in total):", q->cnt);
        list_for_each_entry(p, &q->pkts, list)  {
            s = (stamp_tcp *)&p->stamp;
            LOG_INFO("pkt %u verdict id %" PRIu64 ":" IP_FMT ":%u -> " IP_FMT ":%u",
                     p->pkt_id, p->id, IP_ARG(s->src), s->tcp.sport, IP_ARG(s->dst), s->tcp.dport);
        }
        list_for_each_entry(p, &q->ipkts, list)  {
            LOG_INFO("pkt %u verdict id %" PRIu64 " prot %u", p->pkt_id, p->id, p->prot);
        }
    }else  {
        LOG_INFO("no pkts in queue to dump");
    }
    nfqm_unlock(q);
}

void nfqm_destroy(nfqm *q, int verd, __u32 mark)
{
    kpkt *p, *n;

    nfqm_lock(q);
    list_for_each_entry_safe(p, n, &q->pkts, list)  {
        if(! ___pkt_drop(q, p, verd, mark))
            LOG_DEBUG("dropped pkt %u, verd id %" PRIu64 " prot %u on destroy",
                      p->pkt_id, p->id, p->prot);
    }
    list_for_each_entry_safe(p, n, &q->ipkts, list)  {
        if(! ___pkt_drop(q, p, verd, mark))
            LOG_DEBUG("dropped pkt %u, verd id %" PRIu64 " prot %u on destroy",
                      p->pkt_id, p->id, p->prot);
    }
    timer_unregister_src(&q->timer);
    if(q->flags & NFQM_F_TCP_CHECK)
        free(q->phash);
    free(q->ihash);
    nfqm_unlock(q);
    pthread_mutex_destroy(&q->lock);
}

