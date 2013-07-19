/*
 * sock_stat.h interface to inet diag
 * Copyright (C) 2012  Crs Chin <crs.chin@gmail.com>
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

#ifndef __SOCK_STAT_H
#define __SOCK_STAT_H

#include <malloc.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>

#include "util.h"
#include "ginkgo.h"
#include "linux_inet_diag.h"
#include "linux_sock_diag.h"

__BEGIN_DECLS

typedef struct _sk_entry sk_entry;

struct _sk_entry{
    struct inet_diag_msg *info;
    struct tcp_info *tcp;
    struct inet_diag_meminfo *mem;
    struct tcpvegas_info *vegas;
    char *cong;
};

extern int sock_stat_init(ginkgo_ctx *ctx);

extern int inet_diag_v2;        /* non-zero if available */
extern int inet_diag_v2_udp;    /* non-zero if available */

extern int __sock_stat_dump(list *sks, ginkgo_msg *msg);
extern ginkgo_msg *alloc_req_msg(const struct inet_diag_req *req, int flags);
extern ginkgo_msg *alloc_req_msg_v2(const struct inet_diag_req_v2 *req, int type, int flags);
extern sk_entry *__sock_stat_get(ginkgo_msg *msg);

static inline int sock_stat_dump(list *sks, const struct inet_diag_req_v2 *req)
{
    ginkgo_msg *msg;

    if((msg = alloc_req_msg_v2(req, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST | NLM_F_DUMP)))
        return __sock_stat_dump(sks, msg);
    return -1;
}

/* including both tcp and tcpv6 */
static inline int sock_stat_dump_tcp_compat(list *sks, int tcp_state, __be16 sport, __be16 dport)
{
    struct inet_diag_req req;
    ginkgo_msg *msg;

    bzero(&req, sizeof(req));
    req.idiag_states = tcp_state;
    req.id.idiag_sport = sport;
    req.id.idiag_dport = dport;

    if((msg = alloc_req_msg(&req, NLM_F_REQUEST | NLM_F_DUMP)))
        return __sock_stat_dump(sks, msg);
    return -1;
}

static inline int sock_stat_dump_tcp(list *sks, int af, int tcp_state, __be16 sport, __be16 dport)
{
    struct inet_diag_req_v2 req;

    bzero(&req, sizeof(req));
    req.sdiag_family = af;
    req.sdiag_protocol = IPPROTO_TCP;
    req.idiag_states = tcp_state;
    req.id.idiag_sport = sport;
    req.id.idiag_dport = dport;

    return sock_stat_dump(sks, &req);
}

static inline int sock_stat_dump_udp(list *sks, int af, __be16 sport, __be16 dport)
{
    struct inet_diag_req_v2 req;

    bzero(&req, sizeof(req));
    req.sdiag_family = af;
    req.sdiag_protocol = IPPROTO_UDP;
    req.idiag_states = -1;
    req.id.idiag_sport = sport;
    req.id.idiag_dport = dport;

    return sock_stat_dump(sks, &req);
}

/* lookup from proc fs */
extern int sock_stat_dump_udp_from_proc(list *sks, int af, __u16 sport, __u16 dport);
extern sk_entry *sock_stat_get_udp_from_proc(__be32 src, __be32 dst, __u16 sport, __u16 dport);
extern sk_entry *sock_stat_get_udp6_from_proc(__be32 *src, __be32 *dst, __u16 sport, __u16 dport);

/**
 * NOTE:
 *  compat mode support TCP only
 */
static inline sk_entry *sock_stat_get_compat(const struct inet_diag_req *req)
{
    ginkgo_msg *msg;

    if((msg = alloc_req_msg(req, NLM_F_REQUEST)))
       return __sock_stat_get(msg);
    return NULL;
}

static inline sk_entry *sock_stat_get(const struct inet_diag_req_v2 *req)
{
    ginkgo_msg *msg;

    if((msg = alloc_req_msg_v2(req, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST)))
       return __sock_stat_get(msg);
    return NULL;
}

/* TODO: can't work! why? */
static inline sk_entry *sock_stat_get_udp(__be32 src, __be32 dst, __be16 sport, __be16 dport, __u32 iif)
{
    struct inet_diag_req_v2 req = {
        .sdiag_family = AF_INET,
        .sdiag_protocol = IPPROTO_UDP,
        .idiag_ext = 0,
        .pad = 0,
        .idiag_states = 0,
        .id = {
            .idiag_sport = sport,
            .idiag_dport = dport,
            .idiag_src = {
                src, 0, 0, 0,
            },
            .idiag_dst = {
                dst, 0, 0, 0,
            },
            .idiag_if = iif,
            .idiag_cookie = {
                INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE,
            },
        },
    };

    return sock_stat_get(&req);
}

static inline sk_entry *sock_stat_get_udp6(__be32 *src, __be32 *dst, __be16 sport, __be16 dport, __u32 iif)
{
    struct inet_diag_req_v2 req = {
        .sdiag_family = AF_INET6,
        .sdiag_protocol = IPPROTO_UDP,
        .idiag_ext = 0,
        .pad = 0,
        .idiag_states = 0,
        .id = {
            .idiag_sport = sport,
            .idiag_dport = dport,
            .idiag_src = {
                src[0], src[1], src[2], src[3],
            },
            .idiag_dst = {
                dst[0], dst[1], dst[2], dst[3],
            },
            .idiag_if = iif,
            .idiag_cookie = {
                INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE,
            },
        },
    };

    return sock_stat_get(&req);
}

static inline sk_entry *sock_stat_get_tcp(__be32 src, __be32 dst, __be16 sport, __be16 dport, __u32 iif)
{
    struct inet_diag_req_v2 req = {
        .sdiag_family = AF_INET,
        .sdiag_protocol = IPPROTO_TCP,
        .idiag_ext = 0,
        .pad = 0,
        .idiag_states = 0,
        .id = {
            .idiag_sport = sport,
            .idiag_dport = dport,
            .idiag_src = {
                src, 0, 0, 0,
            },
            .idiag_dst = {
                dst, 0, 0, 0,
            },
            .idiag_if = iif,
            .idiag_cookie = {
                INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE,
            },
        },
    };

    return sock_stat_get(&req);
}

static inline sk_entry *sock_stat_get_tcp_compat(__be32 src, __be32 dst, __be16 sport, __be16 dport, __u32 iif)
{
    struct inet_diag_req req;

    bzero(&req, sizeof(req));
    req.idiag_family = AF_INET;
    req.id.idiag_sport = sport;
    req.id.idiag_dport = dport;
    req.id.idiag_src[0] = src;
    req.id.idiag_dst[0] = dst;
    req.id.idiag_if = iif;
    req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    req.idiag_states = -1;

    return sock_stat_get_compat(&req);
}

static inline sk_entry *sock_stat_get_tcp6_compat(__be32 *src, __be32 *dst, __be16 sport, __be16 dport, __u32 iif)
{
    struct inet_diag_req req;

    bzero(&req, sizeof(req));
    req.idiag_family = AF_INET6;
    req.id.idiag_sport = sport;
    req.id.idiag_dport = dport;
    memcpy(req.id.idiag_src, src, sizeof(req.id.idiag_src));
    memcpy(req.id.idiag_dst, dst, sizeof(req.id.idiag_dst));
    req.id.idiag_if = iif;
    req.id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
    req.id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
    req.idiag_states = -1;

    return sock_stat_get_compat(&req);
}

/* portable functions across kernels */

static inline int sock_stat_lookup_udp(list *sks, __be16 sport, __be16 dport)
{
    if(inet_diag_v2_udp)
        return sock_stat_dump_udp(sks, AF_INET, sport, dport);
    return sock_stat_dump_udp_from_proc(sks, AF_INET, ntohs(sport), ntohs(dport));
}

static inline sk_entry *sock_stat_lookup_udp_exact(__be32 src, __be32 dst, __be16 sport, __be16 dport, __be32 iif)
{
    /* FIXME: this can't work, reason unknown yet.*/
    /* if(inet_diag_v2) */
    /*     return sock_stat_get_udp(src, dst, sport, dport, iif); */
    return sock_stat_get_udp_from_proc(src, dst, ntohs(sport), ntohs(dport));
}

static inline sk_entry *sock_stat_lookup_tcp(__be32 src, __be32 dst, __be16 sport, __be16 dport, __u32 iif)
{
    /* compat mode always available */
    if(inet_diag_v2)
        return sock_stat_get_tcp(src, dst, sport, dport, iif);
    return sock_stat_get_tcp_compat(src, dst, sport, dport, iif);
}

static inline int sock_stat_lookup_udp6(list *sks, __be16 sport, __be16 dport)
{
    if(inet_diag_v2_udp)
        return sock_stat_dump_udp(sks, AF_INET6, sport, dport);
    return sock_stat_dump_udp_from_proc(sks, AF_INET6, ntohs(sport), ntohs(dport));
}

static inline sk_entry *sock_stat_lookup_udp6_exact(__be32 *src, __be32 *dst, __be16 sport, __be16 dport, __u32 iif)
{
    if(inet_diag_v2_udp)
        return sock_stat_get_udp6(src, dst, sport, dport, iif);
    return sock_stat_get_udp6_from_proc(src, dst, ntohs(sport), ntohs(dport));
}

static inline sk_entry *sock_stat_lookup_tcp6(__be32 *src, __be32 *dst, __be16 sport, __be16 dport, __u32 iif)
{
    /* compat mode always available */
    return sock_stat_get_tcp6_compat(src, dst, sport, dport, iif);
}

#define list_sk_entry(ptr)                                          \
    ((sk_entry *)&(list_entry((ptr),ginkgo_msg,lst))->cmn)

#define sk_entry_list(sk)                                           \
    (&(list_entry(sk,ginkgo_msg,cmn))->lst)

#define list_for_each_sk_entry(sk,ls,head)                          \
    for(ls = (head)->l_nxt, sk = list_sk_entry(ls);                 \
        ls != (head);                                               \
        ls = ls->l_nxt, sk = list_sk_entry(ls))

#define list_for_each_sk_entry_safe(sk,n,ls,head)                       \
    for(ls = (head)->l_nxt,                                             \
            sk = list_sk_entry(ls),                                     \
            n = list_sk_entry(ls->l_nxt);                               \
        ls != (head);                                                   \
        sk = n, ls = sk_entry_list(n), n = list_sk_entry(ls->l_nxt))

static inline void sk_entry_free(sk_entry *e)
{
    free(container_of(e, ginkgo_msg, cmn));
}

static inline void sk_entry_list_free(list *h)
{
    sk_entry *sk, *n;
    list *tmp;

    list_for_each_sk_entry_safe(sk, n, tmp, h)  {
        list_delete(sk_entry_list(sk));
        sk_entry_free(sk);
    }
}

extern int udp_port_opened_from_proc(__u16 port);

/* NOTE: canonical will dump both INET and INET6 */
static inline int sock_stat_lookup_tcp_port(list *sks, __be16 sport, __u8 stat)
{
    /* compat mode always available, check listened port only */
    return sock_stat_dump_tcp_compat(sks, 1 << stat, sport, 0);
}

/* udp dport must be checked dynamically */
static inline int sock_stat_lookup_udp_port(list *sks, __be16 sport)
{
    if(inet_diag_v2_udp)
        return sock_stat_dump_udp(sks, AF_INET, sport, 0);
    return sock_stat_dump_udp_from_proc(sks, AF_INET, ntohs(sport), 0);
}

/**
 * return non-zero if local port opened, -1 for error
 * NOTE:
 *  sock stat parsing has no malloc/free penalty, fine to use directly
 *  to detect.
 */
static inline int tcp_port_opened(__be16 port)
{
    list sks;
    int opened = -1;

    /* compat mode always available, check listened port only */
    if(! sock_stat_dump_tcp_compat(&sks, 1 << TCP_LISTEN, port, 0))  {
        opened = ! list_empty(&sks);
        sk_entry_list_free(&sks);
    }
    return opened;
}

static inline int udp_port_opened(__be16 port)
{
    list sks;
    int opened = -1;

    if(inet_diag_v2_udp)  {
        if(! sock_stat_dump_udp(&sks, AF_INET, port, 0))  {
            opened = ! list_empty(&sks);
            sk_entry_list_free(&sks);
        }
        return opened;
    }
    return udp_port_opened_from_proc(ntohs(port));
}

__END_DECLS

#endif  /* __SOCK_STAT_H */

