/*
 * nfct.h
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


#ifndef __NFCT_H
#define __NFCT_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include "linux_netfilter_nfnetlink_conntrack.h"
#include "linux_netfilter_nf_conntrack_common.h"
#include "linux_netfilter_nf_conntrack_tuple_common.h"
#include "linux_netfilter_nf_conntrack_tcp.h"
#include "linux_netfilter_nf_conntrack_sctp.h"

#include "util.h"
#include "nl.h"
#include "ginkgo.h"

__BEGIN_DECLS

typedef struct _conn_counter conn_counter;
typedef struct _conn_timestamp conn_timestamp;

typedef struct _conn_tcpinfo conn_tcpinfo;
typedef struct _conn_sctpinfo conn_sctpinfo;

typedef struct _conn_tuple conn_tuple;

typedef struct _conn_entry conn_entry;
typedef struct _exp_entry exp_entry; /* todo: yet. */

typedef struct _nfct_msg nfct_msg;

typedef struct _nfct_t nfct_t;

struct _conn_counter{
    __u64 orig_pkts;
    __u64 orig_bytes;
    __u64 rep_pkts;
    __u64 rep_bytes;
};

struct _conn_timestamp{
    __u64 start;
    __u64 stop;                 /* 0 marks not stopped */
};

struct _conn_tcpinfo{
    __u8 state;
    __u8 wscale_orig;
    __u8 wscale_rep;
    struct nf_ct_tcp_flags flags_orig;
    struct nf_ct_tcp_flags flags_rep;
};

struct _conn_sctpinfo{
    __u8 state;
    __u32 vtag_orig;
    __u32 vtag_rep;
};

struct _conn_tuple{
    struct{
        union nf_inet_addr u3;
        union nf_conntrack_man_proto u;
        __u16 l3num;            /* currently AF_INET or AF_INET6 */
    }src;
    struct{
        union nf_inet_addr u3;
        union {
            /* Add other protocols here. */
            __be16 all;
            struct {
                __be16 port;
            } tcp;
            struct {
                __be16 port;
            } udp;
            struct {
                __u8 type, code;
            } icmp;
            struct {
                __be16 port;
            } dccp;
            struct {
                __be16 port;
            } sctp;
            struct {
                __be16 key;
            } gre;
        } u;
        __u8 protonum;          /* tcp, udp and etc. */
    }dst;
};

struct _conn_entry{
    __u8 l3num;                /* only AF_INET and AF_INET6 available */
    struct nlattr *nla[CTA_MAX];
    __u32 status;
};

/* todo: exp conntrack to be defined if wanted */

struct _nfct_msg{
    __u16 subsys;
    __u16 type;
    void *entry;
};

#define NFCT_MSG(m) ((nfct_msg *)&(m)->cmn)
#define NFCT_GINKGO_MSG(m) container_of(m,ginkgo_msg,cmn)

#define list_nfct_msg(ptr)                     \
    ({ginkgo_msg *gmsg = list_entry((ptr),ginkgo_msg,lst); NFCT_MSG(gmsg);})

#define list_for_each_nfct_msg(m,head)                          \
    {ginkgo_msg *__gmsg;                                        \
    for(__gmsg = list_entry((head)->l_nxt,ginkgo_msg,lst),      \
            m = NFCT_MSG(__gmsg);                               \
        &__gmsg->lst != (head);                                 \
        __gmsg = list_entry(__gmsg->lst.l_nxt,ginkgo_msg,lst),  \
            m = NFCT_MSG(__gmsg))

#define list_for_each_nfct_msg_safe(m,n,head)               \
    {ginkgo_msg *__gmsg, *__gmsg_n;                         \
    for(__gmsg = list_ginkgo((head)->l_nxt),                \
            m = NFCT_MSG(__gmsg),                           \
            __gmsg_n = list_ginkgo_msg(__gmsg->lst.l_nxt),  \
            n = NFCT_MSG(__gmsg_n);                         \
        &__gmsg->lst != (head);                             \
        __gmsg = __gmsg_n, m = n,                           \
            __gmsg_n = list_ginkgo_msg(__gmsg->lst.l_nxt),  \
            n = NFCT_MSG(__gmsg_n))

#define list_end }

static inline void nfct_msg_free(nfct_msg *m)
{
    if(m->entry)
        free(m->entry);
    free(container_of(m, ginkgo_msg, cmn));
}

static inline void nfct_msg_list_free(list *head)
{
    list *l, *n;

    list_for_each_safe(l, n, head)  {
        list_delete(l);
        nfct_msg_free(list_nfct_msg(l));
    }
}

/**
 * executed in ginkgo handler context, return 1 if msg ate up in
 * handler, all mesages include not supported parsed messages, the
 * caller should check messaged types.
 */
typedef int (*nfct_notify)(nfct_t *h, nfct_msg *m, void *ud);

#define NFCT_GRP_NEW (1<<(NFNLGRP_CONNTRACK_NEW - 1))
#define NFCT_GRP_UPDATE (1<<(NFNLGRP_CONNTRACK_UPDATE - 1))
#define NFCT_GRP_DESTROY (1<<(NFNLGRP_CONNTRACK_DESTROY - 1))

nfct_t *nfct_create(ginkgo_ctx *ctx, int grps, nfct_notify cb, void *ud);
void nfct_destroy(nfct_t *ct);

static inline int nfct_event_set_enabled(int st)
{
    return file_write("/proc/sys/net/netfilter/nf_conntrack_events",
                      st ? "1" : "0", -1);
}

static inline int nfct_event_get_enabled(void)
{
    int val;

    if(! file_read_int("/proc/sys/net/netfilter/nf_conntrack_events", &val))
        return val;
    return -1;
}

int nfct_conn_get_counter(const conn_entry *e, conn_counter *counter);
int nfct_conn_get_tcpinfo(const conn_entry *e, conn_tcpinfo *info);
int nfct_conn_get_sctpinfo(const conn_entry *e, conn_sctpinfo *info);
int __nfct_conn_get_tuple(const conn_entry *e, int type, conn_tuple *tuple);

static inline int nfct_conn_get_src_tuple(const conn_entry *e, conn_tuple *src)
{
    return __nfct_conn_get_tuple(e, CTA_TUPLE_ORIG, src);
}

static inline int nfct_conn_get_dst_tuple(const conn_entry *e, conn_tuple *dst)
{
    return __nfct_conn_get_tuple(e, CTA_TUPLE_REPLY, dst);
}

static inline int nfct_conn_get_master_tuple(const conn_entry *e, conn_tuple *master)
{
    return __nfct_conn_get_tuple(e, CTA_TUPLE_MASTER, master);
}

/* fixme: nat seq adj */

static inline __u16 nfct_conn_zone(const conn_entry *e)
{
    if(e->nla[CTA_ZONE])
        return ntohs(nla_get_be16(e->nla[CTA_ZONE]));
    return 0;
}

static inline __u32 nfct_conn_id(const conn_entry *e) /* internal nf_conn ptr */
{
    if(e->nla[CTA_ID])
        return ntohl(nla_get_be32(e->nla[CTA_ID]));
    return 0;
}

static inline __u32 nfct_conn_timeout(const conn_entry *e)
{
    if(e->nla[CTA_TIMEOUT])
        return ntohl(nla_get_be32(e->nla[CTA_TIMEOUT]));
    return 0;
}

static inline __u32 nfct_conn_mark(const conn_entry *e)
{
    if(e->nla[CTA_MARK])
        return ntohl(nla_get_be32(e->nla[CTA_MARK]));
    return 0;
}

static inline __u32 nfct_conn_use(const conn_entry *e)
{
    if(e->nla[CTA_USE])
        return ntohl(nla_get_be32(e->nla[CTA_USE]));
    return 0;
}

static inline const char *nfct_conn_helper_name(const conn_entry *e)
{
    struct nlattr *helper = e->nla[CTA_HELP];
    struct nlattr *arr[CTA_HELP_MAX + 1];

    if(helper)  {
        nla_parse_nested(arr, CTA_HELP_MAX, helper);
        if(arr[CTA_HELP_NAME])
            return (const char *)nla_data(arr[CTA_HELP_NAME]);
    }
    return NULL;
}

static inline const char *nfct_conn_secctx_name(const conn_entry *e)
{
    struct nlattr *secctx = e->nla[CTA_SECCTX];
    struct nlattr *arr[CTA_SECCTX_MAX + 1];

    if(secctx)  {
        nla_parse_nested(arr, CTA_SECCTX_MAX, secctx);
        if(arr[CTA_SECCTX_NAME])
            return (const char *)nla_data(arr[CTA_SECCTX_NAME]);
    }
    return NULL;
}

#define NFCT_F_CREATE 1         /* create if doesn't exist */
#define NFCT_F_EXCL (1<<1)      /* don't touch if exist */
#define NFCT_F_DUMP (1<<2)

nfct_msg *nfct_msg_new(__u8 l3num, int flags);

/**
 * NOTE:
 *   set functions try to set only if relevant field is not set.
 */

#define TCP_F_STATE 1
#define TCP_F_WSCALE_ORIG (1<<1)
#define TCP_F_WSCALE_REP (1<<2)
#define TCP_F_FLAGS_ORIG (1<<3)
#define TCP_F_FLAGS_REP (1<<4)

int nfct_msg_set_tcpinfo(nfct_msg *m, const conn_tcpinfo *info, int mask);

#define SCTP_F_STATE 1
#define SCTP_F_VTAG_ORIG (1<<1)
#define SCTP_F_VTAG_REP (1<<2)

int nfct_msg_set_sctpinfo(nfct_msg *m, const conn_sctpinfo *info, int mask);

int __nfct_msg_set_tuple(nfct_msg *m, int type, const conn_tuple *src);

static inline int nfct_msg_set_src_tuple(nfct_msg *m, const conn_tuple *src)
{
    return __nfct_msg_set_tuple(m, CTA_TUPLE_ORIG, src);
}

static inline int nfct_msg_set_dst_tuple(nfct_msg *m, const conn_tuple *dst)
{
    return __nfct_msg_set_tuple(m, CTA_TUPLE_REPLY, dst);
}

static inline int nfct_msg_set_master_tuple(nfct_msg *m, const conn_tuple *master)
{
    return __nfct_msg_set_tuple(m, CTA_TUPLE_MASTER, master);
}

int __nfct_msg_set_zone(nfct_msg *m, __u16 zone);

static inline int nfct_msg_set_zone(nfct_msg *m, __u16 zone)
{
    /* if zone supported, 0 is defaulted and no need to set, if not
       supported, should not have zone attr existed, so it's safe to
       set a zero zone to conntrack without zone support */
    if(zone)
        return __nfct_msg_set_zone(m, zone);
    return 0;
}

int __nfct_msg_set_be32(nfct_msg *m, int t, __u32 val);

static inline int nfct_msg_set_id(nfct_msg *m, __u32 id)
{
    return __nfct_msg_set_be32(m, CTA_ID, id);
}

static inline int nfct_msg_set_timeout(nfct_msg *m, __u32 timeout)
{
    return __nfct_msg_set_be32(m, CTA_TIMEOUT, timeout);
}

static inline int nfct_msg_set_mark(nfct_msg *m, __u32 mark)
{
    return __nfct_msg_set_be32(m, CTA_MARK, mark);
}

static inline int nfct_msg_set_status(nfct_msg *m, __u32 status)
{
    conn_entry *e = (conn_entry *)m->entry;
    e->status = status;
    return __nfct_msg_set_be32(m, CTA_STATUS, status);
}

int nfct_msg_set_helper_name(nfct_msg *m, const char *name); /* NULL to remove existing helper */
/* fixme: nat seq adj */

#define NFCT_CMD_NEW 1
#define NFCT_CMD_GET 2
#define NFCT_CMD_DEL 3

int nfct_msg_commit(nfct_t *ct, list *res, nfct_msg *m, int cmd, int wait, int nofree);

/**
 * Attributes MUST be set for @nfct_set_conn:
 * 1. CTA_ZONE(0 if not configured)
 * 2. CTA_TUPLE_ORIG
 * 3. CTA_TUPLE_REPLY(ignored if CTA_TUPLE_ORIG exists)
 * 
 * Attributes can be changed on existing conntrack and set for creating:
 * 1. CTA_HELPER
 * 2. CTA_TIMEOUT
 * 3. CTA_STATUS
 * 4. CTA_PROTOINFO
 * 5. CTA_MARK
 * 6. CTA_NAT_SEQ_ADJ_ORIG
 * 7. CTA_NAT_SEQ_ADJ_REPLY
 *
 * Attributes MUST be set for creating conntrack:
 * 1. CTA_TIMEOUT
 *
 * Attributes can ONLY be set for creating conntrack:
 * 1. CTA_NAT_SRC
 * 2. CTA_NAT_DST
 */
static inline int nfct_set_conn(nfct_t *ct, nfct_msg *m, int nofree)
{
    list res;
    int err;

    err = nfct_msg_commit(ct, &res, m, NFCT_CMD_NEW, 1, nofree);
    nfct_msg_list_free(&res);
    return err;
}

/**
 * @dst ignored if @src not NULL, l3num and l4num picked from @src or
 * @dst, and must be valid.
 * @res: valid only if successfuly returned.
 */
static inline int nfct_get_conn(nfct_t *ct, list *res, __u16 zone, const conn_tuple *src, const conn_tuple *dst)
{
    nfct_msg *m;
    __u8 l3;

    if(ct && res && (src || dst))  {
        l3 = (src ? src->src.l3num : dst->src.l3num);
        if((m = nfct_msg_new(l3, 0))
           && (! zone || ! nfct_msg_set_zone(m, zone))
           && (! src || ! nfct_msg_set_src_tuple(m, src))
           && (src || ! dst || ! nfct_msg_set_dst_tuple(m, dst)))
            return nfct_msg_commit(ct, res, m, NFCT_CMD_GET, 1, 0);
        if(m) nfct_msg_free(m);
    }
    return -1;
}

/**
 * @l3num: PF_UNSPEC to dump all
 */
static inline int nfct_dump_conn(nfct_t *ct, list *res, __u8 l3num, __u32 mark)
{
    nfct_msg *m = NULL;

    if(ct && res)  {
        if((m = nfct_msg_new(l3num, NFCT_F_DUMP))
           && (! mark || nfct_msg_set_mark(m, mark)))
            return nfct_msg_commit(ct, res, m, NFCT_CMD_GET, 1, 0);
        if(m) nfct_msg_free(m);
    }
    return -1;
}

/**
 * @dst ignored if @src available, flush all if both NULL
 * l3num picked from @src or @dst
 */
static inline int nfct_del_conn(nfct_t *ct, __u16 zone, const conn_tuple *src, const conn_tuple *dst, __u32 id)
{
    nfct_msg *m = NULL;
    __u8 l3 = (src ? src->src.l3num : (dst ? dst->src.l3num : PF_UNSPEC));

    if(ct && (m = nfct_msg_new(l3, 0))
       && (! src || ! nfct_msg_set_src_tuple(m, src))
       && (src || ! dst || ! nfct_msg_set_dst_tuple(m, dst))
       && (! id || nfct_msg_set_id(m, id)))
        return nfct_msg_commit(ct, NULL, m, NFCT_CMD_DEL, 1, 0);
    if(m) nfct_msg_free(m);
    return -1;
}

__END_DECLS

#endif  /* __NFCT_H */

