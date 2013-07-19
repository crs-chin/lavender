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

#include <endian.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include "linux_netfilter_nfnetlink_conntrack.h"
#include "linux_netfilter_nf_conntrack_tuple_common.h"
#include "linux_netfilter_nf_conntrack_tcp.h"
#include "linux_netfilter_nf_conntrack_sctp.h"

#include "nl.h"
#include "util.h"
#include "ginkgo.h"
#include "nfct.h"

#define NFCT_MSG_GOOD_SIZE (1024 * 4)

typedef struct _nfct_msg_ctl nfct_msg_ctl;

struct _nfct_msg_ctl{
    nfct_msg base;
    void *ctx;
    size_t sz;
};

struct _nfct_t{
    ginkgo_ctx *ginkgo;
    int id;
    int nlfd;
    int nlgrps;
    int nlseq;
    nfct_notify cb;
    void *ud;
};


static inline nfct_msg_ctl *msg_ctl(ginkgo_msg *msg)
{
    return (nfct_msg_ctl *)&msg->cmn;
}

static int nfct_parse_ct(nfct_msg *ctmsg, struct nlmsghdr *nlh)
{
    struct nfgenmsg *nfmsg = (struct nfgenmsg *)NLMSG_DATA(nlh);
    conn_entry *e;
    struct nlattr *nla;
    int len;

    if(! instantiate(e))
        return 0;
    BZERO(e);
    e->l3num = nfmsg->nfgen_family;
    nla = (struct nlattr *)((char *)NLMSG_DATA(nlh) + NLMSG_ALIGN(sizeof(struct nfgenmsg)));
    len = NLMSG_PAYLOAD(nlh, sizeof(struct nfgenmsg));
    nla_parse(e->nla, CTA_MAX, nla, len);
    if(e->nla[CTA_STATUS])
        e->status = ntohl(nla_get_be32(e->nla[CTA_STATUS]));
    ctmsg->entry = e;
    return 0;
}

static int nfct_parse(ginkgo_msg *msg)
{
    struct nlmsghdr *nlh = NL_HEADER(msg);
    nfct_msg *ctmsg = NFCT_MSG(msg);
    __u16 nlm_type = nlh->nlmsg_type;
    __u16 type = NFNL_MSG_TYPE(nlh->nlmsg_type);
    __u16 subsys = NFNL_SUBSYS_ID(nlh->nlmsg_type);

    if(nlm_type <= NLMSG_MIN_TYPE)
        return -1;

    ctmsg->subsys = subsys;
    ctmsg->type = type;
    ctmsg->entry = NULL;
    if(ctmsg->subsys != NFNL_SUBSYS_CTNETLINK)  {
        PR_INFO("not supported subsys message type parsing:%d %d", subsys, type);
        return 0;
    }
    switch(type)  {
    case IPCTNL_MSG_CT_NEW:
    case IPCTNL_MSG_CT_DELETE:
        return nfct_parse_ct(ctmsg, nlh);
    default:
        PR_INFO("unpexpected ct msg type:%d", type);
        break;
    }
    return 0;
}

static int nfct_handler(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud)
{
    nfct_t *ct = (nfct_t *)ud;

    if(ct->cb && ! nfct_parse(msg))  {
        if(! ct->cb(ud, NFCT_MSG(msg), ct->ud))
            nfct_msg_free(NFCT_MSG(msg));
        return 1;
    }
    return 0;
}

static int nfct_response(ginkgo_msg *msg, ginkgo_msg *rsp)
{
    int val = nl_response(msg, rsp);

    /**
     * IPCTNL_MSG_CT_GET non-dump type request return netlink messages
     * with NLM_F_MULTI set, but will not have subsequent NLMSG_DONE
     * message.
     */
    if(val == GINKGO_RESP_CONT)  {
        struct nlmsghdr *nlh = NL_HEADER(msg);
        __u16 type = NFNL_MSG_TYPE(nlh->nlmsg_type);
        __u16 subsys = NFNL_SUBSYS_ID(nlh->nlmsg_type);

        if(subsys == NFNL_SUBSYS_CTNETLINK
           && type == IPCTNL_MSG_CT_GET
           && (! (nlh->nlmsg_flags & NLM_F_DUMP)))
            return GINKGO_RESP_DONE;
    }
    return val;
}

nfct_t *nfct_create(ginkgo_ctx *ctx, int grps, nfct_notify cb, void *ud)
{
    nfct_t *ct;
    char name[20];
    ginkgo_src src = {
        .name = name,
        .fd = -1,
        .rd = NULL,
        .wr = NULL,
        .pars = nl_parse,
        .resp = nfct_response,
        .hand = nfct_handler,
        .ud = NULL,
    };
    int fd;

    if(! ctx) return NULL;
    if((fd = nl_open(NETLINK_NETFILTER, grps)) < 0)
        return NULL;
    if(! instantiate(ct))  {
        close(fd);
        return NULL;
    }
    ct->ginkgo = ctx;
    ct->nlfd = fd;
    ct->nlgrps = grps;
    ct->nlseq = 0;
    ct->cb = cb;
    ct->ud = ud;

    src.fd = fd;
    src.ud = ct;
    sprintf(name, "nfct-%d", fd);
    if(ginkgo_src_register(ctx, &src, &ct->id, 0) < 0)  {
        close(fd);
        free(ct);
        return NULL;
    }
    return ct;
}

void nfct_destroy(nfct_t *ct)
{
    if(ct)  {
        ginkgo_src_deregister(ct->ginkgo, ct->id, 1, 1);
        close(ct->nlfd);
        free(ct);
    }
}

int nfct_conn_get_counter(const conn_entry *e, conn_counter *counter)
{
    const struct nlattr *orig = e->nla[CTA_COUNTERS_ORIG];
    const struct nlattr *rep = e->nla[CTA_COUNTERS_REPLY];
    struct nlattr *arr[CTA_COUNTERS_MAX + 1];

    if(orig && rep)  {
        nla_parse_nested(arr, CTA_COUNTERS_MAX, orig);
        if(! arr[CTA_COUNTERS_PACKETS] || ! arr[CTA_COUNTERS_BYTES])
            return -1;
        counter->orig_pkts = be64toh(nla_get_be64(arr[CTA_COUNTERS_PACKETS]));
        counter->orig_bytes = be64toh(nla_get_be64(arr[CTA_COUNTERS_BYTES]));

        nla_parse_nested(arr, CTA_COUNTERS_MAX, rep);
        if(! arr[CTA_COUNTERS_PACKETS] || ! arr[CTA_COUNTERS_BYTES])
            return -1;
        counter->rep_pkts = be64toh(nla_get_be64(arr[CTA_COUNTERS_PACKETS]));
        counter->rep_bytes = be64toh(nla_get_be64(arr[CTA_COUNTERS_BYTES]));
        return 0;
    }
    return -1;
}

int nfct_conn_get_tcpinfo(const conn_entry *e, conn_tcpinfo *info)
{
    const struct nlattr *proto = e->nla[CTA_PROTOINFO];
    const struct nlattr *tcp;
    struct nlattr *arr[CTA_PROTOINFO_TCP_MAX + 1];

    if(proto)  {
        tcp = (const struct nlattr *)nla_data(proto);
        if(nla_type(tcp) != CTA_PROTOINFO_TCP)
            return -1;
        nla_parse_nested(arr, CTA_PROTOINFO_TCP_MAX, tcp);
        if(arr[CTA_PROTOINFO_TCP_STATE]
           || arr[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]
           || arr[CTA_PROTOINFO_TCP_WSCALE_REPLY]
           || arr[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL]
           || arr[CTA_PROTOINFO_TCP_FLAGS_REPLY])  {
            info->state = nla_get_u8(arr[CTA_PROTOINFO_TCP_STATE]);
            info->wscale_orig = nla_get_u8(arr[CTA_PROTOINFO_TCP_WSCALE_ORIGINAL]);
            info->wscale_rep = nla_get_u8(arr[CTA_PROTOINFO_TCP_WSCALE_REPLY]);
            nla_get_mem(arr[CTA_PROTOINFO_TCP_FLAGS_ORIGINAL], &info->flags_orig, sizeof(info->flags_orig));
            nla_get_mem(arr[CTA_PROTOINFO_TCP_FLAGS_REPLY], &info->flags_rep, sizeof(info->flags_rep));
            return 0;
        }
    }
    return -1;
}

int nfct_conn_get_sctpinfo(const conn_entry *e, conn_sctpinfo *info)
{
    const struct nlattr *proto = e->nla[CTA_PROTOINFO];
    const struct nlattr *sctp;
    struct nlattr *arr[CTA_PROTOINFO_SCTP_MAX + 1];

    if(proto)  {
        sctp = (const struct nlattr *)nla_data(proto);
        if(nla_type(sctp) != CTA_PROTOINFO_SCTP)
            return -1;
        nla_parse_nested(arr, CTA_PROTOINFO_SCTP_MAX, sctp);
        if(! arr[CTA_PROTOINFO_SCTP_STATE]
           || ! arr[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL]
           || ! arr[CTA_PROTOINFO_SCTP_VTAG_REPLY])  {
            info->state = nla_get_u8(arr[CTA_PROTOINFO_SCTP_STATE]);
            info->vtag_orig = ntohl(nla_get_u8(arr[CTA_PROTOINFO_SCTP_VTAG_ORIGINAL]));
            info->vtag_rep = ntohl(nla_get_u8(arr[CTA_PROTOINFO_SCTP_VTAG_REPLY]));
            return 0;
        }
    }
    return -1;
}

int __nfct_conn_get_tuple(const conn_entry *e, int type, conn_tuple *tuple)
{
    struct nlattr *arr[CTA_TUPLE_MAX + 1];
    struct nlattr *ip[CTA_IP_MAX + 1];
    struct nlattr *proto[CTA_PROTO_MAX + 1];

    if(! e->nla[type])
        return -1;

    memset(tuple, 0, sizeof(*tuple));
    nla_parse_nested(arr, CTA_TUPLE_MAX, e->nla[type]);
    if(! arr[CTA_TUPLE_IP] || ! arr[CTA_TUPLE_PROTO])  {
        PR_WARN("unexpected NULL tuple IP or proto");
        return-1;
    }

    nla_parse_nested(ip, CTA_IP_MAX, arr[CTA_TUPLE_IP]);
    tuple->src.l3num = e->l3num;
    if(e->l3num == AF_INET)  {
        if(! ip[CTA_IP_V4_SRC] || ! ip[CTA_IP_V4_DST])
            return -1;
        tuple->src.u3.ip = nla_get_be32(ip[CTA_IP_V4_SRC]);
        tuple->dst.u3.ip = nla_get_be32(ip[CTA_IP_V4_DST]);
    }else if(e->l3num == AF_INET6)  {
        if(! ip[CTA_IP_V6_SRC] || ! ip[CTA_IP_V6_DST])
            return -1;
        nla_get_mem(ip[CTA_IP_V6_SRC], &tuple->src.u3.in6, sizeof(tuple->src.u3.in6));
        nla_get_mem(ip[CTA_IP_V6_DST], &tuple->dst.u3.in6, sizeof(tuple->dst.u3.in6));
    }else  {
        PR_WARN("unexpected l3num while parsing tuple:%d", e->l3num);
        return -1;
    }

    nla_parse_nested(proto, CTA_PROTO_MAX, arr[CTA_TUPLE_PROTO]);
    if(! proto[CTA_PROTO_NUM])  {
        PR_WARN("unexpected NULL proto num while parsing tuple");
        return -1;
    }
    tuple->dst.protonum = nla_get_u8(proto[CTA_PROTO_NUM]);
    switch(tuple->dst.protonum)  {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_UDPLITE:
        if(! proto[CTA_PROTO_SRC_PORT] || ! proto[CTA_PROTO_DST_PORT])  {
            PR_WARN("unexpected NULL port while parsing tuple");
            return -1;
        }
        tuple->src.u.tcp.port = nla_get_be16(proto[CTA_PROTO_SRC_PORT]);
        tuple->dst.u.tcp.port = nla_get_be16(proto[CTA_PROTO_DST_PORT]);
        break;
    case IPPROTO_ICMP:
        if(! proto[CTA_PROTO_ICMP_ID] || ! proto[CTA_PROTO_ICMP_TYPE] || ! proto[CTA_PROTO_ICMP_CODE])  {
            PR_WARN("unexpected NULL icmp attr while parsing tuple");
            return -1;
        }
        tuple->src.u.icmp.id = nla_get_be16(proto[CTA_PROTO_ICMP_ID]);
        tuple->dst.u.icmp.type = nla_get_u8(proto[CTA_PROTO_ICMP_TYPE]);
        tuple->dst.u.icmp.code = nla_get_u8(proto[CTA_PROTO_ICMP_CODE]);
        break;
    case IPPROTO_ICMPV6:
        if(! proto[CTA_PROTO_ICMPV6_ID]
           || ! proto[CTA_PROTO_ICMPV6_TYPE]
           || ! proto[CTA_PROTO_ICMPV6_CODE])  {
            PR_WARN("unexpected NULL icmpv6 attr while parsing tuple");
            return -1;
        }
        tuple->src.u.icmp.id = nla_get_be16(proto[CTA_PROTO_ICMPV6_ID]);
        tuple->dst.u.icmp.type = nla_get_u8(proto[CTA_PROTO_ICMPV6_TYPE]);
        tuple->dst.u.icmp.code = nla_get_u8(proto[CTA_PROTO_ICMPV6_CODE]);
        break;
    default:
        PR_INFO("unsupported proto %d while parsing tuple", tuple->dst.protonum);
        return -1;
    }
    return 0;
}

/* fixme: nat seq adj */

nfct_msg *nfct_msg_new(__u8 l3num, int flags)
{
    ginkgo_msg *msg;
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfmsg;
    nfct_msg_ctl *ctl;
    conn_entry *e;

    if((msg = ginkgo_new_msg(0, NFCT_MSG_GOOD_SIZE)))  {
        if(! instantiate(e))  {
            free(msg);
            return NULL;
        }

        nlh = NL_HEADER(msg);
        BZERO(nlh);
        nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
        if(flags & NFCT_F_CREATE)
            nlh->nlmsg_flags |= NLM_F_CREATE;
        if(flags & NFCT_F_EXCL)
            nlh->nlmsg_flags |= NLM_F_EXCL;
        if(flags & NFCT_F_DUMP)
            nlh->nlmsg_flags |= NLM_F_DUMP;

        nfmsg = (struct nfgenmsg *)NLMSG_DATA(nlh);
        nfmsg->nfgen_family = l3num;
        nfmsg->version = NFNETLINK_V0;
        nfmsg->res_id = 0;

        BZERO(e);
        e->l3num = l3num;

        ctl = msg_ctl(msg);
        BZERO(ctl);
        ctl->base.entry = e;
        ctl->ctx = (char *)nfmsg + NLMSG_ALIGN(sizeof(struct nfgenmsg));
        ctl->sz = NFCT_MSG_GOOD_SIZE;
        return (nfct_msg *)ctl;
    }
    return NULL;
}

static inline size_t msg_free_space(nfct_msg_ctl *ctl)
{
    return ctl->sz - ((char *)ctl->ctx - GINKGO_MSG_PAYLOAD(NFCT_GINKGO_MSG(ctl), char));
}

int nfct_msg_set_tcpinfo(nfct_msg *m, const conn_tcpinfo *info, int mask)
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;
    struct nlattr *proto, *tcp;
    size_t sz = 0;

    if(nla[CTA_PROTOINFO] || ! mask)
        return -1;
    if(mask & TCP_F_STATE)
        sz += nla_total_size(sizeof(__u8));
    if(mask & TCP_F_WSCALE_ORIG)
        sz += nla_total_size(sizeof(__u8));
    if(mask & TCP_F_WSCALE_REP)
        sz += nla_total_size(sizeof(__u8));
    if(mask & TCP_F_FLAGS_ORIG)
        sz += nla_total_size(sizeof(struct nf_ct_tcp_flags));
    if(mask & TCP_F_FLAGS_REP)
        sz += nla_total_size(sizeof(struct nf_ct_tcp_flags));
    if(sz)  {
        sz = nla_total_size(nla_total_size(sz));
        if(sz < msg_free_space(ctl))  {
            proto = nla_nested_start(&ctl->ctx, CTA_PROTOINFO);
            tcp = nla_nested_start(&ctl->ctx, CTA_PROTOINFO_TCP);
            if(mask & TCP_F_STATE)
                nla_put_u8(&ctl->ctx, CTA_PROTOINFO_TCP_STATE, info->state);
            if(mask & TCP_F_WSCALE_ORIG)
                nla_put_u8(&ctl->ctx, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL, info->wscale_orig);
            if(mask & TCP_F_WSCALE_REP)
                nla_put_u8(&ctl->ctx, CTA_PROTOINFO_TCP_WSCALE_REPLY, info->wscale_rep);
            if(mask & TCP_F_FLAGS_ORIG)
                nla_put_blob(&ctl->ctx, CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, &info->flags_orig, sizeof(info->flags_orig));
            if(mask & TCP_F_FLAGS_REP)
                nla_put_blob(&ctl->ctx, CTA_PROTOINFO_TCP_FLAGS_REPLY, &info->flags_rep, sizeof(info->flags_rep));
            nla_nested_end(tcp, ctl->ctx);
            nla_nested_end(proto, ctl->ctx);
            nla[CTA_PROTOINFO] = proto;
            return 0;
        }
    }
    return -1;
}

int nfct_msg_set_sctpinfo(nfct_msg *m, const conn_sctpinfo *info, int mask)
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;
    struct nlattr *proto, *sctp;
    size_t sz = 0;

    if(nla[CTA_PROTOINFO] || ! mask)
        return -1;
    if(mask & SCTP_F_STATE)
        sz += nla_total_size(sizeof(__u8));
    if(mask & SCTP_F_VTAG_ORIG)
        sz += nla_total_size(sizeof(__u32));
    if(mask & SCTP_F_VTAG_REP)
        sz += nla_total_size(sizeof(__u32));
    if(sz)  {
        sz = nla_total_size(nla_total_size(sz));
        if(sz < msg_free_space(ctl))  {
            proto = nla_nested_start(&ctl->ctx, CTA_PROTOINFO);
            sctp = nla_nested_start(&ctl->ctx, CTA_PROTOINFO_SCTP);
            if(mask & SCTP_F_STATE)
                nla_put_u8(&ctl->ctx, CTA_PROTOINFO_SCTP_STATE, info->state);
            if(mask & SCTP_F_VTAG_ORIG)
                nla_put_be32(&ctl->ctx, CTA_PROTOINFO_SCTP_VTAG_ORIGINAL, htonl(info->vtag_orig));
            if(mask & SCTP_F_VTAG_REP)
                nla_put_be32(&ctl->ctx, CTA_PROTOINFO_SCTP_VTAG_REPLY, htonl(info->vtag_rep));
            nla_nested_end(sctp, ctl->ctx);
            nla_nested_end(proto, ctl->ctx);
            nla[CTA_PROTOINFO] = proto;
            return 0;
        }
    }
    return -1;
}

int __nfct_msg_set_tuple(nfct_msg *m, int type, const conn_tuple *t)
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;
    struct nlattr *tuple, *ip, *proto;
    __u16 l3 = t->src.l3num;
    __u8 l4 = t->dst.protonum;
    size_t sz, ip_sz = 0, proto_sz = 0;

    if(nla[type] || (l3 != AF_INET && l3 != AF_INET6))
        return -1;

    if(l3 == AF_INET)  {
        ip_sz += nla_total_size(sizeof(struct in_addr));
        ip_sz += nla_total_size(sizeof(struct in_addr));
    }else  {
        ip_sz += nla_total_size(sizeof(struct in6_addr));
        ip_sz += nla_total_size(sizeof(struct in6_addr));
    }
    proto_sz += nla_total_size(sizeof(__u8));
    switch(l4)  {
    case IPPROTO_TCP:
    case IPPROTO_UDP:
    case IPPROTO_UDPLITE:
    case IPPROTO_SCTP:
        proto_sz += nla_total_size(sizeof(__u16));
        proto_sz += nla_total_size(sizeof(__u16));
        break;
    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        proto_sz += nla_total_size(sizeof(__u8)) * 2;
        proto_sz += nla_total_size(sizeof(__u16));
        break;
    default:
        PR_WARN("unsupported l4 %d while settings tuple", l4);
        return -1;
    }

    sz = nla_total_size(nla_total_size(ip_sz) + nla_total_size(proto_sz));
    if(sz < msg_free_space(ctl))  {
        tuple = nla_nested_start(&ctl->ctx, type);
        ip = nla_nested_start(&ctl->ctx, CTA_TUPLE_IP);
        if(l3 == AF_INET)  {
            nla_put_be32(&ctl->ctx, CTA_IP_V4_SRC, t->src.u3.ip);
            nla_put_be32(&ctl->ctx, CTA_IP_V4_DST, t->dst.u3.ip);
        }else  {
            nla_put_blob(&ctl->ctx, CTA_IP_V6_SRC, &t->src.u3.in6, sizeof(t->src.u3.in6));
            nla_put_blob(&ctl->ctx, CTA_IP_V6_DST, &t->dst.u3.in6, sizeof(t->dst.u3.in6));
        }
        nla_nested_end(ip, ctl->ctx);

        proto = nla_nested_start(&ctl->ctx, CTA_TUPLE_PROTO);
        nla_put_u8(&ctl->ctx, CTA_PROTO_NUM, l4);
        switch(l4)  {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE:
        case IPPROTO_SCTP:
            nla_put_be16(&ctl->ctx, CTA_PROTO_SRC_PORT, t->src.u.tcp.port);
            nla_put_be16(&ctl->ctx, CTA_PROTO_DST_PORT, t->dst.u.tcp.port);
            break;
        case IPPROTO_ICMP:
            nla_put_be16(&ctl->ctx, CTA_PROTO_ICMP_ID, t->src.u.icmp.id);
            nla_put_u8(&ctl->ctx, CTA_PROTO_ICMP_TYPE, t->dst.u.icmp.type);
            nla_put_u8(&ctl->ctx, CTA_PROTO_ICMP_CODE, t->dst.u.icmp.code);
            break;
        case IPPROTO_ICMPV6:
            nla_put_be16(&ctl->ctx, CTA_PROTO_ICMPV6_ID, t->src.u.icmp.id);
            nla_put_u8(&ctl->ctx, CTA_PROTO_ICMPV6_TYPE, t->dst.u.icmp.type);
            nla_put_u8(&ctl->ctx, CTA_PROTO_ICMPV6_CODE, t->dst.u.icmp.code);
            break;
        default:
            PR_WARN("unsupported l4 %d while settings tuple", l4);
            return -1;
        }
        nla_nested_end(proto, ctl->ctx);
        nla_nested_end(tuple, ctl->ctx);
        nla[type] = tuple;
        return 0;
    }
    return -1;
}

int __nfct_msg_set_zone(nfct_msg *m, __u16 zone)
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;

    if(! nla[CTA_ZONE] && (size_t)nla_total_size(sizeof(__u16)) < msg_free_space(ctl))  {
        nla[CTA_ZONE] = (struct nlattr *)ctl->ctx;
        nla_put_be16(&ctl->ctx, CTA_ZONE, htons(zone));
        return 0;
    }
    return -1;
}

int __nfct_msg_set_be32(nfct_msg *m, int t, __u32 val)
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;

    if(! nla[t] && (size_t)nla_total_size(sizeof(__u32)) < msg_free_space(ctl))  {
        nla[t] = (struct nlattr *)ctl->ctx;
        nla_put_be32(&ctl->ctx, t, htonl(val));
        return 0;
    }
    return -1;
}

int nfct_msg_set_helper_name(nfct_msg *m, const char *name) /* NULL to remove existing helper */
{
    conn_entry *e = (conn_entry *)m->entry;
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    struct nlattr **nla = e->nla;
    struct nlattr *help;
    size_t sz = (name ? strlen(name) : 0);

    sz = nla_total_size(nla_total_size(sz + 1));
    if(! nla[CTA_HELP] && sz < msg_free_space(ctl))  {
        help = nla_nested_start(&ctl->ctx, CTA_HELP);
        nla_put_string(&ctl->ctx, CTA_HELP_NAME, name ? : "");
        nla_nested_end(help, ctl->ctx);
        nla[CTA_HELP] = help;
        return 0;
    }
    return -1;
}

/* fixme: nat seq adj */

static inline __u32 nfct_new_seq(nfct_t *ct)
{
    if(++ct->nlseq == 0)
        ++ct->nlseq;
    return ct->nlseq;
}

int nfct_msg_commit(nfct_t *ct, list *res, nfct_msg *m, int cmd, int wait, int nofree)
{
    nfct_msg_ctl *ctl = (nfct_msg_ctl *)m;
    ginkgo_msg *msg = NFCT_GINKGO_MSG(m), *n;
    struct nlmsghdr *nlh = NL_HEADER(msg);
    list rsp;
    __u16 type;
    int err;

    switch(cmd)  {
    case NFCT_CMD_NEW:
        type = IPCTNL_MSG_CT_NEW;
        break;
    case NFCT_CMD_GET:
        type = IPCTNL_MSG_CT_GET;
        break;
    case NFCT_CMD_DEL:
        type = IPCTNL_MSG_CT_DELETE;
        break;
    default:
        PR_WARN("Unsupported nfct command:%d", cmd);
        return -1;
    }
    type |= (NFNL_SUBSYS_CTNETLINK << 8);
    ctl->base.type = type;

    nlh->nlmsg_type = type;
    nlh->nlmsg_len = (char *)ctl->ctx - GINKGO_MSG_PAYLOAD(msg, char);
    nlh->nlmsg_seq = nfct_new_seq(ct);
    nlh->nlmsg_pid = 0;

    msg->src = ct->id;
    msg->len = GINKGO_MSG_LENGTH(nlh->nlmsg_len);

    err = ginkgo_request(ct->ginkgo, msg, &rsp, 0);
    if(! nofree)
        nfct_msg_free(m);
    if(err != GINKGO_ERR_OK)
        return -1;

    err = 0;
    list_init(res);
    list_for_each_ginkgo_msg_safe(msg, n, &rsp)  {
        list_delete(&msg->lst);

        if(! err)  {
            nlh = NL_HEADER(msg);
            if(nlh->nlmsg_type != NLMSG_ERROR)  {
                if(! nfct_parse(msg))
                    list_append(res, &msg->lst);
                else
                    free(msg);
                continue;
            }
            err = ((struct nlmsgerr *)NLMSG_DATA(nlh))->error;
        }
        free(msg);
    }

    if(err != 0)
        nfct_msg_list_free(res);
    return err;
}


static void nfct_check(void)
{
    ginkgo_msg msg;

    build_fail_on(sizeof(msg.cmn) < sizeof(nfct_msg_ctl));
}
