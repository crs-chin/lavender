/*
 * rtnl.h
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

#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include "linux_if_link.h"
#include <linux/rtnetlink.h>

#include "linux_fib_rules.h"

#include "nl.h"
#include "util.h"
#include "ginkgo.h"
#include "rtnl.h"

typedef struct _rtnl_ctl rtnl_ctl;

struct _rtnl_ctl{
    int peer;
    int group;
};

static int __rtnl_initialize = 0;
static int __ginkgo_id = -1;
static int __rtnl_seq = 1;
static rtnl_notify on_notify = NULL;
static void *notify_ud = NULL;
static ginkgo_ctx *__ginkgo = NULL;


static inline rtnl_ctl *msg_ctl(ginkgo_msg *msg)
{
    return (rtnl_ctl *)&msg->cmn;
}

static inline void rtnl_ctl_set(ginkgo_msg *msg, int peer, int group)
{
    rtnl_ctl *ctl = msg_ctl(msg);
    ctl->peer = peer;
    ctl->group = group;
}

static inline rtnl_msg *rtnl_msg_init(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    rtnl_msg *rmsg = RTNL_MSG(msg);

    if(! nlh)
        nlh = NL_HEADER(msg);
    BZERO(rmsg);
    rmsg->type = nlh->nlmsg_type;
    return rmsg;
}

static int rtattr_parse(struct rtattr *attr[], int max, struct rtattr *rta, int len)
{
    memset(attr, 0, sizeof(struct rtattr *) * (max + 1));
    while(RTA_OK(rta, len))  {
        if(rta->rta_type <= max && ! attr[rta->rta_type])
            attr[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if(len)
        PR_WARN("!!!rtattr type %d len %d, but %d", rta->rta_type, rta->rta_len, len);
    return 0;
}

static int parse_link(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    struct ifinfomsg *imsg = (struct ifinfomsg *)NLMSG_DATA(nlh);
    rtnl_msg *rmsg = rtnl_msg_init(msg, nlh);
    struct rtattr *attr[IFLA_MAX + 1], *rta;
    link_entry *link;
    int type;

    if(rtattr_parse(attr, IFLA_MAX, IFLA_RTA(imsg), IFLA_PAYLOAD(nlh)))
        return -1;
    if(! (link = new_instance(link_entry)))
        return -1;
    BZERO(link);
    link->ifinfo = imsg;
    for(type = IFLA_UNSPEC + 1; type <= IFLA_MAX; type++)  {
        if(! attr[type])
            continue;
        rta = attr[type];
        switch(type)  {
        case IFLA_ADDRESS:
        case IFLA_BROADCAST:
            break;
        case IFLA_IFNAME:
            link->ifname = RTA_DATA(rta);
            break;
        case IFLA_MTU:
            link->mtu = RTA_DATA(rta);
            break;
        case IFLA_LINK:
            link->link = RTA_DATA(rta);
            break;
        case IFLA_QDISC:
            link->qdisc = RTA_DATA(rta);
            break;
        case IFLA_STATS:
            link->ifstat = RTA_DATA(rta);
            break;
        case IFLA_COST:
        case IFLA_PRIORITY:
            /* ignored */
            break;
        case IFLA_MASTER:
            link->master = RTA_DATA(rta);
            break;
        case IFLA_WIRELESS:		/* Wireless Extension event - see wireless.h */
        case IFLA_PROTINFO:		/* Protocol specific information for a link */
            break;
        case IFLA_TXQLEN:
            link->txqlen = RTA_DATA(rta);
            break;
        case IFLA_MAP:
            link->ifmap = RTA_DATA(rta);
            break;
        case IFLA_WEIGHT:
            /* ignored */
            break;
        case IFLA_OPERSTATE:
            link->operstate = RTA_DATA(rta);
            break;
        case IFLA_LINKMODE:
            link->linkmode = RTA_DATA(rta);
            break;
        case IFLA_LINKINFO:
        case IFLA_NET_NS_PID:
            /* ignored */
            break;
        case IFLA_IFALIAS:
            link->ifalias = RTA_DATA(rta);
            break;
        case IFLA_NUM_VF:		/* Number of VFs if device is SR-IOV PF */
        case IFLA_VFINFO_LIST:
            /* ignored */
            break;
        case IFLA_STATS64:
            link->ifstat64 = RTA_DATA(rta);
            break;
        case IFLA_VF_PORTS:
        case IFLA_PORT_SELF:
        case IFLA_AF_SPEC:
            /* ignored */
            break;
        case IFLA_GROUP:		/* Group the device belongs to */
        case IFLA_NET_NS_FD:
        case IFLA_EXT_MASK:		/* Extended info mask, VFs, etc */
            break;
        case IFLA_PROMISCUITY:	/* Promiscuity count: > 0 means acts PROMISC */
            link->promiscuity = RTA_DATA(rta);
            break;
        default:
            PR_WARN("Unrecoginzed link attr:%d", type);
            break;
        }
    }
    memcpy(&link->rta, attr, sizeof(attr));
    rmsg->entry = link;
    return 0;
}

static int parse_addr_inet(rtnl_msg *rmsg, struct ifaddrmsg *amsg, struct rtattr *attr[])
{
    struct rtattr *rta;
    addr_entry_inet *addr;
    int type;

    if(! (addr = new_instance(addr_entry_inet)))
        return -1;
    BZERO(addr);
    addr->base.ifaddr = amsg;
    memcpy(&addr->base.rta, attr, sizeof(struct rtattr *) * (IFA_MAX + 1));
    for(type = IFA_UNSPEC + 1; type <= IFA_MAX; type++)  {
        if(! attr[type])
            continue;
        rta = attr[type];
        switch(type)  {
        case IFA_ADDRESS:
            addr->addr = RTA_DATA(rta);
            break;
        case IFA_LOCAL:
            addr->local = RTA_DATA(rta);
            break;
        case IFA_LABEL:
            addr->label = RTA_DATA(rta);
            break;
        case IFA_BROADCAST:
            addr->broadcast = RTA_DATA(rta);
            break;
        default:
            PR_WARN("Unexpected attr type %d for inet addr", type);
            break;
        }
    }
    rmsg->entry = addr;
    return 0;
}

static int parse_addr_inet6(rtnl_msg *rmsg, struct ifaddrmsg *amsg, struct rtattr *attr[])
{
    struct rtattr *rta;
    addr_entry_inet6 *addr;
    int type;

    if(! (addr = new_instance(addr_entry_inet6)))
        return -1;
    BZERO(addr);
    addr->base.ifaddr = amsg;
    memcpy(&addr->base.rta, attr, sizeof(struct rtattr *) * (IFA_MAX + 1));
    for(type = IFA_UNSPEC + 1; type <= IFA_MAX; type++)  {
        if(! attr[type])
            continue;
        rta = attr[type];
        switch(type)  {
        case IFA_ADDRESS:
            addr->addr = RTA_DATA(rta);
            break;
        case IFA_ANYCAST:
            addr->acaddr = RTA_DATA(rta);
            break;
        case IFA_CACHEINFO:
            addr->cinfo = RTA_DATA(rta);
            break;
        case IFA_MULTICAST:
            addr->mcaddr = RTA_DATA(rta);
            break;
        default:
            PR_WARN("Unexpected attr type %d for inet6 addr", type);
            break;
        }
    }
    rmsg->entry = addr;
    return 0;
}

static int parse_addr_other(rtnl_msg *rmsg, struct ifaddrmsg *amsg, struct rtattr *attr[])
{
    addr_entry *addr;

    if((addr = new_instance(addr_entry)))  {
        BZERO(addr);
        addr->ifaddr = amsg;
        memcpy(&addr->rta, attr, sizeof(struct rtattr *) * (IFA_MAX + 1));
        rmsg->entry = addr;
        return 0;
    }
    return -1;
}

static int parse_addr(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    struct ifaddrmsg *amsg = (struct ifaddrmsg *)NLMSG_DATA(nlh);
    rtnl_msg *rmsg = rtnl_msg_init(msg, nlh);
    struct rtattr *attr[IFA_MAX + 1];

    if(rtattr_parse(attr, IFA_MAX, IFA_RTA(amsg), IFA_PAYLOAD(nlh)))
        return -1;
    if(amsg->ifa_family == AF_INET)
        return parse_addr_inet(rmsg, amsg, attr);
    if(amsg->ifa_family == AF_INET6)
        return parse_addr_inet6(rmsg, amsg, attr);
    return parse_addr_other(rmsg, amsg, attr);
}

static inline void parse_rt_metrics(__u32 *metrics[], struct rtattr *rta, int len)
{
    while(RTA_OK(rta, len))  {
        if(rta->rta_type <= RTAX_MAX && ! metrics[rta->rta_type])
            metrics[rta->rta_type] = RTA_DATA(rta);
        RTA_NEXT(rta, len);
    }
}

static void parse_rt_hops(route_entry_inet *rt, struct rtnexthop *hop, int len)
{
    rtnexthop_elem *elem = rt->hops;
    struct rtattr *rta;
    int alen;

    while(RTNH_OK(hop, len))  {
        elem->hop = hop;
        if(hop->rtnh_len > RTNH_LENGTH(0))  {
            alen = hop->rtnh_len - RTNH_SPACE(0);
            rta = RTNH_DATA(hop);
            while(RTA_OK(rta, alen))  {
                if(rta->rta_type == RTA_GATEWAY)
                    elem->gateway = RTA_DATA(rta);
                else if(rta->rta_type == RTA_FLOW)
                    elem->flow = RTA_DATA(rta);
                else
                    PR_WARN("Unexpected rta type %d for rtnexthop", rta->rta_type);
                RTA_NEXT(rta, alen);
            }
        }
        elem++;
        len -= RTNH_ALIGN(hop->rtnh_len);
        RTNH_NEXT(hop);
    }
}

static int parse_rt_nhops(struct rtattr *hops)
{
    struct rtnexthop *hop = RTA_DATA(hops);
    int len = RTA_PAYLOAD(hops), nhops = 0;

    while(RTNH_OK(hop, len))  {
        nhops++;
        len -= RTNH_ALIGN(hop->rtnh_len);
        RTNH_NEXT(hop);
    };
    if(len)
        PR_WARN("!!! rttnl len %d, but len %d", hop->rtnh_len, len);
    return nhops;
}

static int parse_route_inet(rtnl_msg *rmsg, struct rtmsg *rtmsg, struct rtattr *attr[])
{
    route_entry_inet *rt;
    struct rtattr *rta;
    int hops = 0, type;

    if(attr[RTA_MULTIPATH])
        hops = parse_rt_nhops(attr[RTA_MULTIPATH]);
    if(! instantiate_ex(rt, hops * sizeof(rtnexthop_elem)))
        return -1;
    bzero(rt, sizeof(*rt) + hops * sizeof(rtnexthop_elem));
    rt->base.rt = rtmsg;
    memcpy(&rt->base.rta, attr, sizeof(struct rtattr *) * (RTA_MAX + 1));
    rt->nhops = hops;
    for(type = RTA_UNSPEC + 1; type <= RTA_MAX; type++)  {
        if(! attr[type])
            continue;
        rta = attr[type];
        switch(type)  {
        case RTA_DST:
            rt->dst = RTA_DATA(rta);
            break;
        case RTA_SRC:
            rt->src = RTA_DATA(rta);
            break;
        case RTA_IIF:
            rt->iif = RTA_DATA(rta);
            break;
        case RTA_OIF:
            rt->oif = RTA_DATA(rta);
            break;
        case RTA_GATEWAY:
            rt->gateway = RTA_DATA(rta);
            break;
        case RTA_PRIORITY:
            rt->priority = RTA_DATA(rta);
            break;
        case RTA_PREFSRC:
            rt->prefsrc = RTA_DATA(rta);
            break;
        case RTA_METRICS:
            parse_rt_metrics(rt->metrics, RTA_DATA(rta), RTA_PAYLOAD(rta));
            break;
        case RTA_MULTIPATH:
            parse_rt_hops(rt, RTA_DATA(rta), RTA_PAYLOAD(rta));
            break;
        case RTA_PROTOINFO: /* no longer used */
            break;
        case RTA_FLOW:
            rt->flow = RTA_DATA(rta);
            break;
        case RTA_CACHEINFO:
            rt->cinfo = RTA_DATA(rta);
            break;
        case RTA_SESSION: /* no longer used */
        case RTA_MP_ALGO: /* no longer used */
            break;
        case RTA_TABLE:
            rt->table = RTA_DATA(rta);
            break;
        case RTA_MARK:
            rt->mark = RTA_DATA(rta);
            break;
        default:
            PR_WARN("Unrecognized attr type %d for rtmsg", type);
            break;
        }
    }
    rmsg->entry = rt;
    return 0;
}

static int parse_route_other(rtnl_msg *rmsg, struct rtmsg *rtmsg, struct rtattr *attr[])
{
    route_entry *rt = new_instance(route_entry);

    if(rt)  {
        rt->rt = rtmsg;
        memcpy(&rt->rta, attr, sizeof(struct rtattr *) * (RTA_MAX + 1));
        rmsg->entry = rt;
        return 0;
    }
    return -1;
}

static int parse_route(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    struct rtmsg *rtmsg = (struct rtmsg *)NLMSG_DATA(nlh);
    rtnl_msg *rmsg = rtnl_msg_init(msg, nlh);
    struct rtattr *attr[RTA_MAX + 1];

    if(rtattr_parse(attr, RTA_MAX, RTM_RTA(rtmsg), RTM_PAYLOAD(nlh)))
        return -1;
    if(rtmsg->rtm_family == AF_INET)
        return parse_route_inet(rmsg, rtmsg, attr);
    return parse_route_other(rmsg, rtmsg, attr);
}

static int parse_neigh(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    struct ndmsg *ndmsg = (struct ndmsg *)NLMSG_DATA(nlh);
    rtnl_msg *rmsg = rtnl_msg_init(msg, nlh);
    struct rtattr *attr[NDA_MAX + 1], *rta;
    neigh_entry *neigh;
    int len;

    rta = (struct rtattr *)((char *)ndmsg + NLMSG_ALIGN(sizeof(struct ndmsg)));
    len = NLMSG_PAYLOAD(nlh, sizeof(struct ndmsg));

    if(! rtattr_parse(attr, NDA_MAX, rta, len))  {
        if(instantiate(neigh))  {
            BZERO(neigh);
            neigh->nd = ndmsg;
            memcpy(&neigh->rta, attr, sizeof(attr));
            rmsg->entry = neigh;
            return 0;
        }
    }
    return -1;
}

static int parse_rule_inet(rtnl_msg *rmsg, struct fib_rule_hdr *frh, struct rtattr *attr[])
{
    rule_entry_inet *r;
    struct rtattr *rta;
    int type;

    if(! instantiate(r))
        return -1;
    BZERO(r);
    r->base.hdr = frh;
    memcpy(&r->base.rta, attr, sizeof(struct rtattr *) * (FRA_MAX + 1));
    rmsg->entry = r;
    for(type = FRA_UNSPEC + 1; type <= FRA_MAX; type++)  {
        if(! attr[type])
            continue;
        rta = attr[type];
        switch(type)  {
        case FRA_DST:	/* destination address */
            r->dst = RTA_DATA(rta);
            break;
        case FRA_SRC:	/* source address */
            r->src = RTA_DATA(rta);
            break;
        case FRA_IIFNAME:	/* interface name */
            r->iif = RTA_DATA(rta);
            break;
        case FRA_GOTO:	/* target to jump to (FR_ACT_GOTO) */
            r->target = RTA_DATA(rta);
            break;
        case FRA_UNUSED2:
            break;
        case FRA_PRIORITY:	/* priority/preference */
            r->priority = RTA_DATA(rta);
            break;
        case FRA_UNUSED3:
        case FRA_UNUSED4:
        case FRA_UNUSED5:
            break;
        case FRA_FWMARK:	/* mark */
            r->fwmark = RTA_DATA(rta);
            break;
        case FRA_FLOW:	/* flow/class id */
            r->flow = RTA_DATA(rta);
            break;
        case FRA_UNUSED6:
        case FRA_UNUSED7:
        case FRA_UNUSED8:
            break;
        case FRA_TABLE:	/* Extended table id */
            r->table = RTA_DATA(rta);
            break;
        case FRA_FWMASK:	/* mask for netfilter mark */
            r->fwmask = RTA_DATA(rta);
            break;
        case FRA_OIFNAME:
            r->oif = RTA_DATA(rta);
            break;
        default:
            PR_WARN("Unexpected rtattr %d of route rule", type);
            break;
        }
    }
    return 0;
}

static int parse_rule_other(rtnl_msg *rmsg, struct fib_rule_hdr *frh, struct rtattr *rta[])
{
    rule_entry_inet *r = new_instance(rule_entry_inet);

    if(r)  {
        r->base.hdr = frh;
        memcpy(&r->base.rta, rta, sizeof(struct rtattr *) * (FRA_MAX + 1));
        rmsg->entry = r;
    }
    return 0;
}

static int parse_rule(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)NLMSG_DATA(nlh);
    rtnl_msg *rmsg = rtnl_msg_init(msg, nlh);
    struct rtattr *attr[FRA_MAX + 1];
    struct rtattr *rta = (struct rtattr *)((char *)frh + NLMSG_ALIGN(sizeof(struct fib_rule_hdr)));
    int len = NLMSG_PAYLOAD(nlh, sizeof(struct fib_rule_hdr));

    if(rtattr_parse(attr, FRA_MAX, rta, len))
        return -1;
    if(frh->family == AF_INET)
        return parse_rule_inet(rmsg, frh, attr);
    return parse_rule_other(rmsg, frh, attr);
}

static inline int parse_other(ginkgo_msg *msg, struct nlmsghdr *nlh)
{
    rtnl_msg_init(msg, nlh);
    return 0;
}

static int rtnl_parse(ginkgo_msg *msg)
{
    struct nlmsghdr *nlh = NL_HEADER(msg);

    switch(nlh->nlmsg_type)  {
    case RTM_NEWLINK:
    case RTM_DELLINK:
        return parse_link(msg, nlh);
    case RTM_NEWADDR:
    case RTM_DELADDR:
        return parse_addr(msg, nlh);
    case RTM_NEWROUTE:
    case RTM_DELROUTE:
        return parse_route(msg, nlh);
    case RTM_NEWNEIGH:
    case RTM_DELNEIGH:
        return parse_neigh(msg, nlh);
    case RTM_NEWRULE:
    case RTM_DELRULE:
        return parse_rule(msg, nlh);
    case RTM_NEWQDISC:
    case RTM_DELQDISC:

    case RTM_NEWTCLASS:
    case RTM_DELTCLASS:

    case RTM_NEWTFILTER:
    case RTM_DELTFILTER:

    case RTM_NEWACTION:
    case RTM_DELACTION:

    case RTM_NEWPREFIX:

    case RTM_NEWNEIGHTBL:
    case RTM_GETNEIGHTBL:

    case RTM_NEWNDUSEROPT:

    case RTM_NEWADDRLABEL:
    case RTM_DELADDRLABEL:
        return parse_other(msg, nlh);
    default:
        PR_WARN("Unexpected rtnl msg received:%d", nlh->nlmsg_type);
        return parse_other(msg, nlh);
    }
}

static int rtnl_handler(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud)
{
    if(on_notify)  {
        rtnl_parse(msg);
        if(! on_notify(RTNL_MSG(msg), notify_ud))
            rtnl_msg_free(RTNL_MSG(msg));
        return 1;
    }
    return 0;
}

static ssize_t rtnl_write(int fd, const ginkgo_msg *msg, const void *buf, size_t len)
{
    const rtnl_ctl *ctl = msg_ctl((ginkgo_msg *)msg);
    struct sockaddr_nl addr;
    struct iovec vec = {
        .iov_base = (void *)buf,
        .iov_len = len,
    };
    struct msghdr mhdr = {
        .msg_name = &addr,
        .msg_namelen = sizeof(addr),
        .msg_iov = &vec,
        .msg_iovlen = 1,
    };

    bzero(&addr, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = ctl->peer;
    addr.nl_groups = ctl->group;

    return sendmsg(fd, &mhdr, 0);
}

static int __rtnl_init(ginkgo_ctx *ctx, rtnl_notify cb, void *ud)
{
    ginkgo_src src;
    int fd;
    /* we listen to all messages */
    int grps = -1;

    bzero(&src, sizeof(src));
    if((fd = nl_open(NETLINK_ROUTE, grps)) < 0)
        return -1;
    src.name = "rtnl";
    src.fd = fd;
    src.wr = rtnl_write;
    src.pars = nl_parse;
    src.resp = nl_response;
    src.hand = rtnl_handler;
    src.ud = (void *)&__ginkgo_id;

    if(ginkgo_src_register(ctx, &src, &__ginkgo_id, 0))  {
        close(fd);
        return -1;
    }

    on_notify = cb;
    notify_ud = ud;
    __ginkgo = ctx;
    __rtnl_initialize = 1;
    return 0;
}

int rtnl_init(ginkgo_ctx *ctx, rtnl_notify cb, void *ud)
{
    if(! __rtnl_initialize)
        return __rtnl_init(ctx, cb, ud);
    on_notify = cb;
    notify_ud = ud;
    return 0;
}

static inline int rtnl_msg_type(ginkgo_msg *msg)
{
    return NL_HEADER(msg)->nlmsg_type;
}

static inline int rtnl_parse_check(ginkgo_msg *msg, int type)
{
    int msg_type = rtnl_msg_type(msg);

    if(msg_type == NLMSG_ERROR || msg_type == NLMSG_DONE)
        return -1;
    if(msg_type != type)  {
        PR_WARN("Unexpected msg %d instead of %d", msg_type, type);
        return -1;
    }
    return rtnl_parse(msg);
}

static inline int rtnl_talk(list *rsp, ginkgo_msg *m)
{
    list_init(rsp);
    if(ginkgo_request(__ginkgo, m, rsp, 1) != GINKGO_ERR_OK)  {
        free(m);
        return -1;
    }
    return 0;
}

static int rtnl_list_parse(list *out, list *in, int type)
{
    ginkgo_msg *msg, *n;

    list_init(out);
    list_for_each_ginkgo_msg_safe(msg, n, in)  {
        list_delete(&msg->lst);

        if(rtnl_parse_check(msg, type))  {
            free(msg);
            continue;
        }
        list_append(out, &msg->lst);
    }
    return 0;
}

int __rtnl_get_link(list *links, const struct ifinfomsg *ifm, const char *ifname, __u32 ext_mask)
{
    ginkgo_msg *msg, *n;
    size_t payload = 0;
    struct nlmsghdr *nlh;
    struct rtgenmsg rtgen;
    __u16 flags = NLM_F_REQUEST;
    list rsp;
    void *ctx;

    if(! links)
        return -1;

    if(ifm)  {
        payload += NLMSG_ALIGN(sizeof(*ifm));
        if(ifname)
            payload += nla_total_size(strlen(ifname) + 1);
    }else  {
        payload = NLMSG_ALIGN(sizeof(struct rtgenmsg));
        flags |= NLM_F_DUMP;
    }

    if(ext_mask)
        payload += nla_total_size(sizeof(__u32));

    if(! (msg = nlmsg_new(__ginkgo_id, payload)))
        return -1;

    rtnl_ctl_set(msg, 0, 0);
    ctx = nlmsg_init(msg, RTM_GETLINK, __rtnl_seq++, 0, flags);

    if(flags & NLM_F_DUMP)  {
        rtgen.rtgen_family = AF_UNSPEC;
        nlmsg_put_mem(&ctx, &rtgen, sizeof(rtgen));
    }else  {
        nlmsg_put_mem(&ctx, ifm, sizeof(*ifm));
        if(ifname)
            nla_put_string(&ctx, IFLA_IFNAME, ifname);
    }

    if(ext_mask)
        nla_put_u32(&ctx, IFLA_EXT_MASK, ext_mask);

    if(! rtnl_talk(&rsp, msg))
        return rtnl_list_parse(links, &rsp, RTM_NEWLINK);
    return -1;
}

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific, not
 * supported for most of protocol families to dump according to
 * interface.
 */
int rtnl_dump_addr(list *addrs, unsigned char pf)
{
    ginkgo_msg *msg, *n;
    struct rtgenmsg rtgen = {
        .rtgen_family = pf,
    };
    void *ctx;
    list rsp;

    if(! addrs || ! (msg = nlmsg_new(__ginkgo_id, NLMSG_ALIGN(sizeof(rtgen)))))
        return -1;
    rtnl_ctl_set(msg, 0, 0);
    ctx = nlmsg_init(msg, RTM_GETADDR, __rtnl_seq++, 0, NLM_F_REQUEST | NLM_F_DUMP);
    nlmsg_put_mem(&ctx, &rtgen, sizeof(rtgen));

    if(! rtnl_talk(&rsp, msg))
        return rtnl_list_parse(addrs, &rsp, RTM_NEWADDR);
    return -1;
}

/**
 * @msg: route dump request msg, different protocol family have quite
 * different format of the request, and currently only AF_INET type
 * route is defined and parsed.
 */
int ___rtnl_get_route(list *route, ginkgo_msg *msg, int nofree)
{
    ginkgo_msg *m, *n;
    struct nlmsghdr *nlh;
    list rsp;

    if(! route || ! msg)
        return -1;

    nlh = NL_HEADER(msg);
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = __rtnl_seq++;
    nlh->nlmsg_flags |= NLM_F_REQUEST;

    if(! rtnl_talk(&rsp, msg))
        return rtnl_list_parse(route, &rsp, RTM_NEWROUTE);
    return -1;
}

int rtnl_get_route_inet(list *route, __be32 src, __be32 dst, __u32 iif, __u32 oif,
                        __u32 mark, unsigned char tos, unsigned flags)
{
    struct rtmsg rtm;
    ginkgo_msg *m;
    size_t payload = NLMSG_ALIGN(sizeof(rtm));
    list rsp;
    void *ctx;

    if(! route) return -1;

    bzero(&rtm, sizeof(rtm));
    rtm.rtm_family = AF_INET;
    rtm.rtm_tos = tos;
    rtm.rtm_flags = flags;
    if(src)
        payload += nla_total_size(sizeof(src));
    if(dst)
        payload += nla_total_size(sizeof(dst));
    if(iif)
        payload += nla_total_size(sizeof(iif));
    if(oif)
        payload += nla_total_size(sizeof(oif));
    if(mark)
        payload += nla_total_size(sizeof(mark));
    if(! (m = nlmsg_new(__ginkgo_id, payload)))
        return -1;
    rtnl_ctl_set(m, 0, 0);
    ctx = nlmsg_init(m, RTM_GETROUTE, __rtnl_seq++, 0, NLM_F_REQUEST);
    nlmsg_put_mem(&ctx, &rtm, sizeof(rtm));
    if(src)
        nla_put_be32(&ctx, RTA_SRC, src);
    if(dst)
        nla_put_be32(&ctx, RTA_DST, dst);
    if(iif)
        nla_put_u32(&ctx, RTA_IIF, iif);
    if(oif)
        nla_put_u32(&ctx, RTA_OIF, oif);
    if(mark)
        nla_put_u32(&ctx, RTA_MARK, mark);

    if(! rtnl_talk(&rsp, m))
        return rtnl_list_parse(route, &rsp, RTM_NEWROUTE);
    return -1;
}

int rtnl_dump_route_inet(list *route)
{
    ginkgo_msg *m;
    struct rtgenmsg rtgen = {
        .rtgen_family = AF_INET,
    };
    list rsp;
    void *ctx;

    if(! route) return -1;

    if(! (m = nlmsg_new(__ginkgo_id, NLMSG_ALIGN(sizeof(rtgen)))))
        return -1;
    rtnl_ctl_set(m, 0, 0);
    ctx = nlmsg_init(m, RTM_GETROUTE, __rtnl_seq++, 0, NLM_F_REQUEST | NLM_F_DUMP);

    nlmsg_put_mem(&ctx, &rtgen, sizeof(rtgen));

    if(! rtnl_talk(&rsp, m))
        return rtnl_list_parse(route, &rsp, RTM_NEWROUTE);
    return -1;
}

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific
 * @proxy: non-zero to dump neighbour proxies
 */
int rtnl_dump_neigh(list *neighs, unsigned char pf, int proxy)
{
    ginkgo_msg *m;
    struct ndmsg ndm;
    struct rtgenmsg rtgen;
    size_t payload;
    list rsp;
    void *ctx;

    if(! neighs) return -1;

    if(proxy)  {
        payload = NLMSG_ALIGN(sizeof(ndm));
        bzero(&ndm, sizeof(ndm));
        ndm.ndm_family = pf;
        ndm.ndm_flags = NTF_PROXY;
    }else  {
        payload = NLMSG_ALIGN(sizeof(rtgen));
        rtgen.rtgen_family = pf;
    }

    if(! (m = nlmsg_new(__ginkgo_id, payload)))
        return -1;
    rtnl_ctl_set(m, 0, 0);
    ctx = nlmsg_init(m, RTM_GETNEIGH, __rtnl_seq++, 0, NLM_F_REQUEST | NLM_F_DUMP);

    if(proxy)  {
        nlmsg_put_mem(&ctx, &ndm, sizeof(ndm));
    }else  {
        nlmsg_put_mem(&ctx, &rtgen, sizeof(rtgen));
    }

    if(! rtnl_talk(&rsp, m))
        return rtnl_list_parse(neighs, &rsp, RTM_NEWNEIGH);
    return -1;
}

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific
 */
int rtnl_dump_rule(list *rules, unsigned char pf)
{
    ginkgo_msg *m;
    struct rtgenmsg rtgen;
    list rsp;
    void *ctx;

    if(rules)  {
        rtgen.rtgen_family = pf;
        if((m = nlmsg_new(__ginkgo_id, sizeof(rtgen))))  {
            rtnl_ctl_set(m, 0, 0);
            ctx = nlmsg_init(m, RTM_GETRULE, __rtnl_seq++, 0, NLM_F_REQUEST | NLM_F_DUMP);
            nlmsg_put_mem(&ctx, &rtgen, sizeof(rtgen));
            if(! rtnl_talk(&rsp, m))
                return rtnl_list_parse(rules, &rsp, RTM_NEWRULE);
        }
    }
    return -1;
}

