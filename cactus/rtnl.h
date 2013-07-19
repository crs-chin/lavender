/*
 * rtnl.h Interface to netlink route subsystem
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

#ifndef __RTNL_H
#define __RTNL_H

#include <strings.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/if_addr.h>
#include <linux/neighbour.h>
#include "linux_if_link.h"
#include <linux/rtnetlink.h>

#include "linux_fib_rules.h"

#include "util.h"
#include "ginkgo.h"

__BEGIN_DECLS

typedef struct _rtnl_msg rtnl_msg;

typedef struct _link_entry link_entry;

typedef struct _addr_entry addr_entry;
typedef struct _addr_entry_inet addr_entry_inet;
typedef struct _addr_entry_inet6 addr_entry_inet6;

typedef struct _route_entry route_entry;
typedef struct _route_entry_inet route_entry_inet;

typedef struct _neigh_entry neigh_entry;

typedef struct _rule_entry rule_entry;
typedef struct _rule_entry_inet rule_entry_inet;
/**
 * others to be defined if necessary
 */


struct _rtnl_msg{
    int type;
    void *entry;
};

struct _link_entry{
    struct ifinfomsg *ifinfo;
    struct rtattr *rta[IFLA_MAX + 1];
    char *ifname;
    char *ifalias;
    char *qdisc;
    struct rtnl_link_ifmap *ifmap;
    struct rtnl_link_stats *ifstat;
    struct rtnl_link_stats64 *ifstat64;
    __u32 *txqlen;
    __u32 *weight;
    __u32 *mtu;
    __u32 *link;
    __u32 *master;
    __u32 *promiscuity;
    __u8 *operstate;
    __u8 *linkmode;
    /* more detailed info defined here */
};

struct _addr_entry{
    struct ifaddrmsg *ifaddr;
    struct rtattr *rta[IFA_MAX + 1];
};

struct _addr_entry_inet{
    addr_entry base;
    __be32 *addr;
    __be32 *local;
    __be32 *broadcast;
    char *label;
};

struct _addr_entry_inet6{
    addr_entry base;
    struct in6_addr *addr;
    struct in6_addr *mcaddr;
    struct in6_addr *acaddr;
    struct ifa_cacheinfo *cinfo;
};

typedef struct _rtnexthop_elem rtnexthop_elem;

struct _rtnexthop_elem{
    struct rtnexthop *hop;
    __be32 *gateway;
    __u32 *flow;
};

struct _route_entry{
    struct rtmsg *rt;
    struct rtattr *rta[RTA_MAX + 1];
};

struct _route_entry_inet{
    route_entry base;
    __u32 *table;
    __be32 *dst;
    __be32 *src;
    __u32 *oif;
    __u32 *iif;
    __u32 *flow;
    __be32 *prefsrc;
    __be32 *gateway;
    __u32 *metrics[RTAX_MAX + 1];
    __be32 *mark;
    __u32 *priority;
    struct rta_cacheinfo *cinfo;
    int nhops;
    rtnexthop_elem hops[0];
};

struct _neigh_entry{
    struct ndmsg *nd;
    struct rtattr *rta[NDA_MAX + 1];
};

struct _rule_entry{
    struct fib_rule_hdr *hdr;
    struct rtattr *rta[FRA_MAX + 1];
};

struct _rule_entry_inet{
    rule_entry base;
    __u32 *table;
    char *iif;
    char *oif;
    __be32 *dst;
    __be32 *src;
    __u32 *flow;
    __u32 *priority;
    __u32 *fwmark;
    __u32 *fwmask;
    __u32 *target;
};

#define RTNL_MSG(m) ((rtnl_msg *)&(m)->cmn)
#define RTNL_GINKGO_MSG(m) container_of(m,ginkgo_msg,cmn)

#define list_rtnl_msg(ptr)                      \
    ({ginkgo_msg *gmsg = list_entry((ptr),ginkgo_msg,lst); RTNL_MSG(gmsg);})

#define list_for_each_rtnl_msg(m,head)                          \
    {ginkgo_msg *__gmsg;                                        \
    for(__gmsg = list_entry((head)->l_nxt,ginkgo_msg,lst),      \
            m = RTNL_MSG(__gmsg);                               \
        &__gmsg->lst != (head);                                 \
        __gmsg = list_entry(__gmsg->lst.l_nxt,ginkgo_msg,lst),  \
            m = RTNL_MSG(__gmsg))

#define list_for_each_rtnl_msg_safe(m,n,head)               \
    {ginkgo_msg *__gmsg, *__gmsg_n;                         \
    for(__gmsg = list_ginkgo((head)->l_nxt),                \
            m = RTNL_MSG(__gmsg),                           \
            __gmsg_n = list_ginkgo_msg(__gmsg->lst.l_nxt),  \
            n = RTNL_MSG(__gmsg_n);                         \
        &__gmsg->lst != (head);                             \
        __gmsg = __gmsg_n, m = n,                           \
            __gmsg_n = list_ginkgo_msg(__gmsg->lst.l_nxt),  \
            n = RTNL_MSG(__gmsg_n))

#ifndef list_end
#define list_end }
#endif

static inline void rtnl_msg_free(rtnl_msg *m)
{
    if(m->entry)
        free(m->entry);
    free(RTNL_GINKGO_MSG(m));
}

static inline void rtnl_msg_list_free(list *head)
{
    list *l, *n;

    list_for_each_safe(l, n, head)  {
        list_delete(l);
        rtnl_msg_free(list_rtnl_msg(l));
    }
}

/**
 * no matter parsed or supported or not, all notify messages will be
 * notified through this cb, return non-zero if msg ate up.
 */
typedef int (*rtnl_notify)(rtnl_msg *msg, void *ud);

int rtnl_init(ginkgo_ctx *ctx, rtnl_notify cb, void *ud);

int __rtnl_get_link(list *links, const struct ifinfomsg *ifm, const char *ifname, __u32 ext_mask);

/**
 * @if_index takes precedence over @ifname
 */
static inline rtnl_msg *rtnl_get_link(int if_index, const char *ifname, __u32 ext_mask)
{
    struct ifinfomsg ifm;
    list links, *tmp;

    bzero(&ifm, sizeof(ifm));
    ifm.ifi_index = if_index;
    if(! __rtnl_get_link(&links, &ifm, ifname, ext_mask) && ! list_empty(&links))  {
        tmp = links.l_nxt;
        list_delete(tmp);
        rtnl_msg_list_free(&links);
        return list_rtnl_msg(tmp);
    }
    return NULL;
}

static inline int rtnl_dump_link(list *links, __u32 ext_mask)
{
    return __rtnl_get_link(links, NULL, NULL, ext_mask);
}

/* link set function to be defined here if necessary */

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific, not
 * supported for most of protocol families to dump according to
 * interface.
 */
int rtnl_dump_addr(list *addrs, unsigned char pf);

/* addr set function to be defined here if necessary */

/**
 * @msg: route dump request msg, different protocol family have quite
 * different format of the request, and currently only AF_INET type
 * route is defined and parsed.
 */
int ___rtnl_get_route(list *route, ginkgo_msg *msg, int nofree);

int rtnl_get_route_inet(list *route, __be32 src, __be32 dst, __u32 iif, __u32 oif,
                        __u32 mark, unsigned char tos, unsigned flags);
int rtnl_dump_route_inet(list *route);

/* other route functions to be defined here if necessary */

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific
 * @proxy: non-zero to dump neighbour proxies
 */
int rtnl_dump_neigh(list *neighs, unsigned char pf, int proxy);

/* neigh setup functions to be defined here if necessary */

/**
 * @pf: PF_UNSPEC to dump all, otherwise protocol family specific
 */
int rtnl_dump_rule(list *rules, unsigned char pf);

/* other rule functions to be defined here if necessary */


__END_DECLS

#endif  /* __RTNL_H */

