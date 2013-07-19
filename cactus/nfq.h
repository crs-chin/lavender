/*
 * nfq.h
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

#ifndef __NFQ_H
#define __NFQ_H

#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>

#include "linux_netfilter_nfnetlink_queue.h"

#include "nl.h"

__BEGIN_DECLS

typedef struct _nfq_parm nfq_parm;
typedef struct _nfq_queue nfq_queue;

/**
 * return 0 to break handling loop
 */
typedef int (*nfq_handler)(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud);

static inline void *nfq_pkt(struct nlattr *nla[])
{
    return (nla[NFQA_PAYLOAD] ? nla_data(nla[NFQA_PAYLOAD]) : NULL);
}

static inline struct nfqnl_msg_packet_hdr *nfq_pkt_hdr(struct nlattr *nla[])
{
    return (nla[NFQA_PACKET_HDR] ? (struct nfqnl_msg_packet_hdr *)nla_data(nla[NFQA_PACKET_HDR]) : NULL);
}

static inline struct nfqnl_msg_packet_hw *nfq_pkt_hw(struct nlattr *nla[])
{
    return (nla[NFQA_HWADDR] ? (struct nfqnl_msg_packet_hw *)nla_data(nla[NFQA_HWADDR]) : NULL);
}

static inline __u32 nfq_pkt_mark(struct nlattr *nla[])
{
    return (nla[NFQA_MARK] ? ntohl(nla_get_be32(nla[NFQA_HWADDR])) : 0);
}

static inline struct nfqnl_msg_packet_timestamp *nfq_pkt_ts(struct nlattr *nla[])
{
    return (nla[NFQA_TIMESTAMP] ? (struct nfqnl_msg_packet_timestamp *)nla_data(nla[NFQA_TIMESTAMP]) : NULL);
}

static inline __u32 nfq_pkt_indev(struct nlattr *nla[])
{
    return (nla[NFQA_IFINDEX_INDEV] ? ntohl(nla_get_be32(nla[NFQA_IFINDEX_INDEV])) : 0);
}

static inline __u32 nfq_pkt_outdev(struct nlattr *nla[])
{
    return (nla[NFQA_IFINDEX_OUTDEV] ? ntohl(nla_get_be32(nla[NFQA_IFINDEX_OUTDEV])) : 0);
}

static inline __u32 nfq_pkt_phy_indev(struct nlattr *nla[])
{
    return (nla[NFQA_IFINDEX_PHYSINDEV] ? ntohl(nla_get_be32(nla[NFQA_IFINDEX_PHYSINDEV])) : 0);
}

static inline __u32 nfq_pkt_phy_outdev(struct nlattr *nla[])
{
    return (nla[NFQA_IFINDEX_PHYSOUTDEV] ? ntohl(nla_get_be32(nla[NFQA_IFINDEX_PHYSOUTDEV])) : 0);
}

struct _nfq_parm{
    __u16 queue_num;
    __u16 pf;                   /* NFPROTO_* */
    __u8 copy_mode;
    __u32 copy_range;
    __u32 max_len;
    nfq_handler handler;
    void *ud;
};

int nfq_create(nfq_queue **q, const nfq_parm *parm);

#define NFQ_F_THREAD 1

int nfq_start(nfq_queue *q, int flags);

int nfq_verdict(nfq_queue *q, __be32 id, int verdict, __u32 mark);

/* reentrant version */
int nfq_verdict_r(nfq_queue *q, __be32 id, int verdict, __u32 mark);

int nfq_destroy(nfq_queue *q);


__END_DECLS

#endif  /* __NFQ_H */
