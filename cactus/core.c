/*
 * core.c
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

/* netfilter queue base packet filter */

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/vfs.h>
#include <sys/utsname.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <linux/types.h>
#include <linux/magic.h>
#include <pthread.h>

#include "util.h"
#include "msg_base.h"
#include "msg.h"
#include "kconf.h"
#include "sig_handle.h"
#include "cactus_be.h"
#include "timer.h"
#include "async_work.h"
#include "nfq.h"
#include "nfqm.h"
#include "rtnl.h"
#include "nfct.h"
#include "uevent.h"
#include "sock_stat.h"
#include "fd_lookup.h"
#include "fw_table.h"
#include "cactus_log.h"
#include "core.h"

#ifndef CONFIG_PID_LOCK
#define CONFIG_PID_LOCK "/var/run/" PACKAGE_NAME ".pid"
#endif

#ifndef CONFIG_STAT_DIR
#define CONFIG_STAT_DIR "/var/run/"
#endif

#ifndef CONFIG_STAT_FILE
#define CONFIG_STAT_FILE PACKAGE_NAME ".stat"
#endif

#ifndef CONFIG_RULE_DIR
#define CONFIG_RULE_DIR "/var/lib/" PACKAGE_NAME "/"
#endif

#ifndef CONFIG_RULE_FILE
#define CONFIG_RULE_FILE "rule.list"
#endif

#define CONFIG_STAT_PATH (CONFIG_STAT_DIR CONFIG_STAT_FILE)
#define CONFIG_RULE_PATH (CONFIG_RULE_DIR CONFIG_RULE_FILE)

#define MAX_IP_HDR_LEN (15 * 4)
#define TCP_IP_HDR_LEN (MAX_IP_HDR_LEN + sizeof(struct tcphdr))
#define UDP_IP_HDR_LEN (MAX_IP_HDR_LEN + sizeof(struct udphdr))

#define QUEUE_NUM_TCP_OUT 1127
#define QUEUE_NUM_UDP_OUT 1007
#define QUEUE_NUM_OTHER_OUT 817
#define QUEUE_NUM_PKT_IN 818

#define QUEUE_MAX_LEN 1024

typedef struct _fw_addr fw_addr;
typedef struct _fw_iface fw_iface;
typedef struct _fw_buck fw_buck;

enum{
    CACTUS_ST_UNAVAILABLE,      /* clients may not connect */
    CACTUS_ST_AVAILABLE,        /* clients may connect now */
};

enum{
    QUEUE_TCP_OUT,
    QUEUE_UDP_OUT,
    QUEUE_OTHER_OUT,
    QUEUE_PKT_IN,
    NUM_QUEUE,
};

struct _fw_addr{
    list list;
    int pf;                     /* AF_INET only currently */
    __be32 addr[4];
    __be32 bc[4];
    int ifindex;
};

/* fw check on interface if flags set */
#define IFACE_F_GUARD 1

struct _fw_iface{
    list list;
    list addrs;
    char *ifname;
    int ifindex;
    int flags;
};

struct _fw_buck{
    int initialized;
    ginkgo_ctx *ginkgo;
    nfct_t *ct;

    const nfq_parm *queue_parm;
    nfq_queue *nfq[NUM_QUEUE];
    nfqm *nfqm[NUM_QUEUE];

    pthread_rwlock_t lock;
    list iface_list;
    list white_list;
};

static void core_set_status(int st);
static int on_tcp_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud);
static int on_udp_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud);
static int on_other_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud);
static int on_pkt_in(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud);

static void uevent_log(uevent_msg *msg, void *ud);

static int __core_status = CORE_INIT;
static sigset_t __sig_mask;
static fw_buck fw_core;

static const nfq_parm queue_parm[NUM_QUEUE] = {
    {
        .queue_num = QUEUE_NUM_TCP_OUT,
        .pf = PF_INET,
        .copy_mode = NFQNL_COPY_PACKET,
        .copy_range = TCP_IP_HDR_LEN,
        .max_len = QUEUE_MAX_LEN,
        .handler = on_tcp_out,
        .ud = (void *)&fw_core.nfqm[0],
    },
    {
        .queue_num = QUEUE_NUM_UDP_OUT,
        .pf = PF_INET,
        .copy_mode = NFQNL_COPY_PACKET,
        .copy_range = UDP_IP_HDR_LEN,
        .max_len = QUEUE_MAX_LEN,
        .handler = on_udp_out,
        .ud = (void *)&fw_core.nfqm[1],
    },
    {
        .queue_num = QUEUE_NUM_OTHER_OUT,
        .pf = PF_INET,
        .copy_mode = NFQNL_COPY_PACKET,
        .copy_range = MAX_IP_HDR_LEN,
        .max_len = QUEUE_MAX_LEN,
        .handler = on_other_out,
        .ud = (void *)&fw_core.nfqm[2],
    },
    {
        .queue_num = QUEUE_NUM_PKT_IN,
        .pf = PF_INET,
        .copy_mode = NFQNL_COPY_PACKET,
        .copy_range = TCP_IP_HDR_LEN, /* ensure TCP/UDP header copied */
        .max_len = QUEUE_MAX_LEN,
        .handler = on_pkt_in,
        .ud = (void *)&fw_core.nfqm[3],
    },
};

static uevent_handler uevent_handler_desc = {
    .actions = ACTION_F_ALL,
    .path = NULL,
    .len = 0,
    .cb = uevent_log,
    .ud = NULL,
    .flags = UEVENT_F_INCLUSIVE,
};

static struct{
    char *name;
    int stat;
}modules_autoload[] = {
    {"ip_conntrack", 0,},
};

static __attribute__((noreturn)) void core_abort(void)
{
    /* flush all available logs before quite */
    cactus_log_fini();
    exit(-1);
}

static inline void *ip_next_hdr(struct iphdr *ip)
{
    return (char *)ip + ip->ihl * 4;
}

static inline sk_entry *tcp_sk_entry(struct iphdr *ip, struct tcphdr *tcp, __u32 iif)
{
    return sock_stat_lookup_tcp(ip->saddr, ip->daddr,
                                tcp->source, tcp->dest, iif);
}

static inline sk_entry *udp_sk_entry(struct iphdr *ip, struct udphdr *udp, __u32 iif)
{
    return sock_stat_lookup_udp_exact(ip->saddr, ip->daddr,
                                      udp->source, udp->dest, iif);
}

static int fos_verdict(nfq_queue *q, const struct iphdr *ip,
                       list *fos, __be32 pkt_id, nfqm *qm)
{
    int verd, err = 0;
    __u64 vid;

    switch((verd = fw_table_walk(fos, (void *)qm, &vid)))  {
    case FW_ACCEPT:
        err = nfq_verdict(q, pkt_id, NF_ACCEPT, 0);
        break;
    case FW_STOP:
        err = nfq_verdict(q, pkt_id, NF_STOP, 0);
        break;
    case FW_VERDICT:
        if(qm)  {
            if(nfqm_push(qm, ip, pkt_id, vid))  {
                err = nfq_verdict(q, pkt_id, NF_DROP, 0);
                LOG_ERROR("fail to enqueue nfq pkt %u, dropped", pkt_id);
            }
        }else  {
            err = nfq_verdict(q, pkt_id, NF_DROP, 0);
            LOG_WARN("nfqm not available, pkt %u dropped", pkt_id);
        }
        break;
    default:
        LOG_ERROR("unexpected verdict from fw rule verdict:%u, drop the packet", verd);
    case FW_DROP:
    case FW_KILL:
        err = nfq_verdict(q, pkt_id, NF_DROP, 0);
        break;
    }

    if(err)
        LOG_ERROR("fail to verdict network packet %u:%d", ntohl(pkt_id), err);
    return verd;
}

static inline void sk_verdict(nfq_queue *q, const struct iphdr *ip, 
                              const sk_entry *sk, __be32 pkt_id, nfqm *qm)
{
    list fos;

    if(lookup_fos_from_sk(&fos, sk) || list_empty(&fos))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_ERROR("fail to lookup fd inode %u owners, dropped "
                  IP_FMT " -> " IP_FMT ", prot %u",
                  sk->info->idiag_inode, IP_ARG(ip->saddr),
                  IP_ARG(ip->daddr), ip->protocol);
    }else  {
        fos_verdict(q, ip, &fos, pkt_id, qm);
    }
}

static int local_addr(__be32 ip)
{
    fw_iface *iface;
    fw_addr *fa;
    __u8 *v = (__u8 *)&ip;

    if(v[0] == IN_LOOPBACKNET)
        return 1;

    pthread_rwlock_rdlock(&fw_core.lock);
    list_for_each_entry(iface, &fw_core.iface_list, list)  {
        list_for_each_entry(fa, &iface->addrs, list)  {
            if(fa->pf == AF_INET)  {
                if(fa->addr[0] && fa->addr[0] == ip)  {
                    pthread_rwlock_unlock(&fw_core.lock);
                    return 1;
                }
            }
        }
    }
    pthread_rwlock_unlock(&fw_core.lock);
    return 0;
}

static int ip_out_filtered(nfq_queue *q, const struct iphdr *ip, __u64 id)
{
    __u8 *v0, *v1;

    if(local_addr(ip->daddr))  {
        v0 = (__u8 *)&ip->saddr;
        v1 = (__u8 *)&ip->daddr;

        nfq_verdict(q, id, NF_ACCEPT, 0);
        LOG_INFO("let go link-local out pkt %u.%u.%u.%u -> %u.%u.%u.%u",
                 v0[0], v0[1], v0[2], v0[3],
                 v1[0], v1[1], v1[2], v1[3]);
        return 1;
    }
    return 0;
}

static int on_tcp_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud)
{
    struct nfqnl_msg_packet_hdr *phdr;
    struct iphdr *ip;
    struct tcphdr *tcp;
    sk_entry *sk;
    __u32 iif = nfq_pkt_outdev(nla);

    if(! (phdr = nfq_pkt_hdr(nla)))  {
        LOG_ERROR("no packet hdr on tcp out queue");
        return 1;
    }

    if(! (ip = (struct iphdr *)nfq_pkt(nla)))  {
        LOG_ERROR("no packet payload on tcp out queue");
        goto drop;
    }

    if(ip_out_filtered(q, ip, phdr->packet_id))
        return 1;

    tcp = (struct tcphdr *)ip_next_hdr(ip);
    if(! (sk = tcp_sk_entry(ip, tcp, iif)))  {
        LOG_WARN("fail to lookup tcp sk entry " IP_FMT ":%u -> " IP_FMT ":%u if:%u, droped",
                 IP_ARG(ip->saddr), ntohs(tcp->source), IP_ARG(ip->daddr), ntohs(tcp->dest), iif);
        goto drop;
    }

    sk_verdict(q, ip, sk, phdr->packet_id, ud ? *(nfqm **)ud : NULL);
    sk_entry_free(sk);
    return 1;

 drop:
    nfq_verdict(q, phdr->packet_id, NF_DROP, 0);
    return 1;
}

static inline int sk_mismatch_pkt_udp_out(sk_entry *sk, const struct iphdr *ip,
                                          const struct udphdr *udp)
{
    const struct inet_diag_sockid *id = &sk->info->id;

    return ((id->idiag_src[0] && id->idiag_src[0] != (__be32)ip->saddr)
            || (id->idiag_dst[0] && id->idiag_dst[0] != (__be32)ip->daddr)
            || (id->idiag_dport && id->idiag_dport != udp->dest)
            || (id->idiag_sport && id->idiag_sport != udp->source));
}

static void verd_udp_out(nfq_queue *q, const struct iphdr *ip,
                         const struct udphdr *udp, __be32 pkt_id, nfqm *qm)
{
    list sks, *tmp, fos, _fos;
    sk_entry *sk = NULL, *iter, *n;

    if(sock_stat_lookup_udp_port(&sks, udp->source))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_ERROR("fail to lookup local udp port %u, dropped " IP_FMT
                  " -> " IP_FMT, ntohs(udp->source), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    if(list_empty(&sks))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_INFO("no local udp port %u looked up " IP_FMT " -> " IP_FMT ", dropped",
                 ntohs(udp->source), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    /* notes on udp sockets' ambiguity:
       1. proc may not connect() udp sock, so those sockets are not
       binded onto local address, but only with local port opened
       2. multiple procs may bind onto the same local addr and port
       pair, so there can be multiple procs that have exactly matched
       socket, and we can't distinghuish them
       3. so we can only get rid of unmatched sockets, and verdict the
       rest
    */
    list_for_each_sk_entry_safe(iter, n, tmp, &sks)  {
        if(sk_mismatch_pkt_udp_out(iter, ip, udp))  {
            list_delete(sk_entry_list(iter));
            sk_entry_free(iter);
        }
    }

    if(list_empty(&sks))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_INFO("no matching sock found udp port %u " IP_FMT " -> " IP_FMT ", dropped",
                 ntohs(udp->source), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    /* unable to judge which is one now, verdict them all */
    list_init(&fos);
    list_for_each_sk_entry(iter, tmp, &sks)  {
        if(lookup_fos_from_sk(&_fos, iter) || list_empty(&_fos))  {
            nfq_verdict(q, pkt_id, NF_DROP, 0);
            LOG_ERROR("fail to lookup fd inode %u owners, dropped "
                      IP_FMT " -> " IP_FMT ", prot %u",
                      iter->info->idiag_inode, IP_ARG(ip->saddr),
                      IP_ARG(ip->daddr), ip->protocol);
            goto out;
        }
        list_add(&fos, &_fos);
    }

    fos_verdict(q, ip, &fos, pkt_id, qm);

 out:
    sk_entry_list_free(&sks);
}

static int on_udp_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud)
{
    struct nfqnl_msg_packet_hdr *phdr;
    struct iphdr *ip;
    struct udphdr *udp;

    if(! (phdr = nfq_pkt_hdr(nla)))  {
        LOG_ERROR("no packet hdr on udp out queue");
        return 1;
    }

    if(! (ip = (struct iphdr *)nfq_pkt(nla)))  {
        nfq_verdict(q, phdr->packet_id, NF_DROP, 0);
        LOG_ERROR("no packet payload on udp out queue");
        return 1;
    }

    if(ip_out_filtered(q, ip, phdr->packet_id))
        return 1;

    udp = (struct udphdr *)ip_next_hdr(ip);
    verd_udp_out(q, ip, udp, phdr->packet_id, ud ? *(nfqm **)ud : NULL);
    return 1;
}

static int on_other_out(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud)
{
    struct nfqnl_msg_packet_hdr *phdr;
    struct iphdr *ip;

    if(! (phdr = nfq_pkt_hdr(nla)))  {
        LOG_ERROR("no packet hdr on tcp out queue");
        return 1;
    }

    if(! (ip = (struct iphdr *)nfq_pkt(nla)))  {
        LOG_ERROR("no packet payload on tcp queue");
        goto drop;
    }

    if(ip_out_filtered(q, ip, phdr->packet_id))
        return 1;

    switch(ip->protocol)  {
        /* TODO: AH, ESP and etc for VPN availability */
    case IPPROTO_ICMP:
        /* TODO: accept only in replied connection. */
    default:
        LOG_INFO("unsupported l3 protocol %u", ip->protocol);
        break;
    }

    return 1;

 drop:
    nfq_verdict(q, phdr->packet_id, NF_DROP, 0);
    return 1;
}

/* NOTE: there's no way to notify us on local port been opened util
   new connect request received */
static void verd_tcp_in(nfq_queue *q, const struct iphdr *ip,
                        const struct tcphdr *tcp, __be32 pkt_id, nfqm *qm)
{
    list sks, *tmp;
    sk_entry *sk = NULL, *iter;

    if(sock_stat_lookup_tcp_port(&sks, tcp->dest, TCP_LISTEN))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_ERROR("fail to lookup local tcp listen port %u, dropped " IP_FMT
                  " -> " IP_FMT,  ntohs(tcp->dest),
                  IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    if(list_empty(&sks))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_INFO("dropped pkt on closed tcp port %u " IP_FMT " -> " IP_FMT,
                 ntohs(tcp->dest), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    /* NOTE: this include both INET and INET6, but we support INET
       only for now */
    list_for_each_sk_entry(iter, tmp, &sks)  {
        if(iter->info->idiag_family == AF_INET)  {
            if(sk)  {
                nfq_verdict(q, pkt_id, NF_DROP, 0);
                LOG_ERROR("report bug, multiple sockets listening on port %u, drop it",
                          ntohs(tcp->dest));
                list_for_each_sk_entry(iter, tmp, &sks)  {
                    LOG_ERROR("   sk entry:" IP_FMT ":%u ->" IP_FMT ":%u, if:%d, ino:%u",
                              IP_ARG(iter->info->id.idiag_src[0]), iter->info->id.idiag_sport,
                              IP_ARG(iter->info->id.idiag_dst[0]), iter->info->id.idiag_dport,
                              iter->info->id.idiag_if, iter->info->idiag_inode);
                }
                goto out;
            }

            sk = iter;
        }
    }
    sk_verdict(q, ip, sk, pkt_id, qm);

 out:
    sk_entry_list_free(&sks);
}

static inline int sk_mismatch_pkt_udp_in(sk_entry *sk, const struct iphdr *ip,
                                         const struct udphdr *udp)
{
    const struct inet_diag_sockid *id = &sk->info->id;

    return ((id->idiag_src[0] && id->idiag_src[0] != (__be32)ip->daddr)
            || (id->idiag_dst[0] && id->idiag_dst[0] != (__be32)ip->saddr)
            || (id->idiag_dport && id->idiag_dport != udp->source)
            || (id->idiag_sport && id->idiag_sport != udp->dest));
}

static inline int sk_match_pkt_udp_in(const sk_entry *sk, const struct iphdr *ip,
                                      const struct udphdr *udp)
{
    const struct inet_diag_sockid *id = &sk->info->id;

    return (id->idiag_src[0] == (__be32)ip->daddr
            && id->idiag_dst[0] == (__be32)ip->saddr
            && id->idiag_dport == udp->source
            && id->idiag_sport == udp->dest);
}

static void verd_udp_in(nfq_queue *q, const struct iphdr *ip,
                        const struct udphdr *udp, __be32 pkt_id, nfqm *qm)
{
    list sks, *tmp, fos, _fos;
    sk_entry *sk = NULL, *iter, *n;
    int cnt = 0;

    if(sock_stat_lookup_udp_port(&sks, udp->dest))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_ERROR("fail to lookup local udp listen port %u, dropped " IP_FMT
                  " -> " IP_FMT, ntohs(udp->dest), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    if(list_empty(&sks))  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_INFO("dropped pkt on closed udp port %u " IP_FMT " -> " IP_FMT,
                 ntohs(udp->dest), IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return;
    }

    /* multiple sk is possible for udp but only one will receive the
       pkt */
    /* get rid of unmatched first */
    list_for_each_sk_entry_safe(iter, n, tmp, &sks)  {
        if(sk_mismatch_pkt_udp_in(iter, ip, udp))  {
            list_delete(sk_entry_list(iter));
            sk_entry_free(iter);
            continue;
        }
        sk = iter;
        cnt++;
    }

    if(cnt == 0)  {
        nfq_verdict(q, pkt_id, NF_DROP, 0);
        LOG_INFO("dropped incoming udp pkt on no matching sock, " IP_FMT ":%u -> " IP_FMT ":%u",
                 IP_ARG(ip->saddr), ntohs(udp->source), IP_ARG(ip->daddr), ntohs(udp->dest));
        return;
    }

    if(cnt == 1)  {
        sk_verdict(q, ip, sk, pkt_id, qm);
        goto out;
    }

    /* judge which is the real one */
    list_for_each_sk_entry(iter, tmp, &sks)  {
        if(sk_match_pkt_udp_in(iter, ip, udp))  {
            sk_verdict(q, ip, iter, pkt_id, qm);
            goto out;
        }
    }

    /* unable to judge which is right, verdict them all */
    list_init(&fos);
    list_for_each_sk_entry(iter, tmp, &sks)  {
        if(lookup_fos_from_sk(&_fos, iter) || list_empty(&_fos))  {
            nfq_verdict(q, pkt_id, NF_DROP, 0);
            LOG_ERROR("fail to lookup fd inode %u owners, dropped "
                      IP_FMT " -> " IP_FMT ", prot %u",
                      sk->info->idiag_inode, IP_ARG(ip->saddr),
                      IP_ARG(ip->daddr), ip->protocol);
            goto out;
        }
        list_add(&fos, &_fos);
    }

    fos_verdict(q, ip, &fos, pkt_id, qm);

 out:
    sk_entry_list_free(&sks);
}

static void verd_icmp_in(nfq_queue *q, const struct iphdr *ip,
                         const struct icmphdr *ucmp, __be32 pkt_id, nfqm *qm)
{
    /* FIXME: add config for icmp acceptance */

    nfq_verdict(q, pkt_id, NF_DROP, 0);
}

static int on_pkt_in(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *nla[], void *ud)
{
    struct nfqnl_msg_packet_hdr *phdr;
    struct iphdr *ip;

    if(! (phdr = nfq_pkt_hdr(nla)))  {
        LOG_ERROR("no packet hdr on tcp out queue");
        return 1;
    }

    if(! (ip = (struct iphdr *)nfq_pkt(nla)))  {
        LOG_ERROR("no packet payload on tcp queue");
        goto drop;
    }

    /* by-pass link local connections */
    if(local_addr(ip->saddr))  {
        nfq_verdict(q, phdr->packet_id, NF_ACCEPT, 0);
        LOG_INFO("let go link-local in pkt " IP_FMT " -> " IP_FMT,
                 IP_ARG(ip->saddr), IP_ARG(ip->daddr));
        return 1;
    }

    switch(ip->protocol)  {
    case IPPROTO_TCP:
        verd_tcp_in(q, ip, ip_next_hdr(ip),
                    phdr->packet_id, ud ? *(nfqm **)ud : NULL);
        break;
    case IPPROTO_UDP:
        verd_udp_in(q, ip, ip_next_hdr(ip),
                    phdr->packet_id, ud ? *(nfqm **)ud : NULL);
        break;
    case IPPROTO_ICMP:
        verd_icmp_in(q, ip, ip_next_hdr(ip),
                     phdr->packet_id, ud ? *(nfqm **)ud : NULL);
        break;
    default:
        /* reject all unknown or unsported packets */
        LOG_INFO("unsupported l3 protocol %u, reject", ip->protocol);
        goto drop;
    }
    return 1;

 drop:
    nfq_verdict(q, phdr->packet_id, NF_DROP, 0);
    return 1;
}

static void on_new_link(fw_buck *fw, link_entry *e)
{
    fw_iface *iface, *iter;

    if(! e)
        return;

    if(! instantiate(iface))  {
        LOG_ERROR("OOM instantiate iface");
        return;
    }

    list_init(&iface->list);
    list_init(&iface->addrs);
    iface->ifindex = e->ifinfo->ifi_index;
    if(! (iface->ifname = strdup(e->ifname)))  {
        LOG_ERROR("OOM strdup ifname");
        free(iface);
        return;
    }

    iface->flags = 0;
    if(! (e->ifinfo->ifi_flags & IFF_LOOPBACK))
        iface->flags |= IFACE_F_GUARD;

    pthread_rwlock_wrlock(&fw->lock);
    list_for_each_entry(iter, &fw->iface_list, list)  {
        if(iter->ifindex == iface->ifindex)  {
            free(iter->ifname);
            iter->ifname = iface->ifname;
            free(iface);
            iface = NULL;
            break;
        }
    }
    if(iface)  {
        LOG_INFO("passive added interace %s", iface->ifname);
        list_append(&fw->iface_list, &iface->list);
    }
    pthread_rwlock_unlock(&fw->lock);
}


static void __del_link(fw_iface *iface)
{
    fw_addr *addr, *n;
    __u8 *v;

    list_for_each_entry_safe(addr, n, &iface->addrs, list)  {
        v = (__u8 *)&addr->addr[0];
        LOG_INFO("delete addr %u.%u.%u.%u from dead link", v[0], v[1], v[2], v[3]);
        list_delete(&addr->list);
        free(addr);
    }

    if(iface->ifname)
        free(iface->ifname);
    free(iface);
}

static void on_del_link(fw_buck *fw, link_entry *e)
{
    fw_iface *iter;
    int ifindex;

    if(! e)
        return;

    ifindex = e->ifinfo->ifi_index;
    pthread_rwlock_wrlock(&fw->lock);
    list_for_each_entry(iter, &fw->iface_list, list)  {
        if(iter->ifindex == ifindex)  {
            LOG_INFO("passive deleted interface %s", iter->ifname);
            list_delete(&iter->list);
            __del_link(iter);
            break;
        }
    }
    pthread_rwlock_unlock(&fw->lock);
}

static fw_iface *__lookup_iface(fw_buck *fw, addr_entry_inet *e)
{
    fw_iface *iter;
    __u32 ifindex;

    if(! e->local)  {
        LOG_INFO("empty local addr to lookup");
        return 0;
    }

    ifindex = e->base.ifaddr->ifa_index;

    list_for_each_entry(iter, &fw->iface_list, list)  {
        if(ifindex == (__u32)iter->ifindex)
            return iter;
    }
    return NULL;
}

static int __add_addr(fw_buck *fw, addr_entry_inet *e)
{
    fw_addr *fa;
    fw_iface *iface;
    __u8 *v = (__u8 *)e->local;

    if(! (iface = __lookup_iface(fw, e)))  {
        LOG_ERROR("no binding iface found for addr %u.%u.%u.%u", v[0], v[1], v[2], v[3]);
        return 0;
    }

    if(! e->local && ! e->addr)  {
        LOG_ERROR("bad addr to add, no valid addr in addr_entry_inet, ignored");
        /* silently ignore */
        return 0;
    }

    if(! instantiate(fa))  {
        LOG_ERROR("OOM instantiate fw_addr");
        return -1;
    }

    list_init(&fa->list);
    fa->pf = AF_INET;
    if(e->local)
        fa->addr[0] = *e->local;
    else
        fa->addr[0] = *e->addr;
    if(e->broadcast)
        fa->bc[0] = *e->broadcast;
    else
        fa->bc[0] = 0;
    fa->ifindex = iface->ifindex;
    list_append(&iface->addrs, &fa->list);
    LOG_INFO("added %u.%u.%u.%u to iface %s", v[0], v[1], v[2], v[3], iface->ifname);
    return 0;
}

static int __del_addr(fw_buck *fw, addr_entry_inet *e)
{
    fw_addr *fa;
    fw_iface *iface;
    __u8 *v = (__u8 *)e->local;

    if(! (iface = __lookup_iface(fw, e)))  {
        LOG_WARN("no binding iface to del addr %u.%u.%u.%u", v[0], v[1], v[2], v[3]);
        return 0;
    }

    list_for_each_entry(fa, &iface->addrs, list)  {
        if(*e->local == fa->addr[0])  {
            list_delete(&fa->list);
            LOG_INFO("deleted %u.%u.%u.%u from iface %s", v[0], v[1], v[2], v[3], iface->ifname);
            free(fa);
            break;
        }
    }
    return 0;
}


static void on_new_addr(fw_buck *fw, addr_entry *e)
{
    __u8 af;
    addr_entry_inet *entry = (addr_entry_inet *)e;

    if(! e)
        return;

    af = e->ifaddr->ifa_family;
    if(af != AF_INET)  {
        LOG_INFO("not supported pf %u new address", af);
        return;
    }

    __add_addr(fw, entry);
}

static void on_del_addr(fw_buck *fw, addr_entry *e)
{
    __u8 af;
    addr_entry_inet *entry = (addr_entry_inet *)e;

    if(! e)
        return;

    af = e->ifaddr->ifa_family;
    if(af != AF_INET)  {
        LOG_INFO("not supported pf %u address deletion", af);
        return;
    }

    __del_addr(fw, entry);
}

static int rtnl_handler(rtnl_msg *rtmsg, void *ud)
{
    fw_buck *fw = (fw_buck *)ud;

    switch(rtmsg->type)  {
	case RTM_NEWLINK:
        on_new_link(fw, (link_entry *)rtmsg->entry);
        break;
	case RTM_DELLINK:
        on_del_link(fw, (link_entry *)rtmsg->entry);
        break;
    case RTM_NEWADDR:
        on_new_addr(fw, (addr_entry *)rtmsg->entry);
        break;
	case RTM_DELADDR:
        on_del_addr(fw, (addr_entry *)rtmsg->entry);
    default:
        break;
    }

    LOG_RTNL(rtmsg);
    return 0;
}


static int bcast_ip(__be32 ip)
{
    fw_iface *iface;
    fw_addr *fa;

    if(ip == htonl(INADDR_BROADCAST))
        return 1;

    pthread_rwlock_rdlock(&fw_core.lock);
    list_for_each_entry(iface, &fw_core.iface_list, list)  {
        list_for_each_entry(fa, &iface->addrs, list)  {
            if(fa->pf == AF_INET)  {
                if(fa->bc[0] && fa->bc[0] == ip)  {
                    pthread_rwlock_unlock(&fw_core.lock);
                    return 1;
                }
            }
        }
    }
    pthread_rwlock_unlock(&fw_core.lock);
    return 0;
}

static inline int bcast_ip6(__be32 ip6[4])
{
    static const struct in6_addr bc6 = IN6ADDR_ANY_INIT;

    return ! memcmp(ip6, &bc6, sizeof(__be32) + 4);
}

static int nfct_filtered(nfct_msg *msg)
{
    conn_tuple src;
    conn_entry *ent = (conn_entry *)msg->entry;

    if(! ent)  {
        LOG_WARN("unrecognized nfct msg, subsys:%u, type:%u, ignored", msg->subsys, msg->type);
        return 1;
    }

    if(nfct_conn_get_src_tuple(ent, &src))  {
        LOG_WARN("fail to get src nfct tuple, subsys:%u, type:%u, ignored", msg->subsys, msg->type);
        return 1;
    }

    switch(src.src.l3num)  {
    case AF_INET:  {
        __u8 *v0 = (__u8 *)&src.src.u3.ip;
        __u8 *v1 = (__u8 *)&src.dst.u3.ip;

        if(v1[0] == IN_LOOPBACKNET)  {
            LOG_INFO("ignore AF_INET loopback nfct:%u.%u.%u.%u -> %u.%u.%u.%u",
                     v0[0], v0[1], v0[2], v0[3], v1[0], v1[1], v1[2], v1[3]);
            return 1;
        }
        if(bcast_ip(src.dst.u3.ip))  {
            LOG_INFO("ignore AF_INET bcasted nfct:%u.%u.%u.%u -> %u.%u.%u.%u",
                     v0[0], v0[1], v0[2], v0[3], v1[0], v1[1], v1[2], v1[3]);
            return 1;
        }
        break;
    }
    case AF_INET6:  {
        static const struct in6_addr lo6 = IN6ADDR_LOOPBACK_INIT;

        if(! memcmp(&lo6, src.dst.u3.ip6, sizeof(src.dst.u3.ip6)))  {
            LOG_INFO("ignore AF_INET6 loopback nfct");
            return 1;
        }
        if(bcast_ip6(src.dst.u3.ip6))  {
            LOG_INFO("ignore AF_INET6 bcasted nfct");
            return 1;
        }
        break;
    }
    default:
        LOG_WARN("unsupported nfct protocol family %u, ignored", src.src.l3num);
        return 1;
    }

    return 0;
}

static int nfct_handler(nfct_t *ct, nfct_msg *msg, void *ud)
{
    sk_entry *sk;
    list fos = LIST_HEAD_INIT(fos);

    if(! nfct_filtered(msg))  {
        /* fw table rely on IPCTNL_MSG_CT_DELETE to do GC */
        if(((sk = lookup_sk_from_ct(msg)) && ! lookup_fos_from_sk(&fos, sk))
           || (msg->type == IPCTNL_MSG_CT_DELETE))
            fw_table_conn_changed(msg, sk, &fos);
        __LOG_CONNTRACK(msg, &fos);
        if(sk)
            sk_entry_free(sk);
        fd_owners_free(&fos);
    }
    return 0;
}

static void uevent_log(uevent_msg *msg, void *ud)
{
    LOG_UEVENT(msg);
}

static void verdict_pkt(fw_obj *obj, void *ud)
{
    fd_owner *fo;
    list *head;
    int err;

    if((err = cactus_be_send_verdict(obj)))
        LOG_ERROR("fail to send verdict request:%d", err);

    head = obj->fos;
    list_for_each_entry(fo, head, list)  {
        LOG_INFO("request verdict for %" PRIu64 " pid:%u uid:%u exe:\"%s\"",
                 obj->id, fo->pid, fo->euid, fo->exe);
    }
}

static void verdict_res(__u64 rid, void *ctx, int verd, void *ud)
{
    if(ctx)  {
        switch(verd)  {
        case VERDICT_ALLOW_ONCE:
        case VERDICT_ALLOW_ALWAYS:
            nfqm_pop((nfqm *)ctx, rid, NF_ACCEPT, 0);
            break;
        case VERDICT_NONE:
        case VERDICT_QUERY:
        case VERDICT_DENY_ONCE:
        case VERDICT_DENY_ALWAYS:
        case VERDICT_KILL_ONCE:
        case VERDICT_KILL_ALWAYS:
        default:
            nfqm_pop((nfqm *)ctx, rid, NF_DROP, 0);
            break;
        }
    }
}

static int record_execution(const char *cmd)
{
    FILE *fp;
    char *buf = NULL;
    size_t sz = 0;
    int err;

    if((fp = popen(cmd, "re")))  {
        LOG_INFO("command execution begin:\"%s\"", cmd);
        for(;;)  {
            err = getline(&buf, &sz, fp);
            if(err <= 0)
                break;
            /* overwrite '\n' */
            buf[strlen(buf) - 1] = '\0';
            LOG_INFO("%s", buf);
        }
        LOG_INFO("command execution end");
        if(buf)
            free(buf);
        return pclose(fp);
    }
    return -1;
}

int core_start(void)
{
    fw_buck *fw = &fw_core;
    const nfq_parm *parm = fw->queue_parm;
    int i, flg;

    if(! fw->initialized)  {
        LOG_ERROR("refuse to start uninitialized Cactus Runtime");
        return -1;
    }

    for(i = 0; i < NUM_QUEUE; i++, parm++)  {
        if(nfq_create(&fw->nfq[i], parm))  {
            LOG_ERROR("fail to create pkt queue %u", parm->queue_num);
            goto fail_cleanup;
        }
        flg = 0;
        if(parm->queue_num == QUEUE_NUM_TCP_OUT
           || parm->queue_num == QUEUE_NUM_PKT_IN)
            flg = NFQM_F_TCP_CHECK;
        if(! (fw->nfqm[i] = nfqm_create(flg, fw->nfq[i], parm->max_len)))  {
            LOG_ERROR("fail create nfqm to nfq %u", parm->queue_num);
            goto fail_cleanup;
        }
    }

    for(i = 0; i < NUM_QUEUE; i++)  {
        if(nfq_start(fw->nfq[i],  NFQ_F_THREAD))  {
            LOG_ERROR("fail to start queue %u", i);
            goto fail_cleanup;
        }
    }

    LOG_INFO("loading init rules from \"%s\"", CONFIG_RULE_PATH);
    if(rule_install(CONFIG_RULE_PATH))
        LOG_WARN("fail to load init rules, continue.");

    record_execution("iptables -L -n 2>&1");
    record_execution("iptables -L -n -t nat 2>&1");

    if(__core_status == CORE_INIT)  {
        LOG_INFO("init purging cactus fw rules");
        core_deactivate();
    }

    /* all done, register back-end service */
    if(cactus_be_init())  {
        LOG_ERROR("fail to register core msg handler");
        core_abort();
    }
    core_set_status(CACTUS_ST_AVAILABLE);

    return 0;

 fail_cleanup:
    for(i = 0; i < NUM_QUEUE; i++)  {
        if(fw->nfqm[i])  {
            nfqm_destroy(fw->nfqm[i], NF_DROP, 0);
            fw->nfqm[i] = NULL;
        }
        if(fw->nfq[i])  {
            nfq_destroy(fw->nfq[i]);
            fw->nfq[i] = NULL;
        }
    }
    return -1;
}

static int __addrs_init(fw_buck *fw)
{
    list addrs;
    rtnl_msg *msg;
    addr_entry_inet *entry;

    if(list_empty(&fw->iface_list))  {
        LOG_WARN("no external interface");
        return 0;
    }

    /**
     * FIXME: suppport AF_INET only currently
     */
    if(rtnl_dump_addr(&addrs, AF_INET))  {
        LOG_ERROR("fail to dump addrs");
        return -1;
    }

    list_for_each_rtnl_msg(msg, &addrs)  {
        if(! (entry = (addr_entry_inet *)msg->entry))  {
            LOG_WARN("suspicious NULL entry of addr msg");
            continue;
        }

        if(__add_addr(fw, entry))  {
            rtnl_msg_list_free(&addrs);
            return -1;
        }
    }list_end;

    rtnl_msg_list_free(&addrs);

    return 0;
}

static int __links_init(fw_buck *fw)
{
    list links;
    link_entry *entry;
    fw_iface *iface;
    rtnl_msg *msg;
    int flags;

    list_init(&fw->iface_list);
    list_init(&fw->white_list);

    if(rtnl_dump_link(&links, 0))  {
        LOG_ERROR("fail to dump links");
        return -1;
    }

    list_for_each_rtnl_msg(msg, &links)  {
        if(! (entry = (link_entry *)msg->entry))  {
            LOG_WARN("suspicious NULL link entry");
            continue;
        }

        if(! instantiate(iface))  {
            LOG_ERROR("OOM instantiate fw iface");
            rtnl_msg_list_free(&links);
            return -1;
        }

        list_init(&iface->list);
        list_init(&iface->addrs);

        iface->ifindex = entry->ifinfo->ifi_index;
        if(! (iface->ifname = strdup(entry->ifname)))  {
            LOG_ERROR("OOM strdup ifname");
            rtnl_msg_list_free(&links);
            return -1;
        }

        iface->flags = 0;

        flags = entry->ifinfo->ifi_flags;
        if(! (flags & IFF_LOOPBACK))
            iface->flags = IFACE_F_GUARD;

        list_append(&fw->iface_list, &iface->list);
    }list_end;
    rtnl_msg_list_free(&links);

    return 0;
}

static int setup_signals(void)
{
    int idx, sigs[] = {
        SIGHUP, SIGINT, SIGQUIT, SIGPIPE, SIGTERM,
        SIGTTIN, SIGTTOU, SIGUSR1, SIGUSR2, SIGPIPE,
        SIGALRM,
    };

    /* we user SIGUSR1 to triger SIGSEGV, and debug sys with dump
       stack info */
    sigemptyset(&__sig_mask);
    for(idx = 0; idx < (int)arraysize(sigs); idx++)
        sigaddset(&__sig_mask, sigs[idx]);
    return pthread_sigmask(SIG_BLOCK, &__sig_mask, NULL);
}

static int pid_lock_init(const char *file)
{
    static int lock_fd = -1;
    pid_t pid = getpid();
    struct flock lock;
    char s_pid[20];
    int fd, len;
    mode_t mode;

    if(lock_fd >= 0)  {
        PR_ERROR("pid lock held already");
        return -1;
    }

    mode = umask(S_IRGRP | S_IROTH);
    fd = open(file, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    /* restore incase different */
    umask(mode);
    if(fd < 0)  {
        PR_ERROR("Error open pid lock file:%d(%s)", errno, strerror(errno));
        return -1;
    }

    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    lock.l_start = 0;
    len = sprintf(s_pid, "%u\n", pid);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    if(! fcntl(fd, F_SETLK, &lock)
       && ! ftruncate(fd, 0)
       && write(fd, s_pid, len) == len)  {
        lock_fd = fd;
        return 0;
    }
    close(fd);
    return -1;
}

/**
 * Cactus depends haveayly on linux proc fs, just make sure it's
 * properly mounted.
 */
static void assert_procfs(void)
{
    struct statfs buf;

    if(statfs("/proc", &buf) < 0)  {
        LOG_FATAL("fail to statfs /proc:%d(%s), abort!", errno, strerror(errno));
        core_abort();
    }

    if(buf.f_type != PROC_SUPER_MAGIC)  {
        LOG_FATAL("/proc is not mounted proc fs, abort!");
        core_abort();
    }
    LOG_INFO("check /proc mounted proc OK");
}

/**
 * most distributions don't have ip_conntrack module loaded by
 * default.
 */
static void kmod_init(void)
{
    FILE *fp = fopen("/proc/modules", "r");
    char *line = NULL, *delim;
    char cmd[100];
    size_t len;
    int err, i;

    for(;;)  {
        err = getline(&line, &len, fp);
        if((delim = strchr(line, ' ')))
            *delim = '\0';
        for(i = 0; i < (int)arraysize(modules_autoload); i++)  {
            if(! strcmp(modules_autoload[i].name, line))  {
                modules_autoload[i].stat = 1;
                break;
            }
        }
        if(err < 0)
            break;
    }

    for(i = 0; i < (int)arraysize(modules_autoload); i++)  {
        if(! modules_autoload[i].stat)  {
            LOG_INFO("try loading kernel module \"%s\"", modules_autoload[i].name);
            sprintf(cmd, "modprobe %s", modules_autoload[i].name);
            if(system(cmd))
                LOG_WARN("fail to execute \"%s\", some function may *NOT* be available", cmd);
        }
    }
    if(line)
        free(line);
    fclose(fp);
}

static const fw_cb verd_cbs = {
    .verdict_req = verdict_pkt,
    .verdict_res = verdict_res,
    .req_ud = NULL,
    .res_ud = NULL,
};

static const char *cactus_stat[] = {
    "UNAVAILABLE", "AVAILABLE",
};

static void core_set_status(int st)
{
    int fd, len;
    struct stat stat;
    mode_t m_sav;
    mode_t m = S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH;

    /* make sure others can read */
    m_sav = umask(S_IRGRP | S_IROTH);
    fd = open(CONFIG_STAT_PATH, O_RDWR | O_CREAT, m);
    /* restore incase different */
    umask(m_sav);
    if(fd < 0)  {
        LOG_ERROR("error open cactus state file:%d(%s)", errno, strerror(errno));
        return;
    }

    if(fstat(fd, &stat))  {
        LOG_ERROR("error fstat cactus state file:%d(%s)", errno, strerror(errno));
        close(fd);
        return;
    }

    /* change to the expected mode */
    if((stat.st_mode != m) && fchmod(fd, m))  {
        LOG_ERROR("error fchmod cactus state file:%d(%s)", errno, strerror(errno));
        close(fd);
        return;
    }

    len = strlen(cactus_stat[st]) + 1;
    if(! ftruncate(fd, 0)
       && write(fd, cactus_stat[st], len) == len)
        LOG_INFO("signaled cactus state to \"%s\"", cactus_stat[st]);
    else
        LOG_WARN("fail to signal cactus state to \"%s\"", cactus_stat[st]);
    close(fd);
}

/* NOTE: initialization sequence dependent */
static void __core_init(fw_buck *fw)
{
    struct utsname buf;

    BZERO(fw);
    fw->queue_parm = queue_parm;
    pthread_rwlock_init(&fw->lock, NULL);

    if(cactus_log_init())  {
        PR_ERROR("fail to init cactus log");
        core_abort();
    }

    LOG_INFO("initializing Cactus Runtime %s", VERSION);
    if(! uname(&buf))
        LOG_INFO("UTSNAME:\"%s %s %s %s %s\"",
                 buf.sysname, buf.nodename, buf.release, buf.version, buf.machine);

    assert_procfs();

    if(kconf_init_check(0))  {
        LOG_ERROR("kconf check unsatisfied");
        core_abort();
    }

    kmod_init();

    if(msg_server_init())  {
        LOG_ERROR("fail to init msg server");
        core_abort();
    }

    if(ginkgo_create(&fw->ginkgo, 0))  {
        LOG_ERROR("fail to create ginkgo");
        core_abort();
    }

    if(ginkgo_run(fw->ginkgo))  {
        LOG_ERROR("fail to run ginkgo");
        core_abort();
    }

    if(timer_initialize(0))  {
        LOG_ERROR("fail to init timer");
        core_abort();
    }

    if(async_bus_init())  {
        LOG_ERROR("fail to init async bus");
        core_abort();
    }

    if(sock_stat_init(fw->ginkgo))  {
        LOG_ERROR("fail to init sock stat");
        core_abort();
    }

    if(! (fw->ct = nfct_create(fw->ginkgo,
                               NFCT_GRP_NEW | NFCT_GRP_UPDATE | NFCT_GRP_DESTROY,
                               nfct_handler, (void *)fw)))  {
        LOG_ERROR("fail to create nfct");
        core_abort();
    }

    /* nfct events must be supported */
    if(nfct_event_get_enabled() <= 0 && nfct_event_set_enabled(1) <= 0)  {
        LOG_ERROR("unable to enable nfct event support");
        core_abort();
    }

    if(rtnl_init(fw->ginkgo, rtnl_handler, (void *)fw))  {
        LOG_ERROR("fail to init rtnl");
        core_abort();
    }

    if(uevent_init(fw->ginkgo))  {
        LOG_ERROR("fail to init uevent");
        core_abort();
    }

    if(uevent_register_handler(&uevent_handler_desc))  {
        LOG_ERROR("fail to register uevent handler");
        core_abort();
    }

    if(fw_table_init(&verd_cbs, fw->ct, 0))  {
        LOG_ERROR("fail to init fw table");
        core_abort();
    }

    pthread_rwlock_wrlock(&fw->lock);
    if(__links_init(fw))  {
        LOG_ERROR("fail to init fw links");
        core_abort();
    }

    if(__addrs_init(fw))  {
        LOG_ERROR("fail to init fw addrs");
        core_abort();
    }
    pthread_rwlock_unlock(&fw->lock);

    /* cactus be will register sig handlers at init*/
    if(sig_handle_init(fw->ginkgo, &__sig_mask))  {
        LOG_ERROR("fail to init sig handle");
        core_abort();
    }

    fw->initialized = 1;
    LOG_INFO("Cactus Runtime initialized!");
}

int core_init(void)
{
    if(! fw_core.initialized)  {
        /* must be root currently */
        if(geteuid())  {
            PR_ERROR("Must be root to init Cactus Core!");
            return -1;
        }

        if(pid_lock_init(CONFIG_PID_LOCK))  {
            PR_ERROR("Unable to init pid lock, another instance runing?");
            return -1;
        }

        if(setup_signals())
            return -1;

        __core_init(&fw_core);
    }
    return 0;
}

static const char *nfq_activate[] = {
    "iptables -I INPUT 1 -t filter -p all -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_PKT_IN),
    "iptables -I OUTPUT 1 -t filter -p all -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_OTHER_OUT),
    "iptables -I OUTPUT 1 -t filter -p udp -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_UDP_OUT),
    "iptables -I OUTPUT 1 -t filter -p tcp -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_TCP_OUT),
    "iptables -I INPUT 1 -t filter -p all -m connmark --mark 0xFFFFFFFF -j DROP",
    /* by pass loopback packets */
    "iptables -I OUTPUT 1 -d localhost -j ACCEPT",
    "iptables -I INPUT 1 -s localhost -j ACCEPT",
    NULL,
};

static const char *nfq_deactivate[] = {
    "iptables -D INPUT -t filter -p all -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_PKT_IN),
    "iptables -D OUTPUT -t filter -p all -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_OTHER_OUT),
    "iptables -D OUTPUT -t filter -p udp -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_UDP_OUT),
    "iptables -D OUTPUT -t filter -p tcp -m state --state NEW -j NFQUEUE --queue-num " __stringify(QUEUE_NUM_TCP_OUT),
    "iptables -D INPUT -t filter -p all -m connmark --mark 0xFFFFFFFF -j DROP",
    /* by pass loopback packets */
    "iptables -D OUTPUT -d localhost -j ACCEPT",
    "iptables -D INPUT -s localhost -j ACCEPT",
    NULL,
};


void core_deactivate(void)
{
    const char **p = nfq_deactivate;
    int err;

    if(__core_status != CORE_INACTIVE)  {
        while(*p)  {
            if((err = system(*p)))
                LOG_INFO("fail to execute liberate command \"%s\":%d, ignored", *p, err);
            p++;
        }
        __core_status = CORE_INACTIVE;
        LOG_INFO("Cactus core deactivated");
        CACTUS_BE_MSG("Cactus Runtime Deactivated!");
    }
}

int core_activate(void)
{
    const char **p = nfq_activate;
    int err;

    if(__core_status != CORE_ACTIVE)  {
        while(*p)  {
            if((err = system(*p)))  {
                LOG_ERROR("fail to execute unthrottle cmd \"%s\":%d", *p, err);
                LOG_INFO("fallback to deactivate Cactus");
                core_deactivate();
                return -1;
            }
            p++;
        }
        __core_status = CORE_ACTIVE;
        LOG_INFO("Cactus core activated");
        CACTUS_BE_MSG("Cactus Runtime Activated!");
    }
    return 0;
}

int core_status(void)
{
    return __core_status;
}

int core_nfct_filtered(nfct_msg *msg)
{
    return nfct_filtered(msg);
}

nfct_t *core_nfct(void)
{
    return fw_core.ct;
}

void __attribute__((noreturn)) core_exit(int err)
{
    LOG_INFO("back sync rule list to \"%s\"", CONFIG_RULE_PATH);
    if(! mkpath(CONFIG_RULE_DIR))  {
        if(rule_dump(CONFIG_RULE_PATH))
            LOG_ERROR("fail to back syn rule list to \"%s\"", CONFIG_RULE_PATH);
    }
    if(__core_status == CORE_ACTIVE)  {
        LOG_INFO("purging fw rules at quit");
        core_deactivate();
    }
    core_set_status(CACTUS_ST_UNAVAILABLE);
    /* implicit dropped all nfqm pkts in queue */
    cactus_log_fini();
    msg_server_quit();
    exit(err);
}

