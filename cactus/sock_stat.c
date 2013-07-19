/*
 * sock_stat.c
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

#include <errno.h>
#include <stdio.h>
#include <strings.h>
#include <malloc.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/rtnetlink.h>

#include "nl.h"
#include "util.h"
#include "kconf.h"
#include "ginkgo.h"
#include "sock_stat.h"
#include "cactus_log.h"
#include "linux_inet_diag.h"
#include "linux_sock_diag.h"

static int __initialized = 0;
static int __ginkgo_id = -1;
static int __sock_stat_seq = 0;
static ginkgo_ctx *__ginkgo = NULL;

int inet_diag_v2 = 0;
int inet_diag_v2_udp = 0;

static int inet_diag_handler(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud)
{
    /* discard all unsolicited messaged */
    return 0;
}

/**
 * ref. old inet diag kernel impl.
 * static int inet_diag_rcv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
 * {
 *     int hdrlen = sizeof(struct inet_diag_req);
 * 
 *     if (nlh->nlmsg_type >= INET_DIAG_GETSOCK_MAX ||
 *         nlmsg_len(nlh) < hdrlen)
 *         return -EINVAL;
 *     ... ...
 * }
 */
static void inet_diag_v2_check(void)
{
    struct inet_diag_req_v2 req = {
        .sdiag_family = AF_INET,
        .sdiag_protocol = IPPROTO_TCP,
        .idiag_ext = 0,
        .pad = 0,
        .idiag_states = 0,
        .id = {
            .idiag_sport = htons(1234),
            .idiag_dport = htons(1234),
            .idiag_src = {
                0, 0, 0, 0,
            },
            .idiag_dst = {
                0, 0, 0, 0,
            },
            .idiag_if = 0,
            .idiag_cookie = {
                INET_DIAG_NOCOOKIE, INET_DIAG_NOCOOKIE,
            },
        },
    };
    list rsp;
    ginkgo_msg *msg, *n;
    struct nlmsghdr *nlh;
    struct nlmsgerr *err;
    int avail = 0;

    if(sizeof(struct inet_diag_req_v2) > sizeof(struct inet_diag_req))  {
        LOG_INFO("assuming sock diag v2 not supported!");
        return;
    }

    if(! (msg = alloc_req_msg_v2(&req, SOCK_DIAG_BY_FAMILY, NLM_F_REQUEST)))  {
        LOG_INFO("OOM, assuming sock diag v2 not supported!");
        return;
    }

    list_init(&rsp);
    if(ginkgo_request(__ginkgo, msg, &rsp, 1) != GINKGO_ERR_OK)  {
        LOG_WARN("fail to execute sock diag request!");
        free(msg);
        return;
    }

    avail = 1;
    list_for_each_ginkgo_msg_safe(msg, n, &rsp)  {
        list_delete(&msg->lst);

        nlh = NL_HEADER(msg);
        if(nlh->nlmsg_type == NLMSG_ERROR)  {
            err = NLMSG_DATA(nlh);
            if((err->error == -EINVAL))  {
                LOG_INFO("got EINVAL to SOCK_DIAG_BY_FAMILY, assuming sock diag v2 unavailable");
                avail = 0;
            }
        }
        free(msg);
    }
    LOG_INFO("sock diag v2 availability:%d", avail);
    if((inet_diag_v2 = avail))  {
        inet_diag_v2_udp = (kconf_get("INET_UDP_DIAG") > KCONF_N);
        LOG_INFO("sock diag v2 udp availability:%d", inet_diag_v2_udp);
    }
}

static int __sock_stat_init(ginkgo_ctx *ctx)
{
    ginkgo_src src;
    int fd;

    bzero(&src, sizeof(src));
    if((fd = nl_open(NETLINK_INET_DIAG, 0)) < 0)
        return -1;
    src.name = "sock_diag";
    src.fd = fd;
    src.pars = nl_parse;
    src.resp = nl_response;
    src.hand = inet_diag_handler;
    src.ud = (void *)&__ginkgo_id;

    if(ginkgo_src_register(ctx, &src, &__ginkgo_id, 0))  {
        close(fd);
        return -1;
    }

    __ginkgo = ctx;

    inet_diag_v2_check();
    __initialized = 1;
    return 0;
}

int sock_stat_init(ginkgo_ctx *ctx)
{
    if(! __initialized)
        return __sock_stat_init(ctx);

    return 0;
}

static sk_entry *parse_sk(ginkgo_msg *msg)
{
    struct nlmsghdr *nlh;
    struct rtattr *rta;
    sk_entry *sk = (sk_entry *)&msg->cmn;
    int len;

    nlh = NL_HEADER(msg);
    if(nlh->nlmsg_type == NLMSG_ERROR)  {
        struct nlmsgerr *err = NLMSG_DATA(nlh);
        PR_DEBUG("nlmsg error code:%d(%s)", err->error, strerror(-err->error));
    }
    if(nlh->nlmsg_type == NLMSG_DONE || nlh->nlmsg_type == NLMSG_ERROR)
        return NULL;

    bzero(sk, sizeof(sk_entry));
    if(nlh->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg)))
        return NULL;

    sk->info = NLMSG_DATA(nlh);
    len = NLMSG_PAYLOAD(nlh, sizeof(struct inet_diag_msg));
    rta = (struct rtattr *)((char *)nlh + NLMSG_SPACE(sizeof(struct inet_diag_msg)));
    while(RTA_OK(rta, len))  {
        switch(rta->rta_type)  {
        case INET_DIAG_MEMINFO:
            if(rta->rta_len < RTA_LENGTH(sizeof(struct inet_diag_meminfo)))
                break;
            sk->mem = RTA_DATA(rta);
            break;
        case INET_DIAG_INFO:
            if(rta->rta_len < RTA_LENGTH(sizeof(struct tcp_info)))
                break;
            sk->tcp = RTA_DATA(rta);
            break;
        case INET_DIAG_VEGASINFO:
            if(rta->rta_len < RTA_LENGTH(sizeof(struct tcpvegas_info)))
                break;
            sk->vegas = RTA_DATA(rta);
            break;
        case INET_DIAG_CONG:
            sk->cong = RTA_DATA(rta);
            break;
        default:
            break;
        }
        rta = RTA_NEXT(rta,len);
    }
    return sk;
}


ginkgo_msg *alloc_req_msg(const struct inet_diag_req *req, int flags)
{
    ginkgo_msg *msg = ginkgo_new_msg(__ginkgo_id, NLMSG_SPACE(sizeof(struct inet_diag_req)));
    struct nlmsghdr *hdr;

    if(msg)  {
        hdr = NL_HEADER(msg);
        hdr->nlmsg_len = NLMSG_LENGTH(sizeof(struct inet_diag_req));
        hdr->nlmsg_type = TCPDIAG_GETSOCK;
        hdr->nlmsg_flags = flags;
        hdr->nlmsg_seq = __sock_stat_seq++;
        hdr->nlmsg_pid = __ginkgo_id;
        memcpy(NLMSG_DATA(hdr), req, sizeof(struct inet_diag_req));
    }
    return msg;
}

ginkgo_msg *alloc_req_msg_v2(const struct inet_diag_req_v2 *req, int type, int flags)
{
    ginkgo_msg *msg = ginkgo_new_msg(__ginkgo_id, NLMSG_SPACE(sizeof(*req)));
    struct nlmsghdr *hdr;

    if(msg)  {
        hdr = NL_HEADER(msg);
        hdr->nlmsg_len = NLMSG_LENGTH(sizeof(*req));
        hdr->nlmsg_type = type;
        hdr->nlmsg_flags = flags;
        hdr->nlmsg_seq = __sock_stat_seq++;
        hdr->nlmsg_pid = __ginkgo_id;
        memcpy(NLMSG_DATA(hdr), req, sizeof(*req));
    }
    return msg;
}

int __sock_stat_dump(list *sks, ginkgo_msg *msg)
{
    ginkgo_msg *n;
    sk_entry *sk;
    list rsp;

    list_init(&rsp);
    if(ginkgo_request(__ginkgo, msg, &rsp, 1) != GINKGO_ERR_OK)  {
        free(msg);
        return -1;
    }

    list_init(sks);
    list_for_each_ginkgo_msg_safe(msg, n, &rsp)  {
        list_delete(&msg->lst);

        if(! (sk = parse_sk(msg)))  {
            free(msg);
            continue;
        }
        list_append(sks, sk_entry_list(sk));
    }
    return 0;
}

sk_entry *__sock_stat_get(ginkgo_msg *msg)
{
    ginkgo_msg *n;
    sk_entry *sk = NULL;
    list rsp;

    list_init(&rsp);
    if(ginkgo_request(__ginkgo, msg, &rsp, 1) != GINKGO_ERR_OK)  {
        free(msg);
        return NULL;
    }

    list_for_each_ginkgo_msg_safe(msg, n, &rsp)  {
        list_delete(&msg->lst);

        if(! (sk = parse_sk(msg)))  {
            free(msg);
            continue;
        }
        break;
    }

    list_for_each_ginkgo_msg_safe(msg, n, &rsp)  {
        list_delete(&msg->lst);
        free(msg);
    }

    return sk;
}


/**
 * NOTE:
 * we trust /proc is mounted proc filesystem, and the kernel didn't
 * change the format they write into the proc file, fix it for any
 * security threats.
 */
int sock_stat_dump_udp_from_proc(list *sks, int af, __u16 sport, __u16 dport)
{
    const char *path = ((af == AF_INET) ? "/proc/net/udp" : "/proc/net/udp6");
    char *line = NULL;
    size_t len = 0;
    FILE *fp;
    int garbage;
    int bucket, wmem, rmem;
    __be32 src[4], dst[4];
    __u32 srcp, dstp;
    __u32 stat;
    unsigned long ino, lgarbage;
    uid_t uid;
    ginkgo_msg *gmsg;
    sk_entry *sk;
    struct inet_diag_msg *msg;

    if(! sks || (af != AF_INET && af != AF_INET6))
        return -1;

    if(! (fp = fopen(path, "r")))  {
        LOG_ERROR("fail to open proc file \"%s\"", path);
        return -1;
    }

    list_init(sks);
    if(getline(&line, &len, fp) <= 0)  {
        fclose(fp);
        if(line)  free(line);
        return -1;
    }

    for(;;)  {
        if(getline(&line, &len, fp) <= 0)
            break;

        if(af == AF_INET)  {
            if(sscanf(line, "%d: %x:%x %x:%x %x %x:%x %x:%lx %x %d %d %lu", /* "%5d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu", */
                      &bucket,
                      &src[0], &srcp, &dst[0], &dstp,
                      &stat,
                      &wmem, &rmem,
                      &garbage, &lgarbage, &garbage,
                      &uid,
                      &garbage,
                      &ino) != 14)  {
                LOG_ERROR("fail to parse proc file \"%s\"", path);
                break;
            }
        }else  {
            if(sscanf(line, "%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
                      "%02X %08X:%08X %02X:%08lX %08X %5d %8d %lu",
                      &bucket,
                      &src[0], &src[1], &src[2], &src[3], &srcp,
                      &dst[0], &dst[1], &dst[2], &dst[3], &dstp,
                      &stat,
                      &wmem, &rmem,
                      &garbage, &lgarbage, &garbage,
                      &uid,
                      &garbage,
                      &ino) != 20)  {
                LOG_ERROR("fail to parse proc file \"%s\"", path);
                break;
            }
        }

        if((sport && sport != srcp) || (dport && dport != dstp))
            continue;

        if(! (gmsg = ginkgo_new_msg(0, sizeof(struct inet_diag_msg))))  {
            LOG_EMERG("OOM allog sk entry!");
            break;
        }

        sk = (sk_entry *)&gmsg->cmn;
        msg = (struct inet_diag_msg *)&gmsg->payload;
        memset(msg, 0, sizeof(*msg));

        msg->idiag_state = stat;
        msg->id.idiag_sport = htons(srcp);
        msg->id.idiag_dport = htons(dstp);
        msg->id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
        msg->id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
        msg->idiag_rqueue = rmem;
        msg->idiag_wqueue = wmem;
        msg->idiag_uid = uid;
        msg->idiag_inode = ino;
        if(af == AF_INET)  {
            msg->idiag_family = AF_INET;
            msg->id.idiag_src[0] = src[0];
            msg->id.idiag_dst[0] = dst[0];
        }else  {
            msg->idiag_family = AF_INET6;
            memcpy(msg->id.idiag_src, src, sizeof(msg->id.idiag_src));
            memcpy(msg->id.idiag_dst, dst, sizeof(msg->id.idiag_dst));
        }
        sk->info = msg;
        list_append(sks, sk_entry_list(sk));
    }
    fclose(fp);
    if(line)
        free(line);
    return 0;
}

sk_entry *sock_stat_get_udp_from_proc(__be32 src, __be32 dst, __u16 sport, __u16 dport)
{
    const char *path = "/proc/net/udp";
    char *line = NULL;
    size_t len = 0;
    FILE *fp;
    int garbage;
    int bucket, wmem, rmem;
    __be32 _src, _dst;
    __u32 srcp, dstp;
    __u32 stat;
    unsigned long ino, lgarbage;
    uid_t uid;
    ginkgo_msg *gmsg;
    sk_entry *sk = NULL;
    struct inet_diag_msg *msg;

    if(! (fp = fopen(path, "r")))  {
        LOG_ERROR("fail to open proc file \"%s\"", path);
        return NULL;
    }

    if(getline(&line, &len, fp) <= 0)  {
        fclose(fp);
        if(line)  free(line);
        return NULL;
    }

    for(;;)  {
        if(getline(&line, &len, fp) <= 0)
            break;

        if(sscanf(line, "%5d: %08X:%04X %08X:%04X %02X %08X:%08X %02X:%08lX %08X %5d %8d %lu",
                  &bucket,
                  &_src, &srcp, &_dst, &dstp,
                  &stat,
                  &wmem, &rmem,
                  &garbage, &lgarbage, &garbage,
                  &uid,
                  &garbage,
                  &ino) != 14)  {
            LOG_ERROR("fail to parse proc file \"%s\"", path);
            break;
        }

        if(src != _src || dst != _dst || srcp != sport || dstp != dport)
            continue;

        if(! (gmsg = ginkgo_new_msg(0, sizeof(struct inet_diag_msg))))  {
            LOG_EMERG("OOM allog sk entry!");
            break;
        }

        sk = (sk_entry *)&gmsg->cmn;
        msg = (struct inet_diag_msg *)&gmsg->payload;
        memset(msg, 0, sizeof(*msg));

        msg->idiag_family = AF_INET;
        msg->idiag_state = stat;
        msg->id.idiag_sport = htons(srcp);
        msg->id.idiag_dport = htons(dstp);
        msg->id.idiag_src[0] = _src;
        msg->id.idiag_dst[0] = _dst;
        msg->id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
        msg->id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
        msg->idiag_rqueue = rmem;
        msg->idiag_wqueue = wmem;
        msg->idiag_uid = uid;
        msg->idiag_inode = ino;

        sk->info = msg;
        break;
    }
    fclose(fp);
    if(line)
        free(line);
    return sk;
}

sk_entry *sock_stat_get_udp6_from_proc(__be32 *src, __be32 *dst, __u16 sport, __u16 dport)
{
    const char *path = "/proc/net/udp6";
    char *line = NULL;
    size_t len = 0;
    FILE *fp;
    int garbage;
    int bucket, wmem, rmem;
    __be32 _src[4], _dst[4];
    __u32 srcp, dstp;
    __u32 stat;
    unsigned long ino, lgarbage;
    uid_t uid;
    ginkgo_msg *gmsg;
    sk_entry *sk = NULL;
    struct inet_diag_msg *msg;

    if(! (fp = fopen(path, "r")))  {
        LOG_ERROR("fail to open proc file \"%s\"", path);
        return NULL;
    }

    if(getline(&line, &len, fp) <= 0)  {
        fclose(fp);
        if(line)  free(line);
        return NULL;
    }

    for(;;)  {
        if(getline(&line, &len, fp) <= 0)
            break;

        if(sscanf(line, "%5d: %08X%08X%08X%08X:%04X %08X%08X%08X%08X:%04X "
                  "%02X %08X:%08X %02X:%08lX %08X %5d %8d %lu",
                  &bucket,
                  &_src[0], &_src[1], &_src[2], &_src[3], &srcp,
                  &_dst[0], &_dst[1], &_dst[2], &_dst[3], &dstp,
                  &stat,
                  &wmem, &rmem,
                  &garbage, &lgarbage, &garbage,
                  &uid,
                  &garbage,
                  &ino) != 20)  {
            LOG_ERROR("fail to parse proc file \"%s\"", path);
            break;
        }

        if(memcmp(_src, src, sizeof(_src))
           || memcmp(_dst, dst, sizeof(_dst))
           || srcp != sport
           || dstp != dport)
            continue;

        if(! (gmsg = ginkgo_new_msg(0, sizeof(struct inet_diag_msg))))  {
            LOG_EMERG("OOM allog sk entry!");
            break;
        }

        sk = (sk_entry *)&gmsg->cmn;
        msg = (struct inet_diag_msg *)&gmsg->payload;
        memset(msg, 0, sizeof(*msg));

        msg->idiag_family = AF_INET6;
        msg->idiag_state = stat;
        msg->id.idiag_sport = htons(srcp);
        msg->id.idiag_dport = htons(dstp);
        memcpy(msg->id.idiag_src, _src, sizeof(msg->id.idiag_src));
        memcpy(msg->id.idiag_dst, _dst, sizeof(msg->id.idiag_dst));
        msg->id.idiag_cookie[0] = INET_DIAG_NOCOOKIE;
        msg->id.idiag_cookie[1] = INET_DIAG_NOCOOKIE;
        msg->idiag_rqueue = rmem;
        msg->idiag_wqueue = wmem;
        msg->idiag_uid = uid;
        msg->idiag_inode = ino;

        sk->info = msg;
        break;
    }
    fclose(fp);
    if(line)
        free(line);
    return sk;
}

/* to avail some malloc/free penalties */
int udp_port_opened_from_proc(__u16 port)
{
    const char *path = "/proc/net/udp";
    char *line = NULL;
    size_t len = 0;
    FILE *fp;
    __u32 srcp;
    int opened = 0;

    if(! (fp = fopen(path, "r")))  {
        LOG_ERROR("fail to open proc file \"%s\"", path);
        return -1;
    }

    if(getline(&line, &len, fp) <= 0)  {
        fclose(fp);
        if(line)  free(line);
        return -1;
    }

    for(;;)  {
        if(getline(&line, &len, fp) <= 0)
            break;

        if(sscanf(line, "%*d: %*X:%04X", &srcp) != 1)  {
            LOG_ERROR("fail to parse udp sport of proc file \"%s\"", path);
            break;
        }

        if(srcp == port)  {
            opened = 1;
            break;
        }
    }
    fclose(fp);
    if(line)
        free(line);
    return opened;
}

static void build_check(void)
{
    ginkgo_msg msg;

    build_fail_on(sizeof(sk_entry) > sizeof(msg.cmn));
}

