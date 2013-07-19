/*
 * nfq.c
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
#include <assert.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/netfilter/nfnetlink.h>

#include "linux_netfilter_nfnetlink_queue.h"

#include "util.h"
#include "nl.h"
#include "nfq.h"
#include "cactus_log.h"

#define DEFAULT_BUF_SIZE (1024 * 8)
#define BUF_SIZE_INCREMENTAL 512

struct _nfq_queue{
    __u16 queue_num;
    __u16 pf;
    __u8 copy_mode;
    __u32 copy_range;
    __u32 max_len;
    nfq_handler handler;
    void *ud;
    pthread_t thread;
    int quit;
    int started;
    int pipe[2];
    int fd;
    struct nlmsghdr *nlh;
    size_t sz;
    size_t len;
    void *buf;
    size_t verd_sz;
    size_t verd_mark_sz;
    struct nlmsghdr *verd_nlh;
    struct nfqnl_msg_verdict_hdr *verd_hdr;
    __be32 *mark;

};

static __u32 __nfq_seq = 1;

static struct nlmsghdr *nfq_get_msg(nfq_queue *q, int peek)
{
    struct nlmsghdr *nlh = q->nlh;
    void *buf;
    int res;

    if(nlh)  {
        nlh = NLMSG_NEXT(nlh, q->len);
        memmove(q->buf, nlh, q->len);
        q->nlh = NULL;
    }
    nlh = (struct nlmsghdr *)q->buf;

    for(;;)  {
        if(NLMSG_OK(nlh, q->len))  {
            q->nlh = nlh;
            return nlh;
        }

        if(q->sz - q->len < BUF_SIZE_INCREMENTAL)  {
            if(! (buf = realloc(q->buf, q->sz + BUF_SIZE_INCREMENTAL)))
                return NULL;
            q->buf = buf;
            q->sz += BUF_SIZE_INCREMENTAL;
        }

        for(;;)  {
            res = recv(q->fd, (char *)q->buf + q->len, q->sz - q->len, peek ? MSG_DONTWAIT : 0);
            if(res < 0)  {
                if(errno == EINTR)
                    continue;
                return NULL;
            }
            q->len += res;
            break;
        }
    }
}


static inline int nfq_write(int fd, void *dat, size_t len)
{
    int wr = 0, res;

    do{
        res = write(fd, (char *)dat + wr, len - wr);
        if(res < 0)  {
            if((errno == EINTR))
                continue;
            return -1;
        }
        wr += res;
    }while((size_t)wr < len);
    return 0;
}

static int nfq_talk(nfq_queue *q, struct nlmsghdr *nlm, size_t len)
{
    struct nlmsghdr *rsp;
    __u32 seq = nlm->nlmsg_seq;

    if(nfq_write(q->fd, nlm, len))  {
        free(nlm);
        return -1;
    }

    free(nlm);
    for(;;)  {
        if((rsp = nfq_get_msg(q, 0)))  {
            if(rsp->nlmsg_seq != seq || rsp->nlmsg_type != NLMSG_ERROR)  {
                LOG_WARN("garbage messages from nfq");
                continue;
            }
            return ((struct nlmsgerr *)NLMSG_DATA(rsp))->error;
        }
    }
}

static int create_queue(nfq_queue *q)
{
    struct nlmsghdr *nlm;
    struct nfgenmsg nfgen;
    struct nfqnl_msg_config_cmd cmd;
    struct nfqnl_msg_config_params parm;
    size_t sz;
    void *ctx;
    int err;

    sz = nlmsg_total_size(NLMSG_ALIGN(sizeof(nfgen))
                          + nla_total_size(sizeof(cmd))
                          + nla_total_size(sizeof(parm))
                          + nla_total_size(sizeof(__u32)));

    if(! (nlm = (struct nlmsghdr *)malloc(sz)))
        return -1;

    ctx = NLMSG_DATA(nlm);

    bzero(&nfgen, sizeof(nfgen));
    nfgen.nfgen_family = AF_UNSPEC;
    nfgen.version = NFNETLINK_V0;
    nfgen.res_id = htons(q->queue_num);

    bzero(&cmd, sizeof(cmd));
    cmd.command = NFQNL_CFG_CMD_BIND;
    cmd.pf = htons(q->pf);

    bzero(&parm, sizeof(parm));
    parm.copy_range = htonl(q->copy_range);
    parm.copy_mode = q->copy_mode;

    nlm->nlmsg_len = sz;
    nlm->nlmsg_type = ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG);
    nlm->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlm->nlmsg_seq = __nfq_seq++;
    nlm->nlmsg_pid = 0;

    nlmsg_put_mem(&ctx, &nfgen, sizeof(nfgen));
    memcpy(nla_reserve(&ctx, NFQA_CFG_CMD, sizeof(cmd)), &cmd, sizeof(cmd));
    memcpy(nla_reserve(&ctx, NFQA_CFG_PARAMS, sizeof(parm)), &parm, sizeof(parm));
    nla_put_be32(&ctx, NFQA_CFG_QUEUE_MAXLEN, htonl(q->max_len));

    if((err = nfq_talk(q, nlm, sz)))
       return err;

    sz = nlmsg_total_size(NLMSG_ALIGN(sizeof(nfgen))
                          + nla_total_size(sizeof(cmd)));

    if(! (nlm = (struct nlmsghdr *)malloc(sz)))
        return -1;

    ctx = NLMSG_DATA(nlm);

    cmd.command = NFQNL_CFG_CMD_PF_BIND;

    nlm->nlmsg_len = sz;
    nlm->nlmsg_type = ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_CONFIG);
    nlm->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlm->nlmsg_seq = __nfq_seq++;
    nlm->nlmsg_pid = 0;

    nlmsg_put_mem(&ctx, &nfgen, sizeof(nfgen));
    memcpy(nla_reserve(&ctx, NFQA_CFG_CMD, sizeof(cmd)), &cmd, sizeof(cmd));
    err = nfq_talk(q, nlm, sz);
    /* return success if already binded */
    if(err == -EEXIST)
        err = 0;
    return err;
}

int nfq_create(nfq_queue **q, const nfq_parm *parm)
{
    nfq_queue *nfq = NULL;
    int fd;

    if( ! q || ! parm
       || parm->copy_mode > NFQNL_COPY_PACKET
       || ! parm->handler)
        return -1;

    if((fd = nl_open(NETLINK_NETFILTER, 0)) < 0)
        return -1;

    if(! instantiate(nfq))
        goto err_cleanup;

    BZERO(nfq);
    nfq->queue_num = parm->queue_num;
    nfq->pf = parm->pf;
    nfq->copy_mode = parm->copy_mode;
    nfq->copy_range = parm->copy_range;
    nfq->max_len = parm->max_len;
    nfq->handler = parm->handler;
    nfq->ud = parm->ud;

    nfq->quit = 0;
    nfq->started = 0;
    if(pipe2(nfq->pipe, O_NONBLOCK) < 0)
        goto err_cleanup;

    nfq->fd = fd;
    nfq->nlh = NULL;
    nfq->sz = DEFAULT_BUF_SIZE;
    nfq->len = 0;
    if(! (nfq->buf = malloc(DEFAULT_BUF_SIZE)))
        goto err_cleanup;

    if(create_queue(nfq))
        goto err_cleanup;

    *q = nfq;
    return 0;


 err_cleanup:
    if(nfq)  {
        if(nfq->buf)
            free(nfq->buf);
        if(nfq->pipe[0])  {
            close(nfq->pipe[0]);
            close(nfq->pipe[1]);
        }
        if(nfq->fd)
            close(nfq->fd);
        free(nfq);
    }
    return -1;
}

static int parse_attr(struct rtattr *attr[], int max, struct rtattr *rta, int len)
{
    memset(attr, 0, sizeof(struct rtattr *) * (max + 1));
    while(RTA_OK(rta, len))  {
        if(rta->rta_type <= max && ! attr[rta->rta_type])
            attr[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
    if(len)
        LOG_WARN("!!!rtattr type %d len %d, but %d", rta->rta_type, rta->rta_len, len);
    return 0;
}


static inline int handle_msg(nfq_queue *q, struct nlmsghdr *nlm)
{
    struct nfgenmsg *nfgen = (struct nfgenmsg *)NLMSG_DATA(nlm);
    struct rtattr *attr[NFQA_MAX + 1];
    struct rtattr *rta = (struct rtattr *)((char *)nfgen + NLMSG_ALIGN(sizeof(*nfgen)));
    int rta_len = NLMSG_PAYLOAD(nlm, sizeof(*nfgen));

    if(nlm->nlmsg_type == ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_PACKET))  {
        parse_attr(attr, NFQA_MAX, rta, rta_len);
        return q->handler(q, nfgen, (struct nlattr **)attr, q->ud);
    }
    LOG_WARN("Unexpected message %d receveid in nfq %d", nlm->nlmsg_type, q->queue_num);
    return 1;
}

static int __nfq_loop(nfq_queue *q)
{
    fd_set rd;
    int triger = q->pipe[0];
    int n, nfds = MAX(q->fd, triger) + 1;
    struct nlmsghdr *nlm;
    char buf[20];

    FD_ZERO(&rd);
    FD_SET(q->fd, &rd);
    FD_SET(q->pipe[0], &rd);

    for(;;)  {
        while((n = select(nfds, &rd, NULL, NULL, NULL)) <= 0);
        if(q->quit)
            break;

        if(FD_ISSET(triger, &rd))
            while(read(q->pipe[0], buf, sizeof(buf)) > 0);

        if((nlm = nfq_get_msg(q, 1)))  {
            if(! handle_msg(q, nlm))
                break;
        }
    }
    q->started = 0;
    LOG_INFO("nfq %h handler exit", q->queue_num);
    return 0;
}

static void *nfq_loop(void *arg)
{
    nfq_queue *q = (nfq_queue *)arg;
    char comm[16];

    snprintf(comm, sizeof(comm), "nfq%u", q->queue_num);
    prctl(PR_SET_NAME, (unsigned long)comm, 0, 0, 0);

    __nfq_loop(q);
    return NULL;
}

int nfq_start(nfq_queue *q, int flags)
{
    if(q->started)  return 0;

    q->quit = 0;
    if(! (flags & NFQ_F_THREAD))  {
        q->started = 1;
        return __nfq_loop(q);
    }

    if(pthread_create(&q->thread, NULL, nfq_loop, q))
        return -1;

    q->started = 1;
    LOG_INFO("nfq %d started", q->queue_num);
    return 0;
}

int nfq_verdict(nfq_queue *q, __be32 id, int verdict, __u32 mark)
{
    struct nlmsghdr *nlh = q->verd_nlh;
    size_t sz;

    if(! nlh)  {
        struct nlattr *nla;
        struct nfgenmsg *nfgen;

        sz = nlmsg_total_size(NLMSG_ALIGN(sizeof(struct nfgenmsg))
                              + nla_total_size(sizeof(struct nfqnl_msg_verdict_hdr))
                              + nla_total_size(sizeof(__be32)));

        if(! (nlh = (struct nlmsghdr *)malloc(sz)))
            return -1;

        nlh->nlmsg_type = ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT);
        nlh->nlmsg_flags = NLM_F_REQUEST; /* neglect echo here */
        nlh->nlmsg_pid = 0;

        nfgen = (struct nfgenmsg *)NLMSG_DATA(nlh);
        nfgen->nfgen_family = AF_UNSPEC;
        nfgen->version = NFNETLINK_V0;
        nfgen->res_id = htons(q->queue_num);

        q->verd_sz = nlmsg_total_size(NLMSG_ALIGN(sizeof(struct nfgenmsg))
                                      + nla_total_size(sizeof(struct nfqnl_msg_verdict_hdr)));
        q->verd_mark_sz = sz;
        q->verd_nlh = nlh;

        nla = (struct nlattr *)((char *)nfgen + NLMSG_ALIGN(sizeof(struct nfgenmsg)));
        nla->nla_type = NFQA_VERDICT_HDR;
        nla->nla_len = nla_total_size(sizeof(struct nfqnl_msg_verdict_hdr));
        q->verd_hdr = (struct nfqnl_msg_verdict_hdr *)RTA_DATA(nla);

        nla = (struct nlattr *)((char *)nla + RTA_ALIGN(nla->nla_len));
        q->mark = (__be32 *)RTA_DATA(nla);
    }
    sz = (mark ? q->verd_mark_sz : q->verd_sz);
    nlh->nlmsg_len = sz;
    nlh->nlmsg_seq = __nfq_seq++;
    q->verd_hdr->verdict = htonl(verdict);
    q->verd_hdr->id = id;
    if(mark) *q->mark = htonl(mark);
    return nfq_write(q->fd, q->verd_nlh, sz);
}

int nfq_verdict_r(nfq_queue *q, __be32 id, int verdict, __u32 mark)
{
    struct nlmsghdr *nlm;
    struct nfgenmsg nfgen;
    struct nfqnl_msg_verdict_hdr verd;
    size_t sz;
    void *ctx;

    sz = nlmsg_total_size(NLMSG_ALIGN(sizeof(struct nfgenmsg))
                          + nla_total_size(sizeof(struct nfqnl_msg_verdict_hdr))
                          + (mark ? nla_total_size(sizeof(__be32)) : 0));

    if(! (nlm = (struct nlmsghdr *)alloca(sz)))
        return -1;

    ctx = NLMSG_DATA(nlm);

    bzero(&nfgen, sizeof(nfgen));
    nfgen.nfgen_family = AF_UNSPEC;
    nfgen.version = NFNETLINK_V0;
    nfgen.res_id = htons(q->queue_num);

    bzero(&verd, sizeof(verd));
    verd.verdict = htonl(verdict);
    verd.id = id;

    nlm->nlmsg_len = sz;
    nlm->nlmsg_type = ((NFNL_SUBSYS_QUEUE << 8) | NFQNL_MSG_VERDICT);
    nlm->nlmsg_flags = NLM_F_REQUEST;
    nlm->nlmsg_seq = __nfq_seq++;
    nlm->nlmsg_pid = 0;

    nlmsg_put_mem(&ctx, &nfgen, sizeof(nfgen));
    memcpy(nla_reserve(&ctx, NFQA_VERDICT_HDR, sizeof(verd)), &verd, sizeof(verd));
    if(mark)    nla_put_be32(&ctx, NFQA_MARK, htonl(mark));

    return nfq_write(q->fd, nlm, sz);
}

int nfq_destroy(nfq_queue *q)
{
    if(q->started)  {
        q->quit = 1;
        write(q->pipe[1], "BYEBYE", strlen("BYEBYE"));
        pthread_join(q->thread, NULL);
        assert(! q->started);
    }
    /* do not unbind pf in case other nfq still running */
    close(q->fd);
    close(q->pipe[0]);
    close(q->pipe[1]);
    if(q->buf)
        free(q->buf);
    if(q->verd_nlh)
        free(q->verd_nlh);
    free(q);
    return 0;
}

