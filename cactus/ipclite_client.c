/*
 * IPC lite
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

#include <assert.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>

#include "ipclite.h"
#include "ipclite_priv.h"

#define IPCLITE_CLIENT_TRIGER "RABIT"

struct _ipclite_client{
    ipclite base;
    ipclite_port port;

    unsigned int peer;

    int notify[2];

    pthread_mutex_t lock;
    pthread_cond_t cond;

    pthread_t worker;
    int worker_started;
    int quit;

    fd_set rd;
    fd_set wr;
    int max_fd;

    pthread_mutex_t rd_lock;
    pthread_cond_t rd_cond;
    pthread_t rd_thread;
    int rd_quit;
    int rd_started;
    list rd_queue;
    list req_queue;

    pthread_mutex_t wait_lock;
    pthread_cond_t wait_cond;
    unsigned int wait_cnt;
    list wait_queue;
    int port_state;
};

static inline void client_lock(ipclite_client *c)
{
    pthread_mutex_lock(&c->lock);
}

static inline void client_unlock(ipclite_client *c)
{
    pthread_mutex_unlock(&c->lock);
}

static inline void rd_lock(ipclite_client *c)
{
    pthread_mutex_lock(&c->rd_lock);
}

static inline void rd_unlock(ipclite_client *c)
{
    pthread_mutex_unlock(&c->rd_lock);
}

static inline void wait_lock(ipclite_client *c)
{
    pthread_mutex_lock(&c->wait_lock);
}

static inline void wait_unlock(ipclite_client *c)
{
    pthread_mutex_unlock(&c->wait_lock);
}

static inline void repoll(ipclite_client *c)
{
    while(write(c->notify[1], IPCLITE_CLIENT_TRIGER, strlen(IPCLITE_CLIENT_TRIGER)) < 0 && errno == EAGAIN)
        ;
}

int ipclite_client_create(ipclite **c, const char *msg, int flags)
{
    ipclite_client *client;
    int pip[2];

    if(! c)
        return IPCLITE_ERR_INV;

    if(pipe2(pip, O_NONBLOCK) == -1)  {
        return IPCLITE_ERR_PIP;
    }

    if(! (client = new_instance(ipclite_client)))  {
        close(pip[0]);
        close(pip[1]);
        return IPCLITE_ERR_OOM;
    }

    client->base.type = IPCLITE_CLIENT;
    client->base.msg = ((msg && *msg) ? strdup(msg) : NULL);

    client->base.handler = NULL;
    client->base.ud = NULL;

    client->base.master = -1;
    client->base.path[0] = '\0';

    ipclite_port_init(&client->port, -1);
    client->port_state = client->port.state;

    client->peer = -1;

    client->notify[0] = pip[0];
    client->notify[1] = pip[1];

    pthread_mutex_init(&client->lock, NULL);
    pthread_cond_init(&client->cond, NULL);

    client->worker_started = 0;
    client->quit = 0;

    FD_ZERO(&client->rd);
    FD_ZERO(&client->wr);

    FD_SET(pip[0], &client->rd);
    client->max_fd = pip[0] + 1;

    pthread_mutex_init(&client->rd_lock, NULL);
    pthread_cond_init(&client->rd_cond, NULL);
    client->rd_quit = 0;
    client->rd_started = 0;
    list_init(&client->rd_queue);
    list_init(&client->req_queue);

    pthread_mutex_init(&client->wait_lock, NULL);
    pthread_cond_init(&client->wait_cond, NULL);
    client->wait_cnt = 0;
    list_init(&client->wait_queue);

    *c = (ipclite *)client;
    return IPCLITE_ERR_OK;
}

static int client_connect(ipclite_client *clt, int fd, const char *path, int flags)
{
    int ret = IPCLITE_ERR_OK, fd_flags;

    fd_flags = fcntl(fd, F_GETFL, NULL);
    if(fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) < 0)
        return IPCLITE_ERR_GEN;

    client_lock(clt);
    if(clt->base.master != -1)  {
        client_unlock(clt);
        return IPCLITE_ERR_INV;
    }

    clt->base.path[0] = '\0';
    if(path && *path)  {
        if(flags & IPCLITE_F_ABSTRACT)
            strncpy(clt->base.path + 1, path, sizeof(clt->base.path) - 1);
        else
            strncpy(clt->base.path, path, sizeof(clt->base.path));
    }

    clt->base.master = fd;
    clt->port.fd = fd;
    clt->port.state = PORT_OPENED;

    clt->port_state = PORT_OPENED;

    FD_SET(fd, &clt->rd);
    clt->max_fd = MAX(fd, clt->notify[0]) + 1;
    client_unlock(clt);

    repoll(clt);
    return ret;
}

int ipclite_client_connect(ipclite *c, const char *path, int flags)
{
    ipclite_client *clt = (ipclite_client *)c;
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    int ret, fd;

    if(! clt || clt->base.type != IPCLITE_CLIENT || ! path || ! *path)
        return IPCLITE_ERR_INV;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return IPCLITE_ERR_SCK;

    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    if(flags & IPCLITE_F_ABSTRACT)
        strncpy(addr.sun_path + 1, path, sizeof(addr.sun_path) - 1);
    else
        strncpy(addr.sun_path, path, sizeof(addr.sun_path));

    if(connect(fd, (struct sockaddr *)&addr, len) < 0)  {
        close(fd);
        return IPCLITE_ERR_CNN;
    }

    ret = client_connect(clt, fd, path, flags);
    if(ret != IPCLITE_ERR_OK)
        close(fd);
    return ret;
}

int ipclite_client_connect_ex(ipclite *c, const char *path, int flags, int timeout)
{
    ipclite_client *clt = (ipclite_client *)c;
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    int ret, elapsed, fd;

    if(! clt || clt->base.type != IPCLITE_CLIENT || ! path || ! *path)
        return IPCLITE_ERR_INV;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return IPCLITE_ERR_SCK;

    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    if(flags & IPCLITE_F_ABSTRACT)
        strncpy(addr.sun_path + 1, path, sizeof(addr.sun_path) - 1);
    else
        strncpy(addr.sun_path, path, sizeof(addr.sun_path));

    /* sorry to to have to retry here. */
    for(elapsed = 0;;)  {
        ret = connect(fd, (struct sockaddr *)&addr, len);
        if(ret < 0)  {
            if(timeout > 0 && elapsed >= timeout)  {
                close(fd);
                return IPCLITE_ERR_CNN;
            }
            elapsed += 50;
            usleep(50 * 1000);
            continue;
        }
        break;
    }

    ret = client_connect(clt, fd, path, flags);
    if(ret != IPCLITE_ERR_OK)
        close(fd);
    return ret;
}

int ipclite_client_connect_from_fd(ipclite *c, int fd, int flags)
{
    ipclite_client *clt = (ipclite_client *)c;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    return client_connect(clt, fd, NULL, flags);
}

static inline void __reject_msg(ipclite_client *clt, ipclite_msg *msg)
{
    ipclite_msg_ctl *ctl = msg_ctl(msg);

    ctl->err = IPCLITE_ERR_PER;
    if(ctl->wait)  {
        list_append(&clt->wait_queue, msg_list_ptr(msg));
    }else if(ctl->free)  {
        free(msg);
    }
}

static void __close_port(ipclite_client *clt)
{
    list *msgs = &clt->port.msgs;
    ipclite_msg *msg, *n;

    FD_CLR(clt->port.fd, &clt->rd);
    FD_CLR(clt->port.fd, &clt->wr);
    clt->max_fd = clt->notify[0] + 1;

    close(clt->base.master);
    clt->base.master = -1;
    clt->port.fd = -1;
    clt->port.state = PORT_CLOSED;
    wait_lock(clt);
    list_for_each_msg_safe(msg, n, msgs)  {
        list_delete(msg_list_ptr(msg));
        __reject_msg(clt, msg);
    }

    if(clt->port.msg)
        __reject_msg(clt, clt->port.msg);
    clt->port_state = PORT_CLOSED;
    pthread_cond_broadcast(&clt->wait_cond);
    wait_unlock(clt);

    list_init(msgs);
    clt->port.msg = NULL;
    pthread_cond_broadcast(&clt->cond);
}

int ipclite_client_disconnect(ipclite *c, int wait, int force)
{
    ipclite_client *clt = (ipclite_client *)c;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    client_lock(clt);
    while(clt->base.master != -1)  {
        if(force)  {
            __close_port(clt);
            break;
        }

        if(! list_empty(&clt->port.msgs) || ! clt->port.msg)  {
            clt->port.state = PORT_CLOSING;
        }else  {
            __close_port(clt);
            break;
        }

        if(! wait)
            break;

    wait_port:
        pthread_cond_wait(&clt->cond, &clt->lock);
        if(clt->port.state == PORT_CLOSED)
            break;
        goto wait_port;
    }
    client_unlock(clt);
    return IPCLITE_ERR_OK;
}

static inline void empty_fd(int fd)
{
    int res;
    char buf[10];

    do{
        errno = 0;
        res = read(fd, buf, strlen(IPCLITE_CLIENT_TRIGER));
    }while(res > 0 && errno != EAGAIN && errno != EWOULDBLOCK);
}

static void on_syn_msg(ipclite_client *clt, ipclite_msg_hdr *hdr)
{
    ipclite_msg *syn;
    unsigned int peer;

    peer = ((ipclite_msg_syn *)&hdr->data)->peer;
    syn = new_syn_msg(peer, clt->base.msg);

    clt->peer = peer;
    clt->port.state = PORT_OPENED;
    if(syn)
        list_insert(&clt->port.msgs, msg_list_ptr(syn));
    if(! list_empty(&clt->port.msgs) || clt->port.msg)
        FD_SET(clt->port.fd, &clt->wr);
}

static void new_msg(ipclite_client *clt, ipclite_msg_hdr *hdr)
{
    ipclite_msg *msg;
    ipclite_msg_ctl *ctl;

    if(hdr->msg == IPCLITE_MSG_SYN)
        on_syn_msg(clt, hdr);

    if(! (msg = (ipclite_msg *)malloc(hdr->len - sizeof(ipclite_msg_hdr) + sizeof(ipclite_msg))))  {
        LOGERROR("OOM duplicating message!");
        return;
    }

    ctl = msg_ctl(msg);

    list_init(&ctl->list);
    time(&ctl->stamp);
    ctl->cmmt = 0;
    ctl->wait = 0;
    ctl->free = 1;
    ctl->err = IPCLITE_ERR_OK;
    memcpy((void *)&msg->hdr, (void *)hdr, hdr->len);
    msg->hdr.peer = clt->peer;

    if(hdr->msg == IPCLITE_MSG_RSP ||
       hdr->msg == IPCLITE_MSG_RPX ||
       hdr->msg == IPCLITE_MSG_RXE)  {
        wait_lock(clt);
        assert(clt->wait_cnt >= 0);
        if(clt->wait_cnt > 0)  {
            list_append(&clt->wait_queue, msg_list_ptr(msg));
            pthread_cond_broadcast(&clt->wait_cond);
        }else  {
            LOGINFO("discard orphaned response message:%u", hdr->msg);
            free(msg);
        }
        wait_unlock(clt);
    }else  {
        rd_lock(clt);
        if(hdr->msg == IPCLITE_MSG_REQ || hdr->msg == IPCLITE_MSG_RQX)  {
            list_append(&clt->req_queue, msg_list_ptr(msg));
        }else  {
            list_append(&clt->rd_queue, msg_list_ptr(msg));
        }
        pthread_cond_broadcast(&clt->rd_cond);
        rd_unlock(clt);
    }
}

static inline void __port_closed(ipclite_client *clt)
{
    ipclite_msg *msg = new_cls_msg(clt->peer);

    if(msg)  {
        rd_lock(clt);
        list_append(&clt->rd_queue, msg_list_ptr(msg));
        pthread_cond_broadcast(&clt->rd_cond);
        rd_unlock(clt);
    }
}

static void read_msg(ipclite_client *clt)
{
    ipclite_msg_hdr *hdr;
    int len;

    do{
        len = read(clt->port.fd, clt->port.buf + clt->port.len, IPCLITE_BUF_SIZE - clt->port.len);
    }while(len < 0 && errno == EINTR);

    if((len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) || len == 0)  {
        LOGINFO("Error reading server msg, closed or error, removing.");
        __close_port(clt);

        /* send close msg only passively closed */
        __port_closed(clt);
    }

    if(len > 0)  {
        hdr = (ipclite_msg_hdr *)clt->port.buf;
        len += clt->port.len;
        while(IPCLITE_MSG_OK(hdr, len))  {
            new_msg(clt, hdr);
            hdr = IPCLITE_MSG_NEXT(hdr,len);
        }
        memmove((void *)clt->port.buf, (void *)hdr, len);
        clt->port.len = len;
    }
}

/**
 * return_value:
 * -1: client error or closed
 *  0: successfully commited
 *  1: half commited
 */
static int commit_msg(ipclite_client *clt, ipclite_msg *msg, size_t offset)
{
    ipclite_msg_ctl *ctl = msg_ctl(msg);
    list *ptr;
    int res;

    do{
        res = write(clt->port.fd, ((char *)&msg->hdr) + offset, msg->hdr.len - offset);
    }while(res < 0 && errno == EINTR);

    if(res < 0 && errno != EWOULDBLOCK && errno != EAGAIN)  {
        LOGINFO("Error writting server msg, closed or error, removing.");
        __close_port(clt);
        return -1;
    }

    if(res > 0)
        offset += res;

    if(msg->hdr.len > offset)  {
        clt->port.msg = msg;
        clt->port.msg_offset = offset;
        return 1;
    }

    ctl->cmmt = 1;
    ctl->err = IPCLITE_ERR_OK;
    if(ctl->wait)  {
        wait_lock(clt);
        ptr = msg_list_ptr(msg);
        list_append(&clt->wait_queue, ptr);
        pthread_cond_broadcast(&clt->wait_cond);
        wait_unlock(clt);
    }else if(ctl->free)  {
        free(msg);
    }

    clt->port.msg = NULL;
    clt->port.msg_offset = 0;
    return 0;
}


static void write_msg(ipclite_client *clt)
{
    ipclite_msg *msg = clt->port.msg;
    list *ptr;
    int res = 0;

    if(msg)
        res = commit_msg(clt, msg, clt->port.msg_offset);
    while(res == 0 && ! list_empty(&clt->port.msgs))  {
        ptr = clt->port.msgs.l_nxt;
        msg = list_msg(ptr);
        list_delete(ptr);
        res = commit_msg(clt, msg, 0);
    }
    if(res == 0)  {
        FD_CLR(clt->port.fd, &clt->wr);
        if(clt->port.state == PORT_CLOSING)  {
            __close_port(clt);
            pthread_cond_broadcast(&clt->cond);
        }
    }
}

static void *worker_thread(void *arg)
{
    ipclite_client *clt = (ipclite_client *)arg;
    fd_set rd, wr;
    int max_fd;

    prctl(PR_SET_NAME, (unsigned long)"ipcworker", 0, 0, 0);
    for(;;)  {
        do{
            client_lock(clt);
            rd = clt->rd;
            wr = clt->wr;
            max_fd = clt->max_fd;
            client_unlock(clt);
        }while(select(max_fd, &rd, &wr, NULL, NULL) <= 0);

        if(FD_ISSET(clt->notify[0], &rd))  {
            empty_fd(clt->notify[0]);
        }

        client_lock(clt);
        if(clt->quit)  break;

        if(FD_ISSET(clt->port.fd, &rd))  {
            read_msg(clt);
        }

        if(FD_ISSET(clt->port.fd, &wr))  {
            write_msg(clt);
        }
        client_unlock(clt);
    }

    clt->worker_started = 0;
    client_unlock(clt);
    return NULL;
}

static inline int submit_msg(ipclite_client *clt, ipclite_msg *msg)
{
    int ret = IPCLITE_ERR_PER;

    client_lock(clt);
    if(clt->port.state == PORT_OPENED || clt->port.state == PORT_OPENING)  {
        FD_SET(clt->port.fd, &clt->wr);
        list_append(&clt->port.msgs, msg_list_ptr(msg));
        repoll(clt);
        ret = IPCLITE_ERR_OK;
    }
    client_unlock(clt);
    return ret;
}

static int wait_msg(ipclite_client *clt, ipclite_msg *msg, int fr)
{
    ipclite_msg *iter, *n;
    ipclite_msg_ctl *ctl;
    int ret;

    wait_lock(clt);
    clt->wait_cnt++;
    iter = NULL;
    for(;;)  {
        while(list_empty(&clt->wait_queue))
            pthread_cond_wait(&clt->wait_cond, &clt->wait_lock);

        list_for_each_msg_safe(iter, n, &clt->wait_queue)  {
            if(iter == msg)  {
                list_delete(msg_list_ptr(iter));
                break;
            }
        }

        if(iter == msg)
            break;

        pthread_cond_wait(&clt->wait_cond, &clt->wait_lock);
    }
    clt->wait_cnt--;
    if(! clt->wait_cnt)
        pthread_cond_signal(&clt->wait_cond);

    wait_unlock(clt);

    ctl = msg_ctl(msg);
    ret = ctl->err;
    if(ctl->free || fr)
        free(msg);
    return ret;
}

static int ___on_transact(unsigned int msgid, transact_ctx *ctx,
                          int flags, const void *blob, size_t sz)
{
    ipclite_client *clt = (ipclite_client *)ctx->ipc;
    ipclite_msg *msg;
    int ret;

    if(flags & IPCLITE_RSP_SYN)  {
        char _msg[sizeof(ipclite_msg) + sz];

        msg = (ipclite_msg *)_msg;
        msg_init_ctl(msg, 1, 0);
        msg->hdr.peer = ctx->peer;
        msg->hdr.id = ctx->id;
        msg->hdr.msg = msgid;
        msg->hdr.len = MSG_LENGTH(sz);
        if(sz)
            memcpy(msg->hdr.data, blob, sz);
        ret = submit_msg(clt, msg);
        if(ret == IPCLITE_ERR_OK)
            ret = wait_msg(clt, msg, 0);
    }else  {
        ret = IPCLITE_ERR_OOM;
        if((msg = __new_rsp_msg(ctx->peer, msgid, ctx->id, IPCLITE_ERR_OK, blob, sz)))  {
            ret = submit_msg(clt, msg);
            if(ret != IPCLITE_ERR_OK)
                free(msg);
        }
    }

    return ret;
}

static int __on_transact(const void *blob, size_t sz, int flags, void *ud)
{
    transact_ctx *ctx = (transact_ctx *)ud;

    if((sz == 0 || blob) && ctx)  {
        if(ctx->flags & TRANSACT_F_RSP)  {
            LOGERROR("not supposed to respond again");
            return IPCLITE_ERR_AGN;
        }
        ctx->flags |= TRANSACT_F_RSP;

        return ___on_transact(IPCLITE_MSG_RSP, ctx, flags, blob, sz);
    }
    return IPCLITE_ERR_INV;
}

static int __on_transact_ex(const void *blob, size_t sz, int flags, void *ud)
{
    transact_ctx *ctx = (transact_ctx *)ud;
    unsigned int msgid = IPCLITE_MSG_RPX;

    if((sz == 0 || blob) && ctx)  {
        if(ctx->flags & TRANSACT_F_DONE)  {
            LOGERROR("not supposed to respond anymore");
            return IPCLITE_ERR_AGN;
        }
        ctx->flags |= TRANSACT_F_RSP;
        if(flags & IPCLITE_RSP_END)  {
            msgid = IPCLITE_MSG_RXE;
            ctx->flags |= TRANSACT_F_DONE;
        }

        return ___on_transact(msgid, ctx, flags, blob, sz);
    }
    return IPCLITE_ERR_INV;
}

static void on_transact(ipclite_client *clt, ipclite_msg *req, ipclite_transact transact, void *ud)
{
    ipclite_msg *msg_rsp;

    if(! transact)  {
        if((msg_rsp = new_rsp_msg(req->hdr.peer, req->hdr.id, IPCLITE_ERR_NOS, NULL, 0)))  {
            if(submit_msg(clt, msg_rsp) != IPCLITE_ERR_OK)
                free(msg_rsp);
        }
    }else  {
        transact_ctx ctx = {
            .ipc = (ipclite *)clt,
            .peer = req->hdr.peer,
            .id = req->hdr.id,
            .flags = 0,
        };

        transact(req->hdr.peer,
                 MSG_PAYLOAD(const void, req),
                 req->hdr.len - sizeof(ipclite_msg_hdr),
                 __on_transact, (void *)&ctx, ud);
        /* respond err if not even responded */
        if(! (ctx.flags & TRANSACT_F_RSP)
           && (msg_rsp = new_rsp_msg(ctx.peer, ctx.id, IPCLITE_ERR_NOR, NULL, 0)))
            if(submit_msg(clt, msg_rsp))
                free(msg_rsp);
    }
}

static void on_transact_ex(ipclite_client *clt, ipclite_msg *req, ipclite_transact_ex transact, void *ud)
{
    ipclite_msg *rsp;

    if(! transact)  {
        if((rsp = new_rxe_msg(req->hdr.peer, req->hdr.id, IPCLITE_ERR_NOS, NULL, 0)))  {
            if(submit_msg(clt, rsp) != IPCLITE_ERR_OK)
                free(rsp);
        }
    }else  {
        transact_ctx ctx = {
            .ipc = (ipclite *)clt,
            .peer = req->hdr.peer,
            .id = req->hdr.id,
            .flags = 0,
        };

        transact(req->hdr.peer,
                 MSG_PAYLOAD(const void, req),
                 req->hdr.len - sizeof(ipclite_msg_hdr),
                 __on_transact_ex, (void *)&ctx, ud);
        /* At least a IPCLITE_RSP_END flag set message responded */
        if(! (ctx.flags & TRANSACT_F_DONE)
           && (rsp = new_rxe_msg(ctx.peer, ctx.id, IPCLITE_ERR_NOR, NULL, 0)))
            if(submit_msg(clt, rsp))
                free(rsp);
    }
}

static void *rd_thread(void *arg)
{
    ipclite_client *clt = (ipclite_client *)arg;
    ipclite_msg *msg, *n;
    ipclite_handler h = NULL;
    ipclite_transact transact = NULL;
    ipclite_transact_ex transact_ex = NULL;
    void *ud = NULL, *ud_transact = NULL;
    void *ud_transact_ex = NULL;
    list rd, req;

    prctl(PR_SET_NAME, (unsigned long)"ipcrd", 0, 0, 0);
    list_init(&rd);
    list_init(&req);
    for(;;)  {
        rd_lock(clt);
        while((list_empty(&clt->rd_queue)
               || ! clt->base.handler)
              && list_empty(&clt->req_queue)
              && ! clt->rd_quit)
            pthread_cond_wait(&clt->rd_cond, &clt->rd_lock);

        if(clt->base.handler)  {
            h = clt->base.handler;
            ud = clt->base.ud;
            list_assign(&rd, &clt->rd_queue);
        }

        transact = clt->base.transact;
        ud_transact = clt->base.ud_transact;

        transact_ex = clt->base.transact_ex;
        ud_transact_ex = clt->base.ud_transact_ex;

        list_assign(&req, &clt->req_queue);
        rd_unlock(clt);

        list_for_each_msg_safe(msg, n, &req)  {
            assert(msg->hdr.msg == IPCLITE_MSG_REQ || msg->hdr.msg == IPCLITE_MSG_RQX);

            list_delete(msg_list_ptr(msg));
            if(msg->hdr.msg == IPCLITE_MSG_REQ)
                on_transact(clt, msg, transact, ud_transact);
            else if(msg->hdr.msg == IPCLITE_MSG_RQX)
                on_transact_ex(clt, msg, transact_ex, ud_transact_ex);
            else
                LOGERROR("invalid req message received:%d", msg->hdr.msg);
            free(msg);
        }

        list_for_each_msg_safe(msg, n, &rd)  {
            list_delete(msg_list_ptr(msg));
            if(! h(msg, ud))
                free(msg);
        }

        if(clt->rd_quit)
            break;
    }

    clt->rd_started = 0;
    rd_unlock(clt);
    return NULL;
}


/**
 * gear up ipclite, @h will be run in child thread.
 */
int ipclite_client_run(ipclite *c, ipclite_handler h, void *ud)
{
    ipclite_client *clt = (ipclite_client *)c;
    int ret = IPCLITE_ERR_OK;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    client_lock(clt);
    if(! clt->worker_started)  {
        clt->worker_started = 1;
        if(pthread_create(&clt->worker, NULL, worker_thread, (void *)clt))  {
            LOGERROR("Fail to spawn worker thread");
            clt->worker_started = 0;
            ret = IPCLITE_ERR_THD;
        }
    }
    client_unlock(clt);

    if(ret == IPCLITE_ERR_OK)  {
        rd_lock(clt);
        clt->base.handler = h;
        clt->base.ud = ud;
        if(! clt->rd_started && h)  {
            clt->rd_started = 1;
            if(pthread_create(&clt->rd_thread, NULL, rd_thread, (void *)clt))  {
                LOGERROR("Fail to spawn rd thread");
                clt->rd_started = 0;
                ret = IPCLITE_ERR_THD;
            }
        }else  {
            pthread_cond_broadcast(&clt->rd_cond);
        }
        rd_unlock(clt);
    }
    return ret;
}

int ipclite_client_quit(ipclite *c, int wait)
{
    ipclite_client *clt = (ipclite_client *)c;
    int started;
    pthread_t thd;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    rd_lock(clt);
    started = clt->rd_started;
    if(clt->rd_started)  {
        clt->rd_quit = 1;
        started = clt->rd_started;
        thd = clt->rd_thread;
        pthread_cond_broadcast(&clt->rd_cond);
    }
    rd_unlock(clt);
    if(wait && started && pthread_join(thd, NULL))
        return IPCLITE_ERR_WAT;

    client_lock(clt);
    started = clt->worker_started;
    if(clt->worker_started)  {
        clt->quit = 1;
        started = clt->worker_started;
        thd = clt->worker;
        repoll(clt);
    }
    client_unlock(clt);
    if(wait && started && pthread_join(thd, NULL))
        return IPCLITE_ERR_WAT;
    return IPCLITE_ERR_OK;
}

int ipclite_client_recvmsg(ipclite *c, ipclite_msg **msg)
{
    ipclite_client *clt = (ipclite_client *)c;
    list *ptr;

    if(! clt || clt->base.type != IPCLITE_CLIENT || ! msg)
        return IPCLITE_ERR_INV;

    rd_lock(clt);
    while(list_empty(&clt->rd_queue))
        pthread_cond_wait(&clt->rd_cond, &clt->rd_lock);

    ptr = clt->rd_queue.l_nxt;
    list_delete(ptr);
    *msg = list_msg(ptr);
    rd_unlock(clt);
    return IPCLITE_ERR_OK;
}

/**
 * @wait: wait until successfully sent or failed to sent
 * @free: free @msg or not when done
 * return_value:
 * IPCLITE_MSG_PND if message queued for commiting.
 * IPCLITE_MSG_OK  if message successfully sent out.
 * other values for specific error.
 */
int ipclite_client_sendmsg(ipclite *c, ipclite_msg *msg, int wait, int free)
{
    ipclite_client *clt = (ipclite_client *)c;
    int ret;

    if(! clt || clt->base.type != IPCLITE_CLIENT
       || ! msg || msg->hdr.msg < IPCLITE_MSG_BASE)
        return IPCLITE_ERR_INV;

    msg_init_ctl(msg, wait, free);

    ret = submit_msg(clt, msg);
    if(wait && ret == IPCLITE_ERR_OK)
        return wait_msg(clt, msg, free);
    return ret;
}

/**
 * NOTE: must have transact handler set before call
 * @ipclite_server_transact, and must have message handler available
 * before set tranact handler.
 */
int ipclite_client_set_transact(ipclite *c, ipclite_transact h, void *ud)
{
    ipclite_client *clt = (ipclite_client *)c;
    int err = IPCLITE_ERR_OK;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    rd_lock(clt);
    if(clt->rd_started)  {
        clt->base.transact = h;
        clt->base.ud_transact = ud;
    }else  {
        err = IPCLITE_ERR_INV;
    }
    rd_unlock(clt);
    return err;
}

int ipclite_client_set_transact_ex(ipclite *c, ipclite_transact_ex h, void *ud)
{
    ipclite_client *clt = (ipclite_client *)c;
    int err = IPCLITE_ERR_OK;

    if(! clt || clt->base.type != IPCLITE_CLIENT)
        return IPCLITE_ERR_INV;

    rd_lock(clt);
    if(clt->rd_started)  {
        clt->base.transact_ex = h;
        clt->base.ud_transact_ex = ud;
    }else  {
        err = IPCLITE_ERR_INV;
    }
    rd_unlock(clt);
    return err;
}

static int __do_transact(ipclite_client *clt, ipclite_msg *msg, transact_rsp *trsp, int timeout)
{
    ipclite_msg *iter, *n, *rsp = NULL;
    ipclite_msg_ctl *ctl;
    struct timespec ts;
    int err = IPCLITE_ERR_OK;
    int ret = 0;

    wait_lock(clt);
    clt->wait_cnt++;
    if(timeout > 0)  {
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_nsec += (timeout % 1000) * 1000;
        ts.tv_sec += timeout / 1000;
        if(ts.tv_nsec > 1000000000)  {
            ts.tv_nsec -= 1000000000;
            ts.tv_sec++;
        }
    }
    for(;;)  {
        if(timeout <= 0)  {
            while(list_empty(&clt->wait_queue) && clt->port_state != PORT_CLOSED)
                pthread_cond_wait(&clt->wait_cond, &clt->wait_lock);
        }else if(ret != ETIMEDOUT)  {
            while(list_empty(&clt->wait_queue) && clt->port_state != PORT_CLOSED && ret != ETIMEDOUT)
                ret = pthread_cond_timedwait(&clt->wait_cond, &clt->wait_lock, &ts);
        }

        list_for_each_msg_safe(iter, n, &clt->wait_queue)  {
            if(iter == msg)  {
                list_delete(msg_list_ptr(iter));
                ctl = msg_ctl(msg);
                if(ctl->err != IPCLITE_ERR_OK)  {
                    err = ctl->err;
                    break;
                }
                continue;
            }

            if(msg->hdr.msg == IPCLITE_MSG_REQ)  {
                if(iter->hdr.msg == IPCLITE_MSG_RSP && iter->hdr.id == msg->hdr.id)  {
                    list_delete(msg_list_ptr(iter));
                    rsp = iter;
                    break;
                }
                continue;
            }

            if(msg->hdr.msg == IPCLITE_MSG_RQX)  {
                if((iter->hdr.msg == IPCLITE_MSG_RPX
                    || iter->hdr.msg == IPCLITE_MSG_RXE)
                   && iter->hdr.id == msg->hdr.id)  {
                    list_delete(msg_list_ptr(iter));
                    rsp = iter;
                    break;
                }
                continue;
            }
            /* should never reach here */
            assert(0);
        }

        if(rsp || err != IPCLITE_ERR_OK)
            break;

        if(timeout > 0 && ret == ETIMEDOUT)  {
            err = IPCLITE_ERR_TMO;
            break;
        }

        if(clt->port_state == PORT_CLOSED)  {
            err = IPCLITE_ERR_PER;
            break;
        }

        if(timeout <= 0)  {
            pthread_cond_wait(&clt->wait_cond, &clt->wait_lock);
        }else  {
            ret = pthread_cond_timedwait(&clt->wait_cond, &clt->wait_lock, &ts);
        }
    }
    clt->wait_cnt--;
    if(! clt->wait_cnt)
        pthread_cond_signal(&clt->wait_cond);

    wait_unlock(clt);

    if(rsp)  {
        ctl = msg_ctl(rsp);
        err = ctl->err;
        if(err == IPCLITE_ERR_OK)
            err = __transact_rsp(rsp, trsp);
        if(ctl->free)
            free(rsp);
    }
    return err;
}

static inline void inc_waiters(ipclite_client *clt)
{
    wait_lock(clt);
    clt->wait_cnt++;
    wait_unlock(clt);
}

static inline void dec_waiters(ipclite_client *clt)
{
    wait_lock(clt);
    clt->wait_cnt--;
    if(! clt->wait_cnt)
        pthread_cond_signal(&clt->wait_cond);
    wait_unlock(clt);
}

static int submit_req(ipclite_client *clt,
                      ipclite_msg *msg, unsigned int msgid,
                      const void *blob, size_t sz)
{
    int err = IPCLITE_ERR_PER;

    msg_init_ctl(msg, 1, 0);
    memcpy(MSG_PAYLOAD(void, msg), blob, sz);
    msg->hdr.msg = msgid;
    msg->hdr.len = MSG_LENGTH(sz);

    client_lock(clt);
    msg->hdr.id = ++clt->base.seq;
    msg->hdr.peer = clt->peer;
    if(clt->port.state == PORT_OPENED || clt->port.state == PORT_OPENING)  {
        FD_SET(clt->port.fd, &clt->wr);
        list_append(&clt->port.msgs, msg_list_ptr(msg));
        repoll(clt);
        err = IPCLITE_ERR_OK;
        inc_waiters(clt);
    }
    client_unlock(clt);
    return err;
}

static int do_transact(ipclite_client *clt, const void *blob, size_t sz,
                       void *rsp, size_t *rsp_sz, int timeout)
{
    char _msg[sz + sizeof(ipclite_msg)];
    ipclite_msg *msg = (ipclite_msg *)_msg;
    transact_rsp trsp;
    int err = submit_req(clt, msg, IPCLITE_MSG_REQ, blob, sz);

    if(err == IPCLITE_ERR_OK)  {
        trsp.type = TRANSACT_RSP_CANONICAL;
        trsp.blob = rsp;
        trsp.sz = rsp_sz;
        err = __do_transact(clt, msg, &trsp, timeout);
        dec_waiters(clt);
    }
    return err;
}

static int do_transact_ex(ipclite_client *clt, const void *blob, size_t sz,
                          ipclite_handler cb, void *ud, int timeout)
{
    char _msg[sz + sizeof(ipclite_msg)];
    ipclite_msg *msg = (ipclite_msg *)_msg;
    transact_rsp trsp;
    int err = submit_req(clt, msg, IPCLITE_MSG_RQX, blob, sz);

    if(err == IPCLITE_ERR_OK)  {
        trsp.type = TRANSACT_RSP_EXTENDED;
        trsp.cb = cb;
        trsp.ud = ud;
        trsp.flags = TRANSACT_RSP_F_CONTINUE;
        do{
            err = __do_transact(clt, msg, &trsp, timeout);
        }while(err == IPCLITE_ERR_OK && ! (trsp.flags & TRANSACT_RSP_F_DONE));
        dec_waiters(clt);
    }
    return err;
}

/**
 * the server must recognize and response @blob, otherwise the
 * function will never return if @timeout set to 0.
 * @rsp: response result, set to NULL to ignore.
 * @rsp_sz: @rsp length, response result length on return.
 * @timeout: in millisecconds
 */
int ipclite_client_transact(ipclite *c, const void *blob, size_t size,
                            void *rsp, size_t *rsp_sz, int timeout)
{
    ipclite_client *clt = (ipclite_client *)c;

    if(! clt || clt->base.type != IPCLITE_CLIENT || ! blob || ! size)
        return IPCLITE_ERR_INV;

    return do_transact(clt, blob, size, rsp, rsp_sz, timeout);
}

/**
 * the server must be able to recognize and response @blob, otherwise,
 * the function will never return if @timeout set to 0.
 * @cb: handler for the peer responded ipclite_msg of type
 * IPCLITE_MSG_RPX, and can be called multiple times, with the last
 * ipclite_msg of type IPCLITE_MSG_RXE, if only one ipclite_msg
 * responded, only IPCLITE_MSG_RXE will be recevied, return zero to
 * stop process furthur responses.
 * @timeout: in millisecconds
 */
int ipclite_client_transact_ex(ipclite *c, const void *blob, size_t size,
                               ipclite_handler cb, void *ud, int timeout)
{
    ipclite_client *clt = (ipclite_client *)c;

    if(clt && clt->base.type == IPCLITE_CLIENT && blob && size)
        return do_transact_ex(clt, blob, size, cb, ud, timeout);
    return IPCLITE_ERR_INV;
}

static void __client_destroy(ipclite_client *clt)
{
    ipclite_msg *msg, *n;

    if(clt->base.master != -1)
        __close_port(clt);

    close(clt->notify[0]);
    close(clt->notify[1]);

    if(clt->base.msg)
        free(clt->base.msg);

    list_for_each_msg_safe(msg, n, &clt->rd_queue)  {
        list_delete(msg_list_ptr(msg));
        if(msg_ctl(msg)->free)
            free(msg);
    }

    list_for_each_msg_safe(msg, n, &clt->wait_queue)  {
        list_delete(msg_list_ptr(msg));
        if(msg_ctl(msg)->free)
            free(msg);
    }

    wait_lock(clt);
    while(clt->wait_cnt)
        pthread_cond_wait(&clt->wait_cond, &clt->wait_lock);
    wait_unlock(clt);

    free(clt);
}

void ipclite_client_destroy(ipclite *c)
{
    ipclite_client *clt = (ipclite_client *)c;

    if(clt && clt->base.type == IPCLITE_CLIENT)  {
        ipclite_client_quit(c, 1);
        if(clt->worker_started)
            LOGERROR("Worker not stopped when destroying");
        if(clt->rd_started)
            LOGERROR("rd not stopped when destroying");
        __client_destroy(clt);
    }
}

