/*
 * ginkgo.c
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


#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/select.h>
#include <pthread.h>

#include "ginkgo.h"
#include "util.h"

#define INIT_BUF_SIZE (1024 * 4)
#define MIN_FREE_BUF 512

#define __GINKGO_TRIGER "KISS"

typedef struct _ginkgo_src_ctx ginkgo_src_ctx;
typedef struct _handler_ctx handler_ctx;
typedef union _ginkgo_msg_prv ginkgo_msg_prv;

struct _ginkgo_ctx{
    pthread_mutex_t worker_lock;
    pthread_cond_t worker_cond;
    pthread_t worker;
    int worker_started;
    int worker_quit;
    list src;
    int id_max;
    fd_set rd;
    fd_set wr;
    int max_fd;

    int notify[2];

    pthread_t handler;
    int handler_started;
    int handler_quit;
    queue unsol;
    queue wait;
};

struct _ginkgo_src_ctx{
    list list;

    char *name;

    int id;
    int state;

    int fd;
    ginkgo_read rd;
    ginkgo_writ wr;

    ginkgo_pars pars;
    ginkgo_resp resp;
    ginkgo_hand hand;
    void *ud;

    ginkgo_msg *cur;
    size_t offset;

    handler_ctx *hctx;

    queue *unsol;
    list wr_queue;
    list req_queue;

    size_t len;
    size_t siz;
    void *buf;
};

struct _handler_ctx{
    ginkgo_ctx *ctx;
    char *name;
    int started;
    int quit;
    queue unsol;
    pthread_t handler;
};

enum{
    STATE_ACTIVE,
    STATE_CLOSING,
    STATE_CLOSED,
};

union _ginkgo_msg_prv{
    list list;
    struct{
        ginkgo_hand handler;
        void *ud;
    }h;
};

static list *msg_list(ginkgo_msg *msg)
{
    return &msg->lst;
}

static ginkgo_msg *list_msg(list *l)
{
    return list_entry(l, ginkgo_msg, lst);
}

static list *msg_prv_list(ginkgo_msg *msg)
{
    return &(((ginkgo_msg_prv *)&msg->prv)->list);
}

static ginkgo_hand msg_prv_handler(ginkgo_msg *msg, void **ud)
{
    ginkgo_msg_prv *prv = (ginkgo_msg_prv *)&msg->prv;

    *ud = prv->h.ud;
    return prv->h.handler;
}

static void msg_set_handler(ginkgo_msg *msg, ginkgo_hand h, void *ud)
{
    ginkgo_msg_prv *prv = (ginkgo_msg_prv *)&msg->prv;
    prv->h.handler = h;
    prv->h.ud = ud;
}

static inline void worker_lock(ginkgo_ctx *ctx)
{
    pthread_mutex_lock(&ctx->worker_lock);
}


static inline void worker_unlock(ginkgo_ctx *ctx)
{
    pthread_mutex_unlock(&ctx->worker_lock);
}


static inline void handler_lock(ginkgo_ctx *ctx)
{
    queue_lock(&ctx->unsol);
}

static inline void handler_unlock(ginkgo_ctx *ctx)
{
    queue_unlock(&ctx->unsol);
}


static inline void repoll(ginkgo_ctx *ctx)
{
    while((write(ctx->notify[1], __GINKGO_TRIGER, sizeof(__GINKGO_TRIGER)) < 0) && errno == EINTR)
        ;
}


int ginkgo_create(ginkgo_ctx **ctx, int flags)
{
    ginkgo_ctx *ginkgo;
    int notify[2];

    if(! ctx)
        return GINKGO_ERR_INV;

    if(pipe2(notify, O_NONBLOCK) < 0)
        return GINKGO_ERR_PIPE;

    if(! (ginkgo = new_instance(ginkgo_ctx)))
        return GINKGO_ERR_OOM;

    pthread_mutex_init(&ginkgo->worker_lock, NULL);
    pthread_cond_init(&ginkgo->worker_cond, NULL);
    ginkgo->worker_started = 0;
    list_init(&ginkgo->src);
    ginkgo->id_max = 1;
    FD_ZERO(&ginkgo->rd);
    FD_ZERO(&ginkgo->wr);

    FD_SET(notify[0], &ginkgo->rd);
    ginkgo->max_fd = notify[0];

    ginkgo->notify[0] = notify[0];
    ginkgo->notify[1] = notify[1];

    ginkgo->handler_started = 0;
    queue_init(&ginkgo->unsol);
    queue_init(&ginkgo->wait);

    *ctx = ginkgo;
    return GINKGO_ERR_OK;
}


static void *unsol_handler(void *arg)
{
    handler_ctx *ctx = (handler_ctx *)arg;
    ginkgo_msg *msg, *n;
    ginkgo_hand h;
    void *ud;
    list list;

    prctl(PR_SET_NAME, (unsigned long)ctx->name, 0, 0, 0);
    for(;;)  {
        queue_lock(&ctx->unsol);
        while(list_empty(&ctx->unsol.queue) && ! ctx->quit)
            __queue_wait(&ctx->unsol);
        if(ctx->quit)
            break;
        list_assign(&list, &ctx->unsol.queue);
        queue_unlock(&ctx->unsol);

        list_for_each_ginkgo_msg_safe(msg, n, &list)  {
            if((h = msg_prv_handler(msg, &ud)))  {
                if(! h(ctx->ctx, msg, ud))
                    free(msg);
            }
        }
    }

    ctx->started = 0;
    queue_unlock(&ctx->unsol);
    return NULL;
}

static int handler_start(handler_ctx *ctx)
{
    queue_lock(&ctx->unsol);
    if(ctx->started)  {
        queue_unlock(&ctx->unsol);
        return 0;
    }
    ctx->quit = 0;
    if(pthread_create(&ctx->handler, NULL, unsol_handler, (void *)ctx))  {
        queue_unlock(&ctx->unsol);
        return -1;
    }
    ctx->started = 1;
    queue_unlock(&ctx->unsol);
    return 0;
}


static int handler_stop(handler_ctx *ctx)
{
    pthread_t thd;
    int started;

    queue_lock(&ctx->unsol);
    started = ctx->started;
    ctx->quit = 1;
    thd = ctx->handler;
    __queue_wakeup(&ctx->unsol);
    queue_unlock(&ctx->unsol);
    if(started && pthread_join(thd, NULL))
       return GINKGO_ERR_WAIT;
    return 0;
}

static ssize_t ginkgo_write(int fd, const ginkgo_msg *msg, const void *buf, size_t len)
{
    return write(fd, buf, len);
}

int ginkgo_src_register(ginkgo_ctx *ctx, const ginkgo_src *src, int *id, int flags)
{
    ginkgo_src_ctx *src_ctx;
    size_t sz = sizeof(ginkgo_src_ctx);
    handler_ctx *hctx;
    void *buf;

    if(! ctx || ! src || ! id)
        return GINKGO_ERR_INV;

    if(! src->name || ! *src->name)
        return GINKGO_ERR_INV;

    if(src->fd < 0 || ! src->pars || ! src->resp)
        return GINKGO_ERR_INV;

    if(flags & SF_HANDLER_THREAD)
        sz += sizeof(handler_ctx);

    sz += strlen(src->name) + 1;
    if(! (src_ctx = (ginkgo_src_ctx *)malloc(sz)))
        return GINKGO_ERR_OOM;

    if(! (buf = malloc(INIT_BUF_SIZE)))  {
        free(src_ctx);
        return GINKGO_ERR_OOM;
    }

    src_ctx->state = STATE_ACTIVE;

    list_init(&src_ctx->list);

    src_ctx->fd = src->fd;
    src_ctx->rd = src->rd ? : (ginkgo_read)read;
    src_ctx->wr = src->wr ? : (ginkgo_writ)ginkgo_write;

    src_ctx->pars = src->pars;
    src_ctx->resp = src->resp;
    src_ctx->hand = src->hand;
    src_ctx->ud = src->ud;

    src_ctx->cur = NULL;
    src_ctx->offset = 0;

    src_ctx->unsol = &ctx->unsol;
    if(flags & SF_HANDLER_THREAD)  {
        src_ctx->hctx = hctx = (handler_ctx *)(src_ctx + 1);
        hctx->ctx = ctx;
        hctx->started = 0;
        queue_init(&hctx->unsol);
        src_ctx->unsol = &hctx->unsol;
        src_ctx->name = (char *)(hctx + 1);
    }else  {
        src_ctx->hctx = NULL;
        src_ctx->name = (char *)(src_ctx + 1);
    }
    strcpy(src_ctx->name, src->name);

    list_init(&src_ctx->wr_queue);
    list_init(&src_ctx->req_queue);

    src_ctx->len = 0;
    src_ctx->siz = INIT_BUF_SIZE;
    src_ctx->buf = buf;

    if((flags & SF_HANDLER_THREAD))  {
        hctx->name = src_ctx->name;
        if(handler_start(hctx))  {
            free(buf);
            free(src_ctx);
            return GINKGO_ERR_THREAD;
        }
    }

    worker_lock(ctx);
    if(! ctx->id_max)  {
        worker_unlock(ctx);
        LOGERROR("src ID wrapped!");
        if(flags & SF_HANDLER_THREAD)
            handler_stop(hctx);
        free(buf);
        free(src_ctx);
        return GINKGO_ERR_GEN;
    }
    FD_SET(src->fd, &ctx->rd);
    ctx->max_fd = MAX(ctx->max_fd, src->fd);
    src_ctx->id = *id = ctx->id_max++;
    list_append(&ctx->src, &src_ctx->list);
    worker_unlock(ctx);

    repoll(ctx);
    LOGINFO("ginkgo src [%s] registered", src->name);
    return GINKGO_ERR_OK;
}


static inline void __delete_src(ginkgo_ctx *ctx, ginkgo_src_ctx *s)
{
    list_delete(&s->list);
    free(s);
    __WAKEUP(&ctx->worker_cond);
}

static inline void __reject_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s, ginkgo_msg *msg)
{
    msg->err = GINKGO_ERR_PORT_CLOSED;

    if(msg->flg & GINKGO_MSG_WAIT)  {
        msg->err = GINKGO_ERR_PORT_NOT_AVAIL;
        enqueue_wakeup(&ctx->wait, msg_list(msg));
        return;
    }

    if(msg->flg & GINKGO_MSG_REQ)  {
        msg->err = GINKGO_ERR_PORT_NOT_AVAIL;
        enqueue_wakeup(&ctx->wait, msg_list(msg));
        return;
    }

    if(! (msg->flg & GINKGO_MSG_NO_FREE))  {
        free(msg);
        return;
    }
}

static void __close_src(ginkgo_ctx *ctx, ginkgo_src_ctx *src_ctx)
{
    ginkgo_src_ctx *s;
    ginkgo_msg *msg, *n;
    handler_ctx *hctx;

    src_ctx->state = STATE_CLOSED;
    FD_CLR(src_ctx->fd, &ctx->rd);
    FD_CLR(src_ctx->fd, &ctx->wr);
    if(ctx->max_fd == src_ctx->fd)  {
        ctx->max_fd = ctx->notify[0];
        list_for_each_entry(s, &ctx->src, list)  {
            ctx->max_fd = MAX(ctx->max_fd, s->fd);
        }
    }

    if(src_ctx->cur)
        __reject_msg(ctx, src_ctx, src_ctx->cur);

    list_for_each_ginkgo_msg_safe(msg, n, &src_ctx->wr_queue)  {
        list_delete(msg_list(msg));
        __reject_msg(ctx, src_ctx, msg);
    }

    if(src_ctx->hctx)  {
        hctx = src_ctx->hctx;
        handler_stop(hctx);
        queue_lock(&hctx->unsol);
        list_for_each_ginkgo_msg_safe(msg, n, &hctx->unsol.queue)  {
            list_delete(msg_list(msg));
            __reject_msg(ctx, src_ctx, msg);
        }
        queue_unlock(&hctx->unsol);
    }

    if(src_ctx->buf)
        free(src_ctx->buf);
    __delete_src(ctx, src_ctx);
}

static inline int __src_registered(ginkgo_ctx *ctx, ginkgo_src_ctx *src_ctx)
{
    ginkgo_src_ctx *s;

    list_for_each_entry(s, &ctx->src, list)  {
        if(s == src_ctx)
            return 1;   
    }
    return 0;
}

static int close_src(ginkgo_ctx *ctx, ginkgo_src_ctx *src_ctx, int wait, int force)
{
    ginkgo_src_ctx *s;

    if(force || (! src_ctx->cur && list_empty(&src_ctx->wr_queue)))  {
        __close_src(ctx, src_ctx);
        return GINKGO_ERR_OK;
    }

    src_ctx->state = STATE_CLOSING;
    if(! wait)
        return GINKGO_ERR_PENDING;

    __WAIT_ON(&ctx->worker_cond, &ctx->worker_lock, ! __src_registered(ctx, src_ctx));
    return GINKGO_ERR_OK;
}

int ginkgo_src_deregister(ginkgo_ctx *ctx, int src, int wait, int force)
{
    ginkgo_src_ctx *src_ctx, *n;
    int res = GINKGO_ERR_OK;

    if(! ctx)
        return GINKGO_ERR_INV;

    worker_lock(ctx);
    list_for_each_entry_safe(src_ctx, n, &ctx->src, list)  {
        if(src_ctx->id == src)  {
            res = close_src(ctx, src_ctx, wait, force);
            break;
        }
    }
    worker_unlock(ctx);
    return res;
}


static inline void empty_fd(int fd)
{
    char buf[64];
    int res;

    for(;;)  {
        res = read(fd, buf, sizeof(buf));
        if(res > 0 || (res < 0 && errno == EINTR))
            continue;
        break;
    }
}


static void handle_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s, ginkgo_msg *msg)
{
    ginkgo_msg *m, *n;
    int res;

    list_for_each_ginkgo_msg_safe(m, n, &s->req_queue)  {
        res = s->resp(m, msg);
        if(res == GINKGO_RESP_DONE || res == GINKGO_RESP_CONT)  {
            list_append(msg_prv_list(m), msg_list(msg));
            msg->flg |= GINKGO_MSG_RESP;
            if(res == GINKGO_RESP_DONE)  {
                list_delete(msg_list(m));
                enqueue_wakeup(&ctx->wait, msg_list(m));
            }
            return;
        }
    }

    msg_set_handler(msg, s->hand, s->ud);
    enqueue_wakeup(s->unsol, msg_list(msg));
}

static void parse_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s)
{
    ginkgo_msg *msg;
    size_t offset = 0;
    int len;

    for(;;)  {
        msg = NULL;
        len = s->pars((char *)s->buf + offset, s->len - offset, &msg);

        if(len <= 0)
            break;

        if((size_t)len > s->len - offset)  {
            LOGERROR("Illigal value returned from src %d parser!", s->id);
            if(msg)
                free(msg);
            __close_src(ctx, s);
            return;
        }

        offset += len;
        if(msg)  {
            msg->src = s->id;
            handle_msg(ctx, s, msg);
        }

        if(offset == s->len)
            break;
    }

    if(offset > 0 && offset < s->len)
        memmove(s->buf, (char *)s->buf + offset, s->len - offset);
    s->len -= offset;
}

static void read_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s)
{
    int len, siz;
    void *buf;
    ginkgo_msg *msg = NULL;

    if(s->siz - s->len < MIN_FREE_BUF)  {
        siz = s->siz + MIN_FREE_BUF;
        buf = realloc(s->buf, siz);
        if(! buf)  {
            LOGERROR("Fail to extend reading buff, src:%d", s->id);
            __close_src(ctx, s);
            return;
        }
        s->buf = buf;
        s->siz = siz;
    }

    do{
        len = s->rd(s->fd, s->buf, s->siz - s->len);
    }while(len < 0 && len == EINTR);

    if((len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) || len == 0)  {
        LOGINFO("Exception read src(%d) msg, closed or error", s->id);
        __close_src(ctx, s);
        return;
    }

    if(len > 0)  {
        s->len += len;
        parse_msg(ctx, s);
    }
}


/**
 * return_value:
 * -1: client error or closed
 *  0: successfully commited
 *  1: half commited
 */
static int commit_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s, ginkgo_msg *msg, size_t offset)
{
    list *ptr;
    int res;

    do{
        res = s->wr(s->fd, msg, GINKGO_MSG_PAYLOAD(msg,char) + offset, msg->len - offset);
    }while(res < 0 && errno == EINTR);

    if(res < 0 && errno != EWOULDBLOCK && errno != EAGAIN)  {
        LOGINFO("Error writting ginkgo msg, closed or error, removing:%d", s->id);
        __close_src(ctx, s);
        return -1;
    }

    if(res > 0)
        offset += res;

    if((size_t)msg->len > offset)  {
        s->cur = msg;
        s->offset = offset;
        return 1;
    }

    msg->err = GINKGO_ERR_OK;
    if(msg->flg & GINKGO_MSG_WAIT)  {
        enqueue_wakeup(&ctx->wait, msg_list(msg));
    }else if(msg->flg & GINKGO_MSG_REQ)  {
        list_append(&s->req_queue, msg_list(msg));
    }else if(! (msg->flg & GINKGO_MSG_NO_FREE))  {
        free(msg);
    }

    s->cur = NULL;
    s->offset = 0;
    return 0;
}

static void write_msg(ginkgo_ctx *ctx, ginkgo_src_ctx *s)
{
    ginkgo_msg *msg  = s->cur, *n;
    int res = 0;

    if(msg)
        res = commit_msg(ctx, s, msg, s->offset);
    if(res == 0)  {
        list_for_each_ginkgo_msg_safe(msg, n, &s->wr_queue)  {
            list_delete(msg_list(msg));
            if((res = commit_msg(ctx, s, msg, 0)))
                break;
        }
    }
    if(res == 0)  {
        FD_CLR(s->fd, &ctx->wr);
        if(s->state == STATE_CLOSING)
            __close_src(ctx, s);
    }
}

static void *worker_thread(void *arg)
{
    ginkgo_ctx *ctx = (ginkgo_ctx *)arg;
    ginkgo_src_ctx *s, *n;
    fd_set rd, wr;
    int max_fd;

    prctl(PR_SET_NAME, (unsigned long)"ginkgoworker", 0, 0, 0);
    for(;;)  {
        worker_lock(ctx);
        rd = ctx->rd;
        wr = ctx->wr;
        max_fd = ctx->max_fd + 1;
        worker_unlock(ctx);

        if(select(max_fd, &rd, &wr, NULL, NULL) <= 0)
            continue;

        if(ctx->worker_quit)
            break;

        if(FD_ISSET(ctx->notify[0], &rd))  {
            empty_fd(ctx->notify[0]);
            continue;
        }

        worker_lock(ctx);
        list_for_each_entry_safe(s, n, &ctx->src, list)  {
            if(FD_ISSET(s->fd, &rd))
                read_msg(ctx, s);

            if(FD_ISSET(s->fd, &wr))
                write_msg(ctx, s);
        }
        worker_unlock(ctx);
    }

    ctx->worker_started = 0;
    worker_unlock(ctx);
    return NULL;
}


static void *handler_thread(void *arg)
{
    ginkgo_ctx *ctx = (ginkgo_ctx *)arg;
    ginkgo_msg *msg, *n;
    ginkgo_hand h;
    void *ud;
    list list;

    prctl(PR_SET_NAME, (unsigned long)"ginkgohandler", 0, 0, 0);
    for(;;)  {
        queue_lock(&ctx->unsol);
        while(list_empty(&ctx->unsol.queue) && ! ctx->handler_quit)
            __queue_wait(&ctx->unsol);
        if(ctx->handler_quit)
            break;
        list_assign(&list, &ctx->unsol.queue);
        queue_unlock(&ctx->unsol);

        list_for_each_ginkgo_msg_safe(msg, n, &list)  {
            if((h = msg_prv_handler(msg, &ud)))  {
                if(! h(ctx, msg, ud))
                    free(msg);
            }
        }
    }

    ctx->handler_started = 0;
    queue_unlock(&ctx->unsol);
    return NULL;
}

int ginkgo_run(ginkgo_ctx *ctx)
{
    int res = GINKGO_ERR_THREAD;

    if(! ctx)
        return GINKGO_ERR_INV;

    worker_lock(ctx);
    ctx->worker_quit = 0;
    if(! ctx->worker_started)  {
        if(! pthread_create(&ctx->worker, NULL, worker_thread, (void *)ctx))  {
            ctx->worker_started = 1;
            res = GINKGO_ERR_OK;
        }else  {
            LOGERROR("Fail to start worker thread!");
        }
    }
    worker_unlock(ctx);

    if(res == GINKGO_ERR_OK)  {
        ctx->handler_quit = 0;
        handler_lock(ctx);
        if(! ctx->handler_started)  {
            if(! pthread_create(&ctx->handler, NULL, handler_thread, (void *)ctx))
                ctx->handler_started = 1;
            else
                LOGERROR("Fail to start handler thread!");
        }
        handler_unlock(ctx);
    }
    return res;
}


int ginkgo_quit(ginkgo_ctx *ctx, int wait)
{
    pthread_t thd;
    int started;
    int res = GINKGO_ERR_OK;

    if(! ctx)
        return GINKGO_ERR_INV;

    worker_lock(ctx);
    started = ctx->worker_started;
    if(started)  {
        ctx->worker_quit = 1;
        thd = ctx->worker;
        repoll(ctx);
    }
    worker_unlock(ctx);
    if(wait & started && pthread_join(thd, NULL))  {
        LOGERROR("Fail to wait worker thread!");
        res = GINKGO_ERR_WAIT;
    }

    if(res == GINKGO_ERR_OK)  {
        handler_lock(ctx);
        started = ctx->handler_started;
        if(started)  {
            ctx->handler_quit = 1;
            thd = ctx->handler;
            __queue_wakeup(&ctx->unsol);
        }
        handler_unlock(ctx);
        if(wait && started && pthread_join(thd, NULL))  {
            LOGERROR("Fail to wait handler thread!");
            res = GINKGO_ERR_WAIT;
        }
    }

    return res;
}

int ginkgo_queue_msg(ginkgo_ctx *ctx, ginkgo_msg *msg)
{
    ginkgo_src_ctx *s;

    if(! ctx || ! msg)
        return GINKGO_ERR_INV;

    worker_lock(ctx);
    list_for_each_entry(s, &ctx->src, list)  {
        if(s->id == msg->src)  {
            handle_msg(ctx, s, msg);
            worker_unlock(ctx);
            return GINKGO_ERR_OK;
        }
    }
    worker_unlock(ctx);
    return GINKGO_ERR_NO_SRC;
}

int ginkgo_sendmsg(ginkgo_ctx *ctx, ginkgo_msg *msg, int wait, int fr)
{
    ginkgo_src_ctx *s;
    ginkgo_msg *m = NULL, *n;
    int res = GINKGO_ERR_NO_SRC;

    if(! ctx || ! msg)
        return GINKGO_ERR_INV;

    if(wait)
        msg->flg = GINKGO_MSG_WAIT | GINKGO_MSG_NO_FREE;
    else if(! fr)
        msg->flg = GINKGO_MSG_NO_FREE;
    else
        msg->flg = 0;
    msg->err = GINKGO_ERR_PENDING;
    list_init(msg_prv_list(msg));

    worker_lock(ctx);
    list_for_each_entry(s, &ctx->src, list)  {
        if(s->id == msg->src)  {
            if(s->state == STATE_ACTIVE)  {
                FD_SET(s->fd, &ctx->wr);
                list_append(&s->wr_queue, msg_list(msg));
                repoll(ctx);
                res = GINKGO_ERR_PENDING;
            }else  {
                res = GINKGO_ERR_PORT_NOT_AVAIL;
            }
        }
    }
    worker_unlock(ctx);

    if(wait && res == GINKGO_ERR_PENDING)  {
        queue_lock(&ctx->wait);
        for(;;)  {
            list_for_each_ginkgo_msg_safe(m, n, &ctx->wait.queue)  {
                if(m == msg)  {
                    res = m->err;
                    list_delete(msg_list(m));
                    break;
                }
            }
            if(m == msg)
                break;
            __queue_wait(&ctx->wait);
        }
        queue_unlock(&ctx->wait);
    }

    if(fr && res == GINKGO_ERR_OK)
        free(msg);

    return res;
}


int ginkgo_request(ginkgo_ctx *ctx, ginkgo_msg *msg, list *rsp, int fr)
{
    ginkgo_src_ctx *s;
    ginkgo_msg *m = NULL, *n;
    list *rsp_list;
    int res = GINKGO_ERR_NO_SRC;

    if(! ctx || ! msg || ! rsp)
        return GINKGO_ERR_INV;

    msg->flg = GINKGO_MSG_REQ | GINKGO_MSG_NO_FREE;
    msg->err = GINKGO_ERR_PENDING;
    list_init(msg_prv_list(msg));

    worker_lock(ctx);
    list_for_each_entry(s, &ctx->src, list)  {
        if(s->id == msg->src)  {
            if(s->state == STATE_ACTIVE)  {
                FD_SET(s->fd, &ctx->wr);
                list_append(&s->wr_queue, msg_list(msg));
                repoll(ctx);
                res = GINKGO_ERR_PENDING;
            }else  {
                res = GINKGO_ERR_PORT_NOT_AVAIL;
            }
        }
    }
    worker_unlock(ctx);

    if(res == GINKGO_ERR_PENDING)  {
        queue_lock(&ctx->wait);
        for(;;)  {
            list_for_each_ginkgo_msg_safe(m, n, &ctx->wait.queue)  {
                if(m == msg)  {
                    res = m->err;
                    list_delete(msg_list(m));
                    break;
                }
            }
            if(m == msg)
                break;
            __queue_wait(&ctx->wait);
        }
        queue_unlock(&ctx->wait);
    }

    list_init(rsp);
    if(res == GINKGO_ERR_OK)  {
        if(list_empty(msg_prv_list(msg)))  {
            res = GINKGO_ERR_NO_RESP;
        }else  {
            rsp_list = msg_prv_list(msg);
            list_for_each_ginkgo_msg_safe(m, n, rsp_list)  {
                list_delete(msg_list(m));
                list_append(rsp, msg_list(m));
            }
        }
        if(fr)
            free(msg);
    }

    return res;
}

/**
 * @src: GINKGO_SRC_INV marks all available
 */
ginkgo_msg *ginkgo_recvmsg(ginkgo_ctx *ctx, int src)
{
    ginkgo_msg *msg = NULL, *n;

    if(! ctx)
        return NULL;

    queue_lock(&ctx->unsol);
    for(;;)  {
        list_for_each_ginkgo_msg_safe(msg, n, &ctx->unsol.queue)  {
            if(src == GINKGO_SRC_INV || src == msg->src)  {
                list_delete(msg_list(msg));
                queue_unlock(&ctx->unsol);
                return msg;
            }
        }

        __queue_wait(&ctx->unsol);
    }
}


ginkgo_msg *ginkgo_peekmsg(ginkgo_ctx *ctx, int src)
{
    ginkgo_msg *msg, *n;

    if(! ctx)
        return NULL;

    queue_lock(&ctx->unsol);
    list_for_each_ginkgo_msg_safe(msg, n, &ctx->unsol.queue)  {
        if(src == GINKGO_SRC_INV || src == msg->src)  {
            list_delete(msg_list(msg));
            queue_unlock(&ctx->unsol);
            return msg;
        }
    }
    queue_unlock(&ctx->unsol);
    return NULL;
}

void ginkgo_destroy(ginkgo_ctx *ctx)
{
    ginkgo_src_ctx *s, *n_s;
    ginkgo_msg *m, *n_m;
    ginkgo_msg *m_rsp, *n_m_rsp;
    list *list;

    if(! ctx)
        return;

    ginkgo_quit(ctx, 1);
    worker_lock(ctx);
    list_for_each_entry_safe(s, n_s, &ctx->src, list)  {
        __close_src(ctx, s);
    }
    worker_unlock(ctx);

    close(ctx->notify[0]);
    close(ctx->notify[1]);

    queue_lock(&ctx->unsol);
    list_for_each_ginkgo_msg_safe(m, n_m, &ctx->unsol.queue)  {
        list_delete(msg_list(m));
        if(! (m->flg & GINKGO_MSG_NO_FREE))
            free(m);
    }
    queue_unlock(&ctx->unsol);

    queue_lock(&ctx->wait);
    list_for_each_ginkgo_msg_safe(m, n_m, &ctx->unsol.queue)  {
        list_delete(msg_list(m));
        if(! (m->flg & GINKGO_MSG_NO_FREE))  {
            if(m->flg & GINKGO_MSG_REQ)  {
                list = msg_prv_list(m);
                list_for_each_ginkgo_msg_safe(m_rsp, n_m_rsp, list)  {
                    list_delete(msg_list(m_rsp));
                    if(! (m->flg & GINKGO_MSG_NO_FREE))
                        free(m_rsp);
                }
            }
            free(m);
        }
    }
    queue_unlock(&ctx->wait);
    free(ctx);
}


static void bug_check(void)
{
    ginkgo_msg msg;

    build_fail_on(sizeof(ginkgo_msg_prv) > sizeof(msg.prv));
}

