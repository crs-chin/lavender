/*
 * RPC lite based on ipclite.
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
#include <sys/types.h>
#include <pthread.h>

#include "util.h"
#include "ipclite.h"
#include "rpclite.h"

#define SVC_TABLE_SIZE 100

#define SVC_STATE_CONNECTED 1

typedef struct _parcel parcel;
typedef struct _transact_ctx transact_ctx;

struct _parcel{
    int svc;
    int req;
    int err;
    size_t sz;
    char blob[0];
};

struct _transact_ctx{
    int responded;
    parcel *req;
    ipclite_response rsp;
    void *rsp_ud;
#define TRANSACT_F_EXTENDED 1
#define TRANSACT_F_RESPONDED (1<<1)
#define TRANSACT_F_DONE (1<<2)
    unsigned int flags;
};

enum{
    RPCLITE_TYPE_CANONICAL,
    RPCLITE_TYPE_EXTENDED,
};

static pthread_mutex_t svc_lock = PTHREAD_MUTEX_INITIALIZER;
static ipclite *svc_ipc = NULL;
static htable *svc_table = NULL;
static int svc_id_seq = 0;


static int connect_svc(rpclite_ctx *ctx, ipclite *client, int flags, int timeout)
{
    char blob[sizeof(parcel) + strlen(ctx->svc_name) + 1];
    char rsp[sizeof(parcel)];
    parcel *p = (parcel *)blob;
    size_t rsp_sz = sizeof(rsp);
    int err;

    p->svc = 0;
    p->req = 0;
    p->err = RPC_ERR_OK;
    p->sz = sizeof(blob);
    strcpy(p->blob, ctx->svc_name);

    err = ipclite_client_transact(client, &blob, sizeof(blob), &rsp, &rsp_sz, timeout);
    if(err == IPCLITE_ERR_OK)  {
        p = (parcel *)&rsp;
        err = p->err;
        if(rsp_sz == sizeof(rsp))  {
            if(err == RPC_ERR_OK)  {
                ctx->svc_id = p->svc;
                if(ctx->svc_id)  {
                    ctx->ipc = client;
                    ctx->state |= SVC_STATE_CONNECTED;
                    return RPC_ERR_OK;
                }
            }
        }
        if(err == RPC_ERR_OK)
            err = RPC_ERR_GEN;
        return err;
    }
    return RPC_ERR_TRANS;
}

int rpclite_connect_svc(rpclite_ctx *ctx, ipclite *client, int flags, int timeout)
{
    if(! ctx || ! client || ipclite_type(client) != IPCLITE_CLIENT
       || ! ctx->svc_name || ! *ctx->svc_name || (ctx->state & SVC_STATE_CONNECTED))
        return -1;

    return connect_svc(ctx, client, flags, timeout);
}

static int __do_transact_canonical(ipclite *client, const void *blob, size_t sz,
                                   void *rsp, size_t *rsp_sz, int timeout)
{
    char blob_rsp[sizeof(parcel) + *rsp_sz];
    parcel *p = (parcel *)&blob_rsp;
    size_t rsp_blob_sz = sizeof(blob_rsp);
    int err = ipclite_client_transact(client, blob, sz, &blob_rsp, &rsp_blob_sz, timeout);

    if(err == IPCLITE_ERR_OK)  {
        assert(rsp_blob_sz <= sizeof(blob_rsp));
        assert(rsp_blob_sz >= sizeof(parcel));
        assert(p->sz == rsp_blob_sz);
        err = p->err;
        if(err == RPC_ERR_OK)  {
            *rsp_sz = p->sz - sizeof(parcel);
            if(*rsp_sz > 0)
                memcpy(rsp, &p->blob, *rsp_sz);
        }
        return err;
    }
    return RPC_ERR_TRANS;
}


static int __transact_canonical(rpclite_ctx *ctx, int req, const void *blob, size_t sz,
                                rpclite_rsp *rsp, int timeout)
{
    char blob_req[sizeof(parcel) + sz];
    parcel *p = (parcel *)&blob_req;

    if(req < RPCLITE_REQ_BASE || (! blob && sz))
        return -1;

    p->svc = ctx->svc_id;
    p->req = req;
    p->sz = sizeof(blob_req);
    if(blob)
        memcpy(&p->blob, blob, sz);
    if(! rsp || ! rsp->rsp)
        return (ipclite_client_transact(ctx->ipc, &blob_req, sizeof(blob_req), NULL, NULL, timeout)
                ? RPC_ERR_TRANS : RPC_ERR_OK);
    return __do_transact_canonical(ctx->ipc, &blob_req, sizeof(blob_req), rsp->rsp, rsp->sz, timeout);
}

static int __transact_cb(ipclite_msg *msg, void *ud)
{
    rpclite_rsp *rsp = (rpclite_rsp *)ud;
    parcel *p = MSG_PAYLOAD(parcel, msg);
    size_t payload = msg->hdr.len - sizeof(ipclite_msg_hdr);
    size_t copy;

    assert(msg->hdr.len > sizeof(ipclite_msg_hdr));
    assert(payload >= sizeof(parcel));

    if(rsp)  {
        if(p->err)  {
            /* return directly if encountered error */
            rsp->rsv2 = p->err;
        }else if(rsp->type == RPCLITE_RSP_BLOB)  {
            if(rsp->rsp && rsp->sz)  {
                assert(rsp->rsv1 >= *rsp->sz);

                copy = payload - sizeof(parcel);
                if(copy > (rsp->rsv1 - *rsp->sz))  {
                    /* return size error */
                    rsp->rsv2 = RPC_ERR_SIZE;
                    return 0;
                }
                memcpy((char *)rsp->rsp + *rsp->sz, p->blob, copy);
                *rsp->sz += copy;
                return 1;
            }
        }else if(rsp->type == RPCLITE_RSP_CALLBACK)  {
            if(rsp->cb)
                return rsp->cb(p->blob, p->sz - sizeof(parcel),
                               (msg->hdr.msg == IPCLITE_MSG_RXE) ? RPCLITE_RSP_F_END : 0, rsp->ud);
        }else  {
            /* should never happen */
            assert(0);
        }
    }
    return 0;
}

static int __transact(rpclite_ctx *ctx, int req, const void *blob, size_t sz,
                      rpclite_rsp *rsp, int timeout)
{
    char blob_req[sizeof(parcel) + sz];
    parcel *p = (parcel *)&blob_req;

    if(req >= RPCLITE_REQ_BASE && (blob || ! sz))  {
        p->svc = ctx->svc_id;
        p->req = req;
        p->sz = sizeof(blob_req);
        if(blob)
            memcpy(&p->blob, blob, sz);
        if(rsp->type == RPCLITE_RSP_BLOB)  {
            if(rsp->rsp)  {
                if(! rsp->sz)
                    return RPC_ERR_GEN;
                rsp->rsv1 = *rsp->sz;
                *rsp->sz = 0;
            }
            rsp->rsv2 = RPC_ERR_OK;
            if(ipclite_client_transact_ex(ctx->ipc, blob_req, sizeof(blob_req),
                                          __transact_cb, rsp, timeout) == IPCLITE_ERR_OK)
                return rsp->rsv2;
            return RPC_ERR_OK;
        }
        if(ipclite_client_transact_ex(ctx->ipc, blob_req, sizeof(blob_req),
                                      __transact_cb, rsp, timeout) != IPCLITE_ERR_OK)
            return RPC_ERR_TRANS;
        return RPC_ERR_OK;
    }

    return RPC_ERR_GEN;
}

/**
 * @rsp: set to NULL to ignore.
 */
int __rpclite_transact_full(rpclite_ctx *ctx, rpclite_req *req, rpclite_rsp *rsp)
{
    if(req->type == RPCLITE_REQ_CANONICAL)
        return __transact_canonical(ctx, req->req, req->blob, req->sz, rsp, req->timeout);
    return __transact(ctx, req->req, req->blob, req->sz, rsp, req->timeout);
}

static unsigned long svc_hash(void *key)
{
    return (*(int *)key) % SVC_TABLE_SIZE;
}

static int svc_cmp(hlist *h, void *k)
{
    rpclite_svc *svc = hlist_entry(h, rpclite_svc, node);

    return svc->svc_id - *(int *)k;
}

static void svc_free(hlist *h)
{
    /* nothing to do */
}

static inline void response_err(int type, parcel *req, int err, ipclite_response rsp, void *ud)
{
    char blob[sizeof(parcel)];
    parcel *p = (parcel *)&blob;
    int flags = 0;

    p->svc = req->svc;
    p->req = req->req;
    p->err = err;
    p->sz = sizeof(blob);
    if(type == RPCLITE_TYPE_EXTENDED)
        flags |= IPCLITE_RSP_END;
    rsp(&blob, sizeof(blob), flags, ud);
}

static inline void __confirm_syn(int id, ipclite_response rsp, void *ud)
{
    char blob[sizeof(parcel)];
    parcel *p = (parcel *)&blob;

    p->svc = id;
    p->req = 0;
    p->err = RPC_ERR_OK;
    if(id == 0)
        p->err = RPC_ERR_NOSVC;
    p->sz = sizeof(blob);
    rsp(&blob, sizeof(blob), 0, ud);
}

static inline void confirm_syn(const char *svc_name, size_t sz, ipclite_response rsp, void *ud)
{
    rpclite_svc *iter;
    hlist_head *head;
    hlist *pos;
    int svc_id;
    size_t i;

    /* must non-empty and nul terminated */
    if(sz > 0 && ! svc_name[sz - 1])  {
        pthread_mutex_lock(&svc_lock);
        htable_for_each_head(i, head, svc_table)  {
            hlist_for_each_entry(iter, pos, head, node)  {
                if(! strcmp(svc_name, iter->svc_name))  {
                    svc_id = iter->svc_id;
                    pthread_mutex_unlock(&svc_lock);
                    __confirm_syn(svc_id, rsp, ud);
                    return;
                }
            }
        }
        pthread_mutex_unlock(&svc_lock);
    }
    __confirm_syn(0, rsp, ud);
}

static int rpc_response(const void *blob, size_t sz, int flags, void *ud)
{
    transact_ctx *ctx = (transact_ctx *)ud;
    char blob_rsp[sizeof(parcel) + sz];
    parcel *req = ctx->req;
    parcel *p = (parcel *)&blob_rsp;
    int ipc_flags = 0, err;

    p->svc = req->svc;
    p->req = req->req;
    p->err = RPC_ERR_OK;
    p->sz = sizeof(parcel) + sz;
    if(sz)
        memcpy(&p->blob, blob, sz);

    if(flags & RPCLITE_RSP_SYN)
        ipc_flags |= IPCLITE_RSP_SYN;

    if(ctx->flags & TRANSACT_F_EXTENDED)  {
        if(ctx->flags & TRANSACT_F_DONE)
            return RPC_ERR_GEN;
        if(! (flags & RPCLITE_RSP_MORE))
            ipc_flags |= IPCLITE_RSP_END;
    }else  {
        if(ctx->flags & TRANSACT_F_RESPONDED)
            return RPC_ERR_GEN;
    }

    err = ctx->rsp(&blob_rsp, sizeof(blob_rsp), ipc_flags, ctx->rsp_ud);
    /* make retry if incase failed */
    if(err == IPCLITE_ERR_OK)  {
        ctx->flags |= TRANSACT_F_RESPONDED;
        if(! (flags & RPCLITE_RSP_MORE))
            ctx->flags |= TRANSACT_F_DONE;
    }
    return err;
}

static void __on_transact(int type, rpclite_svc *svc, parcel *req, ipclite_response rsp, void *rsp_ud)
{
    transact_ctx ctx = {
        .req = req,
        .rsp = rsp,
        .rsp_ud = rsp_ud,
        .flags = 0,
    };
    int err;

    if(type == RPCLITE_TYPE_EXTENDED)
        ctx.flags = TRANSACT_F_EXTENDED;
    err = svc->handler(req->req, req->blob, req->sz - sizeof(parcel), rpc_response, (void *)&ctx, svc->ud);

    if(! (ctx.flags & TRANSACT_F_RESPONDED)
       || ((ctx.flags & TRANSACT_F_EXTENDED)
           && ! (ctx.flags & TRANSACT_F_DONE)))
        response_err(type, req, err, rsp, rsp_ud);
}

static void on_transact(int type, unsigned int peer, const void *blob, size_t sz,
                        ipclite_response rsp, void *rsp_ud, void *ud)
{
    rpclite_svc *svc;
    hlist *node;
    parcel *p = (parcel *)blob;
    int err;

    assert(sz >= sizeof(parcel) && p->sz == sz);
    if(! p->svc)  {
        confirm_syn((const char *)&p->blob, p->sz - sizeof(parcel), rsp, rsp_ud);
        return;
    }

    pthread_mutex_lock(&svc_lock);
    if(! (node = htable_find_node(svc_table, &p->svc)))  {
        response_err(type, p, RPC_ERR_NOSVC, rsp, rsp_ud);
        pthread_mutex_unlock(&svc_lock);
        return;
    }

    svc = hlist_entry(node, rpclite_svc, node);
    __on_transact(type, svc, p, rsp, rsp_ud);

    pthread_mutex_unlock(&svc_lock);
}

static void on_transact_canonical(unsigned int peer, const void *blob, size_t sz,
                            ipclite_response rsp, void *rsp_ud, void *ud)
{
    on_transact(RPCLITE_TYPE_CANONICAL, peer, blob, sz, rsp, rsp_ud, ud);
}

static void on_transact_ex(unsigned int peer, const void *blob, size_t sz,
                        ipclite_response rsp, void *rsp_ud, void *ud)
{
    on_transact(RPCLITE_TYPE_EXTENDED, peer, blob, sz, rsp, rsp_ud, ud);
}

static inline int init_svc_table(void)
{
    htable *t = (htable *)malloc(htable_size(SVC_TABLE_SIZE));

    if(t)  {
        htable_init(t, SVC_TABLE_SIZE, svc_hash, svc_cmp, svc_free);
        svc_table = t;
        return 0;
    }
    return -1;
}

int rpclite_server_attach(ipclite *srv)
{
    if(! srv || ipclite_type(srv) != IPCLITE_SERVER)
        return -1;

    pthread_mutex_lock(&svc_lock);
    if((! svc_table && init_svc_table())
       || svc_ipc
       || ipclite_server_set_transact(srv, on_transact_canonical, NULL)
       || ipclite_server_set_transact_ex(srv, on_transact_ex, NULL))  {
        pthread_mutex_unlock(&svc_lock);
        return -1;
    }
    svc_ipc = srv;
    pthread_mutex_unlock(&svc_lock);
    return 0;
}

int rpclite_svc_register(rpclite_svc *svc)
{
    rpclite_svc *iter;
    hlist_head *head;
    hlist *pos;
    int svc_id;
    size_t i;

    if(! svc || ! svc->svc_name || ! *svc->svc_name)
        return -1;

    pthread_mutex_lock(&svc_lock);
    htable_for_each_head(i, head, svc_table)  {
        hlist_for_each_entry(iter, pos, head, node)  {
            if(svc == iter || ! strcmp(svc->svc_name, iter->svc_name))  {
                pthread_mutex_unlock(&svc_lock);
                return -1;
            }
        }
    }

 alloc_id:
    svc_id = ++svc_id_seq;

    if(svc_id == 0)             /* 0 reserved */
        svc_id = ++svc_id_seq;
    htable_for_each_head(i, head, svc_table)  {
        hlist_for_each_entry(iter, pos, head, node)  {
            if(iter->svc_id == svc_id)
                goto alloc_id;
        }
    }

    svc->svc_id = svc_id;
    htable_insert(svc_table, (void *)&svc_id, &svc->node);
    pthread_mutex_unlock(&svc_lock);
    return 0;
}

int rpclite_svc_unregister(rpclite_svc *svc)
{
    rpclite_svc *iter;
    hlist_head *head;
    hlist *pos;
    size_t i;

    pthread_mutex_lock(&svc_lock);
    htable_for_each_head(i, head, svc_table)  {
        hlist_for_each_entry(iter, pos, head, node)  {
            if(iter == svc)  {
                htable_delete(svc_table, (void *)&svc->svc_id);
                pthread_mutex_unlock(&svc_lock);
                return 0;
            }
        }
    }
    pthread_mutex_unlock(&svc_lock);
    return -1;
}

