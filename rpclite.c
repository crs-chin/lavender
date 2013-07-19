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

