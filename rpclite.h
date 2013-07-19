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

#ifndef __RPCLITE_H
#define __RPCLITE_H

#include <sys/types.h>
#include <pthread.h>

#include "util.h"
#include "ipclite.h"

__BEGIN_DECLS

typedef struct _rpclite_ctx rpclite_ctx;

typedef struct _rpclite_req rpclite_req;
typedef struct _rpclite_rsp rpclite_rsp;

#define RPCLITE_REQ_BASE 100

#define RPCLITE_RSP_SYN 1       /* synchronous response call */
#define RPCLITE_RSP_MORE (1<<1)  /* more data awaiting */

typedef int (*rpclite_response)(const void *blob, size_t sz, int flags, void *ud);

#define RPCLITE_RSP_F_END 1     /* last piece of response blob, may
								   not carry payload */
/* return zero to ignore subsequence blobs */
typedef int (*rpclite_cb)(void *rsp, size_t sz, int flags, void *ud);

struct _rpclite_ctx{
    char *svc_name;
    /* private */
    ipclite *ipc;
    int state;
    int svc_id;
};


enum{
    RPCLITE_REQ_CANONICAL,
    RPCLITE_REQ_EXTENDED,
};

struct _rpclite_req{
    int type;
    int req;
    const void *blob;
    size_t sz;
    int timeout;
};

enum{
    RPCLITE_RSP_BLOB,
    RPCLITE_RSP_CALLBACK,
};

struct _rpclite_rsp{
    int type;
    union{
        struct{
            void *rsp;
            size_t *sz;
            size_t rsv1;
            int rsv2;
        };
        struct{
            rpclite_cb cb;
            void *ud;
        };
    };
};

/**
 * @flags: unused currently
 * @timeout: unit in ms
 */
int rpclite_connect_svc(rpclite_ctx *ctx, ipclite *client, int flags, int timeout);

static inline void rpclite_disconnect_svc(rpclite_ctx *ctx)
{
    /* actually a stateless connection */
    ctx->ipc = NULL;
    ctx->state = 0;
    ctx->svc_id = 0;
}

#define RPC_ERR_OK      0
#define RPC_ERR_GEN     (-1)    /* general */
#define RPC_ERR_NOSVC   (-2)    /* no service */
#define RPC_ERR_NOSUP   (-3)    /* no support */
#define RPC_ERR_TRANS   (-4)    /* transact error */
#define RPC_ERR_SIZE    (-5)    /* buffer size error */

#define RPC_ERR_BASE     (-100) /* svc err code base */

/**
 * @rsp: set to NULL to ignore response blob.
 */
int __rpclite_transact_full(rpclite_ctx *ctx, rpclite_req *req, rpclite_rsp *rsp);

static inline int rpclite_transact_full(rpclite_ctx *ctx,
                                        int type, int req, const void *blob, size_t sz,
                                        rpclite_rsp *rsp,
                                        int timeout)
{
    rpclite_req rreq = {
        .type = type,
        .req = req,
        .blob = blob,
        .sz = sz,
        .timeout = timeout,
    };

    return __rpclite_transact_full(ctx, &rreq, rsp);
}

/**
 * @rsp: set to NULL to ignore response blob.
 * @rsp_sz: size of @rsp as input, actual size on return.
 * @timeout: unit in ms.
 */
static inline int
rpclite_transact(rpclite_ctx *ctx, int req,
                 const void *blob, size_t sz,
                 void *rsp, size_t *rsp_sz, int timeout)
{
    rpclite_rsp rrsp;

    rrsp.type = RPCLITE_RSP_BLOB;
    rrsp.rsp = rsp;
    rrsp.sz = rsp_sz;
    return rpclite_transact_full(ctx, RPCLITE_REQ_EXTENDED, req, blob, sz, &rrsp, timeout);
}

/**
 * ignore response data.
 */
static inline int
rpclite_transact_simple(rpclite_ctx *ctx, int req,
                        const void *blob, size_t sz, int timeout)
{
    return rpclite_transact(ctx, req, blob, sz, NULL, NULL, timeout);
}

/**
 * @rsp: set to NULL to ignore response blob.
 * @rsp_sz: size of @rsp as input, actual size on return.
 * @timeout: unit in ms.
 */
static inline int
rpclite_transact_blob(rpclite_ctx *ctx, int req,
                      const void *blob, size_t sz,
                      void *rsp, size_t *rsp_sz, int timeout)
{
    return rpclite_transact(ctx, req, blob, sz, rsp, rsp_sz, timeout);
}

/**
 * @cb: callback to handle response data, set to NULL to ignore
 * response data.
 * @timeout: unit in ms.
 */
static inline int
rpclite_transact_callback(rpclite_ctx *ctx, int req,
                          const void *blob, size_t sz,
                          rpclite_cb cb, void *ud, int timeout)
{
    rpclite_rsp rrsp;

    rrsp.type = RPCLITE_RSP_CALLBACK;
    rrsp.cb = cb;
    rrsp.ud = ud;
    return rpclite_transact_full(ctx, RPCLITE_REQ_EXTENDED, req, blob, sz, &rrsp, timeout);
}

/**
 * Depreciated:
 * based canonical ipclite's rpc, callback style response not
 * supported
 */
static inline int
rpclite_transact_canonical(rpclite_ctx *ctx, int req,
                           const void *blob, size_t sz,
                           void *rsp, size_t *rsp_sz, int timeout)
{
    rpclite_rsp rrsp;

    rrsp.type = RPCLITE_RSP_BLOB;
    rrsp.rsp = rsp;
    rrsp.sz = rsp_sz;
    return rpclite_transact_full(ctx, RPCLITE_REQ_CANONICAL, req, blob, sz, &rrsp, timeout);
}

__END_DECLS

#endif  /* __RPCLITE_H */

