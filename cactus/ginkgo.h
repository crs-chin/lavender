/*
 * ginkgo.h  A Message Engine
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

#ifndef __GINKGO_H
#define __GINKGO_H

#include <string.h>
#include <malloc.h>
#include <sys/types.h>

#include "util.h"

__BEGIN_DECLS

#define GINKGO_SRC_INV (-1)

#define GINKGO_ERR_PENDING 1
#define GINKGO_ERR_OK 0
#define GINKGO_ERR_PORT_CLOSED (-1)
#define GINKGO_ERR_PORT_NOT_AVAIL (-2)
#define GINKGO_ERR_NO_SRC (-3)
#define GINKGO_ERR_NO_RESP (-4)
#define GINKGO_ERR_GEN (-5)
#define GINKGO_ERR_INV (-6)
#define GINKGO_ERR_PIPE (-7)
#define GINKGO_ERR_OOM (-8)
#define GINKGO_ERR_THREAD (-9)
#define GINKGO_ERR_WAIT (-10)

typedef struct _ginkgo_ctx ginkgo_ctx;
typedef struct _ginkgo_src ginkgo_src;

typedef struct _ginkgo_msg ginkgo_msg;

typedef ssize_t (*ginkgo_read)(int fd, void *buf, size_t cnt);
typedef ssize_t (*ginkgo_writ)(int fd, const ginkgo_msg *msg, const void *buf, size_t cnt);

/**
 * parse msg from buf, return 0 if nothing parsed, otherwise the
 * length of parsed.
 */
typedef int (*ginkgo_pars)(void *buf, size_t cnt, ginkgo_msg **msg);

#define GINKGO_RESP_DONE 0
#define GINKGO_RESP_CONT 1
#define GINKGO_RESP_INVA -1

typedef int (*ginkgo_resp)(ginkgo_msg *msg, ginkgo_msg *rsp);

/**
 * default msg handler, msg handled if non-zero returned.
 */
typedef int (*ginkgo_hand)(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud);


struct _ginkgo_src{
    char *name;
    int fd;
    ginkgo_read rd;             /* sys read if NULL */
    ginkgo_writ wr;             /* sys write if NULL */

    ginkgo_pars pars;
    ginkgo_resp resp;
    ginkgo_hand hand;           /* default handler if not NULL */
    void *ud;
};

#define GINKGO_MSG_NO_FREE 1
#define GINKGO_MSG_WAIT (1<<1)
#define GINKGO_MSG_REQ  (1<<2)
#define GINKGO_MSG_RESP (1<<3)

#define GINKGO_MSG_MASK ((1<<4) - 1)

struct _ginkgo_msg{
    int src;
    int flg;
    int len;
    int err;
    list lst;
    char prv[sizeof(void *) * 2]; /* ginko private */
    char cmn[40];                 /* useable to external modules */
    char payload[0];
};

#define list_ginkgo_msg(ptr)                    \
    list_entry((ptr), ginkgo_msg, lst)

#define list_for_each_ginkgo_msg(iter,head)         \
    for(iter = list_ginkgo_msg((head)->l_nxt),      \
            &iter->lst != (head);                   \
        iter = list_ginkgo_msg(iter->lst.l_nxt))

#define list_for_each_ginkgo_msg_safe(iter,n,head)      \
    for(iter = list_ginkgo_msg((head)->l_nxt),          \
            n = list_ginkgo_msg(iter->lst.l_nxt);       \
        &iter->lst != (head);                           \
        iter = n, n = list_ginkgo_msg(iter->lst.l_nxt))

#define GINKGO_MSG_PAYLOAD(msg,type)  ((type *)&((msg)->payload))
#define GINKGO_MSG_OK(msg,len)                          \
    (len >= sizeof(ginkgo_msg) && len >= (msg)->len)
#define GINKGO_MSG_NEXT(msg,len)                                    \
    (len -= msg->len, (ginkgo_msg *)(((char *)(msg)) + (msg)->len))
#define GINKGO_MSG_LENGTH(payload)  ((payload) + sizeof(ginkgo_msg))


/**
 * @flags: reserved for extension
 */
int ginkgo_create(ginkgo_ctx **ctx, int flags);

/**
 * handle msgs in separate thread
 */
#define SF_HANDLER_THREAD 1

int ginkgo_src_register(ginkgo_ctx *ctx, const ginkgo_src *src, int *id, int flags);
/**
 * not reentrantablem, should not be called simultaneously.
 * @wait: wait only pending out messages.
 */
int ginkgo_src_deregister(ginkgo_ctx *ctx, int src, int wait, int force);

int ginkgo_run(ginkgo_ctx *ctx);
int ginkgo_quit(ginkgo_ctx *ctx, int wait);

int ginkgo_queue_msg(ginkgo_ctx *ctx, ginkgo_msg *msg);

int ginkgo_sendmsg(ginkgo_ctx *ctx, ginkgo_msg *msg, int wait, int free);
int ginkgo_request(ginkgo_ctx *ctx, ginkgo_msg *msg, list *rsp, int free);

/**
 * @src: GINKGO_SRC_INV marks all available.
 */
ginkgo_msg *ginkgo_recvmsg(ginkgo_ctx *ctx, int src);
ginkgo_msg *ginkgo_peekmsg(ginkgo_ctx *ctx, int src);

void ginkgo_destroy(ginkgo_ctx *cxt);

static ginkgo_msg *ginkgo_new_msg(int src, size_t payload)
{
    ginkgo_msg *msg = (ginkgo_msg *)malloc(GINKGO_MSG_LENGTH(payload));

    if(msg)  {
        memset(msg, 0, sizeof(ginkgo_msg));
        msg->src = src;
        msg->len = GINKGO_MSG_LENGTH(payload);
    }
    return msg;
}

__END_DECLS

#endif  /* __GINKGO_H */

