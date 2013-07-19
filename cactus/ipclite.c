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

#include "ipclite.h"
#include "ipclite_priv.h"


static const char *err_tbl[] = {
    "Message pending",
    "No error",
    "Generic error",
    "Invalid parameter",
    "Socket error",
    "Bind error",
    "Listen error",
    "Pipe error",
    "Peer error",
    "Out of memory",
    "Permission denied",
    "Thread error",
    "Wait error",
    "Connect error",
    "Timed out",
    "Not supported",
    "Not responded",
    "Responded again",
    "Size error",
};

const char *ipclite_err_string(int err)
{
    err = 1 - err;

    if(err >= 0 && (size_t)err < arraysize(err_tbl))
        return err_tbl[err];
    return "Unknown error";
}


ipclite_msg *new_syn_msg(unsigned int peer, const char *hi)
{
    ipclite_msg *msg;
    ipclite_msg_ctl *ctl;
    ipclite_msg_syn *syn;
    size_t extra = ((hi && *hi) ? strlen(hi) : 0);
    size_t payload  = sizeof(ipclite_msg_syn) + extra;

    if((msg = ipclite_msg_alloc(peer, 0, IPCLITE_MSG_SYN, payload)))  {
        ctl = msg_ctl(msg);

        list_init(&ctl->list);
        time(&ctl->stamp);
        ctl->cmmt = 0;
        ctl->wait = 0;
        ctl->free = 1;
        ctl->err = IPCLITE_ERR_OK;

        syn = MSG_PAYLOAD(ipclite_msg_syn, msg);
        syn->peer = peer;
        syn->len = extra;
        strncpy(syn->msg, hi, extra);
    }
    return msg;
}


ipclite_msg *new_cls_msg(unsigned int peer)
{
    ipclite_msg *msg;
    ipclite_msg_ctl *ctl;
    ipclite_msg_cls *cls;
    size_t payload  = sizeof(ipclite_msg_cls);

    if((msg = ipclite_msg_alloc(peer, 0, IPCLITE_MSG_CLS, payload)))  {
        ctl = msg_ctl(msg);

        list_init(&ctl->list);
        time(&ctl->stamp);
        ctl->cmmt = 0;
        ctl->wait = 0;
        ctl->free = 1;
        ctl->err = IPCLITE_ERR_OK;

        cls = MSG_PAYLOAD(ipclite_msg_cls, msg);
        cls->peer = peer;
    }
    return msg;
}

ipclite_msg *__new_rsp_msg(unsigned int peer, unsigned int msgid,
                           unsigned int id, int err,
                           const void *blob, size_t sz)
{
    ipclite_msg *msg;
    ipclite_msg_ctl *ctl;

    if((msg = ipclite_msg_alloc(peer, id, msgid, sz)))  {
        ctl = msg_ctl(msg);

        list_init(&ctl->list);
        time(&ctl->stamp);
        ctl->cmmt = 0;
        ctl->wait = 0;
        ctl->free = 1;
        ctl->err = err;

        if(sz > 0)
            memcpy(MSG_PAYLOAD(void, msg), blob, sz);
    }
    return msg;
}

int __transact_rsp(ipclite_msg *rsp, transact_rsp *trsp)
{
    size_t rsp_sz;

    if(trsp->type == TRANSACT_RSP_CANONICAL)  {
        if(trsp->blob)  {
            rsp_sz = rsp->hdr.len - sizeof(ipclite_msg_hdr);
            if(rsp_sz > *trsp->sz)
                return IPCLITE_ERR_SIZ;
            *trsp->sz = rsp_sz;
            memcpy(trsp->blob, MSG_PAYLOAD(const void,rsp), rsp_sz);
        }
        return IPCLITE_ERR_OK;
    }

    if(trsp->type == TRANSACT_RSP_EXTENDED)  {
        assert(! (trsp->flags & TRANSACT_RSP_F_DONE));
        if(trsp->cb && (trsp->flags & TRANSACT_RSP_F_CONTINUE) && ! trsp->cb(rsp, trsp->ud))
            trsp->flags &= ~TRANSACT_RSP_F_CONTINUE;
        if(rsp->hdr.msg == IPCLITE_MSG_RXE)
            trsp->flags |= TRANSACT_RSP_F_DONE;
        return IPCLITE_ERR_OK;
    }

    /* should never reach here */
    assert(0);
    return IPCLITE_ERR_GEN;
}

static void build_check(void)
{
    ipclite_msg msg;

    build_fail_on(sizeof(ipclite_msg_ctl) > sizeof(msg.ctl));
}

