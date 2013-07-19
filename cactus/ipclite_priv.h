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

#ifndef __IPCLITE_PRIV_H
#define __IPCLITE_PRIV_H

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pthread.h>
#include <time.h>

#include "cust.h"
#include "ipclite.h"

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#define arraysize(a)  (sizeof(a)/sizeof(a[0]))

#define offset_of(type,member)                  \
    ((size_t)&((type *)0)->member)

#define container_of(ptr,type,member)           \
    (type *)((unsigned char *)(ptr) - offset_of(type,member))

#define new_instance(type) (type *)malloc(sizeof(type))

#define build_fail_on(exp) ((void)sizeof(char[1 - 2 * (!!(exp))]))

#define MAX(a,b)  ({typeof(a) _a = a; typeof(b) _b = b; ((_a > _b) ? _a : _b);})

#define LOGERROR(fmt,args...) fprintf(stderr, "[ERROR]" fmt "\n", ##args)
#define LOGWARN(fmt,args...) fprintf(stderr, "[WARN]" fmt "\n", ##args)
#define LOGINFO(fmt,args...) fprintf(stdout, "[INFO]" fmt "\n", ##args)
#define LOGDEBUG(fmt,args...) fprintf(stdout, "[DEBUG]" fmt "\n", ##args)

#define IPCLITE_BUF_SIZE (1024 * 8)

typedef struct _list list;

typedef struct _ipclite_port ipclite_port;

typedef struct _ipclite_msg_ctl ipclite_msg_ctl;

typedef struct _ipclite_server ipclite_server;
typedef struct _ipclite_client ipclite_client;

typedef struct _transact_ctx transact_ctx;
typedef struct _transact_rsp transact_rsp;

struct _list{
    list *l_nxt;
    list *l_prv;
};

struct _ipclite_port{
    int fd;
    int state;
    ipclite_msg *msg;
    unsigned int msg_offset;
    list msgs;                 /* out msgs */
    unsigned int len;
    unsigned char buf[IPCLITE_BUF_SIZE];
};

struct _ipclite_msg_ctl{
    list list;
    time_t stamp;
    int cmmt:1,                 /* commited */
        wait:1,
        free:1;
    int err;
};

struct _ipclite{
    unsigned int type;

    char *msg;

    ipclite_handler handler;
    ipclite_transact transact;
    ipclite_transact_ex transact_ex;
    void *ud;
    void *ud_transact;
    void *ud_transact_ex;

    unsigned int seq;

    int master;
    char path[UNIX_PATH_MAX];
};

struct _transact_ctx{
    ipclite *ipc;
    unsigned int peer;
    unsigned int id;
#define TRANSACT_F_RSP  (1<<1)  /* responded ever */
#define TRANSACT_F_DONE (1<<2)  /* done responding */
    unsigned int flags;
};

enum{
    TRANSACT_RSP_CANONICAL,
    TRANSACT_RSP_EXTENDED,
};

struct _transact_rsp{
    int type;
    union{
        struct{
            void *blob;
            size_t *sz;
        };
        struct {
            ipclite_handler cb;
            void *ud;
#define TRANSACT_RSP_F_CONTINUE 1
#define TRANSACT_RSP_F_DONE (1<<1)
            int flags;
        };
    };
};

enum{
    PORT_OPENING,
    PORT_OPENED,
    PORT_CLOSING,
    PORT_CLOSED,
};

static inline void list_init(list *l)
{
    l->l_nxt = l;
    l->l_prv = l;
}

static inline void list_append(list *h, list *elem)
{
    elem->l_prv = h->l_prv;
    elem->l_nxt = h;
    elem->l_prv->l_nxt = elem;
    h->l_prv = elem;
}

static inline void list_insert(list *l, list *elem)
{
    elem->l_prv = l;
    elem->l_nxt = l->l_nxt;
    elem->l_nxt->l_prv = elem;
    l->l_nxt = elem;
}

static inline void list_delete(list *l)
{
    l->l_nxt->l_prv = l->l_prv;
    l->l_prv->l_nxt = l->l_nxt;
    list_init(l);
}


static inline int list_empty(list *h)
{
    return (h->l_nxt == h);
}

static inline void list_assign(list *to, list *from)
{
    if(! list_empty(from))  {
        to->l_nxt = from->l_nxt;
        to->l_prv = from->l_prv;
        from->l_nxt->l_prv = to;
        from->l_prv->l_nxt = to;
        list_init(from);
    }else  {
        list_init(to);
    }
}

static inline ipclite_msg_ctl *msg_ctl(ipclite_msg *msg)
{
    return (ipclite_msg_ctl *)&msg->ctl;
}


static inline void msg_init_ctl(ipclite_msg *msg, int wait, int free)
{
    ipclite_msg_ctl *ctl;

    ctl = msg_ctl(msg);

    list_init(&ctl->list);
    time(&ctl->stamp);
    ctl->cmmt = 0;
    ctl->wait = !! wait;
    ctl->free = (! wait && free);
    ctl->err = IPCLITE_ERR_OK;
}

static inline list *msg_list_ptr(ipclite_msg *msg)
{
    return &((ipclite_msg_ctl *)&msg->ctl)->list;
}

#define list_entry(ptr,type,member)       \
    container_of((ptr),type,member)

#define list_msg(ptr)                                                   \
    ({ipclite_msg_ctl *ctl = list_entry(ptr, ipclite_msg_ctl, list);    \
        list_entry(ctl, ipclite_msg, ctl);})

#define list_for_each(iter,head)                                    \
    for(iter = (head)->l_nxt; iter != (head); iter = iter->l_nxt)

#define list_for_each_entry(iter,head,member)                       \
    for(iter = list_entry((head)->l_nxt,typeof(*iter),member);      \
        &(iter)->member != (head);                                  \
        iter = list_entry(iter->member.l_nxt,typeof(*iter),member))

#define list_for_each_entry_safe(iter,n,head,member)                    \
    for(iter = list_entry((head)->l_nxt,typeof(*iter),member),          \
            n = list_entry(iter->member.l_nxt,typeof(*iter),member);    \
        &(iter)->member != (head);                                      \
        iter = n, n = list_entry(iter->member.l_nxt,typeof(*iter),member))

#define list_for_each_msg_safe(iter,n,head)                 \
    for(iter = list_msg((head)->l_nxt),                     \
            n = list_msg(msg_list_ptr(iter)->l_nxt);        \
        &((ipclite_msg_ctl *)(iter->ctl))->list != (head);  \
        iter = n, n = list_msg(msg_list_ptr(iter)->l_nxt))

static inline void ipclite_port_init(ipclite_port *port, int fd)
{
    port->fd = fd;
    port->state = PORT_CLOSED;
    port->msg = NULL;
    port->msg_offset = 0;
    list_init(&port->msgs);
    port->len = 0;
}

static inline void *memdup(const void *src, size_t len)
{
    void *dest = malloc(len);

    if(dest)
        memcpy(dest, src, len);
    return dest;
}


ipclite_msg *new_syn_msg(unsigned int peer, const char *hi);
ipclite_msg *new_cls_msg(unsigned int peer);
ipclite_msg *__new_rsp_msg(unsigned int peer, unsigned int msgid,
                           unsigned int id, int err,
                           const void *blob, size_t sz);
int __transact_rsp(ipclite_msg *rsp, transact_rsp *trsp);

static inline ipclite_msg *
new_rsp_msg(unsigned int peer, unsigned int id, int err,
            const void *blob, size_t sz)
{
    return __new_rsp_msg(peer, IPCLITE_MSG_RSP, id, err, blob, sz);
}

static inline ipclite_msg *
new_rpx_msg(unsigned int peer, unsigned int id, int err,
            const void *blob, size_t sz)
{
    return __new_rsp_msg(peer, IPCLITE_MSG_RPX, id, err, blob, sz);

}

static inline ipclite_msg *
new_rxe_msg(unsigned int peer, unsigned int id, int err,
            const void *blob, size_t sz)
{
    return __new_rsp_msg(peer, IPCLITE_MSG_RXE, id, err, blob, sz);

}

#define IPCLITE_MSG_OK(hdr,len)                     \
    ((unsigned int)len >= sizeof(ipclite_msg_hdr)   \
     && hdr->len >= sizeof(ipclite_msg_hdr)         \
     && (unsigned int)len >= hdr->len)

#define IPCLITE_MSG_NEXT(hdr,len)               \
    (len -= hdr->len, (ipclite_msg_hdr *)(((char *)hdr) + hdr->len))

#if ! HAVE_PIPE2
int pipe2(int fd[2], int flags);
#endif

#endif  /* __IPCLITE_PRIV_H */
