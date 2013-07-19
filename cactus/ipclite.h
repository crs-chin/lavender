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

#ifndef __IPCLITE_H
#define __IPCLITE_H

#include <malloc.h>
#include <sys/types.h>

__BEGIN_DECLS

#define IPCLITE_ERR_PND 1       /* msg pending */
#define IPCLITE_ERR_OK 0        /* no error */
#define IPCLITE_ERR_GEN (-1)    /* generic error */
#define IPCLITE_ERR_INV (-2)    /* invalid parameter or msg */
#define IPCLITE_ERR_SCK (-3)    /* socket error */
#define IPCLITE_ERR_BND (-4)    /* bind error */
#define IPCLITE_ERR_LIS (-5)    /* listen error */
#define IPCLITE_ERR_PIP (-6)    /* pipe error */
#define IPCLITE_ERR_PER (-7)    /* peer error */
#define IPCLITE_ERR_OOM (-8)    /* out of memory */
#define IPCLITE_ERR_PEM (-9)    /* permission denied */
#define IPCLITE_ERR_THD (-10)    /* thread error */
#define IPCLITE_ERR_WAT (-11)    /* wait error */
#define IPCLITE_ERR_CNN (-12)    /* connect error */
#define IPCLITE_ERR_TMO (-13)    /* timeout */
#define IPCLITE_ERR_NOS (-14)    /* no support */
#define IPCLITE_ERR_NOR (-15)    /* no response */
#define IPCLITE_ERR_AGN (-16)    /* responded again */
#define IPCLITE_ERR_SIZ (-17)    /* successfully returned, rsp size error */

#define IPCLITE_LENGTH_MAX (1024 *4)
#define IPCLITE_DATA_MAX (IPCLITE_LENGTH_MAX - sizeof(ipclite_msg))

#define IPCLITE_SERVER 0
#define IPCLITE_CLIENT 1

/**
 * new peers can be monitered through SYN messages, and closed peers
 * through CLS messages
 */
#define IPCLITE_MSG_SYN 0       /* first connected msg from server */
#define IPCLITE_MSG_CLS 1       /* peer closed */
#define IPCLITE_MSG_REQ 3       /* transact request */
#define IPCLITE_MSG_RSP 4       /* transact response */
#define IPCLITE_MSG_RQX 5       /* transact request ex */
#define IPCLITE_MSG_RPX 6       /* transact response ex */
#define IPCLITE_MSG_RXE 7       /* transact response ex end */

/* customized message should start after this */
#define IPCLITE_MSG_BASE 1000

typedef struct _ipclite ipclite;

typedef struct _ipclite_peer ipclite_peer;

typedef struct _ipclite_msg_hdr ipclite_msg_hdr;
typedef struct _ipclite_msg ipclite_msg;

typedef struct _ipclite_msg_syn ipclite_msg_syn;
typedef struct _ipclite_msg_cls ipclite_msg_cls;

struct _ipclite_peer{
    unsigned int peer;
    pid_t pid;
    uid_t uid;
    gid_t gid;
};

struct _ipclite_msg_hdr{
    unsigned int peer;                   /* peer identifer */
    unsigned int msg;                    /* msg type */
    unsigned int id;                     /* msg identifer, transparent to ipclite */
    unsigned int len;                    /* msg length */
    unsigned char data[0];               /* msg payload */
};

struct _ipclite_msg{
    char ctl[40];               /* ipclite private */
    ipclite_msg_hdr hdr;
};


struct _ipclite_msg_syn{
    unsigned int peer;
    unsigned int len;
    char msg[0];
};

struct _ipclite_msg_cls{
    unsigned int peer;
};


/**
 * return_value:
 * 1. As generic message handler, non-zero if successfully handled the
 * msg, otherwise the msg will be handled(freed) by the system.
 * 2. As transact message handler, return zero to stop handling
 * furthur response messages
 */
typedef int (*ipclite_handler)(ipclite_msg *, void *);

#define IPCLITE_RSP_SYN 1       /* send synchronous response blob */
#define IPCLITE_RSP_END (1<<1)  /* last blob for extended transact */

/**
 * internal callback for @ipclite_transact
 * return value: ref. @ipclite_server_sendmsg or @ipclite_client_sendmsg
 */
typedef int (*ipclite_response)(const void *blob, size_t sz, int flags, void *ud);

/**
 * must call @rsp to response, run in ipclite_handler thread context.
 */
typedef void (*ipclite_transact)(unsigned int peer, const void *blob, size_t sz,
                                 ipclite_response rsp, void *rsp_ud, void *ud);

/**
 * redefined just to distinguish transact recevied with the canonical
 * ones.
 */
typedef void (*ipclite_transact_ex)(unsigned int peer, const void *blob, size_t sz,
                                    ipclite_response rsp, void *rsp_ud, void *ud);

#define IPCLITE_F_ABSTRACT 1    /* abstract unix socket, linux only */

/**
 * @flags: IPCLITE_F_ABSTRACT to create abstract unix socket.
 * @msg: greeting message to clients at connection.
 * @path: AF_UNIX path, use @ipclite_server_create_from_fd for other af.
 */
int ipclite_server_create(ipclite **s, const char *path, const char *msg, int max_user, int flags);

/**
 * @fd: must already be CONFIGURED and BINDED, server will listen to
 * it directly.
 * @flags: not used.
 */
int ipclite_server_create_from_fd(ipclite **s, int fd, const char *msg, int max_user, int flags);

/**
 * gear up ipclite, @h will be run in child thread.
 */
int ipclite_server_run(ipclite *s, ipclite_handler h, void *ud);

/**
 * gear ip ipclite, run in current thread until quit
 */
int ipclite_server_loop(ipclite *s, ipclite_handler h, void *ud);

int ipclite_server_quit(ipclite *s, int wait);

/**
 * NOTE: currently connected clients but auth failed will be marked
 * closing and not available before return.
 */
int ipclite_server_set_auth(ipclite *s, int uid_check, uid_t uid, int gid_check, gid_t gid);

int ipclite_server_peer_info(ipclite *s, unsigned int peer, ipclite_peer *info);

/**
 * @wait: wait operation to be done before return
 * @force: close peer immediately, not waiting pending messages to be
 * finished
 */
int ipclite_server_close_peer(ipclite *s, unsigned int peer, int wait, int force);

/**
 * should not use this function to received msg if handler function
 * also set, it will contest with the handler.
 * NOTE: returned @msg should be free by caller.
 */
int ipclite_server_recvmsg(ipclite *s, ipclite_msg **msg);

/**
 * @wait: wait until successfully sent or failed to sent
 * @free: free @msg or not when done
 * return_value:
 * IPCLITE_MSG_PND if message queued for commiting.
 * IPCLITE_MSG_OK  if message successfully sent out.
 * other values for specific error.
 */
int ipclite_server_sendmsg(ipclite *s, ipclite_msg *msg, int wait, int free);

/**
 * NOTE:
 * must have transact handler set before the client being able to call
 * @ipclite_client_transact, and must have message handler available
 * before set tranact handler.
 */
int ipclite_server_set_transact(ipclite *s, ipclite_transact h, void *ud);

/**
 * NOTE:
 * must have transact handler set before the client being able to call
 * @ipclite_client_transact_ex, and must have message handler available
 * before set tranact handler.
 */
int ipclite_server_set_transact_ex(ipclite *s, ipclite_transact_ex h, void *ud);

/**
 * the client must be able to recognize and response @blob, otherwise,
 * the function will never return if @timeout set to 0.
 * @rsp: client response data, set to NULL to ignore
 * @rsp_sz: @rsp length, client response data length on return
 * @timeout: in millisecconds
 */
int ipclite_server_transact(ipclite *s, unsigned int peer,
                            const void *blob, size_t sz,
                            void *rsp, size_t *rsp_sz, int timeout);

/**
 * the client must be able to recognize and response @blob, otherwise,
 * the function will never return if @timeout set to 0.
 * @cb: handler for the peer responded ipclite_msg of type
 * IPCLITE_MSG_RPX, and can be called multiple times, with the last
 * ipclite_msg of type IPCLITE_MSG_RXE, if only one ipclite_msg
 * responded, only IPCLITE_MSG_RXE will be recevied, return zero to
 * stop processing furthur responses, set to NULL to ignore all.
 * @timeout: in millisecconds
 */
int ipclite_server_transact_ex(ipclite *s, unsigned int peer,
                               const void *blob, size_t sz,
                               ipclite_handler cb, void *ud, int timeout);

void ipclite_server_destroy(ipclite *s);


int ipclite_client_create(ipclite **c, const char *msg, int flags);

/**
 * @flags: set to IPCLITE_F_ABSTRACT to connect abstract server socket
 * @path: AF_UNIX path, use @ipclite_client_connect_from_fd for other af.
 */
int ipclite_client_connect(ipclite *c, const char *path, int flags);

/**
 * server may not be ready when client trys to connects, then wait for
 * the server for @timeout ms at most.
 * @timeout: ms to wait, or for evet if non-positive.
 */
int ipclite_client_connect_ex(ipclite *c, const char *path, int flags, int timeout);

/**
 * @fd: must be already CONFIGURED and CONNECTED.
 * @flags: not used
 */
int ipclite_client_connect_from_fd(ipclite *c, int fd, int flags);

int ipclite_client_disconnect(ipclite *c, int wait, int force);

/**
 * gear up ipclite, @h will be run in child thread.
 */
int ipclite_client_run(ipclite *c, ipclite_handler h, void *ud);
int ipclite_client_quit(ipclite *c, int wait);

/**
 * should not use this function to received msg if handler function
 * also set, it will contest with the handler.
 * NOTE: returned @msg should be free by caller.
 */
int ipclite_client_recvmsg(ipclite *c, ipclite_msg **msg);

/**
 * @wait: wait until successfully sent or failed to sent
 * @free: free @msg or not when done
 * return_value:
 * IPCLITE_MSG_PND if message queued for commiting.
 * IPCLITE_MSG_OK  if message successfully sent out.
 * other values for specific error.
 */
int ipclite_client_sendmsg(ipclite *c, ipclite_msg *msg, int wait, int free);

/**
 * NOTE:
 * must have transact handler set before the server being able to call
 * @ipclite_server_transact, and must have message handler available
 * before set tranact handler.
 */
int ipclite_client_set_transact(ipclite *c, ipclite_transact h, void *ud);

/**
 * NOTE:
 * must have transact handler set before the server being able to call
 * @ipclite_server_transact_ex, and must have message handler available
 * before set tranact handler.
 */
int ipclite_client_set_transact_ex(ipclite *c, ipclite_transact_ex h, void *ud);

/**
 * the server must recognize and response @blob, otherwise the
 * function will never return if @timeout set to 0.
 * @rsp: response result, set to NULL to ignore.
 * @rsp_sz: @rsp length, response result length on return.
 * @timeout: in millisecconds
 */
int ipclite_client_transact(ipclite *c, const void *blob, size_t size,
                            void *rsp, size_t *rsp_sz, int timeout);

/**
 * the server must be able to recognize and response @blob, otherwise,
 * the function will never return if @timeout set to 0.
 * @cb: handler for the peer responded ipclite_msg of type
 * IPCLITE_MSG_RPX, and can be called multiple times, with the last
 * ipclite_msg of type IPCLITE_MSG_RXE, if only one ipclite_msg
 * responded, only IPCLITE_MSG_RXE will be recevied, return zero to
 * stop process furthur responses, set to NULL to ignore all.
 * @timeout: in millisecconds
 */
int ipclite_client_transact_ex(ipclite *c, const void *blob, size_t size,
                               ipclite_handler cb, void *ud, int timeout);

void ipclite_client_destroy(ipclite *c);

const char *ipclite_err_string(int err);


#define MSG_PAYLOAD(type,msg) ((type *)&((msg)->hdr.data))
#define MSG_LENGTH(payload) (payload + sizeof(ipclite_msg_hdr))


/**
 * return value: IPCLITE_SERVER or IPCLITE_CLIENT
 */
static inline unsigned int ipclite_type(ipclite *i)
{
    return *(unsigned int *)i;
}

static inline int ipclite_set_transact(ipclite *i, ipclite_transact h, void *ud)
{
    if(ipclite_type(i) == IPCLITE_SERVER)
        return ipclite_server_set_transact(i, h, ud);
    return ipclite_client_set_transact(i, h, ud);
}

static inline ipclite_msg *ipclite_msg_alloc(int peer, int id, int msg, size_t payload)
{
    ipclite_msg *m = (ipclite_msg *)malloc(sizeof(ipclite_msg) + payload);

    if(m)  {
        m->hdr.peer = peer;
        m->hdr.id = id;
        m->hdr.msg = msg;
        m->hdr.len = MSG_LENGTH(payload);
    }
    return m;
}

static inline void ipclite_msg_free(ipclite_msg *msg)
{
    free(msg);
}


__END_DECLS

#endif  /* __IPCLITE_H */

