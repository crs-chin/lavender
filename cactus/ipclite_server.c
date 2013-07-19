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
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/un.h>
#include <pthread.h>

#include "ipclite.h"
#include "ipclite_priv.h"

#define IPCLITE_SERVER_TRIGER "RABIT"

/* not defined outside __USE_GNU, but SO_PEERCRED need it */
#if ! HAVE_ST_UCRED && ! ANDROID_CHANGES
#include <sys/types.h>
struct ucred{
    pid_t pid;            /* PID of sending process.  */
    uid_t uid;            /* UID of sending process.  */
    gid_t gid;            /* GID of sending process.  */
};
#endif

typedef struct _ipclite_session ipclite_session;
typedef struct _peer_state peer_state;

struct _ipclite_session{
    list list;
    ipclite_peer peer;
    ipclite_port port;
};

struct _peer_state{
    list list;
    unsigned int peer;
};

struct _ipclite_server{
    ipclite base;

    int uid_check;
    int gid_check;
    uid_t uid;
    gid_t gid;

    pthread_t worker;

    pthread_mutex_t lock;
    pthread_cond_t cond;
    int worker_started;
    int worker_quit;

    unsigned int peer;          /* max peer */
    unsigned int cnt;
    unsigned int max;

    fd_set rd;
    fd_set wr;
    int fd_max;

    int notify[2];
    list clients;

    pthread_t dispatcher;
    pthread_mutex_t dispatcher_lock;
    pthread_cond_t dispatcher_cond;
    int dispatcher_started;
    int dispatcher_threaded;
    int dispatcher_quit;
    list rd_queue;
    list req_queue;
    list wr_queue;

    pthread_mutex_t wait_lock;
    pthread_cond_t wait_cond;
    int wait_cnt;
    list wait_queue;
    list peers;
};

static inline void worker_lock(ipclite_server *s)
{
    pthread_mutex_lock(&s->lock);
}

static inline void worker_unlock(ipclite_server *s)
{
    pthread_mutex_unlock(&s->lock);
}

static inline void dispatcher_lock(ipclite_server *s)
{
    pthread_mutex_lock(&s->dispatcher_lock);
}

static inline void dispatcher_unlock(ipclite_server *s)
{
    pthread_mutex_unlock(&s->dispatcher_lock);
}

static inline void wait_lock(ipclite_server *s)
{
    pthread_mutex_lock(&s->wait_lock);
}

static inline void wait_unlock(ipclite_server *s)
{
    pthread_mutex_unlock(&s->wait_lock);
}

static int create_server(ipclite **s, int fd, const char *path,
                         const char *msg, int max_user, int flags)
{
    ipclite_server *server;
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    int noti[2];

    if(listen(fd, max_user) == -1)
        return IPCLITE_ERR_LIS;

    if(pipe2(noti, O_NONBLOCK) == -1)
        return IPCLITE_ERR_PIP;

    if(! (server = new_instance(ipclite_server)))  {
        close(noti[0]);
        close(noti[1]);
        return IPCLITE_ERR_OOM;
    }

    bzero(server, sizeof(ipclite_server));

    server->base.type = IPCLITE_SERVER;
    server->base.msg = ((msg && *msg) ? strdup(msg) : NULL);
    server->base.handler = NULL;
    server->base.ud = NULL;

    server->base.master = fd;
    server->base.path[0] = '\0';
    if(path && *path)  {
        if(flags & IPCLITE_F_ABSTRACT)
            strncpy(server->base.path + 1, path, sizeof(server->base.path) - 1);
        else
            strncpy(server->base.path, path, sizeof(server->base.path));
    }

    server->uid_check = 0;
    server->gid_check = 0;
    server->uid = 0;
    server->gid = 0;

    pthread_mutex_init(&server->lock, NULL);
    pthread_cond_init(&server->cond, NULL);
    server->worker_started = 0;
    server->worker_quit = 0;

    server->peer = 0;
    server->cnt = 0;
    server->max = max_user;

    server->notify[0] = noti[0];
    server->notify[1] = noti[1];

    FD_ZERO(&server->rd);
    FD_ZERO(&server->wr);

    FD_SET(fd, &server->rd);
    FD_SET(noti[0], &server->rd);
    server->fd_max = MAX(fd, noti[0]);

    list_init(&server->clients);

    pthread_mutex_init(&server->dispatcher_lock, NULL);
    server->dispatcher_started = 0;
    server->dispatcher_quit = 0;
    list_init(&server->rd_queue);
    list_init(&server->req_queue);
    list_init(&server->wr_queue);

    pthread_mutex_init(&server->wait_lock, NULL);
    pthread_cond_init(&server->wait_cond, NULL);
    server->wait_cnt = 0;
    list_init(&server->wait_queue);
    list_init(&server->peers);

    *s = (ipclite *)server;

    return IPCLITE_ERR_OK;
}

int ipclite_server_create(ipclite **s, const char *path, const char *msg, int max_user, int flags)
{
    struct sockaddr_un addr;
    socklen_t len = sizeof(addr);
    int ret, fd, noti[2];
    int arg = 1;

    if(! s || max_user <= 0 || ! path || ! *path || strlen(path) > sizeof(addr.sun_path))
        return IPCLITE_ERR_INV;

    if((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
        return IPCLITE_ERR_SCK;

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &arg, sizeof(arg));

    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    if(flags & IPCLITE_F_ABSTRACT)  {
        strncpy(addr.sun_path + 1, path, sizeof(addr.sun_path) - 1);
    }else  {
        unlink(path);
        strncpy(addr.sun_path, path, sizeof(addr.sun_path));
    }

    if(bind(fd, (struct sockaddr *)&addr, len) == -1)  {
        close(fd);
        return IPCLITE_ERR_BND;
    }

    ret = create_server(s, fd, path, msg, max_user, flags);
    if(ret != IPCLITE_ERR_OK)
        close(fd);
    return ret;
}

int ipclite_server_create_from_fd(ipclite **s, int fd, const char *msg, int max_user, int flags)
{
    if(! s || fd < 0 || max_user <= 0)
        return IPCLITE_ERR_INV;

    return create_server(s, fd, NULL, msg, max_user, flags);
}

static inline void empty_fd(int fd)
{
    int res;
    char buf[10];

    do{
        errno = 0;
        res = read(fd, buf, strlen(IPCLITE_SERVER_TRIGER));
    }while(res > 0 && errno != EAGAIN && errno != EWOULDBLOCK);
}


static inline void repoll(ipclite_server *s)
{
    int res;

    do{
        res = write(s->notify[1], IPCLITE_SERVER_TRIGER, strlen(IPCLITE_SERVER_TRIGER));
    }while(res < 0 && errno == EAGAIN);
}

static inline void new_peer(ipclite_server *srv, unsigned int peer)
{
    peer_state *p = new_instance(peer_state);

    if(p)  {
        list_init(&p->list);
        p->peer = peer;

        wait_lock(srv);
        list_append(&srv->peers, &p->list);
        wait_unlock(srv);
    }
}

static inline void __delete_peer(ipclite_server *srv, unsigned int peer)
{
    peer_state *p, *n;

    list_for_each_entry_safe(p, n, &srv->peers, list)  {
        if(p->peer == peer)  {
            list_delete(&p->list);
            free(p);
            break;
        }
    }
}

static ipclite_session *new_session(ipclite_server *srv, struct ucred *cred, int fd)
{
    ipclite_session *sess;

    srv->peer += 1;
    if(! srv->peer)  {
        LOGERROR("Peer ID wrapped");
        return NULL;
    }

    if(! (sess = new_instance(ipclite_session)))  {
        LOGERROR("OOM alloc ipclite_session");
        return NULL;
    }

    list_init(&sess->list);
    sess->peer.peer = srv->peer;
    sess->peer.pid = cred->pid;
    sess->peer.uid = cred->uid;
    sess->peer.gid = cred->gid;
    ipclite_port_init(&sess->port, fd);
    sess->port.state = PORT_OPENED;
    return sess;
}

static inline void on_new_client(ipclite_server *srv, ipclite_session *sess)
{
    ipclite_msg *syn = new_syn_msg(sess->peer.peer, srv->base.msg);

    if(syn)  {
        FD_SET(sess->port.fd, &srv->wr);
        list_append(&sess->port.msgs, msg_list_ptr(syn));
    }
}

static void new_client(ipclite_server *srv)
{
    ipclite_session *sess;
    struct ucred cred;
    struct sockaddr_un addr;
    socklen_t addr_len = sizeof(addr);
    socklen_t cred_len = sizeof(cred);
    int fd, flag;

    if((fd = accept(srv->base.master, (struct sockaddr *)&addr, &addr_len)) < 0)  {
        LOGERROR("Fail to accept a new client");
        return;
    }

    flag = fcntl(fd, F_GETFL, NULL);
    if(fcntl(fd, F_SETFL, flag | O_NONBLOCK) != 0)  {
        LOGERROR("Fail to set fd flags");
        close(fd);
        return;
    }

    if(getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0)  {
        LOGERROR("Fail to get the client credentials");
        close(fd);
        return;
    }

    if(cred.uid != 0
       && ((srv->uid_check && cred.uid != srv->uid)
           || (srv->gid_check && cred.gid != srv->gid)))  {
        LOGWARN("Refuse connection from user:%d", cred.uid);
        close(fd);
        return;
    }

    if(! (sess = new_session(srv, &cred, fd)))  {
        close(fd);
        return;
    }

    FD_SET(fd, &srv->rd);
    srv->fd_max = MAX(srv->fd_max, fd);
    srv->cnt++;

    list_append(&srv->clients, &sess->list);
    new_peer(srv, sess->peer.peer);
    on_new_client(srv, sess);
}

static inline void __reject_msg(ipclite_server *srv, ipclite_msg *msg)
{
    ipclite_msg_ctl *ctl = msg_ctl(msg);

    ctl->err = IPCLITE_ERR_PER;
    if(ctl->wait)  {
        list_append(&srv->wait_queue, msg_list_ptr(msg));
    }else if(ctl->free)  {
        free(msg);
    }
}

static void __delete_client(ipclite_server *srv, ipclite_session *sess)
{
    list *msgs = &sess->port.msgs;
    ipclite_msg *msg, *n = NULL;

    close(sess->port.fd);
    list_for_each_msg_safe(msg, n, msgs)  {
        list_delete(msg_list_ptr(msg));
        __reject_msg(srv, msg);
    }

    if(sess->port.msg)
        __reject_msg(srv, sess->port.msg);

    wait_lock(srv);
    __delete_peer(srv, sess->peer.peer);
    pthread_cond_broadcast(&srv->wait_cond);
    wait_unlock(srv);

    free(sess);
}


static void delete_client(ipclite_server *srv, ipclite_session *sess)
{
    ipclite_session *_sess;
    ipclite_msg *msg;

    FD_CLR(sess->port.fd, &srv->rd);
    FD_CLR(sess->port.fd, &srv->wr);

    srv->cnt--;
    list_delete(&sess->list);

    srv->fd_max = MAX(srv->base.master, srv->notify[0]);
    list_for_each_entry(_sess, &srv->clients, list)  {
        srv->fd_max = MAX(srv->fd_max, _sess->port.fd);
    }

    msg = new_cls_msg(sess->peer.peer);
    if(msg)  {
        dispatcher_lock(srv);
        list_append(&srv->rd_queue, msg_list_ptr(msg));
        pthread_cond_broadcast(&srv->dispatcher_cond);
        dispatcher_unlock(srv);
    }

    __delete_client(srv, sess);
    pthread_cond_broadcast(&srv->cond);
}


static void new_msg(ipclite_server *srv, ipclite_session *sess, const ipclite_msg_hdr *hdr)
{
    ipclite_msg *msg;
    ipclite_msg_ctl *ctl;

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
    msg->hdr.peer = sess->peer.peer;

    if(hdr->msg == IPCLITE_MSG_RSP
       || hdr->msg == IPCLITE_MSG_RPX
       || hdr->msg == IPCLITE_MSG_RXE)  {
        wait_lock(srv);
        assert(srv->wait_cnt >= 0);
        if(srv->wait_cnt > 0)  {
            list_append(&srv->wait_queue, msg_list_ptr(msg));
            pthread_cond_broadcast(&srv->wait_cond);
        }else  {
            LOGINFO("discard orphaned response message:%u", hdr->msg);
            free(msg);
        }
        wait_unlock(srv);
    }else  {
        dispatcher_lock(srv);
        if(hdr->msg == IPCLITE_MSG_REQ || hdr->msg == IPCLITE_MSG_RQX)  {
            list_append(&srv->req_queue, msg_list_ptr(msg));
        }else  {
            list_append(&srv->rd_queue, msg_list_ptr(msg));
        }
        pthread_cond_broadcast(&srv->dispatcher_cond);
        dispatcher_unlock(srv);
    }
}

static void read_client_msg(ipclite_server *srv, ipclite_session *sess)
{
    ipclite_msg_hdr *hdr;
    int len;

    do{
        len = read(sess->port.fd, sess->port.buf + sess->port.len, IPCLITE_BUF_SIZE - sess->port.len);
    }while(len < 0 && errno == EINTR);

    if((len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) || len == 0)  {
        LOGINFO("Error reading client msg, closed or error, removing:%d.", sess->peer.peer);
        delete_client(srv, sess);
    }

    if(len > 0)  {
        hdr = (ipclite_msg_hdr *)sess->port.buf;
        len += sess->port.len;
        while(IPCLITE_MSG_OK(hdr, len))  {
            new_msg(srv, sess, hdr);
            hdr = IPCLITE_MSG_NEXT(hdr,len);
        }
        memmove((void *)sess->port.buf, (void *)hdr, len);
        sess->port.len = len;
    }
}


/**
 * return_value:
 * -1: client error or closed
 *  0: successfully commited
 *  1: half commited
 */
static int commit_msg(ipclite_server *srv, ipclite_session *sess, ipclite_msg *msg, size_t offset)
{
    ipclite_msg_ctl *ctl = msg_ctl(msg);
    list *ptr;
    int res;

    do{
        res = write(sess->port.fd, ((char *)&msg->hdr) + offset, msg->hdr.len - offset);
    }while(res < 0 && errno == EINTR);

    if(res < 0 && errno != EWOULDBLOCK && errno != EAGAIN)  {
        LOGINFO("Error writting client msg, closed or error, removing:%d", sess->peer.peer);
        delete_client(srv, sess);
        return -1;
    }

    if(res > 0)
        offset += res;

    if(msg->hdr.len > offset)  {
        sess->port.msg = msg;
        sess->port.msg_offset = offset;
        return 1;
    }

    ctl->cmmt = 1;
    ctl->err = IPCLITE_ERR_OK;
    if(ctl->wait)  {
        wait_lock(srv);
        ptr = msg_list_ptr(msg);
        list_append(&srv->wait_queue, ptr);
        pthread_cond_broadcast(&srv->wait_cond);
        wait_unlock(srv);
    }else if(ctl->free)  {
        free(msg);
    }

    sess->port.msg = NULL;
    sess->port.msg_offset = 0;
    return 0;
}

static void write_client_msg(ipclite_server *srv, ipclite_session *sess)
{
    ipclite_msg *msg = sess->port.msg;
    list *ptr;
    int res = 0;

    if(msg)
        res = commit_msg(srv, sess, msg, sess->port.msg_offset);
    while(res == 0 && ! list_empty(&sess->port.msgs))  {
        ptr = sess->port.msgs.l_nxt;
        msg = list_msg(ptr);
        list_delete(ptr);
        res = commit_msg(srv, sess, msg, 0);
    }
    if(res == 0)  {
        FD_CLR(sess->port.fd, &srv->wr);
        if(sess->port.state == PORT_CLOSING)
            delete_client(srv, sess);
    }
}

static inline int poll_fds(ipclite_server *srv, fd_set *rd, fd_set *wr, fd_set *ex)
{
    int fd_max;

    worker_lock(srv);
    if(rd)  *rd = srv->rd;
    if(wr)  *wr = srv->wr;
    fd_max = srv->fd_max;
    worker_unlock(srv);
    return select(fd_max + 1, rd, wr, NULL, NULL);
}

static void *worker_thread(void *arg)
{
    ipclite_server *srv = (ipclite_server *)arg;
    ipclite_session *sess, *n;
    int quit = 0, repoll = 0;
    fd_set rd_set, wr_set;

    prctl(PR_SET_NAME, (unsigned long)"ipcworker", 0, 0, 0);
    for(;;)  {
        while(poll_fds(srv, &rd_set, &wr_set, NULL) <= 0)
            ;

        if(FD_ISSET(srv->notify[0], &rd_set)) {
            empty_fd(srv->notify[0]);
        }

        worker_lock(srv);
        if(srv->worker_quit)
            break;

        if(FD_ISSET(srv->base.master, &rd_set))  {
            new_client(srv);
        }

        list_for_each_entry_safe(sess, n, &srv->clients, list)  {
            if(FD_ISSET(sess->port.fd, &rd_set))  {
                read_client_msg(srv, sess);
            }
            if(FD_ISSET(sess->port.fd, &wr_set))  {
                write_client_msg(srv, sess);
            }
        }
        worker_unlock(srv);
    }

    srv->worker_started = 0;
    worker_unlock(srv);
    return NULL;
}

static int __submit_msg(ipclite_server *srv, ipclite_msg *msg)
{
    ipclite_session *sess;
    ipclite_msg_ctl *ctl = msg_ctl(msg);
    list *ptr = msg_list_ptr(msg);

    list_for_each_entry(sess, &srv->clients, list)  {
        if(sess->peer.peer == msg->hdr.peer)  {
            if(sess->port.state == PORT_OPENED)  {
                list_append(&sess->port.msgs, ptr);
                FD_SET(sess->port.fd, &srv->wr);
                return IPCLITE_ERR_OK;
            }
            break;
        }
    }

    LOGERROR("No peer or peer closing to send a message:%d", msg->hdr.peer);
    if(ctl->free)
        free(msg);
    return IPCLITE_ERR_PER;
}


static int wait_msg(ipclite_server *srv, ipclite_msg *msg, int fr)
{
    ipclite_msg *iter, *n;
    ipclite_msg_ctl *ctl;
    int ret;

    wait_lock(srv);
    srv->wait_cnt++;
    iter = NULL;
    for(;;)  {
        while(list_empty(&srv->wait_queue))
            pthread_cond_wait(&srv->wait_cond, &srv->wait_lock);

        list_for_each_msg_safe(iter, n, &srv->wait_queue)  {
            if(iter == msg)  {
                list_delete(msg_list_ptr(iter));
                break;
            }
        }

        if(iter == msg)
            break;

        pthread_cond_wait(&srv->wait_cond, &srv->wait_lock);
    }
    srv->wait_cnt--;
    if(! srv->wait_cnt)
        pthread_cond_signal(&srv->wait_cond);

    wait_unlock(srv);

    ctl = msg_ctl(msg);
    ret = ctl->err;
    if(ctl->free || fr)
        free(msg);
    return ret;
}

static inline int submit_msg(ipclite_server *srv, ipclite_msg *msg)
{
    int ret;

    worker_lock(srv);
    ret = __submit_msg(srv, msg);
    if(ret == IPCLITE_ERR_OK)
        repoll(srv);
    worker_unlock(srv);
    return ret;
}

static int ___on_transact(unsigned int msgid, transact_ctx *ctx,
                          int flags, const void *blob, size_t sz)
{
    ipclite_server *srv = (ipclite_server *)ctx->ipc;
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
        ret = submit_msg(srv, msg);
        if(ret == IPCLITE_ERR_OK)
            ret = wait_msg(srv, msg, 0);
    }else  {
        ret = IPCLITE_ERR_OOM;
        if((msg = __new_rsp_msg(ctx->peer, msgid, ctx->id, IPCLITE_ERR_OK, blob, sz)))
            ret = submit_msg(srv, msg);
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

static void on_transact(ipclite_server *srv, ipclite_msg *req, ipclite_transact transact, void *ud)
{
    ipclite_msg *rsp;

    if(! transact)  {
        if((rsp = new_rsp_msg(req->hdr.peer, req->hdr.id, IPCLITE_ERR_NOS, NULL, 0)))
            submit_msg(srv, rsp);
    }else  {
        transact_ctx ctx = {
            .ipc = (ipclite *)srv,
            .peer = req->hdr.peer,
            .id = req->hdr.id,
            .flags = 0,
        };

        transact(req->hdr.peer,
                 MSG_PAYLOAD(const void, req),
                 req->hdr.len - sizeof(ipclite_msg_hdr),
                 __on_transact, (void *)&ctx, ud);
        /* try return err of caller didn't even respond */
        if(! (ctx.flags & TRANSACT_F_RSP)
           && (rsp = new_rsp_msg(ctx.peer, ctx.id, IPCLITE_ERR_NOR, NULL, 0)))
            submit_msg(srv, rsp);
    }
}


static void on_transact_ex(ipclite_server *srv, ipclite_msg *req, ipclite_transact_ex transact, void *ud)
{
    ipclite_msg *rsp;

    if(! transact)  {
        if((rsp = new_rxe_msg(req->hdr.peer, req->hdr.id, IPCLITE_ERR_NOS, NULL, 0)))
            submit_msg(srv, rsp);
    }else  {
        transact_ctx ctx = {
            .ipc = (ipclite *)srv,
            .peer = req->hdr.peer,
            .id = req->hdr.id,
            .flags = 0,
        };

        transact(req->hdr.peer,
                 MSG_PAYLOAD(const void, req),
                 req->hdr.len - sizeof(ipclite_msg_hdr),
                 __on_transact_ex, (void *)&ctx, ud);
        /* implementation MUST respond with a IPCLITE_RSP_END flag in last message */
        if(! (ctx.flags & TRANSACT_F_DONE)
           && (rsp = new_rxe_msg(ctx.peer, ctx.id, IPCLITE_ERR_NOR, NULL, 0)))
            submit_msg(srv, rsp);
    }
}

static void *dispatcher_thread(void *arg)
{
    ipclite_server *srv = (ipclite_server *)arg;
    ipclite_msg *msg, *n;
    list rd_queue, req_queue, wr_queue;
    ipclite_handler handler = NULL;
    ipclite_transact transact = NULL;
    ipclite_transact_ex transact_ex = NULL;
    void *ud = NULL;
    void *ud_transact = NULL;
    void *ud_transact_ex = NULL;

    prctl(PR_SET_NAME, "ipcdispatcher", 0, 0, 0);
    for(;;)  {
        list_init(&rd_queue);
        list_init(&req_queue);
        list_init(&wr_queue);

        dispatcher_lock(srv);
        while((list_empty(&srv->rd_queue)
               || ! srv->base.handler)
              && list_empty(&srv->req_queue)
              && list_empty(&srv->wr_queue)
              && ! srv->dispatcher_quit)
            pthread_cond_wait(&srv->dispatcher_cond, &srv->dispatcher_lock);

        if(srv->base.handler)  {
            list_assign(&rd_queue, &srv->rd_queue);
            handler = srv->base.handler;
            ud = srv->base.ud;
        }

        list_assign(&req_queue, &srv->req_queue);
        transact = srv->base.transact;
        transact_ex = srv->base.transact_ex;
        ud_transact = srv->base.ud_transact;
        ud_transact_ex = srv->base.ud_transact_ex;

        list_assign(&wr_queue, &srv->wr_queue);
        dispatcher_unlock(srv);

        list_for_each_msg_safe(msg, n, &req_queue)  {
            assert(msg->hdr.msg == IPCLITE_MSG_REQ || msg->hdr.msg == IPCLITE_MSG_RQX);

            list_delete(msg_list_ptr(msg));
            if(msg->hdr.msg == IPCLITE_MSG_REQ)
                on_transact(srv, msg, transact, ud_transact);
            else if(msg->hdr.msg == IPCLITE_MSG_RQX)
                on_transact_ex(srv, msg, transact_ex, ud_transact_ex);
            else
                LOGERROR("invalid req message recevied:%d", msg->hdr.msg);
            free(msg);
        }

        list_for_each_msg_safe(msg, n, &rd_queue)  {
            list_delete(msg_list_ptr(msg));
            if(! handler(msg, ud))
                free(msg);
        }

        if(! list_empty(&wr_queue))  {
            worker_lock(srv);
            list_for_each_msg_safe(msg, n, &wr_queue)  {
                list_delete(msg_list_ptr(msg));
                __submit_msg(srv, msg);
            }
            repoll(srv);
            worker_unlock(srv);
        }

        if(srv->dispatcher_quit)
            break;
    }

    srv->dispatcher_started = 0;
    dispatcher_unlock(srv);
    return NULL;
}


/**
 * spawn child thread to wait for new connections and the clients
 * messages, @h will be run in child thread.
 */
int ipclite_server_run(ipclite *s, ipclite_handler h, void *ud)
{
    ipclite_server *svr = (ipclite_server *)s;
    int ret = IPCLITE_ERR_OK;

    if(! s || s->type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    svr->worker_quit = 0;
    worker_lock(svr);
    if(! svr->worker_started)  {
        if(! pthread_create(&svr->worker, NULL, worker_thread, (void *)svr))  {
            svr->worker_started = 1;
        }else  {
            LOGERROR("Fail to spawn worker thread");
            ret = IPCLITE_ERR_THD;
        }
    }
    worker_unlock(svr);

    if(ret == IPCLITE_ERR_OK)  {
        svr->dispatcher_quit = 0;
        dispatcher_lock(svr);
        svr->base.handler = h;
        svr->base.ud = ud;

        if(! svr->dispatcher_started)  {
            if(! pthread_create(&svr->worker, NULL, dispatcher_thread, (void *)svr))  {
                svr->dispatcher_threaded = 1;
                svr->dispatcher_started = 1;
            }else  {
                LOGERROR("Fail tp spawn dispatcher thread");
                ret = IPCLITE_ERR_THD;
            }
        }
        dispatcher_unlock(svr);
    }

    return ret;
}


int ipclite_server_loop(ipclite *s, ipclite_handler h, void *ud)
{
    ipclite_server *svr = (ipclite_server *)s;
    int ret = IPCLITE_ERR_OK;

    if(! s || s->type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    svr->worker_quit = 0;
    worker_lock(svr);
    if(! svr->worker_started)  {
        if(! pthread_create(&svr->worker, NULL, worker_thread, (void *)svr))  {
            svr->worker_started = 1;
        }else  {
            LOGERROR("Fail to spawn worker thread");
            ret = IPCLITE_ERR_THD;
        }
    }
    worker_unlock(svr);

    if(ret == IPCLITE_ERR_OK)  {
        svr->dispatcher_quit = 0;
        dispatcher_lock(svr);
        if(svr->dispatcher_started)  {
            LOGERROR("Server already runing in separate thread");
            dispatcher_unlock(svr);
            return IPCLITE_ERR_GEN;
        }

        svr->base.handler = h;
        svr->base.ud = ud;
        svr->dispatcher_threaded = 0;
        svr->dispatcher_started = 1;
        dispatcher_unlock(svr);
        (void)dispatcher_thread((void *)svr);
    }

    return ret;
}

int ipclite_server_quit(ipclite *s, int wait)
{
    ipclite_server *svr = (ipclite_server *)s;
    int started, threaded;
    pthread_t thd;

    if(! s || s->type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    dispatcher_lock(svr);
    svr->dispatcher_quit = 1;
    started = svr->dispatcher_started;
    threaded= svr->dispatcher_threaded;
    if(started)  {
        thd = svr->dispatcher;
        pthread_cond_broadcast(&svr->dispatcher_cond);
    }
    dispatcher_unlock(svr);
    if(wait && started && threaded && pthread_join(thd, NULL))
        return IPCLITE_ERR_WAT;

    worker_lock(svr);
    svr->worker_quit = 1;
    started = svr->worker_started;
    if(started)  {
        thd = svr->worker;
        repoll(svr);
    }
    worker_unlock(svr);
    if(started && wait && pthread_join(thd, NULL))
        return IPCLITE_ERR_WAT;

    return IPCLITE_ERR_OK;
}


int ipclite_server_set_auth(ipclite *s, int uid_check, uid_t uid, int gid_check, gid_t gid)
{
    ipclite_server *srv = (ipclite_server *)s;
    ipclite_session *sess;
    int pol = 0;

    if(! srv || srv->base.type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    worker_lock(srv);
    srv->uid_check = uid_check;
    srv->gid_check = gid_check;
    srv->uid = uid;
    srv->gid = gid;

    list_for_each_entry(sess, &srv->clients, list)  {
        if((uid_check && sess->peer.uid != uid) || (gid_check && sess->peer.gid != gid))  {
            sess->port.state = PORT_CLOSING;
        }
    }
    worker_unlock(srv);
    return IPCLITE_ERR_OK;
}

int ipclite_server_peer_info(ipclite *s, unsigned int peer, ipclite_peer *info)
{
    ipclite_server *srv = (ipclite_server *)s;
    ipclite_session *sess;
    int ret = IPCLITE_ERR_INV;

    if(! srv || srv->base.type != IPCLITE_SERVER || ! peer || ! info)
        return IPCLITE_ERR_INV;

    worker_lock(srv);
    list_for_each_entry(sess, &srv->clients, list)  {
        if(peer == sess->peer.peer)  {
            *info = sess->peer;
            ret = IPCLITE_ERR_OK;
            break;
        }
    }
    worker_unlock(srv);

    return ret;
}


static void close_peer(ipclite_server *srv, ipclite_session *sess, int wait, int force)
{
    ipclite_session *s = NULL;

    if(force)  {
        delete_client(srv, sess);
        return;
    }

    if(! list_empty(&sess->port.msgs) || sess->port.msg)  {
        sess->port.state = PORT_CLOSING;
    }else  {
        delete_client(srv, sess);
        return;
    }

    if(! wait)
        return;

 wait_client:
    pthread_cond_wait(&srv->cond, &srv->lock);
    list_for_each_entry(s, &srv->clients, list)  {
        if(s == sess)
            goto wait_client;
    }
}

int ipclite_server_close_peer(ipclite *s, unsigned int peer, int wait, int force)
{
    ipclite_server *srv = (ipclite_server *)s;
    ipclite_session *sess, *n;

    if(! srv || srv->base.type != IPCLITE_SERVER || ! peer)
        return IPCLITE_ERR_INV;

    worker_lock(srv);
    list_for_each_entry_safe(sess, n, &srv->clients, list)  {
        if(sess->peer.peer == peer)  {
            close_peer(srv, sess, wait, force);
            break;
        }
    }
    worker_unlock(srv);
    return IPCLITE_ERR_OK;
}

int ipclite_server_recvmsg(ipclite *s, ipclite_msg **msg)
{
    ipclite_server *srv = (ipclite_server *)s;
    list *ptr;

    if(! msg || ! srv || srv->base.type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    dispatcher_lock(srv);
    while(list_empty(&srv->rd_queue))
        pthread_cond_wait(&srv->dispatcher_cond, &srv->dispatcher_lock);

    ptr = srv->rd_queue.l_nxt;
    list_delete(ptr);
    *msg = list_msg(ptr);
    dispatcher_unlock(srv);

    return IPCLITE_ERR_OK;
}

int ipclite_server_sendmsg(ipclite *s, ipclite_msg *msg, int wait, int free)
{
    ipclite_server *srv = (ipclite_server *)s;
    list *ptr;
    int ret;

    if(! msg || msg->hdr.msg < IPCLITE_MSG_BASE
       || ! srv || srv->base.type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    msg_init_ctl(msg, wait, free);

    if(wait)  {
        worker_lock(srv);
        ret = __submit_msg(srv, msg);
        repoll(srv);
        worker_unlock(srv);
        if(ret == IPCLITE_ERR_OK)
            return wait_msg(srv, msg, free);
        return ret;
    }

    dispatcher_lock(srv);
    ptr = msg_list_ptr(msg);
    list_append(&srv->wr_queue, ptr);
    pthread_cond_broadcast(&srv->dispatcher_cond);
    dispatcher_unlock(srv);

    return IPCLITE_ERR_PND;
}

int ipclite_server_set_transact(ipclite *s, ipclite_transact h, void *ud)
{
    ipclite_server *srv = (ipclite_server *)s;
    int err = IPCLITE_ERR_OK;

    if(! srv || srv->base.type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    dispatcher_lock(srv);
#if 0
    if(srv->dispatcher_started)  {
        srv->base.transact = h;
        srv->base.ud_transact = ud;
    }else  {
        err = IPCLITE_ERR_INV;
    }
#else
    /* just set handlers, thread may gear up later */
    srv->base.transact = h;
    srv->base.ud_transact = ud;
#endif
    dispatcher_unlock(srv);
    return err;
}

int ipclite_server_set_transact_ex(ipclite *s, ipclite_transact_ex h, void *ud)
{
    ipclite_server *srv = (ipclite_server *)s;
    int err = IPCLITE_ERR_OK;

    if(! srv || srv->base.type != IPCLITE_SERVER)
        return IPCLITE_ERR_INV;

    dispatcher_lock(srv);
#if 0
    if(srv->dispatcher_started)  {
        srv->base.transact_ex = h;
        srv->base.ud_transact_ex = ud;
    }else  {
        err = IPCLITE_ERR_INV;
    }
#else
    /* just set handlers, thread may gear up later */
    srv->base.transact_ex = h;
    srv->base.ud_transact_ex = ud;
#endif
    dispatcher_unlock(srv);
    return err;
}

static inline int __peer_ok(ipclite_server *srv, unsigned int peer)
{
    peer_state *per;

    list_for_each_entry(per, &srv->peers, list)  {
        if(per->peer == peer)
            return 1;
    }
    return 0;
}

static int __do_transact(ipclite_server *srv, ipclite_msg *m, transact_rsp *trsp, int timeout)
{
    ipclite_msg *iter, *n, *rsp = NULL;
    ipclite_msg_ctl *ctl;
    struct timespec ts;
    unsigned int peer = m->hdr.peer;
    int err = IPCLITE_ERR_OK;
    int ret = 0;

    wait_lock(srv);
    srv->wait_cnt++;
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
            while(list_empty(&srv->wait_queue) && __peer_ok(srv, peer))
                pthread_cond_wait(&srv->wait_cond, &srv->wait_lock);
        }else if(ret != ETIMEDOUT)  {
            while(list_empty(&srv->wait_queue) && __peer_ok(srv, peer) && ret != ETIMEDOUT)
                ret = pthread_cond_timedwait(&srv->wait_cond, &srv->wait_lock, &ts);
        }

        list_for_each_msg_safe(iter, n, &srv->wait_queue)  {
            if(iter == m)  {
                list_delete(msg_list_ptr(iter));
                ctl = msg_ctl(m);
                if(ctl->err != IPCLITE_ERR_OK)  {
                    err = ctl->err;
                    break;
                }
                continue;
            }

            if(m->hdr.msg == IPCLITE_MSG_REQ)  {
                if(iter->hdr.msg == IPCLITE_MSG_RSP && iter->hdr.id == m->hdr.id)  {
                    list_delete(msg_list_ptr(iter));
                    rsp = iter;
                    break;
                }
                continue;
            }

            if(m->hdr.msg == IPCLITE_MSG_RQX)  {
                if((iter->hdr.msg == IPCLITE_MSG_RPX
                    || iter->hdr.msg == IPCLITE_MSG_RXE)
                   && iter->hdr.id == m->hdr.id)  {
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

        if(! __peer_ok(srv, peer))  {
            err = IPCLITE_ERR_PER;
            break;
        }

        if(timeout <= 0)  {
            pthread_cond_wait(&srv->wait_cond, &srv->wait_lock);
        }else  {
            ret = pthread_cond_timedwait(&srv->wait_cond, &srv->wait_lock, &ts);
        }
    }
    srv->wait_cnt--;
    if(! srv->wait_cnt)
        pthread_cond_signal(&srv->wait_cond);

    wait_unlock(srv);

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

static inline void inc_waiters(ipclite_server *srv)
{
    wait_lock(srv);
    srv->wait_cnt++;
    wait_unlock(srv);
}

static inline void dec_waiters(ipclite_server *srv)
{
    wait_lock(srv);
    srv->wait_cnt--;
    if(! srv->wait_cnt)
        pthread_cond_signal(&srv->wait_cond);
    wait_unlock(srv);
}

static inline int submit_req(ipclite_server *srv, ipclite_msg *msg,
                             unsigned int peer, unsigned int msgid,
                             const void *blob, size_t sz)
{
    int err;

    msg_init_ctl(msg, 1, 0);
    memcpy(MSG_PAYLOAD(void, msg), blob, sz);
    msg->hdr.peer = peer;
    msg->hdr.msg = msgid;
    msg->hdr.len = MSG_LENGTH(sz);

    worker_lock(srv);
    msg->hdr.id = ++srv->base.seq;
    err = __submit_msg(srv, msg);
    if(err == IPCLITE_ERR_OK)  {
        inc_waiters(srv);
        repoll(srv);
    }
    worker_unlock(srv);
    return err;
}

static int do_transact(ipclite_server *srv, unsigned int peer,
                       const void *blob, size_t sz,
                       void *rsp, size_t *rsp_sz, int timeout)
{
    char _msg[sz + sizeof(ipclite_msg)];
    ipclite_msg *msg = (ipclite_msg *)_msg;
    transact_rsp trsp;
    int err = submit_req(srv, msg, peer, IPCLITE_MSG_REQ, blob, sz);

    if(err == IPCLITE_ERR_OK)  {
        trsp.type = TRANSACT_RSP_CANONICAL;
        trsp.blob = rsp;
        trsp.sz = rsp_sz;
        err = __do_transact(srv, msg, &trsp, timeout);
        dec_waiters(srv);
    }
    return err;
}


static int do_transact_ex(ipclite_server *srv, unsigned int peer,
                          const void *blob, size_t sz,
                          ipclite_handler cb, void *ud, int timeout)
{
    char _msg[sz + sizeof(ipclite_msg)];
    ipclite_msg *msg = (ipclite_msg *)_msg;
    transact_rsp trsp;
    int err = submit_req(srv, msg, peer, IPCLITE_MSG_RQX, blob, sz);

    if(err == IPCLITE_ERR_OK)  {
        trsp.type = TRANSACT_RSP_EXTENDED;
        trsp.cb = cb;
        trsp.ud = ud;
        trsp.flags = TRANSACT_RSP_F_CONTINUE;
        do{
            err = __do_transact(srv, msg, &trsp, timeout);
        }while(err == IPCLITE_ERR_OK && ! (trsp.flags & TRANSACT_RSP_F_DONE));
        dec_waiters(srv);
    }
    return err;
}

int ipclite_server_transact(ipclite *s, unsigned int peer,
                            const void *blob, size_t sz,
                            void *rsp, size_t *rsp_sz, int timeout)
{
    ipclite_server *srv = (ipclite_server *)s;
    int err = IPCLITE_ERR_OK;

    if(! srv || srv->base.type != IPCLITE_SERVER || ! blob || ! sz)
        return IPCLITE_ERR_INV;

    return do_transact(srv, peer, blob, sz, rsp, rsp_sz, timeout);
}

int ipclite_server_transact_ex(ipclite *s, unsigned int peer,
                               const void *blob, size_t sz,
                               ipclite_handler cb, void *ud, int timeout)
{
    ipclite_server *srv = (ipclite_server *)s;
    int err = IPCLITE_ERR_OK;

    if(srv && srv->base.type == IPCLITE_SERVER && blob && sz)
        return do_transact_ex(srv, peer, blob, sz, cb, ud, timeout);
    return IPCLITE_ERR_INV;
}

static void __ipclite_server_destroy(ipclite_server *srv)
{
    ipclite_session *sess, *n_sess;
    ipclite_msg *msg, *n_msg;

    close(srv->base.master);
    if(srv->base.msg)
        free(srv->base.msg);

    list_for_each_entry_safe(sess, n_sess, &srv->clients, list)  {
        list_delete(&sess->list);
        __delete_client(srv, sess);
    }

    list_for_each_msg_safe(msg, n_msg, &srv->rd_queue)  {
        list_delete(msg_list_ptr(msg));
        if(msg_ctl(msg)->free)
            free(msg);
    }

    list_for_each_msg_safe(msg, n_msg, &srv->wr_queue)  {
        list_delete(msg_list_ptr(msg));
        if(msg_ctl(msg)->free)
            free(msg);
    }

    close(srv->notify[0]);
    close(srv->notify[1]);

    wait_lock(srv);
    while(srv->wait_cnt)
        pthread_cond_wait(&srv->wait_cond, &srv->wait_lock);
    wait_unlock(srv);
    free(srv);
}

void ipclite_server_destroy(ipclite *s)
{
    ipclite_server *srv = (ipclite_server *)s;

    if(srv && srv->base.type != IPCLITE_SERVER)  {
        ipclite_server_quit(s, 1);
        if(srv->worker_started)
            LOGERROR("Worker not stopped when destroying");
        if(srv->dispatcher_started)
            LOGERROR("dispatcher not stoped when destroying");
        __ipclite_server_destroy(srv);
    }
}

