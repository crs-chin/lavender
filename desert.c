/*
 * desert.c Cactus client routings
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
#include "rpclite.h"
#include "msg_base.h"
#include "desert.h"

static int __initialized = 0;
static ipclite *ipc_client = NULL;
static int ipc_seq = 0;
static rpclite_ctx rpc_ctx = {
    .svc_name = CACTUS_SVC_NAME,
};

static connect_cb on_connect = NULL;
static void *on_connect_ud = NULL;

static verdict_cb on_verdict = NULL;
static void *on_verdict_ud = NULL;

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static unsigned int peer = 0;


static int ipc_cb(ipclite_msg *msg, void *ud)
{
    switch(msg->hdr.msg)  {
    case IPCLITE_MSG_SYN:  {
        connect_cb cb = NULL;
        void *ud = NULL;

        ipclite_msg_syn *syn = (ipclite_msg_syn *)msg->hdr.data;
        pthread_mutex_lock(&lock);
        peer = syn->peer;
        if(syn->len)
            PR_INFO("Connected to Lavender:%.*s", syn->len, syn->msg);
        cb = on_connect;
        ud = on_connect_ud;
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&lock);
        if(cb)
            cb(1, syn->peer, ud);
        break;
    }
    case IPCLITE_MSG_CLS:  {
        connect_cb cb = NULL;
        void *ud = NULL;

        pthread_mutex_lock(&lock);
        peer = 0;
        PR_INFO("Lost connect to Lavender");
        cb = on_connect;
        ud = on_connect_ud;
        pthread_cond_broadcast(&cond);
        pthread_mutex_unlock(&lock);
        if(cb)
            cb(0, 0, ud);
        break;
    }
    case CACTUS_VERDICT_REQUEST:
    case CACTUS_RUNTIME_INFO:  {
        verdict_cb cb;
        void *ud;

        pthread_mutex_lock(&lock);
        cb = on_verdict;
        ud = on_verdict_ud;
        pthread_mutex_unlock(&lock);
        cb(msg->hdr.msg, (const void *)msg->hdr.data, ud);
        break;
    }
    default:
        PR_WARN("Unrecognized msg received:%d", msg->hdr.msg);
        break;
    }
    return 0;
}

static int __desert_init(const char *msg, connect_cb cb, void *ud)
{
    int err;

    if((err = ipclite_client_create(&ipc_client, msg, 0)))  {
        PR_ERROR("Fail to create ipc client:%s", ipclite_err_string(err));
        return -1;
    }

    if((err = ipclite_client_run(ipc_client, ipc_cb, NULL)))  {
        PR_ERROR("Fail to run ipc engine:%s", ipclite_err_string(err));
        ipclite_client_destroy(ipc_client);
        return -1;
    }

    on_connect = cb;
    on_connect_ud = ud;
    __initialized = 1;
    return 0;
}

int desert_init(const char *msg, connect_cb cb, void *ud)
{
    if(! __initialized)
        return __desert_init(msg, cb, ud);
    return 0;
}

/**
 * @peer: client peer ID filled in if not NULL.
 * @path: Cactus IPC path, use NULL as default.
 */
int desert_connect(unsigned int *peer_id, const char *path, int flags)
{
    const char *p = CACTUS_SERVER_PATH;
    int flg = CACTUS_SERVER_ABSTRACT ? IPCLITE_F_ABSTRACT : 0;
    int err;

    if(path)  {
        if(flags & DESERT_F_ABSTRACT)
            flags = IPCLITE_F_ABSTRACT;
        p = path;
    }

    /* wait ipc state synced */
    pthread_mutex_lock(&lock);
    if((err = ipclite_client_connect(ipc_client, p, flg)))  {
        PR_ERROR("Fail to connect ipc client:%s", ipclite_err_string(err));
        pthread_mutex_unlock(&lock);
        return -1;
    }

    while(! peer)
        pthread_cond_wait(&cond, &lock);
    if(peer_id)
        *peer_id = peer;
    pthread_mutex_unlock(&lock);

    if(rpclite_connect_svc(&rpc_ctx, ipc_client, 0, 0))  {
        PR_ERROR("Fail to connect cactus service");
        ipclite_client_disconnect(ipc_client, 1, 1);
        return -1;
    }
    return 0;
}

void desert_disconnect(void)
{
    rpclite_disconnect_svc(&rpc_ctx);
    ipclite_client_disconnect(ipc_client, 1, 1);
}

/**
 * @peer: client peer ID.
 */
int desert_register_fe(unsigned int peer_id, verdict_cb cb, void *ud)
{
    msg_fe_register reg;
    int err = 0;

    assert(__initialized);

    if(! cb)
        return -1;
    pthread_mutex_lock(&lock);
    reg.peer = peer_id ? : peer;
    if(! reg.peer)  {
        pthread_mutex_unlock(&lock);
        PR_WARN("can't self register, not connected yet.");
        return -1;
    }
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_REGISTER_FE, (const void *)&reg, sizeof(reg), NULL, NULL, 0);
    if(reg.peer == peer && err == RPC_ERR_OK)  {
        on_verdict = cb;
        on_verdict_ud = ud;
    }
    pthread_mutex_unlock(&lock);
    return err;
}


int desert_unregister_fe(unsigned int peer_id)
{
    msg_fe_unregister unreg;
    int err = 0;

    assert(__initialized);
    pthread_mutex_lock(&lock);
    if(! peer_id)
        peer_id = peer;
    if(! peer_id)  {
        pthread_mutex_unlock(&lock);
        return -1;
    }
    unreg.peer = peer_id;
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_UNREGISTER_FE, (const void *)&unreg, sizeof(unreg), NULL, NULL, 0);
    if(peer == unreg.peer && err == RPC_ERR_OK)
        peer = 0;
    pthread_mutex_unlock(&lock);
    return err;
}

int desert_send_verdict(uint64_t id, int verd)
{
    char _msg[sizeof(ipclite_msg) + sizeof(msg_verdict_res)];
    ipclite_msg *msg = (ipclite_msg *)&_msg;
    msg_verdict_res *blob = MSG_PAYLOAD(msg_verdict_res,msg);
    int err = CACTUS_ERR_BAD_PARM;

    if(verd > VERDICT_NONE && verd < NUM_VERDICT)  {
        pthread_mutex_lock(&lock);
        msg->hdr.peer = peer;
        msg->hdr.id = ++ipc_seq;
        msg->hdr.msg = CACTUS_VERDICT_RESULT;
        msg->hdr.len = MSG_LENGTH(sizeof(msg_verdict_res));
        blob->id = id;
        blob->verdict = verd;
        pthread_mutex_unlock(&lock);
        err = ipclite_client_sendmsg(ipc_client, msg, 1, 0);
    }
    return err;
}

static inline int __load_rules(const char *path)
{
    char msg[sizeof(msg_rule_req) + strlen(path) + 1];
    msg_rule_req *blob = (msg_rule_req *)&msg;

    strcpy(blob->path, path);

    return rpclite_transact(&rpc_ctx, CACTUS_REQ_RULE_LOAD, blob, sizeof(msg),
                            NULL, NULL, 0);
}

int desert_load_rules(const char *rule_path)
{
    assert(__initialized);

    if(! rule_path || ! *rule_path)
        return -1;
    return __load_rules(rule_path);
}

static int __dump_rules(const char *path)
{
    char msg[sizeof(msg_rule_req) + strlen(path) + 1];
    msg_rule_req *blob = (msg_rule_req *)&msg;

    strcpy(blob->path, path);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_RULE_DUMP, blob, sizeof(msg),
                            NULL, NULL, 0);
}

int desert_dump_rules(const char *path)
{
    assert(__initialized);

    if(! path || ! *path)
        return -1;
    return __dump_rules(path);
}

int desert_switch_cactus(int enabled)
{
    assert(__initialized);

    if(enabled)
        return rpclite_transact(&rpc_ctx, CACTUS_REQ_CORE_ACTIVATE, NULL, 0,
                                NULL, NULL, 0);
    return  rpclite_transact(&rpc_ctx, CACTUS_REQ_CORE_DEACTIVATE, NULL, 0,
                             NULL, NULL, 0);
}

int desert_cactus_status(void)
{
    msg_core_status st;
    size_t sz = sizeof(st);
    int err;

    assert(__initialized);
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_CORE_STATUS, NULL, 0,
                           &st, &sz, 0);
    if(err == RPC_ERR_OK)  {
        switch(st.status)  {
        case STATUS_INACTIVE:
            return CACTUS_INACTIVE;
        case STATUS_ACTIVE:
            return CACTUS_ACTIVE;
        default:
            break;
        }
    }
    return -1;
}

const char *desert_cactus_version(int *version)
{
    static char _cactus_version[1024];
    static int cactus_version = 0;
    msg_core_version *ver = (msg_core_version *)&_cactus_version;
    size_t sz = sizeof(_cactus_version);

    assert(__initialized);
    if(cactus_version)  {
        if(version)
            *version = cactus_version;
        return ver->banner;
    }

    if(rpclite_transact(&rpc_ctx, CACTUS_REQ_CORE_VERSION, NULL, 0,
                        _cactus_version, &sz, 0) == RPC_ERR_OK)  {
        cactus_version = ver->version;
        if(version)
            *version = cactus_version;
        return ver->banner;
    }

    if(version)
        *version = 0;
    return NULL;
}

/**
 * Cactus has a cache(libc stdio cache) for log print.
 */
int desert_flush_logs(void)
{
    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_FLUSH, NULL, 0,
                            NULL, NULL, 0);
}


int desert_log_control(const msg_log_ctl *ctl)
{
    assert(__initialized);

    if(ctl)
        return rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_CONTROL, ctl, sizeof(*ctl),
                                NULL, NULL, 0);
    return CACTUS_ERR_BAD_PARM;
}

int desert_log_state(msg_log_stat *stat)
{
    size_t rsp_sz = sizeof(*stat);

    assert(__initialized);

    if(stat)
        return rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_STATE, NULL, 0,
                                stat, &rsp_sz, 0);
    return CACTUS_ERR_BAD_PARM;
}

int desert_log_set_type_enabled(int type, int enabled)
{
    msg_log_stat stat;
    size_t sz = sizeof(stat);
    int i, err = CACTUS_ERR_BAD_PARM;

    assert(__initialized);
    if(type == -1 || (type >= 0 && type < NUM_LOG))  {
        enabled = !! enabled;
        err = rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_STATE, NULL, 0,
                               &stat, &sz, 0);
        if(err == CACTUS_ERR_OK)  {
            if(type == -1)  {
                for(i = 0; i < NUM_LOG; i++)
                    stat.ctl[i] = enabled;
            }else  {
                stat.ctl[type] = enabled;
            }
            err = rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_CONTROL, &stat, sizeof(stat),
                                   NULL, NULL, 0);
        }
    }
    return err;
}

int desert_log_set_level_enabled(int lvl, int enabled)
{
    msg_log_stat stat;
    size_t sz = sizeof(stat);
    int i, err = CACTUS_ERR_BAD_PARM;

    assert(__initialized);
    if(lvl == -1 || (lvl >= 0 && lvl < NUM_LVL))  {
        enabled = !! enabled;
        err = rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_STATE, NULL, 0,
                               &stat, &sz, 0);
        if(err == CACTUS_ERR_OK)  {
            if(lvl == -1)  {
                for(i = 0; i < NUM_LVL; i++)
                    stat.mask[i] = enabled;
            }else  {
                stat.mask[lvl] = enabled;
            }
            err = rpclite_transact(&rpc_ctx, CACTUS_REQ_LOG_CONTROL, &stat, sizeof(stat),
                                   NULL, NULL, 0);
        }
    }
    return err;
}

int desert_shutdown(void)
{
    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_CORE_EXIT, NULL, 0,
                            NULL, NULL, 0);
}

int desert_get_counter_status(void)
{
    msg_counter_status st = {
        .cmd = CMD_QUERY,
        .status = 0,
    };
    msg_counter_status res;
    size_t sz = sizeof(res);
    int err;

    assert(__initialized);
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_COUNTER_STATUS,
                           &st, sizeof(st), &res, &sz, 0);
    if(err == CACTUS_ERR_OK)
        return res.status;
    return -1;
}

int desert_set_counter_enable(int enabled)
{
    msg_counter_status st = {
        .cmd = CMD_SET,
        .status = 0,
    };

    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_COUNTER_STATUS,
                           &st, sizeof(st), NULL, NULL, 0);
}

int desert_get_fw_table_state(msg_fw_table_state *st)
{
    size_t sz = sizeof(*st);

    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_FW_TABLE_STATE,
                            NULL, 0, st, &sz, 0);
}

int desert_refresh_verdicts(void)
{
    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_REFRESH_VERDICT,
                            NULL, 0, NULL, NULL, 0);
}

int desert_get_throttle_connection(__u16 zone, const conn_parm *parm)
{
    msg_throttle_req req = {
        .cmd = CMD_QUERY,
        .type = THROTTLE_CONN,
    };
    msg_throttle_res res = {
        .type = THROTTLE_CONN,
        .enabled = 0,
    };
    size_t sz = sizeof(res);
    int err;

    assert(__initialized);
    req.zone = zone;
    memcpy(&req.conn_parm, parm, sizeof(*parm));
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                           &req, sizeof(req), &res, &sz, 0);
    if(err == CACTUS_ERR_OK)
        return res.enabled;
    return -1;
}

int desert_set_throttle_connection(__u16 zone, const conn_parm *parm, int enabled)
{
    msg_throttle_req req = {
        .cmd = CMD_SET,
        .type = THROTTLE_CONN,
        .enabled = enabled,
    };

    assert(__initialized);
    req.zone = zone;
    memcpy(&req.conn_parm, parm, sizeof(*parm));
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                            &req, sizeof(req), NULL, NULL, 0);
}

int desert_get_throttle_proc(pid_t pid)
{
    msg_throttle_req req = {
        .cmd = CMD_QUERY,
        .type = THROTTLE_PROC,
    };
    msg_throttle_res res = {
        .type = THROTTLE_PROC,
        .enabled = 0,
    };
    size_t sz = sizeof(res);
    int err;

    assert(__initialized);
    req.pid = pid;
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                           &req, sizeof(req), &res, &sz, 0);
    if(err == CACTUS_ERR_OK)
        return res.enabled;
    return -1;
}

int desert_set_throttle_proc(pid_t pid, int enabled)
{
    msg_throttle_req req = {
        .cmd = CMD_SET,
        .type = THROTTLE_PROC,
        .enabled = enabled,
    };

    assert(__initialized);
    req.pid = pid;
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                            &req, sizeof(req), NULL, NULL, 0);
}

int desert_get_throttle_prog(const char *path, uid_t uid)
{
    char _req[sizeof(msg_throttle_req) + strlen(path) + 1];
    msg_throttle_req *req = (msg_throttle_req *)&_req;
    msg_throttle_res res = {
        .type = THROTTLE_PROG,
        .enabled = 0,
    };
    size_t sz = sizeof(res);
    int err;

    assert(__initialized);
    req->cmd = CMD_QUERY;
    req->type = THROTTLE_PROG;
    req->uid = uid;
    strcpy(req->path, path);
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                           req, sizeof(_req), &res, &sz, 0);
    if(err == CACTUS_ERR_OK)
        return res.enabled;
    return -1;
}

int desert_set_throttle_prog(const char *path, uid_t uid, int enabled)
{
    char _req[sizeof(msg_throttle_req) + strlen(path) + 1];
    msg_throttle_req *req = (msg_throttle_req *)&_req;

    assert(__initialized);
    req->cmd = CMD_SET;
    req->type = THROTTLE_PROG;
    req->enabled = enabled;
    req->uid = uid;
    strcpy(req->path, path);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                            req, sizeof(_req), NULL, NULL, 0);
}

int desert_get_throttle_user(uid_t uid)
{
    msg_throttle_req req = {
        .cmd = CMD_QUERY,
        .type = THROTTLE_USER,
    };
    msg_throttle_res res = {
        .type = THROTTLE_PROC,
        .enabled = 0,
    };
    size_t sz = sizeof(res);
    int err;

    assert(__initialized);
    req.uid = uid;
    err = rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                           &req, sizeof(req), &res, &sz, 0);
    if(err == CACTUS_ERR_OK)
        return res.enabled;
    return -1;
}

int desert_set_throttle_user(uid_t uid, int enabled)
{
    msg_throttle_req req = {
        .cmd = CMD_SET,
        .type = THROTTLE_USER,
        .enabled = enabled,
    };

    assert(__initialized);
    req.uid = uid;
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_THROTTLE_CONNECTION,
                            &req, sizeof(req), NULL, NULL, 0);
}

typedef struct _get_conn_ctx get_conn_ctx;

struct _get_conn_ctx{
    desert_conn_cb cb;
    void *ud;
};

static int get_conn_cb(void *rsp, size_t sz, int flags, void *ud)
{
    get_conn_ctx *ctx = (get_conn_ctx *)ud;
    msg_nw_connection *conn = (msg_nw_connection *)rsp;

    /* end of sequence */
    if(sz == 0)
        return 0;

    if(sz != sizeof(*conn))  {
        PR_ERROR("invalid nw conn blob size returned, break");
        return 0;
    }
    return ctx->cb(conn, ctx->ud);
}

int desert_get_proc_conn(pid_t pid, desert_conn_cb cb, void *ud)
{
    msg_query_nw_req req = {
        .type = TYPE_PROC,
    };
    get_conn_ctx ctx = {
        .cb = cb, .ud = ud,
    };

    assert(__initialized);
    req.pid = pid;
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                     &req, sizeof(req), get_conn_cb, &ctx, 0);
}

int desert_get_prog_conn(const char *path, uid_t uid, desert_conn_cb cb, void *ud)
{
    char _req[sizeof(msg_query_nw_req) + strlen(path) + 1];
    msg_query_nw_req *req = (msg_query_nw_req *)&_req;
    get_conn_ctx ctx = {
        .cb = cb, .ud = ud,
    };

    assert(__initialized);
    req->type = TYPE_PROG;
    req->uid = uid;
    strcpy(req->path, path);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                     req, sizeof(_req), get_conn_cb, &ctx, 0);
}

int desert_get_user_conn(uid_t uid, desert_conn_cb cb, void *ud)
{
    msg_query_nw_req req = {
        .type = TYPE_USER,
    };
    get_conn_ctx ctx = {
        .cb = cb, .ud = ud,
    };

    assert(__initialized);
    req.uid = uid;
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                     &req, sizeof(req), get_conn_cb, &ctx, 0);
}

static int cp_conn_cb(void *rsp, size_t sz, int flags, void *ud)
{
    list *head = (list *)ud;
    msg_nw_connection *conn = (msg_nw_connection *)rsp;
    fw_obj *obj;

    /* end of sequence */
    if(sz == 0)
        return 0;

    if(sz != sizeof(*conn))  {
        PR_ERROR("invalid nw conn blob size returned, break");
        return 0;
    }

    if((obj = new_instance_ex(fw_obj, sz)))  {
        memcpy(obj->payload, rsp, sz);
        list_append(head, &obj->list);
        return 1;
    }
    PR_ERROR("OOM alloc fw obj");
    return 0;
}

int desert_get_all_proc_conn(list *conns, pid_t pid)
{
    msg_query_nw_req req = {
        .type = TYPE_PROC,
    };

    assert(__initialized);
    req.pid = pid;
    list_init(conns);
   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                    &req, sizeof(req), cp_conn_cb, conns, 0);
}

int desert_get_all_prog_conn(list *conns, const char *path, uid_t uid)
{
    char _req[sizeof(msg_query_nw_req) + strlen(path) + 1];
    msg_query_nw_req *req = (msg_query_nw_req *)&_req;

    assert(__initialized);
    req->type = TYPE_PROG;
    req->uid = uid;
    strcpy(req->path, path);
    list_init(conns);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                     req, sizeof(_req), cp_conn_cb, conns, 0);
}

int desert_get_all_user_conn(list *conns, uid_t uid)
{
    msg_query_nw_req req = {
        .type = TYPE_USER,
    };

    assert(__initialized);
    req.uid = uid;
    list_init(conns);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_NW_CONNECTION,
                                     &req, sizeof(req), cp_conn_cb, conns, 0);
}

int desert_get_conn_counter(__u16 zone, const conn_parm *parm, msg_nw_counter *counter)
{
    msg_query_nw_req req = {
        .type = TYPE_CONN,
    };
    size_t sz = sizeof(*counter);

    assert(__initialized);
    req.zone = zone;
    req.conn_parm = *parm;
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_QUERY_NW_COUNTER,
                            &req, sizeof(req), counter, &sz, 0);
}

int desert_get_proc_counter(pid_t pid, msg_nw_counter *counter)
{
    msg_query_nw_req req = {
        .type = TYPE_PROC,
    };
    size_t sz = sizeof(*counter);

    assert(__initialized);
    req.pid = pid;
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_QUERY_NW_COUNTER,
                            &req, sizeof(req), counter, &sz, 0);
}

int desert_get_prog_counter(const char *path, uid_t uid, msg_nw_counter *counter)
{
    char _req[sizeof(msg_query_nw_req *) + strlen(path) + 1];
    msg_query_nw_req *req = (msg_query_nw_req *)&_req;
    size_t sz = sizeof(*counter);

    req->type = TYPE_PROG;
    req->uid = uid;
    strcpy(req->path, path);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_QUERY_NW_COUNTER,
                            req, sizeof(_req), counter, &sz, 0);

}

int desert_get_user_counter(uid_t uid, msg_nw_counter *counter)
{
    msg_query_nw_req req = {
        .type = TYPE_USER,
    };
    size_t sz = sizeof(*counter);

    assert(__initialized);
    req.uid = uid;
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_QUERY_NW_COUNTER,
                            &req, sizeof(req), counter, &sz, 0);
}

typedef struct _get_obj_ctx get_obj_ctx;

struct _get_obj_ctx{
    int type;
    union{
        desert_prog_cb prog_cb;
        desert_user_cb user_cb;
        desert_proc_cb proc_cb;
    };
    void *ud;
};

static int get_obj_cb(void *rsp, size_t sz, int flags, void *ud)
{
    get_obj_ctx *ctx = (get_obj_ctx *)ud;

    if(sz == 0)
        return 0;

    switch(ctx->type)  {
    case TYPE_PROC:  {
        msg_proc_res *proc = (msg_proc_res *)rsp;

        if(sz <= sizeof(*proc))  {
            PR_ERROR("invalid nw proc blob size returned, break");
            return 0;
        }
        return ctx->proc_cb(proc, ctx->ud);
    }
    case TYPE_PROG:  {
        msg_prog_res *prog = (msg_prog_res *)rsp;

        if(sz <= sizeof(*prog))  {
            PR_ERROR("invalid nw prog blob size returned, break");
            return 0;
        }
        return ctx->prog_cb(prog, ctx->ud);
    }
    case TYPE_USER:  {
        msg_user_res *user = (msg_user_res *)rsp;

        if(sz <= sizeof(*user))  {
            PR_ERROR("invalid nw user blob size returned, break");
            return 0;
        }
        return ctx->user_cb(user, ctx->ud);
    }
    default:
        PR_ERROR("invalid get_obj_ctx type:%d, break", ctx->type);
        return 0;
    }
}

int desert_get_fw_procs(desert_proc_cb cb, void *ud)
{
    msg_query_fw_req req = {
        .type = TYPE_PROC,
        {.by_which = BY_NONE,},
        .uid = 0,
    };
    get_obj_ctx ctx = {
        .type = TYPE_PROC,
        {.proc_cb = cb,},
        .ud = ud,
    };

   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                    &req, sizeof(req), get_obj_cb, &ctx, 0);
}

int desert_get_fw_progs(int flags, desert_prog_cb cb, void *ud)
{
    msg_query_fw_req req = {
        .type = TYPE_PROG,
        {.active_only = flags & ITER_F_ACTIVE,},
        .uid = 0,
    };
    get_obj_ctx ctx = {
        .type = TYPE_PROG,
        {.prog_cb = cb,},
        .ud = ud,
    };

   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                    &req, sizeof(req), get_obj_cb, &ctx, 0);
}

int desert_get_fw_users(int flags, desert_user_cb cb, void *ud)
{
    msg_query_fw_req req = {
        .type = TYPE_USER,
        {.active_only = flags & ITER_F_ACTIVE,},
        .uid = 0,
    };
    get_obj_ctx ctx = {
        .type = TYPE_USER,
        {.user_cb = cb,},
        .ud = ud,
    };

   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                    &req, sizeof(req), get_obj_cb, &ctx, 0);
}

int desert_get_procs_of_prog(const char *path, desert_proc_cb cb, void *ud)
{
    char _req[sizeof(msg_query_fw_req) + strlen(path) + 1];
    msg_query_fw_req *req = (msg_query_fw_req *)&_req;
    get_obj_ctx ctx = {
        .type = TYPE_PROC,
        {.proc_cb = cb,},
        .ud = ud,
    };

    req->type = TYPE_PROC;
    req->by_which = BY_PROG;
    req->uid = 0;
    strcpy(req->path, path);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                     req, sizeof(_req), get_obj_cb, &ctx, 0);
}

int desert_get_procs_of_user(uid_t uid, desert_proc_cb cb, void *ud)
{
    msg_query_fw_req req = {
        .type = TYPE_PROC,
        {.by_which = BY_USER,},
        .uid = uid,
    };
    get_obj_ctx ctx = {
        .type = TYPE_PROC,
        {.proc_cb = cb,},
        .ud = ud,
    };

    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                     &req, sizeof(req), get_obj_cb, &ctx, 0);
}

static int cp_obj_cb(void *rsp, size_t sz, int flags, void *ud)
{
    list *head = (list *)ud;
    fw_obj *obj;

    /* end of sequence */
    if(sz == 0)
        return 0;
    /* ??check blob from server */
    if((obj = new_instance_ex(fw_obj, sz)))  {
        memcpy(obj->payload, rsp, sz);
        list_append(head, &obj->list);
        return 1;
    }
    PR_ERROR("OOM alloc fw obj!");
    return 0;
}

int desert_get_all_fw_procs(list *procs)
{
    msg_query_fw_req req = {
        .type = TYPE_PROC,
        {.by_which = BY_NONE,},
        .uid = 0,
    };

    list_init(procs);
   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                    &req, sizeof(req), cp_obj_cb, procs, 0);
}

int desert_get_all_fw_progs(list *progs, int flags)
{
    msg_query_fw_req req = {
        .type = TYPE_PROG,
        {.active_only = flags & ITER_F_ACTIVE,},
        .uid = 0,
    };

    list_init(progs);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                     &req, sizeof(req), cp_obj_cb, progs, 0);
}

int desert_get_all_fw_users(list *users, int flags)
{
    msg_query_fw_req req = {
        .type = TYPE_USER,
        {.active_only = flags & ITER_F_ACTIVE,},
        .uid = 0,
    };

    list_init(users);
   return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                    &req, sizeof(req), cp_obj_cb, users, 0);
}

int desert_get_all_procs_of_prog(list *procs, const char *path)
{
    char _req[sizeof(msg_query_fw_req) + strlen(path) + 1];
    msg_query_fw_req *req = (msg_query_fw_req *)&_req;

    req->type = TYPE_PROC;
    req->by_which = BY_PROG;
    req->uid = 0;
    strcpy(req->path, path);
    list_init(procs);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                     req, sizeof(_req), cp_obj_cb, procs, 0);
}

int desert_get_all_procs_of_user(list *procs, uid_t uid)
{
    msg_query_fw_req req = {
        .type = TYPE_PROC,
        {.by_which = BY_USER,},
        .uid = uid,
    };

    list_init(procs);
    return rpclite_transact_callback(&rpc_ctx, CACTUS_REQ_QUERY_FW_OBJECT,
                                     &req, sizeof(req), cp_obj_cb, procs, 0);
}

int desert_set_proc_verdict(pid_t pid, int verd)
{
    /* TODO: */
    return -1;
}

int desert_set_prog_verdict(const char *prog, uid_t uid, int verd)
{
    /* TODO: */
    return -1;
}

int desert_get_proc_verdict(pid_t pid)
{
    /* TODO: */
    return -1;
}

int desert_get_prog_verdict(const char *prog, uid_t uid)
{
    /* TODO: */
    return -1;
}

int desert_make_test(const char *arg, char *buf, size_t sz)
{
    assert(__initialized);
    return rpclite_transact(&rpc_ctx, CACTUS_REQ_MAKE_TEST,
                            arg, strlen(arg) + 1, buf, &sz, 0);
}

