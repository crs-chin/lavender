/*
 * desert.h Cactus client routings
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

#ifndef __DESERT_H
#define __DESERT_H

#include "msg_base.h"
#include "util.h"

__BEGIN_DECLS

typedef void (*connect_cb)(int state, unsigned int peer, void *ud);
typedef void (*verdict_cb)(int type, const void *msg, void *ud);

/**
 * @msg: client banner to server.
 * @flags: unused currently
 */
int desert_init(const char *msg, connect_cb cb, void *ud);

#define DESERT_F_ABSTRACT 1     /* abstract server path */

/**
 * @peer: client peer ID filled in if not NULL.
 * @path: Cactus IPC path, use NULL as default.
 */
int desert_connect(unsigned int *peer, const char *path, int flags);
void desert_disconnect(void);

/**
 * @peer: client peer ID. set to 0 to register current client as
 * front-end.
 * @cb and @ud unused if @peer is not the current.
 */
int desert_register_fe(unsigned int peer, verdict_cb cb, void *ud);
int desert_unregister_fe(unsigned int peer);

/**
 * only available if self registered as front-end.
 */
int desert_send_verdict(uint64_t id, int verd);

int desert_load_rules(const char *rule_path);
int desert_dump_rules(const char *path);

int desert_switch_cactus(int enabled);

#define CACTUS_INACTIVE 0
#define CACTUS_ACTIVE 1

int desert_cactus_status(void);

/**
 * @version: cactus internal version number if not NULL
 */
const char *desert_cactus_version(int *version);

/**
 * Cactus has a cache(libc stdio cache) for log print.
 */
int desert_flush_logs(void);

int desert_log_control(const msg_log_ctl *ctl);
int desert_log_state(msg_log_stat *stat);

/**
 * @type: log type to set or -1 the mark all
 */
int desert_log_set_type_enabled(int type, int enabled);

/**
 * @lvl: log level to set or -1 to mark all
 */
int desert_log_set_level_enabled(int lvl, int enabled);

int desert_shutdown(void);

/**
 * general return values:
 *  0: disabled
 *  1: enabled
 * -1: generic err
 */
int desert_get_counter_status(void);
int desert_set_counter_enable(int enabled);

int desert_get_fw_table_state(msg_fw_table_state *st);

int desert_refresh_verdicts(void);

int desert_get_throttle_connection(__u16 zone, const conn_parm *parm);
int desert_set_throttle_connection(__u16 zone, const conn_parm *parm, int enabled);

int desert_get_throttle_proc(pid_t pid);
int desert_set_throttle_proc(pid_t pid, int enabled);

int desert_get_throttle_prog(const char *path, uid_t uid);
int desert_set_throttle_prog(const char *path, uid_t uid, int enabled);

int desert_get_throttle_user(uid_t uid);
int desert_set_throttle_user(uid_t uid, int enabled);

typedef struct _fw_obj fw_obj;

struct _fw_obj{
    list list;
    union{
        msg_prog_res prog[0];
        msg_proc_res proc[0];
        msg_user_res user[0];
        msg_nw_connection conn[0];
        char payload[0];
    };
};

static inline void fw_objs_free(list *objs)
{
    fw_obj *obj, *n;

    list_for_each_entry_safe(obj, n, objs, list)  {
        list_delete(&obj->list);
        free(obj);
    }
}

/**
 * return 0 to break iteration
 */
typedef int (*desert_conn_cb)(const msg_nw_connection *conn, void *ud);

void desert_get_proc_conn(pid_t pid, desert_conn_cb cb, void *ud);
void desert_get_prog_conn(const char *path, uid_t uid, desert_conn_cb cb, void *ud);
void desert_get_user_conn(uid_t uid, desert_conn_cb cb, void *ud);

void desert_get_all_proc_conn(list *conns, pid_t pid);
void desert_get_all_prog_conn(list *conns, const char *path, uid_t uid);
void desert_get_all_user_conn(list *conns, uid_t uid);

int desert_get_conn_counter(__u16 zone, const conn_parm *parm, msg_nw_counter *counter);
int desert_get_proc_counter(pid_t pid, msg_nw_counter *counter);
int desert_get_prog_counter(const char *path, uid_t uid, msg_nw_counter *counter);
int desert_get_user_counter(uid_t uid, msg_nw_counter *counter);

/**
 * return 0 to break iteration
 */
typedef int (*desert_prog_cb)(const msg_prog_res *prog, void *ud);
typedef int (*desert_user_cb)(const msg_user_res *user, void *ud);
typedef int (*desert_proc_cb)(const msg_proc_res *proc, void *ud);

#define ITER_F_ACTIVE 1         /* get active fw objects only */

void desert_get_fw_procs(desert_proc_cb cb, void *ud);
void desert_get_fw_progs(int flags, desert_prog_cb cb, void *ud);
void desert_get_fw_users(int flags, desert_user_cb cb, void *ud);
void desert_get_procs_of_prog(const char *path, desert_proc_cb cb, void *ud);
void desert_get_procs_of_user(uid_t uid, desert_proc_cb cb, void *ud);

void desert_get_all_fw_procs(list *procs);
void desert_get_all_fw_progs(list *progs, int flags);
void desert_get_all_fw_users(list *users, int flags);
void desert_get_all_procs_of_prog(list *procs, const char *path);
void desert_get_all_procs_of_user(list *procs, uid_t uid);

#define ACTION_TARGET(action)  ((action) & TARGET_MASK)
#define ACTION_VERDICT(action)  ((action) >> VERDICT_SHIFT)

int desert_set_proc_verdict(pid_t pid, int verd);
int desert_set_prog_verdict(const char *prog, uid_t uid, int verd);

int desert_get_proc_verdict(pid_t pid);
int desert_get_prog_verdict(const char *prog, uid_t uid);

int desert_make_test(const char *arg, char *buf, size_t sz);

__END_DECLS

#endif  /* ! __DESERT_H */
