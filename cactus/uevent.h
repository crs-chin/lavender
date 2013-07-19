/*
 * uevent.h Interface to kernel uevent subsystem
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

#ifndef __UEVENT_H
#define __UEVENT_H

#include "util.h"
#include "ginkgo.h"

__BEGIN_DECLS

typedef struct _uevent_msg uevent_msg;
typedef struct _uevent_handler uevent_handler;
typedef void (*uevent_notify)(uevent_msg *msg, void *ud);

enum{
    ACTION_ADD,
    ACTION_REMOVE,
    ACTION_CHANGE,
    ACTION_MOVE,
    ACTION_ONLINE,
    ACTION_OFFLINE,
};

struct _uevent_msg{
    int action;   
    char *path; 
    char *env;
};

/**
 * action bit mask
 */
#define ACTION_F_ADD 1
#define ACTION_F_REMOVE (1<<1)
#define ACTION_F_CHANGE (1<<2)
#define ACTION_F_MOVE (1<<3)
#define ACTION_F_ONLINE (1<<4)
#define ACTION_F_OFFLINE (1<<5)

#define ACTION_F_ALL ((1<<6) - 1)

/**
 * children path events inclusive
 */
#define UEVENT_F_INCLUSIVE 1

struct _uevent_handler{
    list list;
    int actions;
    char *path;
    int len;
    uevent_notify cb;
    void *ud;
    int flags;
};

#define uevent_ginkgo_msg(msg)                  \
    container_of(msg,ginkgo_msg,cmn)

#define uevent_msg_for_each_env(p,msg)          \
    {ginkgo_msg *__gmsg = uevent_ginkgo_msg(msg);                       \
    char *__payload = __gmsg->payload;                                 \
    int __payload_len = __gmsg->len - sizeof(ginkgo_msg);               \
    for(p = msg->env; p && (p - __payload < __payload_len) && *p; p += strlen(p) + 1)

#ifndef list_end
#define list_end }
#endif

int uevent_init(ginkgo_ctx *ctx);

int uevent_register_handler(uevent_handler *handler);
void uevent_unregister_handler(uevent_handler *handler);

__END_DECLS

#endif  /* __UEVENT_H */

