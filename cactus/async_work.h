/*
 * async_work.h asynchronous msg handler
 * Copyright (C) 2013  Crs Chin <crs.chin@gmail.com>
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

#ifndef __ASYNC_WORK_H
#define __ASYNC_WORK_H

#include <pthread.h>

#include "util.h"

__BEGIN_DECLS

typedef struct _async_work async_work;
typedef struct _async_msg async_msg;

struct _async_work{
    char name[16];
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t wait;
    list queue;
    int flags;
    void (*handler)(async_work *handler, void *msg);
};

struct _async_msg{
    list list;
    /* implementation defined */
    char msg[0];
};

int async_work_init(async_work *handler);
void async_work_fini(async_work *handler);

static void async_work_post(async_work *handler, async_msg *am)
{
    pthread_mutex_lock(&handler->lock);
    list_append(&handler->queue, &am->list);
    pthread_cond_signal(&handler->wait);
    pthread_mutex_unlock(&handler->lock);
}

static int async_work_post_full(async_work *handler, size_t len, const char *msg)
{
    async_msg *am = new_instance_ex(async_msg, len);

    if(am)  {
        list_init(&am->list);
        memcpy(&am->msg, msg, len);
        async_work_post(handler, am);
        return 0;
    }
    return -1;
}

/* asychronous message */
typedef struct _async_handler async_handler;
typedef struct _amsg amsg;
typedef struct _async_handler_msg async_handler_msg;

struct _async_handler{
    char *name;
    list list;
    hlist node;
    int id;
    /* don't call amsg functions inside the handler */
    void (*handler)(async_handler *handler, void *msg);
};

struct _amsg{
    int id;
    char msg[0];
};

struct _async_handler_msg{
    list list;
    union{
        amsg amsg;
        struct{
            int id;
            char msg[0];
        };
    };
};

extern async_work *async_bus_work;

int async_bus_init(void);

int async_register_handler(async_handler *handler);
void async_unregister_handler(async_handler *handler);

static inline void async_post(async_handler_msg *am)
{
    async_work_post(async_bus_work, (async_msg *)am);
}

static inline int async_post_full(int id, size_t len, const char *msg)
{
    async_handler_msg *am = new_instance_ex(async_handler_msg, len);

    if(am)  {
        list_init(&am->list);
        am->id = id;
        memcpy(&am->msg, msg, len);
        async_post(am);
        return 0;
    }
    return -1;
}

__END_DECLS

#endif  /* ! __ASYNC_WORK_H */
