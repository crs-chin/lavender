/*
 * async_work.c
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

#include <pthread.h>

#include "util.h"
#include "cactus_log.h"
#include "async_work.h"

#define AMSG_HASH_SIZE 32

#define ASYNC_WORK_F_INIT 1
#define ASYNC_WORK_F_THREADED (1<<1)
#define ASYNC_WORK_F_QUIT (1<<2)

typedef struct _async_bus async_bus;

struct _async_bus{
    async_work work;
    pthread_mutex_t lock;
    int initialized;
    int id_pool;
    list handlers;
    hlist_head hash[AMSG_HASH_SIZE];
};

static void msg_bus_work(async_work *, void *);

static async_bus msg_bus = {
    .work = {
        .name = "msg_bus_work",
        .flags = 0,
        .handler = msg_bus_work,
    },
    .initialized = 0,
    .id_pool = 1,
};

async_work *async_bus_work = &msg_bus.work;

static inline void lockup(async_work *aw)
{
    pthread_mutex_lock(&aw->lock);
}

static inline void unlock(async_work *aw)
{
    pthread_mutex_unlock(&aw->lock);
}

static inline void wakeup(async_work *aw)
{
    pthread_cond_signal(&aw->wait);
}

static inline void wait_on(async_work *aw)
{
    pthread_cond_wait(&aw->wait, &aw->lock);
}

static void *async_work_thread(void *arg)
{
    async_work *aw = (async_work *)arg;
    async_msg *am, *n;
    list ls;

    if(aw->name[0])
        prctl(PR_SET_NAME, (unsigned long)aw->name, 0, 0, 0);

    for(;;)  {
        lockup(aw);
        while(! (aw->flags & ASYNC_WORK_F_QUIT) && list_empty(&aw->queue))
            wait_on(aw);
        if(aw->flags & ASYNC_WORK_F_QUIT)
            break;
        list_assign(&ls, &aw->queue);
        unlock(aw);

        list_for_each_entry_safe(am, n, &ls, list)  {
            list_delete(&am->list);
            aw->handler(aw, am->msg);
            free(am);
        }
    }

    unlock(aw);
    return NULL;
}

void async_work_fini(async_work *aw)
{
    async_msg *am, *n;

    if(aw->flags & ASYNC_WORK_F_INIT)  {
        if(aw->flags & ASYNC_WORK_F_THREADED)  {
            lockup(aw);
            aw->flags |= ASYNC_WORK_F_QUIT;
            wakeup(aw);
            unlock(aw);
            pthread_join(aw->thread, NULL);
            aw->flags &= ~ASYNC_WORK_F_THREADED;
            aw->flags &= ~ASYNC_WORK_F_QUIT;
        }
        pthread_mutex_destroy(&aw->lock);
        pthread_cond_destroy(&aw->wait);

        list_for_each_entry_safe(am, n, &aw->queue, list)  {
            list_delete(&am->list);
            free(am);
        }
        aw->flags &= ~ASYNC_WORK_F_INIT;
    }
}

int async_work_init(async_work *aw)
{
    if(! aw
       || (aw->flags & ASYNC_WORK_F_INIT)
       || ! aw->handler)
        return -1;

    aw->flags = ASYNC_WORK_F_INIT;
    pthread_mutex_init(&aw->lock, NULL);
    pthread_cond_init(&aw->wait, NULL);
    list_init(&aw->queue);
    if(pthread_create(&aw->thread, NULL, async_work_thread, (void *)aw))  {
        async_work_fini(aw);
        return -1;
    }
    aw->flags = ASYNC_WORK_F_THREADED;
    return 0;
}

static inline async_handler *async_handler_lookup(async_bus *ab, int id)
{
    hlist_head *head = &ab->hash[id % AMSG_HASH_SIZE];
    async_handler *handler;
    hlist *pos;

    hlist_for_each_entry(handler, pos, head, node)  {
        if(id == handler->id)
            return handler;
    }
    return NULL;
}

static void msg_bus_work(async_work *aw, void *msg)
{
    async_bus *ab = (async_bus *)aw;
    amsg *am = (amsg *)msg;
    async_handler *ah;

    pthread_mutex_lock(&ab->lock);
    if((ah = async_handler_lookup(ab, am->id)))
        ah->handler(ah, am->msg);
    if(! ah)
        LOG_WARN("can find async handler of ID %d", am->id);
    pthread_mutex_unlock(&ab->lock);
}

int async_bus_init(void)
{
    int err = -1;

    if(msg_bus.initialized)
        return 0;
    pthread_mutex_init(&msg_bus.lock, NULL);
    list_init(&msg_bus.handlers);
    memset(&msg_bus.hash, 0, sizeof(msg_bus.hash));
    if(! (err = async_work_init(&msg_bus.work)))
        msg_bus.initialized = 1;
    return err;
}

int async_register_handler(async_handler *handler)
{
    async_handler *iter;
    hlist_head *head;

    if(! handler || ! handler->name || ! *handler->name || ! handler->handler)
        return -1;

    pthread_mutex_lock(&msg_bus.lock);
    list_for_each_entry(iter, &msg_bus.handlers, list)  {
        if(! strcmp(handler->name, iter->name))  {
            pthread_mutex_unlock(&msg_bus.lock);
            return -1;
        }
    }

    /* should never overflow */
    handler->id = msg_bus.id_pool++;
    head = &msg_bus.hash[handler->id % AMSG_HASH_SIZE];
    hlist_prepend(head, &handler->node);
    list_append(&msg_bus.handlers, &handler->list);
    pthread_mutex_unlock(&msg_bus.lock);
    return 0;
}

void async_unregister_handler(async_handler *handler)
{
    if(handler)  {
        pthread_mutex_lock(&msg_bus.lock);
        hlist_delete(&handler->node);
        list_delete(&handler->list);
        pthread_mutex_unlock(&msg_bus.lock);
    }
}

