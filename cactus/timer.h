/*
 * timer.h
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

#ifndef __TIMER_H
#define __TIMER_H

#include <time.h>
#include <pthread.h>

#include "util.h"

__BEGIN_DECLS

typedef struct _timer timer;

/**
 * return 0 to stop furthur delivery for interval timer
 */
typedef int (*timer_cb)(void *ud);

struct _timer{
    list list;
    int tfd;
#define TIMER_F_REGISTER 1
#define TIMER_F_INTERVAL (1<<1)
#define TIMER_F_SCHED (1<<2)
    int flags;
    /* set to NULL if no need */
    pthread_mutex_t *lock;
    struct timespec ts;
    unsigned int val;
    timer_cb cb;
    void *ud;
};

#define TIMER_INIT(lck,fn,arg)                      \
    {.flags = 0, .lock = lck, .cb = fn, .ud = arg}

static inline void
timer_init(timer *t, pthread_mutex_t *lock, timer_cb cb, void *ud)
{
    t->flags = 0;
    t->lock = lock;
    t->cb = cb;
    t->ud = ud;
}

/**
 * @flags: not used currently
 */
int timer_initialize(int flags);

int timer_register_src(timer *t);
void timer_unregister_src(timer *t);

#define TIMER_INTERVAL 1

/**
 * this could also be used to modify timers, set @t->lock for
 * synchronization problems
 */
int __timer_sched(timer *t, int flags, unsigned int val);
int __timer_sched_abs(timer *t, const struct timespec *ts);
void __timer_cancel(timer *t);

static inline void timer_lock(timer *t)
{
    if(t->lock)
        pthread_mutex_lock(t->lock);
}

static inline void timer_unlock(timer *t)
{
    if(t->lock)
        pthread_mutex_unlock(t->lock);
}

static inline int timer_sched(timer *t, int flags, unsigned int val)
{
    int err;

    timer_lock(t);
    err = __timer_sched(t, flags, val);
    timer_unlock(t);
    return err;
}

static inline int timer_sched_abs(timer *t, const struct timespec *ts)
{
    int err;

    timer_lock(t);
    err = __timer_sched_abs(t, ts);
    timer_unlock(t);
    return err;
}

static inline void timer_cancel(timer *t)
{
    timer_lock(t);
    __timer_cancel(t);
    timer_unlock(t);
}

static inline int __timer_scheded(timer *t)
{
    return !! (t->flags & TIMER_F_SCHED);
}

__END_DECLS

#endif  /* __TIMER_H */
