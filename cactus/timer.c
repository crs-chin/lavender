/*
 * timer.c
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

#include <errno.h>
#include <string.h>
#include <assert.h>
#include <time.h>
#include <sys/types.h>
#include <sys/select.h>
#include <unistd.h>
#include <pthread.h>

#include "util.h"
#include "timer.h"
#include "linux_timerfd.h"
#include "cactus_log.h"

#include "test.h"

/**
 * not using ginkgo just to ensure netlink operations to be more
 * realtime.
 */

static int __initialized = 0;
static pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t timer_thread;
static list timer_src = LIST_HEAD_INIT(timer_src);
static fd_set timer_fds;
static int pipe_fds[2];
static int max_fds;

static inline int __set_itimer(timer *t)
{
    struct itimerspec old, update = {
        .it_value = {
            .tv_sec = t->ts.tv_sec,
            .tv_nsec = t->ts.tv_nsec,
        },
        .it_interval = {
            .tv_sec = t->ts.tv_sec,
            .tv_nsec = t->ts.tv_nsec,
        },
    };
    int err = timerfd_settime(t->tfd, 0, &update, &old);

    if(! err)
        t->flags |= (TIMER_F_INTERVAL | TIMER_F_SCHED);
    if(err < 0)
        LOG_ERROR("fail to update itimer:%d(%s)", errno, strerror(errno));
    return err;
}

static inline int __set_timer(timer *t)
{
    struct itimerspec old, update = {
        .it_interval = {0, 0},
        .it_value = {
            .tv_sec = t->ts.tv_sec,
            .tv_nsec = t->ts.tv_nsec,
        },
    };
    int err = timerfd_settime(t->tfd, TFD_TIMER_ABSTIME, &update, &old);

    if(! err)
        t->flags |= TIMER_F_SCHED;
    if(err < 0)
        LOG_ERROR("fail to update timer:%d(%s)", errno, strerror(errno));
    return err;
}

static inline int empty_fd(int fd)
{
    char buf[64];
    int emitted = 0, res;

    for(;;)  {
        res = read(fd, buf, sizeof(buf));
        if(res > 0)  {
            emitted = 1;
            continue;
        }
        if(res < 0 && errno == EINTR)
            continue;
        return emitted;
    }
}

static inline int __disarm(timer *t)
{
    struct itimerspec its, sav;

    memset(&its, 0, sizeof(its));
    return timerfd_settime(t->tfd, 0, &its, &sav); 
}

static void *thread_func(void *arg)
{
    fd_set rd;
    int fds, ret;
    timer *t;

    prctl(PR_SET_NAME, "timer", 0, 0, 0);
    for(;;)  {
        pthread_mutex_lock(&__lock);
        rd = timer_fds;
        fds = max_fds;
        pthread_mutex_unlock(&__lock);

        if(select(fds, &rd, NULL, NULL, NULL) <= 0)
            continue;

        if(FD_ISSET(pipe_fds[0], &rd))  {
            empty_fd(pipe_fds[0]);
            continue;
        }

        pthread_mutex_lock(&__lock);
        list_for_each_entry(t, &timer_src, list)  {
            /* validate alarms */
            timer_lock(t);
            if(empty_fd(t->tfd))  {
                ret = 0;
                if(t->cb)
                    ret = t->cb(t->ud);
                if(ret && (t->flags & TIMER_F_INTERVAL))  {
                    timer_unlock(t);
                    continue;
                }
                t->flags &= ~TIMER_F_SCHED;
                if(t->flags & TIMER_F_INTERVAL)  {
                    __disarm(t);
                    t->flags &= ~TIMER_F_INTERVAL;
                }
            }
            timer_unlock(t);
        }
        pthread_mutex_unlock(&__lock);
    }
    return NULL;
}

int timer_initialize(int flags)
{
    if(! __initialized)  {
        FD_ZERO(&timer_fds);

        if(pipe2(pipe_fds, O_NONBLOCK) < 0)
            return -1;

        FD_SET(pipe_fds[0], &timer_fds);
        max_fds = pipe_fds[0] + 1;

        if(pthread_create(&timer_thread, NULL, thread_func, NULL))  {
            close(pipe_fds[0]);
            close(pipe_fds[1]);
            return -1;
        }
        __initialized = 1;
    }
    return 0;
}

static inline void repoll(void)
{
    int res;

    do{
        res = write(pipe_fds[1], "PLEASE", sizeof("PLEASE"));
    }while(res < 0 && errno == EAGAIN);
}

int timer_register_src(timer *t)
{
    if(t->flags & TIMER_F_REGISTER)
        return 0;
    list_init(&t->list);
    if((t->tfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC)) < 0)
        return -1;
    pthread_mutex_lock(&__lock);
    list_append(&timer_src, &t->list);
    FD_SET(t->tfd, &timer_fds);
    if(t->tfd + 1 > max_fds)
        max_fds = t->tfd + 1;
    t->flags = TIMER_F_REGISTER;
    repoll();
    pthread_mutex_unlock(&__lock);
    return 0;
}

void timer_unregister_src(timer *t)
{
    timer *iter;

    if(t->flags & TIMER_F_REGISTER)  {
        pthread_mutex_lock(&__lock);
        /* make select return and block first, try not close fd on
           selecting */
        repoll();
        list_delete(&t->list);
        FD_CLR(t->tfd, &timer_fds);
        if(t->tfd + 1 == max_fds)  {
            max_fds = pipe_fds[0];
            list_for_each_entry(iter, &timer_src, list)  {
                if(max_fds < iter->tfd)
                    max_fds = iter->tfd;
            }
            max_fds++;
        }
        t->flags = 0;
        close(t->tfd);
        pthread_mutex_unlock(&__lock);
    }
}

int __timer_sched(timer *t, int flags, unsigned int val)
{
    /* discard all armed */
    __disarm(t);
    empty_fd(t->tfd);
    if(flags & TIMER_INTERVAL)  {
        t->ts.tv_sec = 0;
        t->ts.tv_nsec = 0;
        ts_add(&t->ts, val);
        return __set_itimer(t);
    }else  {
        clock_gettime(CLOCK_MONOTONIC, &t->ts);
        ts_add(&t->ts, val);
        return __set_timer(t);
    }
}

int __timer_sched_abs(timer *t, const struct timespec *ts)
{
    /* discard all armed */
    __disarm(t);
    empty_fd(t->tfd);
    t->val = 0;
    t->ts = *ts;
    return __set_timer(t);
}

void __timer_cancel(timer *t)
{
    __disarm(t);
    empty_fd(t->tfd);
}

