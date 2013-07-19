/*
 * sig_handle.h multi-thread and async safe signal handling
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

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#include "linux_signalfd.h"

#include "util.h"
#include "ginkgo.h"
#include "sig_handle.h"
#include "cactus_log.h"

static int __initialized = 0;
static int __ginkgo_id = -1;
static ginkgo_ctx *__ginkgo = NULL;

static pthread_mutex_t __lock = PTHREAD_MUTEX_INITIALIZER;
static sigset_t __sig_mask;
static list __sighandlers[_NSIG + 1];

static inline void sig_lock(void)
{
    pthread_mutex_lock(&__lock);
}

static inline void sig_unlock(void)
{
    pthread_mutex_unlock(&__lock);
}

static int sigfd_parse(void *buf, size_t cnt, ginkgo_msg **msg)
{
    ginkgo_msg *m = NULL;
    size_t sz = sizeof(struct signalfd_siginfo);

    if(cnt >= sz)  {
        if((m = ginkgo_new_msg(0, sz)))
            memcpy(GINKGO_MSG_PAYLOAD(m, void), buf, sz);
        *msg = m;
        return sz;
    }
    *msg = NULL;
    return 0;
}

/* never receive request */
static int sigfd_respond(ginkgo_msg *msg, ginkgo_msg *rsp)
{
    return GINKGO_RESP_INVA;
}

static int sigfd_handle(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud)
{
    sig_handler *handler, *n;
    struct signalfd_siginfo *sinfo;
    list *h;
    int num;

    sinfo = GINKGO_MSG_PAYLOAD(msg, struct signalfd_siginfo);
    sig_lock();
    num = sinfo->ssi_signo;
    assert(num > 0 && num <= _NSIG);
    h = &__sighandlers[num];
    if(list_empty(h))  {
        LOG_INFO("sig %u caught, no handler registered, ignored", num);
    }else  {
        LOG_INFO("sig %u caught, call handlers", num);
        list_for_each_entry_safe(handler, n, h, list)  {
            if(! handler->cb(sinfo, handler))
                list_delete(&handler->list);
        }
    }
    sig_unlock();
    return 0;
}

/**
 * NOTE: signals expected to handler have to be properly blocked
 * first, unhandled signals would be silently ignored.
 * @mask: signals expected to be handled by sig handle
 */
int sig_handle_init(ginkgo_ctx *ctx, const sigset_t *mask)
{
    ginkgo_src src;
    int i, fd;

    if(__initialized)
        return 0;

    memcpy((void *)&__sig_mask, mask, sizeof(*mask));
    for(i = 0; i <= _NSIG; i++)
        list_init(&__sighandlers[i]);

    memset(&src, 0, sizeof(src));
    if((fd = signalfd(-1, mask, SFD_NONBLOCK | SFD_CLOEXEC)) < 0)  {
        LOG_ERROR("signalfd() syscall failure:%d(%s)", errno, strerror(errno));
        return -1;
    }
    src.name = "signalfd";
    src.fd = fd;
    src.pars = sigfd_parse;
    src.resp = sigfd_respond;
    src.hand = sigfd_handle;
    src.ud = (void *)&__ginkgo_id;

    if(ginkgo_src_register(ctx, &src, &__ginkgo_id, 0))  {
        close(fd);
        return -1;
    }

    __ginkgo = ctx;
    __initialized = 1;
    return 0;
}

int sig_register_handler(sig_handler *handler, int cnt)
{
    sig_handler *iter;
    int i, num, registered = 0;
    list *h;

    sig_lock();
    for(i = 0; i < cnt; handler++, i++)  {
        num = handler->num;
        if(num > 0 && num <= _NSIG && handler->cb)  {
            if(! sigismember(&__sig_mask, num))
                LOG_WARN("registering handler on non-blocked signal %d", num);
            h = &__sighandlers[num];
            list_for_each_entry(iter, h, list)  {
                if(iter == handler)
                    goto already;
            }
            list_append(h, &handler->list);
        already:
            registered++;
        }else  {
            LOG_ERROR("invalid handler or try to register on invalid signal %u", num);
        }
    }
    sig_unlock();
    return registered;
}

void sig_unregister_handler(sig_handler *handler, int cnt)
{
    sig_handler *iter;
    int i, num;
    list *h;

    sig_lock();
    for(i = 0; i < cnt; handler++, i++)  {
        num = handler->num;
        if(num > 0 && num <= _NSIG)  {
            h = &__sighandlers[num];
            list_for_each_entry(iter, h, list)  {
                if(iter == handler)  {
                    list_delete(&handler->list);
                    break;
                }
            }
        }
    }
    sig_unlock();
}

