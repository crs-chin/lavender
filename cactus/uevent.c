/*
 * uevent.c
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


#include <string.h>
#include <strings.h>

#include "nl.h"
#include "util.h"
#include "ginkgo.h"
#include "uevent.h"

static int __initialize = 0;
static int __ginkgo_id = -1;
static ginkgo_ctx *__ginkgo = NULL;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static list uevent_handlers = LIST_HEAD_INIT(uevent_handlers);

static int uevent_parse(void *buf, size_t cnt, ginkgo_msg **msg)
{
    char *p = buf, *start, *end;
    ginkgo_msg *m = NULL;
    int mark;
    size_t i;

    /* not ended properly */
    if(p[cnt - 1])
        return 0;

    for(p = start = end = buf, i = 0, mark = 0; i < cnt; i++)  {
        if(! p[i])  {
            if(! mark)  {
                start = end = p + i + 1;
                continue;
            }
            end = p + i + 1;
            continue;
        }
        if(p[i] == '@')  {
            if(! mark)  {
                mark = 1;
                continue;
            }
            break;
        }
    }

    if(start != end && (m = ginkgo_new_msg(0, end - start)))
        memcpy(GINKGO_MSG_PAYLOAD(m, void), start, end - start);
    *msg = m;
    return (end - (char *)buf);
}

static int uevent_response(ginkgo_msg *msg, ginkgo_msg *rsp)
{
    return GINKGO_RESP_INVA;
}

static const struct{
    char *action;
    size_t len;
}kobject_actions[] = {
    {"add@", 4},
    {"remove@", 7},
    {"change@", 7},
    {"move@", 5},
    {"online7", 7},
    {"offline@", 8},
};

static uevent_msg *uevent_msg_parse(ginkgo_msg *m)
{
    uevent_msg *um = (uevent_msg *)&m->cmn;
    char *payload = GINKGO_MSG_PAYLOAD(m, char);
    int action = -1;
    size_t i;

    for(i = 0; i < arraysize(kobject_actions); i++)  {
        if(! strncmp(kobject_actions[i].action, payload, kobject_actions[i].len))  {
            action = i;
            break;
        }
    }

    if(action != -1)  {
        um->action = action;
        um->path = payload + kobject_actions[i].len;
        um->env = um->path + strlen(um->path) + 1;
        return um;
    }
    PR_ERROR("fail to parse uevent:%s", payload);
    return NULL;
}

static int uevent_cb(ginkgo_ctx *ctx, ginkgo_msg *msg, void *ud)
{
    uevent_handler *h;
    uevent_msg *umsg;
    int action;
    char *path;

    if((umsg = uevent_msg_parse(msg)))  {
        action = (1 << umsg->action);
        path = umsg->path;

        pthread_mutex_lock(&lock);
        list_for_each_entry(h, &uevent_handlers, list)  {
            if(action & h->actions)  {
                if(! h->path)  {
                    h->cb(umsg, h->ud);
                }else if(h->flags & UEVENT_F_INCLUSIVE)  {
                    if(! strncmp(h->path, path, h->len))  {
                        h->cb(umsg, h->ud);
                    }
                }else  {
                    if(! strcmp(h->path, path))  {
                        h->cb(umsg, h->ud);
                    }
                }
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return 0;
}

static int __uevent_init(ginkgo_ctx *ctx)
{
    ginkgo_src src;
    int fd;

    bzero(&src, sizeof(src));
    /* supposed to receive all */
    if((fd = nl_open(NETLINK_KOBJECT_UEVENT, -1)) < 0)
        return -1;
    src.name = "uevent";
    src.fd = fd;
    src.pars = uevent_parse;
    src.resp = uevent_response;
    src.hand = uevent_cb;
    src.ud = (void *)&__ginkgo_id;

    if(ginkgo_src_register(ctx, &src, &__ginkgo_id, 0))  {
        close(fd);
        return -1;
    }

    __ginkgo = ctx;
    __initialize = 1;
    return 0;
}

int uevent_init(ginkgo_ctx *ctx)
{
    if(! __initialize)
        return __uevent_init(ctx);
    return 0;
}

int uevent_register_handler(uevent_handler *handler)
{
    uevent_handler *h;

    if(! handler
       || ! (handler->actions & ACTION_F_ALL)
       || ! handler->cb)
        return -1;

    if(handler->path && ! *handler->path)
        handler->path = NULL;

    if(handler->path && handler->len < 0)
        handler->len = strlen(handler->path);

    pthread_mutex_lock(&lock);
    list_for_each_entry(h, &uevent_handlers, list)  {
        if(h == handler)  {
            pthread_mutex_unlock(&lock);
            return -1;
        }
    }
    list_append(&uevent_handlers, &handler->list);
    pthread_mutex_unlock(&lock);
    return 0;
}

void uevent_unregister_handler(uevent_handler *handler)
{
    uevent_handler *h;

    pthread_mutex_lock(&lock);
    list_for_each_entry(h, &uevent_handlers, list)  {
        if(h == handler)  {
            list_delete(&h->list);
            break;
        }
    }
    pthread_mutex_unlock(&lock);
}


static void uevent_check(void)
{
    ginkgo_msg msg;

    build_fail_on(sizeof(uevent_msg) > sizeof(msg.cmn));
}

