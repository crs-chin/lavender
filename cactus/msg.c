/*
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
#include <sys/types.h>
#include <grp.h>

#include "util.h"
#include "msg.h"
#include "msg_base.h"
#include "ipclite.h"
#include "rpclite.h"
#include "cactus_log.h"

static ipclite *server = NULL;
static list handler = LIST_HEAD_INIT(handler);

static int on_msg(ipclite_msg *msg, void *ud)
{
    msg_handler *h;
    int msg_no;

    if(msg->hdr.msg == IPCLITE_MSG_SYN)  {
        ipclite_msg_syn *syn = (ipclite_msg_syn *)&msg->hdr.data;

        if(syn->len)
            LOG_INFO("new peer(%d)connected:%.*s", msg->hdr.peer, syn->len, syn->msg);
        return 0;
    }

    /* dispatch close msgs to all */
    if(msg->hdr.msg == IPCLITE_MSG_CLS)  {
        LOG_INFO("peer %d disconnected", msg->hdr.peer);

        list_for_each_entry(h, &handler, list)  {
            if(h->h(msg, h->ud))
                return 1;
        }
        return 0;
    }

    list_for_each_entry(h, &handler, list)  {
        msg_no = msg->hdr.msg;
        if(msg_no >= h->base && (msg_no - h->base) <= h->range)
            return h->h(msg, h->ud);
    }
    return 0;
}

int msg_server_init(void)
{
    gid_t gid = 0;
    struct group *grp;

    if(server)
        return 0;

    if((grp = getgrnam(CACTUS_GROUP_NAME)))
        gid = grp->gr_gid;

    if(ipclite_server_create(&server, CACTUS_SERVER_PATH,
                             "Cactus Runtime", CACTUS_SERVER_MAX_PEER,
                             CACTUS_SERVER_ABSTRACT ? IPCLITE_F_ABSTRACT : 0))
        return -1;
    /* if(ipclite_server_set_auth(server, 0, 0, 1, gid)) */
    /*     goto err_free; */
    if(ipclite_server_run(server, on_msg, NULL))
        goto err_free;
    if(rpclite_server_attach(server))
        goto err_free;

    return 0;

 err_free:
    ipclite_server_destroy(server);
    server = NULL;
    return -1;
}

int msg_server_quit(void)
{
    if(! server)
        return 0;
    ipclite_server_quit(server, 1);
    ipclite_server_destroy(server);
    return 0;
}

int msg_register_handler(msg_handler *h)
{
    msg_handler *iter;

    list_for_each_entry(iter, &handler, list)  {
        if(iter == h)
            return 0;
    }

    list_for_each_entry(iter, &handler, list)  {
        if(h->base < iter->base)  {
            list_append(&iter->list, &h->list);
            return 0;
        }
    }
    list_append(&handler, &h->list);
    return 0;
}

int msg_send(ipclite_msg *msg, int wait, int free)
{
    if(server && msg)
        return ipclite_server_sendmsg(server, msg, wait, free);
    return -1;
}

int msg_close_peer(int peer, int wait, int force)
{
    if(server)
        return ipclite_server_close_peer(server, peer, wait, force);
    return -1;
}

int msg_peer_info(int peer, ipclite_peer *info)
{
    if(server)
        return ipclite_server_peer_info(server, peer, info);
    return -1;
}

