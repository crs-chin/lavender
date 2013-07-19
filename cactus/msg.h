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

#ifndef __MSG_H
#define __MSG_H

#include "util.h"
#include "ipclite.h"
#include "msg_base.h"

__BEGIN_DECLS

typedef struct _msg_handler msg_handler;

struct _msg_handler{
    list list;
    int base;
    int range;
    ipclite_handler h;
    void *ud;
};

int msg_server_init(void);
int msg_server_quit(void);

int msg_register_handler(msg_handler *h);

int msg_send(ipclite_msg *msg, int wait, int free);

int msg_close_peer(int peer, int wait, int force);
int msg_peer_info(int peer, ipclite_peer *info);

__END_DECLS

#endif  /* __MSG_H */

