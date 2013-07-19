/*
 * desert_gtk.h Cactus front-end GTK+ routing.
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

#ifndef __DESERT_GTK_H
#define __DESERT_GTK_H

#include "msg_base.h"

__BEGIN_DECLS

typedef void (*on_verdict)(uint64_t id, int verdict, void *ud);

int desert_gtk_init(int *argc, char **argv[], const char *ui, on_verdict cb, void *ud);

int desert_gtk_req_verdict(const msg_verdict_req *req);

__END_DECLS

#endif  /* ! __DESERT_GTK_H */

