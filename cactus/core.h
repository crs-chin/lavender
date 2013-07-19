/*
 * core.h
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

#ifndef __CORE_H
#define __CORE_H

#include <stdlib.h>

#include "nfct.h"
#include "msg.h"
#include "rule.h"
#include "cactus_log.h"

__BEGIN_DECLS

/**
 * NOTE: core will mask signals first before spawn any other threads,
 * make sure no child threads spawn or signals be setup properly
 * before init core
 */
int core_init(void);

int core_start(void);

/* begin pumping kernel packets */
int core_activate(void);

/* by pass fw pumping */
void core_deactivate(void);

#define CORE_INIT -1
#define CORE_INACTIVE 0
#define CORE_ACTIVE 1

int core_status(void);

int core_nfct_filtered(nfct_msg *msg);
nfct_t *core_nfct(void);

void __attribute__((noreturn)) core_exit(int err);

__END_DECLS

#endif  /* __CORE_H */

