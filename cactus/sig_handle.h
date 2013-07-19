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

#ifndef __SIG_HANDLE_H
#define __SIG_HANDLE_H

#include <signal.h>

#include "linux_signalfd.h"

#include "util.h"
#include "ginkgo.h"

__BEGIN_DECLS

typedef struct _sig_handler sig_handler;

/**
 * NOTE: handlers internally protected under sig lock, so do *NOT* try
 * to register/unregister any signal handlers inside callback
 */
struct _sig_handler{
    list list;
    int num;
    /**
     * return 0 to auto unregister handler
     */
    int (*cb)(const struct signalfd_siginfo *info, sig_handler *h);
};

/**
 * NOTE: signals expected to handler have to be properly blocked
 * first, unhandled signals would be silently ignored.
 * @mask: signals expected to be handled by sig handle
 */
int sig_handle_init(ginkgo_ctx *ctx, const sigset_t *mask);

/**
 * @handler: a handler array of count @cnt
 * the function return handlers succesfully registered
 */
int sig_register_handler(sig_handler *handler, int cnt);
void sig_unregister_handler(sig_handler *handler, int cnt);

__END_DECLS

#endif  /* ! __SIG_HANDLE_H */
