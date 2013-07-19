/*
 * rule.h Firewall rule configurations
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

#ifndef __RULE_H
#define __RULE_H

#include "util.h"
#include "fw_table.h"

__BEGIN_DECLS


/**
 * INTRO:
 * fw table states are saved in plain text format
 * 
 * Every non-empty line in the following form specifies a rule.
 * '#' starts a comment till the end of the line.
 *
 * 1. global fw table counter info
 * COUNTER [COUNTER_INFO]
 *
 * 2. fw table user info
 * USER <UID> [COUNTER_INFO]
 *
 * 3. fw table rule
 * RULE ACTION [RULE_ARGS]
 *
 * COUNTER_INFO:
 * [ORIG_PKT [ORIG_BYTES [REP_PKTS [REP_BYTES]]]]
 * 
 * ACTION:
 * ACCEPT|STOP|DROP|QUERY|ALLOW_ONCE|ALLOW_ALWAYS|DENY_ONCE|DENY_ALWAYS|KILL_ONCE|KILL_ALWAYS
 *
 * RULE_ARGS:
 * <UID> <EXE> <FILE_SIZE> <CSUM> [COUNTER_INFO]
 */
int rule_install(const char *file);

/**
 * dump all installed fw rules into @file
 */
int rule_dump(const char *file);

__END_DECLS

#endif  /* __RULE_H */
