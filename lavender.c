/*
 * lavender.c
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

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "cactus/cactus.h"

static const char banner[] =
    PACKAGE_STRING " - Linux Light Weight Userspace Firewall\n"
    "Copyright (C) 2012 Crs Chin<crs.chin@gmail.com>\n";

static inline void help(const char *prog)
{
    /* configurations available through front-end */
    printf("%s\n"
           "%s [OPTIONS]\n"
           "OPTIONS:\n"
           "\t-D  Run in foreground, don't daemonize\n"
           "\t-h  Print this help message\n"
           "\t-v Version info\n",
           banner, prog);
}

int main(int argc, char *argv[])
{
    int opt, daemonize = 1;

    while((opt = getopt(argc, argv, "cCDhv")) != -1)  {
        switch(opt)  {
        case 'D':
            daemonize = 0;
            break;
        case 'h':
            help(argv[0]);
            return 0;
        case 'v':
            printf("%s", banner);
            return 0;
        default:
            fprintf(stderr, "!! Unrecognized option \'%c\'!\n", opt);
            return -1;
        }
    }

    if(geteuid() != 0)  {
        fprintf(stderr, "!! Unprivileged to start Lavender!\n");
        return -1;
    }

    if(daemonize)  {
        if(daemon(0, 0))  {
            fprintf(stderr, "!! Fail to daemonize Lavender!\n");
            return -1;
        }
    }else  {
        /* make stdio buff mode as lined */
        /* do *NOT* output anything before this */
        setvbuf(stdout, NULL, _IOLBF, 0);
        setvbuf(stderr, NULL, _IOLBF, 0);
    }

    if(cactus_startup())  {
        fprintf(stderr, "!! Fail to start Cactus Runtime!\n");
        return -1;
    }

    /* sleep forever now */
    for(;;)
        sleep(-1);
}

