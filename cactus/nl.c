/*
 * nl.c
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

#include <unistd.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>

#include "nl.h"

int nl_open(int unit, int grp)
{
    int fd = socket(PF_NETLINK, SOCK_RAW, unit);
    struct sockaddr_nl addr;

    if(fd >= 0)  {
        bzero(&addr, sizeof(addr));
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = grp;

        if(bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)  {
            close(fd);
            return -1;
        }
    }

    return fd;
}

int nl_parse(void *buf, size_t cnt, ginkgo_msg **msg)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    ginkgo_msg *m = NULL;
    int len = cnt;

    if(cnt >= NLMSG_SPACE(0))  {
        if(NLMSG_OK(nlh, len))  {
            NLMSG_NEXT(nlh, len);
            if((m = ginkgo_new_msg(0, cnt - len)))
                memcpy(GINKGO_MSG_PAYLOAD(m, void), buf, cnt - len);
        }
    }
    *msg = m;
    return cnt - len;
}

int nl_response(ginkgo_msg *msg, ginkgo_msg *rsp)
{
    struct nlmsghdr *m = NL_HEADER(msg), *r = NL_HEADER(rsp);

    if(m->nlmsg_seq == r->nlmsg_seq)  {
        if(r->nlmsg_type == NLMSG_ERROR)
            return GINKGO_RESP_DONE;
        if(r->nlmsg_flags & NLM_F_MULTI)  {
            if(r->nlmsg_type == NLMSG_DONE)
                return GINKGO_RESP_DONE;
            return GINKGO_RESP_CONT;
        }
        return GINKGO_RESP_DONE;
    }

    return GINKGO_RESP_INVA;
}

