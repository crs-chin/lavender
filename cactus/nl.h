/*
 * nl.h  netlink utils
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

#ifndef __NL_H
#define __NL_H

#include <string.h>
#include <sys/types.h>
#include <linux/types.h>
#include <linux/netlink.h>

#include "ginkgo.h"

__BEGIN_DECLS

#define NL_HEADER(msg) GINKGO_MSG_PAYLOAD(msg,struct nlmsghdr)

int nl_open(int unit, int grp);

int nl_parse(void *buf, size_t cnt, ginkgo_msg **msg);
int nl_response(ginkgo_msg *msg, ginkgo_msg *rsp);

/**
 * nla_type - attribute type
 * @nla: netlink attribute
 */
static inline int nla_type(const struct nlattr *nla)
{
    return nla->nla_type & NLA_TYPE_MASK;
}

/**
 * nla_ok - check if the netlink attribute fits into the remaining bytes
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 */
static inline int nla_ok(const struct nlattr *nla, int remaining)
{
    return remaining >= (int) sizeof(*nla) &&
        nla->nla_len >= sizeof(*nla) &&
        nla->nla_len <= remaining;
}

/**
 * nla_next - next netlink attribute in attribute stream
 * @nla: netlink attribute
 * @remaining: number of bytes remaining in attribute stream
 *
 * Returns the next netlink attribute in the attribute stream and
 * decrements remaining by the size of the current attribute.
 */
static inline struct nlattr *nla_next(const struct nlattr *nla, int *remaining)
{
    int totlen = NLA_ALIGN(nla->nla_len);

    *remaining -= totlen;
    return (struct nlattr *) ((char *) nla + totlen);
}

/**
 * nla_data - head of payload
 * @nla: netlink attribute
 */
static inline void *nla_data(const struct nlattr *nla)
{
    return (char *) nla + NLA_HDRLEN;
}

/**
 * nla_attr_size - length of attribute not including padding
 * @payload: length of payload
 */
static inline int nla_attr_size(int payload)
{
    return NLA_HDRLEN + payload;
}

/**
 * nla_total_size - total length of attribute including padding
 * @payload: length of payload
 */
static inline int nla_total_size(int payload)
{
    return NLA_ALIGN(nla_attr_size(payload));
}

/**
 * nlmsg_msg_size - length of netlink message not including padding
 * @payload: length of message payload
 */
static inline int nlmsg_msg_size(int payload)
{
    return NLMSG_HDRLEN + payload;
}

/**
 * nlmsg_total_size - length of netlink message including padding
 * @payload: length of message payload
 */
static inline int nlmsg_total_size(int payload)
{
    return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

static inline ginkgo_msg *nlmsg_new(int ginkgo_id, size_t payload)
{
    ginkgo_msg *msg = ginkgo_new_msg(ginkgo_id, nlmsg_total_size(payload));
    struct nlmsghdr *nlh;

    if(msg)  {
        nlh = NL_HEADER(msg);
        nlh->nlmsg_len = nlmsg_total_size(payload);
    }
    return msg;
}

static void *nlmsg_init(ginkgo_msg *msg, __u16 type, __u32 seq, __u32 pid, __u16 flags)
{
    struct nlmsghdr *nlh = NL_HEADER(msg);
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_seq = seq;
    nlh->nlmsg_pid = pid;
    return NLMSG_DATA(nlh);
}

static void nlmsg_put_mem(void **ctx, const void *mem, size_t len)
{
    memcpy(*ctx, mem, len);
    *(char **)ctx += NLMSG_ALIGN(len);
}

static void *nla_reserve(void **ctx, int type, size_t len)
{
    struct nlattr *nla = (struct nlattr *)(*ctx);

    *(char **)ctx += nla_total_size(len);
    nla->nla_type = type;
    nla->nla_len = nla_attr_size(len);
    return nla_data(nla);
}

static void nla_put_blob(void **ctx, int type, const void *blob, size_t len)
{
    memcpy(nla_reserve(ctx, type, len), blob, len);
}

#define DEFINE_NLA_PUT(type)                                    \
    static void nla_put_##type(void **ctx, int t, __##type var) \
    {                                                           \
        void *data = nla_reserve(ctx, t, sizeof(__##type));     \
        *(__##type *)data = var;                                \
    }

DEFINE_NLA_PUT(u8)
DEFINE_NLA_PUT(u16)
DEFINE_NLA_PUT(u32)
DEFINE_NLA_PUT(u64)
DEFINE_NLA_PUT(be16)
DEFINE_NLA_PUT(be32)
DEFINE_NLA_PUT(be64)
DEFINE_NLA_PUT(le16)
DEFINE_NLA_PUT(le32)
DEFINE_NLA_PUT(le64)

#undef DEFINE_NLA_PUT

static inline struct nlattr *nla_nested_start(void **ctx, int t)
{
    struct nlattr *nla = (struct nlattr *)*ctx;

    nla->nla_type = t;
    *ctx = nla_data(nla);
    return nla;
}

static inline void nla_nested_end(struct nlattr *nla, void *ctx)
{
    nla->nla_len = (char *)ctx - (char *)nla;
}


static inline int nla_get_mem(const struct nlattr *nla, void *ptr, size_t size)
{
    void *src = nla_data(nla);

    if((size_t)(nla->nla_len - nla_attr_size(0)) > size)  {
        memcpy(ptr, src, size);
        return 0;
    }
    return -1;
}

#define DEFINE_NLA_GET(type)                                    \
    static __##type nla_get_##type(const struct nlattr *nla)    \
    {                                                           \
        return *(__##type *)nla_data(nla);                      \
    }

DEFINE_NLA_GET(u8)
DEFINE_NLA_GET(u16)
DEFINE_NLA_GET(u32)
DEFINE_NLA_GET(u64)
DEFINE_NLA_GET(be16)
DEFINE_NLA_GET(be32)
DEFINE_NLA_GET(be64)
DEFINE_NLA_GET(le16)
DEFINE_NLA_GET(le32)
DEFINE_NLA_GET(le64)

#undef DEFINE_NLA_GET

static void nla_put_string(void **ctx, int type, const char *s)
{
    char *dst = nla_reserve(ctx, type, strlen(s) + 1);
    strcpy(dst, s);
}

#define nla_for_each_attr(head, len)            \
    for (; nla_ok(head, len);                   \
         head = nla_next(head, &(len)))

static inline int nla_parse(struct nlattr *arr[], int max, struct nlattr *nla, int len)
{
    memset(arr, 0, sizeof(struct nlattr *) * (max + 1));
    nla_for_each_attr(nla, len)  {
        __u16 type = nla_type(nla);
        if (type > 0 && type <= max) 
            arr[type] = (struct nlattr *)nla;
    }

    if(len > 0)
        PR_WARN("netlink: %d bytes leftover after parsing attributes.", len);
    return 0;
}

static inline int nla_parse_nested(struct nlattr *arr[], int max, const struct nlattr *nla)
{
    struct nlattr *_nla = (struct nlattr *)nla_data(nla);
    int len = nla->nla_len - nla_attr_size(0);

    return nla_parse(arr, max, _nla, len);
}

__END_DECLS

#endif  /* __NL_H */

