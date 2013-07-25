/*
 * rule.c
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

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <pwd.h>

#include "util.h"
#include "fw_table.h"
#include "rule.h"
#include "cactus_log.h"

#define COUNTER_FMT "%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 ""
#define COUNTER_ARG(c)                                          \
    (c)->orig_pkts,(c)->orig_bytes,(c)->rep_pkts,(c)->rep_bytes

typedef struct _rule rule;

struct _rule{
    list list;
    char *desc;
    fw_conf r;
};

static int parse_rule(rule **r, char *line);
static int parse_user(rule **r, char *line);
static int parse_counter(rule **r, char *line);

enum{
    TYPE_RULE,
    TYPE_INFO,
};

static const struct{
    char *name;
    size_t len;
    int type;
    int (*parse)(rule **r, char *line);
}rule_desc[] = {
    {"RULE", sizeof("RULE") -1, TYPE_RULE, parse_rule,},
    {"USER", sizeof("USER") -1, TYPE_INFO, parse_user,},
    {"COUNTER", sizeof("COUNTER") - 1, TYPE_INFO, parse_counter,},
};

static const struct{
    char *name;
    int action;
} action_table[] = {
    {"ACCEPT", FW_ACCEPT},
    {"STOP", FW_STOP},
    {"DROP", FW_DROP},
    {"KILL", FW_KILL},
    {"QUERY", FW_VERDICT | (VERDICT_QUERY << VERDICT_SHIFT)},
    {"ALLOW_ONCE", FW_VERDICT | (VERDICT_ALLOW_ONCE << VERDICT_SHIFT)},
    {"ALLOW_ALWAYS", FW_ACCEPT},
    {"DENY_ONCE", FW_VERDICT | (VERDICT_DENY_ONCE << VERDICT_SHIFT)},
    {"DENY_ALWAYS", FW_DROP},
    {"KILL_ONCE", FW_VERDICT | (VERDICT_KILL_ONCE << VERDICT_SHIFT)},
    {"KILL_ALWAYS", FW_KILL},
};

static char *get_elem(char **line)
{
    char *p = *line, *start;
    int quote = 0;

    while(*p && isspace(*p))
        p++;

    if(*p)  {
        start = p;
        if(*p == '"')  {
            quote = 1;
            p++;
            start++;
        }
        if(*p)  {
            if(quote)  {
                while(*p && *p != '"')
                    p++;
                if(*p != '"')
                    return NULL;
            }else  {
                while(*p && ! isspace(*p))
                    p++;
            }
            if(*p)  {
                *p = '\0';
                *line = p + 1;
            }else  {
                *line = p;
            }
            return start;
        }
    }
    return NULL;
}

static inline int parse_action(int *verd, char **line)
{
    char *tok = get_elem(line);
    size_t i;

    for(i = 0; i < arraysize(action_table); i++)  {
        if(! strcmp(action_table[i].name, tok))  {
            *verd = action_table[i].action;
            return 0;
        }
    }
    LOG_WARN("invalid rule action:%s", *line);
    return -1;
}

static inline rule *rule_alloc(int type, size_t payload)
{
    rule *r = new_instance_ex(rule, payload);

    if(r)  {
        memset(r, 0, sizeof(*r));
        r->r.type = type;
    }
    return r;
}

static inline unsigned char hex_num(char c)
{
    if(c >= '0' && c <= '9')
        return c - '0';
    return c - 'a' + 10;
}

static rule *prog_rule(uid_t uid, const char *exe, size_t sz, const char *csum)
{
    unsigned char md5[16], tmp, c;
    rule *r;
    int i, j;

    if(csum)  {
        for(i = 0, j = 0; i < 32;)  {
            c = tolower(csum[i]);
            if(! ((c >= '0' && c <= '9')
                  || (c >= 'a' && c <= 'f')))  {
                LOG_WARN("invalid MD5 checksum string:%s", csum);
                return NULL;
            }
            tmp = hex_num(c);
            i++;
            c = tolower(csum[i]);
            if(! ((c >= '0' && c <= '9')
                  || (c >= 'a' && c <= 'f')))  {
                LOG_WARN("invalid MD5 checksum string:%s", csum);
                return NULL;
            }
            tmp = ((tmp << 4) | hex_num(c));
            i++;
            md5[j] = tmp;
            j++;
        }
    }
    if((r = rule_alloc(FW_CONF_RULE, strlen(exe) + sizeof(md5) + 1)))  {
        r->r.rule.uid = uid;
        r->r.rule.path = (char *)r + sizeof(*r);
        strcpy(r->r.rule.path, exe);
        r->r.rule.sz = sz;
        if(csum)  {
            r->r.rule.csum = (char *)r + sizeof(*r) + strlen(exe) + 1;
            memcpy(&r->r.rule.csum, &md5, sizeof(md5));
        }
    }
    return r;
}

static int __parse_u64(__u64 *n, char **line)
{
    char *_n = get_elem(line);
    char *end;

    if(_n) {
        *n = strtoll(_n, &end, 0);
        if(*end != '\0')
            return -1;
    }else  {
        *n = 0;
    }
    return 0;
}

static inline int __parse_counter(fw_counter *c, char *line)
{
    if(__parse_u64(&c->orig_pkts, &line)
       || __parse_u64(&c->orig_bytes, &line)
       || __parse_u64(&c->rep_pkts, &line)
       || __parse_u64(&c->rep_bytes, &line))
        return -1;
    return 0;
}

static int parse_rule(rule **r, char *line)
{
    char *_uid = get_elem(&line);
    uid_t uid;
    char *exe = get_elem(&line);
    char *_sz = get_elem(&line);
    char *csum = get_elem(&line);
    char *endp;
    fw_counter c;
    size_t sz = 0;

    if(! _uid || ! *_uid || ! exe || ! *exe)
        return -1;

    uid = strtol(_uid, &endp, 0);
    if(*endp != '\0')  {
        LOG_WARN("invalid uid:\"%s\"", _uid);
        return -1;
    }

    if(_sz && *_sz)  {
        sz = strtol(_sz, &endp, 10);
        if(*endp != '\0')  {
            LOG_WARN("invalid size:\"%s\"", _sz);
            return -1;
        }
    }
    /* MD5 csum */
    if(csum && *csum && strlen(csum) != 32)  {
        LOG_WARN("invalid MD5 CSUM:\"%s\"", csum);
        return -1;
    }

    if(__parse_counter(&c, line))  {
        LOG_WARN("invalid counter info");
        return -1;
    }

    if((*r = prog_rule(uid, exe, sz, csum)))  {
        (*r)->r.rule.counter = c;
        return 0;
    }
    return -1;
}

static int parse_user(rule **r, char *line)
{
    char *_uid = get_elem(&line);
    char *endp;
    char *name = "";
    char *buf = NULL;
    fw_counter c;
    uid_t uid = 0;
    struct passwd pwd, *res = NULL;
    int buf_sz = sysconf(_SC_GETPW_R_SIZE_MAX);
    fw_conf *fr;

    uid = strtol(_uid, &endp, 0);
    if(*endp != '\0')  {
        LOG_WARN("invalid uid:\"%s\"", _uid);
        return -1;
    }

    if(__parse_counter(&c, line))  {
        LOG_WARN("invalid user counter info");
        return -1;
    }

    if(buf_sz < 0)
        buf_sz = 16384;     /* should be more than enough */
    if((buf = (char *)malloc(buf_sz)))  {
        if(! getpwuid_r(uid, &pwd, buf, buf_sz, &res) && res)
            name = pwd.pw_name;
    }

    if((*r = rule_alloc(FW_CONF_USER, strlen(name) + 1)))  {
        fr = &(*r)->r;
        fr->user.uid = uid;
        fr->user.name = (char *)(*r) + sizeof(**r);
        fr->user.counter = c;
        strcpy(fr->user.name, name);
        free_if(buf);
        return 0;
    }
    free_if(buf);
    return -1;
}

static int parse_counter(rule **r, char *line)
{
    fw_counter c;

    if(__parse_counter(&c, line))
        return -1;
    if((*r = rule_alloc(FW_CONF_COUNTER, 0)))  {
        (*r)->r.counter = c;
        return 0;
    }
    return -1;
}

static int __parse(list *rules, char *line)
{
    rule *r;
    char *rdesc;
    int err = -1;
    int verd;
    size_t i;

    for(i = 0; i < arraysize(rule_desc); i++)  {
        if(! strncmp(rule_desc[i].name, line, rule_desc[i].len))  {
            rdesc = strdup(line);
            line += rule_desc[i].len;
            if(rule_desc[i].type != TYPE_RULE
               || ! parse_action(&verd, &line))  {
                if(! (err = rule_desc[i].parse(&r, line)))  {
                    if(rule_desc[i].type == TYPE_RULE)
                        r->r.rule.action = verd;
                    r->desc = rdesc;
                    list_append(rules, &r->list);
                    break;
                }
            }
            LOG_WARN("error parse fw rule \"%s\"", rdesc ?: "");
            if(rdesc)
                free(rdesc);
            break;
        }
    }
    return err;
}

static int parse(list *rules, char *line)
{
    char *p = line;

    /* comments */
    while(*p)  {
        if(*p == '#')  {
            *p = '\0';
            break;
        }
        p++;
    }

    p = line;
    while(*p && isspace(*p))
        p++;
    if(*p)
        return __parse(rules, p);
    return 0;
}

static void do_load(list *rules, FILE *fp)
{
    char *line = NULL;
    size_t sz = 0;
    int res;

    list_init(rules);
    for(;;)  {
        res = getline(&line, &sz, fp);
        if(res <= 0)
            break;
        /* overwrite '\n' */
        line[strlen(line) - 1] = '\0';
        parse(rules, line);
    }
    if(line)
        free(line);
}

/**
 * @rules: list of fw_conf
 */
static int rule_load(list *rules, const char *file)
{
    FILE *fp;

    if(rules && (fp = fopen(file, "r")))  {
        do_load(rules, fp);
        fclose(fp);
        return 0;
    }
    return -1;
}

int rule_install(const char *file)
{
    list rules = LIST_HEAD_INIT(rules);
    rule *r, *n;

    if(! rule_load(&rules, file))  {
        /* TODO: check counter info here */
        list_for_each_entry_safe(r, n, &rules, list)  {
            list_delete(&r->list);
            if(fw_table_insert(&r->r))  {
                LOG_WARN("rule already exist:\"%s\"", r->desc ?: "");
            }else  {
                LOG_INFO("rule inserted:\"%s\"", r->desc ?: "");
            }
            if(r->desc)
                free(r->desc);
            free(r);
        }
        return 0;
    }
    return -1;
}

static inline const char *str_action(int action)
{
    size_t i;

    for(i = 0; i < arraysize(action_table); i++)  {
        if(action == action_table[i].action)
            return action_table[i].name;
    }
    return NULL;
}

static inline const char *str_csum(char *csum)
{
    static char md5[33];

    sprintf(&md5[0], "%2.2X%2.2X%2.2X%2.2X", csum[0], csum[1], csum[2], csum[3]);
    sprintf(&md5[8], "%2.2X%2.2X%2.2X%2.2X", csum[4], csum[5], csum[6], csum[7]);
    sprintf(&md5[16], "%2.2X%2.2X%2.2X%2.2X", csum[8], csum[9], csum[10], csum[11]);
    sprintf(&md5[24], "%2.2X%2.2X%2.2X%2.2X", csum[12], csum[13], csum[14], csum[15]);
    return md5;
}

static void dump_rule(const fw_conf *r, FILE *fp)
{
    const char *action = str_action(r->rule.action);
    const char *csum = "";
    const char *comm = "";
    const fw_counter *c = &r->rule.counter;

    if(! action)  {
        action = "<INVALID>";
        comm = "#(BAD RULE):";
    }

    if(r->rule.csum)
        csum = str_csum(r->rule.csum);

    fprintf(fp, "%sRULE %s %u \"%s\" %u \"%s\" " COUNTER_FMT "\n\n",
            comm, action, r->rule.uid, r->rule.path, r->rule.sz, csum, COUNTER_ARG(c));
}

static void dump_user(const fw_conf *r, FILE *fp)
{
    const char *comm = "";
    const fw_counter *c = &r->user.counter;

    if(r->user.name && *r->user.name)
        fprintf(fp, "# user \"%s\"\n", r->user.name);
    fprintf(fp, "%sUSER %u " COUNTER_FMT "\n\n",
            comm, r->user.uid, COUNTER_ARG(c));
}

static inline void dump_counter(const fw_conf *r, FILE *fp)
{
    const fw_counter *c = &r->counter;

    fprintf(fp, "COUNTER " COUNTER_FMT "\n", COUNTER_ARG(c));
}

static int do_dump(const fw_conf *r, void *ud)
{
    int counter = 0;

    switch(r->type)  {
    case FW_CONF_RULE:
        dump_rule(r, (FILE *)ud);
        break;
    case FW_CONF_USER:
        dump_user(r, (FILE *)ud);
        break;
    case FW_CONF_COUNTER:
        if(counter == 1)
            LOG_WARN("more that one global counter info available, continue");
        dump_counter(r, (FILE *)ud);
        counter++;
        break;
    default:
        fprintf((FILE *)ud, "#(Unknown rule type:%d)\n", r->type);
        break;
    }
    return 1;
}

/**
 * dump all installed fw rules into @file
 */
int rule_dump(const char *file)
{
    char buf[50];
    time_t t = time(NULL);
    FILE *fp;

    ctime_r(&t, buf);
    if((fp = fopen(file, "w")))  {
        fprintf(fp, "# written by Cactus Runtime %s"
                "# manual modification may get *LOST*\n\n", buf);
        fw_table_for_each(do_dump, (void *)fp);
        fclose(fp);
        return 0;
    }
    return -1;
}

