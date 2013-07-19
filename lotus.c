/*
 * lotus.c CLI console for Cactus Runtime.
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
#include <stdlib.h>
#include <malloc.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <time.h>
#ifndef ANDROID_CHANGES
#include <readline/readline.h>
#endif
#include <ctype.h>

#include "desert.h"

#define ERROR(fmt,args...) do{fprintf(stderr, fmt "\n", ##args); exit(-1);}while(0)
#define ERROR_RET(err,fmt,args...) do{fprintf(stderr, fmt "\n", ##args); return err;}while(0)
#define ARRAYSIZE(a)  (sizeof(a)/sizeof(a[0]))

#define TOKS_MIN 10

typedef struct _verdict_record verdict_record;
typedef struct _command_desc command_desc;

struct _verdict_record{
    verdict_record *next;
    msg_verdict_req req[0];
};

struct _command_desc{
    char *cmd;
    char *help;
    void (*func)(char *args[], const command_desc *cmd);
    const char *(*get_help)(const char *cmd);
};

static const char banner[] = "Lotus, The Lavender CLI console";

static pthread_mutex_t record_lock = PTHREAD_MUTEX_INITIALIZER;
static verdict_record *record_list = NULL;
static verdict_record *record_end = NULL;

static void cmd_list(char *args[], const command_desc *cmd);
static void cmd_verd(char *args[], const command_desc *cmd);
static void cmd_exit(char *args[], const command_desc *cmd);
static void cmd_help(char *args[], const command_desc *cmd);
static void cmd_get(char *args[], const command_desc *cmd);
static void cmd_set(char *args[], const command_desc *cmd);
static void cmd_shutdown(char *args[], const command_desc *cmd);
static void cmd_flush(char *args[], const command_desc *cmd);
static void cmd_rule(char *args[], const command_desc *cmd);

static const char *get_help(const char *cmd);

static const command_desc cmd_tbl[] = {
    {"list", NULL, cmd_list, get_help},
    {"verd", NULL, cmd_verd, get_help},
    {"exit", "  exit command shell", cmd_exit, NULL},
    {"get", NULL, cmd_get, get_help},
    {"set", NULL, cmd_set, get_help},
    {"shutdown", "  shutdown lavender service", cmd_shutdown, NULL},
    {"flush", "  flush lavender service logs", cmd_flush, NULL},
    {"rule", NULL, cmd_rule, get_help},
    {"help", "  show this message", cmd_help, NULL},
    {NULL, NULL, NULL, NULL},
};

static const struct{
    char *cmd;
    int verd;
}verdict_cmd[] = {
    {"none", VERDICT_NONE},
    {"allow", VERDICT_ALLOW_ONCE,},
    {"allow_always", VERDICT_ALLOW_ALWAYS, },
    {"deny", VERDICT_DENY_ONCE, },
    {"deny_always", VERDICT_DENY_ALWAYS, },
    {"kill", VERDICT_KILL_ONCE, },
    {"kill_always", VERDICT_KILL_ALWAYS, },
};

static const char *target_tbl[] = {
	"ACCEPT",
	"REINJECT",
	"VERDICT",
	"DROP",
	"KILL",
};

static const char *verdict_tbl[] = {
	"NONE",
	"VERDICT",
	"ALLOW ONCE",
	"ACCEPT",
	"DENY ONCE",
	"DROP",
	"KILL ONCE",
	"KILL",
};

enum{
    CMD_NONE,
    CMD_LOAD,
    CMD_DUMP,
    CMD_STATUS,
    CMD_FLUSH_LOGS,
    CMD_LOG_CONTROL,
    CMD_LEVEL_CONTROL,
    CMD_CACTUS_CONTROL,
    CMD_SHUTDOWN,
    CMD_FRONT_END,
    CMD_VERSION,
    CMD_TEST,
};

static void help(const char *prog)
{
    printf("  %s\nUSAGE:\n%s OPTIONS\n"
           "  -l|--load PATH    Load rules from PATH\n"
           "  -f|--flush        Flush rules\n"
           "  -d|--dump PATH    Dump rules into PATH\n"
           "  -u|--status       Print lavender status\n"
           "  -s|--state on|off Specify target state\n"
           "  -g|--log <TYPE>   Specify log type to operate\n"
           "  -c|--cactus       Specify cactus state to operate\n"
           "  -L|--level <LVL>  Specify log level to operate\n"
           "  -h|--help         Show this help message\n"
           "  -S|--shutdown     Shutdown Cactus Runtime\n"
           "  -t|--front-end    Run in front-end mode\n"
           "  -v|--version      Show version info\n"
           "TYPE: main, rtnl, uevent, conntrack, all\n"
           "LVL: debug, info, warn, emerg, error, fatal, all\n"
           "EXAMPLES:\n"
           "  # enable uevent log\n"
           "  %s -s on -g uevent\n"
           "  # enable debug level log\n"
           "  %s -s on -L debug\n"
           "  # turn on cactus\n"
           "  %s -s on -c\n",
           banner, prog, prog, prog, prog);
}

static const char *get_help(const char *cmd)
{
    const char *msg = "  <no help message>";

    if(! strcmp(cmd, "list"))  {
        msg = "  list Cactus fw objects:\n"
            "    list [ARGUMENTS]\n"
            "  ARGUMENTS:\n"
            "    verd         show pending verdicts\n"
            "    prog  [OPT]  show fw recorded progs\n"
            "     OPT:\n"
            "     active      show only active progs\n"
            "    proc  [OPT]  show fw recorded processes\n"
            "     OPT:\n"
            "     prog <PATH> show processes of prog specified\n"
            "     user <UID>  show processes of uid specified\n"
            "    user  [OPT]  show fw recorded users\n"
            "     OPT:\n"
            "     active      show only active users\n"
            "    conn [OPT]   show fw recorded connections\n"
            "     OPT:\n"
            "     proc <PID>  show connections of pid specified\n"
            "     prog <PATH> show connections of prog specified\n"
            "     user <UID>  show connections of uid specified";
    }else if(! strcmp(cmd, "verd"))  {
        msg = "  verdict the last verdict request:\n"
            "    verd [TARGET]\n"
            "  TARGET:\n"
            "  none            silently ignore this verdict\n"
            "  allow           allow for this time\n"
            "  allow_always    allow always\n"
            "  deny            deny for this time\n"
            "  deny_always     deny always\n"
            "  kill            kill for this time\n"
            "  kill_always     always kill";
    }

    return msg;
}

static inline void set_cmd(int *var, int cmd)
{
    if(*var != CMD_NONE)
        ERROR("Ambiguous command.");
    *var = cmd;
}

#define SET_CMD(command) set_cmd(&cmd, CMD_##command)
#define SET_ARG() do{if(! optarg || ! *optarg) ERROR("Argument required."); arg = optarg;}while(0)

static void on_connect_cb(int state, unsigned int peer, void *ud)
{
    if(! state)
        ERROR("Passively disconencted from server!\n");
}

static inline int ts_cmp(const struct timespec *a, const struct timespec *b)
{
    if(a->tv_sec < b->tv_sec)
        return -1;
    else if(a->tv_sec > b->tv_sec)
        return 1;
    if(a->tv_nsec < b->tv_nsec)
        return -1;
    else if(a->tv_nsec > b->tv_nsec)
        return 1;
    return 0;
}

static void on_verdict_req(const msg_verdict_req *req)
{
    static unsigned int seq = 0;
    const msg_fd_owner *fo;
    verdict_record *r;
    struct timespec ts;
    size_t sz = sizeof(*req);
    int timeout;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    /* ignore already expired ones */
    if(ts_cmp(&ts, &req->ts) >= 0)
        return;

    timeout = req->ts.tv_sec - ts.tv_sec;
    if(req->ts.tv_nsec - ts.tv_nsec > 500000000)
        timeout++;

    printf("\n[%u]. VERDICT REQUEST, ID:%llu, TIMEOUT:%d\n", seq++, req->id, timeout);
    msg_fd_owner_for_each(fo, req)  {
        printf("    UID:%u, PID:%u, EXE:%s\n", fo->euid, fo->pid, fo->exe);
        sz += sizeof(*fo) + strlen(fo->exe) + 1;
    }list_end;

    if((r = (verdict_record *)malloc(sizeof(*r) + sz)))  {
        r->next = NULL;
        memcpy(&r->req, req, sz);
        pthread_mutex_lock(&record_lock);
        if(! record_list)  {
            record_list = r;
            record_end = r;
        }else  {
            record_end->next = r;
            record_end = r;
        }
        pthread_mutex_unlock(&record_lock);
    }
}

static void on_runtime_info(const msg_runtime_info *info)
{
    switch(info->type)  {
    case INFO_MSG:
        printf("\n[INFO]%s %.*s\n", ctime(&info->time), info->len, info->info);
        break;
    default:
        printf("Unrecognized runtime info type received:%u, ignored", info->type);
        break;
    }
}

static void fe_cb(int type, const void *msg, void *ud)
{
    switch(type)  {
    case CACTUS_VERDICT_REQUEST:  {
        on_verdict_req((const msg_verdict_req *)msg);
        break;
    }
    case CACTUS_RUNTIME_INFO:  {
        on_runtime_info((const msg_runtime_info *)msg);
        break;
    }
    default:  {
        printf("Unrecognized fe message received:%u, ignored", type);
        break;
    }
    }
}

static void list_verd(void)
{
    verdict_record *r;
    msg_verdict_req *req;
    msg_fd_owner *fo;
    struct timespec ts;
    int timeout, seq = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    pthread_mutex_lock(&record_lock);
    if(record_list)
        printf("VERDICT LIST:\n");
    else
        printf("No pending Verdicts.\n");

    for(r = record_list; r; r = r->next)  {
        req = &r->req[0];

        timeout = req->ts.tv_sec - ts.tv_sec;
        if(req->ts.tv_nsec - ts.tv_nsec > 500000000)
            timeout++;

        if(ts_cmp(&ts, &req->ts) >= 0)
            timeout = -1;

        if(timeout > 0)
            printf("[%u]. VERDICT REQUEST, ID:%llu, TIMEOUT:%d\n", seq++, req->id, timeout);
        else
            printf("[%u]. VERDICT REQUEST, ID:%llu, OUTDATED\n", seq++, req->id);
        msg_fd_owner_for_each(fo, req)  {
            printf("    UID:%u, PID:%u, EXE:%s\n", fo->euid, fo->pid, fo->exe);
        }list_end;
    }
    pthread_mutex_unlock(&record_lock);
}

static const char *action_string(int action)
{
	int target = ACTION_TARGET(action);
	int verdict = ACTION_VERDICT(action);

	if(target < 0 || target >= arraysize(target_tbl))
		return "<INVALID ACTION>";
	if(target == FW_VERDICT)  {
		if(verdict < 0 || verdict >= arraysize(verdict_tbl))
			return "<INVALID VERDICT>";
		return verdict_tbl[verdict];
	}
	return target_tbl[target];
}

static void list_prog(char *args[])
{
	int seq = 0, flags = 0;
	fw_obj *obj;
	msg_prog_res *res;
	list progs;

	if(args[0] && args[0][0])  {
		if(! strcasecmp(args[0], "active"))  {
			flags = ITER_F_ACTIVE;
		}else  {
			printf("Unrecognized argument \"%s\"\n", args[0]);
			return;
		}
	}

	desert_get_all_fw_progs(&progs, flags);

	if(list_empty(&progs))  {
		printf("No records returned!\n");
		return;
	}

	printf("INDEX UID        ACTION          PATH\n");
	list_for_each_entry(obj, &progs, list)  {
		res = &obj->prog[0];
		printf("[%d].  %-10u %-15s %s\n", seq++, res->uid, action_string(res->action), res->path);
	}
	fw_objs_free(&progs);
}

static void list_user(char *args[])
{
	int seq = 0, flags = 0;
	fw_obj *obj;
	msg_user_res *res;
	list users;

	if(args[0] && args[0][0])  {
		if(! strcasecmp(args[0], "active"))  {
			flags = ITER_F_ACTIVE;
		}else  {
			printf("Unrecognized argument \"%s\"\n", args[0]);
			return;
		}
	}

	desert_get_all_fw_users(&users, flags);

	if(list_empty(&users))  {
		printf("No records returned!\n");
		return;
	}

	printf("INDEX UID        NAME\n");
	list_for_each_entry(obj, &users, list)  {
		res = &obj->user[0];
		printf("[%d].  %-10u %s\n", seq++, res->uid, res->name);
	}
	fw_objs_free(&users);
}

static void list_proc(char *args[])
{
	int seq = 0;
	msg_proc_res *res;
	list procs;

	if(args[0] && args[0][0])  {
		/* TODO: */
	}
	/* TODO: */
}

static void list_conn(char *args[])
{
	/* TODO: */
}

static void cmd_list(char *args[], const command_desc *cd)
{
    char *cmd = args[0];

    if(! cmd || ! *cmd)  {
        printf("Verdict argument required!\n");
        return;
    }

    if(! strcasecmp(cmd, "verd"))  {
        list_verd();
    }else if(! strcasecmp(cmd, "prog"))  {
		list_prog(args + 1);
	}else if(! strcasecmp(cmd, "user"))  {
		list_user(args + 1);
	}else if(! strcasecmp(cmd, "proc"))  {
		list_proc(args + 1);
	}else if(! strcasecmp(cmd, "conn"))  {
		list_conn(args + 1);
    }else  {
        printf("Unrecognized command argument:\"%s\", abort!\n", cmd);
    }
}

static void cmd_verd(char *args[], const command_desc *cd)
{
    verdict_record *r;
    char *cmd = args[0];
    size_t i;

    if(! cmd || ! *cmd)  {
        printf("Verdict argument required!\n");
        return;
    }

    for(i = 0; i < ARRAYSIZE(verdict_cmd); i++)  {
        if(! strcasecmp(cmd, verdict_cmd[i].cmd))
            break;
    }
    if(i == ARRAYSIZE(verdict_cmd))  {
        printf("Invalid verdict target!\n");
        return;
    }

    pthread_mutex_lock(&record_lock);
    if((r = record_list))
        record_list = r->next;
    pthread_mutex_unlock(&record_lock);

    if(r)  {
        if(desert_send_verdict(r->req[0].id, verdict_cmd[i].verd))  {
            ERROR("Fail to send verdict command for %llu!\n", r->req[0].id);
            exit(-1);
        }
        free(r);
    }
}

static void cmd_exit(char *args[], const command_desc *cd)
{
    exit(0);
}

static void cmd_help(char *args[], const command_desc *cd)
{
    const command_desc *c = cmd_tbl;
    char *cmd = args[0];

    while(c->cmd)  {
        if(! cmd || ! *cmd || ! strcmp(cmd, c->cmd))
            printf("%s:\n%s\n", c->cmd,
                   c->help ? : (c->get_help ? c->get_help(c->cmd) : "<no help message>"));
        c++;
    }
}

static void cmd_get(char *args[], const command_desc *cmd)
{
    /* TODO: */
}

static void cmd_set(char *args[], const command_desc *cmd)
{

}

static void cmd_shutdown(char *args[], const command_desc *cmd)
{

}

static void cmd_flush(char *args[], const command_desc *cmd)
{

}

static void cmd_rule(char *args[], const command_desc *cmd)
{

}

static char **tokenize(char ***toks, size_t *sz, char *str)
{
    char *p, **t, **_toks;
    int quoted = 0;
    int squoted = 0;
    int space, cnt = 0;

    if(! *toks || ! *sz)  {
        *toks = (char **)malloc(sizeof(char *) * TOKS_MIN);
        *sz = TOKS_MIN;
    }
    if(! *toks)
        ERROR("OOM!");

    for(space = 1, t = *toks, p = str; *p; p++)  {
        if(! quoted && ! squoted && isspace(*p))  {
            *p = '\0';
            space = 1;
            continue;
        }
        if(! squoted && *p == '"')  {
            *p = '\0';
            quoted = !quoted;
            if(! quoted)
                memmove(p, p + 1, strlen(p + 1) + 1);
        }
        if(! quoted && *p == '\'')  {
            *p = '\0';
            squoted = ! squoted;
            if(! squoted)
                memmove(p, p + 1, strlen(p + 1) + 1);
        }

        if(space)  {
            space = 0;
            *t++ = p;
            cnt++;
            if(cnt + 1 == *sz)  {
                _toks = realloc(*toks, sizeof(char *) *(*sz + TOKS_MIN));
                if(_toks)  {
                    *sz += TOKS_MIN;
                    t = _toks + cnt;
                    *toks = _toks;
                }else  {
                    ERROR("OOM! extending toks array");
                }
            }
        }
    }
    if(quoted || squoted)
        return NULL;
    t = *toks;
    *(t + cnt) = NULL;
    return *toks;
}

static void dispatch_cmd(char **toks)
{
    const command_desc *cd = cmd_tbl;

    if(! *toks || ! **toks)
        return;

    while(cd->cmd)  {
        if(! strcmp(cd->cmd, toks[0]))  {
            cd->func(toks + 1, cd);
            return;
        }
        cd++;
    }
    printf("Unrecognized command, type help for help.\n");
}

static void front_end(void)
{
    char prompt[50], *cmd = NULL;
    char **toks = NULL;
    size_t sz = 0;
    int err;

    pthread_mutex_lock(&record_lock);
    if((err = desert_register_fe(0, fe_cb, NULL)))
        ERROR("Fail to self register as front-end(%d)!", err);
    for(;;)  {
        if(record_list)
            sprintf(prompt, "verdict %llu >", record_list->req[0].id);
        else
            strcpy(prompt, "lotus shell >");
        pthread_mutex_unlock(&record_lock);

#ifndef ANDROID_CHANGES
        if(cmd)
            free(cmd);
        if(! (cmd = readline(prompt)))
            return;
#else
        char buf[1024];

        printf("%s", prompt);
        if(! (cmd = fgets(buf, sizeof(buf), stdin)))
            return;
#endif

        if(! tokenize(&toks, &sz, cmd))  {
            printf("Malformated command & arguments!\n");
            continue;
        }

        dispatch_cmd(toks);
        pthread_mutex_lock(&record_lock);
    }
}

int main(int argc, char *argv[])
{
    int cmd = CMD_NONE;
    int c, idx, log = -1, lvl = -1, stat = 0, ver_num;
    char *arg = NULL;
    int err = -1;
    size_t i;
    const char *ver;
    static struct option opts[] = {
        {"load", 1, NULL, 'l'},
        {"flush", 0, NULL, 'f'},
        {"dump", 1, NULL, 'd'},
        {"status", 0, NULL, 'u'},
        {"state", 1, NULL, 's'},
        {"log", 1, NULL, 'g'},
        {"cactus", 0, NULL, 'c'},
        {"level", 1, NULL, 'L'},
        {"help", 0, NULL, 'h'},
        {"shutdown", 0, NULL, 'S'},
        {"front-end", 0, NULL, 't'},
        {"version", 0, NULL, 'v'},
        {"test", 1, NULL, 'T'},
        {NULL, 0, NULL, 0}
    };
    static const char *log_tbl[] = {
        "main", "rtnl", "uevent", "conntrack",
    };

    static const char *level_tbl[] = {
        "debug", "info", "warn", "emerg", "error", "fatal",
    };

    for(;;)  {
        c = getopt_long(argc, argv, "l:fd:us:g:cL:hStvT:", opts, &idx);
        if(-1 == c)
            break;

        switch(c)  {
        case 'l':
            SET_CMD(LOAD);
            SET_ARG();
            break;
        case 'f':
            SET_CMD(FLUSH_LOGS);
            break;
        case 'd':
            SET_CMD(DUMP);
            SET_ARG();
            break;
        case 'u':
            SET_CMD(STATUS);
            break;
        case 's':
            if(! optarg)
                ERROR("state argument required.");
            if(! strcasecmp(optarg, "on"))
                stat = 1;
            else if(! strcasecmp(optarg, "off"))
                stat = 0;
            else
                ERROR("Invalid argument.");
            break;
        case 'g':
            SET_CMD(LOG_CONTROL);
            if(! optarg)
                ERROR("Log name required.");
            for(i = 0; i < ARRAYSIZE(log_tbl); i++)  {
                if(! strcasecmp(log_tbl[i], optarg))  {
                    log = i;
                    break;
                }
            }
            if(! strcasecmp("all", optarg))
                break;
            if(log == -1)
                ERROR("Invalid log name.");
            break;
        case 'c':
            SET_CMD(CACTUS_CONTROL);
            break;
        case 'L':
            SET_CMD(LEVEL_CONTROL);
            if(! optarg)
                ERROR("Level name required.");
            for(i = 0; i < ARRAYSIZE(level_tbl); i++)  {
                if(! strcasecmp(level_tbl[i], optarg))  {
                    lvl = i;
                    break;
                }
            }
            if(! strcasecmp("all", optarg))
                break;
            if(lvl == -1)
                ERROR("Invalid log level name.");
            break;
        case 'h':
            help(argv[0]);
            return 0;
        case 'S':
            SET_CMD(SHUTDOWN);
            break;
        case 't':
            SET_CMD(FRONT_END);
            break;
        case 'v':
            SET_CMD(VERSION);
            break;
        case 'T':
            SET_CMD(TEST);
            SET_ARG();
            break;
        default:
            fprintf(stderr, "Invalid argment.\n");
            help(argv[0]);
            return -1;
        }
    }

    if(cmd != CMD_NONE)  {
        if((err = desert_init(banner, on_connect_cb, NULL)))
            ERROR_RET(err, "Fail initializing desert.");
        if((err = desert_connect(NULL, NULL, 0)))
            ERROR_RET(err, "Fail to init connection to Lavender.");
        switch(cmd)  {
        case CMD_LOAD:
            err = desert_load_rules(arg);
            break;
        case CMD_FLUSH_LOGS:
            err = desert_flush_logs();
            break;
        case CMD_DUMP:
            err = desert_dump_rules(arg);
            break;
        case CMD_STATUS:
            stat = desert_cactus_status();
            if(stat == CACTUS_ACTIVE || stat == CACTUS_INACTIVE)  {
                err = 0;
                printf("Cactus status: %s\n", stat ? "ACTIVE" : "INACTIVE");
            }
            break;
        case CMD_LOG_CONTROL:
            err = desert_log_set_type_enabled(log, stat);
            break;
        case CMD_LEVEL_CONTROL:
            err = desert_log_set_level_enabled(lvl, stat);
            break;
        case CMD_CACTUS_CONTROL:
            err = desert_switch_cactus(stat);
            break;
        case CMD_SHUTDOWN:
            err = desert_shutdown();
            break;
        case CMD_FRONT_END:
            front_end();
            err = 0;
            break;
        case CMD_VERSION:
            ver = desert_cactus_version(&ver_num);
            if(ver)  {
                printf("%sVERSION(%X)\n", ver, ver_num);
                err = 0;
            }
            break;
        case CMD_TEST:  {
            char buf[1024];

            err = desert_make_test(arg, buf, sizeof(buf));
            if(! err)
                printf("TEST RES:\"%s\"\n", buf);
            break;
        }
        default:
            ERROR_RET(err, "Invalid command:%d.", cmd);
            break;
        }

        if(err)
            ERROR_RET(err, "Command execution failed:%d.", err);
        return err;
    }

    ERROR_RET(err, "Nothing to do.");
    return err;
}

