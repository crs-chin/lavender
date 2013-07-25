#include "test.h"

#ifdef TEST_SOCK_STAT

#include "sock_stat.h"
#include "util.h"


int main()
{
    list *tmp,dump;
    sk_entry *sk;
    int i = 0;
    ginkgo_ctx *ctx;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(sock_stat_init(ctx))  {
        printf("fail to inti sock stat\n");
        return -1;
    }

    printf("-------------- dump tcp -----------------------\n");
    if(sock_stat_dump_tcp_compat(&dump, -1, 0, 0))  {
        printf("fail to dump sock stat\n");
        return -1;
    }

    if(list_empty(&dump))  {
        printf("empty sock dump\n");
        return -1;
    }

    list_for_each_sk_entry(sk,tmp,&dump)  {
        printf("%d. ino:%d, source port:%d, dest port:%d\n",
               i++, sk->info->idiag_inode, ntohs(sk->info->id.idiag_sport), ntohs(sk->info->id.idiag_dport));
    }
    sk_entry_list_free(&dump);

    printf("-------------- dump udp -----------------------\n");
    if(sock_stat_lookup_udp(&dump, 0, 0))  {
        printf("fail to dump sock stat\n");
        return -1;
    }

    if(list_empty(&dump))  {
        printf("empty sock dump\n");
        return -1;
    }

    list_for_each_sk_entry(sk,tmp,&dump)  {
        printf("%d. source port:%d\n", i++, ntohs(sk->info->id.idiag_sport));
    }
    sk_entry_list_free(&dump);

    printf("-------------- udp v2 dump test -----------------------\n");
    if(sock_stat_lookup_udp(&dump, 8888, 0))  {
        printf("fail to dump udp sock\n");
    }else  {
        list_for_each_sk_entry(sk,tmp,&dump)  {
            printf("%d. source port:%d\n", i++, ntohs(sk->info->id.idiag_sport));
        }
        sk_entry_list_free(&dump);
    //        printf("success looked up udp sock\n");
    }


    printf("-------------- tcp lookup test -----------------------\n");
    sk = sock_stat_get_tcp_compat(0xD789210A, 0x671F7D4A, htons(0xBB60), htons(0x50), 0);
    if(sk)  {
        printf("%d. ino:%d, source port:%d, dest port:%d\n",
               i++, sk->info->idiag_inode, ntohs(sk->info->id.idiag_sport), ntohs(sk->info->id.idiag_dport));
    }else  {
        printf("fail lookup tcp sock\n");
    }

    printf("-------------- udp lookup test -----------------------\n");
    sk = sock_stat_lookup_udp_exact(0xD789210AU, 0x2A8A210AU, htons(0xDFA5U), htons(0x22B8U), 0);
    //sk = sock_stat_lookup_udp_exact(0, 0, htons(0x277), 0, 0);
    if(sk)  {
        printf("%d. ino:%d, source port:%d, dest port:%d\n",
               i++, sk->info->idiag_inode, ntohs(sk->info->id.idiag_sport), ntohs(sk->info->id.idiag_dport));
    }else  {
        printf("fail lookup udp sock\n");
    }

    printf("-------------- proc dump test -----------------------\n");
    if(sock_stat_dump_udp_from_proc(&dump, AF_INET, 0, 0))  {
        printf("fail to dump from proc\n");
        return -1;
    }

    list_for_each_sk_entry(sk,tmp,&dump)  {
        printf("%d. source port:%d dest port:%d\n",
               i++,
               ntohs(sk->info->id.idiag_sport),
               ntohs(sk->info->id.idiag_dport));
    }
    sk_entry_list_free(&dump);

    return 0;
}

#elif defined(TEST_FD_LOOKUP)

#include "fd_lookup.h"
#include "util.h"

int main(int argc, char *argv[])
{
    list l;
    fd_owner *fo;
    int i;
    gid_t *g;

    if(lookup_fd_owners(&l, FD_SOCK, strtol(argv[1], NULL, 10)))   {
        printf("fail to lookup\n");
        return -1;
    }

    list_for_each_entry(fo, &l, list)  {
        printf("%d %d %d %s\n", fo->pid, fo->ppid, fo->euid, fo->exe);
        printf("GROUPS:");
        for(g = fo->grps, i = 0; i < fo->ngrps; i++)
            printf("%d ", g[i]);
        printf("\n");
    }

    fd_owners_free(&l);
    return 0;
}

#elif defined(TEST_TIMER)

#include "timer.h"

int cb(void *ud)
{
    printf("cb:%d\n", time(NULL));
    //timer_sched((timer *)ud, 0, 100);
}

int main()
{
    struct timespec ts;
    /* ginkgo_ctx *ctx; */

    /* if(ginkgo_create(&ctx, TIMER_F_THREAD))  { */
    /*     printf("fail to create ginkgo\n"); */
    /*     return -1; */
    /* } */

    /* if(ginkgo_run(ctx))  { */
    /*     printf("fail to run ginkgo\n"); */
    /*     return -1; */
    /* } */

    /* if(timer_init(ctx, 0))  { */
    /*     printf("fail to init timer\n"); */
    /*     return -1; */
    /* } */

    timer t;
    timer t2;

    timer_init(&t, NULL, cb, &t);
    timer_init(&t2, NULL, cb, &t2);

    if(timer_initialize(0))  {
        printf("fail to init timer\n");
        return -1;
    }

    if(timer_register_src(&t))  {
        printf("fail to register timer src\n");
        return -1;
    }

    if(timer_register_src(&t2))  {
        printf("fail to register timer src\n");
        return -1;
    }

    timer_sched(&t, TIMER_INTERVAL, 2000);
    timer_sched(&t2, TIMER_INTERVAL, 1000);

    sleep(100);
}

#elif defined(TEST_JHASH)

#include "jhash.h"

int main()
{


}

#elif defined(TEST_RTNL)

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "rtnl.h"
#include "util.h"

int main()
{
    list *tmp,dump;
    rtnl_msg *rtmsg;
    link_entry *link;
    addr_entry_inet *addr;
    route_entry_inet *route;
    neigh_entry *neigh;
    rule_entry_inet *rule;
    int i = 0;
    ginkgo_ctx *ctx;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(rtnl_init(ctx, NULL, NULL))  {
        printf("fail to init rtnl\n");
        return -1;
    }

    printf("-------------- dump links -----------------------\n");
    if(rtnl_dump_link(&dump, 0))  {
        printf("fail to dump links\n");
        return -1;
    }

    if(! (rtmsg = rtnl_get_link(0, "eth0", 0)))  {
        printf("fail to get link\n");
        return -1;
    }
    link = rtmsg->entry;
    printf("GET LINK: name: %s, alias:%s, mtu:%d, qdisc:%s\n", link->ifname, link->ifalias, *link->mtu, link->qdisc);
    rtnl_msg_free(rtmsg);

    if(list_empty(&dump))  {
        printf("empty links dump\n");
        return -1;
    }

    list_for_each_rtnl_msg(rtmsg, &dump)  {
        link = (link_entry *)rtmsg->entry;
        printf("GET LINK: name: %s, alias:%s, mtu:%d, qdisc:%s\n", link->ifname, link->ifalias, *link->mtu, link->qdisc);
    }list_end;

    rtnl_msg_list_free(&dump);

    printf("-------------- dump addr -----------------------\n");
    if(rtnl_dump_addr(&dump, AF_UNSPEC))  {
        printf("fail to dump addr\n");
        return -1;
    }

    list_for_each_rtnl_msg(rtmsg, &dump)  {
        addr = (addr_entry_inet *)rtmsg->entry;
        if(addr->base.ifaddr->ifa_family == AF_INET)  {
            printf("addr: %s\n", inet_ntoa((struct in_addr){*addr->addr}));
            printf("local: %s\n", inet_ntoa((struct in_addr){*addr->local}));
            printf("bcast: %s\n", inet_ntoa((struct in_addr){addr->broadcast ? *addr->broadcast : 0}));
        }else  {
            printf("addr family %d addr\n", addr->base.ifaddr->ifa_family);
        }
    }list_end;

    rtnl_msg_list_free(&dump);
    printf("-------------- dump inet route -----------------------\n");
    if(rtnl_dump_route_inet(&dump))  {
        printf("fail to dump route\n");
        return -1;
    }

    uint32_t src, dst, gateway;
    list_for_each_rtnl_msg(rtmsg, &dump)  {
        if(! (route = (route_entry_inet *)rtmsg->entry))  {
            printf("route not parsed\n");
            continue;
        }
        if(route->base.rt->rtm_family == AF_INET)  {
            dst = route->dst? *route->dst : 0;
            src = route->src? *route->src : 0;
            gateway = route->gateway? *route->gateway : 0;
            printf("route: dst %s src %s table %d gateway %s\n",
                   inet_ntoa((struct in_addr){dst}),
                   inet_ntoa((struct in_addr){src}),
                   route->table ? *route->table : 0,
                   inet_ntoa((struct in_addr){gateway}));
        }else  {
            printf("route: %d family route\n", route->base.rt->rtm_family);
        }
    }list_end;

    rtnl_msg_list_free(&dump);

    printf("-------------- dump inet neighbours -----------------------\n");
    if(rtnl_dump_neigh(&dump, AF_INET, 0))  {
        printf("fail to dump neigh\n");
        return -1;
    }

    list_for_each_rtnl_msg(rtmsg, &dump)  {
        if(! (neigh = (neigh_entry *)rtmsg->entry))  {
            printf("neigh not parsed\n");
            continue;
        }
        dst = *(__be32 *)RTA_DATA(neigh->rta[NDA_DST]);
        printf("neigh: dst %s\n", inet_ntoa((struct in_addr){dst}));
    }list_end;

    rtnl_msg_list_free(&dump);

    printf("-------------- dump inet rules -----------------------\n");
    if(rtnl_dump_rule(&dump, AF_INET))  {
        printf("fail to dump rule\n");
        return -1;
    }

    __u32 target, table;
    list_for_each_rtnl_msg(rtmsg, &dump)  {
        if(! (rule = (rule_entry_inet *)rtmsg->entry))  {
            printf("rule not parsed\n");
            continue;
        }
        dst = rule->dst? *rule->dst : 0;
        src = rule->src? *rule->src : 0;
        target = rule->target? *rule->target : 0;
        table = rule->table? *rule->table : 0;
        printf("rule: dst %s src %s target %d table %d\n",
               inet_ntoa((struct in_addr){dst}),
               inet_ntoa((struct in_addr){src}),
               target, table);

    }list_end;

    rtnl_msg_list_free(&dump);
    return 0;
}
#elif defined(TEST_NFQ)

#include <stdio.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include "nfq.h"

static int pkt_handler(nfq_queue *q, struct nfgenmsg *msg, struct nlattr *rta[], void *ud)
{
    struct nfqnl_msg_packet_hdr *vhdr = RTA_DATA(rta[NFQA_PACKET_HDR]);

    printf("packet %d recevied, verdict accept.\n", ntohl(vhdr->packet_id));
    nfq_verdict(q, vhdr->packet_id, NF_ACCEPT, 0);
    return 1;
}

int main()
{
    nfq_parm parm = {
        .queue_num = 12345,
        .pf = NFPROTO_IPV4,
        .copy_mode = NFQNL_COPY_PACKET,
        .copy_range = sizeof(struct iphdr),
        .max_len = 1024,
        .handler = pkt_handler,
        .ud = NULL,
    };
    nfq_queue *q;

    if(nfq_create(&q, &parm))  {
        printf("fail to create nfq\n");
        return -1;
    }

    if(nfq_start(q, NFQ_F_THREAD))  {
        printf("fail to start nfq\n");
        return -1;
    }

    sleep(1000);
    return 0;
}
#elif defined(TEST_NFCT)

#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include "nfct.h"

static void nfct_msg_dump(nfct_msg *m)
{
    conn_tuple tuple;
    conn_entry *e = m->entry;
    char *src, *dst;

    if(nfct_conn_get_src_tuple(e, &tuple))  {
        printf("fail to parse src tuple\n");
        return;
    }

    src = strdup(inet_ntoa(tuple.src.u3.in));
    dst = strdup(inet_ntoa(tuple.dst.u3.in));
    printf("NOTIFY: src %s dst %s, src port %d, dst port %d\n",
           src, dst,
           ntohs(tuple.src.u.tcp.port),
           ntohs(tuple.dst.u.tcp.port));
}

static int cb(nfct_t *h, nfct_msg *m, void *ud)
{
    nfct_msg_dump(m);
    return 0;
}

int main()
{
    nfct_t *ct;
    nfct_msg *m;
    conn_tuple tuple;
    ginkgo_ctx *ctx;
    list rsp;
    char *src, *dst;
    int i = 0;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(! (ct = nfct_create(ctx, NFCT_GRP_NEW, cb, NULL)))  {
        printf("fail to create nfct\n");
        return -1;
    }

    if(nfct_dump_conn(ct, &rsp, AF_INET, 0))  {
        printf("fail to dump AF_INET conntrack\n");
        return -1;
    }

    if(list_empty(&rsp))  {
        printf("empty dump\n");
        return -1;
    }

    printf("-------------------------- AF_INET dump --------------------------\n");
    list_for_each_nfct_msg(m, &rsp)  {
        if(m->subsys != NFNL_SUBSYS_CTNETLINK)  {
            printf("unexpected subsys:%d\n", m->subsys);
            continue;
        }
        if(nfct_conn_get_src_tuple(m->entry, &tuple))  {
            printf("fail to get src tuple\n");
            return -1;
        }
        //        printf("%d. \n", i++);
        src = strdup(inet_ntoa(tuple.src.u3.in));
        dst = strdup(inet_ntoa(tuple.dst.u3.in));

        printf("%d. src %s, dst %s, src port %d, dst port %d\n",
               i++, src, dst,
               ntohs(tuple.src.u.tcp.port),
               ntohs(tuple.dst.u.tcp.port));
        free(src);
        free(dst);
    }list_end;

    nfct_msg_list_free(&rsp);

    /* conn_tuple src_tuple; */
    /* src_tuple.src.l3num = AF_INET; */
    /* src_tuple.src.u3.ip = inet_addr("10.33.129.225"); */
    /* src_tuple.src.u.tcp.port = htons(59534); */
    /* src_tuple.dst.u3.ip = inet_addr("10.33.130.23"); */
    /* src_tuple.dst.u.tcp.port = htons(22); */
    /* src_tuple.dst.protonum = IPPROTO_TCP; */

    /* if(nfct_get_conn(ct, &rsp, 0, &src_tuple, NULL))  { */
    /*     printf("fail to get conn\n"); */
    /*     return -1; */
    /* } */

    /* printf("-------------------------- nfct get --------------------------\n"); */
    /* list_for_each_nfct_msg(m, &rsp)  { */
    /*     if(m->subsys != NFNL_SUBSYS_CTNETLINK)  { */
    /*         printf("unexpected subsys:%d\n", m->subsys); */
    /*         continue; */
    /*     } */
    /*     if(nfct_conn_get_src_tuple(m->entry, &tuple))  { */
    /*         printf("fail to get src tuple\n"); */
    /*         return -1; */
    /*     } */
    /*     //        printf("%d. \n", i++); */
    /*     src = strdup(inet_ntoa(tuple.src.u3.in)); */
    /*     dst = strdup(inet_ntoa(tuple.dst.u3.in)); */

    /*     printf("%d. src %s, dst %s, src port %d, dst port %d\n", */
    /*            i++, src, dst, */
    /*            ntohs(tuple.src.u.tcp.port), */
    /*            ntohs(tuple.dst.u.tcp.port)); */
    /*     free(src); */
    /*     free(dst); */
    /* }list_end; */

    sleep(1000);

    return 0;
}

#elif defined(TEST_UEVENT)

#include <stdio.h>

#include "uevent.h"

static const char *kobject_actions[] = {
    "add@",
    "remove@",
    "change@",
    "move@",
    "online7",
    "offline@",
};

static void uevent_cb(uevent_msg *m, void *ud)
{
    char *p;

    printf("==========================================================\n");
    printf("RECV:%s%s\n", kobject_actions[m->action], m->path);
    uevent_msg_for_each_env(p, m)  {
        printf("ATTRIBUTE:%s\n", p);
    }list_end;
}

static uevent_handler handler = {
    .actions = ACTION_F_ALL,
    .path = NULL,
    .cb = uevent_cb,
};

int main()
{
    list *tmp,dump;
    int i = 0;
    ginkgo_ctx *ctx;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(uevent_init(ctx))  {
        printf("fail to init uevent\n");
        return -1;
    }

    if(uevent_register_handler(&handler))  {
        printf("fail to register uevent handler\n");
        return -1;
    }

    for(;;)
        sleep(10000);

    return 0;
}
#elif defined(TEST_IPCLITE)

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>

#include "ipclite.h"

#define SERVER_PATH "./test_sock"

static unsigned int peer = 0;

static int msg_handler(ipclite_msg *msg, void *ud)
{
    ipclite_msg_syn *syn;

    if(msg->hdr.msg == IPCLITE_MSG_SYN)  {
        peer = msg->hdr.peer;
        syn = (ipclite_msg_syn *)&msg->hdr.data;
        fprintf(stderr, "SYN(%d):%.*s\n", peer, syn->len, syn->msg);
    }else if(msg->hdr.msg == IPCLITE_MSG_CLS)  {
        fprintf(stderr, "CLS: peer closed the connection\n");
    }else  {
        fprintf(stderr, "RECV:%s\n", msg->hdr.data);
    }
    return 1;
}

static void transact(unsigned int peer, const void *blob, size_t sz,
                     ipclite_response rsp, void *rsp_ud, void *ud)
{
    char rsp_blob[sz + 1];
    char *p = rsp_blob;
    int i;

    memcpy(rsp_blob, blob, sz);
    for(i = 0; i < sz; i++)
        *p++ = toupper(*p);
    fprintf(stderr, "-- received transact:%.*s\n", sz, blob);
    fprintf(stderr, "-- response transact:%.*s\n", sz, rsp_blob);
    rsp(rsp_blob, sz, 0, rsp_ud);
}

#ifdef SERVER


void server(void)
{
    ipclite *srv;
    ipclite_msg *msg;
    char buf[1024];
    char rsp[1024];
    size_t rsp_sz;

    if(ipclite_server_create(&srv, SERVER_PATH, "Hello, this is ipclite test.", 1, 0))  {
        fprintf(stderr, "Failed to create ipclite server\n");
        return;
    }

    if(ipclite_server_run(srv, msg_handler, NULL))  {
        fprintf(stderr, "Failed to run ipclite server\n");
        return;
    }

    if(ipclite_server_set_transact(srv, transact, NULL))  {
        fprintf(stderr, "fail to set transact\n");
        return;
    }

    for(;;)  {
        msg = (ipclite_msg *)&buf;
        msg->hdr.msg = IPCLITE_MSG_BASE;
        gets(msg->hdr.data);
        if(! peer)  {
            fprintf(stderr, "No peer connected!\n");
            continue;
        }
        msg->hdr.peer = peer;
        msg->hdr.len = MSG_LENGTH(strlen(msg->hdr.data));

        fprintf(stderr, "Sending a message\n");
        if(ipclite_server_sendmsg(srv, msg, 1, 0))  {
            fprintf(stderr, "Failed to send a message\n");
            return;
        }else  {
            fprintf(stderr, "Successfully sent a message\n");
        }

        fprintf(stderr, "Begin transact\n");
        rsp_sz = sizeof(rsp);
        if(ipclite_server_transact(srv, peer, msg->hdr.data, strlen(msg->hdr.data), rsp, &rsp_sz, -1))  {
            fprintf(stderr, "Fail to transact\n");
            return;
        }
        fprintf(stderr, "TRANSACT:%.*s\n", rsp_sz, rsp);

        /* if(! ipclite_server_recvmsg(srv, &msg))  { */
        /*     if(msg->hdr.msg == IPCLITE_MSG_SYN)  { */
        /*         ipclite_msg_syn *syn = (ipclite_msg_syn *)msg->hdr.data; */
        /*         fprintf(stderr, "RECV-SYN:%.*s\n", syn->len, syn->msg); */
        /*     }else if(msg->hdr.msg == IPCLITE_MSG_CLS)  { */
        /*         fprintf(stderr, "RECV-CLS\n"); */
        /*     }else  { */
        /*         fprintf(stderr, "RECV:%.*s\n", msg->hdr.len, (const char *)msg->hdr.data); */
        /*     } */
        /*     free(msg); */
        /* }else  { */
        /*     fprintf(stderr, "Failed to receive a message\n"); */
        /* } */
    }
}
#else

void client(void)
{
    int i = 0;

    ipclite *clt;
    ipclite_msg *msg;
    char buf[1024];
    char rsp[1024];
    size_t rsp_sz;

    if(ipclite_client_create(&clt, "Hello, this is ipclite test client.", 0))  {
        fprintf(stderr, "Failed to create ipclite client\n");
        return;
    }

    if(ipclite_client_connect_ex(clt, SERVER_PATH, 0, 10000))  {
        fprintf(stderr, "Failed to connect ipclite server\n");
        return;
    }

    if(ipclite_client_run(clt, msg_handler, NULL))  {
        fprintf(stderr, "Failed to run ipclite client\n");
        return;
    }

    if(ipclite_client_set_transact(clt, transact, NULL))  {
        fprintf(stderr, "fail to set transact\n");
        return;
    }


    for(;;)  {
        msg = (ipclite_msg *)&buf;
        msg->hdr.msg = IPCLITE_MSG_BASE;
        gets(msg->hdr.data);
        fprintf(stderr, "INPUT:%s\n", msg->hdr.data);
        msg->hdr.len = MSG_LENGTH(strlen(msg->hdr.data));

        fprintf(stderr, "Sending a message\n");
        if(ipclite_client_sendmsg(clt, msg, 1, 0))  {
            fprintf(stderr, "Failed to send a message\n");
            return;
        }else  {
            fprintf(stderr, "Successfully sent a message\n");
        }

        fprintf(stderr, "Begin transact\n");
        rsp_sz = sizeof(rsp);
        if(ipclite_client_transact(clt, msg->hdr.data, strlen(msg->hdr.data), rsp, &rsp_sz, -1))  {
            fprintf(stderr, "Fail to transact\n");
            return;
        }
        fprintf(stderr, "TRANSACT:%.*s\n", rsp_sz, rsp);
    }

    ipclite_client_destroy(clt);
}
#endif

int main()
{
#ifdef SERVER
    server();
#else
    client();
#endif
    return 0;
}

#elif defined(TEST_RPCLITE)

#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <pthread.h>

#include "rpclite.h"
#include "ipclite.h"

#define SERVER_PATH "./test_sock"

static unsigned int peer = 0;

static int msg_handler(ipclite_msg *msg, void *ud)
{
    ipclite_msg_syn *syn;

    if(msg->hdr.msg == IPCLITE_MSG_SYN)  {
        peer = msg->hdr.peer;
        syn = (ipclite_msg_syn *)&msg->hdr.data;
        fprintf(stderr, "SYN(%d):%.*s\n", peer, syn->len, syn->msg);
    }else if(msg->hdr.msg == IPCLITE_MSG_CLS)  {
        fprintf(stderr, "CLS: peer closed the connection\n");
    }else  {
        fprintf(stderr, "RECV:%s\n", msg->hdr.data);
    }
    return 1;
}

static void transact(unsigned int peer, const void *blob, size_t sz,
                     ipclite_response rsp, void *rsp_ud, void *ud)
{
    char rsp_blob[sz + 1];
    char *p = rsp_blob;
    int i;

    memcpy(rsp_blob, blob, sz);
    for(i = 0; i < sz; i++)
        *p++ = toupper(*p);
    fprintf(stderr, "-- received transact:%.*s\n", sz, blob);
    fprintf(stderr, "-- response transact:%.*s\n", sz, rsp_blob);
    rsp(rsp_blob, sz, RPCLITE_RSP_MORE, rsp_ud);
    rsp(rsp_blob, sz, 0, rsp_ud);
}

#ifdef SERVER

static int test_handler(int req, const char *blob, size_t sz, rpclite_response rsp, void *rsp_ud, void *ud)
{
    switch(req)  {
    case 1000:  {
        char rsp_blob[sz + 1];
        char *p = rsp_blob;
        int i;

        if(blob && ! strcmp(blob, "quit"))  {
            ipclite_server_quit((ipclite *)ud, 0);
            return;
        }

        for(i = 0; i < sz; i++)
            *p++ = toupper(blob[i]);
        *p = '\0';
        rsp(rsp_blob, sizeof(rsp_blob), RPCLITE_RSP_MORE, rsp_ud);
        rsp(rsp_blob, sizeof(rsp_blob), 0, rsp_ud);
        break;
    }
    default:
        return -1;
    }
    return 0;
}

static rpclite_svc test_svc = {
    .svc_name = "rpclite_test",
    .handler = test_handler,
};

void server(void)
{
    ipclite *srv;
    ipclite_msg *msg;
    char buf[1024];
    char rsp[1024];
    size_t rsp_sz;

    if(ipclite_server_create(&srv, SERVER_PATH, "Hello, this is ipclite test.", 1, 0))  {
        fprintf(stderr, "Failed to create ipclite server\n");
        return;
    }

    /* if(ipclite_server_run(srv, msg_handler, NULL))  { */
    /*     fprintf(stderr, "Failed to run ipclite server\n"); */
    /*     return; */
    /* } */

    if(rpclite_server_attach(srv))  {
        fprintf(stderr, "fail to attach to ipc server\n");
        return;
    }

    test_svc.ud = srv;
    if(rpclite_svc_register(&test_svc))  {
        fprintf(stderr, "fail to register to test service\n");
        return;
    }

    /* if(ipclite_server_set_transact(srv, transact, NULL))  { */
    /*     fprintf(stderr, "fail to set transact\n"); */
    /*     return; */
    /* } */
    ipclite_server_loop(srv, msg_handler, srv);
    return;

    for(;;)  {
        msg = (ipclite_msg *)&buf;
        msg->hdr.msg = IPCLITE_MSG_BASE;
        gets(msg->hdr.data);
        if(! peer)  {
            fprintf(stderr, "No peer connected!\n");
            continue;
        }
        msg->hdr.peer = peer;
        msg->hdr.len = MSG_LENGTH(strlen(msg->hdr.data));

        fprintf(stderr, "Sending a message\n");
        if(ipclite_server_sendmsg(srv, msg, 1, 0))  {
            fprintf(stderr, "Failed to send a message\n");
            return;
        }else  {
            fprintf(stderr, "Successfully sent a message\n");
        }
    }
}
#else

static int rsp_cb(void *rsp, size_t sz, int flags, void *ud)
{
    fprintf(stderr, "TRANSACT(%d:%x): %.*s\n", sz, flags, sz, rsp);
    return 1;
}

void client(void)
{
    int i = 0;

    ipclite *clt;
    ipclite_msg *msg;
    char buf[1024];
    char rsp[1024];
    size_t rsp_sz;

    rpclite_ctx ctx = {
        .svc_name = "rpclite_test",
    };

    if(ipclite_client_create(&clt, "Hello, this is ipclite test client.", 0))  {
        fprintf(stderr, "Failed to create ipclite client\n");
        return;
    }

    if(ipclite_client_connect(clt, SERVER_PATH, 0))  {
        fprintf(stderr, "Failed to connect ipclite server\n");
        return;
    }

    if(ipclite_client_run(clt, msg_handler, NULL))  {
        fprintf(stderr, "Failed to run ipclite client\n");
        return;
    }

    if(rpclite_connect_svc(&ctx, clt, 0, 0))  {
        fprintf(stderr, "fail to connect to service\n");
        return;
    }

    for(;;)  {
        msg = (ipclite_msg *)&buf;
        msg->hdr.msg = IPCLITE_MSG_BASE;
        gets(msg->hdr.data);
        fprintf(stderr, "INPUT:%s\n", msg->hdr.data);
        msg->hdr.len = MSG_LENGTH(strlen(msg->hdr.data));

        fprintf(stderr, "Sending a message\n");
        if(ipclite_client_sendmsg(clt, msg, 1, 0))  {
            fprintf(stderr, "Failed to send a message\n");
            return;
        }else  {
            fprintf(stderr, "Successfully sent a message\n");
        }

        fprintf(stderr, "Begin transact\n");
        rsp_sz = sizeof(rsp);
        /* if(rpclite_transact(&ctx, 1000, msg->hdr.data, strlen(msg->hdr.data), rsp, &rsp_sz, -1))  { */
        /*     fprintf(stderr, "Fail to transact\n"); */
        /*     return; */
        /* } */
        /* fprintf(stderr, "TRANSACT(%d):%.*s\n", rsp_sz, rsp_sz, rsp); */

        if(rpclite_transact_callback(&ctx, 1000, msg->hdr.data, strlen(msg->hdr.data), rsp_cb, NULL, -1))  {
            fprintf(stderr, "Fail to transact\n");
            return;
        }
    }

    /* if(ipclite_client_set_transact(clt, transact, NULL))  { */
    /*     fprintf(stderr, "fail to set transact\n"); */
    /*     return; */
    /* } */


    /* for(;;)  { */
    /*     msg = (ipclite_msg *)&buf; */
    /*     msg->hdr.msg = IPCLITE_MSG_BASE; */
    /*     gets(msg->hdr.data); */
    /*     fprintf(stderr, "INPUT:%s\n", msg->hdr.data); */
    /*     msg->hdr.len = MSG_LENGTH(strlen(msg->hdr.data)); */

    /*     fprintf(stderr, "Sending a message\n"); */
    /*     if(ipclite_client_sendmsg(clt, msg, 1, 0))  { */
    /*         fprintf(stderr, "Failed to send a message\n"); */
    /*         return; */
    /*     }else  { */
    /*         fprintf(stderr, "Successfully sent a message\n"); */
    /*     } */

    /*     fprintf(stderr, "Begin transact\n"); */
    /*     rsp_sz = sizeof(rsp); */
    /*     if(ipclite_client_transact(clt, msg->hdr.data, strlen(msg->hdr.data), rsp, &rsp_sz, -1))  { */
    /*         fprintf(stderr, "Fail to transact\n"); */
    /*         return; */
    /*     } */
    /*     fprintf(stderr, "TRANSACT:%.*s\n", rsp_sz, rsp); */
    /* } */

    ipclite_client_destroy(clt);
}
#endif

int main()
{
#ifdef SERVER
    server();
#else
    client();
#endif
    return 0;
}

#elif defined(TEST_CONF)

#include "fw_rule.h"
#include "conf.h"

static int do_verdict(fw_obj *obj, void *ud)
{

    printf("in verdict cb\n");
    return VERDICT_NONE;
}

int main()
{
    ginkgo_ctx *ctx;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(timer_init(ctx))  {
        printf("fail to init timer\n");
        return -1;
    }

    if(rules_init(do_verdict, NULL))  {
        printf("fail to init rules table\n");
        return -1;
    }

    if(conf_install("./rule_load.conf"))  {
        printf("fail to install rules\n");
        return -1;
    }

    if(conf_dump("./rule_dump.conf"))  {
        printf("fail to dump rules\n");
        return -1;
    }

    return 0;
}

#elif defined(TEST_RULE)

#include "fw_table.h"
#include "rule.h"

static int do_verdict(fw_obj *obj, void *ud)
{

    printf("in verdict cb\n");
    return VERDICT_NONE;
}

int main()
{
    ginkgo_ctx *ctx;

    if(ginkgo_create(&ctx, 0))  {
        printf("fail to create ginkgo\n");
        return -1;
    }

    if(ginkgo_run(ctx))  {
        printf("fail to run ginkgo\n");
        return -1;
    }

    if(timer_init(ctx))  {
        printf("fail to init timer\n");
        return -1;
    }

    if(fw_table_init(NULL, NULL))  {
        printf("fail to init rules table\n");
        return -1;
    }

    if(conf_install("./rule_load.conf"))  {
        printf("fail to install rules\n");
        return -1;
    }

    if(conf_dump("./rule_dump.conf"))  {
        printf("fail to dump rules\n");
        return -1;
    }

    return 0;
}

#elif defined(TEST_GARDENIA)

#include <stdio.h>
#include "gardenia.h"

int main()
{
    gardenia *g = gardenia_create("./log/a/b/c/d/e/f/g/", "test_log", 100 * 1000 * 1000, 14 * 1000 * 1000);
    int i;

    if(! g)  {
        fprintf(stderr, "fail to create gardenia\n");
        return -1;
    }

    for(i = 0; i < 50000000; i++)  {
        gardenia_print(g, "hello %s, %d\n", "Cross Chin", i);
    }
    gardenia_destroy(g);
    return 0;
}

#elif defined(TEST_SIG_HANDLE)

#include <stdio.h>

#include "sig_handle.h"

int main()
{
    /* TODO: */
}


#else
#error "No test module defined"
#endif
