lib_LTLIBRARIES = libcactus.la

libcactus_la_SOURCES = cactus_be.c \
						cactus_be.h	\
						cactus.h \
						cactus_log.c \
						cactus_log.h \
						nfqm.c \
						nfqm.h \
						rule.c \
						rule.h \
						sig_handle.c \
						sig_handle.h \
						core.c \
						core.h \
						fd_lookup.c \
						fd_lookup.h \
						fw_table.c \
						fw_table.h \
						gardenia.c \
						gardenia.h \
						ginkgo.c \
						ginkgo.h \
						ipclite.c \
						ipclite_client.c \
						ipclite.h \
						ipclite_priv.h \
						ipclite_server.c \
						jhash.h \
						md5.c \
						md5.h \
						msg_base.h \
						msg.c \
						msg.h \
						async_work.c \
						async_work.h \
						nfct.c \
						nfct.h \
						nfq.c \
						nfq.h \
						nl.c \
						nl.h \
						rpclite.c \
						rpclite.h \
						rtnl.c \
						rtnl.h \
						sock_stat.c \
						sock_stat.h \
						stdalign.h \
						timer.c \
						timer.h \
						uevent.c \
						uevent.h \
						branch.c \
						branch.h \
						util.c \
						util.h \
						kconf.c \
						kconf.h \
						port/linux_fib_rules.h \
						port/linux_if_link.h \
						port/linux_inet_diag.h \
						port/linux_netfilter_nf_conntrack_common.h \
						port/linux_netfilter_nf_conntrack_sctp.h \
						port/linux_netfilter_nf_conntrack_tcp.h \
						port/linux_netfilter_nf_conntrack_tuple_common.h \
						port/linux_netfilter_nfnetlink_conntrack.h \
						port/linux_netfilter_nfnetlink_queue.h \
						port/linux_signalfd.h \
						port/linux_sock_diag.h \
						port/linux_timerfd.h


libcactus_la_LIBADD = -lpthread -lrt -lz
libcactus_la_CFLAGS = -O3 -fno-strict-aliasing -Iport

EXTRA_DIST = port/linux_fib_rules.h \
			port/linux_if_link.h \
			port/linux_inet_diag.h \
			port/linux_netfilter_nf_conntrack_common.h \
			port/linux_netfilter_nf_conntrack_sctp.h \
			port/linux_netfilter_nf_conntrack_tcp.h \
			port/linux_netfilter_nf_conntrack_tuple_common.h \
			port/linux_netfilter_nfnetlink_conntrack.h \
			port/linux_netfilter_nfnetlink_queue.h \
			port/linux_signalfd.h \
			port/linux_sock_diag.h \
			port/linux_syscall.S \
			port/linux_timerfd.h \
			port/__set_errno.c

