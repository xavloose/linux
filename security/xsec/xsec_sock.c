#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/file.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/xsecurity.h>
#include <linux/xinternal.h>
#include <linux/xacl.h>

extern int x_search_udp_recvmsg(struct sock *sk, const struct sk_buff *skb);
extern int x_search_udp_sendmsg(struct sock *sk, struct sockaddr_in *addr);

EXPORT_SYMBOL_GPL(x_search_udp_recvmsg);
EXPORT_SYMBOL_GPL(x_search_udp_sendmsg);

#ifdef CONFIG_UNIX_MODULE
EXPORT_SYMBOL_GPL(x_acl_handle_unix);
EXPORT_SYMBOL_GPL(x_acl_handle_mknod);
EXPORT_SYMBOL_GPL(x_handle_chroot_unix);
EXPORT_SYMBOL_GPL(x_handle_create);
#endif

#ifdef CONFIG_XKERNSEC
#define x_conn_table_size 32749
struct conn_table_entry {
	struct conn_table_entry *next;
	struct signal_struct *sig;
};

struct conn_table_entry *x_conn_table[x_conn_table_size];
DEFINE_SPINLOCK(x_conn_table_lock);

extern const char * x_socktype_to_name(unsigned char type);
extern const char * x_proto_to_name(unsigned char proto);
extern const char * x_sockfamily_to_name(unsigned char family);

static int
conn_hash(__u32 saddr, __u32 daddr, __u16 sport, __u16 dport, unsigned int size)
{
	return ((daddr + saddr + (sport << 8) + (dport << 16)) % size);
}

static int
conn_match(const struct signal_struct *sig, __u32 saddr, __u32 daddr,
	   __u16 sport, __u16 dport)
{
	if (unlikely(sig->x_saddr == saddr && sig->x_daddr == daddr &&
		     sig->x_sport == sport && sig->x_dport == dport))
		return 1;
	else
		return 0;
}

static void x_add_to_task_ip_table_nolock(struct signal_struct *sig, struct conn_table_entry *newent)
{
	struct conn_table_entry **match;
	unsigned int index;

	index = conn_hash(sig->x_saddr, sig->x_daddr,
			  sig->x_sport, sig->x_dport,
			  x_conn_table_size);

	newent->sig = sig;

	match = &x_conn_table[index];
	newent->next = *match;
	*match = newent;

	return;
}

static void x_del_task_from_ip_table_nolock(struct signal_struct *sig)
{
	struct conn_table_entry *match, *last = NULL;
	unsigned int index;

	index = conn_hash(sig->x_saddr, sig->x_daddr,
			  sig->x_sport, sig->x_dport,
			  x_conn_table_size);

	match = x_conn_table[index];
	while (match && !conn_match(match->sig,
		sig->x_saddr, sig->x_daddr, sig->x_sport,
		sig->x_dport)) {
		last = match;
		match = match->next;
	}

	if (match) {
		if (last)
			last->next = match->next;
		else
			x_conn_table[index] = NULL;
		kfree(match);
	}

	return;
}

static struct signal_struct * x_lookup_task_ip_table(__u32 saddr, __u32 daddr,
					     __u16 sport, __u16 dport)
{
	struct conn_table_entry *match;
	unsigned int index;

	index = conn_hash(saddr, daddr, sport, dport, x_conn_table_size);

	match = x_conn_table[index];
	while (match && !conn_match(match->sig, saddr, daddr, sport, dport))
		match = match->next;

	if (match)
		return match->sig;
	else
		return NULL;
}

#endif

void x_update_task_in_ip_table(const struct inet_sock *inet)
{
#ifdef CONFIG_XKERNSEC
	struct signal_struct *sig = current->signal;
	struct conn_table_entry *newent;

	newent = kmalloc(sizeof(struct conn_table_entry), GFP_ATOMIC);
	if (newent == NULL)
		return;
	/* no bh lock needed since we are called with bh disabled */
	spin_lock(&x_conn_table_lock);
	x_del_task_from_ip_table_nolock(sig);
	sig->x_saddr = inet->inet_rcv_saddr;
	sig->x_daddr = inet->inet_daddr;
	sig->x_sport = inet->inet_sport;
	sig->x_dport = inet->inet_dport;
	x_add_to_task_ip_table_nolock(sig, newent);
	spin_unlock(&x_conn_table_lock);
#endif
	return;
}

void x_del_task_from_ip_table(struct task_struct *task)
{
#ifdef CONFIG_XKERNSEC
	spin_lock_bh(&x_conn_table_lock);
	x_del_task_from_ip_table_nolock(task->signal);
	spin_unlock_bh(&x_conn_table_lock);
#endif
	return;
}

void
x_attach_curr_ip(const struct sock *sk)
{
#ifdef CONFIG_XKERNSEC
	struct signal_struct *p, *set;
	const struct inet_sock *inet = inet_sk(sk);

	if (unlikely(sk->sk_protocol != IPPROTO_TCP))
		return;

	set = current->signal;

	spin_lock_bh(&x_conn_table_lock);
	p = x_lookup_task_ip_table(inet->inet_daddr, inet->inet_rcv_saddr,
				    inet->inet_dport, inet->inet_sport);
	if (unlikely(p != NULL)) {
		set->curr_ip = p->curr_ip;
		set->used_accept = 1;
		x_del_task_from_ip_table_nolock(p);
		spin_unlock_bh(&x_conn_table_lock);
		return;
	}
	spin_unlock_bh(&x_conn_table_lock);

	set->curr_ip = inet->inet_daddr;
	set->used_accept = 1;
#endif
	return;
}

int
x_handle_sock_all(const int family, const int type, const int protocol)
{
#ifdef CONFIG_XKERNSEC_SOCKET_ALL
	if (xsec_enable_socket_all && in_group_p(xsec_socket_all_gid) &&
	    (family != AF_UNIX)) {
		if (family == AF_INET)
			x_log_str3(X_DONT_AUDIT, X_SOCK_MSG, x_sockfamily_to_name(family), x_socktype_to_name(type), x_proto_to_name(protocol));
		else
			x_log_str2_int(X_DONT_AUDIT, X_SOCK_NOINET_MSG, x_sockfamily_to_name(family), x_socktype_to_name(type), protocol);
		return -EACCES;
	}
#endif
	return 0;
}

int
x_handle_sock_server(const struct sockaddr *sck)
{
#ifdef CONFIG_XKERNSEC_SOCKET_SERVER
	if (xsec_enable_socket_server &&
	    in_group_p(xsec_socket_server_gid) &&
	    sck && (sck->sa_family != AF_UNIX) &&
	    (sck->sa_family != AF_LOCAL)) {
		x_log_noargs(X_DONT_AUDIT, X_BIND_MSG);
		return -EACCES;
	}
#endif
	return 0;
}

int
x_handle_sock_server_other(const struct sock *sck)
{
#ifdef CONFIG_XKERNSEC_SOCKET_SERVER
	if (xsec_enable_socket_server &&
	    in_group_p(xsec_socket_server_gid) &&
	    sck && (sck->sk_family != AF_UNIX) &&
	    (sck->sk_family != AF_LOCAL)) {
		x_log_noargs(X_DONT_AUDIT, X_BIND_MSG);
		return -EACCES;
	}
#endif
	return 0;
}

int
x_handle_sock_client(const struct sockaddr *sck)
{
#ifdef CONFIG_XKERNSEC_SOCKET_CLIENT
	if (xsec_enable_socket_client && in_group_p(xsec_socket_client_gid) &&
	    sck && (sck->sa_family != AF_UNIX) &&
	    (sck->sa_family != AF_LOCAL)) {
		x_log_noargs(X_DONT_AUDIT, X_CONNECT_MSG);
		return -EACCES;
	}
#endif
	return 0;
}
