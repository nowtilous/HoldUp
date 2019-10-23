#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <linux/fs.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/udp.h>
#include <asm/spinlock.h>
#include <linux/jiffies.h>
#include <linux/version.h>
#include "holdup_main.h"
#include "monitor.h"
#include "mmu.h"
#include "asm_implementation.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#include <linux/proc_fs.h>
#endif

/* VFS & NET*/
static int check_vfs_object(int cpu_id);
static int check_net_object(int cpu_id);
static int check_inode_op_fields(int cpu_id, const struct inode_operations *op, const char *obj_name);
static int check_file_op_fields(int cpu_id, const struct file_operations *op, const char *obj_name);
static int check_tcp_seq_afinfo_fields(int cpu_id, const struct tcp_seq_afinfo *op, const char *obj_name);
static int check_udp_seq_afinfo_fields(int cpu_id, const struct udp_seq_afinfo *op, const char *obj_name);
static int check_proto_op_fields(int cpu_id, const struct proto_ops *op, const char *obj_name);

/* TASK LIST */
static int add_task_to_task_manager(struct task_struct *task);
static int del_task_from_task_manager(pid_t pid, pid_t tgid);
static void check_task_periodic(int cpu_id);
static int check_task_list(int cpu_id);
static int get_task_count(void);
static int is_in_task_list(struct task_struct *task);
static void copy_task_list_to_task_manager(void);

/* MODULE LIST */
static int add_module_to_module_manager(struct module *mod, int protect);
static int del_module_from_module_manager(struct module *mod);
static void check_module_periodic(int cpu_id);
static int check_module_list(int cpu_id);
static int get_module_count(void);
static int is_in_module_list(struct module *target);
static void copy_module_list_to_module_manager(void);

static int is_valid_vm_status(int cpu_id);
static int checktimer_expired_and_update(volatile u64 *last_jiffies);

/* Jiffies */
volatile u64 global_last_task_check_jiffies = 0;
volatile u64 global_last_module_check_jiffies = 0;
volatile u64 global_last_dkom_check_jiffies = 0;

volatile int global_module_count = 0;
volatile int global_task_count = 0;

static struct task_manager global_task_manager;
static struct module_manager global_module_manager;

static spinlock_t global_time_lock;
static volatile u64 global_tasklock_fail_count = 0;
static volatile u64 global_modulelock_fail_count = 0;

static int global_vfs_object_attack_detected = 0;
static int global_net_object_attack_detected = 0;

void sync_page_internal(u64 addr);

#if ENABLED_STAROZA
static int check_systemcall_for_cred(int syscall_number);
static void set_exit_flag_in_list(int tgid);
#endif

#pragma region SETUP_MONITOR
int prepare_security_monitor(void)
{
	int i, size;

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Framework Preinitialize\n");
	memset(&global_task_manager, 0, sizeof(global_task_manager));
	memset(&global_module_manager, 0, sizeof(global_module_manager));

	INIT_LIST_HEAD(&(global_task_manager.free_node_head));
	INIT_LIST_HEAD(&(global_task_manager.existing_node_head));
	size = sizeof(struct task_node) * TASK_NODE_MAX;
	global_task_manager.pool = vmalloc(size);
	if (global_task_manager.pool == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Task pool allcation fail\n");
		return -1;
	}
	memset(global_task_manager.pool, 0, size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Task pool %016lX, size %d\n", global_task_manager.pool, size);

	for (i = 0; i < TASK_NODE_MAX; i++)
	{
		list_add(&(global_task_manager.pool[i].list), &(global_task_manager.free_node_head));
	}

	INIT_LIST_HEAD(&(global_module_manager.free_node_head));
	INIT_LIST_HEAD(&(global_module_manager.existing_node_head));
	size = sizeof(struct module_node) * MODULE_NODE_MAX;
	global_module_manager.pool = vmalloc(size);
	if (global_module_manager.pool == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] Module pool allcation fail\n");
		return -1;
	}
	memset(global_module_manager.pool, 0, size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Module pool %016lX, size %d\n", global_module_manager.pool, size);

	for (i = 0; i < MODULE_NODE_MAX; i++)
	{
		list_add(&(global_module_manager.pool[i].list), &(global_module_manager.free_node_head));
	}
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");

	return 0;
}

void init_monitor(void)
{
	spin_lock_init(&global_time_lock);

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Framework Initailize\n");

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Check task list\n");
	copy_task_list_to_task_manager();

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Check module list\n");
	copy_module_list_to_module_manager();

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Task count %d\n", global_task_count);
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Module count %d\n", global_module_count);
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n", global_module_count);
}
#pragma endregion

static int check_file_op_fields(int cpu_id, const struct file_operations *op, const char *obj_name)
{
	int error = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s file operation fields\n", obj_name);

	error |= !is_addr_in_ro_area(op->llseek);
	error |= !is_addr_in_ro_area(op->read);
	error |= !is_addr_in_ro_area(op->write);
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	error |= !is_addr_in_ro_area(op->aio_read);
	error |= !is_addr_in_ro_area(op->aio_write);
#endif
	error |= !is_addr_in_ro_area(op->read_iter);
	error |= !is_addr_in_ro_area(op->write_iter);
	error |= !is_addr_in_ro_area(op->iterate);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 6, 0)
	error |= !is_addr_in_ro_area(op->iterate_shared);
#endif
	error |= !is_addr_in_ro_area(op->poll);
	error |= !is_addr_in_ro_area(op->unlocked_ioctl);
	error |= !is_addr_in_ro_area(op->compat_ioctl);
	error |= !is_addr_in_ro_area(op->mmap);
	error |= !is_addr_in_ro_area(op->open);
	error |= !is_addr_in_ro_area(op->flush);
	error |= !is_addr_in_ro_area(op->release);
	error |= !is_addr_in_ro_area(op->fsync);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !is_addr_in_ro_area(op->aio_fsync);
#endif
	error |= !is_addr_in_ro_area(op->fasync);
	error |= !is_addr_in_ro_area(op->lock);
	error |= !is_addr_in_ro_area(op->sendpage);
	error |= !is_addr_in_ro_area(op->get_unmapped_area);
	error |= !is_addr_in_ro_area(op->check_flags);
	error |= !is_addr_in_ro_area(op->flock);
	error |= !is_addr_in_ro_area(op->splice_write);
	error |= !is_addr_in_ro_area(op->splice_read);
	error |= !is_addr_in_ro_area(op->setlease);
	error |= !is_addr_in_ro_area(op->fallocate);
	error |= !is_addr_in_ro_area(op->show_fdinfo);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
	error |= !is_addr_in_ro_area(op->copy_file_range);
	error |= !is_addr_in_ro_area(op->clone_file_range);
	error |= !is_addr_in_ro_area(op->dedupe_file_range);
#endif

	if (error != 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is detected, function pointer=\"%s file_op\"\n", cpu_id, obj_name);
		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

#pragma region VFS
static int check_inode_op_fields(int cpu_id, const struct inode_operations *op, const char *obj_name)
{
	int error = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s inode operation fields\n", obj_name);

	error |= !is_addr_in_ro_area(op->lookup);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !is_addr_in_ro_area(op->follow_link);
#else
	error |= !is_addr_in_ro_area(op->get_link);
#endif
	error |= !is_addr_in_ro_area(op->permission);
	error |= !is_addr_in_ro_area(op->get_acl);
	error |= !is_addr_in_ro_area(op->readlink);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 5, 0)
	error |= !is_addr_in_ro_area(op->put_link);
#endif
	error |= !is_addr_in_ro_area(op->create);
	error |= !is_addr_in_ro_area(op->link);
	error |= !is_addr_in_ro_area(op->unlink);
	error |= !is_addr_in_ro_area(op->symlink);
	error |= !is_addr_in_ro_area(op->mkdir);
	error |= !is_addr_in_ro_area(op->rmdir);
	error |= !is_addr_in_ro_area(op->mknod);
	error |= !is_addr_in_ro_area(op->rename);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !is_addr_in_ro_area(op->rename2);
#endif
	error |= !is_addr_in_ro_area(op->setattr);
	error |= !is_addr_in_ro_area(op->getattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !is_addr_in_ro_area(op->setxattr);
	error |= !is_addr_in_ro_area(op->getxattr);
#endif
	error |= !is_addr_in_ro_area(op->listxattr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 9, 0)
	error |= !is_addr_in_ro_area(op->removexattr);
#endif
	error |= !is_addr_in_ro_area(op->fiemap);
	error |= !is_addr_in_ro_area(op->update_time);
	error |= !is_addr_in_ro_area(op->atomic_open);
	error |= !is_addr_in_ro_area(op->tmpfile);
	error |= !is_addr_in_ro_area(op->set_acl);

	if (error != 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is detected, function pointer=\"%s inode_op\"\n", cpu_id, obj_name);

		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

static int check_vfs_object(int cpu_id)
{
	struct inode_operations *inode_op;
	struct file_operations *file_op;
	int ret = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check /proc vfs field\n", cpu_id);
	if (global_proc_file_ptr == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check /proc vfs field fail\n", cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations *)global_proc_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations *)global_proc_file_ptr->f_path.dentry->d_inode->i_op;
#endif
		file_op = (struct file_operations *)global_proc_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= check_inode_op_fields(cpu_id, inode_op, "Proc FS");
		ret |= check_file_op_fields(cpu_id, file_op, "Proc FS");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Check / vfs field\n", cpu_id);
	if (global_root_file_ptr == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d]     [*] Check / vfs field fail\n", cpu_id);
	}
	else
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		inode_op = (struct inode_operations *)global_root_file_ptr->f_dentry->d_inode->i_op;
#else
		inode_op = (struct inode_operations *)global_root_file_ptr->f_path.dentry->d_inode->i_op;
#endif
		file_op = (struct file_operations *)global_root_file_ptr->f_op;

		/* Check integrity of inode and file operation function pointers. */
		ret |= check_inode_op_fields(cpu_id, inode_op, "Root FS");
		ret |= check_file_op_fields(cpu_id, file_op, "Root FS");
	}

	return ret;
}

static void check_function_pointers_periodic(int cpu_id)
{
	if (!checktimer_expired_and_update(&global_last_dkom_check_jiffies))
	{
		return;
	}

	if (global_vfs_object_attack_detected == 0)
	{
		if (check_vfs_object(cpu_id) < 0)
		{
			global_vfs_object_attack_detected = 1;
		}
	}

	if (global_net_object_attack_detected == 0)
	{
		if (check_net_object(cpu_id) < 0)
		{
			global_net_object_attack_detected = 1;
		}
	}
}
#pragma endregion

#pragma region NET
static int check_tcp_seq_afinfo_fields(int cpu_id, const struct tcp_seq_afinfo *op, const char *obj_name)
{
	int error = 0;

	if (check_file_op_fields(cpu_id, op->seq_fops, obj_name) < 0)
	{
		return -1;
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s seq_operations function pointer\n", obj_name);

	error |= !is_addr_in_ro_area(op->seq_ops.start);
	error |= !is_addr_in_ro_area(op->seq_ops.stop);
	error |= !is_addr_in_ro_area(op->seq_ops.next);
	error |= !is_addr_in_ro_area(op->seq_ops.show);

	if (error != 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is detected, function pointer=\"%s tcp_seq_afinfo\"\n", cpu_id, obj_name);
		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

static int check_udp_seq_afinfo_fields(int cpu_id, const struct udp_seq_afinfo *op, const char *obj_name)
{
	int error = 0;

	if (check_file_op_fields(cpu_id, op->seq_fops, obj_name) < 0)
	{
		return -1;
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s seq_operations function pointer\n", obj_name);

	error |= !is_addr_in_ro_area(op->seq_ops.start);
	error |= !is_addr_in_ro_area(op->seq_ops.stop);
	error |= !is_addr_in_ro_area(op->seq_ops.next);
	error |= !is_addr_in_ro_area(op->seq_ops.show);

	if (error != 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is detected, function pointer=\"%s udp_seq_afinfo\"\n", cpu_id, obj_name);
		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}

static int check_proto_op_fields(int cpu_id, const struct proto_ops *op, const char *obj_name)
{
	int error = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check %s proto_ops operation fields\n", obj_name);

	error |= !is_addr_in_ro_area(op->release);
	error |= !is_addr_in_ro_area(op->bind);
	error |= !is_addr_in_ro_area(op->connect);
	error |= !is_addr_in_ro_area(op->socketpair);
	error |= !is_addr_in_ro_area(op->accept);
	error |= !is_addr_in_ro_area(op->getname);
	error |= !is_addr_in_ro_area(op->poll);
	error |= !is_addr_in_ro_area(op->ioctl);
	error |= !is_addr_in_ro_area(op->compat_ioctl);
	error |= !is_addr_in_ro_area(op->listen);
	error |= !is_addr_in_ro_area(op->shutdown);
	error |= !is_addr_in_ro_area(op->setsockopt);
	error |= !is_addr_in_ro_area(op->getsockopt);
	error |= !is_addr_in_ro_area(op->compat_setsockopt);
	error |= !is_addr_in_ro_area(op->compat_getsockopt);
	error |= !is_addr_in_ro_area(op->sendmsg);
	error |= !is_addr_in_ro_area(op->recvmsg);
	error |= !is_addr_in_ro_area(op->mmap);
	error |= !is_addr_in_ro_area(op->sendpage);
	error |= !is_addr_in_ro_area(op->splice_read);
	error |= !is_addr_in_ro_area(op->set_peek_off);

	if (error != 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Function pointer attack is detected, function pointer=\"%s proto_seq_afinfo\"\n", cpu_id, obj_name);
		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}
	return 0;
}
#pragma endregion
static int check_net_object(int cpu_id)
{
	struct tcp_seq_afinfo *tcp_afinfo;
	struct udp_seq_afinfo *udp_afinfo;
	int ret = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Check Net Object\n");

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Net Object\n");
	if (global_tcp_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		tcp_afinfo = (struct tcp_seq_afinfo *)PDE_DATA(global_tcp_file_ptr->f_dentry->d_inode);
#else
		tcp_afinfo = (struct tcp_seq_afinfo *)PDE_DATA(global_tcp_file_ptr->f_path.dentry->d_inode);
#endif
		ret |= check_tcp_seq_afinfo_fields(cpu_id, tcp_afinfo, "TCP Net");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Net Object\n");
	if (global_udp_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		udp_afinfo = (struct udp_seq_afinfo *)PDE_DATA(global_udp_file_ptr->f_dentry->d_inode);
#else
		udp_afinfo = (struct udp_seq_afinfo *)PDE_DATA(global_udp_file_ptr->f_path.dentry->d_inode);
#endif
		ret |= check_udp_seq_afinfo_fields(cpu_id, udp_afinfo, "UDP Net");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP6 Net Object\n");
	if (global_tcp6_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		tcp_afinfo = (struct tcp_seq_afinfo *)PDE_DATA(global_tcp6_file_ptr->f_dentry->d_inode);
#else
		tcp_afinfo = (struct tcp_seq_afinfo *)PDE_DATA(global_tcp6_file_ptr->f_path.dentry->d_inode);
#endif
		ret |= check_tcp_seq_afinfo_fields(cpu_id, tcp_afinfo, "TCP6 Net");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP6 Net Object\n");
	if (global_udp6_file_ptr != NULL)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		udp_afinfo = (struct udp_seq_afinfo *)PDE_DATA(global_udp6_file_ptr->f_dentry->d_inode);
#else
		udp_afinfo = (struct udp_seq_afinfo *)PDE_DATA(global_udp6_file_ptr->f_path.dentry->d_inode);
#endif
		ret |= check_udp_seq_afinfo_fields(cpu_id, udp_afinfo, "UDP6 Net");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check TCP Socket Object\n");
	if (global_tcp_sock != NULL)
	{
		ret |= check_proto_op_fields(cpu_id, global_tcp_sock->ops, "TCP Socket");
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check UDP Socket Object\n");
	if (global_udp_sock != NULL)
	{
		ret |= check_proto_op_fields(cpu_id, global_udp_sock->ops, "UDP Socket");
	}

	return ret;
}

#pragma region TASK_LIST
static int add_task_to_task_manager(struct task_struct *task)
{
	struct list_head *temp;
	struct task_node *node;

	global_task_count++;

	if (list_empty(&(global_task_manager.free_node_head)))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
		error_log(ERROR_TASK_OVERFLOW);
		return -1;
	}

	temp = global_task_manager.free_node_head.next;
	node = container_of(temp, struct task_node, list);
	list_del(&(node->list));

	node->pid = task->pid;
	node->tgid = task->tgid;
	node->task = task;
	memcpy(node->comm, task->comm, sizeof(node->comm));
	memcpy(&(node->cred), task->cred, sizeof(struct cred));
	node->syscall_number = -1;
	node->need_exit = 0;

	list_add(&(node->list), &(global_task_manager.existing_node_head));

	return 0;
}

static int del_task_from_task_manager(pid_t pid, pid_t tgid)
{
	struct list_head *node;
	struct task_node *target;

	global_task_count--;

	list_for_each(node, &(global_task_manager.existing_node_head))
	{
		target = container_of(node, struct task_node, list);
		if ((pid == target->pid) && (tgid == target->tgid))
		{
			list_del(&(target->list));
			list_add(&(target->list), &(global_task_manager.free_node_head));
			return 0;
		}
	}

	return -1;
}

static void check_task_periodic(int cpu_id)
{
	if (!checktimer_expired_and_update(&global_last_task_check_jiffies))
	{
		return;
	}

	if (write_trylock(global_tasklist_lock))
	{
		check_task_list(cpu_id);
		write_unlock(global_tasklist_lock);
	}
	else
	{
		global_last_task_check_jiffies = 0;
	}
}

static int check_task_list(int cpu_id)
{
	struct list_head *node, *next;
	struct task_node *target;
	int cur_count;

	cur_count = get_task_count();

	if (global_task_count > cur_count)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Task count is different, expect=%d real=%d\n", cpu_id, global_task_count, cur_count);

		list_for_each_safe(node, next, &(global_task_manager.existing_node_head))
		{
			target = container_of(node, struct task_node, list);

			if (is_in_task_list(target->task))
			{
				continue;
			}

			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Hidden task, PID=%d TGID=%d fork name=\"%s\" process name=\"%s\"\n", cpu_id, target->pid, target->tgid, target->comm, target->task->comm);
			del_task_from_task_manager(target->pid, target->tgid);
		}

		error_log(ERROR_KERNEL_MODIFICATION);
		return -1;
	}

	return 0;
}

static int get_task_count(void)
{
	struct task_struct *iter;
	int count = 0;
#if ENABLED_STAROZA
	struct task_struct* process;
#endif
	sync_page((u64)(init_task.tasks.next), sizeof(struct task_struct));

#if !ENABLED_STAROZA
	for_each_process(iter)
#else
	for_each_process_thread(process, iter)
#endif
	{
		count++;

		if (count >= TASK_NODE_MAX - 1)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "Task count overflows\n");
			break;
		}
		sync_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return count;
}

static int is_in_task_list(struct task_struct *task)
{
	struct task_struct *iter;
	int is_in = 0;
#if ENABLED_STAROZA
	struct task_struct *process;
#endif

	sync_page((u64)(init_task.tasks.next), sizeof(struct task_struct));

#if !ENABLED_STAROZA
	for_each_process(iter)
	{
#else
	for_each_process_thread(process, iter)
	{
#endif
		if ((iter == task) && (task->pid == iter->pid) &&
			(task->tgid == iter->tgid))
		{
			is_in = 1;
			break;
		}

		sync_page((u64)(iter->tasks.next), sizeof(struct task_struct));
	}

	return is_in;
}

static void copy_task_list_to_task_manager(void)
{
	struct task_struct *iter;
#if ENABLED_STAROZA
	struct task_struct *process;
#endif

	/* If STAROZA is turned on, check all processes and threads. */
#if !ENABLED_STAROZA
	for_each_process(iter)
	{
#else
	for_each_process_thread(process, iter)
	{
#endif
		if (add_task_to_task_manager(iter) != 0)
		{
			return;
		}
	}
}
#pragma endregion

#pragma region MODULE_LIST
static int add_module_to_module_manager(struct module *mod, int protect)
{
	struct list_head *temp;
	struct module_node *node;

	global_module_count++;

	if (list_empty(&(global_module_manager.free_node_head)))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "Module count overflows\n");
		error_log(ERROR_MODULE_OVERFLOW);
		return -1;
	}

	temp = global_module_manager.free_node_head.next;
	node = container_of(temp, struct module_node, list);
	list_del(&(node->list));

	node->module = mod;
	node->protect = protect;
	memcpy(node->name, mod->name, sizeof(mod->name));

	list_add(&(node->list), &(global_module_manager.existing_node_head));

	return 0;
}

static int del_module_from_module_manager(struct module *mod)
{
	struct list_head *node;
	struct module_node *target;

	global_module_count--;

	list_for_each(node, &(global_module_manager.existing_node_head))
	{
		target = container_of(node, struct module_node, list);
		if (target->module == mod)
		{
			list_del(&(target->list));
			list_add(&(target->list), &(global_module_manager.free_node_head));
			return 0;
		}
	}

	return -1;
}

static void check_module_periodic(int cpu_id)
{
	if (!checktimer_expired_and_update(&global_last_module_check_jiffies))
	{
		return;
	}

	if (mutex_trylock(&module_mutex))
	{
		check_module_list(cpu_id);
		mutex_unlock(&module_mutex);
	}
	else
	{
		global_last_module_check_jiffies = 0;
	}
}

static int check_module_list(int cpu_id)
{
	struct list_head *node;
	struct list_head *next;
	struct module_node *target;
	int count;

	count = get_module_count();

	if (global_module_count > count)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Module count is different, expect=%d real=%d\n", cpu_id, global_module_count, count);

		list_for_each_safe(node, next, &(global_module_manager.existing_node_head))
		{
			target = container_of(node, struct module_node, list);
			if (is_in_module_list(target->module))
			{
				continue;
			}

			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Hidden module, module name=\"%s\" ptr=%016lX\n", cpu_id, target->name, target->module);

			del_module_from_module_manager(target->module);
		}

		error_log(ERROR_KERNEL_MODIFICATION);
	}

	return global_module_count;
}

static int get_module_count(void)
{
	struct list_head *pos, *node;
	int count = 0;
	struct module *cur;

	node = global_modules_ptr;

	list_for_each(pos, node)
	{
		cur = container_of(pos, struct module, list);
		if (cur != NULL)
		{
			sync_page((u64)cur, sizeof(cur));

			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "kernel module %s, list ptr %016lX, "
												  "phy %016lX module ptr %016lX, phy %016lX\n",
					   cur->name, pos,
					   virt_to_phys(pos), cur, virt_to_phys(pos));
		}
		count++;
	}

	return count;
}

static int is_in_module_list(struct module *target)
{
	struct list_head *pos, *node;
	struct module *cur;
	int find = 0;

	node = global_modules_ptr;

	sync_page((u64)(node->next), sizeof(struct list_head));

	list_for_each(pos, node)
	{
		cur = container_of(pos, struct module, list);
		sync_page((u64)cur, sizeof(cur));
		if (cur == target)
		{
			find = 1;
			break;
		}

		sync_page((u64)(pos->next), sizeof(struct list_head));
	}

	return find;
}

static void copy_module_list_to_module_manager(void)
{
	struct module *mod;
	struct list_head *pos, *node;

	node = global_modules_ptr;
	list_for_each(pos, node)
	{
		mod = container_of(pos, struct module, list);

		if (mod == THIS_MODULE)
		{
			continue;
		}

		add_module_to_module_manager(mod, 1);
	}
}
#pragma endregion

#pragma region CALLBACKS
void callback_add_task(int cpu_id, struct vm_exit_guest_register *context)
{
	struct task_struct *task;

#if ENABLED_STAROZA
	struct list_head *node;
	struct task_node *target;
#endif

	task = (struct task_struct *)context->rdi;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] %s prepares to add list count=%d\n", cpu_id, task->comm, global_task_count);

	while (!write_trylock(global_tasklist_lock))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] *** Task Add Lock Fail ***n", cpu_id);
		pause_loop();
		global_tasklock_fail_count++;
	}

	if (global_task_count == 0)
	{
		goto EXIT;
	}

	sync_page((u64)task, sizeof(struct task_struct));

#if !ENABLED_STAROZA
	if (task->pid != task->tgid)
	{
		goto EXIT;
	}
#endif

	if (is_in_task_list(task))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Task Create addr:%016lX phy:%016lX pid %d tgid %d [%s]\n", cpu_id, task, virt_to_phys(task), task->pid, task->tgid, task->comm);

#if ENABLED_STAROZA

		if (task->cred->uid.val < 1000)
		{
			not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] "
												  "creates privileged task [%s][PID %d, TGID %d, UID %d]\n",
					   cpu_id, current->comm, current->pid, current->tgid, task->comm,
					   task->pid, task->tgid, task->cred->uid.val);
		}

		list_for_each(node, &(global_task_manager.existing_node_head))
		{
			target = container_of(node, struct task_node, list);
			if (current->pid == target->pid)
			{
				if (!((target->syscall_number == __NR_fork) ||
					  (target->syscall_number == __NR_vfork) ||
					  (target->syscall_number == __NR_clone) ||
					  (target->syscall_number == -1)))
				{
					set_exit_flag_in_list(task->tgid);

					not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d, "
														  "TGID %d] creates task [%s][PID %d, TGID %d] in disallowed "
														  "syscall[%d], Kill it.\n",
							   cpu_id, current->comm, current->pid, current->tgid,
							   task->comm, task->pid, task->tgid, target->syscall_number);
				}

				break;
			}
		}

#endif
		add_task_to_task_manager(task);
		check_task_list(cpu_id);
	}

EXIT:
	write_unlock(global_tasklist_lock);
}

void callback_del_task(int cpu_id, struct vm_exit_guest_register *context)
{
	struct task_struct *task;

	while (!write_trylock(global_tasklist_lock))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] *** Task Remove Lock Fail ***\n", cpu_id);
		pause_loop();
		global_tasklock_fail_count++;
	}

	if (global_task_count == 0)
	{
		goto EXIT;
	}

	task = (struct task_struct *)context->rdi;

#if !ENABLED_STAROZA
	if (task->pid != task->tgid)
	{
		goto EXIT;
	}
#endif
	if (is_in_task_list(task))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Task Delete %d %d [%s]\n", cpu_id, task->pid, task->tgid, task->comm);

		check_task_list(cpu_id);
		del_task_from_task_manager(task->pid, task->tgid);
	}

EXIT:
	write_unlock(global_tasklist_lock);
}

void callback_task_switch(int cpu_id)
{
	check_task_list(cpu_id);
}

#if !ENABLED_STAROZA
void callback_insmod(int cpu_id)
{
	struct module *mod;
	struct list_head *mod_head_node;

	mod_head_node = global_modules_ptr;
	while (!mutex_trylock(&module_mutex))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] *** Module Insmod Lock Fail ***\n", cpu_id);
		pause_loop();
		global_modulelock_fail_count++;
	}

	if (global_module_count == 0)
	{
		goto EXIT;
	}

	mod = list_entry((mod_head_node->next), struct module, list);
	sync_page((u64)mod, sizeof(struct module));

	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Kernel module is loaded, current PID=%d PPID=%d process name=%s module=%s\n", cpu_id, current->pid, current->parent->pid, current->comm, mod->name);

	add_module_to_module_manager(mod, 0);
	check_module_list(cpu_id);

EXIT:
	mutex_unlock(&module_mutex);
}

void callback_rmmod(int cpu_id, struct vm_exit_guest_register *context)
{
	struct module *mod;
	u64 mod_base, mod_ro_size;

	while (!mutex_trylock(&module_mutex))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] *** Module Rmmod Lock Fail ***\n", cpu_id);
		pause_loop();
		global_modulelock_fail_count++;
	}

	if (global_module_count == 0)
	{
		goto EXIT;
	}

	/* Synchronize before introspection. */
	mod = (struct module *)context->rdi;
	sync_page((u64)mod, sizeof(struct module));
	sync_page((u64)current, sizeof(struct task_struct));

	if (!is_in_module_list(mod))
	{
		goto EXIT;
	}

	if (mod != THIS_MODULE)
	{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		mod_base = (u64)mod->module_core;
		mod_ro_size = (u64)mod->core_ro_size;
#else
		mod_base = (u64)(mod->core_layout.base);
		mod_ro_size = (u64)(mod->core_layout.ro_size);
#endif
		set_all_access_range(mod_base, mod_base + mod_ro_size, ALLOC_VMALLOC);
		delete_ro_area(mod_base, mod_base + mod_ro_size);

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Kernel module is unloaded, current PID=%d PPID=%d process name=%s module=%s\n", cpu_id, current->pid, current->parent->pid, current->comm, mod->name);

		check_module_list(cpu_id);
		del_module_from_module_manager(mod);
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Process try to unload, holdup. current PID=%d PPID=%d process name=%s\n", cpu_id, current->pid, current->parent->pid, current->comm);

		insert_exception_to_vm();
	}

EXIT:
	mutex_unlock(&module_mutex);
}
#endif
void callback_vm_timer(int cpu_id)
{
	if (is_valid_vm_status(cpu_id) == 1)
	{
		check_task_periodic(cpu_id);
		check_module_periodic(cpu_id);
		check_function_pointers_periodic(cpu_id);
	}
}
#if ENABLED_STAROZA
int callback_check_cred_update_syscall(int cpu_id, struct task_struct *task, int syscall_number)
{
	struct list_head *node;
	struct task_node *target;
	int found = 0, ret = 0;

	while (!write_trylock(global_tasklist_lock))
	{
		pause_loop();
		global_tasklock_fail_count++;
	}

	if (global_task_count == 0)
	{
		goto EXIT;
	}

	list_for_each(node, &(global_task_manager.existing_node_head))
	{
		target = container_of(node, struct task_node, list);

		if (task->pid == target->pid)
		{
			target->syscall_number = syscall_number;

			found = 1;

			//is cred changed abnormally? or should be exited?
			if ((target->cred.uid.val != task->cred->uid.val) ||
				(target->cred.gid.val != task->cred->gid.val) ||
				(target->cred.suid.val != task->cred->suid.val) ||
				(target->cred.sgid.val != task->cred->sgid.val) ||
				(target->cred.euid.val != task->cred->euid.val) ||
				(target->cred.egid.val != task->cred->egid.val) ||
				(target->cred.fsuid.val != task->cred->fsuid.val) ||
				(target->cred.fsgid.val != task->cred->fsgid.val))
			{
				not_printf(LOG_LEVEL_NORMAL, LOG_ERROR "VM [%d] [%s][PID %d] "
													   "cred is changed abnormally org[UID %d, GID %d, SUID %d, SGID %d, "
													   "EUID %d, EGID %d, FSUID %d, FSGID %d], new[UID %d, GID %d, SUID %d, "
													   "SGID %d, EUID %d, EGID %d, FSUID %d, FSGID %d], Terminate it.\n",
						   cpu_id, current->comm, current->pid, target->cred.uid,
						   target->cred.gid, target->cred.suid, target->cred.sgid,
						   target->cred.euid, target->cred.egid, target->cred.fsuid,
						   target->cred.fsgid, task->cred->uid, task->cred->gid,
						   task->cred->suid, task->cred->sgid, task->cred->euid,
						   task->cred->egid, task->cred->fsuid, task->cred->fsgid);

				set_exit_flag_in_list(target->tgid);

				ret = -1;
			}
			else if (target->need_exit == 1)
			{
				ret = -1;
			}

			break;
		}
	}

EXIT:
	mutex_unlock(&module_mutex);
	write_unlock(global_tasklist_lock);

	if (found == 0)
	{
		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s][PID %d] check cred failed [TGID %d]\n", cpu_id, task->comm, task->pid, task->tgid);
	}

	return ret;
}

void callback_update_cred(int cpu_id, struct task_struct *task, struct cred *new)
{
	struct list_head *node;
	struct task_node *target;
	int found = 0;

	while (!write_trylock(global_tasklist_lock))
	{
		pause_loop();
		global_tasklock_fail_count++;
	}

	if (global_task_count == 0)
	{
		goto EXIT;
	}

	list_for_each(node, &(global_task_manager.existing_node_head))
	{
		target = container_of(node, struct task_node, list);
		if (task->pid == target->pid)
		{
			// Monitor UID changes
			if ((target->cred.uid.val != new->uid.val) && (new->uid.val < 1000))
			{
				not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] "
													  "cred is changed, old[UID %d], new[UID %d, GID %d, EUID %d, "
													  "EGID %d, FSUID %d, FSGID %d]\n",
						   cpu_id, current->comm, current->pid, current->tgid,
						   target->cred.uid, new->uid, new->gid, new->euid, new->egid,
						   new->fsuid, new->fsgid);
			}

			// Check valid system call
			if (check_systemcall_for_cred(target->syscall_number) != 0)
			{
				set_exit_flag_in_list(task->tgid);

				not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] [%s][PID %d, TGID %d] cred "
													  "is changed in disallowed syscall[%d]. Restore old cred and kill it.\n",
						   cpu_id, current->comm, current->pid, current->tgid, target->syscall_number);

				// Recover previous uid and gid
				new->uid.val = target->cred.uid.val;
				new->gid.val = target->cred.gid.val;
				new->suid.val = target->cred.suid.val;
				new->sgid.val = target->cred.sgid.val;
				new->euid.val = target->cred.euid.val;
				new->egid.val = target->cred.egid.val;
				new->fsuid.val = target->cred.fsuid.val;
				new->fsgid.val = target->cred.fsgid.val;
			}
			else
			{
				// Root process is executed after fork system call
				if ((target->syscall_number == __NR_execve) && (new->uid.val < 1000))
				{
					not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] "
														  "is executed and has privilege, new[UID %d, "
														  "GID %d, EUID %d, EGID %d, FSUID %d, FSGID %d]\n",
							   cpu_id, current->comm, current->pid, current->tgid,
							   new->uid, new->gid, new->euid, new->egid, new->fsuid, new->fsgid);

					memcpy(target->comm, current->comm, TASK_COMM_LEN);
				}
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] "
													  "cred is changed, new[UID %d, GID %d, EUID %d, EGID %d, FSUID %d, "
													  "FSGID %d]\n",
						   cpu_id, current->comm, current->pid, current->tgid,
						   new->uid, new->gid, new->euid, new->egid,
						   new->fsuid, new->fsgid);

				memcpy(&(target->cred), new, sizeof(struct cred));
			}

			found = 1;
			break;
		}
	}

EXIT:
	write_unlock(global_tasklist_lock);

	if (found == 0)
	{
		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] [%s] updates cred failed [PID %d] [TGID %d]\n", cpu_id, task->comm, task->pid, task->tgid);
	}
}
#endif
#pragma endregion

#if ENABLED_STAROZA
static void set_exit_flag_in_list(int tgid)
{
	struct list_head *node;
	struct task_node *target;

	list_for_each(node, &(global_task_manager.existing_node_head))
	{
		target = container_of(node, struct task_node, list);
		if (target->tgid == tgid)
		{
			target->need_exit = 1;
		}
	}
}

static int check_systemcall_for_cred(int syscall_number)
{
	if (!((syscall_number == __NR_execve) || (syscall_number == __NR_setuid) ||
		  (syscall_number == __NR_setgid) || (syscall_number == __NR_setreuid) ||
		  (syscall_number == __NR_setregid) || (syscall_number == __NR_setresuid) ||
		  (syscall_number == __NR_setresgid) || (syscall_number == __NR_setfsuid) ||
		  (syscall_number == __NR_setfsgid) || (syscall_number == __NR_setgroups) ||
		  (syscall_number == __NR_capset) || (syscall_number == __NR_prctl) ||
		  (syscall_number == __NR_unshare) || (syscall_number == __NR_keyctl) ||
		  (syscall_number == -1)))
	{
		return -1;
	}

	return 0;
}
#endif
static int is_valid_vm_status(int cpu_id)
{
	if (atomic_read(&global_need_init_in_secure) == 0)
	{
		return 1;
	}

	return 0;
}

void sync_page(u64 addr, u64 size)
{
	u64 page_count;
	u64 i;

	page_count = ((addr % S_4KB) + size + S_4KB - 1) / S_4KB;

	for (i = 0; i < page_count; i++)
	{
		sync_page_internal(addr + S_4KB * i);
	}
}

void sync_page_internal(u64 addr)
{
	u64 ret_value;

	ret_value = sync_page_table(addr);
	if (ret_value != 0)
	{
	}

	return;
}

static int checktimer_expired_and_update(volatile u64 *last_jiffies)
{
	int expired = 0;
	u64 value;

	if (spin_trylock(&global_time_lock))
	{
		value = jiffies - *last_jiffies;

		if (jiffies_to_usecs(value) >= TIMER_INTERVAL)
		{
			*last_jiffies = jiffies;
			expired = 1;
		}

		spin_unlock(&global_time_lock);
	}
	else
	{
	}

	return expired;
}

void protect_monitor(void)
{
	u64 size;

	size = sizeof(struct task_node) * TASK_NODE_MAX;
	hide_range((u64)global_task_manager.pool, (u64)global_task_manager.pool + size, ALLOC_VMALLOC);

	size = sizeof(struct module_node) * MODULE_NODE_MAX;
	hide_range((u64)global_module_manager.pool, (u64)global_module_manager.pool + size, ALLOC_VMALLOC);
}