#ifndef __MONITOR_H__
#define __MONITOR_H__

#define TASK_NODE_MAX		(PID_MAX_LIMIT)
#define MODULE_NODE_MAX		(10000)

/*

                     USER VIEW
 <-- PID 43 --> <----------------- PID 42 ----------------->
                     +---------+
                     | process |
                    _| pid=42  |_
                  _/ | tgid=42 | \_ (new thread) _
       _ (fork) _/   +---------+                  \
      /                                        +---------+
+---------+                                    | process |
| process |                                    | pid=44  |
| pid=43  |                                    | tgid=42 |
| tgid=43 |                                    +---------+
+---------+
 <-- PID 43 --> <--------- PID 42 --------> <--- PID 44 --->
                     KERNEL VIEW
*/
struct task_node
{
	struct list_head list;
	pid_t pid; // Proccess ID
	pid_t tgid; // Thread group ID (PID of the thread that started the whole process)
	struct task_struct* task;
	char comm[TASK_COMM_LEN];
	struct cred cred;
	int syscall_number;
	int need_exit;
};

struct module_node
{
	struct list_head list;
	struct module* module;
	int protect;
	char name[MODULE_NODE_MAX];
};

struct task_manager
{
	struct list_head free_node_head;
	struct list_head existing_node_head;
	struct task_node* pool;
};

struct module_manager
{
	struct list_head free_node_head;
	struct list_head existing_node_head;
	struct module_node* pool;
};

int prepare_security_monitor(void);
void init_monitor(void);

void protect_monitor(void);

void callback_vm_timer(int cpu_id);
void callback_del_task(int cpu_id, struct vm_exit_guest_register* context);
void callback_add_task(int cpu_id, struct vm_exit_guest_register* context);
void callback_task_switch(int cpu_id);

#if ENABLED_STAROZA
void callback_update_cred(int cpu_id, struct task_struct* task, struct cred* new);
int callback_check_cred_update_syscall(int cpu_id, struct task_struct* task, int syscall_number);
#else
void callback_insmod(int cpu_id);
void callback_rmmod(int cpu_id, struct vm_exit_guest_register* context);
#endif

void sync_page(u64 addr, u64 size);

#endif //__MONITOR_H__
