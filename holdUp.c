#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <asm/desc.h>
#include <linux/kallsyms.h>
#include <asm/hw_breakpoint.h>
#include <asm/debugreg.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <linux/utsname.h>
#include <linux/jiffies.h>
#include <linux/tboot.h>
#include <linux/version.h>
#include <linux/kfifo.h>
#include <asm/pgalloc.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif
/*--------------------*/
#include "holdup_main.h"
#include "mmu.h"
#include "dma.h"
#include "symbol.h"
#include "asm_implementation.h"
#include "monitor.h"

//NIce support for old kernel versions
/*

x86 Debug Registers

DR0 - Linear breakpoint address 0
DR1 - Linear breakpoint address 1
DR2 - Linear breakpoint address 2
DR3 - Linear breakpoint address 3

DR4 - Reserved. Not defined by Intel

DR5 - Reserved. Not defined by Intel

DR6 - Breakpoint Status

DR7 - Breakpoint control
*/
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
u64 page_offset_base = 0xffff880000000000;
#endif

#ifndef GFP_KERNEL_ACCOUNT
#define GFP_KERNEL_ACCOUNT GFP_KERNEL
#endif

#ifndef PGD_ALLOCATION_ORDER
#define PGD_ALLOCATION_ORDER 1
#endif

int global_ro_array_count = 0;
struct ro_addr_struct global_ro_array[MAX_RO_ARRAY_COUNT];
u64 global_max_ram_size = 0;
struct memory_pool global_memory_pool = {
	0,
};
atomic_t global_is_shutdown_trigger_set = {
	0,
};
volatile u64 global_shutdown_jiffies = 0;
struct share_context *global_share_context = NULL;
static volatile u64 g_first_flag[MAX_PROCESSOR_COUNT] = {
	0,
};

static spinlock_t global_memory_pool_lock;
struct workaround global_workaround = {{
										   0,
									   },
									   {
										   0,
									   }};

/* Variables for kernel objects to be checked periodically */
struct list_head *global_modules_ptr = NULL;
struct file *global_root_file_ptr = NULL;
struct file *global_proc_file_ptr = NULL;
struct socket *global_tcp_sock = NULL;
struct file *global_tcp_file_ptr = NULL;
struct file *global_tcp6_file_ptr = NULL;
struct socket *global_udp_sock = NULL;
struct file *global_udp_file_ptr = NULL;
struct file *global_udp6_file_ptr = NULL;
rwlock_t *global_tasklist_lock;

/* Variables for multi-core. */
struct task_struct *global_vm_start_thread_id[MAX_PROCESSOR_COUNT] = {
	NULL,
};
int global_thread_result = 0;
struct task_struct *global_vm_shutdown_thread_id[MAX_PROCESSOR_COUNT] = {
	NULL,
};
struct desc_ptr global_gdtr_array[MAX_PROCESSOR_COUNT];

void *global_guest_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {
	NULL,
};
void *global_vmx_on_vmcs_log_addr[MAX_PROCESSOR_COUNT] = {
	NULL,
};

void *global_vm_exit_stack_addr[MAX_PROCESSOR_COUNT] = {
	NULL,
};
void *global_io_bitmap_addrA[MAX_PROCESSOR_COUNT] = {
	NULL,
};
void *global_io_bitmap_addrB[MAX_PROCESSOR_COUNT] = {
	NULL,
};
void *global_msr_bitmap_addr[MAX_PROCESSOR_COUNT] = {
	NULL,
};
int global_trap_count[MAX_PROCESSOR_COUNT] = {
	0,
};
void *global_virt_apic_page_addr[MAX_PROCESSOR_COUNT] = {
	NULL,
};
int global_vmx_root_mode[MAX_PROCESSOR_COUNT] = {
	0,
};

u64 global_stack_size = MAX_STACK_SIZE;
u64 global_vm_host_phy_p4 = 0;
u64 global_vm_init_phy_p4 = 0;
struct module *global_holdup_module = THIS_MODULE;
static int global_support_smx = 0;
static int global_support_xsave = 0;

atomic_t global_need_init_in_secure = {1};
volatile int global_allow_module_hide = 0;
volatile u64 global_init_in_secure_jiffies = 0;
atomic_t global_thread_run_flags;
atomic_t global_thread_entry_count;
atomic_t global_sync_flags;
atomic_t global_complete_flags;
atomic_t global_framework_init_start_flags;
atomic_t global_enter_flags;
atomic_t global_enter_count;
atomic_t global_first;
atomic_t global_framework_init_flags;
atomic_t global_iommu_complete_flags;
atomic_t global_mutex_lock_flags;
u64 global_vm_pri_proc_based_ctrl_default = 0;

static u64 global_create_task;
static u64 global_delete_task;
#if ENABLED_STAROZA
static u64 global_syscall_64;
static u64 global_commit_creds;
#else
static u64 global_create_module;
static u64 global_delete_module;
#endif
///////////////////////////////////////////////////

static int get_kernel_version_index(void);
static void disable_desc_monitor(void);
static u64 get_value_from_memory(u64 inst_info, u64 addr);
void hide_module(void);
static u64 calc_vm_pre_timer_value(void);
static u64 calc_dest_mem_addr(struct vm_exit_guest_register *guest_context, u64 inst_info);
static void duplicate_page_table(void);

static int is_kaslr_working(void);
static int relocate_symbol(void);

static void alloc_vmcs_memory(void);
void *allocate_memory(void);

static int setup_memory_pool(void);
static void setup_vmcs(const struct vm_host_register *pstVMHost, const struct vm_guest_register *pstVMGuest, const struct vm_control_register *pstVMControl);
static int init_vmx(int cpu_id);
static void get_object_pointers(void);

#if ENABLED_EPT
static void lock_range(u64 start_addr, u64 end_addr, int alloc_type);
#endif
static void add_and_protect_module_ro(struct module *mod);


#if ENABLED_EPT
static void protect_this_module(void);
static void protect_vmcs(void);
#endif
static void protect_module_list_ro_area(void);
static void protect_kernel_ro_area(void);
static void protect_gdt(int cpu_id);
static int check_gdtr(int cpu_id);

static void setup_vm_control_register(struct vm_control_register *vm_control_register, int cpu_id);
static void setup_vm_host_register(struct vm_host_register *vm_host_register);
static void setup_vm_guest_register(struct vm_guest_register *guest_register, const struct vm_host_register *host_register);
static void dump_vm_host_register(struct vm_host_register *host_register);
static void dump_vm_guest_register(struct vm_guest_register *guest_register);
static void dump_vm_control_register(struct vm_control_register *control_register);
static void vm_set_msr_write_bitmap(struct vm_control_register *vm_control_register, u64 msr_number);
static u64 get_desc_access(u64 offset);

static int vm_thread(void *argument);
static void disable_and_change_machine_check_timer(void);
static void setup_workaround(void);

//////////////////////////////////////////
void vm_resume_fail_callback(u64 error);
static void vm_exit_callback_vmcall(int cpu_id, struct vm_exit_guest_register *guest_context);
void vm_exit_callback(struct vm_exit_guest_register *guest_context);
static int is_shutdown_timer_expired(void);
static int is_system_shutting_down(void);
static void trigger_shutdown_timer(void);
static void advance_vm_guest_rip(void);
static void vm_exit_callback_access_cr(int cpu_id, struct vm_exit_guest_register *guest_context, u64 exit_reason, u64 exit_qual);
static void set_reg_value_from_index(struct vm_exit_guest_register *guest_context, int index, u64 reg_value);
static u64 get_reg_value_from_index(struct vm_exit_guest_register *guest_context, int index);
static void vm_exit_callback_wrmsr(int cpu_id);
static void vm_exit_callback_ept_violation(int cpu_id, struct vm_exit_guest_register *guest_context, u64 exit_reason, u64 exit_qual, u64 guest_linear, u64 guest_physical);
static int is_workaround_addr(u64 addr);
static void vm_exit_callback_ldtr_tr(int cpu_id, struct vm_exit_guest_register *guest_context);
static void set_value_to_memory(u64 inst_info, u64 addr, u64 value);
static void vm_exit_callback_gdtr_idtr(int cpu_id, struct vm_exit_guest_register *guest_context);
static void vm_exit_callback_pre_timer_expired(int cpu_id);
static void remove_int_exception_from_vm(int vector);
static void sync_page_table_flag(struct pagetable *vm, struct pagetable *init, int index, u64 addr);
int vm_is_same_page_table_flag_or_size_flag_set(struct pagetable *vm, struct pagetable *init, int index);
int vm_is_new_page_table_needed(struct pagetable *vm, struct pagetable *init, int index);
void get_phy_from_log(u64 p4_phy_addr, u64 addr, struct vm_page_entry *out_data);
static void vm_exit_callback_int(int cpu_id, unsigned long dr6, struct vm_exit_guest_register *guest_context);
static void vm_exit_callback_init_signal(int cpu_id);
u64 vm_check_alloc_page_table(struct pagetable *pagetable, int index);
void vm_expand_page_table_entry(u64 phy_table_addr, u64 start_entry_and_flags, u64 entry_size, u64 dummy);
int is_addr_in_kernel_ro_area(void *addr);
static void vm_exit_callback_start_up_signal(int cpu_id);
static void vm_exit_callback_cpuid(struct vm_exit_guest_register *guest_context);
static void vm_exit_callback_invd(void);

static u64 custom_get_desc_base(u64 offset);
static unsigned long custom_encode_dr7(int index, unsigned int len, unsigned int type);
static void not_print_vm_result(const char *string, int result);
static void print_dogo(void);

static void init_breakpoint_address(void);

#if ENABLED_STAROZA
static void set_syscall_monitor_mode(int cpu_id);
static void handle_syscall_breakpoints(int cpu_id, u64 dr6, struct vm_exit_guest_register *guest_context);
#else
static void set_process_module_monitor_mode(int cpu_id);
static void handle_process_and_module_breakpoints(int cpu_id, u64 dr6, struct vm_exit_guest_register* guest_context);
#endif
static void disable_breakpoints(void);
static void enable_breakpoints(void);
/* ******************************************************** */

int __init holdup_init(void)
{
	int i, cpu_count, cpu_id;
	struct new_utsname *name;
	u32 eax, ebx, ecx, edx;

	print_dogo();

	/* Checking if the running kernel version matching the kernel in the symbol.h file */
	if (get_kernel_version_index() == -1)
	{
		name = utsname();
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "Kernel version is not supported, [%s]", name->version);
		error_log(ERROR_KERNEL_VERSION_MISMATCH);
		return -1;
	}

	if (is_kaslr_working() == 1)
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Kernel ASLR is enabled\n");
		relocate_symbol();
	}

	cpuid_count(1, 0, &eax, &ebx, &ecx, &edx);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Initialize VMX\n");
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Check virtualization, %08X, %08X, %08X, %08X\n", eax, ebx, ecx, edx);

	/* Checking VMX, SMX, XSAVES features availability using information on [CPUID 0X1] instruction from intel manual Vol 2. Ch 3. Tables 3-8, 3-10 
	* https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf */
	if (ecx & CPUID_1_ECX_VMX)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMX support\n");
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VMX not support\n");
		error_log(ERROR_HW_NOT_SUPPORT);
		return -1;
	}

	if (ecx & CPUID_1_ECX_SMX)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] SMX support\n");
		global_support_smx = 1;
	}
	else
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_ERROR "    [*] SMX not support\n");
	}

	cpuid_count(0x0D, 1, &eax, &ebx, &ecx, &edx);

	if (eax & CPUID_D_EAX_XSAVES)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES support\n");
		global_support_xsave = 1;
	}
	else
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] XSAVES/XRSTORES not support\n");
	}

	global_max_ram_size = get_max_ram_size();
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "totalram_pages %ld, size %ld, global_max_ram_size %ld\n", totalram_pages, totalram_pages * S_4KB, global_max_ram_size);
	if (global_max_ram_size < S_4GB)
	{
		global_max_ram_size = S_4GB;
	}
	else
	{
		global_max_ram_size = global_max_ram_size + S_1GB;
	}
	cpu_id = smp_processor_id();
	cpu_count = num_online_cpus();

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "CPU Count %d\n", cpu_count);
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Booting CPU ID %d\n", cpu_id);

	get_object_pointers();
	alloc_vmcs_memory();

#if ENABLED_EPT
	if (alloc_ept_pages() != 0)
	{
		error_log(ERROR_MEMORY_ALLOC_FAIL);
		goto ERROR_HANDLE;
	}
	setup_ept_pagetable_4KB();
#endif

#if ENABLED_IOMMU
	if (alloc_iommu_pages() != 0)
	{
		error_log(ERROR_MEMORY_ALLOC_FAIL);
		goto ERROR_HANDLE;
	}
	setup_iommu_pagetable_4KB();
#endif

	protect_kernel_ro_area();

#if ENABLED_EPT
	protect_ept_pages();
	protect_vmcs();
#endif

#if ENABLED_IOMMU
	protect_iommu_pages();
#endif

#if ENABLED_HW_BREAKPOINT
	init_breakpoint_address();
#endif
	if (prepare_security_monitor() != 0)
	{
		error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	setup_workaround();

	if (setup_memory_pool() != 0)
	{
		error_log(ERROR_MEMORY_ALLOC_FAIL);
		return -1;
	}

	global_tasklist_lock = (rwlock_t *)get_symbol_address("tasklist_lock");

	atomic_set(&global_thread_run_flags, cpu_count);
	atomic_set(&global_thread_entry_count, cpu_count);
	atomic_set(&global_sync_flags, cpu_count);
	atomic_set(&global_complete_flags, cpu_count);
	atomic_set(&global_framework_init_start_flags, cpu_count);
	atomic_set(&global_first, 1);
	atomic_set(&global_enter_flags, 0);
	atomic_set(&global_enter_count, 0);
	atomic_set(&global_framework_init_flags, cpu_count);
	atomic_set(&global_iommu_complete_flags, 0);
	atomic_set(&(global_mutex_lock_flags), 0);

	for (i = 0; i < cpu_count; i++)
	{
		global_vm_start_thread_id[i] = (struct task_struct *)kthread_create_on_node(vm_thread, NULL, cpu_to_node(i), "vm_thread");
		if (global_vm_start_thread_id[i] != NULL)
		{
			kthread_bind(global_vm_start_thread_id[i], i);
		}
		else
		{
			not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Thread run fail\n", i);
		}
	}

	for (i = 0; i < cpu_count; i++)
	{
		if (i != cpu_id)
		{
			wake_up_process(global_vm_start_thread_id[i]);
			not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", i);
		}
	}

	wake_up_process(global_vm_start_thread_id[cpu_id]);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Thread Run Success\n", cpu_id);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Waiting for complete\n", i);

	while (atomic_read(&global_complete_flags) > 0)
	{
		msleep(100);
	}

	if (global_thread_result != 0)
	{
		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail\n");
		return -1;
	}

	mutex_lock(&module_mutex);
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	mutex_unlock(&module_mutex);

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Complete\n");
	error_log(ERROR_SUCCESS);

	/* Set hide flag and time. */
	global_init_in_secure_jiffies = jiffies;
	global_allow_module_hide = 1;

	return 0;

ERROR_HANDLE:
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Execution Fail\n");

	free_ept_pages();
	free_iommu_pages();
	return -1;
}

void __exit holdup_exit(void)
{
	int cpu_id;

	cpu_id = smp_processor_id();
	print_dogo();
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VMX [%d] Stop HOLDUP\n", cpu_id);
}

static void print_dogo(void)
{
	printk(KERN_ALERT "         ▄              ▄\n");
	printk(KERN_ALERT "        ▌▒█           ▄▀▒▌\n");
	printk(KERN_ALERT "        ▌▒▒█        ▄▀▒▒▒▐\n");
	printk(KERN_ALERT "       ▐▄▀▒▒▀▀▀▀▄▄▄▀▒▒▒▒▒▐\n");
	printk(KERN_ALERT "     ▄▄▀▒░▒▒▒▒▒▒▒▒▒█▒▒▄█▒▐\n");
	printk(KERN_ALERT "   ▄▀▒▒▒░░░▒▒▒░░░▒▒▒▀██▀▒▌\n");
	printk(KERN_ALERT "  ▐▒▒▒▄▄▒▒▒▒░░░▒▒▒▒▒▒▒▀▄▒▒▌\n");
	printk(KERN_ALERT "  ▌░░▌█▀▒▒▒▒▒▄▀█▄▒▒▒▒▒▒▒█▒▐\n");
	printk(KERN_ALERT " ▐░░░▒▒▒▒▒▒▒▒▌██▀▒▒░░░▒▒▒▀▄▌\n");
	printk(KERN_ALERT " ▌░▒▄██▄▒▒▒▒▒▒▒▒▒░░░░░░▒▒▒▒▌\n");
	printk(KERN_ALERT "▌▒▀▐▄█▄█▌▄░▀▒▒░░░░░░░░░░▒▒▒▐\n");
	printk(KERN_ALERT "▐▒▒▐▀▐▀▒░▄▄▒▄▒▒▒▒▒▒░▒░▒░▒▒▒▒▌\n");
	printk(KERN_ALERT "▐▒▒▒▀▀▄▄▒▒▒▄▒▒▒▒▒▒▒▒░▒░▒░▒▒▐\n");
	printk(KERN_ALERT " ▌▒▒▒▒▒▒▀▀▀▒▒▒▒▒▒░▒░▒░▒░▒▒▒▌\n");
	printk(KERN_ALERT " ▐▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▒▄▒▒▐\n");
	printk(KERN_ALERT "  ▀▄▒▒▒▒▒▒▒▒▒▒▒░▒░▒░▒▄▒▒▒▒▌\n");
	printk(KERN_ALERT "    ▀▄▒▒▒▒▒▒▒▒▒▒▄▄▄▀▒▒▒▒▄▀\n");
	printk(KERN_ALERT "      ▀▄▄▄▄▄▄▀▀▀▒▒▒▒▒▄▄▀\n");
	printk(KERN_ALERT "         ▒▒▒▒▒▒▒▒▒▒▀▀\n");
}

#pragma region SETUP_VM
/********************** START SETUP CONTEXT **********************/

static void setup_vm_host_register(struct vm_host_register *vm_host_register)
{
	struct desc_ptr gdtr, idtr;
	struct desc_struct *gdt;
	struct ldttss_desc64 *tss;
	u64 base0 = 0, base1 = 0, base2 = 0, base3 = 0;

	int i;
	char *vm_exit_stack;
	u64 stack_size = global_stack_size;
	int cpu_id;

	cpu_id = smp_processor_id();

	// Allocate kernel stack for VM exit
	vm_exit_stack = (char *)(global_vm_exit_stack_addr[cpu_id]);
	memset(vm_exit_stack, 0, stack_size);

	native_store_gdt(&gdtr);
	native_store_idt(&idtr);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Host Register\n", cpu_id);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Address %016lX\n", gdtr.address);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDTR Size %d\n", gdtr.size);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Address %016lX\n", idtr.address);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IDTR Size %d\n", idtr.size);

	for (i = 0; i < (gdtr.size + 7) / 8; i++)
	{
		gdt = (struct desc_struct *)(gdtr.address + i * 8);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT Index %d\n", i);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] GDT High %08X, Low %08X\n", gdt->b, gdt->a);
	}

	vm_host_register->cr0 = get_cr0();

	// Using Shadow CR3 for separation
	vm_host_register->cr3 = global_vm_host_phy_p4;
	vm_host_register->cr4 = get_cr4();

	vm_host_register->rsp = (u64)vm_exit_stack + stack_size - 0x1000;
	vm_host_register->rip = (u64)vm_exit_callback_stub;

	vm_host_register->cs_selector = __KERNEL_CS;
	vm_host_register->ss_selector = __KERNEL_DS;
	vm_host_register->ds_selector = __KERNEL_DS;
	vm_host_register->es_selector = __KERNEL_DS;
	vm_host_register->fs_selector = __KERNEL_DS;
	vm_host_register->gs_selector = __KERNEL_DS;
	vm_host_register->tr_selector = get_tr();

	vm_host_register->fs_base_addr = cu_read_msr(MSR_FS_BASE_ADDR);
	vm_host_register->gs_base_addr = cu_read_msr(MSR_GS_BASE_ADDR);

	tss = (struct ldttss_desc64 *)(gdtr.address + (vm_host_register->tr_selector & ~MASK_GDT_ACCESS));
	base0 = tss->base0;
	base1 = tss->base1;
	base2 = tss->base2;
	base3 = tss->base3;
	vm_host_register->tr_base_addr = base0 | (base1 << 16) | (base2 << 24) | (base3 << 32);

	vm_host_register->gdtr_base_addr = gdtr.address;
	vm_host_register->idtr_base_addr = idtr.address;

	vm_host_register->ia32_sys_enter_cs = cu_read_msr(MSR_IA32_SYSENTER_CS);
	vm_host_register->ia32_sys_enter_esp = cu_read_msr(MSR_IA32_SYSENTER_ESP);
	vm_host_register->ia32_sys_enter_eip = cu_read_msr(MSR_IA32_SYSENTER_EIP);

	vm_host_register->ia32_perf_global_ctrl = cu_read_msr(MSR_IA32_PERF_GLOBAL_CTRL);
	vm_host_register->ia32_pat = cu_read_msr(MSR_IA32_PAT);
	vm_host_register->ia32_efer = cu_read_msr(MSR_IA32_EFER);

	dump_vm_host_register(vm_host_register);
}

static void dump_vm_host_register(struct vm_host_register *host_register)
{
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Host Register\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", host_register->cr0);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", host_register->cr3);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", host_register->cr4);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", host_register->rsp);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", host_register->rip);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n", host_register->cs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n", host_register->ss_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n", host_register->ds_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n", host_register->es_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n", host_register->fs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n", host_register->gs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n", host_register->tr_selector);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n", host_register->fs_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n", host_register->gs_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n", host_register->tr_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n", host_register->gdtr_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n", host_register->idtr_base_addr);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n", host_register->ia32_sys_enter_cs);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n", host_register->ia32_sys_enter_esp);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n", host_register->ia32_sys_enter_eip);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n", host_register->ia32_perf_global_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n", host_register->ia32_pat);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n", host_register->ia32_efer);
}

static void setup_vm_guest_register(struct vm_guest_register *vm_guest_register, const struct vm_host_register *vm_host_register)
{
	struct desc_ptr gdtr, idtr;
	struct desc_struct *gdt;
	struct ldttss_desc64 *ldt, *tss;

	u64 base0 = 0, base1 = 0, base2 = 0, base3 = 0, access = 0, qwLimit0 = 0, qwLimit1 = 0;
	int cpu_id;
	unsigned long dr7 = 0;

#if ENABLED_HW_BREAKPOINT
	unsigned long dr6;
#endif

	cpu_id = smp_processor_id();
	native_store_gdt(&gdtr);
	native_store_idt(&idtr);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup Guest Register\n", cpu_id);

	vm_guest_register->cr0 = vm_host_register->cr0;
	vm_guest_register->cr3 = get_cr3();
	vm_guest_register->cr4 = vm_host_register->cr4;

#if ENABLED_HW_BREAKPOINT
#if !ENABLED_STAROZA
	set_process_module_monitor_mode(cpu_id);
#else
	set_syscall_monitor_mode(cpu_id);
#endif

	dr7 = custom_encode_dr7(0, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(1, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(2, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(3, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= (0x01 << 10);

	vm_guest_register->dr7 = dr7;
	get_debugreg(dr6, 6);
	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);
#else
	vm_guest_register->dr7 = get_dr7();
#endif
	get_debugreg(dr7, 6);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB6 = %lx", dr7);
	get_debugreg(dr7, 7);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "ORG DB7 = %lx", vm_guest_register->dr7);

	vm_guest_register->rflags = get_rflags();
	// Under two registers are set when VM launch
	vm_guest_register->rsp = 0xFFFFFFFFFFFFFFFF;
	vm_guest_register->rip = 0xFFFFFFFFFFFFFFFF;

	vm_guest_register->cs_selector = get_cs();
	vm_guest_register->ss_selector = get_ss();
	vm_guest_register->ds_selector = hu_get_ds();
	vm_guest_register->es_selector = get_es();
	vm_guest_register->fs_selector = hu_get_fs();
	vm_guest_register->gs_selector = get_gs();
	vm_guest_register->ldtr_selector = get_ldtr();
	vm_guest_register->tr_selector = get_tr();

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "LDTR Selector %08X\n", (u32)vm_guest_register->ldtr_selector);

	vm_guest_register->cs_base_addr = custom_get_desc_base(vm_guest_register->cs_selector);
	vm_guest_register->ss_base_addr = custom_get_desc_base(vm_guest_register->ss_selector);
	vm_guest_register->ds_base_addr = custom_get_desc_base(vm_guest_register->ds_selector);
	vm_guest_register->es_base_addr = custom_get_desc_base(vm_guest_register->es_selector);
	vm_guest_register->fs_base_addr = cu_read_msr(MSR_FS_BASE_ADDR);
	vm_guest_register->gs_base_addr = cu_read_msr(MSR_GS_BASE_ADDR);

	if (vm_guest_register->ldtr_selector == 0)
	{
		vm_guest_register->ldtr_base_addr = 0;
	}
	else
	{
		ldt = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		base0 = ldt->base0;
		base1 = ldt->base1;
		base2 = ldt->base2;
		base3 = ldt->base3;
		vm_guest_register->ldtr_base_addr = base0 | (base1 << 16) | (base2 << 24) | (base3 << 32);
	}

	if (vm_guest_register->tr_selector == 0)
	{
		vm_guest_register->tr_base_addr = 0x00;
	}
	else
	{
		tss = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		base0 = tss->base0;
		base1 = tss->base1;
		base2 = tss->base2;
		base3 = tss->base3;
		vm_guest_register->tr_base_addr = base0 | (base1 << 16) | (base2 << 24) | (base3 << 32);
	}

	vm_guest_register->cs_limit = 0xFFFFFFFF;
	vm_guest_register->ss_limit = 0xFFFFFFFF;
	vm_guest_register->ds_limit = 0xFFFFFFFF;
	vm_guest_register->es_limit = 0xFFFFFFFF;
	vm_guest_register->fs_limit = 0xFFFFFFFF;
	vm_guest_register->gs_limit = 0xFFFFFFFF;

	if (vm_guest_register->ldtr_selector == 0)
	{
		vm_guest_register->ldtr_limit = 0;
	}
	else
	{
		ldt = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = ldt->limit0;
		qwLimit1 = ldt->limit1;
		vm_guest_register->ldtr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	if (vm_guest_register->tr_selector == 0)
	{
		vm_guest_register->tr_limit = 0;
	}
	else
	{
		tss = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		qwLimit0 = tss->limit0;
		qwLimit1 = tss->limit1;
		vm_guest_register->tr_limit = qwLimit0 | (qwLimit1 << 16);
	}

	vm_guest_register->cs_access = get_desc_access(vm_guest_register->cs_selector);
	vm_guest_register->ss_access = get_desc_access(vm_guest_register->ss_selector);
	vm_guest_register->ds_access = get_desc_access(vm_guest_register->ds_selector);
	vm_guest_register->es_access = get_desc_access(vm_guest_register->es_selector);
	vm_guest_register->fs_access = get_desc_access(vm_guest_register->fs_selector);
	vm_guest_register->gs_access = get_desc_access(vm_guest_register->gs_selector);

	if (vm_guest_register->ldtr_selector == 0)
	{
		vm_guest_register->ldtr_access = 0x10000;
	}
	else
	{
		ldt = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->ldtr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct *)ldt;
		access = gdt->b >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		vm_guest_register->ldtr_access = access & 0xF0FF;
	}

	if (vm_guest_register->tr_selector == 0)
	{
		vm_guest_register->tr_access = 0;
	}
	else
	{
		tss = (struct ldttss_desc64 *)(gdtr.address + (vm_guest_register->tr_selector & ~MASK_GDT_ACCESS));
		gdt = (struct desc_struct *)tss;
		access = gdt->b >> 8;

		/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
		vm_guest_register->tr_access = access & 0xF0FF;
	}

	vm_guest_register->gdtr_base_addr = vm_host_register->gdtr_base_addr;
	vm_guest_register->idtr_base_addr = vm_host_register->idtr_base_addr;
	vm_guest_register->gdtr_limit = gdtr.size;
	vm_guest_register->idtr_limit = idtr.size;

	vm_guest_register->ia32_debug_ctrl = 0;
	vm_guest_register->ia32_sys_enter_cs = vm_host_register->ia32_sys_enter_cs;
	vm_guest_register->ia32_sys_enter_esp = vm_host_register->ia32_sys_enter_esp;
	vm_guest_register->ia32_sys_enter_eip = vm_host_register->ia32_sys_enter_eip;
	vm_guest_register->vmcs_link_ptr = 0xFFFFFFFFFFFFFFFF;

	vm_guest_register->ia32_perf_global_ctrl = vm_host_register->ia32_perf_global_ctrl;
	vm_guest_register->ia32_pat = vm_host_register->ia32_pat;
	vm_guest_register->ia32_efer = vm_host_register->ia32_efer;

	dump_vm_guest_register(vm_guest_register);
}

static void dump_vm_guest_register(struct vm_guest_register *guest_register)
{
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Guest Register\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR0 %016lX\n", guest_register->cr0);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR3 %016lX\n", guest_register->cr3);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CR4 %016lX\n", guest_register->cr4);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DR7 %016lX\n", guest_register->dr7);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RSP %016lX\n", guest_register->rsp);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RIP %016lX\n", guest_register->rip);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] RFLAGS %016lX\n", guest_register->rflags);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Selector %08X\n", (u32)guest_register->cs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Selector %08X\n", (u32)guest_register->ss_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Selector %08X\n", (u32)guest_register->ds_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Selector %08X\n", (u32)guest_register->es_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Selector %08X\n", (u32)guest_register->fs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Selector %08X\n", (u32)guest_register->gs_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Selector %08X\n", (u32)guest_register->ldtr_selector);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Selector %08X\n", (u32)guest_register->tr_selector);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Base     %016lX\n", guest_register->cs_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Base     %016lX\n", guest_register->ss_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Base     %016lX\n", guest_register->ds_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Base     %016lX\n", guest_register->es_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Base     %016lX\n", guest_register->fs_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Base     %016lX\n", guest_register->gs_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Base   %016lX\n", guest_register->ldtr_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Base     %016lX\n", guest_register->tr_base_addr);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Limit    %08X\n", (u32)guest_register->cs_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Limit    %08X\n", (u32)guest_register->ss_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Limit    %08X\n", (u32)guest_register->ds_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Limit    %08X\n", (u32)guest_register->es_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Limit    %08X\n", (u32)guest_register->fs_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Limit    %08X\n", (u32)guest_register->gs_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Limit  %08X\n", (u32)guest_register->ldtr_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Limit    %08X\n", (u32)guest_register->tr_limit);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] CS Access   %08X\n", (u32)guest_register->cs_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] SS Access   %08X\n", (u32)guest_register->ss_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] DS Access   %08X\n", (u32)guest_register->ds_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] ES Access   %08X\n", (u32)guest_register->es_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] FS Access   %08X\n", (u32)guest_register->fs_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GS Access   %08X\n", (u32)guest_register->gs_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] LDTR Access %08X\n", (u32)guest_register->ldtr_access);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] TR Access   %08X\n", (u32)guest_register->tr_access);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Base   %016lX\n", guest_register->gdtr_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Base   %016lX\n", guest_register->idtr_base_addr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] GDTR Limit  %08X\n", (u32)guest_register->gdtr_limit);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IDTR Limit  %08X\n", (u32)guest_register->idtr_limit);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 DEBUG CTRL   %016lX\n", guest_register->ia32_debug_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER CS  %016lX\n", guest_register->ia32_sys_enter_cs);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER ESP %016lX\n", guest_register->ia32_sys_enter_esp);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 SYSENTER EIP %016lX\n", guest_register->ia32_sys_enter_eip);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VCMS Link Ptr     %016lX\n", guest_register->vmcs_link_ptr);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 Perf Global Ctrl %016lX\n", guest_register->ia32_perf_global_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 PAT              %016lX\n", guest_register->ia32_pat);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IA32 IA32 EFER        %016lX\n", guest_register->ia32_efer);
}

static void setup_vm_control_register(struct vm_control_register *vm_control_register, int cpu_id)
{
	u64 sec_flags = 0;
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VM Control Register\n", cpu_id);

#if ENABLED_DESC_TABLE
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE;
#endif

#if ENABLED_EPT
#if ENABLED_UNRESTRICTED
	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_UNREST_GUEST;
#endif

	sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_USE_EPT;
#endif
	if ((cu_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) & VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID)
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable INVPCID\n", cpu_id);
		sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID;
	}

	if (global_support_xsave == 1)
	{
		if ((cu_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) & VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE)
		{
			not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Support Enable XSAVE\n", cpu_id);
			sec_flags |= VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE;
		}
	}

#if ENABLED_PRE_TIMER
	vm_control_register->pin_based_ctrl = (cu_read_msr(MSR_IA32_VMX_TRUE_PINBASED_CTLS) | VM_BIT_VM_PIN_BASED_USE_PRE_TIMER) & 0xFFFFFFFF;
#else
	vm_control_register->pin_based_ctrl = (cu_read_msr(MSR_IA32_VMX_TRUE_PINBASED_CTLS)) & 0xFFFFFFFF;
#endif

	vm_control_register->pri_proc_based_ctrl = (cu_read_msr(MSR_IA32_VMX_TRUE_PROCBASED_CTLS) |
												VM_BIT_VM_PRI_PROC_CTRL_USE_IO_BITMAP |
												VM_BIT_VM_PRI_PROC_CTRL_USE_MSR_BITMAP |
												VM_BIT_VM_PRI_PROC_CTRL_USE_SEC_CTRL |
												VM_BIT_VM_PRI_PROC_CTRL_USE_MOVE_DR) &
											   0xFFFFFFFF;

	global_vm_pri_proc_based_ctrl_default = vm_control_register->pri_proc_based_ctrl;
	vm_control_register->sec_proc_based_ctrl = (cu_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2) | sec_flags) & 0xFFFFFFFF;

	vm_control_register->vm_entry_ctrl_field = (cu_read_msr(MSR_IA32_VMX_TRUE_ENTRY_CTRLS) |
												VM_BIT_VM_ENTRY_CTRL_IA32E_MODE_GUEST |
												VM_BIT_VM_ENTRY_LOAD_DEBUG_CTRL) &
											   0xFFFFFFFF;

#if ENABLED_PRE_TIMER
	vm_control_register->vm_exti_ctrl_field = (cu_read_msr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) | VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE |
											   VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
											   VM_BIT_VM_EXIT_CTRL_SAVE_PRE_TIMER |
											   VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) &
											  0xFFFFFFFF;
#else
	vm_control_register->vm_exti_ctrl_field = (cu_read_msr(MSR_IA32_VMX_TRUE_EXIT_CTRLS) |
											   VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE | VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL |
											   VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER) &
											  0xFFFFFFFF;
#endif

#if ENABLED_HW_BREAKPOINT
	vm_control_register->except_bitmap = ((u64)0x01 << VM_INT_DEBUG_EXCEPTION);
#else
	vm_control_register->except_bitmap = 0x00;
#endif

	vm_control_register->io_bitmap_addrA = (u64)(global_io_bitmap_addrA[cpu_id]);
	vm_control_register->io_bitmap_addrB = (u64)(global_io_bitmap_addrB[cpu_id]);
	vm_control_register->msr_bitmap_addr = (u64)(global_msr_bitmap_addr[cpu_id]);
	vm_control_register->virt_apic_page_addr = (u64)(global_virt_apic_page_addr[cpu_id]);

	memset((char *)vm_control_register->io_bitmap_addrA, 0, 0x1000);
	memset((char *)vm_control_register->io_bitmap_addrB, 0, 0x1000);
	memset((char *)vm_control_register->msr_bitmap_addr, 0, 0x1000);
	memset((char *)vm_control_register->virt_apic_page_addr, 0, 0x1000);

	// Registers related SYSENTER, SYSCALL MSR are write-protected
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_SYSENTER_CS);
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_SYSENTER_ESP);
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_SYSENTER_EIP);
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_STAR);
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_LSTAR);
	vm_set_msr_write_bitmap(vm_control_register, MSR_IA32_FMASK);

	vm_control_register->io_bitmap_addrA = (u64)virt_to_phys((void *)vm_control_register->io_bitmap_addrA);
	vm_control_register->io_bitmap_addrB = (u64)virt_to_phys((void *)vm_control_register->io_bitmap_addrB);
	vm_control_register->msr_bitmap_addr = (u64)virt_to_phys((void *)vm_control_register->msr_bitmap_addr);
	vm_control_register->virt_apic_page_addr = (u64)virt_to_phys((void *)vm_control_register->virt_apic_page_addr);
#if ENABLED_EPT
	vm_control_register->ept_ptr = (u64)virt_to_phys((void *)global_ept_data.p4_page_addr_array[0]) | VM_BIT_EPT_PAGE_WALK_LENGTH_BITMAP | VM_BIT_EPT_MEM_TYPE_WB;
#endif
	vm_control_register->cr4_guest_host_mask = CR4_BIT_VMXE;
	vm_control_register->cr4_read_shadow = CR4_BIT_VMXE;

	dump_vm_control_register(vm_control_register);
}

static void dump_vm_control_register(struct vm_control_register *control_register)
{
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Dump Control Register\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Pin Based Ctrl %016lX\n", control_register->pin_based_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Primary Process Based Ctrl %016lX\n", control_register->pri_proc_based_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Secondary Process Based Ctrl %016lX\n", control_register->sec_proc_based_ctrl);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Entry Ctrl %016lX\n", control_register->vm_entry_ctrl_field);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM Exit Ctrl %016lX\n", control_register->vm_exti_ctrl_field);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Exception Bitmap %016lX\n", control_register->except_bitmap);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrA %016lX\n", control_register->io_bitmap_addrA);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IO Bitmap AddrB %016lX\n", control_register->io_bitmap_addrB);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Pointer %016lX\n", control_register->ept_ptr);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] MSRBitmap %016lX\n", control_register->msr_bitmap_addr);
}
/********************** END SETUP CONTEXT **********************/
#pragma endregion

#pragma region CALLBACKS

void vm_resume_fail_callback(u64 error)
{
	u64 value, value2, value3;

	read_vmcs(VM_GUEST_EFER, &value);
	read_vmcs(VM_CTRL_VM_ENTRY_CTRLS, &value2);
	read_vmcs(VM_GUEST_CR0, &value3);

	if (value & EFER_BIT_LME)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM is in 64bit mode, %016lX, %016lX, %016lX\n", value, value2, value3);
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM is not in 64bit mode, %016lX, %016lX, %016lX\n", value, value2, value3);
	}

	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM_RESUME fail %d\n", error);
	error_log(ERROR_LAUNCH_FAIL);
}

void vm_exit_callback(struct vm_exit_guest_register *guest_context)
{
	u64 exit_reason, exit_qual, guest_linear, guest_physical, info_field;
	int cpu_id;

	cpu_id = smp_processor_id();

	global_vmx_root_mode[cpu_id] = 1;

	read_vmcs(VM_DATA_EXIT_REASON, &exit_reason);
	read_vmcs(VM_DATA_EXIT_QUALIFICATION, &exit_qual);
	read_vmcs(VM_DATA_GUEST_LINEAR_ADDR, &guest_linear);
	read_vmcs(VM_DATA_GUEST_PHY_ADDR, &guest_physical);

	read_vmcs(VM_DATA_VM_EXIT_INT_INFO, &info_field);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] EXIT Reason field: %016lX\n", cpu_id, exit_reason);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] EXIT Interrupt Info field: %016lX\n", cpu_id, info_field);

	trigger_shutdown_timer();
	is_shutdown_timer_expired();

	write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);

	if ((global_allow_module_hide == 1) &&
		((jiffies_to_msecs(jiffies - global_init_in_secure_jiffies) >= HIDE_TIME_BUFFER_MS)))
	{
		if (atomic_cmpxchg(&global_need_init_in_secure, 1, 0))
		{
#if ENABLED_EPT
			protect_this_module();
			protect_monitor();
#endif
			global_allow_module_hide = 0;
		}
	}

	switch ((exit_reason & 0xFFFF))
	{
	case VM_EXIT_REASON_EXCEPT_OR_NMI:
		vm_exit_callback_int(cpu_id, exit_qual, guest_context);
		break;

	case VM_EXIT_REASON_EXT_INTTERUPT:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] External Interrupt \n", cpu_id);
		break;

	case VM_EXIT_REASON_TRIPLE_FAULT:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Triple fault \n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_INIT_SIGNAL:
		vm_exit_callback_init_signal(cpu_id);
		break;

	case VM_EXIT_REASON_START_UP_IPI:
		vm_exit_callback_start_up_signal(cpu_id);
		break;

	case VM_EXIT_REASON_IO_SMI:
	case VM_EXIT_REASON_OTHER_SMI:
	case VM_EXIT_REASON_INT_WINDOW:
	case VM_EXIT_REASON_NMI_WINDOW:
	case VM_EXIT_REASON_TASK_SWITCH:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_SMI, INT, NMI\n", cpu_id);
		advance_vm_guest_rip();
		break;

	// Unconditional VM exit event
	case VM_EXIT_REASON_CPUID:
		vm_exit_callback_cpuid(guest_context);
		break;

	// Tboot interoperation
	case VM_EXIT_REASON_GETSEC:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] GETSEC call \n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_HLT:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_GETSEC, HLT\n", cpu_id);
		advance_vm_guest_rip();
		break;

	// Unconditional VM exit event
	case VM_EXIT_REASON_INVD:
		vm_exit_callback_invd();
		break;

	case VM_EXIT_REASON_INVLPG:
	case VM_EXIT_REASON_RDPMC:
	case VM_EXIT_REASON_RDTSC:
	case VM_EXIT_REASON_RSM:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INVLPG, RDPMC, RDTSC, RSM\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_VMCLEAR:
	case VM_EXIT_REASON_VMLAUNCH:
	case VM_EXIT_REASON_VMPTRLD:
	case VM_EXIT_REASON_VMPTRST:
	case VM_EXIT_REASON_VMREAD:
	case VM_EXIT_REASON_VMRESUME:
	case VM_EXIT_REASON_VMWRITE:
	case VM_EXIT_REASON_VMXON:
	case VM_EXIT_REASON_VMXOFF:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Virtualization Instruction Detected\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Skip VT instruction\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_VMCALL:
		vm_exit_callback_vmcall(cpu_id, guest_context);
		break;

	// Unconditional VM exit event (move fron reg_value)
	case VM_EXIT_REASON_CTRL_REG_ACCESS:
		vm_exit_callback_access_cr(cpu_id, guest_context, exit_reason, exit_qual);
		break;

	case VM_EXIT_REASON_MOV_DR:
		not_printf(LOG_LEVEL_DETAIL, LOG_ERROR "VM [%d] MOVE DR is executed", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_IO_INST:
	case VM_EXIT_REASON_RDMSR:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_IO_INST, RDMSR\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_WRMSR:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_WRMSR\n", cpu_id);
		vm_exit_callback_wrmsr(cpu_id);
		break;

	case VM_EXIT_REASON_VM_ENTRY_FAILURE_INV_GUEST:
	case VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOAD:
	case VM_EXIT_REASON_MWAIT:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_VM_ENTRY_FAILURE_INV_GUEST, MSR_LOAD\n", cpu_id);
		advance_vm_guest_rip();
		break;

	/* For hardware breakpoint interoperation */
	case VM_EXIT_REASON_MONITOR_TRAP_FLAG:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_TRAP_FLAG\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_MONITOR:
	case VM_EXIT_REASON_PAUSE:
	case VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK:
	case VM_EXIT_REASON_TRP_BELOW_THRESHOLD:
	case VM_EXIT_REASON_APIC_ACCESS:
	case VM_EXIT_REASON_VIRTUALIZED_EOI:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_MONITOR, PAUSE, VM_ENTRY_FAILURE_MACHINE_CHECK,...\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_ACCESS_GDTR_OR_IDTR:
		vm_exit_callback_gdtr_idtr(cpu_id, guest_context);
		break;

	case VM_EXIT_REASON_ACCESS_LDTR_OR_TR:
		vm_exit_callback_ldtr_tr(cpu_id, guest_context);
		break;

	case VM_EXIT_REASON_EPT_VIOLATION:
		vm_exit_callback_ept_violation(cpu_id, guest_context, exit_reason, exit_qual, guest_linear, guest_physical);
		break;

	case VM_EXIT_REASON_EPT_MISCONFIGURATION:
	case VM_EXIT_REASON_INVEPT:
	case VM_EXIT_REASON_RDTSCP:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_EPT_MISCONFIG\n", cpu_id);
		advance_vm_guest_rip();
		break;

	case VM_EXIT_REASON_VMX_PREEMP_TIMER_EXPIRED:
		vm_exit_callback_pre_timer_expired(cpu_id);
		break;

	case VM_EXIT_REASON_INVVPID:
	case VM_EXIT_REASON_WBINVD:
	case VM_EXIT_REASON_XSETBV:
	case VM_EXIT_REASON_APIC_WRITE:
	case VM_EXIT_REASON_RDRAND:
	case VM_EXIT_REASON_INVPCID:
	case VM_EXIT_REASON_VMFUNC:
	case VM_EXIT_REASON_RDSEED:
	case VM_EXIT_REASON_XSAVES:
	case VM_EXIT_REASON_XRSTORS:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_INVVPID\n", cpu_id);
		advance_vm_guest_rip();
		break;

	default:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] VM_EXIT_REASON_DEFAULT\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Exit Reason: %d, %016lX\n", cpu_id, (u32)exit_reason, exit_reason);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Exit Qualification: %d, %016lX\n", cpu_id, (u32)exit_qual, exit_qual);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Guest Linear: %d, %016lX\n", cpu_id, (u32)guest_linear, guest_linear);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Guest Physical: %d, %016lX\n", cpu_id, (u32)guest_physical, guest_physical);
		advance_vm_guest_rip();
		break;
	}

	// Update currnt cpu mode
	global_vmx_root_mode[cpu_id] = 0;
}

// Process Startup IPI
static void vm_exit_callback_start_up_signal(int cpu_id)
{
	u64 status;

	read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ********************** WARNING **********************\n", cpu_id);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Change Activity Status to Active, %016lX\n", cpu_id, status);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ********************** WARNING **********************\n", cpu_id);
}

// Process INVD callback
static void vm_exit_callback_invd(void)
{
	do_invd();
	advance_vm_guest_rip();
}

// Process CPUID callback
static void vm_exit_callback_cpuid(struct vm_exit_guest_register *guest_context)
{
	cpuid_count(guest_context->rax, guest_context->rcx, (u32 *)&guest_context->rax, (u32 *)&guest_context->rbx, (u32 *)&guest_context->rcx, (u32 *)&guest_context->rdx);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM_EXIT_REASON_CPUID Result: %08X, %08X, %08X, %08X\n", (u32)guest_context->rax, (u32)guest_context->rbx, (u32)guest_context->rcx, (u32)guest_context->rdx);
	advance_vm_guest_rip();
}

// Process interrupt callback
static void vm_exit_callback_int(int cpu_id, unsigned long dr6, struct vm_exit_guest_register *guest_context)
{
	unsigned long dr7;
	u64 info_field;
	int vector, type;

	// 8:10 bit is NMI
	read_vmcs(VM_DATA_VM_EXIT_INT_INFO, &info_field);
	vector = VM_EXIT_INT_INFO_VECTOR(info_field);
	type = VM_EXIT_INT_INFO_INT_TYPE(info_field);

	if (type == VM_EXIT_INT_TYPE_NMI)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING *******************n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] NMI Interrupt Occured\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING *******************n", cpu_id);
	}
	else if (vector != VM_INT_DEBUG_EXCEPTION)
	{
		remove_int_exception_from_vm(vector);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ********************** WARNING vector %d **********************\n",
		cpu_id, vector);
		return;
	}

	// For stable shutdown, skip processing if system is shutdowning
	if (is_system_shutting_down() == 0)
	{
#if !ENABLED_STAROZA
		handle_process_and_module_breakpoints(cpu_id, dr6, guest_context);
#else
		handle_syscall_breakpoints(cpu_id, dr6, guest_context);
#endif
	}

	dr6 &= 0xfffffffffffffff0;
	set_debugreg(dr6, 6);

	// When the guest is resumed, Let the guest skip hardware breakpoint
	read_vmcs(VM_GUEST_RFLAGS, (u64 *)&dr7);
	dr7 |= RFLAGS_BIT_RF;
	write_vmcs(VM_GUEST_RFLAGS, dr7);

	remove_int_exception_from_vm(vector);
}

// Process EPT violation
static void vm_exit_callback_ept_violation(int cpu_id, struct vm_exit_guest_register *guest_context, u64 exit_reason, u64 exit_qual, u64 guest_linear, u64 guest_physical)
{
	u64 log_addr, cr0;

	not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] Memory attack is detected, guest linear=%016lX guest physical=%016X virt_to_phys=%016lX\n", cpu_id, guest_linear, guest_physical, virt_to_phys((void *)guest_linear));

	if (is_system_shutting_down() == 0)
	{
		// If the address is in workaround area, set all permission to the page
		if (is_workaround_addr(guest_physical) == 1)
		{
			set_ept_all_access_page(guest_physical);
			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] *** %016lX is Workaround Address ***\n\n", cpu_id, guest_physical);
		}
		else
		{
			// Insert exception to the guest
			insert_exception_to_vm();
			read_vmcs(VM_GUEST_CR0, &cr0);

			// If malware turns WP bit off, recover it again
			if ((cr0 & CR0_BIT_PG) && !(cr0 & CR0_BIT_WP))
			{
				write_vmcs(VM_GUEST_CR0, cr0 | CR0_BIT_WP);
			}

			error_log(ERROR_KERNEL_MODIFICATION);
		}
	}
	else
	{
		log_addr = (u64)phys_to_virt(guest_physical);
		if (is_addr_in_kernel_ro_area((void *)log_addr) == 0)
		{
			set_ept_all_access_page(guest_physical);
		}
	}
}

/*
 * Process LDTR, TR modification callback.
 * Linux set 0 to LLDT, so this function allows only 0 value setting.
 */
static void vm_exit_callback_ldtr_tr(int cpu_id, struct vm_exit_guest_register *guest_context)
{
	u64 inst_info, value, dest_addr = 0;
	int memory = 0;

	read_vmcs(VM_DATA_VM_EXIT_INST_INFO, &inst_info);

	// Check destination type
	if (!VM_INST_INFO_MEM_REG(inst_info))
	{
		dest_addr = calc_dest_mem_addr(guest_context, inst_info);
		memory = 1;
	}
	else
	{
		dest_addr = get_reg_value_from_index(guest_context,
											 VM_INST_INFO_REG1(inst_info));
	}

	switch (VM_INST_INFO_INST_IDENTITY(inst_info))
	{
	// SLDT
	case VM_INST_INFO_SLDT:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] SLDT is not allowed\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_ldtr_tr SLDT\n", cpu_id);
		value = get_ldtr();
		if (memory == 1)
		{
			set_value_to_memory(inst_info, dest_addr, value);
		}
		else
		{
			set_reg_value_from_index(guest_context, (inst_info >> 3) & 0xF, value);
		}
		break;

	// STR
	case VM_INST_INFO_STR:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] STR is not allowed\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_ldtr_tr STR\n", cpu_id);
		insert_exception_to_vm();
		break;

	// LLDT
	case VM_INST_INFO_LLDT:
		if (memory == 1)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Memory, value[%016lX]\n", cpu_id, dest_addr);
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_ldtr_tr LLDT 1\n", cpu_id);
			insert_exception_to_vm();

			value = get_value_from_memory(inst_info, dest_addr);
			write_vmcs(VM_GUEST_LDTR_SELECTOR, value);
		}
		else
		{
			if (dest_addr == 0)
			{
				write_vmcs(VM_GUEST_LDTR_SELECTOR, dest_addr);
			}
			else
			{
				not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] LLDT Value is not 0, %016lX\n", cpu_id, dest_addr);
				not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_ldtr_tr LLDT 2\n", cpu_id);
				insert_exception_to_vm();
			}
		}
		break;

	// LTR
	case VM_INST_INFO_LTR:
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] LTR is not allowed\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_ldtr_tr LTR\n", cpu_id);
		insert_exception_to_vm();
		break;
	}

	advance_vm_guest_rip();
}

// Process GDTR, IDTR modification callback
static void vm_exit_callback_gdtr_idtr(int cpu_id, struct vm_exit_guest_register *guest_context)
{
	if (is_system_shutting_down() == 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING *******************\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_gdtr_idtr\n", cpu_id);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING *******************\n", cpu_id);

		advance_vm_guest_rip();
	}
	else
	{
		disable_desc_monitor();
	}
}

// Process write MSR callback.
static void vm_exit_callback_wrmsr(int cpu_id)
{
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] vm_exit_callback_wrmsr\n", cpu_id);
	insert_exception_to_vm();
}

// Process  read and write event of control register
static void vm_exit_callback_access_cr(int cpu_id, struct vm_exit_guest_register *guest_context, u64 exit_reason, u64 exit_qual)
{
	u64 reg_value = 0, prev_cr3 = 0;

	if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) == VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_FROM_CR)
	{
		switch (VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
		case REG_NUM_CR0:
			reg_value = get_cr0();
			break;

		case REG_NUM_CR2:
			reg_value = get_cr2();
			break;

		case REG_NUM_CR3:
			reg_value = get_cr3();
			break;

		case REG_NUM_CR4:
			reg_value = get_cr4();
			break;

		case REG_NUM_CR8:
			reg_value = get_cr8();
			break;
		}

		set_reg_value_from_index(guest_context, VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual), reg_value);
	}
	else if (VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual) == VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_TO_CR)
	{
		reg_value = get_reg_value_from_index(guest_context, VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(exit_qual));

		switch (VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(exit_qual))
		{
		case REG_NUM_CR0:
			write_vmcs(VM_GUEST_CR0, reg_value);
			break;

		case REG_NUM_CR2:
			// write_vmcs(VM_GUEST_CR2, reg_value);
			break;

		case REG_NUM_CR3:
			read_vmcs(VM_GUEST_CR3, &prev_cr3);
			write_vmcs(VM_GUEST_CR3, reg_value);
			break;

		case REG_NUM_CR4:
			// VMXE bit should be set! for unrestricted guest
			reg_value |= ((u64)CR4_BIT_VMXE);
			write_vmcs(VM_GUEST_CR4, reg_value);
			break;

		case REG_NUM_CR8:
			// write_vmcs(VM_GUEST_CR8, reg_value);
			break;
		}
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is not move from reg_value: %d\n", cpu_id, (int)VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(exit_qual));
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] VM_EXIT_QUAL_CTRL_REG is not move from reg_value\n", cpu_id);
	}

	advance_vm_guest_rip();
}

// Process VM call
static void vm_exit_callback_vmcall(int cpu_id, struct vm_exit_guest_register *guest_context)
{
	u64 svr_num;
	void *arg;

	svr_num = guest_context->rax;
	arg = (void *)guest_context->rbx;

	// Set return value
	guest_context->rax = 0;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] VMCALL index[%ld], arg_in[%016lX]\n", cpu_id, svr_num, arg);

	// Move RIP to next instruction
	advance_vm_guest_rip();

	switch (svr_num)
	{
	// Return log info structure
	case VM_SERVICE_GET_LOGINFO:
		guest_context->rax = 0;
		break;

	default:
		advance_vm_guest_rip();
		break;
	}
}

// Process VT-timer expire callback
static void vm_exit_callback_pre_timer_expired(int cpu_id)
{
	u64 value;

	if (is_system_shutting_down() == 0)
	{
#if ENABLED_DESC_TABLE		
		// Check gdtr
		if (check_gdtr(cpu_id) == -1)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] GDTR or IDTR attack is detected\n", cpu_id);
			error_log(ERROR_KERNEL_MODIFICATION);
		}

		// Call the function of the monitor
		callback_vm_timer(cpu_id);
#endif
	}

	// Reset VM timer
	value = calc_vm_pre_timer_value();
	write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
}

//  Process INIT IPI
static void vm_exit_callback_init_signal(int cpu_id)
{
	u64 status;

	read_vmcs(VM_GUEST_ACTIVITY_STATE, &status);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING *******************\n", cpu_id);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Activity Status %016lX\n", cpu_id, status);
	not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] ******************* WARNING ******************* \n", cpu_id);
}

#pragma endregion

#pragma region VMCS
static void alloc_vmcs_memory(void)
{
	int cpu_count, i;

	cpu_count = num_online_cpus();

	printk("Alloc VMCS Memory\n");

	for (i = 0; i < cpu_count; i++)
	{
		global_vmx_on_vmcs_log_addr[i] = kmalloc(VMCS_SIZE, GFP_KERNEL | __GFP_COLD);
		global_guest_vmcs_log_addr[i] = kmalloc(VMCS_SIZE, GFP_KERNEL | __GFP_COLD);
		global_vm_exit_stack_addr[i] = (void *)vmalloc(global_stack_size);

		global_io_bitmap_addrA[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		global_io_bitmap_addrB[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		global_msr_bitmap_addr[i] = kmalloc(IO_BITMAP_SIZE, GFP_KERNEL | __GFP_COLD);
		global_virt_apic_page_addr[i] = kmalloc(VIRT_APIC_PAGE_SIZE, GFP_KERNEL | __GFP_COLD);

		if ((global_vmx_on_vmcs_log_addr[i] == NULL) || (global_guest_vmcs_log_addr[i] == NULL) ||
			(global_vm_exit_stack_addr[i] == NULL) || (global_io_bitmap_addrA[i] == NULL) ||
			(global_io_bitmap_addrB[i] == NULL) || (global_msr_bitmap_addr[i] == NULL) ||
			(global_virt_apic_page_addr[i] == NULL))
		{
			printk("alloc_vmcs_memory alloc fail\n");
			return;
		}
		else
		{
			printk("    [*] VM[%d] Alloc Host VMCS %016lX\n", i, global_vmx_on_vmcs_log_addr[i]);
			printk("    [*] VM[%d] Alloc Guest VMCS %016lX\n", i, global_guest_vmcs_log_addr[i]);
			printk("    [*] VM[%d] Stack Addr %016lX\n", i, global_vm_exit_stack_addr[i]);
			printk("    [*] VM[%d] IO bitmapA Addr %016lX\n", i, global_io_bitmap_addrA[i]);
			printk("    [*] VM[%d] IO bitmapB Addr %016lX\n", i, global_io_bitmap_addrB[i]);
			printk("    [*] VM[%d] MSR Bitmap Addr %016lX\n", i, global_msr_bitmap_addr[i]);
			printk("    [*] VM[%d] Virt APIC Page Addr %016lX\n", i, global_virt_apic_page_addr[i]);
		}
	}
}

/* We used this tutorial: https://rayanfam.com/topics/hypervisor-from-scratch-part-5/ */
static void setup_vmcs(const struct vm_host_register *vm_host_register, const struct vm_guest_register *vm_guest_register, const struct vm_control_register *vm_control_register)
{
	int result, cpu_id;
	u64 value;

	cpu_id = smp_processor_id();

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] Setup VMCS\n", cpu_id);

	// Setup host information
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Host Register\n");
	result = write_vmcs(VM_HOST_CR0, vm_host_register->cr0);
	not_print_vm_result("    [*] CR0", result);
	result = write_vmcs(VM_HOST_CR3, vm_host_register->cr3);
	not_print_vm_result("    [*] CR3", result);
	result = write_vmcs(VM_HOST_CR4, vm_host_register->cr4);
	not_print_vm_result("    [*] CR4", result);
	result = write_vmcs(VM_HOST_RSP, vm_host_register->rsp);
	not_print_vm_result("    [*] RSP", result);
	result = write_vmcs(VM_HOST_RIP, vm_host_register->rip);
	not_print_vm_result("    [*] RIP", result);
	result = write_vmcs(VM_HOST_CS_SELECTOR, vm_host_register->cs_selector);
	not_print_vm_result("    [*] CS Selector", result);
	result = write_vmcs(VM_HOST_SS_SELECTOR, vm_host_register->ss_selector);
	not_print_vm_result("    [*] SS Selector", result);
	result = write_vmcs(VM_HOST_DS_SELECTOR, vm_host_register->ds_selector);
	not_print_vm_result("    [*] DS Selector", result);
	result = write_vmcs(VM_HOST_ES_SELECTOR, vm_host_register->es_selector);
	not_print_vm_result("    [*] ES Selector", result);
	result = write_vmcs(VM_HOST_FS_SELECTOR, vm_host_register->fs_selector);
	not_print_vm_result("    [*] FS Selector", result);
	result = write_vmcs(VM_HOST_GS_SELECTOR, vm_host_register->gs_selector);
	not_print_vm_result("    [*] GS Selector", result);
	result = write_vmcs(VM_HOST_TR_SELECTOR, vm_host_register->tr_selector);
	not_print_vm_result("    [*] TR Selector", result);

	result = write_vmcs(VM_HOST_FS_BASE, vm_host_register->fs_base_addr);
	not_print_vm_result("    [*] FS Base", result);
	result = write_vmcs(VM_HOST_GS_BASE, vm_host_register->gs_base_addr);
	not_print_vm_result("    [*] GS Base", result);
	result = write_vmcs(VM_HOST_TR_BASE, vm_host_register->tr_base_addr);
	not_print_vm_result("    [*] TR Base", result);
	result = write_vmcs(VM_HOST_GDTR_BASE, vm_host_register->gdtr_base_addr);
	not_print_vm_result("    [*] GDTR Base", result);
	result = write_vmcs(VM_HOST_IDTR_BASE, vm_host_register->idtr_base_addr);
	not_print_vm_result("    [*] IDTR Base", result);

	result = write_vmcs(VM_HOST_IA32_SYSENTER_CS, vm_host_register->ia32_sys_enter_cs);
	not_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = write_vmcs(VM_HOST_IA32_SYSENTER_ESP, vm_host_register->ia32_sys_enter_esp);
	not_print_vm_result("    [*] SYSENTER_ESP", result);
	result = write_vmcs(VM_HOST_IA32_SYSENTER_EIP, vm_host_register->ia32_sys_enter_eip);
	not_print_vm_result("    [*] SYSENTER_EIP", result);
	result = write_vmcs(VM_HOST_PERF_GLOBAL_CTRL, vm_host_register->ia32_perf_global_ctrl);
	not_print_vm_result("    [*] Perf Global Ctrl", result);
	result = write_vmcs(VM_HOST_PAT, vm_host_register->ia32_pat);
	not_print_vm_result("    [*] PAT", result);
	result = write_vmcs(VM_HOST_EFER, vm_host_register->ia32_efer);
	not_print_vm_result("    [*] EFER", result);

	// Setup guest information
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Set Guest Register\n");
	result = write_vmcs(VM_GUEST_CR0, vm_guest_register->cr0);
	not_print_vm_result("    [*] CR0", result);
	result = write_vmcs(VM_GUEST_CR3, vm_guest_register->cr3);
	not_print_vm_result("    [*] CR3", result);
	result = write_vmcs(VM_GUEST_CR4, vm_guest_register->cr4);
	not_print_vm_result("    [*] CR4", result);
	result = write_vmcs(VM_GUEST_DR7, vm_guest_register->dr7);
	not_print_vm_result("    [*] DR7", result);
	result = write_vmcs(VM_GUEST_RSP, vm_guest_register->rsp);
	not_print_vm_result("    [*] RSP", result);
	result = write_vmcs(VM_GUEST_RIP, vm_guest_register->rip);
	not_print_vm_result("    [*] RIP", result);
	result = write_vmcs(VM_GUEST_RFLAGS, vm_guest_register->rflags);
	not_print_vm_result("    [*] RFLAGS", result);
	result = write_vmcs(VM_GUEST_CS_SELECTOR, vm_guest_register->cs_selector);
	not_print_vm_result("    [*] CS Selector", result);
	result = write_vmcs(VM_GUEST_SS_SELECTOR, vm_guest_register->ss_selector);
	not_print_vm_result("    [*] SS Selector", result);
	result = write_vmcs(VM_GUEST_DS_SELECTOR, vm_guest_register->ds_selector);
	not_print_vm_result("    [*] DS Selector", result);
	result = write_vmcs(VM_GUEST_ES_SELECTOR, vm_guest_register->es_selector);
	not_print_vm_result("    [*] ES Selector", result);
	result = write_vmcs(VM_GUEST_FS_SELECTOR, vm_guest_register->fs_selector);
	not_print_vm_result("    [*] FS Selector", result);
	result = write_vmcs(VM_GUEST_GS_SELECTOR, vm_guest_register->gs_selector);
	not_print_vm_result("    [*] GS Selector", result);
	result = write_vmcs(VM_GUEST_LDTR_SELECTOR, vm_guest_register->ldtr_selector);
	not_print_vm_result("    [*] LDTR Selector", result);
	result = write_vmcs(VM_GUEST_TR_SELECTOR, vm_guest_register->tr_selector);
	not_print_vm_result("    [*] TR Selector", result);

	result = write_vmcs(VM_GUEST_CS_BASE, vm_guest_register->cs_base_addr);
	not_print_vm_result("    [*] CS Base", result);
	result = write_vmcs(VM_GUEST_SS_BASE, vm_guest_register->ss_base_addr);
	not_print_vm_result("    [*] SS Base", result);
	result = write_vmcs(VM_GUEST_DS_BASE, vm_guest_register->ds_base_addr);
	not_print_vm_result("    [*] DS Base", result);
	result = write_vmcs(VM_GUEST_ES_BASE, vm_guest_register->es_base_addr);
	not_print_vm_result("    [*] ES Base", result);
	result = write_vmcs(VM_GUEST_FS_BASE, vm_guest_register->fs_base_addr);
	not_print_vm_result("    [*] FS Base", result);
	result = write_vmcs(VM_GUEST_GS_BASE, vm_guest_register->gs_base_addr);
	not_print_vm_result("    [*] GS Base", result);
	result = write_vmcs(VM_GUEST_LDTR_BASE, vm_guest_register->ldtr_base_addr);
	not_print_vm_result("    [*] LDTR Base", result);
	result = write_vmcs(VM_GUEST_TR_BASE, vm_guest_register->tr_base_addr);
	not_print_vm_result("    [*] TR Base", result);

	result = write_vmcs(VM_GUEST_CS_LIMIT, vm_guest_register->cs_limit);
	not_print_vm_result("    [*] CS Limit", result);
	result = write_vmcs(VM_GUEST_SS_LIMIT, vm_guest_register->ss_limit);
	not_print_vm_result("    [*] SS Limit", result);
	result = write_vmcs(VM_GUEST_DS_LIMIT, vm_guest_register->ds_limit);
	not_print_vm_result("    [*] DS Limit", result);
	result = write_vmcs(VM_GUEST_ES_LIMIT, vm_guest_register->es_limit);
	not_print_vm_result("    [*] ES Limit", result);
	result = write_vmcs(VM_GUEST_FS_LIMIT, vm_guest_register->fs_limit);
	not_print_vm_result("    [*] FS Limit", result);
	result = write_vmcs(VM_GUEST_GS_LIMIT, vm_guest_register->gs_limit);
	not_print_vm_result("    [*] GS Limit", result);
	result = write_vmcs(VM_GUEST_LDTR_LIMIT, vm_guest_register->ldtr_limit);
	not_print_vm_result("    [*] LDTR Limit", result);
	result = write_vmcs(VM_GUEST_TR_LIMIT, vm_guest_register->tr_limit);
	not_print_vm_result("    [*] TR Limit", result);

	result = write_vmcs(VM_GUEST_CS_ACC_RIGHT, vm_guest_register->cs_access);
	not_print_vm_result("    [*] CS Access", result);
	result = write_vmcs(VM_GUEST_SS_ACC_RIGHT, vm_guest_register->ss_access);
	not_print_vm_result("    [*] SS Access", result);
	result = write_vmcs(VM_GUEST_DS_ACC_RIGHT, vm_guest_register->ds_access);
	not_print_vm_result("    [*] DS Access", result);
	result = write_vmcs(VM_GUEST_ES_ACC_RIGHT, vm_guest_register->es_access);
	not_print_vm_result("    [*] ES Access", result);
	result = write_vmcs(VM_GUEST_FS_ACC_RIGHT, vm_guest_register->fs_access);
	not_print_vm_result("    [*] FS Access", result);
	result = write_vmcs(VM_GUEST_GS_ACC_RIGHT, vm_guest_register->gs_access);
	not_print_vm_result("    [*] GS Access", result);
	result = write_vmcs(VM_GUEST_LDTR_ACC_RIGHT, vm_guest_register->ldtr_access);
	not_print_vm_result("    [*] LDTR Access", result);
	result = write_vmcs(VM_GUEST_TR_ACC_RIGHT, vm_guest_register->tr_access);
	not_print_vm_result("    [*] TR Access", result);

	result = write_vmcs(VM_GUEST_GDTR_BASE, vm_guest_register->gdtr_base_addr);
	not_print_vm_result("    [*] GDTR Base", result);
	result = write_vmcs(VM_GUEST_IDTR_BASE, vm_guest_register->idtr_base_addr);
	not_print_vm_result("    [*] IDTR Base", result);
	result = write_vmcs(VM_GUEST_GDTR_LIMIT, vm_guest_register->gdtr_limit);
	not_print_vm_result("    [*] GDTR Base", result);
	result = write_vmcs(VM_GUEST_IDTR_LIMIT, vm_guest_register->idtr_limit);
	not_print_vm_result("    [*] IDTR Base", result);

	result = write_vmcs(VM_GUEST_DEBUGCTL, vm_guest_register->ia32_debug_ctrl);
	not_print_vm_result("    [*] DEBUG CONTROL", result);
	result = write_vmcs(VM_GUEST_IA32_SYSENTER_CS, vm_guest_register->ia32_sys_enter_cs);
	not_print_vm_result("    [*] SYSENTER_CS Base", result);
	result = write_vmcs(VM_GUEST_IA32_SYSENTER_ESP, vm_guest_register->ia32_sys_enter_esp);
	not_print_vm_result("    [*] SYSENTER_ESP", result);
	result = write_vmcs(VM_GUEST_IA32_SYSENTER_EIP, vm_guest_register->ia32_sys_enter_eip);
	not_print_vm_result("    [*] SYSENTER_EIP", result);
	result = write_vmcs(VM_GUEST_PERF_GLOBAL_CTRL, vm_guest_register->ia32_perf_global_ctrl);
	not_print_vm_result("    [*] Perf Global Ctrl", result);
	result = write_vmcs(VM_GUEST_PAT, vm_guest_register->ia32_pat);
	not_print_vm_result("    [*] PAT", result);
	result = write_vmcs(VM_GUEST_EFER, vm_guest_register->ia32_efer);
	not_print_vm_result("    [*] EFER", result);

	result = write_vmcs(VM_VMCS_LINK_PTR, vm_guest_register->vmcs_link_ptr);
	not_print_vm_result("    [*] VMCS Link ptr", result);

	result = write_vmcs(VM_GUEST_INT_STATE, 0);
	not_print_vm_result("    [*] Guest Int State", result);

	result = write_vmcs(VM_GUEST_ACTIVITY_STATE, 0);
	not_print_vm_result("    [*] Guest Activity State", result);

	result = write_vmcs(VM_GUEST_SMBASE, 0);
	not_print_vm_result("    [*] Guest SMBase", result);

	result = write_vmcs(VM_GUEST_PENDING_DBG_EXCEPTS, 0);
	not_print_vm_result("    [*] Pending DBG Excepts", result);

	value = calc_vm_pre_timer_value();
	result = write_vmcs(VM_GUEST_VMX_PRE_TIMER_VALUE, value);
	not_print_vm_result("    [*] VM Preemption Timer", result);

	// Setup VM control information
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Set VM Control Register\n");

	result = write_vmcs(VM_CTRL_PIN_BASED_VM_EXE_CTRL, vm_control_register->pin_based_ctrl);
	not_print_vm_result("    [*] PIN Based Ctrl", result);
	result = write_vmcs(VM_CTRL_PRI_PROC_BASED_EXE_CTRL, vm_control_register->pri_proc_based_ctrl);
	not_print_vm_result("    [*] Primary Process Based Ctrl", result);
	result = write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, vm_control_register->sec_proc_based_ctrl);
	not_print_vm_result("    [*] Secondary Process Based Ctrl", result);
	result = write_vmcs(VM_CTRL_EXCEPTION_BITMAP, vm_control_register->except_bitmap);
	not_print_vm_result("    [*] Exception Bitmap", result);
	result = write_vmcs(VM_CTRL_IO_BITMAP_A_ADDR, vm_control_register->io_bitmap_addrA);
	not_print_vm_result("    [*] IO Bitmap A", result);
	result = write_vmcs(VM_CTRL_IO_BITMAP_B_ADDR, vm_control_register->io_bitmap_addrB);
	not_print_vm_result("    [*] IO Bitmap B", result);
	result = write_vmcs(VM_CTRL_EPT_PTR, vm_control_register->ept_ptr);
	not_print_vm_result("    [*] EPT Ptr", result);
	result = write_vmcs(VM_CTRL_MSR_BITMAPS, vm_control_register->msr_bitmap_addr);
	not_print_vm_result("    [*] MSR Bitmap", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_CTRLS, vm_control_register->vm_entry_ctrl_field);
	not_print_vm_result("    [*] VM Entry Control", result);
	result = write_vmcs(VM_CTRL_VM_EXIT_CTRLS, vm_control_register->vm_exti_ctrl_field);
	not_print_vm_result("    [*] VM Exit Control", result);
	result = write_vmcs(VM_CTRL_VIRTUAL_APIC_ADDR, vm_control_register->virt_apic_page_addr);
	not_print_vm_result("    [*] Virtual APIC Page", result);
	result = write_vmcs(VM_CTRL_CR0_GUEST_HOST_MASK, 0);
	not_print_vm_result("    [*] CR0 Guest Host Mask", result);
	result = write_vmcs(VM_CTRL_CR4_GUEST_HOST_MASK, vm_control_register->cr4_guest_host_mask);
	not_print_vm_result("    [*] CR4 Guest Host Mask", result);
	result = write_vmcs(VM_CTRL_CR0_READ_SHADOW, 0);
	not_print_vm_result("    [*] CR0 Read Shadow", result);
	result = write_vmcs(VM_CTRL_CR4_READ_SHADOW, vm_control_register->cr4_read_shadow);
	not_print_vm_result("    [*] CR4 Read Shadow", result);
	result = write_vmcs(VM_CTRL_CR3_TARGET_VALUE_0, 0);
	not_print_vm_result("    [*] CR3 Target Value 0", result);
	result = write_vmcs(VM_CTRL_CR3_TARGET_VALUE_1, 0);
	not_print_vm_result("    [*] CR3 Target Value 1", result);
	result = write_vmcs(VM_CTRL_CR3_TARGET_VALUE_2, 0);
	not_print_vm_result("    [*] CR3 Target Value 2", result);
	result = write_vmcs(VM_CTRL_CR3_TARGET_VALUE_3, 0);
	not_print_vm_result("    [*] CR3 Target Value 3", result);

	result = write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MASK, 0);
	not_print_vm_result("    [*] Page Fault Error Code Mask", result);
	result = write_vmcs(VM_CTRL_PAGE_FAULT_ERR_CODE_MATCH, 0);
	not_print_vm_result("    [*] Page Fault Error Code Match", result);
	result = write_vmcs(VM_CTRL_CR3_TARGET_COUNT, 0);
	not_print_vm_result("    [*] CR3 Target Count", result);
	result = write_vmcs(VM_CTRL_VM_EXIT_MSR_STORE_COUNT, 0);
	not_print_vm_result("    [*] MSR Store Count", result);
	result = write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_COUNT, 0);
	not_print_vm_result("    [*] MSR Load Count", result);
	result = write_vmcs(VM_CTRL_VM_EXIT_MSR_LOAD_ADDR, 0);
	not_print_vm_result("    [*] MSR Load Addr", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, 0);
	not_print_vm_result("    [*] VM Entry Int Info Field", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
	not_print_vm_result("    [*] VM Entry Except Err Code", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_INST_LENGTH, 0);
	not_print_vm_result("    [*] VM Entry Inst Length", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_COUNT, 0);
	not_print_vm_result("    [*] VM Entry MSR Load Count", result);
	result = write_vmcs(VM_CTRL_VM_ENTRY_MSR_LOAD_ADDR, 0);
	not_print_vm_result("    [*] VM Entry MSR Load Addr", result);

	result = write_vmcs(VM_CTRL_TPR_THRESHOLD, 0);
	not_print_vm_result("    [*] TPR Threashold", result);
	result = write_vmcs(VM_CTRL_EXECUTIVE_VMCS_PTR, 0);
	not_print_vm_result("    [*] Executive VMCS Ptr", result);
	result = write_vmcs(VM_CTRL_TSC_OFFSET, 0);
	not_print_vm_result("    [*] TSC Offset", result);
}

#if ENABLED_EPT
static void protect_vmcs(void)
{
	int i, cpu_count;

	cpu_count = num_online_cpus();
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect VMCS\n");

	for (i = 0; i < cpu_count; i++)
	{
		hide_range((u64)global_vmx_on_vmcs_log_addr[i], (u64)global_vmx_on_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		hide_range((u64)global_guest_vmcs_log_addr[i], (u64)global_guest_vmcs_log_addr[i] + VMCS_SIZE, ALLOC_KMALLOC);
		hide_range((u64)global_vm_exit_stack_addr[i], (u64)global_vm_exit_stack_addr[i] + global_stack_size, ALLOC_VMALLOC);
		hide_range((u64)global_io_bitmap_addrA[i], (u64)global_io_bitmap_addrA[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		hide_range((u64)global_io_bitmap_addrB[i], (u64)global_io_bitmap_addrB[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		hide_range((u64)global_msr_bitmap_addr[i], (u64)global_msr_bitmap_addr[i] + IO_BITMAP_SIZE, ALLOC_KMALLOC);
		hide_range((u64)global_virt_apic_page_addr[i], (u64)global_virt_apic_page_addr[i] + VIRT_APIC_PAGE_SIZE, ALLOC_KMALLOC);
	}
}
#endif
#pragma endregion

#pragma region RO_FUNCTIONS
int is_addr_in_ro_area(void *addr)
{
	int i;

	// Allow NULL pointer
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0; i < global_ro_array_count; i++)
	{
		if ((global_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (global_ro_array[i].end)))
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}
	}

	//not_printf(LOG_LEVEL_ERROR, LOG_ERROR "%p is not in code area\n", addr);

	return 0;
}

void add_ro_area(u64 start, u64 end, u64 ro_type)
{
	global_ro_array[global_ro_array_count].start = start;
	global_ro_array[global_ro_array_count].end = end;
	global_ro_array[global_ro_array_count].type = ro_type;
	global_ro_array_count++;
}

static void add_and_protect_module_ro(struct module *mod)
{
	u64 mod_init_base, mod_init_size, mod_init_text_size, mod_init_ro_size, mod_core_ro_size, mod_core_base, mod_core_size, mod_core_text_size;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	mod_init_base = (u64)mod->module_init;
	mod_init_size = (u64)mod->init_size;
	mod_init_text_size = (u64)mod->init_text_size;
	mod_init_ro_size = (u64)mod->init_ro_size;
	mod_core_base = (u64)mod->module_core;
	mod_core_size = (u64)mod->core_size;
	mod_core_text_size = (u64)mod->core_text_size;
	mod_core_ro_size = (u64)mod->core_ro_size;
#else
	mod_init_base = (u64)(mod->init_layout.base);
	mod_init_size = (u64)(mod->init_layout.size);
	mod_init_text_size = (u64)(mod->init_layout.text_size);
	mod_init_ro_size = (u64)(mod->init_layout.ro_size);
	mod_core_base = (u64)(mod->core_layout.base);
	mod_core_size = (u64)(mod->core_layout.size);
	mod_core_text_size = (u64)(mod->core_layout.text_size);
	mod_core_ro_size = (u64)(mod->core_layout.ro_size);
#endif

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] mod:%p [%s]", mod, mod->name);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init:0x%p module_init:0x%08lX module_core:0x%08lX\n", mod->init, mod_init_base, mod_core_base);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_size:0x%ld core_size:%ld", mod_init_size, mod_core_size);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_text_size:%ld core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:%ld", mod_init_ro_size, mod_core_ro_size);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "\n");
#if ENABLED_EPT
	lock_range(mod_core_base, mod_core_base + mod_core_ro_size, ALLOC_VMALLOC);
#endif
	add_ro_area(mod_core_base, mod_core_base + mod_core_ro_size, RO_MODULE);
}

int is_addr_in_kernel_ro_area(void *addr)
{
	int i;

	// Allow NULL pointer
	if (addr == NULL)
	{
		return 1;
	}

	for (i = 0; i < global_ro_array_count; i++)
	{
		if ((global_ro_array[i].start <= (u64)addr) &&
			((u64)addr < (global_ro_array[i].end)) &&
			(global_ro_array[i].type == RO_KERNEL))
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "%p is in core area\n", addr);
			return 1;
		}

		if (global_ro_array[i].type == RO_MODULE)
		{
			break;
		}
	}

	return 0;
}

void delete_ro_area(u64 start, u64 end)
{
	int i;

	for (i = 0; i < global_ro_array_count; i++)
	{
		if ((global_ro_array[global_ro_array_count].start == start) &&
			(global_ro_array[global_ro_array_count].end == end))
		{
			global_ro_array[global_ro_array_count].start = 0;
			global_ro_array[global_ro_array_count].end = 0;
			break;
		}
	}
}
#pragma endregion

#pragma region PROTECT
static void protect_module_list_ro_area(void)
{
	struct module *mod;
	struct list_head *pos, *node;
	unsigned long mod_head_node;
	u64 mod_core_size;

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Module Code Area\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");

	global_holdup_module = THIS_MODULE;
	mod = THIS_MODULE;
	pos = &THIS_MODULE->list;

	add_and_protect_module_ro(mod);

	node = &THIS_MODULE->list;
	mod_head_node = get_symbol_address("modules");

	global_modules_ptr = (struct list_head *)mod_head_node;

	list_for_each(pos, node)
	{
		if (mod_head_node == (unsigned long)pos)
			break;

		mod = container_of(pos, struct module, list);

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
		mod_core_size = mod->core_size;
#else
		mod_core_size = mod->core_layout.size;
#endif
		if (mod_core_size == 0)
		{
			continue;
		}

		add_and_protect_module_ro(mod);
	}

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}

static void protect_kernel_ro_area(void)
{
	char *sym_list[] = {
		"_text",
		"_etext",
		"__start___ex_table",
		"__stop___ex_table",
		"__start_rodata",
		"__end_rodata",
	};
	u64 start_log_addr, end_log_addr, start_phy_addr, end_phy_addr, i;

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Protect Kernel Code Area\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Setup RO Area\n");
	for (i = 0; i < sizeof(sym_list) / sizeof(char *); i += 2)
	{
		start_log_addr = get_symbol_address(sym_list[i]);
		end_log_addr = get_symbol_address(sym_list[i + 1]);

		start_phy_addr = virt_to_phys((void *)start_log_addr);
		end_phy_addr = virt_to_phys((void *)end_log_addr);

		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n", sym_list[i], start_log_addr, start_phy_addr);
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %s Log %016lX, Phy %016lX\n", sym_list[i + 1], end_log_addr, end_phy_addr);
#if ENABLED_EPT
		lock_range(start_log_addr, end_log_addr, ALLOC_KMALLOC);
#endif	
		add_ro_area(start_log_addr, end_log_addr, RO_KERNEL);

		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] %d Pages\n", (end_log_addr - start_log_addr) / EPT_PAGE_SIZE);
	}

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Complete\n");
}

#if ENABLED_EPT
static void protect_this_module(void)
{
	struct module *mod;
	u64 mod_init_base, mod_init_size, mod_init_text_size, mod_init_ro_size, mod_core_base, mod_core_size, mod_core_text_size, mod_core_ro_size;

	mod = global_holdup_module;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	mod_init_base = (u64)mod->module_init;
	mod_init_size = (u64)mod->init_size;
	mod_init_text_size = (u64)mod->init_text_size;
	mod_init_ro_size = (u64)mod->init_ro_size;
	mod_core_base = (u64)mod->module_core;
	mod_core_size = (u64)mod->core_size;
	mod_core_text_size = (u64)mod->core_text_size;
	mod_core_ro_size = (u64)mod->core_ro_size;
#else
	mod_init_base = (u64)(mod->init_layout.base);
	mod_init_size = (u64)(mod->init_layout.size);
	mod_init_text_size = (u64)(mod->init_layout.text_size);
	mod_init_ro_size = (u64)(mod->init_layout.ro_size);
	mod_core_base = (u64)(mod->core_layout.base);
	mod_core_size = (u64)(mod->core_layout.size);
	mod_core_text_size = (u64)(mod->core_layout.text_size);
	mod_core_ro_size = (u64)(mod->core_layout.ro_size);
#endif

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect HoldUp Area\n");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] mod:%p [%s], size of module struct %d", mod, mod->name, sizeof(struct module));
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init:0x%p module_init:0x%08lX module_core:0x%08lX\n", mod->init, mod_init_base, mod_core_base);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_size:0x%ld core_size:%ld", mod_init_size, mod_core_size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_text_size:%ld core_text_size:%ld\n", mod_init_text_size, mod_core_text_size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] init_ro_size:%ld core_ro_size:%ld", mod_init_ro_size, mod_core_ro_size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "\n");

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] protection start:%016lX end:%016lX", mod_core_base, mod_core_base + mod_core_size);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");

	hide_range(mod_core_base, mod_core_base + mod_core_size, ALLOC_VMALLOC);

	// Module structure is included in module core range, so give full access to module structure.

	set_all_access_range((u64)global_holdup_module, (u64)global_holdup_module + sizeof(struct module), ALLOC_VMALLOC);
}
#endif

static void protect_gdt(int cpu_id)
{
	struct desc_ptr idtr;

	native_store_gdt(&(global_gdtr_array[cpu_id]));
	native_store_idt(&idtr);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d] Protect GDT IDT\n", cpu_id);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] GDTR Base %16lX, Size %d\n", cpu_id, global_gdtr_array[cpu_id].address, global_gdtr_array[cpu_id].size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM[%d]    [*] IDTR Base %16lX, Size %d\n", cpu_id, idtr.address, idtr.size);
#if ENABLED_EPT
	lock_range(idtr.address, (idtr.address + 0xFFF) & MASK_PAGE_ADDR, ALLOC_VMALLOC);
#endif
}

#pragma endregion

#pragma region MEMORY
static int setup_memory_pool(void)
{
	u64 i, size;

	spin_lock_init(&global_memory_pool_lock);

	// Allocate 1 page per 2MB
	global_memory_pool.max_count = global_max_ram_size / S_2MB;
	size = global_memory_pool.max_count * S_4KB;
	global_memory_pool.pool = NULL;

	global_memory_pool.pool = (u64 *)vmalloc(size);
	if (global_memory_pool.pool == NULL)
	{
		goto ERROR;
	}

	memset(global_memory_pool.pool, 0, sizeof(global_memory_pool.max_count));
	for (i = 0; i < global_memory_pool.max_count; i++)
	{
		global_memory_pool.pool[i] = (u64)kmalloc(S_4KB, GFP_KERNEL | __GFP_COLD);
		if (global_memory_pool.pool[i] == 0)
		{
			goto ERROR;
		}
	}

	global_memory_pool.pop_index = 0;

	return 0;

ERROR:
	if (global_memory_pool.pool != NULL)
	{
		for (i = 0; i < global_memory_pool.max_count; i++)
		{
			if (global_memory_pool.pool[i] != 0)
			{
				kfree((void *)global_memory_pool.pool[i]);
			}
		}

		kfree(global_memory_pool.pool);
	}

	return -1;
}

void *allocate_memory(void)
{
	void *memory;

	spin_lock(&global_memory_pool_lock);

	if (global_memory_pool.pop_index >= global_memory_pool.max_count)
	{
		spin_unlock(&global_memory_pool_lock);
		return NULL;
	}

	memory = (void *)global_memory_pool.pool[global_memory_pool.pop_index];

	global_memory_pool.pop_index++;
	spin_unlock(&global_memory_pool_lock);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Get Memory Index %d Addr %016lX\n", global_memory_pool.pop_index, memory);

	return memory;
}

static void set_value_to_memory(u64 inst_info, u64 addr, u64 value)
{
	switch (VM_INST_INFO_ADDR_SIZE(inst_info))
	{
	case VM_INST_INFO_ADDR_SIZE_16BIT:
		*(u16 *)addr = (u16)value;
		break;

	case VM_INST_INFO_ADDR_SIZE_32BIT:
		*(u32 *)addr = (u64)value;
		break;

	case VM_INST_INFO_ADDR_SIZE_64BIT:
		*(u64 *)addr = (u64)value;
		break;
	}
}

static u64 get_value_from_memory(u64 inst_info, u64 addr)
{
	u64 value = 0;

	switch (VM_INST_INFO_ADDR_SIZE(inst_info))
	{
	case VM_INST_INFO_ADDR_SIZE_16BIT:
		value = *(u16 *)addr;
		break;

	case VM_INST_INFO_ADDR_SIZE_32BIT:
		value = *(u32 *)addr;
		break;

	case VM_INST_INFO_ADDR_SIZE_64BIT:
		value = *(u64 *)addr;
		break;
	}

	return value;
}

#pragma endregion

#pragma region TABLES
#if ENABLED_EPT
static void lock_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i, phy_addr, align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGE_ADDR;

	for (i = (start_addr & MASK_PAGE_ADDR); i < align_end_addr; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void *)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void *)i));
		}

		set_ept_lock_page(phy_addr);

#if ENABLED_IOMMU
		set_iommu_hide_page(phy_addr);
#endif
	}
}
#endif
void hide_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i, phy_addr, align_end_addr;

	// Round up the end address
	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGE_ADDR;

	for (i = (start_addr & MASK_PAGE_ADDR); i < align_end_addr; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void *)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void *)i));
		}
#if ENABLED_EPT
		set_ept_hide_page(phy_addr);
#endif

#if ENABLED_IOMMU
		set_iommu_hide_page(phy_addr);
#endif
	}
}

void set_all_access_range(u64 start_addr, u64 end_addr, int alloc_type)
{
	u64 i, phy_addr, align_end_addr;

	align_end_addr = (end_addr + PAGE_SIZE - 1) & MASK_PAGE_ADDR;

	for (i = (start_addr & MASK_PAGE_ADDR); i < align_end_addr; i += 0x1000)
	{
		if (alloc_type == ALLOC_KMALLOC)
		{
			phy_addr = virt_to_phys((void *)i);
		}
		else
		{
			phy_addr = PFN_PHYS(vmalloc_to_pfn((void *)i));
		}

		set_ept_all_access_page(phy_addr);

#if ENABLED_IOMMU
		set_iommu_all_access_page(phy_addr);
#endif
	}
}

/*	OFFICIAL DOCUMENTATION: https://www.kernel.org/doc/Documentation/x86/x86_64/mm.txt
	See: "Virtual memory map.txt" */

static void duplicate_page_table(void)
{
	struct pagetable *org_p4, *org_p3, *org_p2, *org_p1, *vm_p4, *vm_p3, *vm_p2, *vm_p1;
	int i, j, k;
	struct mm_struct *swapper_mm;
	u64 cur_addr;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Duplicate page tables\n");

	org_p4 = (struct pagetable *)get_symbol_address("init_level4_pgt");
	global_vm_init_phy_p4 = virt_to_phys(org_p4);
	swapper_mm = (struct mm_struct *)get_symbol_address("init_mm");
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "init_mm %016lX\n", swapper_mm);
	vm_p4 = (struct pagetable *)__get_free_pages(GFP_KERNEL_ACCOUNT | __GFP_ZERO, PGD_ALLOCATION_ORDER);
#if ENABLED_EPT
	hide_range((u64)vm_p4, (u64)vm_p4 + PAGE_SIZE * (0x1 << PGD_ALLOCATION_ORDER), ALLOC_KMALLOC);
#endif

	global_vm_host_phy_p4 = virt_to_phys(vm_p4);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "P4 Logical %016lX, Physical %016lX, page_offset_base %016lX\n", vm_p4, global_vm_host_phy_p4, page_offset_base);

	// Create page tables
	for (i = 0; i < 512; i++)
	{
		cur_addr = i * S_512GB;

		if ((org_p4->entry[i] == 0) || ((org_p4->entry[i] & MASK_PAGE_SIZE_FLAG)))
		{
			vm_p4->entry[i] = org_p4->entry[i];
			continue;
		}

		vm_p4->entry[i] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC | __GFP_COLD | __GFP_ZERO);
#if ENABLED_EPT
		hide_range((u64)vm_p4->entry[i], (u64)(vm_p4->entry[i]) + PAGE_SIZE, ALLOC_KMALLOC);
#endif
		vm_p4->entry[i] = virt_to_phys((void *)(vm_p4->entry[i]));
		vm_p4->entry[i] |= org_p4->entry[i] & MASK_PAGE_FLAG;

		// Run loop to copy P3
		org_p3 = (struct pagetable *)(org_p4->entry[i] & ~(MASK_PAGE_FLAG));
		vm_p3 = (struct pagetable *)(vm_p4->entry[i] & ~(MASK_PAGE_FLAG));
		org_p3 = phys_to_virt((u64)org_p3);
		vm_p3 = phys_to_virt((u64)vm_p3);

		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] P4[%d] %16lX %16lp %16lp\n", i, org_p4->entry[i], org_p3, vm_p3);
		for (j = 0; j < 512; j++)
		{
			if ((org_p3->entry[j] == 0) || ((org_p3->entry[j] & MASK_PAGE_SIZE_FLAG)))
			{
				vm_p3->entry[j] = org_p3->entry[j];
				continue;
			}

			// Allocate P3 and copy
			vm_p3->entry[j] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC |
													   __GFP_COLD | __GFP_ZERO);
#if ENABLED_EPT
			hide_range((u64)vm_p3->entry[j], (u64)(vm_p3->entry[j]) + PAGE_SIZE, ALLOC_KMALLOC);
#endif
			vm_p3->entry[j] = virt_to_phys((void *)(vm_p3->entry[j]));
			vm_p3->entry[j] |= org_p3->entry[j] & MASK_PAGE_FLAG;

			/* Run loop to copy P3 */
			org_p2 = (struct pagetable *)(org_p3->entry[j] & ~(MASK_PAGE_FLAG));
			vm_p2 = (struct pagetable *)(vm_p3->entry[j] & ~(MASK_PAGE_FLAG));
			org_p2 = phys_to_virt((u64)org_p2);
			vm_p2 = phys_to_virt((u64)vm_p2);

			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] PDP1_PD[%d] %016lX %016lp %016lp\n", j, org_p3->entry[j], org_p2, vm_p2);
			for (k = 0; k < 512; k++)
			{
				if ((org_p2->entry[k] == 0) ||
					((org_p2->entry[k] & MASK_PAGE_SIZE_FLAG)))
				{
					vm_p2->entry[k] = org_p2->entry[k];
					continue;
				}

				// Allocate P1 and copy
				vm_p2->entry[k] = (u64)kmalloc(0x1000, GFP_KERNEL | GFP_ATOMIC | __GFP_COLD | __GFP_ZERO);
#if ENABLED_EPT
				hide_range((u64)vm_p2->entry[k], (u64)(vm_p2->entry[k]) + PAGE_SIZE, ALLOC_KMALLOC);
#endif
				vm_p2->entry[k] = virt_to_phys((void *)(vm_p2->entry[k]));
				vm_p2->entry[k] |= org_p2->entry[k] & MASK_PAGE_FLAG;

				// Run loop to copy P1
				org_p1 = (struct pagetable *)(org_p2->entry[k] & ~(MASK_PAGE_FLAG));
				vm_p1 = (struct pagetable *)(vm_p2->entry[k] & ~(MASK_PAGE_FLAG));
				org_p1 = phys_to_virt((u64)org_p1);
				vm_p1 = phys_to_virt((u64)vm_p1);

				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "            [*] P3[%d] %016lX %016lp %016lp\n", k, org_p2->entry[k], org_p1, vm_p1);
				memcpy(vm_p1, org_p1, 0x1000);
			}
		}
	}
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] complete\n");
}
#pragma endregion

#pragma region WORKAROUND
static void setup_workaround(void)
{
#if ENABLED_WORKAROUND
	char *function_list[WORK_AROUND_MAX_COUNT] = {
		"__netif_hash_nolisten",
		"__ip_select_ident",
		"secure_dccpv6_sequence_number",
		"secure_ipv4_port_ephemeral",
		"netif_receive_skb_internal",
		"__netif_receive_skb_core",
		"netif_rx_internal",
		"inet6_ehashfn.isra.6",
		"inet_ehashfn",
	};
	u64 log_addr, phy_addr;
	int i, index = 0;

	memset(&global_workaround, 0, sizeof(global_workaround));
	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Setup Workaround Address\n");

	for (i = 0; i < WORK_AROUND_MAX_COUNT; i++)
	{
		if (function_list[i] == 0)
		{
			break;
		}

		log_addr = sb_get_symbol_address(function_list[i]);
		if (log_addr <= 0)
		{
			not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX is not found\n", function_list[i], log_addr);
			continue;
		}
		phy_addr = virt_to_phys((void *)(log_addr & MASK_PAGEADDR));

		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] %s log %016lX %016lX\n", function_list[i], log_addr, phy_addr);
		global_workaround.addr_array[index] = phy_addr;
		global_workaround.count_array[index] = 0;

		index++;
	}
#endif
}
static int is_workaround_addr(u64 addr)
{
#if ENABLED_WORKAROUND
	int i;

	for (i = 0; i < WORK_AROUND_MAX_COUNT; i++)
	{
		if (global_workaround.addr_array[i] == (addr & MASK_PAGE_ADDR))
		{
			return 1;
		}
	}
#endif

	return 0;
}
#pragma endregion

#pragma region VM
static void vm_set_msr_write_bitmap(struct vm_control_register *vm_control_register, u64 msr_number)
{
	u64 byte_offset, bit_offset, bitmap_add = 2048;

	byte_offset = (msr_number & 0xFFFFFFF) / 8;
	bit_offset = (msr_number & 0xFFFFFFF) % 8;

	if (msr_number >= 0xC0000000)
	{
		bitmap_add += 1024;
	}

	((u8 *)vm_control_register->msr_bitmap_addr)[bitmap_add + byte_offset] = ((u8 *)vm_control_register->msr_bitmap_addr)[bitmap_add + byte_offset] | (0x01 << bit_offset);
}

u64 vm_check_alloc_page_table(struct pagetable *pagetable, int index)
{
	u64 value;

	if ((pagetable->entry[index] == 0) || (pagetable->entry[index] & MASK_PAGE_SIZE_FLAG))
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is null\n", pagetable, index);

		value = (u64)allocate_memory();
		if (value == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "vm_check_alloc_page fail \n");
			error_log(ERROR_MEMORY_ALLOC_FAIL);
		}

		memset((void *)value, 0, 0x1000);

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "vm_check_alloc_page log %lX, phy %lX \n", value, virt_to_phys((void *)value));
		value = virt_to_phys((void *)value);
	}
	else
	{
		value = pagetable->entry[index];
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "PageTable %016lX Index %d is not null %016lX\n", pagetable, index, value);
	}

	return value;
}

void vm_expand_page_table_entry(u64 phy_table_addr, u64 start_entry_and_flags, u64 entry_size, u64 dummy)
{
	u64 i;
	struct pagetable *log_addr;

	log_addr = (struct pagetable *)phys_to_virt((u64)phy_table_addr & ~(MASK_PAGE_FLAG));

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Expand page table entry. Start entry %016lX, size %016lX, phy table %016lX\n", start_entry_and_flags, entry_size, phy_table_addr);

	for (i = 0; i < 512; i++)
	{
		if (entry_size == S_4KB)
		{
			log_addr->entry[i] = (start_entry_and_flags & ~(MASK_PAGE_SIZE_FLAG)) + (i * entry_size);
		}
		else
		{
			log_addr->entry[i] = (start_entry_and_flags | MASK_PAGE_SIZE_FLAG) + (i * entry_size);
		}
	}
}

int vm_is_same_page_table_flag_or_size_flag_set(struct pagetable *vm, struct pagetable *init, int index)
{
	u64 vm_value;
	u64 init_value;

	if (init->entry[index] & MASK_PAGE_SIZE_FLAG)
	{
		return 1;
	}

	vm_value = vm->entry[index] & MASK_PAGE_FLAG_WO_DA;
	init_value = init->entry[index] & MASK_PAGE_FLAG_WO_DA;

	if (vm_value == init_value)
	{
		return 1;
	}

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not same %d\n", index);
	return 0;
}

int vm_is_new_page_table_needed(struct pagetable *vm, struct pagetable *init, int index)
{
	if ((vm->entry[index] != 0) && ((vm->entry[index] & MASK_PAGE_SIZE_FLAG) == 0))
	{
		return 0;
	}

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Index not present %d\n", index);

	return 1;
}

void insert_exception_to_vm(void)
{
	u64 info_field;
	read_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, &info_field);

	info_field = VM_BIT_VM_ENTRY_INT_INFO_UD;

	write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
	write_vmcs(VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE, 0);
}

static void remove_int_exception_from_vm(int vector)
{
	u64 info_field;

	read_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, &info_field);
	info_field &= ~((u64)0x01 << vector);
	write_vmcs(VM_CTRL_VM_ENTRY_INT_INFO_FIELD, info_field);
}

#pragma endregion

#pragma region KASLR
static int is_kaslr_working(void)
{
	u64 stored_text_addr, real_text_addr;

	stored_text_addr = get_symbol_address("_etext");
	real_text_addr = kallsyms_lookup_name("_etext");

	if (stored_text_addr != real_text_addr)
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "_etext System.map=%lX Kallsyms=%lX\n", stored_text_addr, real_text_addr);
		return 1;
	}

	return 0;
}

static int relocate_symbol(void)
{
	u64 stored_text_addr, real_text_addr, delta;
	int index, i;

	stored_text_addr = get_symbol_address("_etext");
	real_text_addr = kallsyms_lookup_name("_etext");

	delta = real_text_addr - stored_text_addr;
	if (delta == 0)
	{
		return 0;
	}

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Reloace symbol System.map=%lX Kallsyms=%lX\n", stored_text_addr, real_text_addr);

	index = get_kernel_version_index();
	if (index == -1)
	{
		return -1;
	}

	for (i = 0; i < SYMBOL_MAX_COUNT; i++)
	{
		global_symbol_table_array[index].symbol[i].addr += delta;
	}

	return 0;
}
#pragma endregion

#pragma region MAIN_VM_FUNCTIONS
static int vm_thread(void *argument)
{
	struct vm_host_register *host_register;
	struct vm_guest_register *guest_register;
	struct vm_control_register *control_register;
	u64 vm_err_number;
	unsigned long irqs;
	int result, cpu_id;

	cpu_id = smp_processor_id();

	// Disable MCE exception
	disable_and_change_machine_check_timer();

	// Synchronize processors
	atomic_dec(&global_thread_entry_count);
	while (atomic_read(&global_thread_entry_count) > 0)
	{
		schedule();
	}

	host_register = kmalloc(sizeof(struct vm_host_register), GFP_KERNEL | __GFP_COLD);
	guest_register = kmalloc(sizeof(struct vm_guest_register), GFP_KERNEL | __GFP_COLD);
	control_register = kmalloc(sizeof(struct vm_control_register), GFP_KERNEL | __GFP_COLD);

	if ((host_register == NULL) || (guest_register == NULL) || (control_register == NULL))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] Host or Guest or Control Register alloc fail\n", cpu_id);
		global_thread_result |= -1;
		return -1;
	}

	memset(host_register, 0, sizeof(struct vm_host_register));
	memset(guest_register, 0, sizeof(struct vm_guest_register));
	memset(control_register, 0, sizeof(struct vm_control_register));

	// Lock module_mutex, and protect module RO area, and syncronize all core
	if (cpu_id == 0)
	{
		mutex_lock(&module_mutex);
		protect_module_list_ro_area();

		atomic_set(&global_mutex_lock_flags, 1);
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] module mutex lock complete\n", cpu_id);
	}
	else
	{
		while (atomic_read(&global_mutex_lock_flags) == 0)
		{
			schedule();
		}
	}

	// Disable preemption and hold processors
	preempt_disable();

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Wait until thread executed\n", cpu_id);

	// Synchronize processors
	atomic_dec(&global_thread_run_flags);
	while (atomic_read(&global_thread_run_flags) > 0)
	{
		mdelay(1);
	}
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Complete to wait until thread executed\n", cpu_id);

	// Lock tasklist_lock and initialize the monitor.
	if (cpu_id == 0)
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize \n", cpu_id);

		// Duplicate page table for the host
		duplicate_page_table();

		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Dup talbe Initialize Complete\n", cpu_id);

		/// Lock tasklist
		read_lock(global_tasklist_lock);

		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize \n", cpu_id);

		init_monitor();

		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize Complete \n", cpu_id);

		// Unlock tasklist
		read_unlock(global_tasklist_lock);
	}

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Framework Initialize Waiting\n", cpu_id);

	atomic_dec(&global_framework_init_flags);
	while (atomic_read(&global_framework_init_flags) > 0)
	{
		mdelay(1);
	}
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Complete\n", cpu_id);

	// Disable interrupt before VM launch
	local_irq_save(irqs);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] IRQ Lock complete\n", cpu_id);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Wait until stable status\n", cpu_id);
	mdelay(10);

	atomic_dec(&global_sync_flags);
	while (atomic_read(&global_sync_flags) > 0)
	{
		mdelay(1);
	}
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Ready to go!!\n", cpu_id);

#if ENABLED_IOMMU
	// Lock iommu and synchronize processors
	if (cpu_id == 0)
	{
		lock_iommu();
		atomic_set(&global_iommu_complete_flags, 1);
	}
	else
	{
		while (atomic_read(&global_iommu_complete_flags) == 0)
		{
			mdelay(1);
		}
	}
#endif

	while (atomic_read(&global_enter_count) != cpu_id)
	{
		mdelay(1);
	}

	// Initialize VMX
	if (init_vmx(cpu_id) < 0)
	{
		atomic_set(&global_enter_flags, 0);
		atomic_inc(&global_enter_count);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "VM [%d] init_vmx fail\n", cpu_id);
		goto ERROR;
	}

	protect_gdt(cpu_id);
	setup_vm_host_register(host_register);
	setup_vm_guest_register(guest_register, host_register);
	setup_vm_control_register(control_register, cpu_id);
	setup_vmcs(host_register, guest_register, control_register);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "VM [%d] Launch Start\n", cpu_id);
	result = vm_launch();

	atomic_set(&global_enter_flags, 0);
	atomic_inc(&global_enter_count);

	if (result == -2)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Launch Valid Fail\n", cpu_id);
		read_vmcs(VM_DATA_INST_ERROR, &vm_err_number);
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Error Number [%d]\n", cpu_id, (int)vm_err_number);
		error_log(ERROR_LAUNCH_FAIL);

		goto ERROR;
	}
	else if (result == -1)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VM [%d] Launch Invalid Fail\n", cpu_id);
		error_log(ERROR_LAUNCH_FAIL);

		goto ERROR;
	}
	else
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] VM [%d] Launch Success\n", cpu_id);
	}

	atomic_dec(&global_framework_init_start_flags);
	while (atomic_read(&global_framework_init_start_flags) > 0)
	{
		mdelay(1);
	}

	// Enable interrupt
	local_irq_restore(irqs);
	preempt_enable();

	if (cpu_id == 0)
	{
		mutex_unlock(&module_mutex);
	}
	atomic_dec(&global_complete_flags);

	return 0;

ERROR:
	global_thread_result |= -1;

	local_irq_restore(irqs);
	preempt_enable();

	if (cpu_id == 0)
	{
		mutex_unlock(&module_mutex);
	}
	atomic_dec(&global_complete_flags);

	return -1;
}

static int init_vmx(int cpu_id)
{
	u64 vmx_msr, msr, cr4, cr0, value;
	u32 *vmx_VMCS_log_addr, *vmx_VMCS_phy_addr, *guest_VMCS_log_addr, *guest_VMCS_phy_addr;
	int result;

	// To handle the SMXE exception.
	if (global_support_smx)
	{
		cr4 = get_cr4();
		cr4 |= CR4_BIT_SMXE;
		set_cr4(cr4);
	}

	vmx_msr = cu_read_msr(MSR_IA32_VM_BASIC);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_BASIC MSR Value %016lX\n", vmx_msr);

	value = cu_read_msr(MSR_IA32_VMX_ENTRY_CTRLS);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_ENTRY_CTRLS MSR Value %016lX\n", value);

	value = cu_read_msr(MSR_IA32_VMX_EXIT_CTLS_INDEX);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_VMX_EXIT_CTRLS MSR Value %016lX\n", value);

	msr = cu_read_msr(MSR_IA32_FEATURE_CONTROL);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_FEATURE_CONTROL MSR Value %016lX\n", msr);

	msr = cu_read_msr(MSR_IA32_VMX_PROCBASED_CTLS);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS MSR Value %016lX\n", msr);

	msr = cu_read_msr(MSR_IA32_VMX_PROCBASED_CTLS2);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_PROCBASED_CTRLS2 MSR Value %016lX\n", msr);

	msr = cu_read_msr(MSR_IA32_VMX_EPT_VPID_CAP);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_IA32_VMX_EPT_VPID MSR Value %016lX\n", msr);

	msr = cu_read_msr(MSR_IA32_EFER);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IA32_EFER MSR Value %016lX\n", msr);

	cr0 = get_cr0();
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] CR0 %016lX\n", cr0);

	cr4 = get_cr4();
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Before Enable VMX CR4 %016lX\n", cr4);

	enable_vmx();
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Enable VMX CR4\n");

	cr4 = get_cr4();
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] After Enable VMX CR4 %016lX\n", cr4);

	vmx_VMCS_log_addr = (u32 *)(global_vmx_on_vmcs_log_addr[cpu_id]);
	vmx_VMCS_phy_addr = (u32 *)virt_to_phys(vmx_VMCS_log_addr);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical VMCS %016lX\n", vmx_VMCS_phy_addr);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Start VMX\n");

	// First data of VMCS should be VMX revision number
	vmx_VMCS_log_addr[0] = (u32)vmx_msr;
	result = start_vmx(&vmx_VMCS_phy_addr);
	if (result == 0)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] VMXON Success\n");
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] VMXON Fail\n");
		error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Preparing Geust\n");

	// Allocate kernel memory for Guest VCMS
	guest_VMCS_log_addr = (u32 *)(global_guest_vmcs_log_addr[cpu_id]);
	guest_VMCS_phy_addr = (u32 *)virt_to_phys(guest_VMCS_log_addr);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Alloc Physical Guest VMCS %016lX\n", guest_VMCS_phy_addr);

	// First data of VMCS should be VMX revision number
	guest_VMCS_log_addr[0] = (u32)vmx_msr;
	result = clear_vmcs(&guest_VMCS_phy_addr);
	if (result == 0)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VCMS Clear Success\n");
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] Guest VCMS Clear Fail\n");
		error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	result = load_vmcs((void **)&guest_VMCS_phy_addr);
	if (result == 0)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Guest VCMS Load Success\n");
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "    [*] Guest VCMS Load Fail\n");
		error_log(ERROR_LAUNCH_FAIL);
		return -1;
	}

	return 0;
}
#pragma endregion

#pragma region SYNC_PAGETABLE
u64 sync_page_table(u64 addr)
{
	struct pagetable *init_p4, *init_p3, *init_p2, *init_p1, *vm_p4, *vm_p3, *vm_p2, *vm_p1;
	struct vm_page_entry phy_entry;

	u64 p4_index, p3_index, p2_index, p1_index, value, expand_value = 0;

	// Skip direct mapping area
	if (((u64)page_offset_base <= addr) && (addr < (u64)page_offset_base + (64 * S_1TB)))
	{
		return 0;
	}

	// Skip static kernel object area
	if (is_addr_in_kernel_ro_area((void *)addr))
	{
		return 0;
	}

	// Get physical page by traversing page table of the guest
	get_phy_from_log(global_vm_init_phy_p4, addr, &phy_entry);
	if (!IS_PRESENT(phy_entry.phy_addr[3]))
	{
		return 0;
	}

	init_p4 = (struct pagetable *)global_vm_init_phy_p4;
	init_p4 = phys_to_virt((u64)init_p4);
	vm_p4 = phys_to_virt(global_vm_host_phy_p4);

	p4_index = (addr / S_512GB) % 512;
	p3_index = (addr / S_1GB) % 512;
	p2_index = (addr / S_2MB) % 512;
	p1_index = (addr / S_4KB) % 512;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "addr = %016lX P4 index %ld %016lX %016lX %016X\n", addr, p4_index, vm_p4, init_p4, init_p4->entry[p4_index]);

	init_p3 = (struct pagetable *)(init_p4->entry[p4_index]);
	if ((init_p3 == 0) || ((u64)init_p3 & MASK_PAGE_SIZE_FLAG))
	{
		vm_p4->entry[p4_index] = (u64)init_p3;

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "p4 addr = %016lX sync\n", addr);
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "p3 has size flags or 0\n");

		goto EXIT;
	}

	if (vm_is_new_page_table_needed(vm_p4, init_p4, p4_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_p4, p4_index);
		vm_expand_page_table_entry(value, vm_p4->entry[p4_index], S_1GB, init_p4->entry[p4_index]);
		sync_page_table_flag(vm_p4, init_p4, p4_index, value);

		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "New table is needed. Expand Log %016lX Phy %016lX", addr, (u64)virt_to_phys((void *)addr));
		if (expand_value == 0)
		{
			expand_value = S_1GB;
		}
	}

	init_p3 = phys_to_virt((u64)init_p3 & ~(MASK_PAGE_FLAG));
	vm_p3 = (struct pagetable *)(vm_p4->entry[p4_index]);
	vm_p3 = phys_to_virt((u64)vm_p3 & ~(MASK_PAGE_FLAG));

	init_p2 = (struct pagetable *)(init_p3->entry[p3_index]);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p3 index %d %016lX %016lX %016lX\n", p3_index, vm_p3, init_p3, init_p3->entry[p3_index]);

	if ((init_p2 == 0) || ((u64)init_p2 & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_p3->entry[p3_index] != (u64)init_p2)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "p2 addr = %016lX sync\n", addr);
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");
		}
		else
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p2 is same");
		}

		vm_p3->entry[p3_index] = (u64)init_p2;

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "p2 has size flags or 0\n");

		goto EXIT;
	}

	if (vm_is_new_page_table_needed(vm_p3, init_p3, p3_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_p3, p3_index);
		vm_expand_page_table_entry(value, vm_p3->entry[p3_index], S_2MB, init_p3->entry[p3_index]);
		sync_page_table_flag(vm_p3, init_p3, p3_index, value);

		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "New p2 is needed. Expand Log %016lX Phy %016lX", addr, (u64)virt_to_phys((void *)addr));

		if (expand_value == 0)
		{
			expand_value = S_2MB;
		}
	}

	init_p2 = phys_to_virt((u64)init_p2 & ~(MASK_PAGE_FLAG));
	vm_p2 = (struct pagetable *)(vm_p3->entry[p3_index]);
	vm_p2 = phys_to_virt((u64)vm_p2 & ~(MASK_PAGE_FLAG));

	init_p1 = (struct pagetable *)(init_p2->entry[p2_index]);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p2 index %d %016lX %016lX %016lX\n", p2_index, vm_p2, init_p2, init_p2->entry[p2_index]);

	if ((init_p1 == 0) || ((u64)init_p1 & MASK_PAGE_SIZE_FLAG))
	{
		if (vm_p2->entry[p2_index] != (u64)init_p1)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "p2 addr = %016lX sync\n", addr);
			not_printf(LOG_LEVEL_ERROR, LOG_INFO "******************* INFO *******************");
		}
		else
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p2 is same");
		}

		vm_p2->entry[p2_index] = (u64)init_p1;

		not_printf(LOG_LEVEL_ERROR, LOG_INFO "p1 has size flags or 0\n");

		goto EXIT;
	}

	if (vm_is_new_page_table_needed(vm_p2, init_p2, p2_index) == 1)
	{
		value = vm_check_alloc_page_table(vm_p2, p2_index);
		vm_expand_page_table_entry(value, vm_p2->entry[p2_index], S_4KB, init_p2->entry[p2_index]);
		sync_page_table_flag(vm_p2, init_p2, p2_index, value);

		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "New p1 is needed. Expand Log %016lX Phy %016lX", addr, (u64)virt_to_phys((void *)addr));

		if (expand_value == 0)
		{
			expand_value = S_4KB;
		}
	}
	init_p1 = phys_to_virt((u64)init_p1 & ~(MASK_PAGE_FLAG));
	vm_p1 = (struct pagetable *)(vm_p2->entry[p2_index]);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p1 index %d Physical %016lX %016lX\n", p1_index, vm_p1, init_p1);
	vm_p1 = phys_to_virt((u64)vm_p1 & ~(MASK_PAGE_FLAG));
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p1 index %d %016lX %016lX %016lX\n", p1_index, vm_p1, init_p1, init_p1->entry[p1_index]);

	if (vm_p1->entry[p1_index] != init_p1->entry[p1_index])
	{
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "******************* INFO *******************");
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "p1 addr = %016lX sync\n", addr);
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "p1 index %d %016lX %016lX %016lX\n", p1_index, vm_p1, init_p1, init_p1->entry[p1_index]);
		not_printf(LOG_LEVEL_DEBUG, LOG_INFO "******************* INFO *******************");
	}
	else
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "p1 is same");
	}

	vm_p1->entry[p1_index] = init_p1->entry[p1_index];

EXIT:

	// Update page table to CPU
	set_cr3(global_vm_host_phy_p4);
	return expand_value;
}

static void sync_page_table_flag(struct pagetable *vm, struct pagetable *init, int index, u64 addr)
{
	u64 value;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "SyncPage %016lX %016lX Index %d %016lX\n", vm->entry[index], init->entry[index], index, addr);

	value = addr & ~(MASK_PAGE_FLAG);
	value |= init->entry[index] & MASK_PAGE_FLAG;

	vm->entry[index] = value;
}
#pragma endregion

#pragma region SHUTDOWN
static void trigger_shutdown_timer(void)
{
	if (is_system_shutting_down() == 0)
	{
		return;
	}

	if (atomic_cmpxchg(&global_is_shutdown_trigger_set, 0, 1) == 0)
	{
#if ENABLED_IOMMU
		unlock_iommu();
#endif

		global_shutdown_jiffies = jiffies;
	}

	return;
}

static int is_system_shutting_down(void)
{
	if ((system_state == SYSTEM_RUNNING) || (system_state == SYSTEM_BOOTING))
	{
		return 0;
	}

	return 1;
}

static int is_shutdown_timer_expired(void)
{
	u64 value;

	if (global_is_shutdown_trigger_set.counter == 0)
	{
		return 0;
	}

	value = jiffies - global_shutdown_jiffies;

	if (jiffies_to_msecs(value) >= SHUTDOWN_TIME_LIMIT_MS)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM[%d] Shutdown timer is expired\n", smp_processor_id());
		error_log(ERROR_SHUTDOWN_TIME_OUT);
		global_shutdown_jiffies = jiffies;
		return 1;
	}

	return 0;
}
#pragma endregion

#pragma region CALC
static u64 calc_vm_pre_timer_value(void)
{
	u64 scale;

	scale = cu_read_msr(MSR_IA32_VMX_MISC);
	scale &= 0x1F;

	return (VM_PRE_TIMER_VALUE >> scale);
}

static u64 calc_dest_mem_addr(struct vm_exit_guest_register *guest_context, u64 inst_info)
{
	u64 dest_addr = 0;

	if (!(inst_info & VM_INST_INFO_IDX_REG_INVALID))
	{
		dest_addr += get_reg_value_from_index(guest_context, VM_INST_INFO_IDX_REG(inst_info));
		dest_addr = dest_addr << VM_INST_INFO_SCALE(inst_info);
	}

	if (!(inst_info & VM_INST_INFO_BASE_REG_INVALID))
	{
		dest_addr += get_reg_value_from_index(guest_context, VM_INST_INFO_BASE_REG(inst_info));
	}

	return dest_addr;
}
#pragma endregion

#pragma region HELPERS
void not_printf(int level, char *format, ...)
{
	va_list arg_list;

	if (level <= LOG_LEVEL)
	{
		va_start(arg_list, format);
		vprintk(format, arg_list);
		va_end(arg_list);
	}
}

static void not_print_vm_result(const char *string, int result)
{
	return;
	if (result == 1)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "%s Success\n", string);
	}
	else
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "%s Fail\n", string);
	}
}

void error_log(int error_code)
{
	not_printf(LOG_LEVEL_ERROR, LOG_ERROR "errorcode=%d\n", error_code);
}

static int get_kernel_version_index(void)
{
	int i, match_index = -1;
	struct new_utsname *name;

	name = utsname();

	for (i = 0; i < (sizeof(global_kernel_version) / sizeof(char *)); i++)
	{
		if (strcmp(name->version, global_kernel_version[i]) == 0)
		{
			match_index = i;
			break;
		}
	}

	return match_index;
}
#pragma endregion

#pragma region BREAKPOINTS

static void init_breakpoint_address(void){

	
	global_create_task = get_symbol_address("wake_up_new_task");
	global_delete_task = get_symbol_address("proc_flush_task");

	#if ENABLED_STAROZA
	global_syscall_64 = get_symbol_address("entry_SYSCALL_64");
	global_commit_creds = get_symbol_address("commit_creds");
	#else
	global_create_module = get_symbol_address("ftrace_module_init");
	global_delete_module  = get_symbol_address("free_module");
	#endif

}
#if ENABLED_STAROZA
static void set_syscall_monitor_mode(int cpu_id)
{
	disable_breakpoints();

	set_debugreg(global_create_task, 0);
	set_debugreg(global_delete_task, 1);
	set_debugreg(global_syscall_64, 2);
	set_debugreg(global_commit_creds, 3);

	enable_breakpoints();
}



static void handle_syscall_breakpoints(int cpu_id, u64 dr6, struct vm_exit_guest_register *guest_context)
{
	u64 syscall_number;
	struct task_struct *task;

	if (dr6 & DR_BIT_SYSCALL_64)
	{
		syscall_number = (int)guest_context->rax;

		// If cred is changed anbornally or should be killed, change syscall number to __NR_exit
		if (callback_check_cred_update_syscall(cpu_id, current, syscall_number) != 0)
		{
			guest_context->rax = __NR_exit;
			not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] An abnormal privilege escalation is detected. [%s][PID %d, TGID %d] is killed\n", cpu_id, current->comm, current->pid, current->tgid);
		}
	}

	/* Create process. */
	if (dr6 & DR_BIT_CREATE_TASK)
	{
		callback_add_task(cpu_id, guest_context);
		task = (struct task_struct *)guest_context->rdi;
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] [%s][PID %d] new task %s [PID %d, TGID %d] is created\n", cpu_id, current->comm, current->pid, task->comm, task->pid, task->tgid);
	}

	/* Terminate process. */
	if (dr6 & DR_BIT_DELETE_TASK)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] is deleted\n", cpu_id, current->comm, current->pid, current->tgid);
		callback_del_task(cpu_id, guest_context);
	}

	/* Change cred. */
	if (dr6 & DR_BIT_COMMIT_CREDS)
	{
		callback_update_cred(cpu_id, current, (struct cred *)(guest_context->rdi));
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM [%d] [%s][PID %d, TGID %d] cred is changed\n", cpu_id, current->comm, current->pid, current->tgid);
	}
}

#else

static void set_task_module_monitor_breakpoints(int cpu_id)
{
	disable_breakpoints();

	set_debugreg(global_create_task, 0);
	set_debugreg(global_delete_task, 1);
	set_debugreg(global_create_module, 2);
	set_debugreg(global_delete_module, 3);

	enable_breakpoints();
}

static void handle_process_and_module_breakpoints(int cpu_id, u64 dr6, struct vm_exit_guest_register* guest_context)
{

/* Create process case. */
	if (dr6 & DR_BIT_CREATE_TASK)
	{
		callback_add_task(cpu_id, guest_context);
	}

	/* Terminate process case. */
	if (dr6 & DR_BIT_DELETE_TASK)
	{
		callback_del_task(cpu_id, guest_context);
	}

	/* Load module case. */
	if (dr6 & DR_BIT_CREATE_MODULE)
	{
		callback_insmod(cpu_id);
	}

	/* Unload module case. */
	if (dr6 & DR_BIT_DELETE_MODULE)
	{
		callback_rmmod(cpu_id, guest_context);
	}

}

static void set_process_module_monitor_mode(int cpu_id)
{
	disable_breakpoints();

	set_debugreg(global_create_task, 0);
	set_debugreg(global_delete_task, 1);
	set_debugreg(global_create_module, 2);
	set_debugreg(global_delete_module, 3);

	enable_breakpoints();
}


#endif

static void enable_breakpoints(void)
{
	unsigned long dr7;

	dr7 = custom_encode_dr7(0, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(1, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(2, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= custom_encode_dr7(3, X86_BREAKPOINT_LEN_X, X86_BREAKPOINT_EXECUTE);
	dr7 |= (0x01 << 10);

	set_debugreg(dr7, 7);
}

static void disable_breakpoints(void)
{
	set_debugreg(0, 7);
}

#pragma endregion

static void disable_and_change_machine_check_timer(void)
{
	typedef void (*mce_timer_delete_all)(void);
	typedef void (*mce_cpu_restart)(void *data);
	u64 cr4;

	unsigned long *check_interval;
	mce_timer_delete_all delete_timer_fp;
	mce_cpu_restart restart_cpu_fp;

	// Disable MCE event
	cr4 = get_cr4();
	cr4 &= ~(CR4_BIT_MCE);
	set_cr4(cr4);
	disable_irq(VM_INT_MACHINE_CHECK);

	// Change MCE polling timer
	if (smp_processor_id() == 0)
	{
		check_interval = (unsigned long *)get_symbol_address("check_interval");
		delete_timer_fp = (mce_timer_delete_all)get_symbol_address("mce_timer_delete_all");
		restart_cpu_fp = (mce_cpu_restart)get_symbol_address("mce_cpu_restart");

		// Set seconds for timer interval and restart timer
		*check_interval = VM_MCE_TIMER_VALUE;

		delete_timer_fp();
		on_each_cpu(restart_cpu_fp, NULL, 1);
	}
}

static void advance_vm_guest_rip(void)
{
	u64 inst_delta, rip;

	read_vmcs(VM_DATA_VM_EXIT_INST_LENGTH, &inst_delta);
	read_vmcs(VM_GUEST_RIP, &rip);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "VM_DATA_VM_EXIT_INST_LENGTH: %016lX, VM_GUEST_RIP: %016lX\n", inst_delta, rip);
	write_vmcs(VM_GUEST_RIP, rip + inst_delta);
}

static u64 get_desc_access(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct *gdt;
	u64 total_access = 0;
	u64 access = 0;

	if (offset == 0)
	{
		// Return unused value
		return 0x10000;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct *)(gdtr.address + (offset & ~MASK_GDT_ACCESS));
	access = gdt->b >> 8;

	/* type: 4, s: 1, dpl: 2, p: 1; limit: 4, avl: 1, l: 1, d: 1, g: 1, base2: 8 */
	total_access = access & 0xF0FF;
	return total_access;
}

u64 get_symbol_address(char *symbol)
{
	u64 log_addr = 0;
#if ENABLED_PRE_SYMBOL
	int i, match_index;
#endif

	log_addr = kallsyms_lookup_name(symbol);
#if ENABLED_PRE_SYMBOL
	if (log_addr == 0)
	{
		match_index = get_kernel_version_index();

		if (match_index == -1)
		{
			return 0;
		}

		for (i = 0; i < SYMBOL_MAX_COUNT; i++)
		{
			if (strcmp(global_symbol_table_array[match_index].symbol[i].name, symbol) == 0)
			{
				log_addr = global_symbol_table_array[match_index].symbol[i].addr;
				break;
			}
		}
	}
#endif

	return log_addr;
}

static void get_object_pointers(void)
{
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Get function pointers\n");

	global_modules_ptr = (struct list_head *)get_symbol_address("modules");

	global_root_file_ptr = filp_open("/", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(global_root_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/ Open VFS Object Fail\n");
	}

	global_proc_file_ptr = filp_open("/proc", O_RDONLY | O_DIRECTORY, 0);
	if (IS_ERR(global_proc_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc Open VFS Object Fail\n");
	}

	global_tcp_file_ptr = filp_open("/proc/net/tcp", O_RDONLY, 0);
	if (IS_ERR(global_tcp_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/tcp Open VFS Object Fail\n");
	}

	global_udp_file_ptr = filp_open("/proc/net/udp", O_RDONLY, 0);
	if (IS_ERR(global_udp_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/udp Open VFS Object Fail\n");
	}

	global_tcp6_file_ptr = filp_open("/proc/net/tcp6", O_RDONLY, 0);
	if (IS_ERR(global_tcp6_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/tcp6 Open VFS Object Fail\n");
	}

	global_udp6_file_ptr = filp_open("/proc/net/udp6", O_RDONLY, 0);
	if (IS_ERR(global_udp6_file_ptr))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "/proc/net/udp6 Open VFS Object Fail\n");
	}

	if (sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &global_udp_sock) < 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "UDP Socket Object Open Fail\n");
	}

	if (sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &global_tcp_sock) < 0)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "TCP Socket Object Open Fail\n");
	}
}

static void set_reg_value_from_index(struct vm_exit_guest_register *guest_context, int index, u64 reg_value)
{
	switch (index)
	{
	case REG_NUM_RAX:
		guest_context->rax = reg_value;
		break;

	case REG_NUM_RCX:
		guest_context->rcx = reg_value;
		break;

	case REG_NUM_RDX:
		guest_context->rdx = reg_value;
		break;

	case REG_NUM_RBX:
		guest_context->rbx = reg_value;
		break;

	case REG_NUM_RSP:
		// guest_context->rsp = reg_value;
		break;

	case REG_NUM_RBP:
		guest_context->rbp = reg_value;
		break;

	case REG_NUM_RSI:
		guest_context->rsi = reg_value;
		break;

	case REG_NUM_RDI:
		guest_context->rdi = reg_value;
		break;

	case REG_NUM_R8:
		guest_context->r8 = reg_value;
		break;

	case REG_NUM_R9:
		guest_context->r9 = reg_value;
		break;

	case REG_NUM_R10:
		guest_context->r10 = reg_value;
		break;

	case REG_NUM_R11:
		guest_context->r11 = reg_value;
		break;

	case REG_NUM_R12:
		guest_context->r12 = reg_value;
		break;

	case REG_NUM_R13:
		guest_context->r13 = reg_value;
		break;

	case REG_NUM_R14:
		guest_context->r14 = reg_value;
		break;

	case REG_NUM_R15:
		guest_context->r15 = reg_value;
		break;
	}
}

static u64 get_reg_value_from_index(struct vm_exit_guest_register *guest_context, int index)
{
	u64 reg_value = 0;

	switch (index)
	{
	case REG_NUM_RAX:
		reg_value = guest_context->rax;
		break;

	case REG_NUM_RCX:
		reg_value = guest_context->rcx;
		break;

	case REG_NUM_RDX:
		reg_value = guest_context->rdx;
		break;

	case REG_NUM_RBX:
		reg_value = guest_context->rbx;
		break;

	case REG_NUM_RSP:
		// reg_value = guest_context->rsp;
		break;

	case REG_NUM_RBP:
		reg_value = guest_context->rbp;
		break;

	case REG_NUM_RSI:
		reg_value = guest_context->rsi;
		break;

	case REG_NUM_RDI:
		reg_value = guest_context->rdi;
		break;

	case REG_NUM_R8:
		reg_value = guest_context->r8;
		break;

	case REG_NUM_R9:
		reg_value = guest_context->r9;
		break;

	case REG_NUM_R10:
		reg_value = guest_context->r10;
		break;

	case REG_NUM_R11:
		reg_value = guest_context->r11;
		break;

	case REG_NUM_R12:
		reg_value = guest_context->r12;
		break;

	case REG_NUM_R13:
		reg_value = guest_context->r13;
		break;

	case REG_NUM_R14:
		reg_value = guest_context->r14;
		break;

	case REG_NUM_R15:
		reg_value = guest_context->r15;
		break;
	}

	return reg_value;
}

static void disable_desc_monitor(void)
{
	u64 reg_value;

	read_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, &reg_value);
	reg_value &= ~((u64)(VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE));
	reg_value &= 0xFFFFFFFF;
	write_vmcs(VM_CTRL_SEC_PROC_BASED_EXE_CTRL, reg_value);
}

void get_phy_from_log(u64 p4_phy_addr, u64 addr, struct vm_page_entry *out_data)
{
	struct pagetable *p4, *p3, *p2, *p1;

	u64 p4_index, p3_index, p2_index, p1_index, value, addr_value;

	p4_index = (addr / S_512GB) % 512;
	p3_index = (addr / S_1GB) % 512;
	p2_index = (addr / S_2MB) % 512;
	p1_index = (addr / S_4KB) % 512;

	memset(out_data, 0, sizeof(struct vm_page_entry));

	/* P4 */
	p4 = phys_to_virt((u64)p4_phy_addr);
	value = p4->entry[p4_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[0] = value;

	if (!IS_PRESENT(value))
	{
		return;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += p3_index * S_1GB + p2_index * S_2MB + p1_index * S_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGE_FLAG_WO_SIZE);
		return;
	}

	/* p3 */
	p3 = phys_to_virt((u64)addr_value);
	value = p3->entry[p3_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[1] = value;

	if (!IS_PRESENT(value))
	{
		return;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += p2_index * S_2MB + p1_index * S_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGE_FLAG_WO_SIZE);
		return;
	}

	/* p2 */
	p2 = phys_to_virt((u64)addr_value);
	value = p2->entry[p2_index];
	addr_value = GET_ADDR(value);
	out_data->phy_addr[2] = value;

	if (!IS_PRESENT(value))
	{
		return;
	}

	if (IS_SIZE_FLAG_SET(value))
	{
		addr_value += p1_index * S_4KB;
		out_data->phy_addr[3] = addr_value | (value & MASK_PAGE_FLAG_WO_SIZE);
		return;
	}

	/* p1 */
	p1 = phys_to_virt((u64)addr_value);
	value = p1->entry[p1_index];
	out_data->phy_addr[3] = value;
}

static int check_gdtr(int cpu_id)
{
	struct desc_ptr gdtr;
	struct desc_struct *gdt;
	int result = 0, i;
	u64 address, size;

	read_vmcs(VM_GUEST_GDTR_BASE, &address);
	read_vmcs(VM_GUEST_GDTR_LIMIT, &size);
	gdtr.address = address;
	gdtr.size = (u16)size;

	if ((is_system_shutting_down() == 1))
	{
		return 0;
	}

	if (gdtr.address != global_gdtr_array[cpu_id].address)
	{
		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] Structure not same, Org Addr %016lX, Size %d, New Addr %016lX, Size %d\n", cpu_id, global_gdtr_array[cpu_id].address, global_gdtr_array[cpu_id].size, gdtr.address, gdtr.size);

		return -1;
	}

	if (gdtr.size >= 0x1000)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_ERROR "VM [%d] GDT size is over, Org Addr %016lX, Size %d, New Addr %016lX, Size %d\n", cpu_id, global_gdtr_array[cpu_id].address, global_gdtr_array[cpu_id].size, gdtr.address, gdtr.size);
	}

	// Check descriptors in GDT
	for (i = 0; i < gdtr.size; i += 8)
	{
		gdt = (struct desc_struct *)(gdtr.address + i);
		// Is the descriptor system? Can user level access the descriptor?
		if ((gdt->s == 0) && (gdt->p == 1) && (gdt->dpl == 3))
		{
			if ((gdt->type == GDT_TYPE_64BIT_CALL_GATE) ||
				(gdt->type == GDT_TYPE_64BIT_INTERRUPT_GATE) ||
				(gdt->type == GDT_TYPE_64BIT_TRAP_GATE))
			{
				not_printf(LOG_LEVEL_NORMAL, LOG_INFO "VM [%d] index %d low %08X high %08X\n", cpu_id, i, gdt->a, gdt->b);

				result = -1;
				break;
			}
			else if ((gdt->type == GDT_TYPE_64BIT_LDT) ||
					 (gdt->type == GDT_TYPE_64BIT_TSS) ||
					 (gdt->type == GDT_TYPE_64BIT_TSS_BUSY))
			{
				// For 16byte Descriptor
				i += 8;
			}
		}
	}

	return result;
}

static u64 custom_get_desc_base(u64 offset)
{
	struct desc_ptr gdtr;
	struct desc_struct *gdt;
	u64 qwTotalBase = 0;
	u64 base0 = 0, base1 = 0, base2 = 0;

	if (offset == 0)
	{
		return 0;
	}

	native_store_gdt(&gdtr);
	gdt = (struct desc_struct *)(gdtr.address + (offset & ~MASK_GDT_ACCESS));

	base0 = gdt->base0;
	base1 = gdt->base1;
	base2 = gdt->base2;

	qwTotalBase = base0 | (base1 << 16) | (base2 << 24);
	return qwTotalBase;
}

static unsigned long custom_encode_dr7(int index, unsigned int len, unsigned int type)
{
	unsigned long value;

	value = (len | type) & 0xf;
	value <<= (DR_CONTROL_SHIFT + index * DR_CONTROL_SIZE);
	value |= (DR_GLOBAL_ENABLE << (index * DR_ENABLE_SIZE));

	return value;
}

module_init(holdup_init);
module_exit(holdup_exit);

MODULE_AUTHOR("Ron Mashkovich & Yonatan Gutchin");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("HoldUp is a security monitoring framework for linux kernel using virtualization technologies.");
