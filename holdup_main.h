#ifndef __HOLDUP_MAIN_H__
#define __HOLDUP_MAIN_H__


#include "config.h"

/* Log level. */
#define LOG_LEVEL						(LOG_LEVEL_NORMAL)
#define LOG_LEVEL_ERROR					0
#define LOG_LEVEL_NORMAL				1
#define LOG_LEVEL_DEBUG					2
#define LOG_LEVEL_DETAIL				3

/* Log type. */
#define LOG_INFO						KERN_INFO "holdup: "
#define LOG_ERROR						KERN_ERR "holdup: "
#define LOG_WARNING						KERN_WARNING "holdup: "

/* Utility macros. */
#define CEIL(X, Y)						(((X) + (Y) - 1) / (Y))
#define MASK_GDT_ACCESS					((u64)0x03)


#define TIMER_INTERVAL 	100000 //10 ms

#define VM_PRE_TIMER_VALUE	((u64)tsc_khz * 1024 * TIMER_INTERVAL / 1000000)
#define VM_MCE_TIMER_VALUE	(1)

/* Shutdown timeout limit, 10 minute. */
#define SHUTDOWN_TIME_LIMIT_MS				(10 * 60 * 1000)

#define HIDE_TIME_BUFFER_MS		(1000)

#define MAX_PROCESSOR_COUNT 				256
#define MAX_RO_ARRAY_COUNT 					2048
#define MAX_STACK_SIZE						0x800000

#define WORK_AROUND_MAX_COUNT				30
#define SYMBOL_MAX_COUNT					30

#define VMCS_SIZE							0x2000
#define IO_BITMAP_SIZE						0x1000
#define VIRT_APIC_PAGE_SIZE 				0x1000

#ifdef __GNUC__
#pragma region VMX_ENABLING
#endif

/* MSRs bits used for VMX enabling 
 * SRC: https://github.com/ionescu007/SimpleVisor/blob/master/vmx.h
 */
#define MSR_IA32_VM_BASIC					0x480
#define MSR_IA32_VMX_EXIT_CTLS_INDEX		0x483
#define MSR_IA32_VMX_TRUE_EXIT_CTRLS		0x48F
#define MSR_IA32_VMX_ENTRY_CTRLS			0x484
#define MSR_IA32_VMX_TRUE_ENTRY_CTRLS		0x490

#ifdef __GNUC__
#pragma endregion
#endif 

#define MSR_FS_BASE_ADDR					0xC0000100 // Map of BASE Address of FS
#define MSR_GS_BASE_ADDR					0xC0000101 // Map of BASE Address of GS
#define MSR_IA32_EFER						0xC0000080 // Extended Feature Enables
/* Global Performance Counter Control.
 * Counter increments while the result of ANDing the respective enable bit in this
 * MSR with the corresponding OS or USR bits in the general-purpose or fixed counter
 * control MSR is true.
 */
#define MSR_IA32_PERF_GLOBAL_CTRL			0x38F 
#define MSR_IA32_PAT						0x277 // Page attribute table control.

/* https://wiki.osdev.org/SYSENTER#MSRs */
#define MSR_IA32_STAR						0xC0000081 // System Call Target Address
#define MSR_IA32_LSTAR						0xC0000082 // IA-32e Mode System Call Target Address
#define MSR_IA32_FMASK						0xC0000084 // System Call Flag Mask
 
/* VMCS field encoding - 16 bits guest fields */
/* https://github.com/zer0mem/HyperVisor/blob/master/Common/CPU/vmcs.h */

#define VM_GUEST_ES_SELECTOR				0x800
#define VM_GUEST_CS_SELECTOR				0x802
#define VM_GUEST_SS_SELECTOR				0x804
#define VM_GUEST_DS_SELECTOR				0x806
#define VM_GUEST_FS_SELECTOR				0x808
#define VM_GUEST_GS_SELECTOR				0x80A
#define VM_GUEST_LDTR_SELECTOR				0x80C
#define VM_GUEST_TR_SELECTOR				0x80E

/* VMCS field encoding - 64 Bits guest fields */
#define VM_VMCS_LINK_PTR					0x2800
#define VM_GUEST_DEBUGCTL					0x2802
#define VM_GUEST_PAT						0x2804
#define VM_GUEST_EFER						0x2806
#define VM_GUEST_PERF_GLOBAL_CTRL			0x2808

/* VMCS field encoding - 32 Bits guest state fields */
#define VM_GUEST_ES_LIMIT					0x4800
#define VM_GUEST_CS_LIMIT					0x4802
#define VM_GUEST_SS_LIMIT			   		0x4804
#define VM_GUEST_DS_LIMIT					0x4806
#define VM_GUEST_FS_LIMIT					0x4808
#define VM_GUEST_GS_LIMIT					0x480A
#define VM_GUEST_LDTR_LIMIT					0x480C
#define VM_GUEST_TR_LIMIT					0x480E
#define VM_GUEST_GDTR_LIMIT					0x4810
#define VM_GUEST_IDTR_LIMIT					0x4812
#define VM_GUEST_ES_ACC_RIGHT				0x4814
#define VM_GUEST_CS_ACC_RIGHT				0x4816
#define VM_GUEST_SS_ACC_RIGHT				0x4818
#define VM_GUEST_DS_ACC_RIGHT				0x481A
#define VM_GUEST_FS_ACC_RIGHT				0x481C
#define VM_GUEST_GS_ACC_RIGHT				0x481E
#define VM_GUEST_LDTR_ACC_RIGHT				0x4820
#define VM_GUEST_TR_ACC_RIGHT				0x4822
#define VM_GUEST_INT_STATE					0x4824
#define VM_GUEST_ACTIVITY_STATE				0x4826
#define VM_GUEST_SMBASE						0x4828
#define VM_GUEST_IA32_SYSENTER_CS			0x482A
#define VM_GUEST_VMX_PRE_TIMER_VALUE		0x482E

/* VMCS field encoding - Natural width guest state fields */
#define VM_GUEST_CR0						0x6800
#define VM_GUEST_CR3						0x6802
#define VM_GUEST_CR4						0x6804
#define VM_GUEST_ES_BASE					0x6806
#define VM_GUEST_CS_BASE					0x6808
#define VM_GUEST_SS_BASE					0x680A
#define VM_GUEST_DS_BASE					0x680C
#define VM_GUEST_FS_BASE					0x680E
#define VM_GUEST_GS_BASE					0x6810
#define VM_GUEST_LDTR_BASE					0x6812
#define VM_GUEST_TR_BASE					0x6814
#define VM_GUEST_GDTR_BASE					0x6816
#define VM_GUEST_IDTR_BASE					0x6818
#define VM_GUEST_DR7						0x681A
#define VM_GUEST_RSP						0x681C
#define VM_GUEST_RIP						0x681E
#define VM_GUEST_RFLAGS						0x6820
#define VM_GUEST_PENDING_DBG_EXCEPTS		0x6822
#define VM_GUEST_IA32_SYSENTER_ESP			0x6824
#define VM_GUEST_IA32_SYSENTER_EIP			0x6826

/* VMCS field encoding - 16 bits host fields */
#define VM_HOST_ES_SELECTOR			 		0xC00
#define VM_HOST_CS_SELECTOR			 		0xC02
#define VM_HOST_SS_SELECTOR			 		0xC04
#define VM_HOST_DS_SELECTOR			 		0xC06
#define VM_HOST_FS_SELECTOR			 		0xC08
#define VM_HOST_GS_SELECTOR			 		0xC0A
#define VM_HOST_TR_SELECTOR			 		0xC0C

/* VMCS field encoding - 64 bits host fields */
#define VM_HOST_PAT							0x2C00
#define VM_HOST_EFER						0x2C02
#define VM_HOST_PERF_GLOBAL_CTRL			0x2C04

/* VMCS field encoding - 32 Bits host state fields */
#define VM_HOST_IA32_SYSENTER_CS			0x4C00

#define VM_HOST_CR0							0x6C00
#define VM_HOST_CR3							0x6C02
#define VM_HOST_CR4							0x6C04
#define VM_HOST_FS_BASE						0x6C06
#define VM_HOST_GS_BASE						0x6C08
#define VM_HOST_TR_BASE						0x6C0A
#define VM_HOST_GDTR_BASE					0x6C0C
#define VM_HOST_IDTR_BASE					0x6C0E
#define VM_HOST_IA32_SYSENTER_ESP			0x6C10
#define VM_HOST_IA32_SYSENTER_EIP			0x6C12
#define VM_HOST_RSP							0x6C14
#define VM_HOST_RIP							0x6C16

/* VMCS field encoding - 64 Bits control fields */
#define VM_CTRL_IO_BITMAP_A_ADDR			0x2000
#define VM_CTRL_IO_BITMAP_B_ADDR			0x2002
#define VM_CTRL_MSR_BITMAPS					0x2004
#define VM_CTRL_VM_EXIT_MSR_LOAD_ADDR		0x2008
#define VM_CTRL_VM_ENTRY_MSR_LOAD_ADDR		0x200A
#define VM_CTRL_EXECUTIVE_VMCS_PTR			0x200C
#define VM_CTRL_TSC_OFFSET					0x2010
#define VM_CTRL_VIRTUAL_APIC_ADDR			0x2012
#define VM_CTRL_EPT_PTR						0x201A

/* VMCS field encoding - 32 Bits control fields */
#define VM_CTRL_PIN_BASED_VM_EXE_CTRL		0x4000
#define VM_CTRL_PRI_PROC_BASED_EXE_CTRL		0x4002
#define VM_CTRL_EXCEPTION_BITMAP			0x4004
#define VM_CTRL_PAGE_FAULT_ERR_CODE_MASK	0x4006
#define VM_CTRL_PAGE_FAULT_ERR_CODE_MATCH	0x4008
#define VM_CTRL_CR3_TARGET_COUNT			0x400A
#define VM_CTRL_VM_EXIT_CTRLS				0x400C
#define VM_CTRL_VM_EXIT_MSR_STORE_COUNT		0x400E
#define VM_CTRL_VM_EXIT_MSR_LOAD_COUNT		0x4010
#define VM_CTRL_VM_ENTRY_CTRLS				0x4012
#define VM_CTRL_VM_ENTRY_MSR_LOAD_COUNT		0x4014
#define VM_CTRL_VM_ENTRY_INT_INFO_FIELD		0x4016
#define VM_CTRL_VM_ENTRY_EXCEPT_ERR_CODE	0x4018
#define VM_CTRL_VM_ENTRY_INST_LENGTH		0x401A
#define VM_CTRL_TPR_THRESHOLD				0x401C
#define VM_CTRL_SEC_PROC_BASED_EXE_CTRL		0x401E

/* Natural width control fields */
#define VM_CTRL_CR0_GUEST_HOST_MASK			0x6000
#define VM_CTRL_CR4_GUEST_HOST_MASK			0x6002
#define VM_CTRL_CR0_READ_SHADOW				0x6004
#define VM_CTRL_CR4_READ_SHADOW				0x6006
#define VM_CTRL_CR3_TARGET_VALUE_0			0x6008
#define VM_CTRL_CR3_TARGET_VALUE_1			0x600A
#define VM_CTRL_CR3_TARGET_VALUE_2			0x600C
#define VM_CTRL_CR3_TARGET_VALUE_3			0x600E

/* Data fields of VMCS. */
#define VM_DATA_GUEST_PHY_ADDR				0x2400
#define VM_DATA_INST_ERROR					0x4400
#define VM_DATA_EXIT_REASON					0x4402
#define VM_DATA_VM_EXIT_INT_INFO			0x4404
#define VM_DATA_VM_EXIT_INST_LENGTH			0x440C
#define VM_DATA_VM_EXIT_INST_INFO			0x440E

/* Natural width read-only data fields */
#define VM_DATA_EXIT_QUALIFICATION			0x6400
#define VM_DATA_GUEST_LINEAR_ADDR			0x640A

/* VM control fields of VMCS. */
#define VM_BIT_VM_ENTRY_LOAD_DEBUG_CTRL			(0x01 << 2)
#define VM_BIT_VM_ENTRY_CTRL_IA32E_MODE_GUEST	(0x01 << 9)

#define VM_BIT_VM_EXIT_SAVE_DEBUG_CTRL			(0x01 << 2)
#define VM_BIT_VM_EXIT_CTRL_HOST_ADDR_SIZE		(0x01 << 9)
#define VM_BIT_VM_EXIT_CTRL_SAVE_IA32_EFER		(0x01 << 20)
#define VM_BIT_VM_EXIT_CTRL_SAVE_PRE_TIMER		(0x01 << 22)

/* PIN Based VM execution control flags. */
#define VM_BIT_VM_PIN_BASED_USE_PRE_TIMER		(0x01 << 6)

/* Primary processor-based VM execution control flags. */
#define VM_BIT_VM_PRI_PROC_CTRL_USE_MOVE_DR		(0x01 << 23)
#define VM_BIT_VM_PRI_PROC_CTRL_USE_IO_BITMAP	(0x01 << 25)
#define VM_BIT_VM_PRI_PROC_CTRL_USE_MSR_BITMAP	(0x01 << 28)
#define VM_BIT_VM_PRI_PROC_CTRL_USE_SEC_CTRL	(0x01 << 31)

/* Secondary processor-based VM execution control flags. */
#define VM_BIT_VM_SEC_PROC_CTRL_USE_EPT			(0x01 << 1)
#define VM_BIT_VM_SEC_PROC_CTRL_DESC_TABLE		(0x01 << 2)
#define VM_BIT_VM_SEC_PROC_CTRL_UNREST_GUEST	(0x01 << 7)
#define VM_BIT_VM_SEC_PROC_CTRL_ENABLE_INVPCID  (0x01 << 12)
#define VM_BIT_VM_SEC_PROC_CTRL_ENABLE_XSAVE  	(0x01 << 20)

/* EPT flags. */
#define VM_BIT_EPT_PAGE_WALK_LENGTH_BITMAP		(0x03 << 3)
#define VM_BIT_EPT_MEM_TYPE_WB					(0x06 << 0)

/* VM entry flags. */
#define VM_BIT_VM_ENTRY_INT_INFO_HW				(0x3 << 8)
#define VM_BIT_VM_ENTRY_INT_INFO_VALID			(0x01 << 31)
#define VM_BIT_VM_ENTRY_INT_INFO_UD				(6 | VM_BIT_VM_ENTRY_INT_INFO_HW |\
	VM_BIT_VM_ENTRY_INT_INFO_VALID)

/* VM instruction information fields. */
#define VM_INST_INFO_INST_IDENTITY(info)			(((info) >> 28) & 0x03)
#define VM_INST_INFO_MEM_REG(info)					(((info) >> 10) & 0x01)
#define VM_INST_INFO_REG1(info)						(((info) >> 3) & 0x0F)
#define VM_INST_INFO_IDX_REG(info)					(((info) >> 18) & 0x0F)
#define VM_INST_INFO_SCALE(info)					((info) & 0x03)
#define VM_INST_INFO_BASE_REG(info)					(((info) >> 23) & 0x0F)
#define VM_INST_INFO_ADDR_SIZE(info)				(((info) >> 7) & 0x07)

#define VM_INST_INFO_SLDT							0
#define VM_INST_INFO_STR							1
#define VM_INST_INFO_LLDT							2
#define VM_INST_INFO_LTR							3

#define VM_INST_INFO_IDX_REG_INVALID				(0x01 << 22)
#define VM_INST_INFO_BASE_REG_INVALID				(0x01 << 27)

#define VM_INST_INFO_ADDR_SIZE_16BIT				0
#define VM_INST_INFO_ADDR_SIZE_32BIT				1
#define VM_INST_INFO_ADDR_SIZE_64BIT				2

/* VM exit interrupt information fields and vector. */
#define VM_EXIT_INT_INFO_INT_TYPE(info)				(((info) >> 8) & 0x07)
#define VM_EXIT_INT_INFO_VECTOR(info)				((info) & 0xFF)
 
/* VM exit interrupt type. */
#define VM_EXIT_INT_TYPE_NMI						2

/* Exception types. */
#define VM_INT_DEBUG_EXCEPTION						1
#define VM_INT_MACHINE_CHECK						18

/* VM exit reason. */
#define VM_EXIT_REASON_EXCEPT_OR_NMI				(0)
#define VM_EXIT_REASON_EXT_INTTERUPT				(1)
#define VM_EXIT_REASON_TRIPLE_FAULT					(2)
#define VM_EXIT_REASON_INIT_SIGNAL					(3)
#define VM_EXIT_REASON_START_UP_IPI					(4)
#define VM_EXIT_REASON_IO_SMI						(5)
#define VM_EXIT_REASON_OTHER_SMI					(6)
#define VM_EXIT_REASON_INT_WINDOW					(7)
#define VM_EXIT_REASON_NMI_WINDOW					(8)
#define VM_EXIT_REASON_TASK_SWITCH					(9)
#define VM_EXIT_REASON_CPUID						(10)
#define VM_EXIT_REASON_GETSEC						(11)
#define VM_EXIT_REASON_HLT							(12)
#define VM_EXIT_REASON_INVD							(13)
#define VM_EXIT_REASON_INVLPG						(14)
#define VM_EXIT_REASON_RDPMC						(15)
#define VM_EXIT_REASON_RDTSC						(16)
#define VM_EXIT_REASON_RSM							(17)
#define VM_EXIT_REASON_VMCALL						(18)
#define VM_EXIT_REASON_VMCLEAR						(19)
#define VM_EXIT_REASON_VMLAUNCH						(20)
#define VM_EXIT_REASON_VMPTRLD						(21)
#define VM_EXIT_REASON_VMPTRST						(22)
#define VM_EXIT_REASON_VMREAD						(23)
#define VM_EXIT_REASON_VMRESUME						(24)
#define VM_EXIT_REASON_VMWRITE						(25)
#define VM_EXIT_REASON_VMXOFF						(26)
#define VM_EXIT_REASON_VMXON						(27)
#define VM_EXIT_REASON_CTRL_REG_ACCESS		 		(28)
#define VM_EXIT_REASON_MOV_DR						(29)
#define VM_EXIT_REASON_IO_INST						(30)
#define VM_EXIT_REASON_RDMSR						(31)
#define VM_EXIT_REASON_WRMSR						(32)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_INV_GUEST	(33)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_MSR_LOAD	(34)
#define VM_EXIT_REASON_MWAIT						(36)
#define VM_EXIT_REASON_MONITOR_TRAP_FLAG			(37)
#define VM_EXIT_REASON_MONITOR						(39)
#define VM_EXIT_REASON_PAUSE						(40)
#define VM_EXIT_REASON_VM_ENTRY_FAILURE_MACHINE_CHECK (41)
#define VM_EXIT_REASON_TRP_BELOW_THRESHOLD			(43)
#define VM_EXIT_REASON_APIC_ACCESS					(44)
#define VM_EXIT_REASON_VIRTUALIZED_EOI				(45)
#define VM_EXIT_REASON_ACCESS_GDTR_OR_IDTR			(46)
#define VM_EXIT_REASON_ACCESS_LDTR_OR_TR			(47)
#define VM_EXIT_REASON_EPT_VIOLATION				(48)
#define VM_EXIT_REASON_EPT_MISCONFIGURATION			(49)
#define VM_EXIT_REASON_INVEPT						(50)
#define VM_EXIT_REASON_RDTSCP						(51)
#define VM_EXIT_REASON_VMX_PREEMP_TIMER_EXPIRED		(52)
#define VM_EXIT_REASON_INVVPID						(53)
#define VM_EXIT_REASON_WBINVD						(54)
#define VM_EXIT_REASON_XSETBV						(55)
#define VM_EXIT_REASON_APIC_WRITE					(56)
#define VM_EXIT_REASON_RDRAND						(57)
#define VM_EXIT_REASON_INVPCID						(58)
#define VM_EXIT_REASON_VMFUNC						(59)
#define VM_EXIT_REASON_RDSEED						(61)
#define VM_EXIT_REASON_XSAVES						(63)
#define VM_EXIT_REASON_XRSTORS						(64)

/* VM exit qualification flags. */
#define VM_EXIT_QUAL_CTRL_REG_ACC_GET_CTRL_REG_NUMBER(x)	((x) & 0xF)
#define VM_EXIT_QUAL_CTRL_REG_ACC_GET_ACC_TYPE(x)			(((x) >> 4) & 0x3)
#define VM_EXIT_QUAL_CTRL_REG_ACC_GET_GP_REG_NUMBER(x)		(((x) >> 8) & 0xF)
#define VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_TO_CR				(0)
#define VM_EXIT_QUAL_CTRL_REG_ACC_MOVE_FROM_CR				(1)

#define REG_NUM_CR0											0
#define REG_NUM_CR2											2
#define REG_NUM_CR3											3
#define REG_NUM_CR4											4
#define REG_NUM_CR8											8

#define REG_NUM_RAX											0
#define REG_NUM_RCX											1
#define REG_NUM_RDX											2
#define REG_NUM_RBX											3
#define REG_NUM_RSP											4
#define REG_NUM_RBP											5
#define REG_NUM_RSI											6
#define REG_NUM_RDI											7
#define REG_NUM_R8											8
#define REG_NUM_R9											9
#define REG_NUM_R10											10
#define REG_NUM_R11											11
#define REG_NUM_R12											12
#define REG_NUM_R13											13
#define REG_NUM_R14											14
#define REG_NUM_R15											15

/* Debug register (hardware breakpoint) flags. */
#define DR_BIT_ADD_TASK							(0x01 << 0)
#define DR_BIT_DEL_TASK							(0x01 << 1)
#define DR_BIT_INSMOD							(0x01 << 2)
#define DR_BIT_RMMOD							(0x01 << 3)

/* CPUID flags. */
#define CPUID_1_ECX_VMX							((u64)0x01 << 5)
#define CPUID_1_ECX_SMX							((u64)0x01 << 6)
#define CPUID_D_EAX_XSAVES						((u64)0x01 << 3)

/* RFLAGS register flags. */
//=========================================================
#define RFLAGS_BIT_RF							((u64)0x01 << 16)

/* IA32_EFER MSR flags. */
#define EFER_BIT_LME							(0x01 << 8)

/* CR0 Flags. */
#define CR0_BIT_WP								((u64)0x01 << 16)
#define CR0_BIT_PG								((u64)0x01 << 31)

/* CR4 Flags. */
#define CR4_BIT_MCE								((u64)0x01 << 6)
#define CR4_BIT_VMXE							((u64)0x01 << 13)
#define CR4_BIT_SMXE							((u64)0x01 << 14)
 
#define ERROR_SUCCESS							0
#define ERROR_NOT_START						 	1
#define ERROR_HW_NOT_SUPPORT					2
#define ERROR_LAUNCH_FAIL						3
#define ERROR_KERNEL_MODIFICATION				4
#define ERROR_KERNEL_VERSION_MISMATCH			5
#define ERROR_SHUTDOWN_TIME_OUT					6
#define ERROR_MEMORY_ALLOC_FAIL					7
#define ERROR_TASK_OVERFLOW						8
#define ERROR_MODULE_OVERFLOW					9

/* Define allocated memory type. */
#define ALLOC_KMALLOC							0
#define ALLOC_VMALLOC							1

/* Define ead-only memory type. */
#define RO_MODULE								0
#define RO_KERNEL								1

/* Define GDT descriptor type. */
#define GDT_TYPE_64BIT_TSS						9
#define GDT_TYPE_64BIT_LDT						10
#define GDT_TYPE_64BIT_TSS_BUSY					11
#define GDT_TYPE_64BIT_CALL_GATE				12
#define GDT_TYPE_64BIT_INTERRUPT_GATE			14
#define GDT_TYPE_64BIT_TRAP_GATE				15

/* Define VM call service number. */
#define VM_SERVICE_GET_LOGINFO					0


/* Debug register (hardware breakpoint) flags. */
#define DR_BIT_CREATE_TASK						(0x01 << 0)
#define DR_BIT_DELETE_TASK						(0x01 << 1)
#define DR_BIT_CREATE_MODULE					(0x01 << 2)
#define DR_BIT_DELETE_MODULE					(0x01 << 3)
#define DR_BIT_SYSCALL_64						(0x01 << 2)
#define DR_BIT_COMMIT_CREDS						(0x01 << 3)


typedef int (*my_system_walk_function)(unsigned long start_pfn, unsigned long nr_pages, void *arg,
									   int (*func)(unsigned long, unsigned long, void *));

struct symbol_addr_struct
{
	char *name;
	u64 addr;
};

struct symbol_table_struct
{
	struct symbol_addr_struct symbol[SYMBOL_MAX_COUNT];
};

/* Host registers for VMCS. */
struct vm_host_register
{
	u64 cr0;
	u64 cr3;
	u64 cr4;
	u64 rsp;
	u64 rip;
	u64 cs_selector;
	u64 ss_selector;
	u64 ds_selector;
	u64 es_selector;
	u64 fs_selector;
	u64 gs_selector;
	u64 tr_selector;

	u64 fs_base_addr;
	u64 gs_base_addr;
	u64 tr_base_addr;
	u64 gdtr_base_addr;
	u64 idtr_base_addr;

	u64 ia32_sys_enter_cs;
	u64 ia32_sys_enter_esp;
	u64 ia32_sys_enter_eip;
	u64 ia32_perf_global_ctrl;
	u64 ia32_pat;
	u64 ia32_efer;
};

/* Guest registers for VMCS. */
struct vm_guest_register
{
	u64 cr0;
	u64 cr3;
	u64 cr4;
	u64 dr7;
	u64 rsp;
	u64 rip;
	u64 rflags;
	u64 cs_selector;
	u64 ss_selector;
	u64 ds_selector;
	u64 es_selector;
	u64 fs_selector;
	u64 gs_selector;
	u64 ldtr_selector;
	u64 tr_selector;

	u64 cs_base_addr;
	u64 ss_base_addr;
	u64 ds_base_addr;
	u64 es_base_addr;
	u64 fs_base_addr;
	u64 gs_base_addr;
	u64 ldtr_base_addr;
	u64 tr_base_addr;

	u64 cs_limit;
	u64 ss_limit;
	u64 ds_limit;
	u64 es_limit;
	u64 fs_limit;
	u64 gs_limit;
	u64 ldtr_limit;
	u64 tr_limit;

	u64 cs_access;
	u64 ss_access;
	u64 ds_access;
	u64 es_access;
	u64 fs_access;
	u64 gs_access;
	u64 ldtr_access;
	u64 tr_access;

	u64 gdtr_base_addr;
	u64 idtr_base_addr;
	u64 gdtr_limit;
	u64 idtr_limit;

	u64 ia32_debug_ctrl;
	u64 ia32_sys_enter_cs;
	u64 ia32_sys_enter_esp;
	u64 ia32_sys_enter_eip;
	u64 vmcs_link_ptr;

	u64 ia32_perf_global_ctrl;
	u64 ia32_pat;
	u64 ia32_efer;
};

/* VM control registers for VMCS. */
struct vm_control_register
{
	u64 pin_based_ctrl;
	u64 pri_proc_based_ctrl;
	u64 sec_proc_based_ctrl;
	u64 except_bitmap;
	u64 io_bitmap_addrA;
	u64 io_bitmap_addrB;
	u64 ept_ptr;
	u64 msr_bitmap_addr;
	u64 vm_entry_ctrl_field;
	u64 vm_exti_ctrl_field;
	u64 virt_apic_page_addr;
	u64 cr4_guest_host_mask;
	u64 cr4_read_shadow;
};

/* Guest registers for VM exit. */
struct vm_exit_guest_register
{
	u64 r15;
	u64 r14;
	u64 r13;
	u64 r12;
	u64 r11;
	u64 r10;
	u64 r9;
	u64 r8;
	u64 rsi;
	u64 rdi;
	u64 rdx;
	u64 rcx;
	u64 rbx;
	u64 rax;
	u64 rbp;
};

struct memory_pool
{
	u64 max_count;
	u64 pop_index;
	u64 *pool;
};

struct ro_addr_struct
{
	u64 start;
	u64 end;
	u64 type;
};

/* Guest full context for VMX off. */
struct vm_full_context
{
	u64 cr4;
	u64 cr3;
	u64 cr0;

	u64 tr_selector;
	u64 ldtr_selector;
	u64 gs_selector;
	u64 fs_selector;
	u64 es_selector;
	u64 ds_selector;
	u64 cs_selector;

	struct vm_exit_guest_register gp_register;
	u64 rflags;
	u64 rip;
};
/* Workaround information structure. */
struct workaround
{
	u64 addr_array[WORK_AROUND_MAX_COUNT];
	int count_array[WORK_AROUND_MAX_COUNT];
};
/* Shared context between the host and the guest. */
struct share_context
{
	atomic_t shutdown_flag;
	atomic_t shutdown_complete_count;
};

void not_printf(int level, char* format, ...);
u64 get_symbol_address(char *symbol);
int is_addr_in_ro_area(void *addr);
void add_ro_area(u64 start, u64 end, u64 ro_type);
void hide_range(u64 start_addr, u64 end_addr, int alloc_type);
void set_all_access_range(u64 start_addr, u64 end_addr, int alloc_type);
void delete_ro_area(u64 start, u64 end);
void insert_exception_to_vm(void);
u64 sync_page_table(u64 addr);
void error_log(int error_code);

extern u64 global_max_ram_size;
extern struct list_head *global_modules_ptr;
extern struct file *global_root_file_ptr;
extern struct file *global_proc_file_ptr;
extern struct file *global_tcp_file_ptr;
extern struct file *global_tcp6_file_ptr;
extern struct file *global_udp_file_ptr;
extern struct file *global_udp6_file_ptr;
extern struct socket *global_tcp_sock;
extern struct socket *global_udp_sock;
extern rwlock_t* global_tasklist_lock;
extern atomic_t global_need_init_in_secure;
extern volatile int global_allow_module_hide;
#endif //_HOLDUP_MAIN_H_
