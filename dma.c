#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/syscalls.h>
#include <linux/dmar.h>
#include <linux/intel-iommu.h>
#include <linux/delay.h>
#include <linux/kthread.h>
#include <linux/reboot.h>
#include <linux/smp.h>
#include <linux/version.h>
#include <asm/tlbflush.h>
#include "holdup_main.h"
#include "mmu.h"
#include "dma.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

struct iommu_data global_dmar_data = {
	0,
};
u32 global_entry_level = ENTRY_4LEVEL_PTE;

static int need_intel_i915_workaround(void);
static int is_intel_graphics_in(struct acpi_dmar_hardware_unit *drhd);
static void start_iommu(u8 *reg_remap_addr, int skip);
static void wait_dmar_operation(u8 *reg_remap_addr, int flag);

static void enable_iommu(u8 *reg_remap_addr);
static void set_iommu_root_entry_register(u8 *reg_remap_addr, u64 addr);
static void setup_root_table_entry(void);
static void setup_context_table_entry(void);

static int need_intel_i915_workaround(void);
static int is_intel_graphics_in(struct acpi_dmar_hardware_unit *drhd);

static void *get_iommu_pagetable_physical_assr(int type, int index);
static void *get_iommu_pagetable_logical_addr(int type, int index);

static void set_iommu_root_entry_register(u8 *reg_remap_addr, u64 addr);

#pragma region MEMORY_FUNCTIONS_EPT
int alloc_iommu_pages(void)
{
	struct root_entry *root_entry_table;
	struct context_entry *context_entry_table;
	int i;

	global_dmar_data.p4_entries_count = CEIL(global_max_ram_size, S_512GB);
	global_dmar_data.p3_entries_count = CEIL(global_max_ram_size, S_1GB);
	global_dmar_data.p2_entries_count = CEIL(global_max_ram_size, S_2MB);
	global_dmar_data.p1_entries_count = CEIL(global_max_ram_size, S_4KB);

	global_dmar_data.p4_page_count = CEIL(global_dmar_data.p4_entries_count, IOMMU_PAGE_ENT_COUNT);
	global_dmar_data.p3_page_count = CEIL(global_dmar_data.p3_entries_count, IOMMU_PAGE_ENT_COUNT);
	global_dmar_data.p2_page_count = CEIL(global_dmar_data.p2_entries_count, IOMMU_PAGE_ENT_COUNT);
	global_dmar_data.p1_page_count = CEIL(global_dmar_data.p1_entries_count, IOMMU_PAGE_ENT_COUNT);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup IOMMU Page Table & Root/Context Entry Table, Max RAM Size %ld\n", global_max_ram_size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] IOMMU Size: %d\n", (int)sizeof(struct iommu_pagetable));
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P4 Entry Count: %d\n", (int)global_dmar_data.p4_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P3 Entry Count: %d\n", (int)global_dmar_data.p3_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Entry Count: %d\n", (int)global_dmar_data.p2_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Entry Count: %d\n", (int)global_dmar_data.p1_entries_count);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P4 Page Count: %d\n", (int)global_dmar_data.p4_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P3 Page Count: %d\n", (int)global_dmar_data.p3_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Page Count: %d\n", (int)global_dmar_data.p2_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Page Count: %d\n", (int)global_dmar_data.p1_page_count);

	/* Allocate memory for page table. */
	global_dmar_data.p4_page_addr_array = (u64 *)vmalloc(global_dmar_data.p4_page_count * sizeof(u64 *));
	global_dmar_data.p3_page_addr_array = (u64 *)vmalloc(global_dmar_data.p3_page_count * sizeof(u64 *));
	global_dmar_data.p2_page_addr_array = (u64 *)vmalloc(global_dmar_data.p2_page_count * sizeof(u64 *));
	global_dmar_data.p1_page_addr_array = (u64 *)vmalloc(global_dmar_data.p1_page_count * sizeof(u64 *));

	if ((global_dmar_data.p4_page_addr_array == 0) ||
		(global_dmar_data.p3_page_addr_array == 0) ||
		(global_dmar_data.p2_page_addr_array == 0) ||
		(global_dmar_data.p1_page_addr_array == 0))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "alloc_iommu_pages alloc fail\n");
		return -1;
	}

	for (i = 0; i < global_dmar_data.p4_page_count; i++)
	{
		global_dmar_data.p4_page_addr_array[i] = (u64)kmalloc(0x1000, GFP_KERNEL);
		if (global_dmar_data.p4_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_iommu_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0; i < global_dmar_data.p3_page_count; i++)
	{
		global_dmar_data.p3_page_addr_array[i] = (u64)kmalloc(0x1000, GFP_KERNEL);
		if (global_dmar_data.p3_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_iommu_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0; i < global_dmar_data.p2_page_count; i++)
	{
		global_dmar_data.p2_page_addr_array[i] = (u64)kmalloc(0x1000, GFP_KERNEL);
		if (global_dmar_data.p2_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_iommu_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0; i < global_dmar_data.p1_page_count; i++)
	{
		global_dmar_data.p1_page_addr_array[i] = (u64)kmalloc(0x1000, GFP_KERNEL);
		if (global_dmar_data.p1_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_iommu_pages alloc fail\n");
			return -1;
		}
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Page Table Memory Alloc Success\n");

	/* Allocate memory for root table and context table. */
	root_entry_table = (struct root_entry *)kmalloc(0x1000, GFP_KERNEL);
	context_entry_table = (struct context_entry *)kmalloc(0x1000, GFP_KERNEL);
	if ((root_entry_table == NULL) || (context_entry_table == NULL))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_iommu_pages alloc fail\n");
		return -1;
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] root_entry_table Logical: %016lX Physical: %016lX\n", root_entry_table, virt_to_phys(root_entry_table));
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] context_entry_table Logical: %016lX Physical: %016lX\n", context_entry_table, virt_to_phys(context_entry_table));

	global_dmar_data.root_entry_table_addr = (u64 *)root_entry_table;
	global_dmar_data.context_entry_table_addr = (u64 *)context_entry_table;

	return 0;
}

void free_iommu_pages(void)
{
	if (global_dmar_data.p4_page_addr_array != 0)
	{
		kfree(global_dmar_data.p4_page_addr_array);
		global_dmar_data.p4_page_addr_array = 0;
	}

	if (global_dmar_data.p3_page_addr_array != 0)
	{
		kfree(global_dmar_data.p3_page_addr_array);
		global_dmar_data.p3_page_addr_array = 0;
	}

	if (global_dmar_data.p2_page_addr_array != 0)
	{
		kfree(global_dmar_data.p2_page_addr_array);
		global_dmar_data.p2_page_addr_array = 0;
	}

	if (global_dmar_data.p1_page_addr_array != 0)
	{
		kfree(global_dmar_data.p1_page_addr_array);
		global_dmar_data.p1_page_addr_array = 0;
	}

	if (global_dmar_data.root_entry_table_addr != 0)
	{
		kfree(global_dmar_data.root_entry_table_addr);
		global_dmar_data.root_entry_table_addr = 0;
	}

	if (global_dmar_data.context_entry_table_addr != 0)
	{
		kfree(global_dmar_data.context_entry_table_addr);
		global_dmar_data.context_entry_table_addr = 0;
	}
}
#pragma endregion

#pragma region SETUP_FUNCTIONS
void setup_iommu_pagetable_4KB(void)
{
	struct iommu_pagetable *pstIOMMU;
	u64 next_page_table;
	int i, j, iLoopCnt;

	/* Setup P4. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P4\n");
	pstIOMMU = (struct iommu_pagetable *)get_iommu_pagetable_logical_addr(IOMMU_TYPE_P4, 0);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup P4 %016lX, %016lX\n",
			   (u64)pstIOMMU, virt_to_phys((void *)pstIOMMU));
	memset(pstIOMMU, 0, sizeof(struct iommu_pagetable));
	for (i = 0; i < global_dmar_data.p4_entries_count; i++)
	{
		next_page_table = (u64)get_iommu_pagetable_physical_assr(IOMMU_TYPE_P3, i);
		pstIOMMU->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
		if (i == 0)
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table);
		}
	}
	clflush_cache_range(pstIOMMU, IOMMU_PAGE_SIZE);

	// Setup P3
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P3\n");
	for (j = 0; j < global_dmar_data.p3_page_count; j++)
	{
		pstIOMMU = (struct iommu_pagetable *)get_iommu_pagetable_logical_addr(IOMMU_TYPE_P3, j);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup P3 [%d] %016lX %016lX\n", j, (u64)pstIOMMU, virt_to_phys((void *)pstIOMMU));
		memset(pstIOMMU, 0, sizeof(struct iommu_pagetable));

		iLoopCnt = global_dmar_data.p3_entries_count - (j * IOMMU_PAGE_ENT_COUNT);
		if (iLoopCnt > IOMMU_PAGE_ENT_COUNT)
		{
			iLoopCnt = IOMMU_PAGE_ENT_COUNT;
		}

		for (i = 0; i < iLoopCnt; i++)
		{
			next_page_table = (u64)get_iommu_pagetable_physical_assr(IOMMU_TYPE_P2, (j * IOMMU_PAGE_ENT_COUNT) + i);
			pstIOMMU->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
			if (i == 0)
			{
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table);
			}
		}

		clflush_cache_range(pstIOMMU, IOMMU_PAGE_SIZE);
	}

	/* Setup p2. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup p2\n");
	for (j = 0; j < global_dmar_data.p2_page_count; j++)
	{
		pstIOMMU = (struct iommu_pagetable *)get_iommu_pagetable_logical_addr(IOMMU_TYPE_P2, j);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup p2 [%d] %016lX %016lX\n", j, (u64)pstIOMMU, virt_to_phys(pstIOMMU));
		memset(pstIOMMU, 0, sizeof(struct iommu_pagetable));

		iLoopCnt = global_dmar_data.p2_entries_count - (j * IOMMU_PAGE_ENT_COUNT);
		if (iLoopCnt > IOMMU_PAGE_ENT_COUNT)
		{
			iLoopCnt = IOMMU_PAGE_ENT_COUNT;
		}

		for (i = 0; i < iLoopCnt; i++)
		{
			next_page_table = (u64)get_iommu_pagetable_physical_assr(IOMMU_TYPE_P1,
																	 (j * IOMMU_PAGE_ENT_COUNT) + i);
			pstIOMMU->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
			if (i == 0)
			{
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table);
			}
		}
		clflush_cache_range(pstIOMMU, IOMMU_PAGE_SIZE);
	}

	/* Setup P1. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P1\n");
	for (j = 0; j < global_dmar_data.p1_page_count; j++)
	{
		pstIOMMU = (struct iommu_pagetable *)get_iommu_pagetable_logical_addr(IOMMU_TYPE_P1, j);
		memset(pstIOMMU, 0, sizeof(struct iommu_pagetable));

		iLoopCnt = global_dmar_data.p1_entries_count - (j * IOMMU_PAGE_ENT_COUNT);
		if (iLoopCnt > IOMMU_PAGE_ENT_COUNT)
		{
			iLoopCnt = IOMMU_PAGE_ENT_COUNT;
		}

		for (i = 0; i < iLoopCnt; i++)
		{
			next_page_table = ((u64)j * IOMMU_PAGE_ENT_COUNT + i) * IOMMU_PAGE_SIZE;
			pstIOMMU->entry[i] = next_page_table | IOMMU_PAGE_ALL_ACCESS;
		}
		clflush_cache_range(pstIOMMU, IOMMU_PAGE_SIZE);
	}
}

static void setup_root_table_entry(void)
{
	struct root_entry *root_entry_table;
	struct context_entry *context_entry_table;
	int i;

	root_entry_table = (struct root_entry *)global_dmar_data.root_entry_table_addr;
	context_entry_table = (struct context_entry *)global_dmar_data.context_entry_table_addr;
	for (i = 0; i < 256; i++)
	{
		root_entry_table[i].rsvd1 = 0;
		root_entry_table[i].val = (u64)virt_to_phys(context_entry_table) | ENTRY_PRESENT;

		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Table [%d] %016lX %016lX\n", i, root_entry_table[i].rsvd1, root_entry_table[i].val);
	}
	clflush_cache_range(root_entry_table, IOMMU_PAGE_SIZE);
}

static void setup_context_table_entry(void)
{
	struct context_entry *context_entry_table;
	u64 table_array;
	int i;

	context_entry_table = (struct context_entry *)global_dmar_data.context_entry_table_addr;
	if (global_entry_level == ENTRY_3LEVEL_PTE)
	{
		table_array = global_dmar_data.p3_page_addr_array[0];
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "3 Level PTE\n");
	}
	else
	{
		table_array = global_dmar_data.p4_page_addr_array[0];
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "4 Level PTE\n");
	}

	for (i = 0; i < 256; i++)
	{
		context_entry_table[i].hi = global_entry_level;
		context_entry_table[i].lo = (u64)virt_to_phys((void *)table_array) | ENTRY_PRESENT;
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Context Table [%d] %016lX %016lX\n", i, context_entry_table[i].hi, context_entry_table[i].lo);
	}
	clflush_cache_range(context_entry_table, IOMMU_PAGE_SIZE);
}

#pragma endregion

#pragma region MEMORY_TRANSLATION
static void *get_iommu_pagetable_logical_addr(int type, int index)
{
	u64 *table_array;

	switch (type)
	{
	case IOMMU_TYPE_P4:
		table_array = global_dmar_data.p4_page_addr_array;
		break;

	case IOMMU_TYPE_P3:
		table_array = global_dmar_data.p3_page_addr_array;
		break;

	case IOMMU_TYPE_P2:
		table_array = global_dmar_data.p2_page_addr_array;
		break;

	case IOMMU_TYPE_P1:
	default:
		table_array = global_dmar_data.p1_page_addr_array;
		break;
	}

	return (void *)table_array[index];
}

static void *get_iommu_pagetable_physical_assr(int type, int index)
{
	void *pvLogAddr;

	pvLogAddr = get_iommu_pagetable_logical_addr(type, index);
	return (void *)virt_to_phys(pvLogAddr);
}
#pragma endregion

#pragma region SET_PAGE_FUNCTIONS
void set_iommu_page_flags(u64 phy_addr, u32 flags)
{
	u64 page_offset, page_index, *page_table_addr;

	page_offset = phy_addr / IOMMU_PAGE_SIZE;
	page_index = page_offset % IOMMU_PAGE_ENT_COUNT;
	page_table_addr = get_iommu_pagetable_logical_addr(IOMMU_TYPE_P1, page_offset / IOMMU_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (page_table_addr[page_index] & MASK_PAGE_ADDR) | flags;
}

void set_iommu_hide_page(u64 phy_addr)
{
	set_iommu_page_flags(phy_addr, 0);
}

void set_iommu_all_access_page(u64 phy_addr)
{
	set_iommu_page_flags(phy_addr, IOMMU_PAGE_ALL_ACCESS);
}
#pragma endregion

#pragma region CHECK_HARDWERE
static int need_intel_i915_workaround(void)
{
	struct module *mod;
	struct list_head *pos, *node;
	unsigned long mod_head_node;

	node = &THIS_MODULE->list;
	mod_head_node = get_symbol_address("modules");

	list_for_each(pos, node)
	{
		if (mod_head_node == (unsigned long)pos)
			break;

		mod = container_of(pos, struct module, list);
		if (strcmp(mod->name, "i915") == 0)
		{
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] i915 driver is detected.\n");
			return 1;
		}
	}

	return 0;
}

static int is_intel_graphics_in(struct acpi_dmar_hardware_unit *drhd)
{
	struct acpi_dmar_device_scope *device_scope;
	struct acpi_dmar_pci_path *pci_path;
	u64 start_device_scope, start_pci_path;
	int device_count = 0, path_count = 0, is_bus_device_function_match = 0;

	for (start_device_scope = sizeof(struct acpi_dmar_hardware_unit); start_device_scope < drhd->header.length;)
	{
		device_scope = (struct acpi_dmar_device_scope *)(start_device_scope + (u64)drhd);

		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Device Scope %d\n", device_count);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Type %d\n", device_scope->entry_type);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Length %d, PCI path %d\n", device_scope->length, sizeof(struct acpi_dmar_pci_path));
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Enum ID %d\n", device_scope->enumeration_id);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] Bus %d\n", device_scope->bus);

		for (start_pci_path = sizeof(struct acpi_dmar_device_scope); start_pci_path < device_scope->length;)
		{
			pci_path = (struct acpi_dmar_pci_path *)(start_pci_path + (u64)device_scope);
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "        [*] PCI Path\n");
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "            [*] Device %d, Function %d\n", pci_path->device, pci_path->function);

			start_pci_path += sizeof(struct acpi_dmar_pci_path);
			path_count++;

			if ((device_scope->entry_type == ACPI_DMAR_SCOPE_TYPE_ENDPOINT) &&
				(device_scope->bus == 0) && (pci_path->device == 2) &&
				(pci_path->function == 0))
			{
				is_bus_device_function_match = 1;
			}
		}

		start_device_scope += device_scope->length;
		device_count++;
	}

	if ((device_count == 1) && (is_bus_device_function_match == 1))
	{
		not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Intel Integrated Graphics is detected\n");
		return 1;
	}

	return 0;
}
#pragma endregion

#pragma region MANAGING_FUNCTIONS
static void start_iommu(u8 *reg_remap_addr, int skip)
{
	u64 extend_cap = 0;

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "IOMMU Start\n");

	setup_root_table_entry();
	setup_context_table_entry();

	flush_cache_all();

	extend_cap = dmar_readq(reg_remap_addr + DMAR_ECAP_REG);
	if (ecap_ecs(extend_cap))
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Extended Context Supported\n");
	}

	if (skip == 0)
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root entry %016lX\n", global_dmar_data.root_entry_table_addr);
		set_iommu_root_entry_register(reg_remap_addr, (u64)virt_to_phys(global_dmar_data.root_entry_table_addr));

		enable_iommu(reg_remap_addr);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IOMMU STATUS = %08X\n", readl(reg_remap_addr + DMAR_GSTS_REG));
	}
	else
	{
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root entry is skipped\n");

		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] IOMMU STATUS = %08X\n", readl(reg_remap_addr + DMAR_GSTS_REG));
	}
}

static void enable_iommu(u8 *reg_remap_addr)
{
	u32 flags;
	unsigned long irqs;

	local_irq_save(irqs);
	local_irq_disable();
	preempt_disable();

	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
	writel(flags | DMA_GCMD_QIE, reg_remap_addr + DMAR_GCMD_REG);
	wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_QIES);

	writel(flags | DMA_GCMD_TE, reg_remap_addr + DMAR_GCMD_REG);
	wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_TES);

	local_irq_restore(irqs);
	preempt_enable();
}

void disable_iommu(u8 *reg_remap_addr)
{
	u32 flags;
	unsigned long irqs;

	local_irq_save(irqs);
	local_irq_disable();
	preempt_disable();

	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
	writel(flags & ~DMA_GCMD_TE, reg_remap_addr + DMAR_GCMD_REG);

	wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, 0);

	local_irq_restore(irqs);
	preempt_enable();
}
#pragma endregion

static void wait_dmar_operation(u8 *reg_remap_addr, int flag)
{
	u32 sts;
	cycles_t init_time = get_cycles();

	while (1)
	{
		sts = readl(reg_remap_addr);
		if (sts & flag)
		{
			break;
		}

		if (DMAR_OPERATION_TIMEOUT < (get_cycles() - init_time))
		{
			break;
		}

		cpu_relax();
	}
}

static void set_iommu_root_entry_register(u8 *reg_remap_addr, u64 addr)
{
	u32 flags;
	unsigned long irqs;

	local_irq_save(irqs);
	preempt_disable();

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Entry Addr %016lX\n", addr);
	flags = readl(reg_remap_addr + DMAR_GSTS_REG);
	dmar_writeq(reg_remap_addr + DMAR_RTADDR_REG, addr);

	writel(flags | DMA_GCMD_SRTP, reg_remap_addr + DMAR_GCMD_REG);
	wait_dmar_operation(reg_remap_addr + DMAR_GSTS_REG, DMA_GSTS_RTPS);

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Root Entry Addr %016lX\n", dmar_readq(reg_remap_addr + DMAR_RTADDR_REG));

	local_irq_restore(irqs);
	preempt_enable();
}

void lock_iommu(void)
{
	struct acpi_table_dmar *dmar_ptr;
	struct acpi_dmar_header *dmar_header;
	struct acpi_dmar_hardware_unit *drhd;
	acpi_status result = AE_OK;
	u8 *remap_addr;
	u64 start, root_table_addr = 0;

	int i, need_i915_workaround = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	acpi_size dmar_table_size = 0;
#endif

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "Lock IOMMU\n");

	need_i915_workaround = need_intel_i915_workaround();

/* Read ACPI. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	result = acpi_get_table_with_size(ACPI_SIG_DMAR, 0,
									  (struct acpi_table_header **)&dmar_ptr, &dmar_table_size);
#else
	result = acpi_get_table(ACPI_SIG_DMAR, 0, (struct acpi_table_header **)&dmar_ptr);
#endif

	if (!ACPI_SUCCESS(result) || (dmar_ptr == NULL))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] WARNING: DMAR find error.\n");
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "    [*] WARNING: IOMMU is disabled.\n");
		return;
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR find success %016lX\n", (u64)dmar_ptr);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Signature: %s\n", dmar_ptr->header.signature);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Length: %d\n", dmar_ptr->header.length);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Revision: %X\n", dmar_ptr->header.revision);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Checksum: %X\n", dmar_ptr->header.checksum);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] OEM ID: %s\n", dmar_ptr->header.oem_id);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Width: %X\n", dmar_ptr->width);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Flag: %X\n", dmar_ptr->flags);

	for (start = sizeof(struct acpi_table_dmar); start < dmar_ptr->header.length;)
	{
		dmar_header = (struct acpi_dmar_header *)(start + (u64)dmar_ptr);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR Type: %d\n", dmar_header->type);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] DMAR Length: %d\n", dmar_header->length);

		if (dmar_header->type == ACPI_DMAR_TYPE_HARDWARE_UNIT)
		{
			drhd = (struct acpi_dmar_hardware_unit *)dmar_header;
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Flag: %X\n", drhd->flags);
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Segment: %X\n", drhd->segment);
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Address: %016lX\n", (u64)drhd->address);

			remap_addr = (u8 *)ioremap_nocache((resource_size_t)(drhd->address), VTD_PAGE_SIZE);
			root_table_addr = dmar_readq(remap_addr + DMAR_CAP_REG);
			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] CAP Register: %016lX\n", root_table_addr);

			if (root_table_addr & (0x01 << 10))
			{
				global_entry_level = ENTRY_4LEVEL_PTE;
			}
			else
			{
				global_entry_level = ENTRY_3LEVEL_PTE;
			}

			for (i = 0; i < 1024; i++)
			{
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Data %d %08X\n", i, readl(remap_addr + 4 * i));
			}

			root_table_addr = dmar_readq(remap_addr + DMAR_RTADDR_REG);

			not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Root Table Address: %016lX\n", root_table_addr);

			/* If IOMMU is already activated, use it. */
			if (root_table_addr != 0)
			{
			}
			else
			{
				/* Intel Internal Graphics has dedicated DRHD, and for the sleep
				   workaround, it should be skipped. */
				if ((need_i915_workaround == 1) &&
					(is_intel_graphics_in(drhd) == 1))
				{
					start_iommu(remap_addr, need_i915_workaround);
					need_i915_workaround = 0;
				}
				else
				{
					start_iommu(remap_addr, 0);
				}

				set_ept_read_only_page(drhd->address);
				set_iommu_hide_page(drhd->address);
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] MM Register Lock OK %016X\n", drhd->address);
			}

			iounmap(remap_addr);
		}
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "\n");

		start += dmar_header->length;
	}

	not_printf(LOG_LEVEL_NORMAL, LOG_INFO "    [*] Lock IOMMU complete\n");
}

void unlock_iommu(void)
{
	struct acpi_table_dmar *dmar_ptr;
	struct acpi_dmar_header *dmar_header;
	struct acpi_dmar_hardware_unit *hardware_unit;
	u8 *remap_addr;
	u64 start;
	acpi_status result = AE_OK;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	acpi_size dmar_table_size = 0;
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0)
	result = acpi_get_table_with_size(ACPI_SIG_DMAR, 0,
									  (struct acpi_table_header **)&dmar_ptr, &dmar_table_size);
#else
	result = acpi_get_table(ACPI_SIG_DMAR, 0, (struct acpi_table_header **)&dmar_ptr);
#endif
	if (!ACPI_SUCCESS(result) || (dmar_ptr == NULL))
	{
		return;
	}

	for (start = sizeof(struct acpi_table_dmar); start < dmar_ptr->header.length;)
	{
		dmar_header = (struct acpi_dmar_header *)(start + (u64)dmar_ptr);

		if (dmar_header->type == ACPI_DMAR_TYPE_HARDWARE_UNIT)
		{
			hardware_unit = (struct acpi_dmar_hardware_unit *)dmar_header;
			remap_addr = (u8 *)ioremap_nocache((resource_size_t)(hardware_unit->address), VTD_PAGE_SIZE);

			disable_iommu(remap_addr);
			set_ept_all_access_page(hardware_unit->address);
			set_iommu_all_access_page(hardware_unit->address);

			iounmap(remap_addr);
		}
		start += dmar_header->length;
	}
}

void protect_iommu_pages(void)
{
	int i;
	u64 end;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect IOMMU\n");

	end = (u64)global_dmar_data.p4_page_addr_array + global_dmar_data.p4_page_count * sizeof(u64 *);
	hide_range((u64)global_dmar_data.p4_page_addr_array, end, 1);

	end = (u64)global_dmar_data.p3_page_addr_array + global_dmar_data.p3_page_count * sizeof(u64 *);
	hide_range((u64)global_dmar_data.p3_page_addr_array, end, 1);

	end = (u64)global_dmar_data.p2_page_addr_array + global_dmar_data.p2_page_count * sizeof(u64 *);
	hide_range((u64)global_dmar_data.p2_page_addr_array, end, 1);

	end = (u64)global_dmar_data.p1_page_addr_array + global_dmar_data.p1_page_count * sizeof(u64 *);
	hide_range((u64)global_dmar_data.p1_page_addr_array, end, 1);

	for (i = 0; i < global_dmar_data.p4_page_count; i++)
	{
		end = (u64)global_dmar_data.p4_page_addr_array[i] + 0x1000;
		hide_range((u64)global_dmar_data.p4_page_addr_array[i], end, 0);
	}

	for (i = 0; i < global_dmar_data.p3_page_count; i++)
	{
		end = (u64)global_dmar_data.p3_page_addr_array[i] + 0x1000;
		hide_range((u64)global_dmar_data.p3_page_addr_array[i], end, 0);
	}

	for (i = 0; i < global_dmar_data.p2_page_count; i++)
	{
		end = (u64)global_dmar_data.p2_page_addr_array[i] + 0x1000;
		hide_range((u64)global_dmar_data.p2_page_addr_array[i], end, 0);
	}

	for (i = 0; i < global_dmar_data.p1_page_count; i++)
	{
		end = (u64)global_dmar_data.p1_page_addr_array[i] + 0x1000;
		hide_range((u64)global_dmar_data.p1_page_addr_array[i], end, 0);
	}

	end = (u64)global_dmar_data.root_entry_table_addr + 0x1000;
	hide_range((u64)global_dmar_data.root_entry_table_addr, end, 0);

	end = (u64)global_dmar_data.context_entry_table_addr + 0x1000;
	hide_range((u64)global_dmar_data.context_entry_table_addr, end, 0);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");
}