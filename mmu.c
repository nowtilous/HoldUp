#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/rwlock_types.h>
#include <linux/reboot.h>
#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/version.h>
#include "mmu.h"
#include "holdup_main.h"

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
#include <linux/vmalloc.h>
#endif

struct ept_data global_ept_data = {0,};
static u64 global_ram_end;


static void set_ept_page_addr(u64 phy_addr, u64 addr);
static void set_ept_page_flags(u64 phy_addr, u32 flags);

static void setup_ept_system_ram_range(void);

static int callback_walk_ram(unsigned long start, unsigned long size, void* arg);
static int callback_set_write_back_to_ram(unsigned long start, unsigned long size, void* arg);

#ifdef __GNUC__
#pragma region MEMORY_FUNCTIONS_EPT
#endif
/*
EPT allocating functions
Input:  none
Output:  allocates EPTs and returns 0 upon success, -1 otherwise
*/
int alloc_ept_pages(void)
{
	int i;

	global_ept_data.p4_entries_count = CEIL(global_max_ram_size, S_512GB);
	global_ept_data.p3_entries_count = CEIL(global_max_ram_size, S_1GB);
	global_ept_data.p2_entries_count = CEIL(global_max_ram_size, S_2MB);
	global_ept_data.p1_entries_count = CEIL(global_max_ram_size, S_4KB);

	global_ept_data.p4_page_count = CEIL(global_ept_data.p4_entries_count, EPT_PAGE_ENT_COUNT);
	global_ept_data.p3_page_count = CEIL(global_ept_data.p3_entries_count, EPT_PAGE_ENT_COUNT);
	global_ept_data.p2_page_count = CEIL(global_ept_data.p2_entries_count, EPT_PAGE_ENT_COUNT);
	global_ept_data.p1_page_count = CEIL(global_ept_data.p1_entries_count, EPT_PAGE_ENT_COUNT);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Setup EPT, Max RAM Size %ld\n", global_max_ram_size);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] EPT Size: %d\n", (int)sizeof(struct ept_pagetable));
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P4 Entry Count: %d\n", (int)global_ept_data.p4_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*]  P3 Entry Count: %d\n", (int)global_ept_data.p3_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Entry Count: %d\n", (int)global_ept_data.p2_entries_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Entry Count: %d\n", (int)global_ept_data.p1_entries_count);

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] P4 Page Count: %d\n", (int)global_ept_data.p4_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*]  P3 Page Count: %d\n", (int)global_ept_data.p3_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PDE PT Page Count: %d\n", (int)global_ept_data.p2_page_count);
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] PTE Page Count: %d\n", (int)global_ept_data.p1_page_count);

	/* Allocate memory for page table. */
	global_ept_data.p4_page_addr_array = (u64*)vmalloc(global_ept_data.p4_page_count * sizeof(u64*));
	global_ept_data.p3_page_addr_array = (u64*)vmalloc(global_ept_data.p3_page_count * sizeof(u64*));
	global_ept_data.p2_page_addr_array = (u64*)vmalloc(global_ept_data.p2_page_count * sizeof(u64*));
	global_ept_data.p1_page_addr_array = (u64*)vmalloc(global_ept_data.p1_page_count * sizeof(u64*));

	if ((global_ept_data.p4_page_addr_array == NULL) ||
		(global_ept_data.p3_page_addr_array == NULL) ||
		(global_ept_data.p2_page_addr_array == NULL) ||
		(global_ept_data.p1_page_addr_array == NULL))
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_ept_pages alloc fail\n");
		return -1;
	}

	for (i = 0 ; i < global_ept_data.p4_page_count ; i++)
	{
		global_ept_data.p4_page_addr_array[i] = (u64)kmalloc(0x1000,GFP_KERNEL);
		if (global_ept_data.p4_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_ept_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0 ; i < global_ept_data.p3_page_count ; i++)
	{
		global_ept_data.p3_page_addr_array[i] = (u64)kmalloc(0x1000,GFP_KERNEL);

		if (global_ept_data.p3_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_ept_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0 ; i < global_ept_data.p2_page_count ; i++)
	{
		global_ept_data.p2_page_addr_array[i] = (u64)kmalloc(0x1000,GFP_KERNEL);

		if (global_ept_data.p2_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_ept_pages alloc fail\n");
			return -1;
		}
	}

	for (i = 0 ; i < global_ept_data.p1_page_count ; i++)
	{
		global_ept_data.p1_page_addr_array[i] = (u64)kmalloc(0x1000,GFP_KERNEL);

		if (global_ept_data.p1_page_addr_array[i] == 0)
		{
			not_printf(LOG_LEVEL_ERROR, LOG_INFO " alloc_ept_pages alloc fail\n");
			return -1;
		}
	}

	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Page Table Memory Alloc Success\n");

	return 0;
}

/*
EPT freeing function
Input:  none
Output:  frees EPTs
*/
void free_ept_pages(void)
{
	if (global_ept_data.p4_page_addr_array != 0)
	{
		kfree(global_ept_data.p4_page_addr_array);
		global_ept_data.p4_page_addr_array = 0;
	}

	if (global_ept_data.p3_page_addr_array != 0)
	{
		kfree(global_ept_data.p3_page_addr_array);
		global_ept_data.p3_page_addr_array = 0;
	}

	if (global_ept_data.p2_page_addr_array != 0)
	{
		kfree(global_ept_data.p2_page_addr_array);
		global_ept_data.p2_page_addr_array = 0;
	}

	if (global_ept_data.p1_page_addr_array != 0)
	{
		kfree(global_ept_data.p1_page_addr_array);
		global_ept_data.p1_page_addr_array = 0;
	}
}

void setup_ept_pagetable_4KB(void)
{
	struct ept_pagetable* ept_info;
	u64 next_page_table_addr;
	u64 i;
	u64 j;
	u64 loop_cnt;
	u64 base_addr;

	/* Setup P4 */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup PLML4\n");
	ept_info = (struct ept_pagetable*)get_pagetable_logical_addr(EPT_TYPE_P4, 0);
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup P4 %016lX\n", (u64)ept_info);
	memset(ept_info, 0, sizeof(struct ept_pagetable));

	base_addr = 0;
	for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
	{
		if (i < global_ept_data.p4_entries_count)
		{
			next_page_table_addr = (u64)get_pagetable_physical_addr(EPT_TYPE_P3, i);
			ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

			if (i == 0)
			{
				not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table_addr);
			}
		}
		else
		{
			ept_info->entry[i] = base_addr | EPT_ALL_ACCESS;
		}

		base_addr += S_512GB;
	}

	/* Setup P3. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P3\n");
	base_addr = 0;
	for (j = 0 ; j < global_ept_data.p3_page_count ; j++)
	{
		ept_info = (struct ept_pagetable*)get_pagetable_logical_addr(EPT_TYPE_P3, j);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup P3 [%d] %016lX\n", j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct ept_pagetable));

		loop_cnt = global_ept_data.p3_entries_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)get_pagetable_physical_addr(EPT_TYPE_P2, (j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS;
			}

			base_addr += S_1GB;
		}
	}

	/* Setup P2. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P2\n");
	base_addr = 0;
	for (j = 0 ; j < global_ept_data.p2_page_count ; j++)
	{
		ept_info = (struct ept_pagetable*)get_pagetable_logical_addr(EPT_TYPE_P2, j);
		not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] Setup P2 [%d] %016lX\n", j, (u64)ept_info);
		memset(ept_info, 0, sizeof(struct ept_pagetable));

		loop_cnt = global_ept_data.p2_entries_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = (u64)get_pagetable_physical_addr(EPT_TYPE_P1, (j * EPT_PAGE_ENT_COUNT) + i);
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;

				if (i == 0)
				{
					not_printf(LOG_LEVEL_DETAIL, LOG_INFO "    [*] %016lX\n", (u64)next_page_table_addr);
				}
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS;
			}

			base_addr += S_2MB;
		}
	}

	/* Setup P1. */
	not_printf(LOG_LEVEL_DETAIL, LOG_INFO "Setup P1\n");
	for (j = 0 ; j < global_ept_data.p1_page_count ; j++)
	{
		ept_info = (struct ept_pagetable*)get_pagetable_logical_addr(EPT_TYPE_P1, j);
		memset(ept_info, 0, sizeof(struct ept_pagetable));

		loop_cnt = global_ept_data.p1_entries_count - (j * EPT_PAGE_ENT_COUNT);
		if (loop_cnt > EPT_PAGE_ENT_COUNT)
		{
			loop_cnt = EPT_PAGE_ENT_COUNT;
		}

		for (i = 0 ; i < EPT_PAGE_ENT_COUNT ; i++)
		{
			if (i < loop_cnt)
			{
				next_page_table_addr = ((u64)j * EPT_PAGE_ENT_COUNT + i) * EPT_PAGE_SIZE;
				ept_info->entry[i] = next_page_table_addr | EPT_ALL_ACCESS;
			}
			else
			{
				ept_info->entry[i] = base_addr | EPT_ALL_ACCESS;
			}

			base_addr += S_4KB;
		}
	}

	setup_ept_system_ram_range();
}

static void setup_ept_system_ram_range(void)
{
	my_walk_system_ram_range func = NULL;

	func = (my_walk_system_ram_range)get_symbol_address("walk_system_ram_range");
	if (func == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return ;
	}

	func(0, global_max_ram_size / PAGE_SIZE, NULL, callback_set_write_back_to_ram);
}
#ifdef __GNUC__
#pragma endregion
#endif

#ifdef __GNUC__
#pragma region MEMORY_TRANSLATION 
#endif
void *get_pagetable_logical_addr(int type, int index)
{
	u64* table_array_addr;

	switch(type)
	{
	case EPT_TYPE_P4:
		table_array_addr = global_ept_data.p4_page_addr_array;
		break;

	case EPT_TYPE_P3:
		table_array_addr = global_ept_data.p3_page_addr_array;
		break;

	case EPT_TYPE_P2:
		table_array_addr = global_ept_data.p2_page_addr_array;
		break;

	case EPT_TYPE_P1:
	default:
		table_array_addr = global_ept_data.p1_page_addr_array;
		break;
	}

	return (void*)table_array_addr[index];
}

void *get_pagetable_physical_addr(int type, int index)
{
	void* table_logical_addr;

	table_logical_addr = get_pagetable_logical_addr(type, index);
	return (void*)virt_to_phys(table_logical_addr);
}
#ifdef __GNUC__
#pragma endregion
#endif

#ifdef __GNUC__
#pragma region  SET_PAGE_FUNCTIONS
#endif
static void set_ept_page_flags(u64 phy_addr, u32 flags)
{
	u64 page_offset, page_index, *page_table_addr;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = get_pagetable_logical_addr(EPT_TYPE_P1, page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (page_table_addr[page_index] & MASK_PAGE_ADDR) | flags;
}

static void set_ept_page_addr(u64 phy_addr, u64 addr)
{
	u64 page_offset, page_index, *page_table_addr;

	page_offset = phy_addr / EPT_PAGE_SIZE;
	page_index = page_offset % EPT_PAGE_ENT_COUNT;
	page_table_addr = get_pagetable_logical_addr(EPT_TYPE_P1, page_offset / EPT_PAGE_ENT_COUNT);
	page_table_addr[page_index] = (addr & MASK_PAGE_ADDR) | (page_table_addr[page_index] & ~MASK_PAGE_ADDR);
}

void set_ept_hide_page(u64 phy_addr)
{
	set_ept_page_flags(phy_addr, EPT_READ | EPT_BIT_MEM_TYPE_WB);
	set_ept_page_addr(phy_addr, 0);
}

void set_ept_read_only_page(u64 phy_addr)
{
	set_ept_page_flags(phy_addr, EPT_READ | EPT_BIT_MEM_TYPE_WB);
	set_ept_page_addr(phy_addr, phy_addr);
}

void set_ept_lock_page(u64 phy_addr)
{
	set_ept_page_flags(phy_addr, EPT_READ | EPT_EXECUTE | EPT_BIT_MEM_TYPE_WB);
	set_ept_page_addr(phy_addr, phy_addr);
}

void set_ept_all_access_page(u64 phy_addr)
{
	set_ept_page_flags(phy_addr, EPT_ALL_ACCESS | EPT_BIT_MEM_TYPE_WB);
	set_ept_page_addr(phy_addr, phy_addr);
}
#pragma endregion

#ifdef __GNUC__
#pragma region CALLBACKS
#endif
static int callback_set_write_back_to_ram(unsigned long start, unsigned long size, void* arg)
{
	struct ept_pagetable* ept_info;
	unsigned long i;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE, size * PAGE_SIZE);

	for (i = start ; i < start + size ; i++)
	{
		ept_info = (struct ept_pagetable*)get_pagetable_logical_addr(EPT_TYPE_P1, i / EPT_PAGE_ENT_COUNT);
		ept_info->entry[i %  EPT_PAGE_ENT_COUNT] |= EPT_BIT_MEM_TYPE_WB;
	}

	return 0;
}

static int callback_walk_ram(unsigned long start, unsigned long size, void* arg)
{
	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "System RAM start %016lX, end %016lX, size %016lX\n", start * PAGE_SIZE, start * PAGE_SIZE + size * PAGE_SIZE, size * PAGE_SIZE);

	if (global_ram_end < ((start + size) * PAGE_SIZE))
	{
		global_ram_end = (start + size) * PAGE_SIZE;
	}

	return 0;
}
#ifdef __GNUC__
#pragma endregion
#endif
u64 get_max_ram_size(void)
{
	my_walk_system_ram_range func = NULL;

	global_ram_end = 0;

	/* Getting the system walk_system_ram_range fumction from the symbol list
	 * https://elixir.bootlin.com/linux/latest/source/arch/powerpc/mm/mem.c#L185
	 */
	func = (my_walk_system_ram_range)get_symbol_address("walk_system_ram_range");
	if (func == NULL)
	{
		not_printf(LOG_LEVEL_ERROR, LOG_INFO "walk_system_ram_range fail\n");
		return totalram_pages * 2 * S_4KB;
	}
	/* Using the walk_system_ram_range system function to call callback_walk_ram (that counts the number of pages) against all memory ranges of type System RAM which are marked as IORESOURCE_SYSTEM_RAM and IORESOUCE_BUSY
	 * with what method we counting the size of the ram
	 */
	func(0, totalram_pages * 2, NULL, callback_walk_ram);

	return global_ram_end;
}

void protect_ept_pages(void)
{
	int i;
	u64 end;

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "Protect EPT\n");

	//Hide the EPT page table
	end = (u64)global_ept_data.p4_page_addr_array + global_ept_data.p4_page_count * sizeof(u64*);
	hide_range((u64)global_ept_data.p4_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)global_ept_data.p3_page_addr_array + global_ept_data.p3_page_count * sizeof(u64*);
	hide_range((u64)global_ept_data.p3_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)global_ept_data.p2_page_addr_array + global_ept_data.p2_page_count * sizeof(u64*);
	hide_range((u64)global_ept_data.p2_page_addr_array, end, ALLOC_VMALLOC);

	end = (u64)global_ept_data.p1_page_addr_array + global_ept_data.p1_page_count * sizeof(u64*);
	hide_range((u64)global_ept_data.p1_page_addr_array, end, ALLOC_VMALLOC);

	for (i = 0 ; i < global_ept_data.p4_page_count ; i++)
	{
		end = (u64)global_ept_data.p4_page_addr_array[i] + EPT_PAGE_SIZE;
		hide_range((u64)global_ept_data.p4_page_addr_array[i], end, ALLOC_KMALLOC);
	}

	for (i = 0 ; i < global_ept_data.p3_page_count ; i++)
	{
		end = (u64)global_ept_data.p3_page_addr_array[i] + EPT_PAGE_SIZE;
		hide_range((u64)global_ept_data.p3_page_addr_array[i], end, ALLOC_KMALLOC);
	}

	for (i = 0 ; i < global_ept_data.p2_page_count ; i++)
	{
		end = (u64)global_ept_data.p2_page_addr_array[i] + EPT_PAGE_SIZE;
		hide_range((u64)global_ept_data.p2_page_addr_array[i], end, ALLOC_KMALLOC);
	}

	for (i = 0 ; i < global_ept_data.p1_page_count ; i++)
	{
		end = (u64)global_ept_data.p1_page_addr_array[i] + EPT_PAGE_SIZE;
		hide_range((u64)global_ept_data.p1_page_addr_array[i], end, ALLOC_KMALLOC);
	}

	not_printf(LOG_LEVEL_DEBUG, LOG_INFO "    [*] Complete\n");
}