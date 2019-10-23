#ifndef __MMU_H__
#define __MMU_H__

/* Page table flags. */
#define MASK_PAGE_FLAG			((u64) 0xFF00000000000FFF)
#define MASK_PAGE_FLAG_WO_DA		(((u64) 0xFF00000000000FFF) ^ (0x01 << 5) ^ (0x01 << 6))
#define MASK_PAGE_SIZE_FLAG		(0x01 << 7)
#define MASK_PAGE_FLAG_WO_SIZE	(MASK_PAGE_FLAG ^ MASK_PAGE_SIZE_FLAG)
#define MASK_PRESENT_FLAG		(0x01 << 0)
#define MASK_PAGE_ADDR			((u64) 0xFFFFFFFFFFFFF000)

/*EPT falgs*/
#define EPT_READ				(0x01 << 0)
#define EPT_WRITE				(0x01 << 1)
#define EPT_EXECUTE				(0x01 << 2)
#define EPT_ALL_ACCESS			(EPT_READ | EPT_WRITE | EPT_EXECUTE)
#define EPT_BIT_MEM_TYPE_WB		(0x06 << 3)
#define EPT_PAGE_ENT_COUNT		512
#define EPT_PAGE_SIZE			4096

/* EPT page type. */
#define EPT_TYPE_P4			0
#define EPT_TYPE_P3		    1
#define EPT_TYPE_P2			2
#define EPT_TYPE_P1			3

#define IS_PRESENT(x)			((x) & MASK_PRESENT_FLAG)
#define IS_SIZE_FLAG_SET(x)		((x) & MASK_PAGE_SIZE_FLAG)
#define GET_ADDR(x)				((x) & ~MASK_PAGE_FLAG)

#define S_1TB					((u64)1 * 1024 * 1024 * 1024 * 1024)
#define S_512GB				((u64)512 * 1024 * 1024 * 1024)
#define S_4GB					((u64)4* 1024 * 1024 * 1024)
#define S_1GB					((u64)1024 * 1024 * 1024)
#define S_2MB					((u64)2 * 1024 * 1024)
#define S_4KB					((u64)4 * 1024)

/*
    Low (4) -> High (1)
    +----------+------------------------+---------------+
    | NEW NAME |       DESCRIPTION      | OFFICIAL NAME |
    +----------+------------------------+---------------+
    |    P4    | pagetable level 4 page |      PML4     |
    +----------+------------------------+---------------+
    |    P3    | pagetable level 3 page |      PDP      |
    +----------+------------------------+---------------+
    |    P2    | pagetable level 2 page |       PD      |
    +----------+------------------------+---------------+
    |    P1    | pagetable level 1 page |       PT      |
    +----------+------------------------+---------------+
*/

struct pagetable
{
    u64 entry[512];
};

struct ept_pagetable
{
    u64 entry[512];
};

struct ept_data
{
    u64 p4_entries_count;
    u64 p3_entries_count;
    u64 p2_entries_count;
    u64 p1_entries_count;

    u64 p4_page_count;
    u64 p3_page_count;
    u64 p2_page_count;
    u64 p1_page_count;

    u64 *p4_page_addr_array;
    u64 *p3_page_addr_array;
    u64 *p2_page_addr_array;
    u64 *p1_page_addr_array;
};


struct vm_page_entry
{
	u64 phy_addr[4];
};

extern struct ept_data global_ept_data;

/* Function prototype for using the system walk_system_ram_range*/
typedef int (*my_walk_system_ram_range) (unsigned long start_pfn, unsigned long nr_pages,
	void *arg, int (*func)(unsigned long, unsigned long, void*));

u64 get_max_ram_size(void);

void set_ept_hide_page(u64 phy_addr);
void set_ept_lock_page(u64 phy_addr);
void set_ept_read_only_page(u64 phy_addr);
void set_ept_all_access_page(u64 phy_addr);

void protect_ept_pages(void);

void setup_ept_pagetable_4KB(void);
int alloc_ept_pages(void);
void free_ept_pages(void);

void* get_pagetable_logical_addr(int type, int index);
void* get_pagetable_physical_addr(int iType, int iIndex);


#endif //_MMU_H_