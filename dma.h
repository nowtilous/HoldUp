#ifndef __DMA_H__
#define __DMA_H__

#include <linux/vmalloc.h>
#include "holdup_main.h"

/* Page table flags. */
#define ENTRY_PRESENT				(0x01 << 0)
#define ENTRY_3LEVEL_PTE			(0x01 << 0)
#define ENTRY_4LEVEL_PTE			(0x01 << 1)

#define IOMMU_PAGE_PRESENT			(0x01 << 0)
#define IOMMU_PAGE_RW				(0x01 << 1)
#define IOMMU_PAGE_ALL_ACCESS		(IOMMU_PAGE_PRESENT | IOMMU_PAGE_RW)


/* Page size macro. */
#define IOMMU_PAGE_ENT_COUNT		512
#define IOMMU_PAGE_SIZE				4096

/* DMAR page type. */
#define IOMMU_TYPE_P4				0
#define IOMMU_TYPE_P3				1
#define IOMMU_TYPE_P2				2
#define IOMMU_TYPE_P1				3

/*
* va = virtual adress
* pa = physical address
*/

struct iommu_pagetable
{
	u64 entry[512];
};

struct iommu_data
{
	u64 p4_entries_count;
	u64 p3_entries_count;
	u64 p2_entries_count;
	u64 p1_entries_count;

	u64 p4_page_count;
	u64 p3_page_count;
	u64 p2_page_count;
	u64 p1_page_count;

	u64* p4_page_addr_array;
	u64* p3_page_addr_array;
	u64* p2_page_addr_array;
	u64* p1_page_addr_array;

	u64* root_entry_table_addr;
	u64* context_entry_table_addr;
};

/* Root table entry structure. */
struct root_entry
{
	u64	val;
	u64	rsvd1;
};

/* Context table entry structure. */
struct context_entry
{
	u64	lo;
	u64	hi;
};


int alloc_iommu_pages(void);
void free_iommu_pages(void);

void lock_iommu(void);
void unlock_iommu(void);

void protect_iommu_pages(void);

void set_iommu_page_flags(u64 phy_addr, u32 flags);
void set_iommu_hide_page(u64 phy_addr);
void set_iommu_all_access_page(u64 phy_addr);

void setup_iommu_pagetable_4KB(void);
int check_iommu(void);

#endif //_DMA_H_
