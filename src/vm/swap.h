#ifndef VM_SWAP_H
#define VM_SWAP_H
#include "devices/block.h"
#include "threads/vaddr.h"
/* SWAP SLOTS
 * 
 * A swap slot is a continuous, page-size region of disk space in the swap
 * partition, Although hardware limitations dictating the placement of slots are
 * looser than for pages and frames, swap slots should be page-aligned because
 * there is no downside in doing so.
 */

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);

void read_from_block(block_sector_t, void *);
void write_from_block(block_sector_t, void *);

#endif /* vm/swap.h */