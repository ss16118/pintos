#include "devices/block.h"

#include "threads/vaddr.h"

#ifndef VM_SWAP_H
#define VM_SWAP_H

#define SWAP_ERROR -1
typedef size_t swap_index;

/* SWAP SLOTS
 * 
 * A swap slot is a continuous, page-size region of disk space in the swap
 * partition, Although hardware limitations dictating the placement of slots are
 * looser than for pages and frames, swap slots should be page-aligned because
 * there is no downside in doing so.
 */

#define SECTORS_PER_PAGE (PGSIZE / BLOCK_SECTOR_SIZE)

void swap_init(void);

swap_index swap_get_free_slots(void);
swap_index swap_get_used_slots(void);
void swap_clear_slot(swap_index);
swap_index swap_frame_to_slot(void *);
void swap_slot_to_frame(swap_index, void *);

#endif /* vm/swap.h */