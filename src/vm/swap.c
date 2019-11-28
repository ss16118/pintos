#include "swap.h"

#include "lib/kernel/bitmap.h"

#include "threads/synch.h"

static struct block *swap_blocks;
static struct bitmap *swap_table;
static struct lock swap_lock;
static size_t swap_slot_count;

static void read_from_block(block_sector_t, void *);
static void write_from_block(block_sector_t, void *);
static block_sector_t swap_index_to_sector(swap_index);

void swap_init(void) 
{
  lock_init(&swap_lock);
  swap_blocks = block_get_role(BLOCK_SWAP);
  swap_slot_count = block_size(swap_blocks) * BLOCK_SECTOR_SIZE / PGSIZE;
  swap_table = bitmap_create(swap_slot_count);
}

/* Check if the swap table has any free swap slots */
bool swap_has_free_slots()
{
  return bitmap_scan(swap_table, 0, 1, false);
}

swap_index swap_get_free_slots()
{
  return bitmap_scan_and_flip(swap_table, 0, 1, false);
}

/* Attempts to swap the given FRAME into memory, will select the swap slot from
   available slots in the swap table. If no slots are avilable, return NULL
   @param frame, the frame to swap into a slot
   @return the index of the slot within the swap table that the frame has been
           swapped into. NULL if no slots are available
*/
swap_index swap_frame_to_slot(void * frame)
{
  lock_acquire(&swap_lock);
  swap_index free_slot = swap_get_free_slots();
  if (free_slot != BITMAP_ERROR)
  {
    write_from_block(swap_index_to_sector(free_slot), frame);
    lock_release(&swap_lock);
    return free_slot;
  }
  lock_release(&swap_lock);
  return NULL;
}

void swap_slot_to_frame(swap_index index, void *frame)
{
  if (index < swap_slot_count)
  {
    return read_from_block(swap_index_to_sector(index), frame);
  }
  return NULL;
}

/**
 * Read the content from swap_blocks into the given frame starting
 * from the given sector.
 */
static
void read_from_block(block_sector_t sector, void *frame)
{
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_read(swap_blocks, sector + i, frame + (i * BLOCK_SECTOR_SIZE));
  }
}

/**
 * Write the content from the given frame into swap_blocks staring
 * from the given sector.
 */
static
void write_from_block(block_sector_t sector, void *frame)
{
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_write(swap_blocks, sector + i, frame + (i * BLOCK_SECTOR_SIZE));
  }
}

static
block_sector_t swap_index_to_sector(swap_index index)
{
  return index / swap_slot_count * block_size(swap_blocks);
}