#include "swap.h"

static struct block *swap_blocks;

void swap_init(void) 
{
  swap_blocks = block_get_role(BLOCK_SWAP);
}

/**
 * Read the content from swap_blocks into the given frame starting
 * from the given sector.
 */
void read_from_block(block_sector_t sector, void *frame)
{
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_read(swap_blocks, secotr + i, frame + (i * BLOCK_SECTOR_SIZE));
  }
}

/**
 * Write the content from the given frame into swap_blocks staring
 * from the given sector.
 */
void write_from_block(block_sector_t sector, void *frame)
{
  for (int i = 0; i < SECTORS_PER_PAGE; i++)
  {
    block_write(swap_blocks, secotr + i, frame + (i * BLOCK_SECTOR_SIZE));
  }
}

