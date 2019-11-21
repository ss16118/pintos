#include "frame.h"

static struct list frame_table;
static struct lock frame_table_lock;

void frame_init(void)
{
  list_init(&frame_table);
  lock_init(&frame_table_lock);
}