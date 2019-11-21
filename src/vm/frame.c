#include "frame.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"

static struct list frame_table;
static struct lock frame_table_lock;

void frame_init(void)
{
  list_init(&frame_table);
  lock_init(&frame_table_lock);
}

/**
 * Retrieves the frame table entry from the frame table given the
 * frame address. If the frame table does not contain an entry
 * with the frame address, return NULL.
 * @param frame_addr: the address of the frame.
 * @return the pointer to the struct frame_table_entry containing
 * the specific frame address if it exists in the table.
 */
static struct frame_table_entry *frame_table_lookup(uint32_t *frame_addr)
{
  for (struct list_elem *e = list_begin(&frame_table);
       e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_table_entry *entry =
        list_entry(e, struct frame_table_entry, elem);
    if (entry->frame_addr == frame_addr)
    {
      return entry;
    }
  }
  return NULL;
}



/**
 * Adds a new entry to the frame table.
 * @return: the address of the physical frame if the allocation is
 * successful, otherwise, return NULL.
 */
uint32_t *frame_add_entry(void)
{
  uint32_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL)
  {
    struct frame_table_entry *new_entry =
        malloc(sizeof(struct frame_table_entry *));
    new_entry->frame_addr = kpage - (uint32_t *) PHYS_BASE;
    new_entry->owner = thread_current();

    lock_acquire(&frame_table_lock);
    list_push_back(&frame_table, &new_entry->elem);
    lock_release(&frame_table_lock);

    return new_entry->frame_addr;
  }
  return NULL;
}


/**
 * Removes the entry from the frame table given the address of the frame.
 * Returns true if the removal is successful, false otherwise.
 * @return: a boolean indicating whether the removal is successful.
 */
bool frame_remove_entry(uint32_t *frame_addr)
{
  lock_acquire(&frame_table_lock);
  struct frame_table_entry *entry = frame_table_lookup(frame_addr);
  if (entry != NULL)
  {
    list_remove(&entry->elem);
    lock_release(&frame_table_lock);
    return true;
  }
  lock_release(&frame_table_lock);
  return false;
}


/**
 * Retrieves the frame table entry containing the given frame address.
 * Returns NULL if the entry does not exist.
 * @param frame_addr: the frame address to be searched for.
 * @return: the pointer to the struct frame table entry, if it exists.
 */
struct frame_table_entry *frame_get_frame(uint32_t *frame_addr)
{
  return frame_table_lookup(frame_addr);
}