#include "frame.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/malloc.h"

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
 * @param kpage_addr: the address of the kernel page.
 * @return the pointer to the struct frame_table_entry containing
 * the specific frame address if it exists in the table.
 */
static struct frame_table_entry *frame_table_lookup(void *kpage_addr)
{
  for (struct list_elem *e = list_begin(&frame_table);
       e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_table_entry *entry =
        list_entry(e, struct frame_table_entry, elem);
    if (entry->kpage_addr == kpage_addr)
    {
      return entry;
    }
  }
  return NULL;
}


/**
 * Adds a new entry to the frame table.
 * @param kpage: the address to the kernel page allocated
 * by palloc_get_page().
 * @return: the address of the physical frame if the allocation is
 * successful, otherwise, return NULL.
 */
void *frame_add_entry(void *kpage)
{
  if (kpage != NULL)
  {
    struct frame_table_entry *new_entry =
        malloc(sizeof(struct frame_table_entry *));
    if (new_entry != NULL)
    {
      new_entry->kpage_addr = kpage;
      new_entry->owner = thread_current();
      lock_acquire(&frame_table_lock);
      list_push_back(&frame_table, &new_entry->elem);
      lock_release(&frame_table_lock);

      return vtop(new_entry->kpage_addr);
    }
  }

  // TODO: ELSE should utilize swap

  return NULL;
}


/**
 * Removes the entry from the frame table given the address of the frame.
 * Returns true if the removal is successful, false otherwise.
 * @return: a boolean indicating whether the removal is successful.
 */
bool frame_remove_entry(void *kpage_addr)
{
  lock_acquire(&frame_table_lock);
  struct frame_table_entry *entry = frame_table_lookup(kpage_addr);
  if (entry != NULL)
  {
    list_remove(&entry->elem);
    free(entry);
    lock_release(&frame_table_lock);
    return true;
  }
  lock_release(&frame_table_lock);
  return false;
}


/**
 * Frees the frame table entries according to the page address in
 * the given page directory.
 */
void frame_free_entries_from_pd(uint32_t *pd)
{
  if (pd == NULL)
    return;

  uint32_t *pde;

  ASSERT(pd != init_page_dir);
  for (pde = pd; pde < pd + pd_no(PHYS_BASE); pde++)
  {
    if (*pde & PTE_P)
    {
      uint32_t *pt = pde_get_pt(*pde);
      uint32_t *pte;

      for (pte = pt; pte < pt + PGSIZE / sizeof *pte; pte++)
      {
        if (*pte & PTE_P)
        {
          frame_remove_entry(pte_get_page(*pte));
        }
      }
    }
  }
}



/**
 * Retrieves the frame table entry containing the given frame address.
 * Returns NULL if the entry does not exist.
 * @param kpage: the kernel page address to be searched for.
 * @return: the pointer to the struct frame table entry, if it exists.
 */
struct frame_table_entry *frame_get_frame(void *kpage_addr)
{
  return frame_table_lookup(kpage_addr);
}