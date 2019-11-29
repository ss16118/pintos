#include "frame.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "threads/pte.h"
#include "threads/malloc.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/process.h"
#include <string.h>

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
void * frame_add_entry(struct spage_table_entry *spte)
{
  uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);

  if (kpage != NULL)
  {
    struct frame_table_entry *new_entry =
        malloc(sizeof(struct frame_table_entry *));
    if (new_entry != NULL)
    {
      size_t page_read_bytes = 0;
      size_t page_zero_bytes = PGSIZE;
      bool writable = true;
      // If the new page allocated is used for stack growth
      if (spte != NULL && !strlen(spte->file_name) == 0)
      {
        /* Load this page. */
        // printf("File name : %s\n", spte->file_name);
        struct file *file_to_load = filesys_open(spte->file_name);
        // struct file *file_to_load = file_reopen(spte->file);
        page_read_bytes = spte->page_read_byte;
        page_zero_bytes = PGSIZE - page_read_bytes;
        writable = spte->writable;
        if (file_read_at(file_to_load, kpage, page_read_bytes, spte->ofs) != (int) page_read_bytes)
        {
          file_close(file_to_load);
          palloc_free_page (kpage);
          return NULL;
        }
        file_close(file_to_load);
      }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      if (!install_page(spte->uaddr, kpage, writable)) 
      {
        return NULL;
      }

      spte->is_installed = true;
      new_entry->kpage_addr = kpage;
      new_entry->owner = thread_current();
      lock_acquire(&frame_table_lock);
      list_push_back(&frame_table, &new_entry->elem);
      lock_release(&frame_table_lock);
      // printf("Frame table entry added %p\n", kpage);
      return vtop(new_entry->kpage_addr);
    }
  }
  else
  {
    // TODO: Implement eviction
  }
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