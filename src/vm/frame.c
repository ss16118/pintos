#include "frame.h"

#include <string.h>

#include "devices/timer.h"
#include "threads/init.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/pte.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include "swap.h"

static struct list frame_table;
static struct lock frame_table_lock;

static void *evict_frame(void);
static void *reclaim_frame(struct spage_table_entry *);

static int frame_table_index = 0;

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
  // printf("looking up %p\n", kpage_addr);
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
 * @return: the address of the frame entry if the allocation is
 * successful, otherwise, return NULL.
 */
void *frame_add_entry(struct spage_table_entry *spte)
{
  if (spte != NULL)
  {
    // printf("frame adding entry for %p\n", spte->uaddr);
    struct frame_table_entry *new_entry =
                                       malloc(sizeof(struct frame_table_entry));

    if (new_entry != NULL)
    {
      uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
      bool writable = true;
      while (kpage == NULL)
      {
        kpage = evict_frame();
        // printf("received free frame: %p\n", kpage);
      }
      if (spte->is_swapped)
      {
        // printf("upage: %p was swapped, checking swap slot %d\n", spte->uaddr, spte->swap_slot);
        // Page needs to be swapped in from swap slot
        swap_slot_to_frame(spte->swap_slot, kpage);
        swap_clear_slot(spte->swap_slot);
      }
      else
      {
        size_t page_read_bytes = 0;
        size_t page_zero_bytes = PGSIZE;
        // If the new page allocated is used for stack growth
        if (!strlen(spte->file_name) == 0)
        {
          // printf("loading file: %s\n", spte->file_name);
          /* Load this page. */
          struct file *file_to_load = filesys_open(spte->file_name);
          page_read_bytes = spte->page_read_byte;
          page_zero_bytes = PGSIZE - page_read_bytes;
          writable = spte->writable;
          if (file_read_at(file_to_load, kpage, page_read_bytes, spte->ofs) != (int) page_read_bytes)
          {
            // printf("failed to load file\n");
            file_close(file_to_load);
            palloc_free_page (kpage);
            return NULL;
          }
          // printf("successfully read from file\n");
          file_close(file_to_load);
        }
        memset (kpage + page_read_bytes, 0, page_zero_bytes);
        // printf("memset complete\n");
      }
      // printf("upage %p\n", spte->uaddr);
      // printf("kpage %p\n", kpage);
      // printf("writable %d\n", writable);
      if (!install_page(spte->uaddr, kpage, writable)) 
      {
        // printf("installation of %p failed\n", kpage);
        palloc_free_page(kpage);
        return NULL;
      }
      // printf("installed upage %p and kpage %p\n", spte->uaddr, kpage);

      spte->is_installed = true;
      new_entry->pinned = false;
      new_entry->kpage_addr = kpage;
      new_entry->uaddr = spte->uaddr;
      new_entry->owner = thread_current();
      new_entry->second_chance = false;
      lock_acquire(&frame_table_lock);
      list_push_back(&frame_table, &new_entry->elem);
      lock_release(&frame_table_lock);
      // printf("Frame table entry added %p\n", kpage);
      return new_entry;
    }
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
    palloc_free_page(entry->kpage_addr);
    free(entry);
    lock_release(&frame_table_lock);
    return true;
  }
  lock_release(&frame_table_lock);
  return false;
}


/**
 * Frees the frame table entries according to the page address in
 * the given page directory. USED ONLY DURING PROCESS EXIT
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
          // frame_remove_entry(pte_get_page(*pte));
          struct frame_table_entry *entry =
                                        frame_table_lookup(pte_get_page(*pte));       
          lock_acquire(&frame_table_lock);
          list_remove(&entry->elem);
          free(entry);
          lock_release(&frame_table_lock);
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

/*
 * Selects and evicts A SINGLE FRAME from the frame table, and returns the frame
 * kaddr as the freed frame
 * @return the newly freed frame address
 */
static void *evict_frame()
{
  // printf("frame_table_index: %d\n", frame_table_index);
  // Frame table is current full
  lock_acquire(&frame_table_lock);
  lock_acquire(&spage_lock);
  if (list_empty(&frame_table))
  {
    PANIC("SOMETHING IS VERY WRONG");
  }
  // printf("frames: %d\n", list_size(&frame_table));
  int counter = 0;
  struct list_elem *e = list_begin(&frame_table);
  struct list_elem pointer_elem;
  struct frame_table_entry *entry;
  while (true)
  {
    if (e == list_end(&frame_table))
    {
      counter = 0;
      frame_table_index = 0;
      e = list_begin(&frame_table);
    }
    else
    {
      if (counter >= frame_table_index)
      {
        entry = list_entry(e, struct frame_table_entry, elem);
        if (entry != NULL)
        {
          if (entry->second_chance)
          {
            entry->second_chance = false;
          }
          else if (!entry->pinned)
          {
            frame_table_index = counter;
            break;
          }
        }
      }
      counter++;
      e = list_next(e);
    }
  }
  struct thread *owner = entry->owner;
  lock_release(&spage_lock);
  struct spage_table_entry *spte =
    spage_get_entry(&owner->spage_table, entry->uaddr);
  
  lock_acquire(&spage_lock);
  swap_index swap_slot = 0;
  // printf("evicted upage: %p kpage:%p\n", entry->uaddr, entry->kpage_addr);
  if (strlen(spte->file_name) > 0 && page_is_mmap(spte->uaddr))
  {
    write_page_to_file(spte, entry->kpage_addr);
  }
  else
  {
    swap_slot = swap_frame_to_slot(entry->kpage_addr);
    // printf("swapped page: %p to slot %d\n", entry->uaddr, swap_slot);
  }
  if (swap_slot != SWAP_ERROR)
  {
    pagedir_clear_page(owner->pagedir, spte->uaddr);
    palloc_free_page(entry->kpage_addr);
    spte->is_installed = false;
    spte->is_swapped = true;
    spte->swap_slot = swap_slot;
    list_remove(&entry->elem);
    free(entry);
    // printf("freed resources\n");
    lock_release(&spage_lock);
    lock_release(&frame_table_lock);
    return palloc_get_page(PAL_USER | PAL_ZERO);
  }
  else
  {
    PANIC("INSUFFICIENT SWAP MEMORY");
  }
}