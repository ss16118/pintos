#include "frame.h"

#include <string.h>
#include <stdio.h>

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

/* struct representing the frame table implementation */
static struct list frame_table;
/* lock for synchronisation across processes */
static struct lock frame_table_lock;
/* list of pages which are read-only */
static struct list read_only_pages;

struct read_only_page
{
  char file_name[MAX_FILENAME_LEN];
  off_t ofs;
  struct frame_table_entry *fte;
  struct list_elem elem;
};

struct page_owner
{
   void *uaddr;
   struct thread *owner;
   struct list_elem elem;
};

static void *evict_frame(void);
static bool load_file_to_page(char *, void *, size_t, size_t, off_t);
static void frame_remove_entry(void *);

static struct read_only_page *rpage_add(struct spage_table_entry *,
                                        struct frame_table_entry *);
static struct page_owner *rpage_get_owner(struct frame_table_entry *);
static struct read_only_page *rpage_lookup(struct spage_table_entry *);
static struct read_only_page *rpage_lookup_frame(struct frame_table_entry *);

static int frame_table_index = 0;

/* Initialisation */
void frame_init(void)
{
  list_init(&frame_table);
  list_init(&read_only_pages);
  lock_init(&frame_table_lock);
}

/**
 * Retrieves the frame table entry from the frame table given the
 * frame address. If the frame table does not contain an entry
 * with the frame address, return NULL.
 * @param kpage_addr: The address of the kernel page.
 * @return:           The pointer to the struct frame_table_entry containing the
 *                    specific frame address if it exists in the table.
 */
static
struct frame_table_entry *frame_table_lookup(void *kpage_addr)
{
  bool has_lock = lock_held_by_current_thread(&frame_table_lock);
  if (!has_lock)
    lock_acquire(&frame_table_lock);
  for (struct list_elem *e = list_begin(&frame_table);
       e != list_end(&frame_table); e = list_next(e))
  {
    struct frame_table_entry *entry =
        list_entry(e, struct frame_table_entry, elem);
    if (entry->kpage_addr == kpage_addr)
    {
      if (!has_lock)
        lock_release(&frame_table_lock);
      return entry;
    }
  }
  if (!has_lock)
    lock_release(&frame_table_lock);
  return NULL;
}

inline static
bool load_file_to_page(char *fn, void *kpage, size_t rb, size_t zb, off_t ofs)
{
  struct file *file_to_load = filesys_open(fn);
  if (file_read_at(file_to_load, kpage, rb, ofs) != (int) rb)
  {
    file_close(file_to_load);
    palloc_free_page (kpage);
    return false;
  }
  file_close(file_to_load);
  return true;
}

/**
 * Adds a new entry to the frame table.
 * @param spte: The spage table entry with required information to allocate new
 *              frame
 * @return:     The address of the frame entry if the allocation is successful,
 *              otherwise, return NULL.
 */
struct frame_table_entry *frame_add_entry(struct spage_table_entry *spte)
{
  bool has_lock = lock_held_by_current_thread(&frame_table_lock);
  if (!has_lock)
    lock_acquire(&frame_table_lock);
  if (spte != NULL)
  {
    struct read_only_page *rpage = rpage_lookup(spte);
    if (rpage == NULL || spte->writable)
    {
      struct frame_table_entry *new_entry =
                                       malloc(sizeof(struct frame_table_entry));
      if (new_entry != NULL)
      {
        uint8_t *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
        bool writable = true;
        while (kpage == NULL)
        {
          kpage = evict_frame();
        }
        if (spte->is_swapped)
        {
          // Page needs to be swapped in from swap slot
          swap_slot_to_frame(spte->swap_slot, kpage);
          swap_clear_slot(spte->swap_slot);
          spte->is_swapped = false;
        }
        else
        {
          size_t page_read_bytes = 0;
          size_t page_zero_bytes = PGSIZE;

          // If the new page allocated is used for stack growth
          if (strlen(spte->file_name) != 0)
          {
            /* Load this page. */
            writable = spte->writable;
            page_read_bytes = spte->page_read_byte;
            page_zero_bytes = PGSIZE - page_read_bytes;
            if (!load_file_to_page(spte->file_name, kpage, page_read_bytes,
                page_zero_bytes, spte->ofs))
              goto failed;
          }
          memset (kpage + page_read_bytes, 0, page_zero_bytes);
        }
        if (!install_page(spte->uaddr, kpage, writable)) 
        {
          palloc_free_page(kpage);
          goto failed;
        }
        if (!writable)
        {
          rpage = rpage_add(spte, new_entry);
          if (rpage == NULL)
            goto failed;
        }

        spte->is_installed = true;
        new_entry->pinned = false;
        new_entry->kpage_addr = kpage;
        new_entry->uaddr = spte->uaddr;
        new_entry->second_chance = false;

        list_init(&new_entry->owners);
        struct page_owner* new_owner = malloc(sizeof(struct page_owner));
        new_owner->owner = thread_current();
        new_owner->uaddr = spte->uaddr;
        list_push_back(&new_entry->owners, &new_owner->elem);

        list_push_back(&frame_table, &new_entry->elem);
        if (!has_lock)
          lock_release(&frame_table_lock);
        return new_entry;
      }
    }
    else
    {
      if (install_page(spte->uaddr, rpage->fte->kpage_addr, spte->writable))
      {
        struct page_owner *owner = malloc(sizeof(struct page_owner));
        if (owner == NULL)
          goto failed;

        owner->owner = thread_current();
        owner->uaddr = spte->uaddr;
        list_push_back(&rpage->fte->owners, &owner->elem);
        if (!has_lock)
          lock_release(&frame_table_lock);
        return rpage->fte;
      }
    }
  }
 failed:
  if (!has_lock)
    lock_release(&frame_table_lock);
  return NULL;
}

/*
 * Removes a frame with given KADDR from the frame table, or, if the frame is
 * shared across multiple processes, unmaps all page mappings from the given
 * process
 * @param kaddr: The kpage address of the frame to be removed
 */
static
void frame_remove_entry(void * kaddr)
{
  bool has_lock = lock_held_by_current_thread(&frame_table_lock);
  if (!has_lock)
    lock_acquire(&frame_table_lock);

  struct frame_table_entry *entry = frame_table_lookup(kaddr);
  if (entry != NULL)
  {
    struct page_owner *owner = rpage_get_owner(entry);
    bool has_one_owner = true;
    if (list_size(&entry->owners) > 1)
    {
      struct list_elem *e = list_begin(&entry->owners);
      while (e != list_end(&entry->owners))
      {
        struct page_owner *temp = list_entry(e, struct page_owner, elem);
        e = list_next(e);
        if (temp->owner != thread_current()) has_one_owner = false;
        if (temp->owner == thread_current() && temp != owner)
        {
          pagedir_clear_page(thread_current()->pagedir, temp->uaddr);
          list_remove(&temp->elem);
          free(temp);
        }
      }
      if (!has_one_owner)
      {
        pagedir_clear_page(thread_current()->pagedir, owner->uaddr);
        list_remove(&owner->elem);
        free(owner);
      }
    }
    if (entry != NULL && list_size(&entry->owners) == 1 && 
        list_begin(&entry->owners) == &owner->elem)
    {
      list_remove(&entry->elem);
      struct read_only_page *rpage = rpage_lookup_frame(entry);
      if (rpage != NULL)
      {
        list_remove(&rpage->elem);
        free(rpage);
      }
      free(owner);
      free(entry);
    }
  }
  if (!has_lock)
    lock_release(&frame_table_lock);
}

/**
 * Frees the frame table entries according to the page address in
 * the given page directory. USED ONLY DURING PROCESS EXIT
 * @param pd: the page directory to free 
 */
void frame_free_entries_from_pd(uint32_t *pd)
{
  bool has_lock = lock_held_by_current_thread(&frame_table_lock);
  if (!has_lock)
    lock_acquire(&frame_table_lock);

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
  if (!has_lock)
    lock_release(&frame_table_lock);
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
static
void *evict_frame(void)
{
  ASSERT(!list_empty(&frame_table));
  // Frame table is current full
  bool has_frame_lock = lock_held_by_current_thread(&frame_table_lock);
  if (!has_frame_lock)
    lock_acquire(&frame_table_lock);
  bool has_spage_lock = lock_held_by_current_thread(&spage_lock);
  if (&spage_lock)
    lock_acquire(&spage_lock);

  /* Select a frame to evict from the frame table using second chance eviction
   * policy
   */
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
  
  swap_index swap_slot = NOT_SWAPPED;
  struct thread *owner = list_entry(list_begin(&entry->owners),
                                    struct page_owner,
                                    elem)->owner;
  struct spage_table_entry *spte =
      spage_get_entry(&owner->spage_table, entry->uaddr);
  if (strlen(spte->file_name) > 0 && page_is_mmap(spte->uaddr) &&
      pagedir_is_dirty(owner->pagedir, spte->uaddr))
  {
    write_page_to_file(spte, entry->kpage_addr);
  }
  else
  {
    swap_slot = swap_frame_to_slot(entry->kpage_addr);
  }
  if (swap_slot != SWAP_ERROR)
  {
    pagedir_clear_page(owner->pagedir, spte->uaddr);
    palloc_free_page(entry->kpage_addr);
    spte->is_installed = false;
    spte->is_swapped = (swap_slot != NOT_SWAPPED);
    if (spte->is_swapped)
      spte->swap_slot = swap_slot;
    list_remove(&entry->elem);
    free(entry);
    void *kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (!has_spage_lock)
      lock_release(&spage_lock);
    if (!has_frame_lock)
      lock_release(&frame_table_lock);
    return kpage;
  }
  else
  {
    PANIC("INSUFFICIENT SWAP MEMORY");
  }
}

/*
 * Adds a new read-only-page entry to the list of read-only pages corresponding
 * to te given frame.
 * @param spte: The supplementary page table entry corresponding to a read-only
 *              page
 * @param fte:  The frame table entry to be edited to acommodate a new upage
 *              mapping
 * @return:     The new read-only page entry for the read_only_pages list
 */
static
struct read_only_page *rpage_add(struct spage_table_entry *spte,
                                 struct frame_table_entry *fte)
{
  struct read_only_page *rpage = malloc(sizeof(struct read_only_page));
  if (rpage == NULL)
    return NULL;

  strlcpy(rpage->file_name, spte->file_name, MAX_FILENAME_LEN);
  rpage->ofs = spte->ofs;
  rpage->fte = fte;
  list_push_back(&read_only_pages, &rpage->elem);
  return rpage;
}

/*
 * Gets the first page_owner struct owned by the current thread from the frame
 * table.
 * @param fte:  The frame table entry from which to retrieve the first owner.
 * @returns:    The page_owner struct corresponding to the first owner entry
 *              owned by the current thread.
 */
static
struct page_owner *rpage_get_owner(struct frame_table_entry *fte)
{
  if (!list_empty(&fte->owners))
  {
    for (struct list_elem *e = list_begin(&fte->owners);
         e != list_end(&fte->owners); e = list_next(e))
    {
      struct page_owner *owner = list_entry(e, struct page_owner, elem);
      if (owner->owner == thread_current())
      {
        return owner;
      }
    }
  }
  return NULL;
}

static
struct read_only_page *rpage_lookup_frame(struct frame_table_entry *fte)
{
  if (!list_empty(&read_only_pages))
  {
    for (struct list_elem *e = list_begin(&read_only_pages);
         e != list_end(&read_only_pages); e = list_next(e))
    {
      struct read_only_page *rpage = list_entry(e, struct read_only_page, elem);
      if (rpage->fte == fte)
      {
        return rpage;
      }
    }
  }
  return NULL;
}


static
struct read_only_page *rpage_lookup(struct spage_table_entry *spte)
{
  if (strlen(spte->file_name) > 0 && !list_empty(&read_only_pages))
  {
    for (struct list_elem *e = list_begin(&read_only_pages);
         e != list_end(&read_only_pages); e = list_next(e))
    {
      struct read_only_page *rpage = list_entry(e, struct read_only_page, elem);
      if (strcmp(rpage->file_name, spte->file_name) == 0 && rpage->ofs == spte->ofs)
      {
        return rpage;
      }
    }
  }
  return NULL;
}
