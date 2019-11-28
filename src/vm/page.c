#include <debug.h>

#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include "filesys/file.h"
#include "filesys/off_t.h"
#include "page.h"


static struct lock spage_lock;

static void spage_table_entry_destroy(struct hash_elem *e, void *aux);
static unsigned spte_hash_func(const struct hash_elem *e, void *aux);
static bool spte_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux);

/* Initialise thread's supplementary page table, use this function to abstract
   and hide any hash table operations from thread perspective */
void spage_init(struct hash *spage_table)
{
  lock_init(&spage_lock);
  hash_init(spage_table, &spte_hash_func, &spte_less_func, NULL);
}

/* Retrieves a supplementary page table entry for the given UADDR, or NULL if
 * the entry does not exist within the current thread's supplementary page
 * table.
 * @param spage_table: the hash table to be accessed.
 * @param uaddr: the user virtual address.
 * @return the pointer to the struct retrieved from the current thread's spage
 * table, or NULL if the entry does not exit within the spage table.
 */
struct spage_table_entry *spage_get_entry(struct hash *spage_table, void *uaddr)
{
  lock_acquire(&spage_lock);
  /* Create a temporary entry to retrieve the version within the hash table.
   * Done this way to maintain abstraction and hiding of spage table hash table
   * implementation.
   */
  struct spage_table_entry temp_entry; // = malloc(sizeof(struct spage_table_entry *));
  // if (temp_entry != NULL)
  // {
  temp_entry.uaddr = uaddr;
  // temp_entry.hash_elem = *(struct hash_elem *) malloc(sizeof(struct hash_elem *));
  struct hash_elem *spte_elem = hash_find(spage_table,
                                          &temp_entry.hash_elem);
  // printf("returned from hash_find\n");
  if (spte_elem != NULL)
  {
    struct spage_table_entry *spte = hash_entry(spte_elem,
                                                struct spage_table_entry,
                                                hash_elem);
    lock_release(&spage_lock);
    // printf("getting entry successful\n");
    return spte;
  }
  // }
  lock_release(&spage_lock);
  // printf("getting entry failed\n");
  return NULL;
}

/* Creates a new entry within the supplementary page table for the given UADDR.
 * @param spage_table: the hash table to be accessed.
 * @param uaddr: the user virtual address
 * @param kaddr: the kernel virtual address
 * @return the pointer to the newly created supplementary page table entry or
 * NULL if the creation fails.
 */
struct spage_table_entry *spage_set_entry(struct hash *spage_table, void *uaddr,
                                          struct file* file, off_t ofs, bool writable)
{
  /* virtual address already mapped within spage table.
   * NOTE that a function should never be called on UADDR whilst it is mapped
   * in the table within normal execution. But should not cause issues for the
   * wider execution of the process.
   */
  struct spage_table_entry *spte = spage_get_entry(spage_table, uaddr);
  // printf("setting %p, elems in table: %d\n", uaddr, hash_size(spage_table));
  if (spte != NULL)
  {
    return spte;
  }
  struct spage_table_entry *new_entry = malloc(sizeof(struct spage_table_entry));

  if (new_entry != NULL)
  {
    new_entry->uaddr = uaddr;
    new_entry->is_installed = false;
    new_entry->is_swapped = false;
    new_entry->file = file;
    new_entry->ofs = ofs;
    new_entry->writable = writable;
    lock_acquire(&spage_lock);

    if (hash_insert(spage_table, &new_entry->hash_elem) == NULL)
    {
      lock_release(&spage_lock);
      printf("Spte set for %p\n", uaddr);
      return new_entry;
    }
  }
  lock_release(&spage_lock);
  return NULL;
}

/* Retrieves and removes the mapping, if it exists within the spage table, for
 * the given UADDR.
 * @param spage_table: the hash table to be accessed.
 * @param uaddr: the user virtual address
 * @return whether deletion was successful, will return false otherwise. If
 * entry did not exist, it would count as an unsuccessful deletion.
 */
bool spage_remove_entry(struct hash *spage_table, void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(spage_table, uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  { 
    if (hash_delete(spage_table, &spte->hash_elem) != NULL)
    {
      pagedir_clear_page(thread_current()->pagedir, uaddr);
      free(spte);
      lock_release(&spage_lock);
      return true;
    }
  }
  lock_release(&spage_lock);
  return false;
}

/* Toggles the status of whether the page has a corresponding frame installed.
 * @param spage_table: the hash table to be accessed.
 * @param uaddr: the user virtual address
 * @return if the toggle action was successful, namely if the entry existed
 * within the current process's spage table.
 */
bool spage_flip_is_installed(struct hash *spage_table, void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(spage_table, uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  {
    spte->is_installed = !spte->is_installed;
    return true;
  }
  return false;
}

/* Toggles the status of whether the page's corresponding frame has been swapped
 * out of memory into a swap slot.
 * @param spage_table: the hash table to be accessed.
 * @param uaddr: the user virtual address
 * @return if the toggle action was successful, namely if the entry existed
 * within the current process's spage table.
 */
bool spage_flip_is_swapped(struct hash *spage_table, void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(spage_table, uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  {
    spte->is_swapped = !spte->is_swapped;
    return true;
  }
  return false;
}

/**
 * Frees all the resources allocated to a supplemental page table.
 * @param spage_table
 */
void spage_table_destroy(struct hash *spage_table)
{
  lock_acquire(&spage_lock);
  hash_destroy(spage_table, &spage_table_entry_destroy);
  lock_release(&spage_lock);
}


/**
 * Frees the resources allocated for a single supplemental page table entry.
 */
static void spage_table_entry_destroy(struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *entry =
      hash_entry(e, struct spage_table_entry, hash_elem);

  if (entry != NULL)
  {
    free(entry);
  }
}

/* The hash function for the process supplementary page table hash table
 * implementation. Made static to abstract and hide the hash table
 * implementation from process code.
 */
static unsigned spte_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte =
      hash_entry(e, struct spage_table_entry, hash_elem);

  return hash_bytes(&spte->uaddr, sizeof(spte->uaddr));
}

/* The comparison function for process supplementary page table two entries.
 * Made static to abstract and hide the hash table implementation from process
 * code.
 */
static bool spte_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED)
{
  return spte_hash_func(a, NULL) < spte_hash_func(b, NULL);
}
