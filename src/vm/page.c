#include <debug.h>

#include "threads/thread.h"
#include "threads/synch.h"
#include "page.h"


static struct lock spage_lock;

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
 * @param uaddr: the user virtual address
 * @return the pointer to the struct retrieved from the current thread's spage
 * table, or NULL if the entry does not exit within the spage table.
 */
struct spage_table_entry *spage_get_entry(void *uaddr)
{
  lock_acquire(&spage_lock);
  /* Create a temporary entry to retrieve the version within the hash table.
   * Done this way to maintain abstraction and hiding of spage table hash table
   * implementation.
   */
  struct spage_table_entry *temp_entry =
                                    malloc(sizeof(struct spage_table_entry *));
  if (temp_entry != NULL)
  {
    temp_entry->uaddr = uaddr;
    struct hash_elem *spte_elem = hash_find(&thread_current()->spage_table,
                                            &temp_entry->hash_elem);
    if (spte_elem != NULL)
    {
      struct spage_table_entry *spte = hash_entry(spte_elem,
                                                  struct spage_table_entry,
                                                  hash_elem);
      free(temp_entry);
      lock_release(&spage_lock);
      return spte;
    }
  }
  free(temp_entry);
  lock_release(&spage_lock);
  return NULL;
}

/* Creates a new entry within the supplementary page table for the given UADDR.
   @param uaddr: the user virtual address
   @return the pointer to the newly created supplementary page table entry or
    NULL if the creation fails.
 */
struct spage_table_entry *spage_set_entry(void *uaddr)
{
  /* virtual address already mapped within spage table.
   * NOTE that a function should never be called on UADDR whilst it is mapped
   * in the table within normal execution. But should not cause issues for the
   * wider execution of the process.
   */
  struct spage_table_entry *spte = spage_get_entry(uaddr);
  if (spte != NULL)
  {
    return spte;
  }

  spte = malloc(sizeof(struct spage_get_entry *));
  if (spte != NULL)
  {
    spte->uaddr = uaddr;
    spte->isInstalled = false;
    spte->isSwapped = false;
    lock_acquire(&spage_lock);
    if (hash_insert(&thread_current()->spage_table, &spte->hash_elem))
    {
      lock_release(&spage_lock);
      return spte;
    }
  }
  lock_release(&spage_lock);
  return NULL;
}

/* Retrieves and removes the mapping, if it exists within the spage table, for
 * the given UADDR.
 * @param uaddr: the user virtual address
 * @return whether deletion was successful, will return false otherwise. If
 * entry did not exist, it would count as an unsuccessful deletion.
 */
bool spage_remove_entry(void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  {
    if (hash_delete(&thread_current()->spage_table, &spte->hash_elem) != NULL)
    {
      free(spte);
      lock_release(&spage_lock);
      return true; 
    }
  }
  lock_release(&spage_lock);
  return false;
}

/* Toggles the status of whether the page has a corresponding frame installed.
 * @param uaddr: the user virtual address
 * @return if the toggle action was successful, namely if the entry existed
 * within the current process's spage table.
 */
bool spage_flip_is_installed(void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  {
    spte->isInstalled = !spte->isInstalled;
    return true;
  }
  return false;
}

/* Toggles the status of whether the page's corresponding frame has been swapped
 * out of memory into a swap slot.
 * @param uaddr: the user virtual address
 * @return if the toggle action was successful, namely if the entry existed
 * within the current process's spage table.
 */
bool spage_flip_is_swapped(void *uaddr)
{
  struct spage_table_entry *spte = spage_get_entry(uaddr);
  lock_acquire(&spage_lock);
  if (spte != NULL)
  {
    spte->isSwapped = !spte->isSwapped;
    return true;
  }
  return false;
}

/* The hash function for the process supplementary page table hash table
 * implementation. Made static to abstract and hide the hash table
 * implementation from process code.
 */
static unsigned spte_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry(e,
                                              struct spage_table_entry,
                                              hash_elem);

  return hash_int((int) spte->uaddr);
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
