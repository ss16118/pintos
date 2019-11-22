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

struct spage_table_entry *spage_get_entry(void *uaddr)
{
  lock_acquire(&spage_lock);
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

struct spage_table_entry *spage_set_entry(void *uaddr)
{
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

static unsigned spte_hash_func(const struct hash_elem *e, void *aux UNUSED)
{
  struct spage_table_entry *spte = hash_entry(e,
                                              struct spage_table_entry,
                                              hash_elem);

  return hash_int((int) spte->uaddr);
}

static bool spte_less_func(const struct hash_elem *a,
                           const struct hash_elem *b,
                           void *aux UNUSED)
{
  return spte_hash_func(a, NULL) < spte_hash_func(b, NULL);
}
