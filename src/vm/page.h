#ifndef VM_PAGE_H
#define VM_PAGE_H

#include "lib/kernel/hash.h"

/* PAGES

A page, sometimes called a virtual page, is a continuous region of virtual
memory 4kb in length. A page must be page-aligned, that is, start on a virtual
address evenly divisible by the page size. Thus a 32-bit virtual address can be
divided into a 20-bit page number and a 12-bit page offset, like this:
                 31               12 11         0
                +-------------------+------------+
                |    Page Number    |   Offset   |
                +-------------------+------------+
                         Virtual Address

********************************************************************************
*            COPIED FROM SPEC FOR SANITY REASONS, DELETE WHEN DONE             *
********************************************************************************
Each process has an independent set of user memory pages, which are those pages
below virtual address PHYS_BASE, typically 0xc0000000 (3GB). The set of kernel
virtual pages, on the other hand, is global, remaining the same regardless of
what thread or process is active. The kernel may access both user virtual and
kernel virtual pages, but a user process may access only its own user virtual
pages. See section 4.1.4 [Virtual Memory Layout], page 28 for more information.

Pintos provides several useful functions for working with virtual addresses. See
Section A.6 [Virtual Addresses], page 68, for details.
********************************************************************************
*            COPIED FROM SPEC FOR SANITY REASONS, DELETE WHEN DONE             *
********************************************************************************
*/

struct spage_table_entry
{
  void *uaddr;

  bool isInstalled;
  bool isSwapped;

  struct hash_elem hash_elem;
};

void spage_init(struct hash *);

// Get entry from spage_table
struct spage_table_entry *spage_get_entry(void *uaddr);

// Added entry to spage_table
struct spage_table_entry *spage_set_entry(void *uaddr);

// Remove entry to spage_table
bool spage_remove_entry(void *uaddr);

// Set entry to installed
bool spage_flip_is_installed(void *uaddr);

// Set entry to swapped
bool spage_flip_is_swapped(void *uaddr);

#endif /* vm/page.h */
