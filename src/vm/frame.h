#ifndef VM_FRAME_H
#define VM_FRAME_H

#include "list.h"
#include "page.h"
/* FRAMES
 
   A frame, sometimes called a physical frame or a page frame, is a continuous
   region of physical memory. Like pages, frames must be page-size and
   page-aligned. Thus, a 32-bit physical address can be divided into a 20-bit
   frame number and a 12-bit frame offset (or just offset), like this:
  
                  31               12 11         0
                 +-------------------+------------+
                 |    Frame Number   |   Offset   |
                 +-------------------+------------+
                          Physical Address
  
********************************************************************************
*            COPIED FROM SPEC FOR SANITY REASONS, DELETE WHEN DONE             *
********************************************************************************
   The 80x86 doesn't provide any way to directly access memory at a physical
   address. Pintos works around this by mapping kernel virtual memory to
   physical memory: the first page of kernel virtual memory is mapped to the
   first frame of physical memory, the second page to the second frame, and so
   on. Thus, frames can be accessed through kernel virtual memory.

   Pintos provides function for translating between physical addresses and
   kernel virtual addresses. See Section A.6 [Virtual Addresses], page 68, for
   details.
********************************************************************************
*            COPIED FROM SPEC FOR SANITY REASONS, DELETE WHEN DONE             *
********************************************************************************
*/

struct frame_table_entry
{
   bool second_chance;
   bool pinned;

   struct list owners;
   void *kpage_addr;
   void *uaddr;                     /* We store this so we can find the upage
                                       via a given kpage and unmap it */
   struct list_elem elem;
};

void frame_init(void);

/* Allocates a new frame for use by the spage entry */
struct frame_table_entry *frame_add_entry(struct spage_table_entry *);

/* Retrieves a frame with the given physical address */
struct frame_table_entry *frame_get_frame(void *);

/* Frees resources allocated to various structs used in frame table operations 
 */
void frame_free_entries_from_pd(uint32_t *);
#endif /* vm/frame.h */
