#include "lib/kernel/list.h"

struct mmap_list_entry
{
    int fd;
    tid owner;
    void *addr;
    struct list_elem elem;
}

void mmap_init(struct list *);

struct mmap_list_entry* mmap_get_entry(int, tid);

void mmap_add_entry(struct list *, void *);
