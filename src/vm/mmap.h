#include "lib/kernel/hash.h"

struct mmap_table_entry
{
    int fd;
    tid owner;
    void *addr;
    struct hash_elem hash_elem;
}

void mmap_init(struct hash*);

struct mmap_table_entry* mmap_get_entry(int, tid);

void mmap_add_entry(struct hash *, void *);
