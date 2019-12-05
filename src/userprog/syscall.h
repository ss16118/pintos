#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <user/syscall.h>
#include <list.h>

#include "threads/thread.h"
#include "vm/page.h"

#define SYSCALL_ERROR -1
#define CHILD_RUNNING -2

struct lock filesys_lock;

void syscall_init(void);
void halt(void);
void exit (int status);
pid_t exec(const char *cmd_line);

int wait(pid_t pid);
bool creat(const char *file, unsigned initial_size);
bool remove(const char *file);

/* Struct binds an open file to its UNIQUE file descriptor, stored in thread's
   FILES list */
struct file_fd
{
    int fd;                     /* unique file descriptor */
    struct file *file;          /* the opened file */
    char file_name[MAX_FILENAME_LEN];
    struct list_elem elem;
};

/* Child process bookmark, allows parent to keep track of child exit status */
struct child_bookmark
{
    pid_t child_pid;        /* PID of child this is bookmarking */
    int child_exit_status;  /* child's exit status, default to CHILD_RUNNING */
    struct list_elem elem;
};


/* Struct binds the starting virtural address of a file with a unique mapping id*/
struct file_mmap
{
  mapid_t map_id;
  char file_name[MAX_FILENAME_LEN];
  struct thread *owner;
  size_t file_size;
  void *uaddr;
  struct list_elem elem;
};

int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);

void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);
mapid_t mmap (int fd , void * addr);
void munmap (mapid_t mapping);
bool page_is_mmap(void *uaddr);
void write_page_to_file(struct spage_table_entry *spte, void *kpage);

#endif /* userprog/syscall.h */
