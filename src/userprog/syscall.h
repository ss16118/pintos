#include <user/syscall.h>
#include <list.h>

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#define SYSCALL_ERROR -1
#define CHILD_RUNNING -2

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
    struct file *file;          /* the openned file */
    struct list_elem elem;
};

struct child_bookmark
{
    pid_t child_pid;        /* PID of child this is bookmarking */
    int child_exit_status;  /* child's exit status, default to CHILD_RUNNING */
    struct list_elem elem;
};

int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);

void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);


#endif /* userprog/syscall.h */
