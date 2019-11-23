#include "userprog/syscall.h"
#include "process.h"
#include "pagedir.h"

#include <stdio.h>
#include <syscall-nr.h>
#include <limits.h>
#include <string.h>

#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

#include "kernel/console.h"
#include "devices/input.h"
#include "devices/shutdown.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

#define WORD 4

static void syscall_handler (struct intr_frame *);
static bool is_valid_pointer(const void *uaddr);
static int file_desc_count = 2;
static struct lock filesys_lock;

/*
 * Checks if the pointer is a valid pointer. It is implemented with
 * pagedir_get_page() and is_user_vaddr().
 */
static bool is_valid_pointer(const void *uaddr)
{
  if (uaddr != NULL && is_user_vaddr(uaddr))
  {
    return pagedir_get_page(thread_current()->pagedir, uaddr) != NULL;
  }
  return false;
}

/* Initialises the syscall system */
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f)
{
  if (!(is_valid_pointer(f->esp) && 
        is_valid_pointer((int *) f->esp + 1) &&
        is_valid_pointer((int *) f->esp + 2) &&
        is_valid_pointer((int *) f->esp + 3)))
  {
    exit(SYSCALL_ERROR);
  }

  /* If the pointers are not valid, exit process directly */

  /* Invoke the corresponding system call function according to the
     stack frame's stack pointer */

  int syscall_num = *(int *) f->esp;

  switch (syscall_num)
  {
    case SYS_HALT:

      halt();

      break;

    case SYS_EXIT:

      exit(*(int *) ((int *) f->esp + 1));

      break;

    case SYS_EXEC:

      f->eax = exec(*(char **) ((char *) f->esp + WORD));

      break;

    case SYS_WAIT:

      f->eax = wait(*(pid_t *) ((pid_t *) f->esp + 1));

      break;

    case SYS_CREATE:

      f->eax = create(*(char **) ((char *) f->esp + WORD),
                      *(unsigned *) ((int *) f->esp + 2));
      break;

    case SYS_REMOVE:

      f->eax = remove(*(char **) ((char *) f->esp + WORD));

      break;

    case SYS_OPEN:

      f->eax = open(*(char **) ((char *) f->esp + WORD));

      break;

    case SYS_FILESIZE:
    
      f->eax = filesize(*(int *) ((int *) f->esp + 1));

      break;

    case SYS_READ:

      f->eax = read(*(int *) ((int *) f->esp + 1),
                    *(void **) ((int *) f->esp + 2),
                    *(unsigned *) ((int *) f->esp + 3));

      break;

    case SYS_WRITE:

      f->eax = write(*(int *) ((int *) f->esp + 1),
                     *(void **) ((int *) f->esp + 2),
                     *(unsigned *) ((int *) f->esp + 3));

      break;

    case SYS_SEEK:

      seek(*(int *) ((int *) f->esp + 1),
           *(unsigned *) ((int *) f->esp + 2));

      break;

    case SYS_TELL:

      f->eax = tell(*(int *) ((int *) f->esp + 1));

      break;

    case SYS_CLOSE:

      close(*(int *) ((int *) f->esp + 1));

      break;

    default:

      exit(SYSCALL_ERROR);

      break;
  }
}

/**
 * Terminates Pintos by calling shutdown_power_off(). Should be seldom used,
 * since some information about possible deadlock situations may be lost.
 */
void halt(void)
{
  shutdown_power_off();
}


/**
 * Terminates the current user program, sending its exit status to the kernel.
 * If the process's parent waits for it, this is the status that will be
 * returned. Conventionally, a status of 0 indicates success and nonzero values
 * indicate errors.
 * @param status: the exit status of the current user program.
 */
void exit(int status)
{
  printf("%s: exit(%d)\n", thread_current()->name, status);

  /* Frees all the memory occupied by the file descriptors in
     struct thread */
  if (!list_empty(&thread_current()->files))
  {
    enum intr_level old_level = intr_disable();
    struct list_elem *e = list_begin(&thread_current()->files);
    while (e != list_end(&thread_current()->files))
    {
      struct file_fd *fl = list_entry(e, struct file_fd, elem);
      e = list_next(e);
      file_close(fl->file);
      free(fl);
    }
    intr_set_level(old_level);
  }

  /* Frees all the memory occupied by the child_bookmarks held by the current
     thread */
  if (!list_empty(&thread_current()->child_waits))
  {
    enum intr_level old_level = intr_disable();
    struct list_elem *e = list_begin(&thread_current()->child_waits);
    while (e != list_end(&thread_current()->child_waits))
    {
      struct child_bookmark *child_exit = list_entry(e,
                                                      struct child_bookmark,
                                                      elem);
      e = list_next(e);
      free(child_exit);
    }
    intr_set_level(old_level);
  }

  /* Checks if parent is waiting on thread */
  enum intr_level old_level = intr_disable();
  if (thread_current()->parent != NULL)
  {
    thread_current()->parent->child_exit_status = status;
    struct child_bookmark* child_exit =
        thread_waiting_child(&thread_current()->parent->child_waits,
                             thread_current()->tid);

    if (child_exit != NULL)
    {
      /* Log the thread's exit status to parent's list of bookmarks */
      child_exit->child_exit_status = status;
    }
    
    if (!list_empty(&thread_current()->parent->wait_for_child.waiters) &&
        thread_current()->parent->child_waiting == thread_current()->tid)
    {
      /* Instructs parent to stop waiting */
      sema_up(&thread_current()->parent->wait_for_child);
    }
  }
  intr_set_level(old_level);
  thread_exit();
}


/**
 * Runs the executable whose name is given in cmd_line, passing any given
 * arguments, and returns the new process's program id (pid). Must return
 * pid -1, which otherwise should not be a valid pid, if the program cannot load
 * or run for any reason. The parent process cannot return from the exec until
 * it knows whether the child process successfully loaded its executable.
 * Must use appropriate synchronization to ensure this.
 * @param cmd_line: name of the program to run.
 * @return pid of the new process's program.
 */
pid_t exec(const char *cmd_line)
{
  if (cmd_line == NULL || cmd_line > PHYS_BASE)
  {
    exit(SYSCALL_ERROR);
  }

  thread_current()->child_exit_status = CHILD_RUNNING;

  char temp_cmd_line[MAX_ARG_LEN * MAX_PARAM_NUM];
  memcpy(temp_cmd_line, cmd_line, strlen(cmd_line) + 1);

  /* Lock edits to filesys while child is loading stack */
  lock_acquire(&filesys_lock);
  pid_t child_pid = process_execute(temp_cmd_line);

  /* Create child wait bookmark in parent thread */
  struct child_bookmark* child_status = malloc(sizeof(struct child_bookmark));
  child_status->child_pid = child_pid;
  list_push_back(&thread_current()->child_waits, &child_status->elem);

  /* Set parent thread to wait for child thread to finish loading */
  thread_current()->child_waiting = child_pid;
  sema_down(&thread_current()->wait_for_child);

  /* Re-enable file system access */
  lock_release(&filesys_lock);

  if (child_pid == TID_ERROR || child_status->child_exit_status == SYSCALL_ERROR)
  {
    return SYSCALL_ERROR;
  }
 
  child_status->child_exit_status = CHILD_RUNNING;
  return child_pid;
}


/***************************************************************************
 * THIS SYSTEM CALL REQUIRES CONSIDERABLY MORE WORK THAN ANY OF THE OTHERS.
 ***************************************************************************
 *
 * Waits for a child process pid and retrieves the child's exit status.
 * If pid is still alive, waits until it terminates. Returns the status that
 * pid passed to exit. If pid did not call exit(), but was terminated by kernel
 * (e.g. killed due to an exception), wait(pid) must return -1.
 *
 * wait will fail and return -1 immediately if any of the following conditions
 * is true:
 *
 *  - pid does not refer to a direct child of the calling process. pid is a
 *    direct child of the calling process iff the calling process received pid
 *    as a return value from a successful call to exec.
 *
 *  - The process that calls wait has already called wait of pid. That is,
 *    a process may wait for any given child at most once.
 *
 * Processes may spawn any number of children, wait for them in any order, and
 * may even exit without having waited for some or all of their children. All
 * of a process's resources will be freed whether its parent ever waits for it
 * or not, and regardless of whether the child exits before or after its parent.
 *
 * @param pid: the pid of the child process.
 * @return: the status that the child process passed to exit.
 *
 */
int wait(pid_t pid)
{
  /* Check if given pid is a child of current thread */
  struct child_bookmark* child_exit =
            thread_waiting_child(&thread_current()->child_waits, pid);
  if (child_exit != NULL)
  {
    if (child_exit->child_exit_status == CHILD_RUNNING)
    {
      /* Child is still running, wait until it finishes */
      thread_current()->child_waiting = pid;
      sema_down(&thread_current()->wait_for_child);

      /* Get child exit status */
      child_exit = thread_waiting_child(&thread_current()->child_waits, pid);
      int child_exit_status = child_exit->child_exit_status;

      /* Set child exit status so parent cannot wait on child again */
      child_exit->child_exit_status = SYSCALL_ERROR;

      return child_exit_status;
    }
    return child_exit->child_exit_status; 
  }
  return SYSCALL_ERROR;
}



/************************************************************************
 *                      File Related System Calls                       *
 ************************************************************************/


/**
 * Creates a new file called file initially initial_size bytes in size.
 * Returns true if successful, false otherwise. Does not open the file.
 * @param file: name of the file to be created.
 * @param initial_size: the initial size of the file in bytes.
 * @return: whether the file has been created successfully.
 */
bool create(const char *file, unsigned initial_size)
{
  if (file == NULL || file > PHYS_BASE)
  {
    exit(SYSCALL_ERROR);
  }

  lock_acquire(&filesys_lock);
  if (strcmp(file, "") != 0)
  {
    int result = filesys_create(file, initial_size);
    lock_release(&filesys_lock);
    return result;
  }
  lock_release(&filesys_lock);
  return false;
}

/**
 * Deletes the file called file. Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed. Removing
 * an open file does not close it.
 * @param file: name of the file to be deleted.
 * @return: whether the file has been deleted successfully.
 */
bool remove(const char *file)
{
  if (file == NULL)
  {
    exit(SYSCALL_ERROR);
  }

  lock_acquire(&filesys_lock);
  if (strcmp(file, "") != 0)
  {
    int result = filesys_remove(file);
    lock_release(&filesys_lock);
    return result;
  }
  lock_release(&filesys_lock);
  return false;
}

/**
 * Opens the file called file. Returns a non-negative integer handle called
 * a "file descriptor" (fd), or -1 if the file could be not opened.
 *
 * File descriptors numbered 0 and 1 are reserved for the console:
 * fd 0 (STDIN_FILENO) is standard input, fd 1 (STDOUT_FILENO) is standard
 * output. Will never return either of these file descriptors.
 *
 * Each process has an independent set of file descriptors. File descriptors
 * are not inherited by child processes.
 *
 * When a single file is opened more than once, whether by a single process or
 * different processes, each open returns a new file descriptor. Different
 * file descriptors for a single file are closed independently in separate calls
 * to close and they do not share a file position.
 *
 * @param file: name of the file to be opened.
 * @return: a non-negative file descriptor.
 */
int open(const char *file)
{  
  if (file == NULL || file > PHYS_BASE)
  {
    exit(SYSCALL_ERROR);
  }

  lock_acquire(&filesys_lock);

  struct file *f = filesys_open(file);
  if (f != NULL)
  {
    int fd = file_desc_count++;
    struct file_fd *fl = malloc(sizeof(struct file_fd *));
    fl->fd = fd;
    fl->file = f;

    // If the name of the executable file opened matches that of the
    // executable file of the current process, deny the permission to
    // write to it
    if (strcmp(file, thread_current()->executable_filename) == 0)
    {
      file_deny_write(f);
    }

    list_push_back(&thread_current()->files, &fl->elem);
    
    lock_release(&filesys_lock);
    return fd;
  }
  lock_release(&filesys_lock);
  return SYSCALL_ERROR;
}

/**
 * Retrieves the file_fd wrapper that contains the 
 * file pointer given the file's file descriptor. Returns
 * NULL if the file searched for does not exist in the
 * list.
 **/
static struct file_fd *get_file_elem_from_fd(int fd)
{
  enum intr_level old_level = intr_disable();
  if (!list_empty(&thread_current()->files))
  {
    for (struct list_elem *e = list_begin(&thread_current()->files);
        e != list_end(&thread_current()->files);
        e = list_next(e))
    {
      struct file_fd *fl = list_entry(e, struct file_fd, elem);
      if (fl != NULL && fl->fd == fd)
      {
        intr_set_level(old_level);
        return fl;
      }
    }
  }
  intr_set_level(old_level);
  return NULL;
}

/**
 * Returns the size, in bytes, of the file open as fd.
 * @param fd: the file open as fd.
 * @return: the size of the file in bytes.
 */
int filesize(int fd)
{
  struct file_fd *fl = get_file_elem_from_fd(fd);
  if (fl != NULL)
  {
    return file_length(fl->file);
  }
  return 0;
}


/**
 * Reads size bytes from the file open as fd into buffer. Returns the number of
 * bytes actually read (0 at end of file), or -1 if the file could not be read.
 * Fd 0 reads from the keyboard using input_getc() in 'src/devices/input.h'.
 * @param fd: the file open as fd.
 * @param buffer: the pointer to the buffer to be read from.
 * @param size: number of bytes to be read.
 * @return: number of bytes actually read.
 */
int read(int fd, void *buffer, unsigned size)
{
  if (buffer == NULL || buffer > PHYS_BASE)
  {
    exit(SYSCALL_ERROR);
  }

  lock_acquire(&filesys_lock);
  if (fd > STDIN_FILENO)
  {
    struct file_fd *fl = get_file_elem_from_fd(fd);
    if (fl != NULL)
    {
      int bytes_read = file_read(fl->file, buffer, size);
      lock_release(&filesys_lock);
      return bytes_read;
    }
  }
  else if (fd == STDIN_FILENO)
  {
    unsigned char_count = 0;
    while (char_count < size)
    {
      memset(buffer, input_getc(), sizeof(uint8_t));
      buffer = (char *) buffer + 1;
      char_count++;

    }
    lock_release(&filesys_lock);
    return size;
  }
  lock_release(&filesys_lock);
  return SYSCALL_ERROR;
}


/**
 * Writes size bytes from buffer to the open file fd. Returns the number of
 * bytes actually written.
 *
 * Write as many bytes as possible up to end-of-file and return the actual
 * number written, or 0 if no bytes could be written at all.
 *
 * Fd 1 writes to the console. Write to the console writes all of buffer
 * in one call to putbuf().
 * @param fd: the file open as fd.
 * @param buffer: the pointer to the buffer to which the data will be written.
 * @param size: number of bytes to be written.
 * @return: number of bytes actually written.
 */
int write(int fd, const void *buffer, unsigned size)
{
  if (buffer == NULL || buffer > PHYS_BASE)
  {
    exit(SYSCALL_ERROR);
  }

  if (fd == STDOUT_FILENO)
  {
    putbuf((char *) buffer, size);
    return size;
  }

  lock_acquire(&filesys_lock);
  struct file_fd *fl = get_file_elem_from_fd(fd);
  if (fl != NULL)
  {
    int result = file_write(fl->file, buffer, size);
    lock_release(&filesys_lock);
    return result;
  }
  lock_release(&filesys_lock);
  return 0;
}

/**
 * Changes the next byte to be read or written in open file fd to position,
 * expressed in bytes from the beginning of the file. (A position of 0 is
 * the file's start).
 *
 * A seek past the current end of a file is not an error. A later read obtains 0
 * bytes, indicating end-of-file. Implemented in the file system and do not
 * require any special effort in system call implementation.
 * @param fd: the file open as fd.
 * @param position: number of bytes from the beginning of the file which
 * the next byte will be read from or written to.
 */
void seek(int fd, unsigned position)
{
  struct file_fd *fl = get_file_elem_from_fd(fd);
  if (fl != NULL)
  {
    file_seek(fl->file, position);
  }
}

/**
 * Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file.
 * @param fd: the file open as fd.
 * @return: the position of the next byte to be read to or written from.
 */
unsigned tell(int fd)
{
  struct file_fd *fl = get_file_elem_from_fd(fd);
  if (fl != NULL)
  {
    return file_tell(fl->file);
  }
  return SYSCALL_ERROR;
}


/**
 * Closes file descriptor fd. Exiting or terminating a process implicitly closes
 * all its open file descriptors, as if by calling this function for each one.
 * @param fd: the file open as fd.
 */
void close(int fd)
{
  struct file_fd *fl = get_file_elem_from_fd(fd);
  if (fl != NULL)
  {
    file_close(fl->file);
    list_remove(&fl->elem);
    free(fl);
  }
}
