#include "syscall.h"
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
#include "threads/palloc.h"

#include "kernel/console.h"
#include "devices/input.h"
#include "devices/shutdown.h"

#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

#include "vm/page.h"
#include "vm/frame.h"

#define WORD 4

static void syscall_handler (struct intr_frame *);
static bool is_valid_pointer(const void *uaddr);
static struct file_mmap *get_file_mmap(mapid_t);
static struct file_fd *get_file_elem_from_fd(int fd);
static void remove_file_mmap_on_exit(void);
static void munmap_write_back_to_file(struct file_mmap *);
static bool preemptive_load(void *, unsigned);
static int file_desc_count = 2;
static struct list file_mappings;
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
  list_init(&file_mappings);
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
  // Saves the current stack pointer in case of transition from
  // user mode to kernel mode in a page fault
  thread_current()->saved_stk_ptr = f->esp;

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

    case SYS_MMAP:

      f->eax = mmap(*(int *) ((int *) f->esp + 1), *(void **) ((int *) f->esp + 2));

      break;

    case SYS_MUNMAP:

      munmap(*(int *) ((int *) f->esp + 1));

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
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);
  printf("%s: exit(%d)\n", thread_current()->name, status);

  /* Frees all the memory occupied by the file descriptors in
     struct thread */
  if (!list_empty(&thread_current()->files))
  {
    struct list_elem *e = list_begin(&thread_current()->files);
    while (e != list_end(&thread_current()->files))
    {
      struct file_fd *fl = list_entry(e, struct file_fd, elem);
      e = list_next(e);
      file_close(fl->file);
      free(fl);
    }
  }

  /* Frees all the memory occupied by the child_bookmarks held by the current
     thread */
  if (!list_empty(&thread_current()->child_waits))
  {
    struct list_elem *e = list_begin(&thread_current()->child_waits);
    while (e != list_end(&thread_current()->child_waits))
    {
      struct child_bookmark *child_exit = list_entry(e,
                                                      struct child_bookmark,
                                                      elem);
      e = list_next(e);
      free(child_exit);
    }
  }

  /* Removes all the struct file_mmap owned by the current thread */
  remove_file_mmap_on_exit();

  /* Checks if parent is waiting on thread */
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
  // printf("SYSCALL EXIT COMPLETE\n");
  lock_release(&filesys_lock);
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
  struct child_bookmark* child_status = malloc(sizeof(struct child_bookmark *));
  child_status->child_pid = child_pid;
  list_push_back(&thread_current()->child_waits, &child_status->elem);

  /* Set parent thread to wait for child thread to finish loading */
  thread_current()->child_waiting = child_pid;
  lock_release(&filesys_lock);
  // printf("parent waiting for process %d\n", child_pid);
  sema_down(&thread_current()->wait_for_child);
  // printf("child load complete \n");


  if (child_pid == TID_ERROR || child_status->child_exit_status == SYSCALL_ERROR)
  {
    return SYSCALL_ERROR;
  }
 
  child_status->child_exit_status = CHILD_RUNNING;
  // printf("exec completed\n");
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
    /* Checks if the file is mapped. If it is, 
    read in the content of the file. */
    struct file_mmap *fm = NULL;
    for (struct list_elem *e = list_begin(&file_mappings);
        e != list_end(&file_mappings); e = list_next(e))
    {
      struct file_mmap *temp = list_entry(e, struct file_mmap, elem);
      if (temp != NULL && strcmp(temp->file_name, file) == 0)
      {
        fm = temp;
      }
    }
    if (fm != NULL)
    {
      int number_of_pages = (fm->file_size - 1) / PGSIZE + 1;
      for (int i = 0; i < number_of_pages; i++)
      {
        frame_add_entry(spage_get_entry(&thread_current()->spage_table, 
                                        fm->uaddr + i * PGSIZE));
      }
    }
    
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
    struct file_fd *fl = malloc(sizeof(struct file_fd));
    fl->fd = fd;
    fl->file = f;
    strlcpy(fl->file_name, file, MAX_FILENAME_LEN);
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

/*
 * Preemptively load in the pages for a buffer so that no page faults occur during
 * a function call in filesys.
 */
static bool preemptive_load(void *buffer, unsigned size)
{
  size_t number_of_pages = (size - 1) / PGSIZE + 1;
  // printf("Process %d loading %d pages for the buffer\n", thread_current()->tid, number_of_pages);
  for (int i = 0; i <= number_of_pages; i++)
  {
    void *upage = pg_round_down(buffer + PGSIZE * i);
    struct spage_table_entry *spte = spage_get_entry(&thread_current()->spage_table, upage);
    if (spte != NULL && !spte->is_installed)
    {
      frame_add_entry(spte);
      // printf("%d Process % d Loaded page %p\n", i, thread_current()->tid, upage);
    }
  }
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
      preemptive_load(buffer, size);
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
    preemptive_load(buffer, size);
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

/************************************************************************
 *                            MMAP and MUNMAP                           *
 ************************************************************************/

/**
 * Obtains the struct file_mmap of the given mapping id.
 * If the list does not contain the element with the id,
 * return NULL.
 */
static struct file_mmap *get_file_mmap(mapid_t mapping)
{
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);

  for (struct list_elem *e = list_begin(&file_mappings);
       e != list_end(&file_mappings); e = list_next(e))
  {
    struct file_mmap *fm = list_entry(e, struct file_mmap, elem);
    if (fm->map_id == mapping)
    {
      if (!has_lock)
        lock_release(&filesys_lock);
      return fm;
    }
  }
  if (!has_lock)
    lock_release(&filesys_lock);
  return NULL;
}

/**
 * Unmaps all the mapped files of the current thread, and frees all
 * the occupied resources.
 */ 
static void remove_file_mmap_on_exit(void)
{
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);
  if (!list_empty(&file_mappings))
  {
    struct list_elem *e = list_begin(&file_mappings);
    while (e != list_end(&file_mappings))
    {
      struct file_mmap *fm = list_entry(e, struct file_mmap, elem);
      e = list_next(e);
      if (fm->owner == thread_current())
      {
        munmap_write_back_to_file(fm);
        list_remove(&fm->elem);
        free(fm);
      }
    }
    if (!has_lock)
      lock_release(&filesys_lock);
  } 
}

/* Checks whether the given page is an mmap */
bool page_is_mmap(void *uaddr)
{
  for (struct list_elem *e = list_begin(&file_mappings);
       e != list_end(&file_mappings); e = list_next(e))
  {
    struct file_mmap *fm = list_entry(e, struct file_mmap, elem);
    if (fm->uaddr == uaddr && fm->owner == thread_current())
    {
      return true;
    }
  }
  return false;
}

void write_page_to_file(struct spage_table_entry *spte, void *kpage)
{
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);
  if (spte != NULL && kpage != NULL && strlen(spte->file_name) > 0)
  {
    struct file *file_to_write = filesys_open(spte->file_name);
    int bytes_written = file_write_at(file_to_write, kpage, spte->page_read_byte, spte->ofs);
    file_close(file_to_write);
  }
  if (!has_lock)
    lock_release(&filesys_lock);
}

/**
 * Maps the file open as fd into the process's virtual address space.
 * The entire file is mapped into consecutive vitual pages starting at
 * addr. The pages in mmap regions are lazily loaded.
 * The mmaped file itself is used as backing store. That is evicting a
 * page mapped by mmap writes it back to the file it was mapped from.
 *
 * If successful, this function returns a "mapping ID" that uniquely
 * identifies the mapping within the process. On failure, it returns
 * -1, which otherwise should not be a valid mapping id, and the
 * processing's mappings must be unchanged.
 *
 * A call to mmap may fail if the file open as fd has a length of zero
 * bytes. It must fail if addr is not page-aligned, or if the
 * range of pages mapped overlaps any existing set of mapped pages,
 * including the stack or pages mapped at executable load time. It
 * must fail if addr is 0. Fd 0 and 1 represent console input and output
 * respectively, and should not be mapped.
 */
mapid_t mmap(int fd , void *addr)
{
  if (fd < 2 || filesize(fd) == 0
      || addr == 0 || addr > PHYS_BASE || ((uint32_t) addr) % PGSIZE != 0)
  {
    return SYSCALL_ERROR;
  }

  int file_size = filesize(fd);
  int number_of_pages = (file_size - 1) / PGSIZE + 1;

  /* Checks if the range of pages mapped overlaps any existing set of mapped pages. */
  for (int i = 0; i < number_of_pages; i++)
  {
    pagedir_get_page(thread_current()->pagedir, addr + i * PGSIZE);
    if (spage_get_entry(&thread_current()->spage_table, addr + i * PGSIZE) != NULL)
    {
      return SYSCALL_ERROR;
    }
  }
  lock_acquire(&filesys_lock);
  struct file_fd* fl = get_file_elem_from_fd(fd);

  if (fl == NULL)
  {
    lock_release(&filesys_lock);
    return SYSCALL_ERROR;
  }

  size_t page_read_bytes = file_size >= PGSIZE ? PGSIZE : file_size;
  off_t ofs = 0;
  for (int i = 0; i < number_of_pages; i++)
  {
    spage_set_entry(&thread_current()->spage_table, addr + PGSIZE * i, 
                    fl->file_name, ofs, page_read_bytes, true);
    // Advance
    ofs += PGSIZE;
    page_read_bytes = file_size - ofs > PGSIZE ? PGSIZE : file_size - ofs;
    // printf("Process %d mmapped page %p\n", thread_current()->tid, addr + PGSIZE * i);
  }

  /* Creates the struct to save the meta data */
  struct file_mmap *new_mmap = malloc(sizeof(struct file_mmap));

  if (new_mmap != NULL)
  {
    new_mmap->map_id = fd;
    strlcpy(new_mmap->file_name, fl->file_name, MAX_FILENAME_LEN);
    new_mmap->owner = thread_current();
    new_mmap->file_size = file_size;
    new_mmap->uaddr = addr;
    list_push_back(&file_mappings, &new_mmap->elem);
    lock_release(&filesys_lock);
    return fd;
  }
  lock_release(&filesys_lock);
  return SYSCALL_ERROR;
}


/**
 * Goes through all the mapped pages and checks they have been modified
 * writes the modified pages back to the file. Removes the mapped pages
 * in the supplemental page table.
 */
static void munmap_write_back_to_file(struct file_mmap *file_mmap)
{
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);
  int file_size = file_mmap->file_size;
  int number_of_pages = (file_size - 1) / PGSIZE + 1;
  for (int i = 0; i < number_of_pages; i++)
  {
    void *curr_uaddr = file_mmap->uaddr + i * PGSIZE;
    if (pagedir_is_dirty(thread_current()->pagedir, curr_uaddr))
    {
      void *kpage = pagedir_get_page(thread_current()->pagedir, curr_uaddr);
      struct spage_table_entry *spte = spage_get_entry(&thread_current()->spage_table, curr_uaddr);
      if (kpage == NULL && spte != NULL && spte->is_swapped)
      {
        struct frame_table_entry *fte = frame_add_entry(spte);
        if (fte != NULL)
          kpage = fte->kpage_addr;
      }

      write_page_to_file(spte, kpage);
    }
    spage_remove_entry(&thread_current()->spage_table, curr_uaddr);
  }
  if (!has_lock)
    lock_release(&filesys_lock);
}



/**
 * Unmaps the mapping designated by mapping, which must be
 * a mapping ID returned by a previous call to mmap by the
 * same process that has not yet been unmmaped.
 *
 * All mappings are implicitly unmapped when a process exits,
 * whether via exit or by any other means. When a mapping
 * is unmapped, whether implicitly or explicitly, all pages
 * written to by the process are written are written back to
 * the file, and pages not written must not be. The pages
 * are then removed from the process's list of virtual pages.
 *
 * Closing or removing a file does not unmap any of its mappings.
 * Once created, a mapping is valid until munmap is called or the
 * process exits.
 */
void munmap (mapid_t mapping)
{
  int fd = mapping;
  bool has_lock = lock_held_by_current_thread(&filesys_lock);
  if (!has_lock)
    lock_acquire(&filesys_lock);
  struct file_mmap *file_mmap = get_file_mmap(mapping);
  
  if (file_mmap == NULL)
  {
    exit(SYSCALL_ERROR);
  }
  munmap_write_back_to_file(file_mmap);
  list_remove(&file_mmap->elem);
  free(file_mmap);
  if (!has_lock)
    lock_release(&filesys_lock);
}