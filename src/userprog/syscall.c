#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"

#include "../devices/shutdown.h"

static void syscall_handler (struct intr_frame *);
static bool is_valid_pointer(const void *uaddr);


static bool is_valid_pointer(const void *uaddr) {
  void *phys_addr = pagedir_get_page(thread_current()->pagedir, uaddr);
  if (phys_addr == NULL) {
    return false;
  }
  return is_user_vaddr(phys_addr);

}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f)
{

  /* Checks if the stack pointer is valid before de-referencing */
  int syscall_num;
  if (is_valid_pointer(f->esp))
  {
    syscall_num = *(int *) f->esp;
  }
  /* Invoke the corresponding system call function according to the
     stack frame's stack pointer */
  switch (syscall_num)
  {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      if (is_valid_pointer(f->esp + 1))
      {
        exit(*(int *) (f->esp + 1));
      }
      break;

    case SYS_EXEC:
      if (is_valid_pointer(f->esp + 1))
      {
        exec((char *) (f->esp + 1));
      }
      break;

    case SYS_WAIT:
      if (is_valid_pointer(f->esp + 1))
      {
        wait(* (int *) (f->esp + 1));
      }
      break;

    case SYS_CREATE:
      if (is_valid_pointer(f->esp + 1) && is_valid_pointer(f->esp + 2))
      {
        create((char *) (f->esp + 1), *(uint8_t *) (f->esp + 2));
      }
      break;

    case SYS_REMOVE:
      if (is_valid_pointer(f->esp + 1))
      {
        remove((char *) (f->esp + 1));
      }
      break;

    case SYS_FILESIZE:
      
      break;

    case SYS_READ:

      break;

    case SYS_WRITE:

      break;

    case SYS_SEEK:

      break;

    case SYS_TELL:

      break;

    case SYS_CLOSE:

      break;
  }


  printf ("system call!\n");

  thread_exit ();
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
void exit(int status UNUSED)
{
  while (true)
  {

  }
  // printf("%s: exit(%d)\n");

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
pid_t exec(const char *cmd_line UNUSED)
{
  // TODO

  return -1;
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
int wait(pid_t pid UNUSED)
{
  // TODO

  return 0;
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
bool create(const char *file UNUSED, unsigned initial_size UNUSED)
{
  // TODO

  return false;
}

/**
 * Deletes the file called file. Returns true if successful, false otherwise.
 * A file may be removed regardless of whether it is open or closed. Removing
 * an open file does not close it.
 * @param file: name of the file to be deleted.
 * @return: whether the file has been deleted successfully.
 */
bool remove(const char *file UNUSED)
{
  // TODO

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
int open(const char *file UNUSED)
{
  // TODO

  return 2;
}


/**
 * Returns the size, in bytes, of the file open as fd.
 * @param fd: the file open as fd.
 * @return: the size of the file in bytes.
 */
int filesize(int fd UNUSED)
{
  // TODO

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
int read(int fd UNUSED, void *buffer UNUSED, unsigned size UNUSED)
{
  // TODO

  return 0;
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
int write(int fd UNUSED, const void *buffer UNUSED, unsigned size UNUSED)
{
  // TODO

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
void seek(int fd UNUSED, unsigned position UNUSED)
{
  // TODO
}

/**
 * Returns the position of the next byte to be read or written in open file fd,
 * expressed in bytes from the beginning of the file.
 * @param fd: the file open as fd.
 * @return: the position of the next byte to be read to or written from.
 */
unsigned tell(int fd UNUSED)
{
  // TODO

  return 0;
}


/**
 * Closes file descriptor fd. Exiting or terminating a process implicitly closes
 * all its open file descriptors, as if by calling this function for each one.
 * @param fd: the file open as fd.
 */
void close(int fd UNUSED)
{
  // TODO
}