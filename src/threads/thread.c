#include "threads/thread.h"
#include <debug.h>
#include <stddef.h>
#include <random.h>
#include <stdio.h>
#include <string.h>
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/switch.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "threads/fixed-point.h"
#include "devices/timer.h"
#include "../userprog/syscall.h"

#ifdef USERPROG
#include "userprog/process.h"
#endif
#ifdef VM
#include "vm/page.h"
#endif

/* Random value for struct thread's `magic' member.
   Used to detect stack overflow.  See the big comment at the top
   of thread.h for details. */
#define THREAD_MAGIC 0xcd6abf4b

/* List of processes in THREAD_READY state, that is, processes
   that are ready to run but not actually running. */
static struct list ready_list;

/* List of all processes.  Processes are added to this list
   when they are first scheduled and removed when they exit. */
static struct list all_list;

/* Idle thread. */
static struct thread *idle_thread;

/* Initial thread, the thread running init.c:main(). */
static struct thread *initial_thread;

/* Lock used by allocate_tid(). */
static struct lock tid_lock;

/* Stack frame for kernel_thread(). */
struct kernel_thread_frame 
  {
    void *eip;                  /* Return address. */
    thread_func *function;      /* Function to call. */
    void *aux;                  /* Auxiliary data for function. */
  };

/* Statistics. */
static long long idle_ticks;    /* # of timer ticks spent idle. */
static long long kernel_ticks;  /* # of timer ticks in kernel threads. */
static long long user_ticks;    /* # of timer ticks in user programs. */

static int64_t load_average = 0;

/* Scheduling. */
#define TIME_SLICE 4            /* # of timer ticks to give each thread. */
static unsigned thread_ticks;   /* # of timer ticks since last yield. */

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
bool thread_mlfqs;

static void kernel_thread (thread_func *, void *aux);

static void idle (void *aux UNUSED);
static struct thread *running_thread (void);
static struct thread *next_thread_to_run (void);
static void init_thread (struct thread *, const char *name, int priority);
static bool is_thread (struct thread *) UNUSED;
static void *alloc_frame (struct thread *, size_t size);
static void schedule (void);
void thread_schedule_tail (struct thread *prev);
static tid_t allocate_tid (void);

/* Initializes the threading system by transforming the code
   that's currently running into a thread.  This can't work in
   general and it is possible in this case only because loader.S
   was careful to put the bottom of the stack at a page boundary.

   Also initializes the run queue and the tid lock.

   After calling this function, be sure to initialize the page
   allocator before trying to create any threads with
   thread_create().

   It is not safe to call thread_current() until this function
   finishes. */
void
thread_init (void) 
{
  ASSERT (intr_get_level () == INTR_OFF);

  lock_init (&tid_lock);
  list_init (&ready_list);
  list_init (&all_list);

  /* Set up a thread structure for the running thread. */
  initial_thread = running_thread ();
  init_thread (initial_thread, "main", PRI_DEFAULT);
  initial_thread->status = THREAD_RUNNING;
  initial_thread->tid = allocate_tid ();
}

/* Starts preemptive thread scheduling by enabling interrupts.
   Also creates the idle thread. */
void
thread_start (void)
{
  /* Create the idle thread. */
  struct semaphore idle_started;
  sema_init (&idle_started, 0);
  thread_create ("idle", PRI_MIN, idle, &idle_started);

  /* Start preemptive thread scheduling. */
  intr_enable ();
  /* Wait for the idle thread to initialize idle_thread. */
  sema_down (&idle_started);
}

/* Returns the number of threads currently in the ready list */
size_t
threads_ready (void)
{
  return list_size (&ready_list);
}

/* Called by the timer interrupt handler at each timer tick.
   Thus, this function runs in an external interrupt context. */
void
thread_tick (void)
{
  struct thread *t = thread_current ();

  /* Update statistics. */
  if (t == idle_thread)
    idle_ticks++;
#ifdef USERPROG
  else if (t->pagedir != NULL)
    user_ticks++;
#endif
  else
    kernel_ticks++;

  if (thread_mlfqs)
  {
    if (thread_current() != idle_thread)
    {
      thread_current()->recent_cpu = add_int(thread_current()->recent_cpu, 1);
    }
    if (timer_ticks() % TIMER_FREQ == 0)
    {
      update_load_average();
      update_recent_cpu();
    }
    if (timer_ticks() % TIME_SLICE == 0)
    {
      update_priority();
      sort_based_on_priority();
      if (!thread_is_highest_priority())
      {
        intr_yield_on_return();
      }
    }
  }

  /* Enforce preemption. */
  if (++thread_ticks >= TIME_SLICE)
  {
    intr_yield_on_return ();
  }
}

/* Prints thread statistics. */
void
thread_print_stats (void)
{
  printf ("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n",
          idle_ticks, kernel_ticks, user_ticks);
}

/* Creates a new kernel thread named NAME with the given initial
   PRIORITY, which executes FUNCTION passing AUX as the argument,
   and adds it to the ready queue.  Returns the thread identifier
   for the new thread, or TID_ERROR if creation fails.

   If thread_start() has been called, then the new thread may be
   scheduled before thread_create() returns.  It could even exit
   before thread_create() returns.  Contrariwise, the original
   thread may run for any amount of time before the new thread is
   scheduled.  Use a semaphore or some other form of
   synchronization if you need to ensure ordering.

   The code provided sets the new thread's `priority' member to
   PRIORITY, but no actual priority scheduling is implemented.
   Priority scheduling is the goal of Problem 1-3. */
tid_t
thread_create (const char *name, int priority,
               thread_func *function, void *aux)
{
  struct thread *t;
  struct kernel_thread_frame *kf;
  struct switch_entry_frame *ef;
  struct switch_threads_frame *sf;
  tid_t tid;
  enum intr_level old_level;

  ASSERT (function != NULL);

  /* Allocate thread. */
  t = palloc_get_page (PAL_ZERO);
  if (t == NULL)
    return TID_ERROR;

  /* Initialize thread. */
  init_thread (t, name, priority);
  tid = t->tid = allocate_tid ();

  /* Prepare thread for first run by initializing its stack.
     Do this atomically so intermediate values for the 'stack' 
     member cannot be observed. */
  old_level = intr_disable ();

  /* Stack frame for kernel_thread(). */
  kf = alloc_frame (t, sizeof *kf);
  kf->eip = NULL;
  kf->function = function;
  kf->aux = aux;

  /* Stack frame for switch_entry(). */
  ef = alloc_frame (t, sizeof *ef);
  ef->eip = (void (*) (void)) kernel_thread;

  /* Stack frame for switch_threads(). */
  sf = alloc_frame (t, sizeof *sf);
  sf->eip = switch_entry;
  sf->ebp = 0;

  #ifdef USERPROG
  /* Set the new thread's parent to the current thread */
  t->parent = thread_current();
  #endif
  #ifdef VM
  spage_init(&t->spage_table, &t->spage_lock);
  #endif
    
  intr_set_level (old_level);

  /* Add to run queue. */
  thread_unblock (t);

  if (t->effective_priority > thread_current()->effective_priority
      && !thread_mlfqs)
  {
    thread_yield();
  }
  return tid;
}

/* Compares the thread priority of two list elements. For use in
   priority scheduling */
bool comp_priority(const struct list_elem *a,
                  const struct list_elem *b,
                  void *aux UNUSED)
{
  struct thread *threadA = thread_get_thread(a);
  struct thread *threadB = thread_get_thread(b);
  if (thread_mlfqs)
  {
    return threadA->priority > threadB->priority;
  }
  return threadA->effective_priority > threadB->effective_priority;
}

/* Puts the current thread to sleep.  It will not be scheduled
   again until awoken by thread_unblock().

   This function must be called with interrupts turned off.  It
   is usually a better idea to use one of the synchronization
   primitives in synch.h. */
void
thread_block (void)
{
  ASSERT (!intr_context ());
  ASSERT (intr_get_level () == INTR_OFF);
  thread_current ()->status = THREAD_BLOCKED;
  schedule ();
}

/* Transitions a blocked thread T to the ready-to-run state.
   This is an error if T is not blocked.  (Use thread_yield() to
   make the running thread ready.)

   This function does not preempt the running thread.  This can
   be important: if the caller had disabled interrupts itself,
   it may expect that it can atomically unblock a thread and
   update other data. */
void
thread_unblock (struct thread *t) 
{
  enum intr_level old_level;

  ASSERT (is_thread (t));

  old_level = intr_disable ();
  ASSERT (t->status == THREAD_BLOCKED);
  list_insert_ordered(&ready_list, &t->elem, &comp_priority, NULL);
  t->status = THREAD_READY;
  intr_set_level (old_level);
}

/* Returns the name of the running thread. */
const char *
thread_name (void) 
{
  return thread_current ()->name;
}

/* Returns the running thread.
   This is running_thread() plus a couple of sanity checks.
   See the big comment at the top of thread.h for details. */
struct thread *
thread_current (void) 
{
  struct thread *t = running_thread ();
  
  /* Make sure T is really a thread.
     If either of these assertions fire, then your thread may
     have overflowed its stack.  Each thread has less than 4 kB
     of stack, so a few big automatic arrays or moderate
     recursion can cause stack overflow. */
  ASSERT (is_thread (t));
  ASSERT (t->status == THREAD_RUNNING);

  return t;
}

/* Returns the running thread's tid. */
tid_t
thread_tid (void) 
{
  return thread_current ()->tid;
}

/* Deschedules the current thread and destroys it.  Never
   returns to the caller. */
void
thread_exit (void) 
{
  ASSERT (!intr_context ());

#ifdef USERPROG
  process_exit ();
#endif

  /* Remove thread from all threads list, set our status to dying,
     and schedule another process.  That process will destroy us
     when it calls thread_schedule_tail(). */
  intr_disable ();
  list_remove (&thread_current()->allelem);
  thread_current ()->status = THREAD_DYING;
  schedule ();
  NOT_REACHED ();
}

/* Yields the CPU.  The current thread is not put to sleep and
   may be scheduled again immediately at the scheduler's whim. */
void
thread_yield (void) 
{
  struct thread *cur = thread_current ();
  enum intr_level old_level;

  ASSERT (!intr_context ());
  old_level = intr_disable ();
  if (cur != idle_thread)
    list_insert_ordered(&ready_list, &cur->elem, &comp_priority, NULL);
  cur->status = THREAD_READY;
  schedule ();
  intr_set_level (old_level);
}

/**
 * Obtains the child thread of the current thread given its tid.
 * Used in process.c.
 **/
struct thread *thread_get_child(tid_t child_tid)
{
  enum intr_level old_level = intr_disable();

  for (struct list_elem *e =
              list_begin(&all_list); e != list_end(&all_list); e = list_next(e))
  {
    struct thread *current_thread = list_entry(e, struct thread, allelem);
    if (current_thread != idle_thread &&
        current_thread->tid == child_tid &&
        current_thread->parent == thread_current())
    {
      intr_set_level(old_level);
      return current_thread;
    }
  }
  intr_set_level(old_level);
  return NULL;
}

/* Gets the child_bookmark from the given CHILD_LIST with the given
   CHILD_TID or NULL if it is not found */
struct child_bookmark* thread_waiting_child(struct list* child_list,
                                             tid_t child_tid)
{
  /* Do not attempt to fetch bookmark if parent no longer exists */
  if (child_list == NULL)
  {
    return NULL;
  }

  enum intr_level old_level = intr_disable();

  for (struct list_elem *e = list_begin(child_list);
       e != list_end(child_list); e = list_next(e))
  {
    struct child_bookmark* child_exit = list_entry(e,
                                                   struct child_bookmark,
                                                   elem);
    if (child_exit->child_pid == child_tid)
    {
      intr_set_level(old_level);
      return child_exit;
    }
  }
  intr_set_level(old_level);
  return NULL;
}


/* Invoke function 'func' on all threads, passing along 'aux'.
   This function must be called with interrupts off. */
void
thread_foreach (thread_action_func *func, void *aux)
{
  struct list_elem *e;

  ASSERT (intr_get_level () == INTR_OFF);

  for (e = list_begin (&all_list); e != list_end (&all_list);
       e = list_next (e))
    {
      struct thread *t = list_entry (e, struct thread, allelem);
      func (t, aux);
    }
}

struct thread* thread_get_thread(const struct list_elem* e)
{
  struct thread* t = list_entry(e, struct thread, elem);
  return t;
}

/* Checks if the current running thread has the highest priority */
bool thread_is_highest_priority(void)
{
  if (!list_empty(&ready_list))
  {
    if (thread_mlfqs)
    {
      return (thread_current()->priority >=
              thread_get_thread(list_begin(&ready_list))->priority);
    }
    else
    {
      return (thread_current()->effective_priority >=
              thread_get_thread(list_begin(&ready_list))->effective_priority);
    }
  }
  return true;
}

/* Sets the current thread's priority to NEW_PRIORITY. */
void
thread_set_priority (int new_priority)
{
  thread_current ()->priority = new_priority;
  if (!thread_mlfqs)
  {
    if (list_empty(&thread_current()->dependent_list) ||
        new_priority > thread_current()->effective_priority)
    {
      thread_current()->effective_priority = new_priority;
    }
    else
    {
      thread_current()->effective_priority = thread_get_highest_priority();
    }
  }
  // If the thread no longer has the highest priority, immediately yield CPU
  if (!thread_is_highest_priority())
  {
    thread_yield();
  }
}

/* Returns the current thread's priority. */
int
thread_get_priority (void) 
{
  return (!thread_mlfqs) ?
            thread_current()->effective_priority :
            thread_current()->priority;
}

/* Returns the highest priority out of the current thread's dependent threads,
   NOT FOR USE with mlfqs mode on*/
int thread_get_highest_priority(void)
{
  if (!list_empty(&thread_current()->dependent_list))
  {
    int donated_priority = list_entry(list_begin(&thread_current()->dependent_list),
                                 struct thread,
                                 dependent_elem)->effective_priority;
    return (donated_priority > thread_current()->priority) ?
              donated_priority :
              thread_current()->effective_priority;
  }
  return thread_current()->priority;
}

/* Sets all members of the waiting list to be dependent on DEP, used when
   releasing locks to make all threads waiting on lock to be dependent on the
   next owner of the lock */
void thread_change_dependencies(struct list *waiting_list, struct thread *dep)
{
  if (!list_empty(waiting_list))
  {
    enum intr_level old_level = intr_disable();
    for (struct list_elem *waiter = list_begin(waiting_list);
         waiter != list_end(waiting_list);
         waiter = list_next(waiter))
    {
      struct thread *th = thread_get_thread(waiter);
      if (dep != th)
      {
        th->dependent_on = dep;
        list_remove(&th->dependent_elem);
        list_push_back(&dep->dependent_list,
                       &th->dependent_elem);
      }
    }
    intr_set_level(old_level);
  }
}

/* Recursively donates current thread's effective priority to RECIPIENT */
void thread_donate_priority(struct thread *recipient)
{
  if (recipient->effective_priority < thread_current()->effective_priority)
  {
    recipient->effective_priority = thread_current()->effective_priority;
    if (recipient->dependent_on != NULL)
    {
      thread_donate_priority(recipient->dependent_on);
    }
  }
}

/* Sets the current thread's nice value to NICE. */
void
thread_set_nice (int nice)
{ 
  struct thread *cur = thread_current();
  cur->nice = nice;
  cur->priority = calculate_priority(cur->recent_cpu, cur->nice);
  if (!thread_is_highest_priority())
  {
    thread_yield();
  }
}

/* Returns the current thread's nice value. */
int
thread_get_nice (void) 
{
  return thread_current()->nice;
}

/* Returns 100 times the system load average. */
int
thread_get_load_avg (void) 
{

  return convert_to_int_round_to_nearest(multiply_int(load_average, 100));
}

/* Returns 100 times the current thread's recent_cpu value. */
int
thread_get_recent_cpu (void) 
{
  return convert_to_int_round_to_nearest(multiply_int(
                                                  thread_current()->recent_cpu,
                                                  100));
}

/* Idle thread.  Executes when no other thread is ready to run.

   The idle thread is initially put on the ready list by
   thread_start().  It will be scheduled once initially, at which
   point it initializes idle_thread, "up"s the semaphore passed
   to it to enable thread_start() to continue, and immediately
   blocks.  After that, the idle thread never appears in the
   ready list.  It is returned by next_thread_to_run() as a
   special case when the ready list is empty. */
static void
idle (void *idle_started_ UNUSED) 
{
  struct semaphore *idle_started = idle_started_;
  idle_thread = thread_current ();
  sema_up (idle_started);

  for (;;) 
    {
      /* Let someone else run. */
      intr_disable ();
      thread_block ();

      /* Re-enable interrupts and wait for the next one.

         The `sti' instruction disables interrupts until the
         completion of the next instruction, so these two
         instructions are executed atomically.  This atomicity is
         important; otherwise, an interrupt could be handled
         between re-enabling interrupts and waiting for the next
         one to occur, wasting as much as one clock tick worth of
         time.

         See [IA32-v2a] "HLT", [IA32-v2b] "STI", and [IA32-v3a]
         7.11.1 "HLT Instruction". */
      asm volatile ("sti; hlt" : : : "memory");
    }
}

/* Function used as the basis for a kernel thread. */
static void
kernel_thread (thread_func *function, void *aux) 
{
  ASSERT (function != NULL);

  intr_enable ();       /* The scheduler runs with interrupts off. */
  function (aux);       /* Execute the thread function. */
  thread_exit ();       /* If function() returns, kill the thread. */
}

/* Returns the running thread. */
struct thread *
running_thread (void) 
{
  uint32_t *esp;

  /* Copy the CPU's stack pointer into `esp', and then round that
     down to the start of a page.  Because `struct thread' is
     always at the beginning of a page and the stack pointer is
     somewhere in the middle, this locates the curent thread. */
  asm ("mov %%esp, %0" : "=g" (esp));
  return pg_round_down (esp);
}

/* Returns true if T appears to point to a valid thread. */
static bool
is_thread (struct thread *t)
{
  return t != NULL && t->magic == THREAD_MAGIC;
}

/* Does basic initialization of T as a blocked thread named
   NAME. */
static void
init_thread (struct thread *t, const char *name, int priority)
{
  enum intr_level old_level;

  ASSERT (t != NULL);
  ASSERT (PRI_MIN <= priority && priority <= PRI_MAX);
  ASSERT (name != NULL);

  memset (t, 0, sizeof *t);
  t->status = THREAD_BLOCKED;
  strlcpy (t->name, name, sizeof t->name);
  t->stack = (uint8_t *) t + PGSIZE;
  t->priority = priority;
  t->effective_priority = priority;
  t->wake_time = SLEEP_DEFAULT;
  t->dependent_on = NULL;
  list_init(&t->dependent_list);
  #ifdef USERPROG
  sema_init(&t->wait_for_child, 0);
  list_init(&t->files);
  list_init(&t->child_waits);
  t->child_waiting = TID_ERROR;
  #endif
  t->magic = THREAD_MAGIC; 

  /* The new thread's nice is inherited if it has a parent thread, else it is
     set to 0 */
  t->nice = (list_size(&all_list) == 0) ? 0 : thread_current()->nice;
  t->recent_cpu = 0;

  old_level = intr_disable ();
  list_push_back (&all_list, &t->allelem);
  intr_set_level (old_level);
}

/* Allocates a SIZE-byte frame at the top of thread T's stack and
   returns a pointer to the frame's base. */
static void *
alloc_frame (struct thread *t, size_t size) 
{
  /* Stack data is always allocated in word-size units. */
  ASSERT (is_thread (t));
  ASSERT (size % sizeof (uint32_t) == 0);

  t->stack -= size;
  return t->stack;
}

/* Chooses and returns the next thread to be scheduled.  Should
   return a thread from the run queue, unless the run queue is
   empty.  (If the running thread can continue running, then it
   will be in the run queue.)  If the run queue is empty, return
   idle_thread. */
static struct thread *
next_thread_to_run (void) 
{
  if (list_empty (&ready_list))
    return idle_thread;
  else
    return list_entry (list_pop_front (&ready_list), struct thread, elem);
}

/* Completes a thread switch by activating the new thread's page
   tables, and, if the previous thread is dying, destroying it.

   At this function's invocation, we just switched from thread
   PREV, the new thread is already running, and interrupts are
   still disabled.  This function is normally invoked by
   thread_schedule() as its final action before returning, but
   the first time a thread is scheduled it is called by
   switch_entry() (see switch.S).

   It's not safe to call printf() until the thread switch is
   complete.  In practice that means that printf()s should be
   added at the end of the function.

   After this function and its caller returns, the thread switch
   is complete. */
void
thread_schedule_tail (struct thread *prev)
{
  struct thread *cur = running_thread ();
  
  ASSERT (intr_get_level () == INTR_OFF);

  /* Mark us as running. */
  cur->status = THREAD_RUNNING;

  /* Start new time slice. */
  thread_ticks = 0;

#ifdef USERPROG
  /* Activate the new address space. */
  process_activate ();
#endif

  /* If the thread we switched from is dying, destroy its struct
     thread.  This must happen late so that thread_exit() doesn't
     pull out the rug under itself.  (We don't free
     initial_thread because its memory was not obtained via
     palloc().) */
  if (prev != NULL && prev->status == THREAD_DYING && prev != initial_thread) 
    {
      ASSERT (prev != cur);
      palloc_free_page (prev);
    }
}

/* Calculates the priority of a thread with MLFQS MODE ON using the formula
      priority = PRI_MAX - (recent_cpu / 4) - (nice / 2)
*/
int calculate_priority(int64_t recent_cpu, int nice)
{
  int priority = PRI_MAX;
  priority -= (nice * 2);
  int64_t priority_fixed_point = int_to_fixed_point(priority);
  priority_fixed_point = subtract(priority_fixed_point,
                                  divide_int(recent_cpu, 4));
  priority = convert_to_int_round_towards_zero(priority_fixed_point);
  if (priority > PRI_MAX)
  {
    priority = PRI_MAX;
  } 
  if (priority < PRI_MIN)
  {
    priority = PRI_MIN;
  }
  return priority;
} 

/* Calculates the recent_cpu of a thread with MLFQS MODE ON using the formula
      recent_cpu = (2 * load_avg)/ (2 * load_avg + 1) * recent_cpu + nice
*/
int64_t calculate_recent_cpu(int64_t recent_cpu, int64_t load_average, int nice)
{
  return add_int(multiply(divide(multiply_int(load_average, 2),
                          add_int(multiply_int(load_average, 2), 1)),
                          recent_cpu), nice);
}

/* Calculates the load_avg of a thread with MLFQS MODE ON using the formula
      load_avg = (59/60) * load_avg + (1 / 60) * ready_threads
*/
int64_t calculate_load_average(int64_t load_average, int ready_threads)
{
  return add(divide_int(multiply_int(load_average, 59), 60),
             divide_int(int_to_fixed_point(ready_threads), 60));
}

/* Updates the load_avg global variable with MLFQS MODE ON */
void update_load_average(void)
{
  int ready_threads = list_size(&ready_list);
  if (thread_current() != idle_thread)
  {
    ready_threads++;
  }
  load_average = calculate_load_average(load_average, ready_threads);
}

/* Calculates and updates the recent_cpu value for all threads, does not require
   interrupts to be disabled as this function is only called during a timer
   interrupt, requires MLFQS TRUE*/
void update_recent_cpu(void)
{
  ASSERT(thread_mlfqs);

  for (struct list_elem *e = list_begin(&all_list); e != list_end(&all_list);
       e = list_next(e))
  {
    struct thread *current_thread = list_entry(e, struct thread, allelem);
    if (current_thread != idle_thread)
    {
      current_thread->recent_cpu = calculate_recent_cpu(current_thread->recent_cpu,
                                                        load_average,
                                                        current_thread->nice);
    }
  }
}

/* Calculates and updates the priority value for all threads, does not require
   interrupts to be disabled as this function is only called during a timer
   interrupt */
void update_priority(void)
{
  ASSERT(thread_mlfqs);

  for (struct list_elem *e = list_begin(&all_list); e != list_end(&all_list);
       e = list_next(e))
  {
    struct thread *current_thread = list_entry(e, struct thread, allelem);
    if (current_thread != idle_thread)
    {
      current_thread->priority = calculate_priority(current_thread->recent_cpu,
                                                    current_thread->nice);
    }
  }
}

/* Sorts ready list based on thread priority to enable priority scheduling */
void sort_based_on_priority()
{
  list_sort(&ready_list, comp_priority, NULL);
}

/* Schedules a new process.  At entry, interrupts must be off and
   the running process's state must have been changed from
   running to some other state.  This function finds another
   thread to run and switches to it.

   It's not safe to call printf() until thread_schedule_tail()
   has completed. */
static void
schedule (void) 
{
  struct thread *cur = running_thread ();
  struct thread *next = next_thread_to_run ();
  struct thread *prev = NULL;

  ASSERT (intr_get_level () == INTR_OFF);
  ASSERT (cur->status != THREAD_RUNNING);
  ASSERT (is_thread (next));

  if (cur != next)
    prev = switch_threads (cur, next);
  thread_schedule_tail (prev);
}

/* Returns a tid to use for a new thread. */
static tid_t
allocate_tid (void) 
{
  static tid_t next_tid = 1;
  tid_t tid;

  lock_acquire (&tid_lock);
  tid = next_tid++;
  lock_release (&tid_lock);

  return tid;
}

/* Offset of `stack' member within `struct thread'.
   Used by switch.S, which can't figure it out on its own. */
uint32_t thread_stack_ofs = offsetof (struct thread, stack);
