#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "lib/kernel/console.h"
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "vm/page.h"
#include "vm/frame.h"

// standard file descriptor numbers
#define STDIN_FILENO 0
#define STDOUT_FILENO 1

// Global lock for file system synchronization
struct lock filesys_lock;

/* Function declarations */
static void syscall_handler (struct intr_frame *);
static void validate_user_ptr (const void *ptr);
static void validate_user_buffer (const void *ptr, size_t size, void* esp);
static void validate_user_string (const char *str);
static bool range_mapped (const void *usrc, size_t size, void* esp);
static bool get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size, void* esp);
static void halt (void);
static void exit (int status);
static int write (int fd, const void *buffer, unsigned size, void* esp);
static int exec (const char *cmd_line);
static int wait (int child_tid);
static int read (int fd, void *buffer, unsigned size, void* esp);
static int filesize_sys (int fd);
int allocate_fd(struct file *file);
struct file *get_file_by_fd(int fd);
void close_fd(int fd);

void syscall_init (void)
{
  // initialize the file system lock
  lock_init (&filesys_lock);
  
  // register our system call handler for interrupt 0x30
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f)
{
  int syscall_number;
  uint32_t *esp = (uint32_t *) f->esp;
  
  // validate the stack pointer is in user space
  validate_user_ptr ((void *) esp);
  
  // safely read the system call number from user stack
  if (!get_user_bytes ((uint8_t *) &syscall_number, (uint8_t *) esp, sizeof (int), esp))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
  
  // dispatch to the appropriate system call handler
  switch (syscall_number)
    {
      case SYS_HALT:
        halt (); // power off the system
        break;
        
      case SYS_EXIT:
        {
          int status;
          // safely read the exit status from user stack
          if (!get_user_bytes ((uint8_t *) &status, (uint8_t *) (esp + 1), sizeof (int), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          exit (status); // terminate process with status
        }
        break;
        
      case SYS_WRITE:
        {
          int fd;
          void *buffer;
          unsigned size;
          
          // safely read write arguments from user stack
          if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int), esp) ||
              !get_user_bytes ((uint8_t *) &buffer, (uint8_t *) (esp + 2), sizeof (void *), esp) ||
              !get_user_bytes ((uint8_t *) &size, (uint8_t *) (esp + 3), sizeof (unsigned), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          // validate the buffer pointer is in user space
          validate_user_ptr (buffer);
          
          // call our write implementation and set return value
          int result = write (fd, buffer, size, esp);
          f->eax = result;
        }
        break;
        
      case SYS_EXEC:
        {
          const char *cmd_line;
          
          // safely read exec argument from user stack
          if (!get_user_bytes ((uint8_t *) &cmd_line, (uint8_t *) (esp + 1), sizeof (const char *), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          // validate the command line pointer is in user space
          validate_user_string (cmd_line);
          
          // call our exec implementation and set return value
          int result = exec (cmd_line); // start new process
          f->eax = result;
        }
        break;
        
      case SYS_WAIT:
        {
          int child_tid;
          
          // safely read wait argument from user stack
          if (!get_user_bytes ((uint8_t *) &child_tid, (uint8_t *) (esp + 1), sizeof (int), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          // call our wait implementation and set return value
          int result = wait (child_tid); // wait for child process
          f->eax = result;
        }
        break;
        
      case SYS_READ:
        {
          int fd;
          void *buffer;
          unsigned size;
          
          // safely read arguments from user stack
          if (!get_user_bytes ((uint8_t *) &fd, (uint8_t *) (esp + 1), sizeof (int), esp) ||
              !get_user_bytes ((uint8_t *) &buffer, (uint8_t *) (esp + 2), sizeof (void *), esp) ||
              !get_user_bytes ((uint8_t *) &size, (uint8_t *) (esp + 3), sizeof (unsigned), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          
          // validate the buffer pointer is in user space
          validate_user_ptr (buffer);
          
          // call our read implementation and set return value
          int result = read (fd, buffer, size, esp); // read from stdin only
          f->eax = result;
        }
        break;
        
        case SYS_CREATE: 
        {
          const char *file;
          unsigned initial_size;
          if (!get_user_bytes ((uint8_t *) &file, (uint8_t *) (esp + 1), sizeof (const char *), esp) ||
              !get_user_bytes ((uint8_t *) &initial_size, (uint8_t *) (esp + 2), sizeof (unsigned), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
            if (file == NULL) {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
            validate_user_string(file);
            lock_acquire (&filesys_lock);
            f->eax = filesys_create(file, initial_size);
            lock_release (&filesys_lock);
        }
        break;

        case SYS_REMOVE: 
        {
          const char *file;
          unsigned initial_size;
          if (!get_user_bytes ((uint8_t *) &file, (uint8_t *) (esp + 1), sizeof (const char *), esp) ||
              !get_user_bytes ((uint8_t *) &initial_size, (uint8_t *) (esp + 2), sizeof (unsigned), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
            if (file == NULL) {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
            validate_user_string(file);
            lock_acquire (&filesys_lock);
            f->eax = filesys_remove(file);
            lock_release (&filesys_lock);
        }
        break;

        case SYS_OPEN:
        {
          const char *file_name;
          if (!get_user_bytes((uint8_t *)&file_name, (uint8_t *)(esp + 1), sizeof(file_name), esp))
            thread_exit(); 

          validate_user_string(file_name); 

          lock_acquire (&filesys_lock);
          struct file *file = filesys_open(file_name);  
          lock_release (&filesys_lock);

          if (file == NULL)
            {
              f->eax = -1; 
            }
          else
            {
              f->eax = allocate_fd(file); 
              if (f->eax == -1) {
                lock_acquire (&filesys_lock);
                file_close(file);
                lock_release (&filesys_lock);
              }
            }
          break;
        }

        case SYS_CLOSE:
        {
          int fd;
          if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(fd), esp))
            thread_exit(); 

          close_fd(fd); 
          break;
        }

        case SYS_FILESIZE:
        {
          int fd;
          if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(fd), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          f->eax = filesize_sys(fd);
          break;
        }
        case SYS_SEEK:
        {
          int fd;
          unsigned position;
          if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(int), esp) ||
              !get_user_bytes((uint8_t *)&position, (uint8_t *)(esp + 2), sizeof(unsigned), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          struct file *fptr = get_file_by_fd(fd);
          if (fptr != NULL)
            {
              lock_acquire (&filesys_lock);
              file_seek(fptr, position);
              lock_release (&filesys_lock);
            }
          break;
        }
        case SYS_TELL:
        {
          int fd;
          if (!get_user_bytes((uint8_t *)&fd, (uint8_t *)(esp + 1), sizeof(int), esp))
            {
              printf ("%s: exit(-1)\n", thread_name ());
              thread_exit ();
            }
          struct file *fptr = get_file_by_fd(fd);
          if (fptr == NULL)
            {
              f->eax = -1;
            }
          else
            {
              lock_acquire (&filesys_lock);
              f->eax = file_tell(fptr);
              lock_release (&filesys_lock);
            }
          break;
        }

      default:
        // unknown system call - terminate process (file system calls not implemented yet)
        printf ("%s: exit(-1)\n", thread_name ());
        thread_exit ();
    }
}

// validates that a range of user memory is valid
// terminates the process if invalid
static void
validate_user_buffer (const void *ptr, size_t size, void* esp)
{
  // use range_mapped to check the entire range
  if (!range_mapped (ptr, size, esp))
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
}

// returns if the entire [usrc, usrc+size-1] lies in user space
// and every overlapped page is mapped in the current process.
static bool
range_mapped (const void *usrc, size_t size, void* esp)
{
  if (size == 0)
    return true;
  if (usrc == NULL)
    return false;

  const uint8_t *start = (const uint8_t *) usrc;
  const uint8_t *last  = start + size - 1;

  if (!is_user_vaddr (start) || !is_user_vaddr (last))
    return false;

  uint8_t *p   = pg_round_down ((void *) start);
  uint8_t *end = pg_round_down ((void *) last);

  struct thread *cur = thread_current ();
  if (cur == NULL || cur->pagedir == NULL)
    return false;

  while (p <= end)
    {
      // Check if page is loaded in page table
      if (pagedir_get_page (cur->pagedir, p) != NULL)
        {
          p += PGSIZE;
          continue;
        }
      
      // If not loaded, check if it's in the SPT (demand-paged)
      struct page *pg = page_lookup (&cur->spt, p);
      if (pg != NULL)
        {
          // Page is in SPT, so it's valid (will be loaded on fault)
          p += PGSIZE;
          continue;
        }
      
      // If not in SPT, check if it's in stack range and is above the stack pointer
      // Stack pages can be demand-paged, so allow them even if not in SPT yet
      void *bottom_of_stack = (void *)((uint8_t *)PHYS_BASE - 0x800000); // stack limit
      void *top_of_stack = (void *) PHYS_BASE;
      if (p >= bottom_of_stack && p < top_of_stack && p != NULL && is_user_vaddr(esp) && p > esp)
        {
          // Valid stack address - will be handled by page fault handler
          p += PGSIZE;
          continue;
        }
      
      // Page not in page table, SPT, or stack range - invalid
      return false;
      }
  return true;
}

// safely reads size bytes from user address to kernel address
// validates the user address range first
static bool
get_user_bytes (uint8_t *dst, const uint8_t *usrc, size_t size, void* esp)
{
  if (size == 0)
    return true;

  // validate the entire range, including the last page
  if (!range_mapped (usrc, size, esp))
    return false;

  // now it's safe to copy
  for (size_t i = 0; i < size; i++)
    dst[i] = usrc[i];
  return true;
}

// validates that a single pointer is in user space
static void
validate_user_ptr (const void *ptr)
{
  if (ptr == NULL || !is_user_vaddr (ptr)) 
    {
      printf ("%s: exit(-1)\n", thread_name ());
      thread_exit ();
    }
}

// validates that a null-terminated string is in user space and mapped
static void validate_user_string(const char *str)
{
  if (str == NULL || !is_user_vaddr(str))
    {
      printf("%s: exit(-1)\n", thread_name());
      thread_exit();
    }

  const char *ptr = str;
  struct thread *cur = thread_current();

  while (true)
    {
      // check if the current pointer is in user space and mapped
      if (!is_user_vaddr(ptr) || pagedir_get_page(cur->pagedir, (void *)ptr) == NULL)
        {
          printf("%s: exit(-1)\n", thread_name());
          thread_exit();
        }

      if (*ptr == '\0')
        break;

      // move to next char
      ptr++;
    }
}

// halt system call - powers off the system
static void halt (void)
{
  shutdown_power_off (); // call kernel shutdown function
}

// exit system call - terminates the current process
static void exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status; // store exit status for parent to read
  printf ("%s: exit(%d)\n", thread_name (), status); // print exit message
  thread_exit (); // terminate the thread
}

// write system call - writes data to a file descriptor
static int write (int fd, const void *buffer, unsigned size, void* esp)
{
  if (fd == STDOUT_FILENO)
    {
      // validate buffer before writing
      validate_user_buffer (buffer, size, esp);
      
      // write to console
      putbuf (buffer, size);
      return size;
    }
  else
    {
      struct file *temp = get_file_by_fd(fd);
      if (temp == NULL) {
        return -1;
      }
      validate_user_buffer (buffer, size, esp);
      // pin buffer
      vm_pin_buffer(buffer, size, false);
      lock_acquire (&filesys_lock);
      int bytes_written = file_write(temp, buffer, size);
      lock_release (&filesys_lock);
      vm_unpin_buffer(buffer, size);
      return bytes_written;
    }
}

// exec system call - starts another process
static int exec (const char *cmd_line)
{
  // validate the command line string is in user space
  validate_user_ptr (cmd_line);
  validate_user_string (cmd_line);
  
  // start the new process and return its thread id
  tid_t tid = process_execute (cmd_line);

  // if process_execute returns TID_ERROR, return -1
  if (tid == TID_ERROR)
    return -1;

  // otherwise return the thread id
  return tid;
}

// wait system call - waits for a child process to complete
static int wait (int child_tid)
{
  // call the process_wait function and return its result
  return process_wait (child_tid);
}

// read system call - reads from a file descriptor
static int read (int fd, void *buffer, unsigned size, void* esp)
{
  if (fd == STDIN_FILENO)
    {
      // validate buffer before reading
      validate_user_buffer (buffer, size, esp);
      
      // read from keyboard
      unsigned i;
      for (i = 0; i < size; i++)
        {
          ((char *) buffer)[i] = input_getc ();
        }
      return size;
    }
  else
    {
      struct file *temp = get_file_by_fd(fd);
      if (temp == NULL) {
        return -1;
      }
      validate_user_buffer (buffer, size, esp);
      //pin buffer
      vm_pin_buffer(buffer, size, true);
      lock_acquire (&filesys_lock);
      int bytes_read = file_read(temp, buffer, size);
      lock_release (&filesys_lock);
      vm_unpin_buffer(buffer, size);
      if (bytes_read < 0) {
        printf("file_read failed for fd %d\n", fd);
      }
      return bytes_read;

    }
}

static int filesize_sys (int fd)
{
  struct file *f = get_file_by_fd(fd);
  if (f == NULL)
    return -1;
  lock_acquire (&filesys_lock);
  int length = file_length(f);
  lock_release (&filesys_lock);
  return length;
}

int allocate_fd(struct file *file) {
  struct thread *cur = thread_current();
  if (cur->fd_table == NULL)
    return -1;

  // find the next available fd
  int fd = cur->fd_next;
  while (fd < 128) {
    if (cur->fd_table[fd] == NULL) {
      cur->fd_table[fd] = file; // assign the file to this fd
      // update fd_next for next allocation
      cur->fd_next = fd + 1;
      return fd;
    }
    fd++;
  }
  return -1; // no available fd
}

struct file *get_file_by_fd(int fd) {
  struct thread *cur = thread_current();
  if (cur->fd_table == NULL || fd < 0 || fd > 128)
    return NULL; // invalid fd or fd table not initialized
  return cur->fd_table[fd];
}

void close_fd(int fd) {
  struct thread *cur = thread_current();
  if (cur->fd_table == NULL || fd < 0 || fd > 128)
    return;
  if (cur->fd_table[fd] != NULL) {
    lock_acquire (&filesys_lock);
    file_close(cur->fd_table[fd]);
    lock_release (&filesys_lock);
    cur->fd_table[fd] = NULL;
    // update fd_next to allow reusing lower fds
    if (fd < cur->fd_next)
      cur->fd_next = fd;
  }
}
